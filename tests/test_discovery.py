"""Directory walking, exclusion and manifest/lockfile pairing."""

from __future__ import annotations

from pathlib import Path, PurePath

import pytest

from icebergsca.core.discovery import DiscoveryOptions, discover
from icebergsca.core.errors import DiscoveryError
from icebergsca.core.models import EcosystemId


def build_tree(root: Path, files: dict[str, str]) -> None:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def test_finds_manifests_across_ecosystems(tmp_path: Path) -> None:
    build_tree(
        tmp_path,
        {
            "requirements.txt": "requests==2.31.0\n",
            "frontend/package.json": "{}",
            "service/pom.xml": "<project/>",
            "tool/go.mod": "module example\n",
        },
    )
    found = {unit.ecosystem for unit in discover(tmp_path).units}
    assert found == {
        EcosystemId.PYPI,
        EcosystemId.NPM,
        EcosystemId.MAVEN,
        EcosystemId.GO,
    }


def test_matching_is_case_insensitive(tmp_path: Path) -> None:
    """Gemfile and Cargo.toml are conventionally capitalised; both cases must match."""
    build_tree(tmp_path, {"a/Cargo.toml": "", "b/gemfile": "", "c/Gemfile": ""})
    ecosystems = [unit.ecosystem for unit in discover(tmp_path).units]
    assert ecosystems.count(EcosystemId.RUBYGEMS) == 2
    assert EcosystemId.CARGO in ecosystems


def test_requirements_directory_convention(tmp_path: Path) -> None:
    """``requirements/base.txt`` is a requirements file; ``notes.txt`` is not."""
    build_tree(
        tmp_path,
        {"requirements/base.txt": "requests==2.31.0\n", "docs/notes.txt": "hello"},
    )
    units = discover(tmp_path).units
    assert len(units) == 1
    assert units[0].manifests == (PurePath("requirements/base.txt"),)


def test_ignores_unrelated_text_files(tmp_path: Path) -> None:
    build_tree(tmp_path, {"README.txt": "hi", "notes.txt": "hi"})
    assert discover(tmp_path).units == ()


# ---------------------------------------------------------------------------
# Pruning
# ---------------------------------------------------------------------------


def test_prunes_vendored_and_build_directories(tmp_path: Path) -> None:
    """Walking node_modules would re-report what the lockfile already covers."""
    build_tree(
        tmp_path,
        {
            "package.json": "{}",
            "node_modules/left-pad/package.json": "{}",
            ".venv/lib/requirements.txt": "requests==1.0\n",
            "target/pom.xml": "<project/>",
        },
    )
    units = discover(tmp_path).units
    assert len(units) == 1
    assert units[0].directory == PurePath(".")


def test_exclude_glob_matches_bare_filename(tmp_path: Path) -> None:
    build_tree(tmp_path, {"app.csproj": "", "requirements.txt": ""})
    options = DiscoveryOptions(exclude=("*.csproj",))
    result = discover(tmp_path, options)
    assert [unit.ecosystem for unit in result.units] == [EcosystemId.PYPI]
    assert [entry.reason for entry in result.skipped] == ["excluded by --exclude"]


def test_exclude_glob_prunes_directories(tmp_path: Path) -> None:
    build_tree(tmp_path, {"requirements.txt": "", "fixtures/requirements.txt": ""})
    result = discover(tmp_path, DiscoveryOptions(exclude=("fixtures",)))
    assert [unit.directory for unit in result.units] == [PurePath(".")]


def test_max_depth_limits_the_walk(tmp_path: Path) -> None:
    build_tree(
        tmp_path,
        {"requirements.txt": "", "a/requirements.txt": "", "a/b/requirements.txt": ""},
    )
    directories = [
        unit.directory
        for unit in discover(tmp_path, DiscoveryOptions(max_depth=1)).units
    ]
    assert directories == [PurePath("."), PurePath("a")]


def test_ecosystem_filter(tmp_path: Path) -> None:
    build_tree(tmp_path, {"requirements.txt": "", "package.json": "{}"})
    options = DiscoveryOptions(ecosystems=frozenset({EcosystemId.NPM}))
    assert [unit.ecosystem for unit in discover(tmp_path, options).units] == [
        EcosystemId.NPM
    ]


# ---------------------------------------------------------------------------
# Pairing
# ---------------------------------------------------------------------------


def test_pairs_lockfile_with_manifest_in_same_directory(tmp_path: Path) -> None:
    build_tree(tmp_path, {"pyproject.toml": "", "uv.lock": ""})
    units = discover(tmp_path).units
    assert len(units) == 1
    assert units[0].manifests == (PurePath("pyproject.toml"),)
    assert units[0].lockfiles == (PurePath("uv.lock"),)
    assert units[0].has_lockfile


def test_lockfile_alone_is_still_a_scan_unit(tmp_path: Path) -> None:
    """Cargo.lock tells us everything; refusing to scan it would be perverse."""
    build_tree(tmp_path, {"Cargo.lock": ""})
    units = discover(tmp_path).units
    assert len(units) == 1
    assert units[0].lockfiles == (PurePath("Cargo.lock"),)
    assert units[0].manifests == ()


def test_go_mod_is_treated_as_a_lockfile(tmp_path: Path) -> None:
    """Its require block is already MVS-resolved, so it is authoritative."""
    build_tree(tmp_path, {"go.mod": "module example\n"})
    assert discover(tmp_path).units[0].lockfiles == (PurePath("go.mod"),)


def test_separate_directories_are_separate_units(tmp_path: Path) -> None:
    build_tree(tmp_path, {"a/package.json": "{}", "b/package.json": "{}"})
    assert len(discover(tmp_path).units) == 2


# ---------------------------------------------------------------------------
# Single-file targets and errors
# ---------------------------------------------------------------------------


def test_scanning_a_single_manifest(tmp_path: Path) -> None:
    build_tree(tmp_path, {"requirements.txt": "requests==2.31.0\n"})
    result = discover(tmp_path / "requirements.txt")
    assert result.units[0].manifests == (PurePath("requirements.txt"),)
    assert result.root == tmp_path.resolve()


def test_single_unrecognised_file_is_an_error(tmp_path: Path) -> None:
    build_tree(tmp_path, {"notes.txt": "hi"})
    with pytest.raises(DiscoveryError, match="not a recognised manifest"):
        discover(tmp_path / "notes.txt")


def test_missing_path_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(DiscoveryError, match="does not exist"):
        discover(tmp_path / "nope")


def test_oversized_file_is_skipped_not_dropped(tmp_path: Path) -> None:
    """A skipped file must be reported; silently dropping it would look clean."""
    build_tree(tmp_path, {"requirements.txt": "x" * 500})
    result = discover(tmp_path, DiscoveryOptions(max_file_bytes=100))
    assert result.units == ()
    assert len(result.skipped) == 1
    assert "exceeds size limit" in result.skipped[0].reason


def test_max_files_cap_reports_what_it_dropped(tmp_path: Path) -> None:
    build_tree(tmp_path, {f"p{i}/requirements.txt": "" for i in range(5)})
    result = discover(tmp_path, DiscoveryOptions(max_files=2))
    assert result.file_count == 2
    assert len(result.skipped) == 3
    assert all("max-files" in entry.reason for entry in result.skipped)
