"""Python manifest parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from icebergsca.core.errors import ParseError
from icebergsca.core.models import Dependency, Pin, Scope
from icebergsca.ecosystems.python import parse_manifest
from tests.conftest import FIXTURES


def parse(case: str) -> dict[str, Dependency]:
    """Parse the single manifest in a fixture directory, keyed by package name.

    Fixtures live in directories so each file keeps its real name — the parser
    dispatches on the filename, so a fixture called ``pyproject-poetry.toml`` would
    silently be parsed as a requirements file and prove nothing.
    """
    directory = FIXTURES / "python" / case
    path = next(entry for entry in sorted(directory.iterdir()) if entry.is_file())
    return {
        dep.ref.name: dep
        for dep in parse_manifest(Path(path.name), path.read_text(encoding="utf-8"))
    }


# ---------------------------------------------------------------------------
# requirements.txt
# ---------------------------------------------------------------------------


def test_requirements_pins_exact_equality() -> None:
    dep = parse("basic")["requests"]
    assert dep.ref.version == "2.31.0"
    assert dep.pin is Pin.PINNED


def test_requirements_keeps_ranges_unresolved_with_the_constraint() -> None:
    """The raw constraint is retained so the resolver has something to work with."""
    dep = parse("basic")["flask"]
    assert dep.ref.version is None
    assert dep.pin is Pin.UNRESOLVED
    assert dep.constraint == "<3.0,>=2.0"


def test_requirements_bare_package_has_no_constraint() -> None:
    dep = parse("basic")["django"]
    assert (dep.ref.version, dep.pin, dep.constraint) == (None, Pin.UNRESOLVED, None)


def test_requirements_normalises_names() -> None:
    assert "django" in parse("basic")
    assert "Django" not in parse("basic")


def test_requirements_strips_extras() -> None:
    dep = parse("basic")["urllib3"]
    assert dep.ref.version == "2.2.1"


def test_requirements_strips_inline_comments() -> None:
    assert parse("basic")["pyyaml"].ref.version == "6.0.1"


@pytest.mark.parametrize("skipped", ["base.txt", "foo", "bar", "-e", "-r"])
def test_requirements_skips_options_urls_and_vcs(skipped: str) -> None:
    assert skipped not in parse("basic")


def test_requirements_keeps_dependencies_behind_markers() -> None:
    """Over-reporting is the safe direction: a marker may still be satisfied."""
    assert parse("basic")["importlib-metadata"].ref.version == "7.1.0"


def test_requirements_joins_backslash_continuations() -> None:
    assert parse("basic")["starlette"].ref.version == "0.37.2"


def test_requirements_records_line_numbers() -> None:
    assert parse("basic")["requests"].source.line == 2


# ---------------------------------------------------------------------------
# pip-compile annotations
# ---------------------------------------------------------------------------


def test_pip_compile_via_package_means_transitive() -> None:
    deps = parse("compiled")
    assert deps["anyio"].direct is False
    assert deps["click"].direct is False


def test_pip_compile_via_requirements_in_means_direct() -> None:
    deps = parse("compiled")
    assert deps["fastapi"].direct is True
    assert deps["typer"].direct is True


def test_pip_compile_multiline_via_block_is_consumed_not_parsed() -> None:
    """The names inside a ``# via`` block are annotations, not dependencies."""
    deps = parse("compiled")
    assert set(deps) == {"anyio", "click", "fastapi", "h11", "typer"}


# ---------------------------------------------------------------------------
# pyproject.toml
# ---------------------------------------------------------------------------


def test_pep621_runtime_dependencies() -> None:
    deps = parse("pep621")
    assert deps["httpx"].scope is Scope.RUNTIME
    assert deps["pydantic-core"].ref.version == "2.18.2"


def test_pep621_optional_groups_get_meaningful_scopes() -> None:
    deps = parse("pep621")
    assert deps["ruff"].scope is Scope.DEV
    assert deps["pytest"].scope is Scope.TEST
    # An extra that is not obviously tooling stays optional rather than being
    # guessed into dev and filtered out of the default scan.
    assert deps["typer"].scope is Scope.OPTIONAL


def test_pep735_dependency_groups() -> None:
    assert parse("pep621")["mypy"].scope is Scope.DEV


def test_build_requires_are_build_scope() -> None:
    """Build tooling reaches the artefact, so it is in scope by default."""
    assert parse("pep621")["hatchling"].scope is Scope.BUILD


def test_poetry_caret_constraints_stay_unresolved() -> None:
    """Caret is not PEP 440 and must not be mistaken for a version."""
    dep = parse("poetry")["requests"]
    assert (dep.ref.version, dep.pin, dep.constraint) == (
        None,
        Pin.UNRESOLVED,
        "^2.31.0",
    )


def test_poetry_exact_version_is_pinned() -> None:
    dep = parse("poetry")["pinned-thing"]
    assert (dep.ref.version, dep.pin) == ("1.2.3", Pin.PINNED)


def test_poetry_table_form_reads_the_version_key() -> None:
    assert parse("poetry")["tabled"].constraint == "~1.4"


def test_poetry_skips_python_and_path_dependencies() -> None:
    deps = parse("poetry")
    assert "python" not in deps
    assert "local-pkg" not in deps


def test_poetry_groups_map_to_scopes() -> None:
    deps = parse("poetry")
    assert deps["black"].scope is Scope.DEV
    assert deps["pytest"].scope is Scope.TEST


def test_invalid_toml_raises_parse_error_naming_the_file() -> None:
    with pytest.raises(ParseError, match=r"pyproject\.toml: invalid TOML"):
        parse_manifest(Path("pyproject.toml"), "not [ valid")


# ---------------------------------------------------------------------------
# setup.cfg
# ---------------------------------------------------------------------------


def test_setup_cfg_install_requires() -> None:
    deps = parse("setupcfg")
    assert deps["requests"].ref.version == "2.31.0"
    assert deps["jinja2"].scope is Scope.RUNTIME


def test_setup_cfg_extras_require() -> None:
    assert parse("setupcfg")["pytest"].scope is Scope.DEV
