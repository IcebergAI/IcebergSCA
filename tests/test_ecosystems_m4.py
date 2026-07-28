"""Go, Rust, .NET and Ruby parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from icebergsca.core.errors import ParseError
from icebergsca.core.models import Dependency, EcosystemId, Pin, Scope
from icebergsca.ecosystems import dotnet, golang, ruby, rust
from tests.conftest import FIXTURES


def by_name(dependencies: list[Dependency]) -> dict[str, Dependency]:
    return {dep.ref.name: dep for dep in dependencies}


def read(ecosystem: str, case: str, filename: str) -> str:
    return (FIXTURES / ecosystem / case / filename).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------


def go_mod() -> dict[str, Dependency]:
    return by_name(
        golang.SPEC.parse_lockfile(Path("go.mod"), read("go", "basic", "go.mod"))
    )


def test_go_reads_require_blocks_and_single_lines() -> None:
    deps = go_mod()
    assert deps["golang.org/x/crypto"].ref.version == "v0.17.0"
    assert deps["github.com/pkg/errors"].ref.version == "v0.9.1"


def test_go_indirect_marks_transitive() -> None:
    """The // indirect comment is the only record of directness that go.mod keeps."""
    deps = go_mod()
    assert deps["github.com/stretchr/testify"].direct is True
    assert deps["golang.org/x/sys"].direct is False
    assert deps["github.com/bytedance/sonic"].direct is False


def test_go_versions_are_always_pinned() -> None:
    """MVS has already run: every version in go.mod is the one that builds."""
    assert all(dep.pin is Pin.PINNED for dep in go_mod().values())


def test_go_replace_directive_redirects_to_what_actually_builds() -> None:
    deps = go_mod()
    assert "github.com/gin-gonic/gin" not in deps
    assert deps["github.com/forked/gin"].ref.version == "v1.9.2"


def test_go_local_replacement_is_dropped_not_misattributed() -> None:
    """A path replacement has nothing to look up, and the original is not built."""
    assert "github.com/local/thing" not in go_mod()


def replace_mod() -> dict[str, Dependency]:
    return by_name(
        golang.SPEC.parse_lockfile(Path("go.mod"), read("go", "replace", "go.mod"))
    )


def test_go_replace_survives_a_trailing_comment() -> None:
    """A comment on the replace line must not cost us the module entirely.

    The right-hand side is greedy, so an unstripped ``// patched upstream`` made the
    version unparseable — and an unversioned replacement is dropped. The module then
    appeared under neither name and vanished from the scan without a warning.
    """
    deps = replace_mod()
    assert deps["github.com/example/errors"].ref.version == "v1.2.3"
    assert "github.com/pkg/errors" not in deps


def test_go_commented_local_replacement_is_still_recognised_as_local() -> None:
    deps = replace_mod()
    assert "github.com/stretchr/testify" not in deps
    assert deps["golang.org/x/text"].ref.version == "v0.14.0"


def test_go_ignores_exclude_directives() -> None:
    assert "github.com/bad/module" not in go_mod()


def test_go_purl_encodes_the_module_path() -> None:
    ref = go_mod()["github.com/pkg/errors"].ref
    assert ref.purl == "pkg:golang/github.com/pkg/errors@v0.9.1"


def test_go_empty_file_is_an_error_not_a_clean_result() -> None:
    with pytest.raises(ParseError, match="no module declaration"):
        golang.SPEC.parse_lockfile(Path("go.mod"), "\n# nothing here\n")


def test_go_module_with_no_dependencies_is_fine() -> None:
    assert (
        golang.SPEC.parse_lockfile(Path("go.mod"), "module example\n\ngo 1.22\n") == []
    )


# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------


def cargo_lock() -> dict[str, Dependency]:
    return by_name(
        rust.parse_lockfile(Path("Cargo.lock"), read("rust", "basic", "Cargo.lock"))
    )


def cargo_toml() -> dict[str, Dependency]:
    return by_name(
        rust.parse_manifest(Path("Cargo.toml"), read("rust", "basic", "Cargo.toml"))
    )


def test_cargo_lock_pins_and_links() -> None:
    deps = cargo_lock()
    assert deps["serde"].ref.version == "1.0.197"
    assert [ref.name for ref in deps["serde_derive"].parents] == ["serde"]


def test_cargo_lock_excludes_workspace_members() -> None:
    """A package with no source is the project itself, not a dependency."""
    assert "example-app" not in cargo_lock()


def test_cargo_lock_seeds_directness_from_workspace_members() -> None:
    deps = cargo_lock()
    assert deps["serde"].direct is True
    assert deps["serde_derive"].direct is False


def test_cargo_lock_dependency_entries_may_carry_a_version() -> None:
    """Entries are "name" or "name version"; only the name identifies the edge."""
    assert [ref.name for ref in cargo_lock()["proc-macro2"].parents] == ["serde_derive"]


def duplicate_lock() -> list[Dependency]:
    return rust.parse_lockfile(
        Path("Cargo.lock"), read("rust", "duplicate-versions", "Cargo.lock")
    )


def test_cargo_lock_keeps_every_version_of_a_duplicated_crate() -> None:
    """Keying the graph on the bare name dropped all but the last copy.

    Rust locks two majors of a crate side by side routinely. Collapsing them reports
    only whichever came last in the file, so a vulnerable older copy that is genuinely
    installed disappears — the exact false-clean this tool exists to avoid.
    """
    versions = {
        dep.ref.version for dep in duplicate_lock() if dep.ref.name == "windows-sys"
    }
    assert versions == {"0.48.0", "0.52.0"}


def test_cargo_lock_versioned_edges_point_at_the_right_copy() -> None:
    deps = duplicate_lock()
    old = next(d for d in deps if d.ref.version == "0.48.0")
    new = next(d for d in deps if d.ref.version == "0.52.0")
    assert [ref.name for ref in old.parents] == ["legacy-dep"]
    assert new.parents == ()
    assert new.direct is True


def test_cargo_toml_scopes() -> None:
    deps = cargo_toml()
    assert deps["serde"].scope is Scope.RUNTIME
    assert deps["criterion"].scope is Scope.DEV
    assert deps["cc"].scope is Scope.BUILD


def test_cargo_toml_reads_target_specific_dependencies() -> None:
    assert cargo_toml()["winapi"].scope is Scope.RUNTIME


def test_cargo_bare_version_is_a_caret_range_not_a_pin() -> None:
    """Cargo treats "1.36" as "^1.36"; only "=1.2.3" actually pins."""
    deps = cargo_toml()
    assert deps["tokio"].pin is Pin.UNRESOLVED
    assert deps["exactly"].pin is Pin.PINNED
    assert deps["exactly"].ref.version == "1.2.3"


def test_cargo_path_dependency_is_skipped() -> None:
    assert "locally" not in cargo_toml()


# ---------------------------------------------------------------------------
# .NET
# ---------------------------------------------------------------------------


def csproj() -> dict[str, Dependency]:
    return by_name(
        dotnet.parse_manifest(
            Path("App.csproj"), read("dotnet", "csproj", "App.csproj")
        )
    )


def packages_lock() -> dict[str, Dependency]:
    return by_name(
        dotnet.parse_lockfile(
            Path("packages.lock.json"), read("dotnet", "lock", "packages.lock.json")
        )
    )


def test_csproj_reads_package_references() -> None:
    deps = csproj()
    assert deps["Newtonsoft.Json"].ref.version == "13.0.3"
    assert deps["Newtonsoft.Json"].pin is Pin.PINNED


def test_csproj_version_as_a_child_element() -> None:
    """MSBuild allows Version as an attribute or a nested element."""
    assert csproj()["Legacy.Style"].ref.version == "1.0.0"


def test_csproj_unresolved_msbuild_property_is_not_a_version() -> None:
    dep = csproj()["Serilog"]
    assert dep.ref.version is None
    assert dep.pin is Pin.UNRESOLVED
    assert dep.constraint == "$(SerilogVersion)"


def test_csproj_interval_ranges_are_constraints() -> None:
    dep = csproj()["AWSSDK.Core"]
    assert dep.ref.version is None
    assert dep.constraint == "[3.7.0,4.0.0)"


def test_csproj_bracketed_equality_is_a_pin() -> None:
    assert csproj()["Pinned.Package"].ref.version == "2.1.0"


def test_csproj_private_assets_means_build_scope() -> None:
    """An analyser still runs during the build, so it is not merely a dev dependency."""
    assert csproj()["StyleCop.Analyzers"].scope is Scope.BUILD


def test_csproj_rejects_invalid_xml() -> None:
    with pytest.raises(ParseError, match="invalid XML"):
        dotnet.parse_manifest(Path("App.csproj"), "<Project><unclosed>")


def test_packages_lock_uses_its_own_direct_labels() -> None:
    deps = packages_lock()
    assert deps["Newtonsoft.Json"].direct is True
    assert deps["Serilog"].direct is False


def test_packages_lock_resolves_versions_and_edges() -> None:
    deps = packages_lock()
    assert deps["Serilog"].ref.version == "2.12.0"
    assert [ref.name for ref in deps["Serilog"].parents] == ["Serilog.Sinks.Console"]


def test_packages_lock_rejects_a_file_with_no_dependencies_section() -> None:
    with pytest.raises(ParseError, match="no dependencies section"):
        dotnet.parse_lockfile(Path("packages.lock.json"), '{"version": 1}')


# ---------------------------------------------------------------------------
# Ruby
# ---------------------------------------------------------------------------


def gemfile_lock() -> dict[str, Dependency]:
    return by_name(
        ruby.parse_lockfile(Path("Gemfile.lock"), read("ruby", "basic", "Gemfile.lock"))
    )


def gemfile() -> dict[str, Dependency]:
    return by_name(
        ruby.parse_manifest(Path("Gemfile"), read("ruby", "basic", "Gemfile"))
    )


def test_gemfile_lock_reads_versions_from_indentation() -> None:
    deps = gemfile_lock()
    assert deps["actionpack"].ref.version == "7.1.3"
    assert deps["concurrent-ruby"].ref.version == "1.2.3"


def test_gemfile_lock_builds_edges_from_nesting() -> None:
    deps = gemfile_lock()
    assert sorted(ref.name for ref in deps["activesupport"].parents) == ["actionpack"]
    assert [ref.name for ref in deps["concurrent-ruby"].parents] == ["activesupport"]


def test_gemfile_lock_dependencies_section_marks_direct() -> None:
    deps = gemfile_lock()
    assert deps["actionpack"].direct is True
    assert deps["activesupport"].direct is False


def test_gemfile_lock_nested_names_are_not_mistaken_for_gems() -> None:
    """A six-space line is a dependency edge, not a separate resolved gem."""
    assert gemfile_lock()["rack"].ref.version == "3.0.9"


def test_gemfile_groups_map_to_scopes() -> None:
    deps = gemfile()
    assert deps["actionpack"].scope is Scope.RUNTIME
    assert deps["capybara"].scope is Scope.TEST
    # Declared in both :development and :test, so the most-included of the two wins.
    assert deps["rspec"].scope is Scope.TEST


def test_gemfile_group_block_ends_at_end() -> None:
    """A gem after the block closes is runtime again, not still grouped."""
    assert gemfile()["sidekiq"].scope is Scope.RUNTIME


def test_gemfile_exact_version_is_pinned_but_a_range_is_not() -> None:
    deps = gemfile()
    assert (deps["puma"].ref.version, deps["puma"].pin) == ("6.4.2", Pin.PINNED)
    assert deps["actionpack"].pin is Pin.UNRESOLVED
    assert deps["actionpack"].constraint == "~> 7.1"


def test_ruby_purl_type_is_gem() -> None:
    assert gemfile_lock()["rack"].ref.purl == "pkg:gem/rack@3.0.9"


def test_every_ecosystem_uses_its_own_id() -> None:
    assert go_mod()["github.com/pkg/errors"].ref.ecosystem is EcosystemId.GO
    assert cargo_lock()["serde"].ref.ecosystem is EcosystemId.CARGO
    assert packages_lock()["Serilog"].ref.ecosystem is EcosystemId.NUGET
    assert gemfile_lock()["rack"].ref.ecosystem is EcosystemId.RUBYGEMS
