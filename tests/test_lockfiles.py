"""Lockfile parsing and the shared graph resolver."""

from __future__ import annotations

from pathlib import Path

import pytest

from icebergsca.core.errors import ParseError, UnsupportedFileError
from icebergsca.core.graph import Node, most_included, resolve
from icebergsca.core.models import Dependency, Pin, Scope
from icebergsca.ecosystems import npm, python
from tests.conftest import FIXTURES


def load(ecosystem: str, case: str, filename: str) -> dict[str, Dependency]:
    """Parse a lockfile fixture, keyed by package name."""
    module = python if ecosystem == "python" else npm
    path = FIXTURES / ecosystem / case / filename
    return {
        dep.ref.name: dep
        for dep in module.parse_lockfile(
            Path(filename), path.read_text(encoding="utf-8")
        )
    }


# ---------------------------------------------------------------------------
# Graph resolver
# ---------------------------------------------------------------------------


def test_runtime_wins_over_dev_when_both_reach_a_package() -> None:
    """A package that ships still ships, whichever other path also reaches it."""
    nodes = {
        "app": Node("app", "app", children=("shared",)),
        "tool": Node("tool", "tool", children=("shared",)),
        "shared": Node("shared", "shared"),
    }
    result = {
        r.node.key: r.scope
        for r in resolve(nodes, {"app": Scope.RUNTIME, "tool": Scope.DEV})
    }
    assert result["shared"] is Scope.RUNTIME


def test_dev_only_package_stays_dev() -> None:
    nodes = {
        "tool": Node("tool", "tool", children=("helper",)),
        "helper": Node("helper", "helper"),
    }
    result = {r.node.key: r.scope for r in resolve(nodes, {"tool": Scope.DEV})}
    assert result["helper"] is Scope.DEV


def test_cycles_terminate() -> None:
    """Dependency graphs really do contain cycles, especially in npm."""
    nodes = {
        "a": Node("a", "a", children=("b",)),
        "b": Node("b", "b", children=("a",)),
    }
    assert len(resolve(nodes, {"a": Scope.RUNTIME})) == 2


def test_parents_are_recorded() -> None:
    nodes = {
        "app": Node("app", "app", children=("lib",)),
        "other": Node("other", "other", children=("lib",)),
        "lib": Node("lib", "lib"),
    }
    parents = {
        r.node.key: r.parents
        for r in resolve(nodes, {"app": Scope.RUNTIME, "other": Scope.RUNTIME})
    }
    assert set(parents["lib"]) == {"app", "other"}


def test_unreachable_nodes_are_kept_as_runtime() -> None:
    """Under-reporting a lockfile entry is worse than over-reporting it."""
    nodes = {"a": Node("a", "a"), "orphan": Node("orphan", "orphan")}
    result = resolve(nodes, {"a": Scope.RUNTIME})
    assert {r.node.key for r in result} == {"a", "orphan"}
    assert not next(r for r in result if r.node.key == "orphan").direct


def test_most_included_is_not_alphabetical() -> None:
    """min() over the raw enum values would rank build above runtime."""
    assert most_included([Scope.BUILD, Scope.RUNTIME]) is Scope.RUNTIME
    assert most_included([Scope.DEV, Scope.TEST]) is Scope.TEST
    assert most_included([]) is Scope.RUNTIME


# ---------------------------------------------------------------------------
# uv.lock
# ---------------------------------------------------------------------------


def test_uv_lock_pins_every_version() -> None:
    deps = load("python", "uvlock", "uv.lock")
    assert deps["httpx"].ref.version == "0.27.0"
    assert all(dep.pin is Pin.PINNED for dep in deps.values())


def test_uv_lock_marks_root_dependencies_direct() -> None:
    deps = load("python", "uvlock", "uv.lock")
    assert deps["httpx"].direct is True
    assert deps["anyio"].direct is False


def test_uv_lock_excludes_the_project_itself() -> None:
    """A project is not its own dependency."""
    assert "example-app" not in load("python", "uvlock", "uv.lock")


def test_uv_lock_propagates_dev_scope_through_transitives() -> None:
    deps = load("python", "uvlock", "uv.lock")
    assert deps["pytest"].scope is Scope.DEV
    assert deps["pluggy"].scope is Scope.DEV


def test_uv_lock_traverses_extras_of_transitive_packages() -> None:
    """tomli is reachable only through coverage[toml].

    Without traversing a transitive package's own extras it is unreachable, and an
    unreachable node has to be assumed to ship — which reported this dev-only
    package as a runtime dependency.
    """
    deps = load("python", "uvlock", "uv.lock")
    assert deps["coverage"].scope is Scope.DEV
    assert deps["tomli"].scope is Scope.DEV
    assert [ref.name for ref in deps["tomli"].parents] == ["coverage"]


def test_uv_lock_records_parents() -> None:
    deps = load("python", "uvlock", "uv.lock")
    assert [ref.name for ref in deps["idna"].parents] == ["anyio"]


def test_uv_lock_merges_scopes_across_groups_by_inclusion() -> None:
    """A package in both a dev-flavoured extra and an ordinary one installs whenever
    either is asked for, so the most-included scope must win — first-wins would let
    the ``docs`` group hide it from the default scan."""
    content = """\
version = 1

[[package]]
name = "example-app"
version = "0.1.0"
source = { editable = "." }

[package.optional-dependencies]
docs = [{ name = "sphinx" }]
gui = [{ name = "sphinx" }]

[[package]]
name = "sphinx"
version = "7.0.0"
source = { registry = "https://pypi.org/simple" }
"""
    deps = {d.ref.name: d for d in python.parse_lockfile(Path("uv.lock"), content)}
    assert deps["sphinx"].scope is Scope.OPTIONAL


def test_uv_lock_rejects_a_file_with_no_packages() -> None:
    with pytest.raises(ParseError, match="no \\[\\[package\\]\\] entries"):
        python.parse_lockfile(Path("uv.lock"), "version = 1\n")


# ---------------------------------------------------------------------------
# poetry.lock
# ---------------------------------------------------------------------------


def test_poetry_lock_reads_groups() -> None:
    deps = load("python", "poetrylock", "poetry.lock")
    assert deps["requests"].scope is Scope.RUNTIME
    assert deps["black"].scope is Scope.DEV


def test_poetry_lock_pins_versions_and_records_edges() -> None:
    deps = load("python", "poetrylock", "poetry.lock")
    assert deps["urllib3"].ref.version == "2.2.1"
    assert [ref.name for ref in deps["urllib3"].parents] == ["requests"]


def test_poetry_lock_falls_back_to_category() -> None:
    """Poetry 1.x wrote `category` rather than `groups`."""
    content = (
        '[[package]]\nname = "black"\nversion = "24.0.0"\ncategory = "dev"\n'
        '\n[[package]]\nname = "requests"\nversion = "2.31.0"\ncategory = "main"\n'
    )
    deps = {d.ref.name: d for d in python.parse_lockfile(Path("poetry.lock"), content)}
    assert deps["black"].scope is Scope.DEV
    assert deps["requests"].scope is Scope.RUNTIME


# ---------------------------------------------------------------------------
# Pipfile / Pipfile.lock
# ---------------------------------------------------------------------------


def test_pipfile_lock_separates_default_from_develop() -> None:
    deps = load("python", "pipenv", "Pipfile.lock")
    assert deps["requests"].ref.version == "2.31.0"
    assert deps["requests"].scope is Scope.RUNTIME
    assert deps["pytest"].scope is Scope.DEV


def test_pipfile_lock_does_not_guess_directness() -> None:
    """It flattens direct and transitive together; the Pipfile supplies the rest."""
    assert all(
        not dep.direct for dep in load("python", "pipenv", "Pipfile.lock").values()
    )


def test_pipfile_manifest_reads_both_sections() -> None:
    path = FIXTURES / "python" / "pipenv" / "Pipfile"
    deps = {
        d.ref.name: d for d in python.parse_manifest(Path("Pipfile"), path.read_text())
    }
    assert deps["requests"].ref.version == "2.31.0"
    assert deps["pytest"].scope is Scope.DEV
    # "*" is a constraint carrying no information, not a version.
    assert deps["flask"].ref.version is None
    assert deps["flask"].constraint is None


def test_pipfile_wildcard_equality_is_a_range_not_a_pin() -> None:
    """``==2.*`` sliced to the "version" ``2.*`` would be sent to OSV, match no
    advisory range, and read as clean. ``===2.0.0`` is the opposite case: a real
    pin that the naive slice mangled into ``=2.0.0``."""
    content = '[packages]\nrequests = "==2.*"\nflask = "===2.0.0"\n'
    deps = {d.ref.name: d for d in python.parse_manifest(Path("Pipfile"), content)}

    assert deps["requests"].ref.version is None
    assert deps["requests"].pin is Pin.UNRESOLVED
    assert deps["requests"].constraint == "==2.*"

    assert deps["flask"].ref.version == "2.0.0"
    assert deps["flask"].pin is Pin.PINNED


# ---------------------------------------------------------------------------
# package.json
# ---------------------------------------------------------------------------


def npm_manifest() -> dict[str, Dependency]:
    path = FIXTURES / "npm" / "manifest" / "package.json"
    return {
        d.ref.name: d
        for d in npm.parse_manifest(Path("package.json"), path.read_text())
    }


def test_package_json_scopes() -> None:
    deps = npm_manifest()
    assert deps["lodash"].scope is Scope.RUNTIME
    assert deps["jest"].scope is Scope.DEV
    assert deps["fsevents"].scope is Scope.OPTIONAL
    # Peer dependencies are the consumer's to install, not ours to ship.
    assert deps["react"].scope is Scope.OPTIONAL


def test_package_json_pins_exact_versions_only() -> None:
    deps = npm_manifest()
    assert (deps["express"].ref.version, deps["express"].pin) == ("4.19.2", Pin.PINNED)
    assert deps["lodash"].pin is Pin.UNRESOLVED
    assert deps["lodash"].constraint == "^4.17.21"


def test_package_json_keeps_scoped_names_intact() -> None:
    assert npm_manifest()["@scope/widget"].ref.purl == "pkg:npm/%40scope/widget"


def test_package_json_skips_non_registry_specs() -> None:
    """file: and git+ specs name a location, not something OSV can be asked about."""
    deps = npm_manifest()
    assert "local-lib" not in deps
    assert "forked-thing" not in deps


def test_package_json_skips_wildcard_specs() -> None:
    assert "anything" not in npm_manifest()


def test_package_json_rejects_invalid_json() -> None:
    with pytest.raises(ParseError, match="invalid JSON"):
        npm.parse_manifest(Path("package.json"), "{not json")


# ---------------------------------------------------------------------------
# package-lock.json
# ---------------------------------------------------------------------------


def test_lock_v3_uses_npms_own_scope_flags() -> None:
    deps = load("npm", "lock-v3", "package-lock.json")
    assert deps["express"].scope is Scope.RUNTIME
    assert deps["jest"].scope is Scope.DEV
    assert deps["chalk"].scope is Scope.DEV
    assert deps["fsevents"].scope is Scope.OPTIONAL


def test_lock_v3_dev_optional_still_ships() -> None:
    """npm's devOptional flag means "dev tree *and* optional dep of something that
    ships" — a production install still gets it, so it must not be classed as dev,
    which the default scan excludes."""
    content = """{
      "lockfileVersion": 3,
      "packages": {
        "": {"dependencies": {"sharp": "^0.33.0"}},
        "node_modules/sharp": {
          "version": "0.33.0",
          "dependencies": {"detect-libc": "^2.0.0"}
        },
        "node_modules/detect-libc": {"version": "2.0.3", "devOptional": true}
      }
    }"""
    deps = {
        d.ref.name: d for d in npm.parse_lockfile(Path("package-lock.json"), content)
    }
    assert deps["detect-libc"].scope is Scope.OPTIONAL


def test_lock_v3_marks_root_dependencies_direct() -> None:
    deps = load("npm", "lock-v3", "package-lock.json")
    assert deps["express"].direct is True
    assert deps["debug"].direct is False


def test_lock_v3_resolves_nested_copies_separately() -> None:
    """ms exists at 2.0.0 nested under debug and 2.1.3 hoisted; both are real."""
    parsed = npm.parse_lockfile(
        Path("package-lock.json"),
        (FIXTURES / "npm" / "lock-v3" / "package-lock.json").read_text(),
    )
    versions = sorted(d.ref.version or "" for d in parsed if d.ref.name == "ms")
    assert versions == ["2.0.0", "2.1.3"]


def test_lock_v3_edges_follow_node_resolution() -> None:
    """debug requires ms 2.0.0, which is its *nested* copy, not the hoisted one."""
    parsed = npm.parse_lockfile(
        Path("package-lock.json"),
        (FIXTURES / "npm" / "lock-v3" / "package-lock.json").read_text(),
    )
    nested = next(d for d in parsed if d.ref.name == "ms" and d.ref.version == "2.0.0")
    assert [ref.name for ref in nested.parents] == ["debug"]


def test_lock_v3_excludes_the_root_entry() -> None:
    assert "example-app" not in load("npm", "lock-v3", "package-lock.json")


def test_lock_v1_nested_tree() -> None:
    deps = load("npm", "lock-v1", "package-lock.json")
    assert deps["express"].ref.version == "4.19.2"
    assert deps["jest"].scope is Scope.DEV


def test_lock_v1_keeps_both_copies_of_a_nested_package() -> None:
    parsed = npm.parse_lockfile(
        Path("package-lock.json"),
        (FIXTURES / "npm" / "lock-v1" / "package-lock.json").read_text(),
    )
    assert sorted(d.ref.version or "" for d in parsed if d.ref.name == "ms") == [
        "2.0.0",
        "2.1.3",
    ]


def test_package_lock_without_a_recognised_shape_fails_clearly() -> None:
    with pytest.raises(UnsupportedFileError, match="lockfileVersion"):
        npm.parse_lockfile(Path("package-lock.json"), '{"lockfileVersion": 9}')


def nested_v1() -> list[Dependency]:
    return npm.parse_lockfile(
        Path("package-lock.json"),
        (FIXTURES / "npm" / "lock-v1-nested" / "package-lock.json").read_text(),
    )


def test_lock_v1_edges_prefer_a_privately_nested_copy() -> None:
    """Node resolves from the requiring package's own directory outwards.

    ``inner`` has its own ``ms@2.0.0`` installed beneath it, so that is the copy it
    loads. Starting the walk one level too high found the hoisted ``ms@9.9.9``
    instead — an edge to a version that package never sees, which misattributes
    every finding reported against it.
    """
    parsed = nested_v1()
    inner_ms = next(
        d for d in parsed if d.ref.name == "ms" and d.ref.version == "2.0.0"
    )
    hoisted = next(d for d in parsed if d.ref.name == "ms" and d.ref.version == "9.9.9")
    assert [ref.name for ref in inner_ms.parents] == ["inner"]
    assert hoisted.parents == ()


def test_lock_v1_nested_copies_are_still_reachable() -> None:
    """An unreachable node defaults to runtime, hiding the scope it really has."""
    parsed = nested_v1()
    inner_ms = next(
        d for d in parsed if d.ref.name == "ms" and d.ref.version == "2.0.0"
    )
    assert inner_ms.direct is False


# ---------------------------------------------------------------------------
# pnpm-lock.yaml
# ---------------------------------------------------------------------------


def test_pnpm_unreadable_lockfile_version_is_refused_by_name() -> None:
    """An old pnpm wrote ``lockfileVersion: 'v5'``, which is not a float.

    Letting the conversion raise turned a supported-version problem into an opaque
    "parser error", which reads like a bug in us rather than a file we decline.
    """
    with pytest.raises(UnsupportedFileError, match="lockfileVersion"):
        npm.parse_lockfile(
            Path("pnpm-lock.yaml"), "lockfileVersion: 'v5'\npackages: {}"
        )


def test_pnpm_reads_importers_as_seeds() -> None:
    deps = load("npm", "pnpm", "pnpm-lock.yaml")
    assert deps["express"].direct is True
    assert deps["debug"].direct is False


def test_pnpm_propagates_dev_scope() -> None:
    deps = load("npm", "pnpm", "pnpm-lock.yaml")
    assert deps["jest"].scope is Scope.DEV
    assert deps["chalk"].scope is Scope.DEV
    assert deps["express"].scope is Scope.RUNTIME


def test_pnpm_merges_packages_and_snapshots() -> None:
    """v9 splits metadata from edges; both halves are needed for a full graph."""
    deps = load("npm", "pnpm", "pnpm-lock.yaml")
    assert deps["ms"].ref.version == "2.0.0"
    assert [ref.name for ref in deps["ms"].parents] == ["debug"]


def test_pnpm_rejects_ancient_lockfile_versions() -> None:
    with pytest.raises(UnsupportedFileError, match="not supported"):
        npm.parse_lockfile(Path("pnpm-lock.yaml"), "lockfileVersion: '5.4'\n")


# ---------------------------------------------------------------------------
# yarn.lock
# ---------------------------------------------------------------------------


def test_yarn_v1_parses_the_bespoke_format() -> None:
    deps = load("npm", "yarn-v1", "yarn.lock")
    assert deps["express"].ref.version == "4.19.2"
    assert deps["@scope/widget"].ref.version == "2.0.1"


def test_yarn_v1_resolves_edges_through_the_descriptor_index() -> None:
    """An edge names the requested range, which appears verbatim as another key."""
    parsed = npm.parse_lockfile(
        Path("yarn.lock"), (FIXTURES / "npm" / "yarn-v1" / "yarn.lock").read_text()
    )
    nested = next(d for d in parsed if d.ref.name == "ms" and d.ref.version == "2.0.0")
    assert [ref.name for ref in nested.parents] == ["debug"]


def test_yarn_v1_reads_quoted_scoped_dependency_edges() -> None:
    """yarn quotes scoped packages in dependency lists — ``"@scope/widget" "^2.0.0"``
    — and a key pattern that cannot match the quotes drops every such edge."""
    deps = load("npm", "yarn-v1", "yarn.lock")
    assert [ref.name for ref in deps["@scope/widget"].parents] == ["app-ui"]


def test_yarn_v1_keeps_both_resolved_versions() -> None:
    parsed = npm.parse_lockfile(
        Path("yarn.lock"), (FIXTURES / "npm" / "yarn-v1" / "yarn.lock").read_text()
    )
    assert sorted(d.ref.version or "" for d in parsed if d.ref.name == "ms") == [
        "2.0.0",
        "2.1.3",
    ]


def test_yarn_berry_is_parsed_as_yaml() -> None:
    deps = load("npm", "yarn-berry", "yarn.lock")
    assert deps["express"].ref.version == "4.19.2"
    assert deps["debug"].ref.version == "2.6.9"


def test_yarn_berry_resolves_npm_protocol_edges() -> None:
    deps = load("npm", "yarn-berry", "yarn.lock")
    assert [ref.name for ref in deps["ms"].parents] == ["debug"]


def test_yarn_empty_file_fails_rather_than_reporting_nothing() -> None:
    with pytest.raises(ParseError, match="no lockfile entries"):
        npm.parse_lockfile(Path("yarn.lock"), "# yarn lockfile v1\n")
