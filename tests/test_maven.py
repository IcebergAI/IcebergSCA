"""Maven and Gradle parsing, and effective-POM resolution."""

from __future__ import annotations

from pathlib import Path, PurePath

import httpx
import pytest

from icebergsca.cache import Cache
from icebergsca.core.errors import ParseError
from icebergsca.core.models import (
    Dependency,
    EcosystemId,
    PackageRef,
    Pin,
    Scope,
    SourceLocation,
)
from icebergsca.core.scanner import ScanOptions, scan
from icebergsca.ecosystems.maven import MavenResolver, MavenUnit, parse_manifest
from icebergsca.ecosystems.maven.model import Coordinate
from icebergsca.ecosystems.maven.parser import interpolate, parse_pom
from icebergsca.ecosystems.maven.resolver import CENTRAL
from tests.conftest import FIXTURES, MockTransport


def read(case: str, filename: str) -> str:
    return (FIXTURES / "maven" / case / filename).read_text(encoding="utf-8")


def pom_deps() -> dict[str, Dependency]:
    return {
        dep.ref.name: dep
        for dep in parse_manifest(Path("pom.xml"), read("basic", "pom.xml"))
    }


def gradle_deps() -> dict[str, Dependency]:
    return {
        dep.ref.name: dep
        for dep in parse_manifest(Path("build.gradle"), read("gradle", "build.gradle"))
    }


# ---------------------------------------------------------------------------
# POM structure
# ---------------------------------------------------------------------------


def test_pom_parses_through_the_default_namespace() -> None:
    """Real POMs declare a default namespace; raw tag matching misses everything."""
    pom = parse_pom(read("basic", "pom.xml"))
    assert pom.coordinate.artifact == "demo"
    assert len(pom.dependencies) == 6


def test_pom_inherits_group_and_version_from_its_parent() -> None:
    pom = parse_pom(read("basic", "pom.xml"))
    assert pom.parent is not None
    assert pom.parent.artifact == "parent-pom"
    # The POM declares neither groupId nor version of its own.
    assert pom.coordinate.group == "com.example"
    assert pom.coordinate.version == "2.0.0"


def test_pom_reads_exclusions() -> None:
    pom = parse_pom(read("basic", "pom.xml"))
    guava = next(d for d in pom.dependencies if d.artifact == "guava")
    assert guava.exclusions == frozenset({"com.google.code.findbugs:jsr305"})


def test_pom_dependency_management_is_kept_separate_from_dependencies() -> None:
    """It is a version *policy*, not a dependency — conflating them over-reports."""
    pom = parse_pom(read("basic", "pom.xml"))
    assert [entry.artifact for entry in pom.managed] == ["slf4j-api"]


def test_invalid_pom_raises_parse_error() -> None:
    with pytest.raises(ParseError, match="invalid XML"):
        parse_pom("<project><unclosed>", source="pom.xml")


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


def test_property_interpolation() -> None:
    deps = pom_deps()
    assert deps["com.fasterxml.jackson.core:jackson-databind"].ref.version == "2.9.8"
    assert deps["com.google.guava:guava"].ref.version == "31.1-jre"


def test_undefined_property_stays_unresolved_rather_than_becoming_empty() -> None:
    """Blanking a ${...} would turn "we don't know" into "no version"."""
    dep = pom_deps()["com.example:mystery"]
    assert dep.ref.version is None
    assert dep.pin is Pin.UNRESOLVED
    assert dep.constraint == "${undefined.version}"


def test_interpolation_terminates_on_self_referencing_properties() -> None:
    assert interpolate("${a}", {"a": "${a}"}) == "${a}"


def test_local_dependency_management_supplies_a_missing_version() -> None:
    assert pom_deps()["org.slf4j:slf4j-api"].ref.version == "1.7.36"


# ---------------------------------------------------------------------------
# Scopes
# ---------------------------------------------------------------------------


def test_maven_scopes_map_onto_ours() -> None:
    deps = pom_deps()
    assert deps["com.fasterxml.jackson.core:jackson-databind"].scope is Scope.RUNTIME
    assert deps["junit:junit"].scope is Scope.TEST
    # provided is compiled against, so it reaches the artefact even if the container
    # supplies it at runtime.
    assert deps["javax.servlet:javax.servlet-api"].scope is Scope.BUILD


def test_maven_names_are_group_colon_artifact() -> None:
    ref = pom_deps()["com.google.guava:guava"].ref
    assert ref.purl == "pkg:maven/com.google.guava/guava@31.1-jre"


# ---------------------------------------------------------------------------
# Gradle
# ---------------------------------------------------------------------------


def test_gradle_string_notation() -> None:
    deps = gradle_deps()
    assert deps["com.google.guava:guava"].ref.version == "31.1-jre"
    assert deps["org.apache.commons:commons-lang3"].ref.version == "3.12.0"


def test_gradle_map_notation() -> None:
    assert gradle_deps()["org.postgresql:postgresql"].ref.version == "42.7.1"


def test_gradle_configurations_map_to_scopes() -> None:
    deps = gradle_deps()
    assert deps["com.google.guava:guava"].scope is Scope.RUNTIME
    assert deps["org.projectlombok:lombok"].scope is Scope.BUILD
    assert deps["junit:junit"].scope is Scope.TEST


def test_gradle_ignores_comments_and_unknown_configurations() -> None:
    deps = gradle_deps()
    assert "commented:out" not in deps
    assert "not:a" not in deps


def test_gradle_coordinate_without_a_version_is_unresolved() -> None:
    dep = gradle_deps()["io.example:no-version"]
    assert dep.ref.version is None
    assert dep.pin is Pin.UNRESOLVED


# ---------------------------------------------------------------------------
# Effective-POM resolution
# ---------------------------------------------------------------------------


def pom_url(group: str, artifact: str, version: str) -> str:
    path = group.replace(".", "/")
    return f"{CENTRAL}/{path}/{artifact}/{version}/{artifact}-{version}.pom"


def pom_xml(
    group: str,
    artifact: str,
    version: str,
    *,
    dependencies: str = "",
    parent: str = "",
    management: str = "",
    properties: str = "",
) -> httpx.Response:
    body = f"""<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  {parent}
  <groupId>{group}</groupId>
  <artifactId>{artifact}</artifactId>
  <version>{version}</version>
  <properties>{properties}</properties>
  <dependencyManagement><dependencies>{management}</dependencies></dependencyManagement>
  <dependencies>{dependencies}</dependencies>
</project>"""
    return httpx.Response(200, text=body)


def dep_xml(
    group: str,
    artifact: str,
    version: str = "",
    scope: str = "",
    *,
    exclusions: tuple[tuple[str, str], ...] = (),
) -> str:
    version_tag = f"<version>{version}</version>" if version else ""
    scope_tag = f"<scope>{scope}</scope>" if scope else ""
    excluded = "".join(
        f"<exclusion><groupId>{eg}</groupId><artifactId>{ea}</artifactId></exclusion>"
        for eg, ea in exclusions
    )
    exclusions_tag = f"<exclusions>{excluded}</exclusions>" if exclusions else ""
    return (
        f"<dependency><groupId>{group}</groupId><artifactId>{artifact}</artifactId>"
        f"{version_tag}{scope_tag}{exclusions_tag}</dependency>"
    )


def direct(
    name: str,
    version: str | None,
    scope: Scope = Scope.RUNTIME,
    *,
    exclusions: frozenset[str] = frozenset(),
    path: str = "pom.xml",
) -> Dependency:
    return Dependency(
        ref=PackageRef(EcosystemId.MAVEN, name, version),
        scope=scope,
        direct=True,
        source=SourceLocation(Path(path), 1),
        pin=Pin.PINNED if version else Pin.UNRESOLVED,
        exclusions=exclusions,
    )


def resolver(responses: dict[str, object], **kwargs: object) -> MavenResolver:
    return MavenResolver(
        httpx.AsyncClient(transport=MockTransport(responses)),
        Cache.memory(),
        **kwargs,  # type: ignore[arg-type]
    )


async def test_transitive_dependencies_are_discovered() -> None:
    responses = {
        f"GET:{pom_url('g', 'a', '1.0')}": pom_xml(
            "g", "a", "1.0", dependencies=dep_xml("g", "b", "2.0")
        ),
        f"GET:{pom_url('g', 'b', '2.0')}": pom_xml(
            "g", "b", "2.0", dependencies=dep_xml("g", "c", "3.0")
        ),
        f"GET:{pom_url('g', 'c', '3.0')}": pom_xml("g", "c", "3.0"),
    }
    result = await resolver(responses).expand((direct("g:a", "1.0"),))

    found = {dep.ref.name: dep for dep in result.dependencies}
    assert found["g:b"].ref.version == "2.0"
    assert found["g:c"].ref.version == "3.0"
    assert found["g:b"].direct is False
    assert result.approximate is True


async def test_nearest_declaration_wins_a_version_conflict() -> None:
    """Maven takes the declaration closest to the root, not the highest version."""
    responses = {
        f"GET:{pom_url('g', 'a', '1.0')}": pom_xml(
            "g",
            "a",
            "1.0",
            dependencies=dep_xml("g", "shared", "1.0") + dep_xml("g", "mid", "1.0"),
        ),
        f"GET:{pom_url('g', 'shared', '1.0')}": pom_xml("g", "shared", "1.0"),
        f"GET:{pom_url('g', 'mid', '1.0')}": pom_xml(
            "g", "mid", "1.0", dependencies=dep_xml("g", "shared", "9.9")
        ),
    }
    result = await resolver(responses).expand((direct("g:a", "1.0"),))

    shared = [d for d in result.dependencies if d.ref.name == "g:shared"]
    assert [d.ref.version for d in shared] == ["1.0"]


async def test_test_scoped_dependencies_do_not_propagate() -> None:
    """Your test dependencies are not mine — Maven's own rule."""
    responses = {
        f"GET:{pom_url('g', 'a', '1.0')}": pom_xml(
            "g", "a", "1.0", dependencies=dep_xml("junit", "junit", "4.12", "test")
        ),
    }
    result = await resolver(responses).expand((direct("g:a", "1.0"),))
    assert all(d.ref.name != "junit:junit" for d in result.dependencies)


async def test_exclusions_are_honoured_down_the_branch() -> None:
    responses = {
        f"GET:{pom_url('g', 'a', '1.0')}": pom_xml(
            "g",
            "a",
            "1.0",
            dependencies=dep_xml("g", "b", "2.0", exclusions=(("g", "unwanted"),)),
        ),
        f"GET:{pom_url('g', 'b', '2.0')}": pom_xml(
            "g", "b", "2.0", dependencies=dep_xml("g", "unwanted", "1.0")
        ),
    }
    result = await resolver(responses).expand((direct("g:a", "1.0"),))
    assert all(d.ref.name != "g:unwanted" for d in result.dependencies)


async def test_versions_are_inherited_from_a_parent_poms_management() -> None:
    responses = {
        f"GET:{pom_url('g', 'a', '1.0')}": pom_xml(
            "g",
            "a",
            "1.0",
            parent=(
                "<parent><groupId>g</groupId><artifactId>base</artifactId>"
                "<version>1.0</version></parent>"
            ),
            dependencies=dep_xml("g", "managed", ""),
        ),
        f"GET:{pom_url('g', 'base', '1.0')}": pom_xml(
            "g", "base", "1.0", management=dep_xml("g", "managed", "7.7")
        ),
        f"GET:{pom_url('g', 'managed', '7.7')}": pom_xml("g", "managed", "7.7"),
    }
    result = await resolver(responses).expand((direct("g:a", "1.0"),))
    managed = next(d for d in result.dependencies if d.ref.name == "g:managed")
    assert managed.ref.version == "7.7"


async def test_imported_boms_supply_versions() -> None:
    """The Spring Boot pattern: a <scope>import</scope> BOM pinning everything."""
    responses = {
        f"GET:{pom_url('g', 'a', '1.0')}": pom_xml(
            "g",
            "a",
            "1.0",
            management=(
                "<dependency><groupId>g</groupId><artifactId>bom</artifactId>"
                "<version>5.0</version><type>pom</type><scope>import</scope></dependency>"
            ),
            dependencies=dep_xml("g", "from-bom", ""),
        ),
        f"GET:{pom_url('g', 'bom', '5.0')}": pom_xml(
            "g", "bom", "5.0", management=dep_xml("g", "from-bom", "3.3")
        ),
        f"GET:{pom_url('g', 'from-bom', '3.3')}": pom_xml("g", "from-bom", "3.3"),
    }
    result = await resolver(responses).expand((direct("g:a", "1.0"),))
    entry = next(d for d in result.dependencies if d.ref.name == "g:from-bom")
    assert entry.ref.version == "3.3"


async def test_unreachable_central_degrades_to_direct_dependencies() -> None:
    """Losing the network costs depth, never correctness of what we already had."""
    result = await resolver({}).expand((direct("g:a", "1.0"),))
    assert [d.ref.name for d in result.dependencies] == ["g:a"]


async def test_depth_cap_is_enforced() -> None:
    responses = {
        f"GET:{pom_url('g', f'p{i}', '1.0')}": pom_xml(
            "g", f"p{i}", "1.0", dependencies=dep_xml("g", f"p{i + 1}", "1.0")
        )
        for i in range(10)
    }
    result = await resolver(responses, max_depth=2).expand((direct("g:p0", "1.0"),))
    assert len(result.dependencies) <= 3


async def test_node_cap_is_disclosed_not_silent() -> None:
    fanout = "".join(dep_xml("g", f"child{i}", "1.0") for i in range(20))
    responses = {
        f"GET:{pom_url('g', 'a', '1.0')}": pom_xml("g", "a", "1.0", dependencies=fanout)
    }
    result = await resolver(responses, max_nodes=5).expand((direct("g:a", "1.0"),))
    assert any("truncated" in warning for warning in result.warnings)


async def test_poms_are_cached_between_resolvers() -> None:
    """A released POM is immutable, so it never needs fetching twice."""
    responses = {
        f"GET:{pom_url('g', 'a', '1.0')}": pom_xml(
            "g", "a", "1.0", dependencies=dep_xml("g", "b", "2.0")
        ),
        f"GET:{pom_url('g', 'b', '2.0')}": pom_xml("g", "b", "2.0"),
    }
    transport = MockTransport(responses)
    cache = Cache.memory()

    first = MavenResolver(httpx.AsyncClient(transport=transport), cache)
    await first.expand((direct("g:a", "1.0"),))
    calls = len(transport.calls)

    second = MavenResolver(httpx.AsyncClient(transport=transport), cache)
    await second.expand((direct("g:a", "1.0"),))
    assert len(transport.calls) == calls


async def test_non_maven_dependencies_pass_through_untouched() -> None:
    pypi = Dependency(
        ref=PackageRef(EcosystemId.PYPI, "requests", "2.31.0"),
        scope=Scope.RUNTIME,
        direct=True,
        source=SourceLocation(Path("requirements.txt")),
        pin=Pin.PINNED,
    )
    result = await resolver({}).expand((pypi,))
    assert result.dependencies == (pypi,)
    assert result.approximate is False


async def test_an_implausible_coordinate_is_refused_rather_than_fetched() -> None:
    """Coordinates come out of POM files in the repository being scanned.

    Interpolated into a Central path unchecked, a groupId containing whitespace made
    httpx raise ``InvalidURL`` — which is not an ``HTTPError``, so it escaped the
    handler and ended the whole scan. A component of ``..`` would traverse instead.
    """
    transport = MockTransport({})
    resolved = MavenResolver(httpx.AsyncClient(transport=transport), Cache.memory())

    assert await resolved._fetch_pom(Coordinate("gro up\n", "artifact", "1.0")) is None
    assert await resolved._fetch_pom(Coordinate("g", "..", "1.0")) is None
    assert await resolved._fetch_pom(Coordinate("g", "a", "../../secret")) is None
    assert transport.calls == []


async def test_a_bom_may_supply_the_scope_as_well_as_the_version() -> None:
    """A dependency declaring no scope takes the managed one.

    Reading the declared scope alone treated every such entry as ``compile``, so a
    test-scoped family pinned by a BOM propagated as if it shipped.
    """
    responses = {
        f"GET:{pom_url('g', 'a', '1.0')}": pom_xml(
            "g",
            "a",
            "1.0",
            management=(
                "<dependency><groupId>g</groupId><artifactId>b</artifactId>"
                "<version>2.0</version><scope>test</scope></dependency>"
            ),
            dependencies=dep_xml("g", "b"),
        ),
        f"GET:{pom_url('g', 'b', '2.0')}": pom_xml("g", "b", "2.0"),
    }
    result = await resolver(responses).expand((direct("g:a", "1.0"),))
    assert "g:b" not in {dep.ref.name for dep in result.dependencies}

    # The same graph without the managed scope must still pull g:b in, so the
    # assertion above cannot pass merely because the version went missing.
    responses[f"GET:{pom_url('g', 'a', '1.0')}"] = pom_xml(
        "g",
        "a",
        "1.0",
        management=(
            "<dependency><groupId>g</groupId><artifactId>b</artifactId>"
            "<version>2.0</version></dependency>"
        ),
        dependencies=dep_xml("g", "b"),
    )
    unmanaged = await resolver(responses).expand((direct("g:a", "1.0"),))
    assert "g:b" in {dep.ref.name for dep in unmanaged.dependencies}


# ---------------------------------------------------------------------------
# Exclusions declared on a direct dependency
# ---------------------------------------------------------------------------


def _one_level(child: str = "unwanted") -> dict[str, object]:
    """``g:a 1.0`` pulling in ``g:<child> 1.0``, so an exclusion has something
    to bite."""
    return {
        f"GET:{pom_url('g', 'a', '1.0')}": pom_xml(
            "g", "a", "1.0", dependencies=dep_xml("g", child, "1.0")
        ),
        f"GET:{pom_url('g', child, '1.0')}": pom_xml("g", child, "1.0"),
    }


def test_a_pom_manifest_carries_exclusions_onto_the_dependency() -> None:
    """The parser reads <exclusions>; this asserts they survive into the model.

    They used to be dropped one line after being parsed, which is what let an
    explicitly excluded artifact be reported as a live, vulnerable dependency.
    """
    dependencies = parse_manifest(Path("pom.xml"), read("basic", "pom.xml"))
    guava = next(d for d in dependencies if d.ref.name.endswith(":guava"))
    assert guava.exclusions == frozenset({"com.google.code.findbugs:jsr305"})


async def test_exclusions_on_a_direct_dependency_are_honoured() -> None:
    result = await resolver(_one_level()).expand(
        (direct("g:a", "1.0", exclusions=frozenset({"g:unwanted"})),)
    )
    assert all(d.ref.name != "g:unwanted" for d in result.dependencies)


async def test_a_direct_dependency_is_not_removed_by_its_own_exclusions() -> None:
    """Exclusions apply to a declaration's subtree, never to the declaration itself."""
    result = await resolver(_one_level()).expand(
        (direct("g:a", "1.0", exclusions=frozenset({"g:a"})),)
    )
    assert "g:a" in {d.ref.name for d in result.dependencies}


async def test_a_wildcard_group_exclusion_removes_the_whole_group() -> None:
    result = await resolver(_one_level()).expand(
        (direct("g:a", "1.0", exclusions=frozenset({"g:*"})),)
    )
    assert all(d.ref.name != "g:unwanted" for d in result.dependencies)


async def test_a_wildcard_artifact_exclusion_removes_it_from_any_group() -> None:
    result = await resolver(_one_level()).expand(
        (direct("g:a", "1.0", exclusions=frozenset({"*:unwanted"})),)
    )
    assert all(d.ref.name != "g:unwanted" for d in result.dependencies)


async def test_a_full_wildcard_exclusion_removes_the_subtree() -> None:
    result = await resolver(_one_level()).expand(
        (direct("g:a", "1.0", exclusions=frozenset({"*:*"})),)
    )
    assert [d.ref.name for d in result.dependencies] == ["g:a"]


async def test_a_wildcard_does_not_reach_a_different_group() -> None:
    """The failure direction that matters: over-matching hides a real dependency."""
    result = await resolver(_one_level()).expand(
        (direct("g:a", "1.0", exclusions=frozenset({"other:*"})),)
    )
    assert "g:unwanted" in {d.ref.name for d in result.dependencies}


async def test_a_wildcard_is_not_a_prefix_glob() -> None:
    """Maven's ``*`` is a whole segment: ``g:un*`` matches nothing at all."""
    result = await resolver(_one_level()).expand(
        (direct("g:a", "1.0", exclusions=frozenset({"g:un*"})),)
    )
    assert "g:unwanted" in {d.ref.name for d in result.dependencies}


def test_a_half_declared_exclusion_is_dropped_rather_than_kept() -> None:
    """``<exclusion>`` with no artifactId must not become the key ``g:``."""
    pom = parse_pom(
        """<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>
        <dependencies><dependency><groupId>g</groupId><artifactId>b</artifactId>
        <exclusions><exclusion><groupId>g</groupId></exclusion></exclusions>
        </dependency></dependencies></project>"""
    )
    assert pom.dependencies[0].exclusions == frozenset()


async def test_dependency_management_supplies_exclusions_to_a_transitive() -> None:
    """A parent centralising an exclusion for a dependency that declares none."""
    responses = {
        f"GET:{pom_url('g', 'a', '1.0')}": pom_xml(
            "g",
            "a",
            "1.0",
            management=dep_xml("g", "b", "2.0", exclusions=(("g", "unwanted"),)),
            dependencies=dep_xml("g", "b"),
        ),
        f"GET:{pom_url('g', 'b', '2.0')}": pom_xml(
            "g", "b", "2.0", dependencies=dep_xml("g", "unwanted", "1.0")
        ),
    }
    result = await resolver(responses).expand((direct("g:a", "1.0"),))
    names = {d.ref.name for d in result.dependencies}
    assert "g:b" in names
    assert "g:unwanted" not in names


def test_declared_and_managed_exclusions_are_merged() -> None:
    """Maven unions the two lists; neither replaces the other."""
    dependencies = parse_manifest(
        Path("pom.xml"),
        """<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>
        <dependencyManagement><dependencies>
          <dependency><groupId>g</groupId><artifactId>b</artifactId><version>2.0</version>
            <exclusions><exclusion><groupId>g</groupId><artifactId>from-parent</artifactId>
            </exclusion></exclusions></dependency>
        </dependencies></dependencyManagement>
        <dependencies>
          <dependency><groupId>g</groupId><artifactId>b</artifactId>
            <exclusions><exclusion><groupId>g</groupId><artifactId>from-child</artifactId>
            </exclusion></exclusions></dependency>
        </dependencies></project>""",
    )
    assert dependencies[0].exclusions == frozenset({"g:from-parent", "g:from-child"})


# ---------------------------------------------------------------------------
# Per-module resolution
# ---------------------------------------------------------------------------


def _two_modules() -> dict[str, object]:
    """Two modules that both reach ``g:shared``, by different routes and versions."""
    return {
        f"GET:{pom_url('g', 'a', '1.0')}": pom_xml(
            "g", "a", "1.0", dependencies=dep_xml("g", "shared", "1.0")
        ),
        f"GET:{pom_url('g', 'b', '1.0')}": pom_xml(
            "g", "b", "1.0", dependencies=dep_xml("g", "shared", "2.0")
        ),
        f"GET:{pom_url('g', 'shared', '1.0')}": pom_xml("g", "shared", "1.0"),
        f"GET:{pom_url('g', 'shared', '2.0')}": pom_xml("g", "shared", "2.0"),
    }


async def test_each_module_resolves_its_own_version_of_a_shared_coordinate() -> None:
    """One ``seen`` map across modules let whichever was walked first decide."""
    units = (
        MavenUnit(PurePath("a"), (direct("g:a", "1.0", path="a/pom.xml"),)),
        MavenUnit(PurePath("b"), (direct("g:b", "1.0", path="b/pom.xml"),)),
    )
    declared = tuple(dep for unit in units for dep in unit.dependencies)
    result = await resolver(_two_modules()).expand_units(declared, units)

    shared = {
        (str(d.source.path), d.ref.version)
        for d in result.dependencies
        if d.ref.name == "g:shared"
    }
    assert shared == {("a/pom.xml", "1.0"), ("b/pom.xml", "2.0")}


async def test_a_transitive_names_the_declaration_that_introduced_it() -> None:
    """Provenance used to be whichever root sorted first, for every transitive."""
    units = (
        MavenUnit(PurePath("a"), (direct("g:a", "1.0", path="a/pom.xml"),)),
        MavenUnit(PurePath("b"), (direct("g:b", "1.0", path="b/pom.xml"),)),
    )
    declared = tuple(dep for unit in units for dep in unit.dependencies)
    result = await resolver(_two_modules()).expand_units(declared, units)

    introduced = {
        (str(d.source.path), d.parents[0].name, d.source.line)
        for d in result.dependencies
        if d.ref.name == "g:shared" and not d.direct
    }
    assert introduced == {("a/pom.xml", "g:a", 1), ("b/pom.xml", "g:b", 1)}


async def test_a_directly_declared_package_is_not_dropped_from_another_module() -> None:
    """Filtering transitives by bare name across the whole scan lost module B's copy."""
    units = (
        MavenUnit(PurePath("a"), (direct("g:shared", "1.0", path="a/pom.xml"),)),
        MavenUnit(PurePath("b"), (direct("g:b", "1.0", path="b/pom.xml"),)),
    )
    declared = tuple(dep for unit in units for dep in unit.dependencies)
    result = await resolver(_two_modules()).expand_units(declared, units)

    assert any(
        d.ref.name == "g:shared" and str(d.source.path) == "b/pom.xml"
        for d in result.dependencies
    )


async def test_expand_units_leaves_non_maven_dependencies_in_place() -> None:
    other = Dependency(
        ref=PackageRef(EcosystemId.PYPI, "flask", "3.0.0"),
        scope=Scope.RUNTIME,
        direct=True,
        source=SourceLocation(Path("requirements.txt")),
        pin=Pin.PINNED,
    )
    unit = MavenUnit(PurePath("."), (direct("g:a", "1.0"),))
    result = await resolver(_one_level()).expand_units(
        (other, *unit.dependencies), (unit,)
    )
    assert other in result.dependencies


async def test_the_node_budget_is_shared_across_modules() -> None:
    """The cap bounds a runaway fetch loop, so splitting must not multiply it."""
    units = (
        MavenUnit(PurePath("a"), (direct("g:a", "1.0", path="a/pom.xml"),)),
        MavenUnit(PurePath("b"), (direct("g:b", "1.0", path="b/pom.xml"),)),
    )
    declared = tuple(dep for unit in units for dep in unit.dependencies)
    result = await resolver(_two_modules(), max_nodes=2).expand_units(declared, units)

    assert any("truncated" in warning for warning in result.warnings)
    assert sum(1 for _ in result.warnings if "truncated" in _) == 1


# ---------------------------------------------------------------------------
# Multi-module scans, end to end
# ---------------------------------------------------------------------------


async def test_a_multi_module_scan_attributes_transitives_to_their_own_module(
    canned_upstream: object,
) -> None:
    """The whole of both fixes, observed from the outside.

    ``service-a`` and ``service-b`` both reach ``com.example:shared``, by different
    routes and at different versions, and ``service-b`` excludes ``unwanted``. A
    merged resolve pass gave every transitive one module's POM as its source and let
    whichever module was walked first pick the shared version for both.
    """
    responses = {
        f"GET:{pom_url('com.example', 'alpha', '1.0')}": pom_xml(
            "com.example",
            "alpha",
            "1.0",
            dependencies=dep_xml("com.example", "shared", "1.0"),
        ),
        f"GET:{pom_url('com.example', 'beta', '1.0')}": pom_xml(
            "com.example",
            "beta",
            "1.0",
            dependencies=dep_xml("com.example", "shared", "2.0")
            + dep_xml("com.example", "unwanted", "1.0"),
        ),
        f"GET:{pom_url('com.example', 'shared', '1.0')}": pom_xml(
            "com.example", "shared", "1.0"
        ),
        f"GET:{pom_url('com.example', 'shared', '2.0')}": pom_xml(
            "com.example", "shared", "2.0"
        ),
        f"GET:{pom_url('com.example', 'unwanted', '1.0')}": pom_xml(
            "com.example", "unwanted", "1.0"
        ),
    }
    canned_upstream(responses)  # type: ignore[operator]

    report = await scan(
        FIXTURES / "maven" / "multimodule",
        ScanOptions(check_vulnerabilities=False, resolve_ranges=False),
    )

    shared = {
        (str(dep.source.path), dep.ref.version)
        for dep in report.dependencies
        if dep.ref.name == "com.example:shared"
    }
    assert shared == {
        ("service-a/pom.xml", "1.0"),
        ("service-b/pom.xml", "2.0"),
    }

    # Declared on service-b's <dependency>, so it must not reach the graph at all.
    assert all(d.ref.name != "com.example:unwanted" for d in report.dependencies)

    # Every module's count is its own, which only holds once transitives stop being
    # attributed to whichever POM happened to sort first.
    counts = {str(m.directory): m.dependency_count for m in report.manifests}
    assert counts == {".": 0, "service-a": 2, "service-b": 2}
