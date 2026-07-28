"""Maven and Gradle parsing, and effective-POM resolution."""

from __future__ import annotations

from pathlib import Path

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
from icebergsca.ecosystems.maven import MavenResolver, parse_manifest
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


def dep_xml(group: str, artifact: str, version: str = "", scope: str = "") -> str:
    version_tag = f"<version>{version}</version>" if version else ""
    scope_tag = f"<scope>{scope}</scope>" if scope else ""
    return (
        f"<dependency><groupId>{group}</groupId>"
        f"<artifactId>{artifact}</artifactId>{version_tag}{scope_tag}</dependency>"
    )


def direct(name: str, version: str | None, scope: Scope = Scope.RUNTIME) -> Dependency:
    return Dependency(
        ref=PackageRef(EcosystemId.MAVEN, name, version),
        scope=scope,
        direct=True,
        source=SourceLocation(Path("pom.xml")),
        pin=Pin.PINNED if version else Pin.UNRESOLVED,
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
            dependencies=(
                "<dependency><groupId>g</groupId><artifactId>b</artifactId>"
                "<version>2.0</version><exclusions><exclusion>"
                "<groupId>g</groupId><artifactId>unwanted</artifactId>"
                "</exclusion></exclusions></dependency>"
            ),
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
