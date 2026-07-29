"""Parsing ``pom.xml`` and ``build.gradle`` into declared dependencies.

This layer is deliberately synchronous and offline: it reports what a file *says*.
Turning that into a full transitive graph needs the parent chain and imported BOMs
from Maven Central, which happens later in :mod:`icebergsca.ecosystems.maven.resolver`.
"""

from __future__ import annotations

import re
from pathlib import Path
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as ElementTree
from defusedxml.common import DefusedXmlException

from icebergsca.core.errors import ParseError
from icebergsca.core.models import (
    Dependency,
    EcosystemId,
    PackageRef,
    Pin,
    Scope,
    SourceLocation,
)
from icebergsca.ecosystems.maven.model import (
    DEFAULT_SCOPE,
    Coordinate,
    Pom,
    RawDependency,
)

#: Maven scope names mapped onto ours. ``provided`` is a build scope: the artefact is
#: compiled against it even though the container supplies it at runtime.
_SCOPE_MAP: dict[str, Scope] = {
    "compile": Scope.RUNTIME,
    "runtime": Scope.RUNTIME,
    "provided": Scope.BUILD,
    "system": Scope.BUILD,
    "test": Scope.TEST,
    "import": Scope.RUNTIME,
}

#: ``${...}`` property references. A version still containing one after interpolation
#: is unresolved, never a literal version.
_PROPERTY = re.compile(r"\$\{([^}]+)\}")

#: Gradle: ``implementation 'group:artifact:version'`` or the same with double quotes.
_GRADLE_STRING = re.compile(
    r"""^\s*(?P<config>\w+)\s*[\s(]\s*['"](?P<coord>[^'"]+)['"]"""
)
#: Gradle: ``implementation group: 'g', name: 'a', version: 'v'``
_GRADLE_MAP = re.compile(
    r"""^\s*(?P<config>\w+)\s.*?group:\s*['"](?P<group>[^'"]+)['"].*?"""
    r"""name:\s*['"](?P<artifact>[^'"]+)['"]"""
    r"""(?:.*?version:\s*['"](?P<version>[^'"]+)['"])?"""
)

#: Gradle configurations and the scope each implies.
_GRADLE_SCOPES: dict[str, Scope] = {
    "implementation": Scope.RUNTIME,
    "api": Scope.RUNTIME,
    "compile": Scope.RUNTIME,
    "runtimeOnly": Scope.RUNTIME,
    "runtime": Scope.RUNTIME,
    "compileOnly": Scope.BUILD,
    "annotationProcessor": Scope.BUILD,
    "kapt": Scope.BUILD,
    "testImplementation": Scope.TEST,
    "testCompile": Scope.TEST,
    "testRuntimeOnly": Scope.TEST,
    "androidTestImplementation": Scope.TEST,
}


def maven_scope(name: str) -> Scope:
    return _SCOPE_MAP.get(name.lower(), Scope.RUNTIME)


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------


def _tag(element: Element) -> str:
    """Local tag name. POMs declare a default namespace; many in the wild do not."""
    return element.tag.rsplit("}", 1)[-1]


def _child(parent: Element, name: str) -> Element | None:
    for element in parent:
        if _tag(element) == name:
            return element
    return None


def _text(parent: Element, name: str, default: str = "") -> str:
    element = _child(parent, name)
    return (element.text or "").strip() if element is not None else default


def _children(parent: Element, name: str) -> list[Element]:
    return [element for element in parent if _tag(element) == name]


def parse_pom(content: str, *, source: str = "pom.xml") -> Pom:
    """Parse POM text into its raw parts, resolving only same-file properties."""
    try:
        root = ElementTree.fromstring(content)
    except (DefusedXmlException, SyntaxError, ValueError) as exc:
        raise ParseError(source, f"invalid XML: {exc}") from exc

    parent_element = _child(root, "parent")
    parent = None
    if parent_element is not None:
        parent = Coordinate(
            group=_text(parent_element, "groupId"),
            artifact=_text(parent_element, "artifactId"),
            version=_text(parent_element, "version") or None,
        )

    # A POM may omit groupId and version, inheriting both from its parent.
    group = _text(root, "groupId") or (parent.group if parent else "")
    version = _text(root, "version") or (parent.version if parent else None)

    properties: dict[str, str] = {}
    properties_element = _child(root, "properties")
    if properties_element is not None:
        for element in properties_element:
            properties[_tag(element)] = (element.text or "").strip()

    management = _child(root, "dependencyManagement")
    managed: tuple[RawDependency, ...] = ()
    if management is not None:
        managed = _dependencies(_child(management, "dependencies"))

    modules_element = _child(root, "modules")
    modules = (
        tuple((m.text or "").strip() for m in _children(modules_element, "module"))
        if modules_element is not None
        else ()
    )

    return Pom(
        coordinate=Coordinate(group, _text(root, "artifactId"), version),
        parent=parent,
        properties=properties,
        managed=managed,
        dependencies=_dependencies(_child(root, "dependencies")),
        modules=tuple(m for m in modules if m),
    )


def _dependencies(container: Element | None) -> tuple[RawDependency, ...]:
    if container is None:
        return ()

    parsed: list[RawDependency] = []
    for element in _children(container, "dependency"):
        exclusions_element = _child(element, "exclusions")
        # A half-declared exclusion is discarded rather than kept as ``g:`` or ``:a``.
        # Exclusions remove packages from the report, and a half-key sits one wildcard
        # rule away from matching everything — dropping it over-reports, which is the
        # direction to fail in.
        items = (
            _children(exclusions_element, "exclusion")
            if exclusions_element is not None
            else []
        )
        exclusions = frozenset(
            f"{group}:{artifact}"
            for group, artifact in (
                (_text(item, "groupId"), _text(item, "artifactId")) for item in items
            )
            if group and artifact
        )

        parsed.append(
            RawDependency(
                group=_text(element, "groupId"),
                artifact=_text(element, "artifactId"),
                version=_text(element, "version") or None,
                scope=_text(element, "scope"),
                optional=_text(element, "optional").lower() == "true",
                exclusions=exclusions,
                is_import=_text(element, "type").lower() == "import"
                or _text(element, "scope").lower() == "import",
            )
        )
    return tuple(parsed)


def interpolate(value: str | None, properties: dict[str, str]) -> str | None:
    """Substitute ``${...}`` references, leaving unknown ones intact.

    An unresolved reference is deliberately returned as-is so the caller can see the
    version is still a placeholder. Replacing it with an empty string would turn
    "we don't know" into "no version", which reads as a resolved answer.
    """
    if value is None:
        return None

    seen = 0
    while _PROPERTY.search(value) and seen < 10:  # bounded: properties can self-refer
        seen += 1
        value = _PROPERTY.sub(
            lambda match: properties.get(match.group(1), match.group(0)), value
        )
    return value


def has_unresolved_property(value: str | None) -> bool:
    return value is not None and bool(_PROPERTY.search(value))


# ---------------------------------------------------------------------------
# Direct dependencies
# ---------------------------------------------------------------------------


def _find_line(content: str, artifact: str) -> int | None:
    needle = f">{artifact}<"
    for number, line in enumerate(content.splitlines(), start=1):
        if needle in line or artifact in line:
            return number
    return None


def parse_manifest(path: Path, content: str) -> list[Dependency]:
    """Direct dependencies only.

    Transitive expansion happens in the resolver, which needs network access. If the
    resolver is disabled or unreachable, this is still a truthful — if shallow —
    answer, and the report marks the graph as incomplete rather than implying depth.
    """
    if path.name.lower().startswith("build.gradle"):
        return _parse_gradle(path, content)
    return _parse_pom_manifest(path, content)


def _parse_pom_manifest(path: Path, content: str) -> list[Dependency]:
    pom = parse_pom(content, source=str(path))
    properties = dict(pom.properties)
    properties.setdefault("project.version", pom.coordinate.version or "")
    properties.setdefault("project.groupId", pom.coordinate.group)

    managed_versions = {
        entry.key: interpolate(entry.version, properties)
        for entry in pom.managed
        if entry.version
    }
    # Maven merges a managed entry's exclusions with the dependency's own rather than
    # letting either replace the other, which is how a parent centralises an exclusion
    # for a dependency that declares none of its own.
    managed_exclusions = {
        entry.key: entry.exclusions for entry in pom.managed if entry.exclusions
    }

    dependencies: list[Dependency] = []
    for entry in pom.dependencies:
        group = interpolate(entry.group, properties) or entry.group
        artifact = interpolate(entry.artifact, properties) or entry.artifact
        key = f"{group}:{artifact}"
        version = interpolate(entry.version, properties) or managed_versions.get(key)

        usable = version if version and not has_unresolved_property(version) else None
        dependencies.append(
            Dependency(
                ref=PackageRef(EcosystemId.MAVEN, key, usable),
                scope=maven_scope(entry.scope or DEFAULT_SCOPE),
                direct=True,
                source=SourceLocation(path, _find_line(content, artifact)),
                pin=Pin.PINNED if usable else Pin.UNRESOLVED,
                constraint=version,
                exclusions=_interpolated_exclusions(
                    entry.exclusions | managed_exclusions.get(key, frozenset()),
                    properties,
                ),
            )
        )
    return dependencies


def _interpolated_exclusions(
    exclusions: frozenset[str], properties: dict[str, str]
) -> frozenset[str]:
    """Resolve ``${...}`` in exclusion keys, which are coordinates like any other.

    A key left with an unresolved property is kept verbatim: it will simply not match,
    which leaves the package in the report rather than removing it on a guess.
    """
    if not exclusions:
        return frozenset()

    resolved: set[str] = set()
    for key in exclusions:
        group, _, artifact = key.partition(":")
        resolved.add(
            f"{interpolate(group, properties) or group}"
            f":{interpolate(artifact, properties) or artifact}"
        )
    return frozenset(resolved)


def _parse_gradle(path: Path, content: str) -> list[Dependency]:
    """Read declared coordinates out of a Gradle build script.

    Gradle builds are programs, so this only sees literal declarations. Version
    catalogues, computed versions and plugin-injected dependencies are invisible —
    which is why the Maven graph is marked approximate in the report.
    """
    dependencies: list[Dependency] = []
    seen: set[str] = set()

    for number, raw in enumerate(content.splitlines(), start=1):
        line = raw.split("//", 1)[0]
        if not line.strip():
            continue

        match = _GRADLE_STRING.match(line)
        if match:
            parts = match.group("coord").split(":")
            if len(parts) < 2:
                continue
            group, artifact = parts[0], parts[1]
            version = parts[2] if len(parts) > 2 else None
            config = match.group("config")
        else:
            match = _GRADLE_MAP.match(line)
            if match is None:
                continue
            group = match.group("group")
            artifact = match.group("artifact")
            version = match.group("version")
            config = match.group("config")

        scope = _GRADLE_SCOPES.get(config)
        if scope is None:
            continue

        name = f"{group}:{artifact}"
        if name in seen:
            continue
        seen.add(name)

        usable = version if version and not has_unresolved_property(version) else None
        dependencies.append(
            Dependency(
                ref=PackageRef(EcosystemId.MAVEN, name, usable),
                scope=scope,
                direct=True,
                source=SourceLocation(path, number),
                pin=Pin.PINNED if usable else Pin.UNRESOLVED,
                constraint=version,
            )
        )

    return dependencies
