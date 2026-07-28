"""NuGet / .NET manifests and lockfiles.

``packages.lock.json`` is the best-annotated lockfile of any ecosystem here: it
labels every entry ``Direct`` or ``Transitive`` and records each one's dependencies,
so scope, directness and edges all come straight out of the file.

Project files are XML and are parsed with ``defusedxml`` — a ``.csproj`` is
untrusted input like any other file in a scanned repository.
"""

from __future__ import annotations

import json
from pathlib import Path
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as ElementTree
from defusedxml.common import DefusedXmlException

from icebergsca.core.errors import ParseError
from icebergsca.core.graph import Node, resolve
from icebergsca.core.models import (
    Dependency,
    EcosystemId,
    PackageRef,
    Pin,
    Scope,
    SourceLocation,
)
from icebergsca.ecosystems.base import EcosystemSpec, FileSpec, build_dependencies

#: NuGet version ranges use interval notation: ``[1.0,2.0)``, ``[1.0]``, ``(1.0,)``.
#: A bare version means "this or newer", so only bracketed equality is a true pin.
_RANGE_CHARS = "[]()"

#: ``PackageReference`` items whose asset flags exclude them from the compiled
#: output — analysers and build tooling rather than shipped code.
_DEV_ASSET_MARKERS = ("all", "runtime")


def _local_name(tag: str) -> str:
    """Strip the XML namespace, which .csproj files may or may not carry."""
    return tag.rsplit("}", 1)[-1]


def _parse_xml(path: Path, content: str) -> Element:
    try:
        return ElementTree.fromstring(content)
    except (DefusedXmlException, SyntaxError, ValueError) as exc:
        raise ParseError(str(path), f"invalid XML: {exc}") from exc


def _version_from_range(raw: str | None) -> tuple[str | None, str | None]:
    """Split a NuGet version spec into (exact version, constraint)."""
    if not raw:
        return None, None
    spec = raw.strip()
    if not spec or spec.startswith("$("):  # an unresolved MSBuild property
        return None, spec or None
    if spec.startswith("[") and spec.endswith("]") and "," not in spec:
        return spec[1:-1].strip(), spec
    if any(char in spec for char in _RANGE_CHARS) or "," in spec:
        return None, spec
    return spec, spec


def _attribute(element: Element, name: str) -> str | None:
    """Read an attribute or a child element — MSBuild allows either form."""
    value = element.get(name)
    if value is not None:
        return value
    for child in element:
        if _local_name(child.tag).lower() == name.lower():
            return (child.text or "").strip() or None
    return None


def _find_line(content: str, name: str) -> int | None:
    for number, line in enumerate(content.splitlines(), start=1):
        if f'"{name}"' in line or f"'{name}'" in line:
            return number
    return None


def parse_manifest(path: Path, content: str) -> list[Dependency]:
    root = _parse_xml(path, content)
    filename = path.name.lower()
    dependencies: list[Dependency] = []

    for element in root.iter():
        tag = _local_name(element.tag)

        if filename == "packages.config":
            if tag != "package":
                continue
            name, raw_version = element.get("id"), element.get("version")
            scope = (
                Scope.DEV
                if element.get("developmentDependency") == "true"
                else Scope.RUNTIME
            )
        elif tag in ("PackageReference", "PackageVersion"):
            name = _attribute(element, "Include") or _attribute(element, "Update")
            raw_version = _attribute(element, "Version")
            scope = _reference_scope(element)
        else:
            continue

        if not name:
            continue
        version, constraint = _version_from_range(raw_version)
        dependencies.append(
            Dependency(
                ref=PackageRef(EcosystemId.NUGET, name, version),
                scope=scope,
                direct=True,
                source=SourceLocation(path, _find_line(content, name)),
                pin=Pin.PINNED if version else Pin.UNRESOLVED,
                constraint=constraint,
            )
        )

    return dependencies


def _reference_scope(element: Element) -> Scope:
    """Classify a PackageReference from its asset flags.

    ``PrivateAssets="all"`` marks a package that is not propagated to consumers —
    analysers, source generators and build tooling. It still runs during the build,
    so it is build scope rather than dev: a compromised analyser reaches the artefact.
    """
    private = (_attribute(element, "PrivateAssets") or "").lower()
    exclude = (_attribute(element, "ExcludeAssets") or "").lower()
    if any(marker in private for marker in _DEV_ASSET_MARKERS):
        return Scope.BUILD
    if "runtime" in exclude:
        return Scope.BUILD
    return Scope.RUNTIME


def parse_lockfile(path: Path, content: str) -> list[Dependency]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ParseError(str(path), f"invalid JSON: {exc}") from exc

    targets = data.get("dependencies") if isinstance(data, dict) else None
    if not isinstance(targets, dict):
        raise ParseError(str(path), "no dependencies section found")

    nodes: dict[str, Node] = {}
    seeds: dict[str, Scope] = {}

    # One block per target framework. A package present in several is the same
    # package; the first resolved version wins and duplicates are ignored.
    for framework in targets.values():
        if not isinstance(framework, dict):
            continue
        for name, entry in framework.items():
            if not isinstance(entry, dict) or name in nodes:
                continue
            version = entry.get("resolved")
            children = tuple(entry.get("dependencies") or {})
            nodes[name] = Node(
                key=name,
                name=name,
                version=version if isinstance(version, str) else None,
                children=children,
            )
            if str(entry.get("type", "")).lower() == "direct":
                seeds[name] = Scope.RUNTIME

    if not seeds:
        seeds = dict.fromkeys(nodes, Scope.RUNTIME)

    return build_dependencies(
        resolve(nodes, seeds), nodes, ecosystem=EcosystemId.NUGET, path=path
    )


SPEC = EcosystemSpec(
    id=EcosystemId.NUGET,
    manifests=FileSpec(
        names=frozenset({"packages.config", "directory.packages.props"}),
        patterns=("*.csproj", "*.fsproj", "*.vbproj"),
    ),
    lockfiles=FileSpec(names=frozenset({"packages.lock.json"})),
    parse_manifest=parse_manifest,
    parse_lockfile=parse_lockfile,
)
