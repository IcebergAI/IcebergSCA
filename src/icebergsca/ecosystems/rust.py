"""Rust / crates.io manifests and lockfiles.

``Cargo.lock`` records the full resolved graph including edges, so dependency paths
come out of it directly. What it does not record is scope: dev-dependencies and
build-dependencies are locked alongside runtime ones with no marker. ``Cargo.toml``
carries that distinction, and the scanner merges the two.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

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

#: Cargo.toml sections and the scope each implies.
_MANIFEST_SECTIONS: tuple[tuple[str, Scope], ...] = (
    ("dependencies", Scope.RUNTIME),
    ("dev-dependencies", Scope.DEV),
    ("build-dependencies", Scope.BUILD),
)

#: A Cargo.lock dependency entry is "name" or "name version" or
#: "name version (registry+https://...)" — only the first two fields matter.
_DEP_ENTRY = re.compile(r"^(?P<name>\S+)(?:\s+(?P<version>\S+))?")

#: An exact version with no range operator. Cargo treats a bare "1.2.3" as "^1.2.3",
#: so it is a constraint rather than a pin — only the lockfile truly pins anything.
_EXACT = re.compile(r"^=\s*(?P<version>\d[\w.+-]*)$")


def _spec_constraint(spec: Any) -> str | None:
    """Normalise a Cargo dependency spec, which is a string or a table."""
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        version = spec.get("version")
        return version if isinstance(version, str) else None
    return None


def _find_line(content: str, name: str) -> int | None:
    for number, line in enumerate(content.splitlines(), start=1):
        if line.lstrip().startswith((f"{name} ", f"{name}=", f'"{name}"')):
            return number
    return None


def parse_manifest(path: Path, content: str) -> list[Dependency]:
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ParseError(str(path), f"invalid TOML: {exc}") from exc

    dependencies: list[Dependency] = []
    tables: list[tuple[dict[str, Any], Scope]] = []

    for section, scope in _MANIFEST_SECTIONS:
        table = data.get(section)
        if isinstance(table, dict):
            tables.append((table, scope))
        # Target-specific dependencies live under [target.'cfg(...)'.dependencies]
        # and are just as real as the plain ones.
        for target in (data.get("target") or {}).values():
            nested = target.get(section) if isinstance(target, dict) else None
            if isinstance(nested, dict):
                tables.append((nested, scope))

    for table, scope in tables:
        for name, spec in table.items():
            constraint = _spec_constraint(spec)
            if constraint is None:
                continue  # a path or git dependency has no registry version
            exact = _EXACT.match(constraint.strip())
            version = exact.group("version") if exact else None
            dependencies.append(
                Dependency(
                    ref=PackageRef(EcosystemId.CARGO, name, version),
                    scope=scope,
                    direct=True,
                    source=SourceLocation(path, _find_line(content, name)),
                    pin=Pin.PINNED if version else Pin.UNRESOLVED,
                    constraint=constraint,
                )
            )

    return dependencies


def parse_lockfile(path: Path, content: str) -> list[Dependency]:
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ParseError(str(path), f"invalid TOML: {exc}") from exc

    packages = data.get("package")
    if not isinstance(packages, list):
        raise ParseError(str(path), "no [[package]] entries found")

    nodes: dict[str, Node] = {}
    local: set[str] = set()

    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            continue
        name = package["name"]
        version = (
            package.get("version") if isinstance(package.get("version"), str) else None
        )

        # Workspace members have no source; they are the project, not dependencies.
        if package.get("source") is None:
            local.add(name)

        children = tuple(
            match.group("name")
            for entry in package.get("dependencies") or []
            if isinstance(entry, str) and (match := _DEP_ENTRY.match(entry.strip()))
        )
        nodes[name] = Node(key=name, name=name, version=version, children=children)

    # Everything a workspace member requires is a direct dependency of the project.
    seeds: dict[str, Scope] = {}
    for member in local:
        for child in nodes[member].children:
            seeds.setdefault(child, Scope.RUNTIME)
    if not seeds:
        seeds = dict.fromkeys(nodes, Scope.RUNTIME)

    for member in local:
        nodes.pop(member, None)
        seeds.pop(member, None)

    return build_dependencies(
        resolve(nodes, seeds), nodes, ecosystem=EcosystemId.CARGO, path=path
    )


SPEC = EcosystemSpec(
    id=EcosystemId.CARGO,
    manifests=FileSpec(names=frozenset({"cargo.toml"})),
    lockfiles=FileSpec(names=frozenset({"cargo.lock"})),
    parse_manifest=parse_manifest,
    parse_lockfile=parse_lockfile,
)
