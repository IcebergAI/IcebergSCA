"""Rust / crates.io manifests and lockfiles.

``Cargo.lock`` records the full resolved graph including edges, so dependency paths
come out of it directly. What it does not record is scope: dev-dependencies and
build-dependencies are locked alongside runtime ones with no marker. ``Cargo.toml``
carries that distinction, and the scanner merges the two.
"""

from __future__ import annotations

import re
import tomllib
from collections import Counter, defaultdict
from dataclasses import replace
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

    entries = [
        package
        for package in packages
        if isinstance(package, dict) and isinstance(package.get("name"), str)
    ]
    # Two versions of one crate in a single lock is routine in Rust, and keying the
    # graph on the bare name would drop all but the last — silently, and in the
    # direction that hides a vulnerable older copy.
    duplicated = {
        name for name, count in Counter(p["name"] for p in entries).items() if count > 1
    }

    nodes: dict[str, Node] = {}
    by_name: dict[str, list[str]] = defaultdict(list)
    requires: dict[str, list[str]] = {}
    local: set[str] = set()

    for package in entries:
        name = package["name"]
        version = (
            package.get("version") if isinstance(package.get("version"), str) else None
        )

        key = _node_key(name, version, duplicated, taken=nodes)
        by_name[name].append(key)
        requires[key] = [
            entry.strip()
            for entry in package.get("dependencies") or []
            if isinstance(entry, str)
        ]
        nodes[key] = Node(key=key, name=name, version=version)

        # Workspace members have no source; they are the project, not dependencies.
        if package.get("source") is None:
            local.add(key)

    for key, entries_for_key in requires.items():
        nodes[key] = replace(
            nodes[key],
            children=tuple(
                dict.fromkeys(_resolve_edges(entries_for_key, by_name, nodes))
            ),
        )

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


def _node_key(
    name: str, version: str | None, duplicated: set[str], *, taken: dict[str, Node]
) -> str:
    """A key unique within the lockfile.

    The bare name is kept whenever a crate appears once, because that is what an
    unambiguous dependency entry refers to. Only crates locked at several versions
    take the ``name version`` form Cargo itself uses to disambiguate them.
    """
    if name not in duplicated:
        return name
    key = f"{name} {version}" if version else name
    suffix = 2
    while key in taken:
        key = f"{name} {version or '?'}#{suffix}"
        suffix += 1
    return key


def _resolve_edges(
    entries: list[str], by_name: dict[str, list[str]], nodes: dict[str, Node]
) -> list[str]:
    """Point each dependency entry at the node it names.

    Cargo writes just the crate name when the lock holds one version of it and
    ``name version`` when it holds several. An entry that still cannot be pinned to
    one node is linked to every candidate: an extra edge over-reports reachability,
    while a missing one would leave a locked crate looking unused.
    """
    resolved: list[str] = []
    for entry in entries:
        match = _DEP_ENTRY.match(entry)
        if match is None:
            continue
        name = match.group("name")
        version = match.group("version")
        candidates = by_name.get(name, [])
        exact = f"{name} {version}" if version else None
        if exact is not None and exact in nodes:
            resolved.append(exact)
        elif len(candidates) == 1:
            resolved.append(candidates[0])
        else:
            resolved.extend(candidates)
    return resolved


SPEC = EcosystemSpec(
    id=EcosystemId.CARGO,
    manifests=FileSpec(names=frozenset({"cargo.toml"})),
    lockfiles=FileSpec(names=frozenset({"cargo.lock"})),
    parse_manifest=parse_manifest,
    parse_lockfile=parse_lockfile,
)
