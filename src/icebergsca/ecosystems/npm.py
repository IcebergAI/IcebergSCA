"""npm / JavaScript manifests and lockfiles.

Four lockfile formats, each describing the same graph differently:

* ``package-lock.json`` v2/v3 — a flat ``packages`` map keyed by install path, with
  npm's own ``dev``/``optional`` flags already computed. The richest of the four.
* ``package-lock.json`` v1 — a nested ``dependencies`` tree.
* ``pnpm-lock.yaml`` — importers plus ``name@version`` keys.
* ``yarn.lock`` — Berry is YAML; v1 is a bespoke indented format with no scope or
  directness information at all.

The npm formats need real install-path resolution rather than name lookup, because
the same package legitimately appears at several versions in one tree and the edges
mean different things depending on where they sit.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml

from icebergsca.core.errors import ParseError, UnsupportedFileError
from icebergsca.core.graph import Node, Resolved, resolve
from icebergsca.core.models import (
    Dependency,
    EcosystemId,
    PackageRef,
    Pin,
    Scope,
    SourceLocation,
)
from icebergsca.ecosystems.base import EcosystemSpec, FileSpec, build_dependencies

#: Manifest sections and the scope each implies. Peer dependencies are the consumer's
#: responsibility to install, so they are optional to us rather than runtime.
_MANIFEST_SECTIONS: tuple[tuple[str, Scope], ...] = (
    ("dependencies", Scope.RUNTIME),
    ("devDependencies", Scope.DEV),
    ("optionalDependencies", Scope.OPTIONAL),
    ("peerDependencies", Scope.OPTIONAL),
)

#: Specs that name a location rather than a registry version. There is nothing to
#: look up in OSV for these, so they are skipped rather than reported as unversioned.
_NON_REGISTRY = ("file:", "link:", "workspace:", "git+", "git:", "github:", "portal:")

#: An exact semver release — no range operator, no wildcard. Anything else is a
#: constraint that milestone M5 resolves against the registry.
_EXACT_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")

_NODE_MODULES = "/node_modules/"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _package_name(install_path: str) -> str:
    """Recover the package name from a node_modules install path.

    ``node_modules/a/node_modules/@scope/b`` is the package ``@scope/b``: everything
    before the final ``node_modules/`` describes where it was placed, not what it is.
    """
    _, _, tail = install_path.rpartition("node_modules/")
    return tail or install_path


def _spec_version(spec: str) -> tuple[str | None, str | None]:
    """Split an npm version spec into (exact version, constraint).

    Returns ``(None, None)`` for specs that do not name a registry package at all.
    """
    spec = spec.strip()
    if not spec or spec.lower().startswith(_NON_REGISTRY):
        return None, None
    if spec.startswith("npm:"):
        # Aliased install, "npm:real-package@^1.0.0" — the range is after the last @.
        _, _, remainder = spec[4:].rpartition("@")
        spec = remainder or spec
    if spec in ("*", "", "latest", "x"):
        return None, None
    return (spec, spec) if _EXACT_VERSION.match(spec) else (None, spec)


def _apply_lock_scopes(
    resolved: list[Resolved], scopes: dict[str, Scope]
) -> list[Resolved]:
    """Prefer the lockfile's own scope flags over anything we inferred.

    npm computes ``dev`` and ``optional`` across the whole tree when it writes the
    file, and it knows things our traversal cannot — such as a package being reached
    only through an optional dependency that failed to install.
    """
    return [
        replace(entry, scope=scopes[entry.node.key])
        if entry.node.key in scopes
        else entry
        for entry in resolved
    ]


def _build(
    nodes: dict[str, Node],
    seeds: dict[str, Scope],
    scopes: dict[str, Scope],
    path: Path,
) -> list[Dependency]:
    resolved = _apply_lock_scopes(resolve(nodes, seeds), scopes)
    return build_dependencies(resolved, nodes, ecosystem=EcosystemId.NPM, path=path)


# ---------------------------------------------------------------------------
# package.json
# ---------------------------------------------------------------------------


def parse_manifest(path: Path, content: str) -> list[Dependency]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ParseError(str(path), f"invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError(str(path), "expected a JSON object")

    dependencies: list[Dependency] = []
    for section, scope in _MANIFEST_SECTIONS:
        table = data.get(section)
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            if not isinstance(spec, str):
                continue
            version, constraint = _spec_version(spec)
            if version is None and constraint is None:
                continue
            dependencies.append(
                Dependency(
                    ref=PackageRef(EcosystemId.NPM, name, version),
                    scope=scope,
                    direct=True,
                    source=SourceLocation(path, _find_line(content, name)),
                    pin=Pin.PINNED if version else Pin.UNRESOLVED,
                    constraint=constraint,
                )
            )
    return dependencies


def _find_line(content: str, name: str) -> int | None:
    needle = f'"{name}"'
    for number, line in enumerate(content.splitlines(), start=1):
        if needle in line:
            return number
    return None


# ---------------------------------------------------------------------------
# package-lock.json
# ---------------------------------------------------------------------------


def _entry_scope(entry: dict[str, Any]) -> Scope | None:
    """Read npm's precomputed scope flags, or ``None`` if it recorded none."""
    if entry.get("dev") or entry.get("devOptional"):
        return Scope.DEV
    if entry.get("optional"):
        return Scope.OPTIONAL
    return None


def _resolve_install_path(known: set[str], parent: str, name: str) -> str | None:
    """Find which installed copy a dependency edge points at.

    npm hoists packages, so an edge from ``node_modules/a`` to ``b`` may resolve to a
    nested copy under ``a`` or to a hoisted one at the top level.
    Node's own algorithm walks up the directory chain taking the first match, and
    reproducing that is what keeps the parent edges honest when two versions of the
    same package are installed side by side.
    """
    prefix = parent
    while True:
        candidate = (
            f"{prefix}{_NODE_MODULES}{name}" if prefix else f"node_modules/{name}"
        )
        if candidate in known:
            return candidate
        if not prefix:
            return None
        index = prefix.rfind(_NODE_MODULES)
        prefix = prefix[:index] if index != -1 else ""


def _parse_package_lock(path: Path, content: str) -> list[Dependency]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ParseError(str(path), f"invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError(str(path), "expected a JSON object")

    if isinstance(data.get("packages"), dict):
        return _parse_lock_v2(path, data)
    if isinstance(data.get("dependencies"), dict):
        return _parse_lock_v1(path, data)

    version = data.get("lockfileVersion", "unknown")
    raise UnsupportedFileError(
        str(path),
        f"lockfileVersion {version} has neither a packages nor a dependencies map",
    )


def _parse_lock_v2(path: Path, data: dict[str, Any]) -> list[Dependency]:
    packages: dict[str, Any] = data["packages"]
    known = set(packages)

    nodes: dict[str, Node] = {}
    scopes: dict[str, Scope] = {}

    for install_path, entry in packages.items():
        # "" is the project itself, and "link" entries are workspace symlinks whose
        # real content lives at another key.
        if not install_path or not isinstance(entry, dict) or entry.get("link"):
            continue

        children = [
            resolved
            for section in ("dependencies", "optionalDependencies", "peerDependencies")
            for name in (entry.get(section) or {})
            if (resolved := _resolve_install_path(known, install_path, name))
            is not None
        ]
        nodes[install_path] = Node(
            key=install_path,
            name=_package_name(install_path),
            version=entry.get("version")
            if isinstance(entry.get("version"), str)
            else None,
            children=tuple(dict.fromkeys(children)),
        )
        scope = _entry_scope(entry)
        if scope is not None:
            scopes[install_path] = scope

    seeds: dict[str, Scope] = {}
    root = packages.get("", {})
    if isinstance(root, dict):
        for section, scope in _MANIFEST_SECTIONS:
            for name in root.get(section) or {}:
                key = _resolve_install_path(known, "", name)
                if key is not None:
                    seeds.setdefault(key, scope)

    return _build(nodes, seeds, scopes, path)


def _parse_lock_v1(path: Path, data: dict[str, Any]) -> list[Dependency]:
    """Walk the nested v1 tree.

    v1 nests a package's private dependencies under it rather than recording install
    paths, so the path is reconstructed during the walk to give every copy a stable,
    unique key.
    """
    nodes: dict[str, Node] = {}
    scopes: dict[str, Scope] = {}
    requires: dict[str, list[str]] = {}

    def walk(table: dict[str, Any], prefix: str) -> None:
        for name, entry in table.items():
            if not isinstance(entry, dict):
                continue
            key = f"{prefix}{_NODE_MODULES}{name}" if prefix else f"node_modules/{name}"
            nodes[key] = Node(
                key=key,
                name=name,
                version=entry.get("version")
                if isinstance(entry.get("version"), str)
                else None,
            )
            if entry.get("dev"):
                scopes[key] = Scope.DEV
            elif entry.get("optional"):
                scopes[key] = Scope.OPTIONAL
            requires[key] = list(entry.get("requires") or {})
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                walk(nested, key)

    walk(data["dependencies"], "")

    known = set(nodes)
    for key, names in requires.items():
        # Resolution starts at the requiring package's own install path, so a copy
        # nested directly beneath it wins over a hoisted one — Node's rule, and the
        # difference between an edge to the version actually loaded and an edge to
        # some other version of the same package elsewhere in the tree.
        children = [
            resolved
            for name in names
            if (resolved := _resolve_install_path(known, key, name)) is not None
        ]
        nodes[key] = replace(nodes[key], children=tuple(dict.fromkeys(children)))

    # v1 has no root entry, so everything hoisted to the top level seeds the graph.
    # The sibling package.json narrows that to what was actually declared.
    seeds = {
        key: scopes.get(key, Scope.RUNTIME)
        for key in nodes
        if key.count(_NODE_MODULES) == 0
    }
    return _build(nodes, seeds, scopes, path)


# ---------------------------------------------------------------------------
# pnpm-lock.yaml
# ---------------------------------------------------------------------------

#: A pnpm package key: an optional leading slash, the name, a separator, the version,
#: and an optional peer-dependency suffix in brackets.
_PNPM_KEY = re.compile(r"^/?(?P<name>(?:@[^/]+/)?[^/@]+)[@/](?P<version>[^()]+)")


def _pnpm_split(key: str) -> tuple[str, str] | None:
    match = _PNPM_KEY.match(key.split("(")[0])
    if match is None:
        return None
    return match.group("name"), match.group("version").rstrip("/")


def _pnpm_key(name: str, version: str) -> str:
    """Normalise a reference into the canonical ``name@version`` node key."""
    version = version.split("(")[0]
    return f"{name}@{version}"


def _parse_pnpm_lock(path: Path, content: str) -> list[Dependency]:
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ParseError(str(path), f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError(str(path), "expected a YAML mapping")

    version = str(data.get("lockfileVersion", "")).strip()
    # pnpm has written the version as a bare number, a quoted string and a "v"-prefixed
    # one across releases. Anything we cannot read a major out of is refused by name
    # rather than allowed to raise, which would surface as an opaque "parser error".
    major = re.match(r"v?(\d+)", version)
    if version and (major is None or int(major.group(1)) < 6):
        raise UnsupportedFileError(
            str(path),
            f"pnpm lockfileVersion {version} is not supported (need 6.0 or later)",
        )

    nodes: dict[str, Node] = {}
    scopes: dict[str, Scope] = {}

    # v9 splits metadata (packages) from edges (snapshots); v6 keeps both together.
    entries: dict[str, Any] = {}
    for section in ("packages", "snapshots"):
        table = data.get(section)
        if isinstance(table, dict):
            for raw_key, entry in table.items():
                merged = entries.setdefault(str(raw_key).split("(")[0], {})
                if isinstance(entry, dict):
                    merged.update(entry)

    for raw_key, entry in entries.items():
        split = _pnpm_split(raw_key)
        if split is None:
            continue
        name, package_version = split
        key = _pnpm_key(name, package_version)
        children = [
            _pnpm_key(child_name, str(child_version))
            for section in ("dependencies", "optionalDependencies")
            for child_name, child_version in (entry.get(section) or {}).items()
        ]
        nodes[key] = Node(
            key=key, name=name, version=package_version, children=tuple(children)
        )
        if entry.get("dev") is True:
            scopes[key] = Scope.DEV

    seeds: dict[str, Scope] = {}
    importers = data.get("importers")
    sources = list(importers.values()) if isinstance(importers, dict) else [data]
    for importer in sources:
        if not isinstance(importer, dict):
            continue
        for section, scope in _MANIFEST_SECTIONS:
            table = importer.get(section)
            if not isinstance(table, dict):
                continue
            for name, entry in table.items():
                resolved_version = (
                    entry.get("version") if isinstance(entry, dict) else entry
                )
                if isinstance(resolved_version, str):
                    seeds.setdefault(_pnpm_key(name, resolved_version), scope)

    return _build(nodes, seeds, scopes, path)


# ---------------------------------------------------------------------------
# yarn.lock
# ---------------------------------------------------------------------------


def _parse_yarn_lock(path: Path, content: str) -> list[Dependency]:
    if "__metadata" in content:
        return _parse_yarn_berry(path, content)
    return _parse_yarn_v1(path, content)


def _parse_yarn_berry(path: Path, content: str) -> list[Dependency]:
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ParseError(str(path), f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError(str(path), "expected a YAML mapping")

    nodes: dict[str, Node] = {}
    spec_index: dict[str, str] = {}

    for raw_key, entry in data.items():
        if raw_key == "__metadata" or not isinstance(entry, dict):
            continue
        version = entry.get("version")
        if not isinstance(version, str):
            continue

        specs = [spec.strip().strip('"') for spec in str(raw_key).split(",")]
        name = _yarn_spec_name(specs[0])
        if name is None:
            continue
        key = f"{name}@{version}"
        for spec in specs:
            spec_index[spec] = key
        nodes[key] = Node(key=key, name=name, version=version)

    _link_yarn_children(nodes, data, spec_index, berry=True)

    # Berry records the workspace root as a "@workspace:" resolution; everything it
    # requires is direct. Failing that, the sibling package.json supplies directness.
    return _build(nodes, dict.fromkeys(nodes, Scope.RUNTIME), {}, path)


def _yarn_spec_name(spec: str) -> str | None:
    """Extract the package name from a ``name@range`` descriptor."""
    spec = spec.strip().strip('"')
    if not spec:
        return None
    index = spec.rfind("@")
    return spec[:index] if index > 0 else spec


def _link_yarn_children(
    nodes: dict[str, Node],
    data: dict[str, Any],
    spec_index: dict[str, str],
    *,
    berry: bool,
) -> None:
    """Wire dependency edges using the descriptor index.

    A yarn lockfile records each edge as the *range* that was requested, and the same
    range appears verbatim as a key elsewhere in the file. Looking edges up through
    that index is exact, and avoids needing a semver resolver to read a lockfile.
    """
    for raw_key, entry in data.items():
        if raw_key == "__metadata" or not isinstance(entry, dict):
            continue
        first = str(raw_key).split(",")[0].strip().strip('"')
        key = spec_index.get(first)
        if key is None or key not in nodes:
            continue

        children = []
        for section in ("dependencies", "optionalDependencies"):
            table = entry.get(section)
            if not isinstance(table, dict):
                continue
            for name, range_spec in table.items():
                descriptor = f"{name}@{range_spec}"
                target = spec_index.get(descriptor)
                if target is None and berry:
                    target = spec_index.get(f"{name}@npm:{range_spec}")
                if target is not None:
                    children.append(target)

        nodes[key] = replace(nodes[key], children=tuple(dict.fromkeys(children)))


_YARN_HEADER = re.compile(r"^(?P<specs>\S.*?):\s*$")
_YARN_FIELD = re.compile(r'^\s+(?P<key>[\w-]+)\s+"?(?P<value>[^"]*)"?\s*$')


def _parse_yarn_v1(path: Path, content: str) -> list[Dependency]:
    """Parse the bespoke yarn v1 format.

    Entries are an unindented comma-separated list of ``name@range`` descriptors
    ending in a colon, followed by indented fields. It is not YAML and cannot be
    parsed as such.

    v1 records neither directness nor scope, so every package starts as a direct
    runtime dependency and the sibling package.json corrects it. That over-reports
    dev dependencies when no package.json is present, which is the safe direction.
    """
    blocks: dict[str, dict[str, Any]] = {}
    current: dict[str, Any] | None = None
    section: str | None = None

    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue

        if not line[0].isspace():
            header = _YARN_HEADER.match(line)
            if header is None:
                continue
            current = {"specs": header.group("specs"), "dependencies": {}}
            blocks[header.group("specs")] = current
            section = None
            continue

        if current is None:
            continue

        stripped = line.strip()
        if stripped.endswith(":") and " " not in stripped[:-1]:
            section = stripped[:-1]
            continue

        field = _YARN_FIELD.match(line)
        if field is None:
            continue
        if section in ("dependencies", "optionalDependencies"):
            current["dependencies"][field.group("key").strip('"')] = field.group(
                "value"
            )
        elif field.group("key") == "version":
            current["version"] = field.group("value")
            section = None

    if not blocks:
        raise ParseError(str(path), "no lockfile entries found")

    nodes: dict[str, Node] = {}
    spec_index: dict[str, str] = {}
    for specs, block in blocks.items():
        version = block.get("version")
        if not isinstance(version, str):
            continue
        descriptors = [spec.strip().strip('"') for spec in specs.split(",")]
        name = _yarn_spec_name(descriptors[0])
        if name is None:
            continue
        key = f"{name}@{version}"
        for descriptor in descriptors:
            spec_index[descriptor] = key
        nodes[key] = Node(key=key, name=name, version=version)

    for specs, block in blocks.items():
        node_key = spec_index.get(specs.split(",")[0].strip().strip('"'))
        if node_key is None or node_key not in nodes:
            continue
        children = [
            target
            for name, range_spec in block["dependencies"].items()
            if (target := spec_index.get(f"{name}@{range_spec}")) is not None
        ]
        nodes[node_key] = replace(
            nodes[node_key], children=tuple(dict.fromkeys(children))
        )

    return _build(nodes, dict.fromkeys(nodes, Scope.RUNTIME), {}, path)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def parse_lockfile(path: Path, content: str) -> list[Dependency]:
    filename = path.name.lower()
    if filename == "pnpm-lock.yaml":
        return _parse_pnpm_lock(path, content)
    if filename == "yarn.lock":
        return _parse_yarn_lock(path, content)
    return _parse_package_lock(path, content)


SPEC = EcosystemSpec(
    id=EcosystemId.NPM,
    manifests=FileSpec(names=frozenset({"package.json"})),
    lockfiles=FileSpec(
        names=frozenset(
            {
                "package-lock.json",
                "npm-shrinkwrap.json",
                "pnpm-lock.yaml",
                "yarn.lock",
            }
        )
    ),
    parse_manifest=parse_manifest,
    parse_lockfile=parse_lockfile,
)
