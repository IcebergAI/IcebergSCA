"""RubyGems manifests and lockfiles.

``Gemfile.lock`` encodes the graph in its indentation: gems sit at four spaces under
``GEM/specs``, and their dependencies at six. The ``DEPENDENCIES`` section at the end
lists what the Gemfile asked for directly.

Scope is the one thing the lockfile omits — Bundler groups (``:development``,
``:test``) live only in the Gemfile — so the scanner merges that in.
"""

from __future__ import annotations

import re
from pathlib import Path

from icebergsca.core.graph import Node, most_included, resolve
from icebergsca.core.models import (
    Dependency,
    EcosystemId,
    PackageRef,
    Pin,
    Scope,
    SourceLocation,
)
from icebergsca.ecosystems.base import EcosystemSpec, FileSpec, build_dependencies

#: ``gem "rails", "~> 7.1.0"`` — quotes may be single or double.
_GEM = re.compile(
    r"""^\s*gem\s+["'](?P<name>[^"']+)["']\s*(?:,\s*["'](?P<version>[^"']+)["'])?"""
)
#: ``group :development, :test do`` — the group list runs up to a standalone ``do``.
_GROUP = re.compile(r"^\s*group\s+(?P<groups>.+?)\s+do\s*$")
#: A spec line inside GEM/specs: four spaces for a gem, six for its dependencies.
_SPEC = re.compile(
    r"^(?P<indent> +)(?P<name>[A-Za-z0-9._-]+)(?:\s+\((?P<version>[^)]+)\))?$"
)

_GROUP_SCOPES: dict[str, Scope] = {
    "development": Scope.DEV,
    "test": Scope.TEST,
}

#: An exact pin in a Gemfile. Everything else (``~>``, ``>=``) is a range.
_EXACT = re.compile(r"^=?\s*(?P<version>\d[\w.]*)$")


def parse_manifest(path: Path, content: str) -> list[Dependency]:
    """Parse a Gemfile, tracking which ``group`` block each gem sits in."""
    dependencies: list[Dependency] = []
    group_stack: list[Scope] = []

    for number, raw in enumerate(content.splitlines(), start=1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue

        group = _GROUP.match(line)
        if group:
            names = [
                token.strip().lstrip(":").strip("\"'")
                for token in group.group("groups").split(",")
            ]
            # A gem in several groups is installed whenever any of them is, so the
            # most-included scope wins — the same rule the graph resolver uses.
            group_stack.append(
                most_included(
                    (_GROUP_SCOPES.get(name, Scope.OPTIONAL) for name in names if name),
                    default=Scope.OPTIONAL,
                )
            )
            continue

        if line.strip() == "end" and group_stack:
            group_stack.pop()
            continue

        match = _GEM.match(line)
        if match is None:
            continue

        constraint = match.group("version")
        exact = _EXACT.match(constraint.strip()) if constraint else None
        # An inline "group:" option is equivalent to wrapping the gem in a block.
        scope = _inline_scope(line) or (
            group_stack[-1] if group_stack else Scope.RUNTIME
        )

        dependencies.append(
            Dependency(
                ref=PackageRef(
                    EcosystemId.RUBYGEMS,
                    match.group("name"),
                    exact.group("version") if exact else None,
                ),
                scope=scope,
                direct=True,
                source=SourceLocation(path, number),
                pin=Pin.PINNED if exact else Pin.UNRESOLVED,
                constraint=constraint,
            )
        )

    return dependencies


def _inline_scope(line: str) -> Scope | None:
    match = re.search(r"group:\s*:?(\w+)|:group\s*=>\s*:(\w+)", line)
    if match is None:
        return None
    name = match.group(1) or match.group(2)
    return _GROUP_SCOPES.get(name, Scope.OPTIONAL)


def parse_lockfile(path: Path, content: str) -> list[Dependency]:
    """Read the resolved graph out of a Gemfile.lock.

    Indentation is the structure: four spaces introduces a resolved gem, six spaces
    lists one of its dependencies. The ``DEPENDENCIES`` block names the direct ones.
    """
    nodes: dict[str, Node] = {}
    seeds: dict[str, Scope] = {}
    section: str | None = None
    current: str | None = None
    children: dict[str, list[str]] = {}

    for raw in content.splitlines():
        if not raw.strip():
            continue

        if not raw[0].isspace():
            section = raw.strip()
            current = None
            continue

        if section == "DEPENDENCIES":
            name = raw.strip().split()[0].rstrip("!")
            seeds[name] = Scope.RUNTIME
            continue

        if section not in ("GEM", "GIT", "PATH", "PLUGIN SOURCE"):
            continue

        match = _SPEC.match(raw)
        if match is None:
            current = None
            continue

        indent = len(match.group("indent"))
        name = match.group("name")

        if indent <= 4:
            current = name
            children.setdefault(name, [])
            nodes[name] = Node(key=name, name=name, version=match.group("version"))
        elif current is not None:
            children[current].append(name)

    for name, kids in children.items():
        if name in nodes:
            nodes[name] = Node(
                key=name,
                name=name,
                version=nodes[name].version,
                children=tuple(kid for kid in kids if kid in nodes),
            )

    if not seeds:
        seeds = dict.fromkeys(nodes, Scope.RUNTIME)

    return build_dependencies(
        resolve(nodes, seeds), nodes, ecosystem=EcosystemId.RUBYGEMS, path=path
    )


SPEC = EcosystemSpec(
    id=EcosystemId.RUBYGEMS,
    manifests=FileSpec(names=frozenset({"gemfile"}), patterns=("*.gemspec",)),
    lockfiles=FileSpec(names=frozenset({"gemfile.lock"})),
    parse_manifest=parse_manifest,
    parse_lockfile=parse_lockfile,
)
