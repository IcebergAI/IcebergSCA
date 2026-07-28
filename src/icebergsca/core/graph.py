"""Turning a lockfile's nodes and edges into scoped, attributed dependencies.

Every lockfile format describes the same shape — a set of resolved packages plus
edges between them, seeded by whatever the project asked for directly. What differs
is only the file syntax, so the traversal lives here once and each parser's job is
reduced to producing :class:`Node` values.

Two things this computes that no lockfile states outright:

* **Effective scope.** A package reachable from a runtime dependency ships, even if
  some other path to it runs through a dev dependency. Scope therefore propagates as
  the *most included* value across all paths, never the last one visited.
* **Parents.** Which packages pull a given one in, which is what lets a report answer
  "why is this here" rather than just "this is here".
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from icebergsca.core.models import Scope

#: Lower sorts first and wins when a package is reachable by several paths. Runtime
#: leads because a package that ships is a package that ships, whatever else also
#: happens to depend on it — resolving a tie the other way would let a dev edge hide
#: a production dependency from the default scan.
_SCOPE_PRECEDENCE: dict[Scope, int] = {
    Scope.RUNTIME: 0,
    Scope.BUILD: 1,
    Scope.OPTIONAL: 2,
    Scope.TEST: 3,
    Scope.DEV: 4,
}


def most_included(scopes: Iterable[Scope], default: Scope = Scope.RUNTIME) -> Scope:
    """The winning scope when a package is declared under several at once.

    Ordering is by inclusion, not alphabetically — ``min`` over the raw enum values
    would rank ``build`` above ``runtime`` purely because "b" sorts before "r".
    """
    candidates = list(scopes)
    return (
        min(candidates, key=lambda scope: _SCOPE_PRECEDENCE[scope])
        if candidates
        else default
    )


@dataclass(frozen=True, slots=True)
class Node:
    """One resolved package in a lockfile.

    ``key`` is whatever uniquely identifies the entry *within that file* — a name for
    flat formats, an install path for npm, ``name@version`` for pnpm. It is never
    shown to users; it exists so edges can be followed unambiguously when the same
    package appears at several versions.
    """

    key: str
    name: str
    version: str | None = None
    children: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Resolved:
    node: Node
    scope: Scope
    direct: bool
    parents: tuple[str, ...] = field(default=())


def resolve(
    nodes: Mapping[str, Node],
    seeds: Mapping[str, Scope],
    *,
    include_unreachable: bool = True,
) -> list[Resolved]:
    """Attribute every node with an effective scope, directness and its parents.

    ``seeds`` maps the keys the project depends on *directly* to the scope it declared
    them under. Nodes reachable from a seed inherit the best scope along any path.

    ``include_unreachable`` keeps entries that no seed reaches, classified as runtime.
    Lockfiles list what is installed; dropping an entry because our seed extraction
    missed it would understate the scan, and over-reporting is the safe direction.
    Output order follows ``nodes`` so reports are stable between runs.
    """
    best = _propagate(nodes, seeds)
    parents = _parents(nodes, best)

    resolved: list[Resolved] = []
    for key, node in nodes.items():
        scope = best.get(key)
        if scope is None:
            if not include_unreachable:
                continue
            scope = Scope.RUNTIME
        resolved.append(
            Resolved(
                node=node,
                scope=scope,
                direct=key in seeds,
                parents=tuple(parents.get(key, ())),
            )
        )
    return resolved


def _propagate(
    nodes: Mapping[str, Node], seeds: Mapping[str, Scope]
) -> dict[str, Scope]:
    """Breadth-first scope propagation from the seeds.

    A node is re-enqueued only when a path reaches it with a *better* scope, which is
    what terminates the walk on cyclic graphs — and dependency graphs do contain
    cycles, particularly in npm.
    """
    best: dict[str, Scope] = {}
    queue: deque[str] = deque()

    for key, scope in seeds.items():
        if key in nodes and _improves(scope, best.get(key)):
            best[key] = scope
            queue.append(key)

    while queue:
        key = queue.popleft()
        scope = best[key]
        for child in nodes[key].children:
            if child in nodes and _improves(scope, best.get(child)):
                best[child] = scope
                queue.append(child)

    return best


def _improves(candidate: Scope, current: Scope | None) -> bool:
    if current is None:
        return True
    return _SCOPE_PRECEDENCE[candidate] < _SCOPE_PRECEDENCE[current]


def _parents(
    nodes: Mapping[str, Node], reachable: Mapping[str, Scope]
) -> dict[str, list[str]]:
    """Invert the edges, keeping only parents that are themselves part of the graph."""
    parents: dict[str, list[str]] = defaultdict(list)
    for key, node in nodes.items():
        if key not in reachable:
            continue
        for child in node.children:
            if child in nodes and key not in parents[child]:
                parents[child].append(key)
    return parents
