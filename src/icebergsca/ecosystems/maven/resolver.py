"""Reconstructing Maven's transitive graph from Maven Central.

Java has no lockfile, and ``pom.xml`` alone lists only direct dependencies. The rest
of the graph depends on parent POMs, ``dependencyManagement``, imported BOMs and
properties that may be defined several files away.

We rebuild that by fetching POMs from Central rather than running ``mvn``. Executing
a project's build in order to find out what it depends on is itself a supply chain
risk — a malicious build script would run with the scanner's privileges — and it also
requires a JDK, a warm local repository, and minutes rather than seconds.

The trade-off is honesty about fidelity. We implement Maven's main rules:

* parent inheritance, including properties and ``dependencyManagement``
* ``import``-scoped BOMs, expanded recursively
* nearest-wins conflict resolution, breadth-first
* ``test``/``provided`` scopes not propagating, and ``<exclusions>`` being honoured

We do not implement profiles, mirrors, ``<relocation>``, version *ranges*, or
classifier-specific graphs. The result is therefore marked ``approximate`` in the
report, and the output says so rather than implying a fidelity it does not have.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field, replace
from pathlib import Path

import httpx

from icebergsca.cache import Cache
from icebergsca.core.models import (
    Dependency,
    EcosystemId,
    PackageRef,
    Pin,
    Scope,
    SourceLocation,
)
from icebergsca.ecosystems.maven.model import (
    NON_TRANSITIVE_SCOPES,
    Coordinate,
    Pom,
    RawDependency,
)
from icebergsca.ecosystems.maven.parser import (
    has_unresolved_property,
    interpolate,
    maven_scope,
    parse_pom,
)

logger = logging.getLogger(__name__)

CENTRAL = "https://repo1.maven.org/maven2"

#: Depth and breadth caps. A large Spring project reaches several hundred nodes;
#: beyond that we are almost certainly in a cycle or a mis-parse, and an unbounded
#: fetch loop against Central is not an acceptable failure mode.
MAX_DEPTH = 5
MAX_NODES = 500

#: Parent chains are short in practice. This only guards against a cycle.
MAX_PARENT_DEPTH = 10

_TIMEOUT = 15.0


@dataclass(frozen=True, slots=True)
class EffectivePom:
    """A POM merged with everything it inherits."""

    coordinate: Coordinate
    properties: dict[str, str] = field(default_factory=dict)
    #: ``group:artifact`` → version, from dependencyManagement and imported BOMs.
    managed: dict[str, str] = field(default_factory=dict)
    #: ``group:artifact`` → scope, so a BOM can pin scope as well as version.
    managed_scopes: dict[str, str] = field(default_factory=dict)
    dependencies: tuple[RawDependency, ...] = ()


@dataclass(frozen=True, slots=True)
class MavenResult:
    dependencies: tuple[Dependency, ...]
    warnings: tuple[str, ...] = ()
    #: True when at least one graph was reconstructed rather than read from a file.
    approximate: bool = False


class MavenResolver:
    """Expands declared Maven dependencies into a full transitive graph."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        cache: Cache,
        *,
        offline: bool = False,
        concurrency: int = 10,
        max_depth: int = MAX_DEPTH,
        max_nodes: int = MAX_NODES,
    ) -> None:
        self._client = client
        self._cache = cache
        self._offline = offline
        self._semaphore = asyncio.Semaphore(max(1, concurrency))
        self._max_depth = max_depth
        self._max_nodes = max_nodes
        self._warnings: list[str] = []

    # -- public ------------------------------------------------------------

    async def expand(
        self, declared: tuple[Dependency, ...], root: Path | None = None
    ) -> MavenResult:
        """Walk the graph beneath a set of declared Maven dependencies.

        Two things happen here. First any direct dependency that declared no version
        gets one from the project's own ``dependencyManagement`` — which usually means
        fetching an imported BOM, since that is how Spring Boot projects are written
        and why so many ``<dependency>`` blocks carry no ``<version>`` at all. Then
        the transitive graph beneath everything is walked.

        Anything whose version we never learn is kept and reported unresolved rather
        than dropped.
        """
        maven_deps = [dep for dep in declared if dep.ref.ecosystem is EcosystemId.MAVEN]
        if not maven_deps:
            return MavenResult(declared)

        declared = await self._backfill(declared, root)
        roots = [dep for dep in declared if dep.ref.ecosystem is EcosystemId.MAVEN]

        found = await self._walk(roots, roots[0].source)
        known = {dep.ref.name for dep in declared}
        transitive = tuple(dep for dep in found if dep.ref.name not in known)

        return MavenResult(
            dependencies=declared + transitive,
            warnings=tuple(dict.fromkeys(self._warnings)),
            approximate=True,
        )

    async def _backfill(
        self, declared: tuple[Dependency, ...], root: Path | None
    ) -> tuple[Dependency, ...]:
        """Fill in versions the project's own dependencyManagement supplies.

        The synchronous parser can only see literal versions in the file it was
        handed. A ``<scope>import</scope>`` BOM lives on Maven Central, so resolving
        it needs the network and has to happen here.
        """
        unresolved = {
            dep.source.path
            for dep in declared
            if dep.ref.ecosystem is EcosystemId.MAVEN and dep.ref.version is None
        }
        if not unresolved or root is None:
            return declared

        managed: dict[str, str] = {}
        for relative in sorted(unresolved):
            path = root / relative
            if path.name.lower() != "pom.xml":
                continue  # Gradle has no equivalent we can read statically
            try:
                pom = parse_pom(
                    path.read_text(encoding="utf-8", errors="replace"), source=str(path)
                )
            except (OSError, Exception) as exc:  # noqa: BLE001 — never fail the scan
                logger.debug("could not re-read %s: %s", path, exc)
                continue

            properties = dict(pom.properties)
            properties.setdefault("project.version", pom.coordinate.version or "")
            properties.setdefault("project.groupId", pom.coordinate.group)
            await self._apply_management(pom, properties, managed, {})

        if not managed:
            return declared

        return tuple(
            replace(
                dep,
                ref=PackageRef(EcosystemId.MAVEN, dep.ref.name, managed[dep.ref.name]),
                pin=Pin.PINNED,
            )
            if dep.ref.ecosystem is EcosystemId.MAVEN
            and dep.ref.version is None
            and dep.ref.name in managed
            else dep
            for dep in declared
        )

    # -- traversal ---------------------------------------------------------

    async def _walk(
        self, roots: list[Dependency], source: SourceLocation
    ) -> list[Dependency]:
        """Breadth-first, nearest-wins.

        Maven resolves a version conflict by taking the declaration closest to the
        root, so a breadth-first walk that ignores any coordinate already seen
        reproduces that rule exactly — the first time a ``group:artifact`` is
        reached is by definition its shortest path.
        """
        seen: dict[str, str | None] = {}
        results: list[Dependency] = []

        frontier: list[tuple[Coordinate, Scope, frozenset[str]]] = []
        for dep in roots:
            group, _, artifact = dep.ref.name.partition(":")
            seen[dep.ref.name] = dep.ref.version
            if dep.ref.version and dep.scope not in (Scope.TEST,):
                frontier.append(
                    (
                        Coordinate(group, artifact, dep.ref.version),
                        dep.scope,
                        frozenset(),
                    )
                )

        depth = 0
        while frontier and depth < self._max_depth and len(seen) < self._max_nodes:
            depth += 1
            poms = await asyncio.gather(
                *(self._effective(coordinate) for coordinate, _, _ in frontier),
                return_exceptions=True,
            )

            next_frontier: list[tuple[Coordinate, Scope, frozenset[str]]] = []
            for (parent_coord, parent_scope, inherited), pom in zip(
                frontier, poms, strict=True
            ):
                if isinstance(pom, BaseException) or pom is None:
                    logger.debug("could not resolve %s: %s", parent_coord, pom)
                    continue

                for child, version, scope in self._children(pom, parent_scope):
                    if child.key in inherited or child.key in seen:
                        continue
                    if len(seen) >= self._max_nodes:
                        break

                    seen[child.key] = version
                    results.append(
                        Dependency(
                            ref=PackageRef(EcosystemId.MAVEN, child.key, version),
                            scope=scope,
                            direct=False,
                            source=source,
                            pin=Pin.PINNED if version else Pin.UNRESOLVED,
                        )
                    )
                    if version:
                        next_frontier.append(
                            (
                                Coordinate(child.group, child.artifact, version),
                                scope,
                                inherited | child.exclusions,
                            )
                        )

            frontier = next_frontier

        if len(seen) >= self._max_nodes:
            self._warnings.append(
                f"Maven graph truncated at {self._max_nodes} packages; "
                "the dependency list is incomplete"
            )
        return results

    def _children(
        self, pom: EffectivePom, parent_scope: Scope
    ) -> list[tuple[RawDependency, str | None, Scope]]:
        """The dependencies a POM contributes to its dependents.

        Optional dependencies and non-transitive scopes are dropped, because Maven
        does not pass them on — including them would report packages that are never
        on the classpath.
        """
        children: list[tuple[RawDependency, str | None, Scope]] = []

        for entry in pom.dependencies:
            if entry.optional or entry.scope.lower() in NON_TRANSITIVE_SCOPES:
                continue

            group = interpolate(entry.group, pom.properties) or entry.group
            artifact = interpolate(entry.artifact, pom.properties) or entry.artifact
            key = f"{group}:{artifact}"

            version = interpolate(entry.version, pom.properties)
            if not version or has_unresolved_property(version):
                version = pom.managed.get(key)
            if version and has_unresolved_property(version):
                version = None
            # A version range is a resolution problem we do not solve; treat it as
            # unknown rather than pretending the bracket text is a version.
            if version and version.startswith(("[", "(")):
                version = None

            scope_name = entry.scope if entry.scope else pom.managed_scopes.get(key, "")
            scope = maven_scope(scope_name) if scope_name else Scope.RUNTIME
            # A dependency of a build-scoped dependency is itself build-scoped.
            if parent_scope is not Scope.RUNTIME:
                scope = parent_scope

            resolved = RawDependency(
                group=group,
                artifact=artifact,
                version=version,
                scope=entry.scope,
                exclusions=entry.exclusions,
            )
            children.append((resolved, version, scope))

        return children

    # -- effective POMs ----------------------------------------------------

    async def _effective(self, coordinate: Coordinate) -> EffectivePom | None:
        """Merge a POM with its parent chain and any BOMs it imports."""
        pom = await self._fetch_pom(coordinate)
        if pom is None:
            return None

        properties: dict[str, str] = {}
        managed: dict[str, str] = {}
        managed_scopes: dict[str, str] = {}

        chain: list[Pom] = [pom]
        current = pom
        for _ in range(MAX_PARENT_DEPTH):
            if current.parent is None or not current.parent.version:
                break
            parent = await self._fetch_pom(current.parent)
            if parent is None:
                break
            chain.append(parent)
            current = parent

        # Walk the chain from the most distant ancestor inwards so that nearer
        # definitions overwrite inherited ones, which is Maven's own precedence.
        for entry in reversed(chain):
            properties.update(entry.properties)

        properties.setdefault("project.version", coordinate.version or "")
        properties.setdefault("project.groupId", coordinate.group)
        properties.setdefault("project.artifactId", coordinate.artifact)

        for entry in reversed(chain):
            await self._apply_management(entry, properties, managed, managed_scopes)

        return EffectivePom(
            coordinate=coordinate,
            properties=properties,
            managed=managed,
            managed_scopes=managed_scopes,
            dependencies=pom.dependencies,
        )

    async def _apply_management(
        self,
        pom: Pom,
        properties: dict[str, str],
        managed: dict[str, str],
        managed_scopes: dict[str, str],
    ) -> None:
        """Fold one POM's dependencyManagement in, expanding imported BOMs first.

        A BOM's entries are weaker than the importing POM's own, so they are applied
        before it — that is what lets a project override a version a BOM pins.
        """
        for entry in pom.managed:
            group = interpolate(entry.group, properties) or entry.group
            artifact = interpolate(entry.artifact, properties) or entry.artifact
            version = interpolate(entry.version, properties)

            if entry.is_import and version and not has_unresolved_property(version):
                bom = await self._effective(Coordinate(group, artifact, version))
                if bom is not None:
                    properties.update(
                        {k: v for k, v in bom.properties.items() if k not in properties}
                    )
                    for key, bom_version in bom.managed.items():
                        managed.setdefault(key, bom_version)
                continue

            if version and not has_unresolved_property(version):
                managed[f"{group}:{artifact}"] = version
            if entry.scope:
                managed_scopes[f"{group}:{artifact}"] = entry.scope

    async def _fetch_pom(self, coordinate: Coordinate) -> Pom | None:
        """Fetch and parse one POM, cached for a week.

        POMs at a released version are immutable, so a long TTL is safe — Central
        does not permit republishing a version.
        """
        if not coordinate.version or not coordinate.group or not coordinate.artifact:
            return None

        key = str(coordinate)
        cached = self._cache.get("maven_pom", key)
        if cached is not None:
            return self._parse(cached.payload, key)

        if self._offline:
            stale = self._cache.get("maven_pom", key, allow_stale=True)
            return self._parse(stale.payload, key) if stale else None

        url = (
            f"{CENTRAL}/{coordinate.group.replace('.', '/')}/{coordinate.artifact}"
            f"/{coordinate.version}/{coordinate.artifact}-{coordinate.version}.pom"
        )

        async with self._semaphore:
            try:
                response = await self._client.get(url, timeout=_TIMEOUT)
            except httpx.HTTPError as exc:
                self._warnings.append(f"could not fetch POM for {coordinate}: {exc}")
                return None

        if response.status_code == 404:
            logger.debug("no POM at %s", url)
            return None
        if response.status_code >= 400:
            self._warnings.append(
                f"Maven Central returned HTTP {response.status_code} for {coordinate}"
            )
            return None

        self._cache.set("maven_pom", key, response.text)
        self._cache.commit()
        return self._parse(response.text, key)

    def _parse(self, text: str, source: str) -> Pom | None:
        try:
            return parse_pom(text, source=source)
        except Exception as exc:  # noqa: BLE001 — a bad POM must not end the scan
            logger.debug("unparseable POM %s: %s", source, exc)
            return None
