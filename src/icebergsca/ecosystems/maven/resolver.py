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
* nearest-wins conflict resolution, breadth-first, **per module**
* ``test``/``provided`` scopes not propagating
* ``<exclusions>`` on declared and inherited dependencies alike, including the
  whole-segment wildcards (``*:*``, ``group:*``, ``*:artifact``) Maven 3 allows

We do not implement profiles, mirrors, ``<relocation>``, version *ranges*, or
classifier-specific graphs, and a parent POM that exists only on disk — never
published to Central — cannot be read, so the management it supplies is missed. The
result is therefore marked ``approximate`` in the report, and the output says so
rather than implying a fidelity it does not have.

Each module is resolved on its own. Sharing one traversal across a reactor lets
whichever module was walked first decide the others' versions, and leaves every
transitive attributed to a POM that may not lead to it.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePath

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
    DEFAULT_SCOPE,
    NON_TRANSITIVE_SCOPES,
    Coordinate,
    Pom,
    RawDependency,
    is_excluded,
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

#: What a coordinate component may contain before it is interpolated into a Central
#: URL. Coordinates come out of POM files inside a scanned repository — untrusted
#: input — and Maven's own rules are far narrower than "any string", so anything
#: outside this is refused rather than escaped. ``.`` matters especially: group
#: separators become path separators, so a component of ``..`` would traverse.
_VALID_COMPONENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.+-]*$")


@dataclass(frozen=True, slots=True)
class EffectivePom:
    """A POM merged with everything it inherits."""

    coordinate: Coordinate
    properties: dict[str, str] = field(default_factory=dict)
    #: ``group:artifact`` → version, from dependencyManagement and imported BOMs.
    managed: dict[str, str] = field(default_factory=dict)
    #: ``group:artifact`` → scope, so a BOM can pin scope as well as version.
    managed_scopes: dict[str, str] = field(default_factory=dict)
    #: ``group:artifact`` → exclusions, so a parent or BOM can centralise them.
    managed_exclusions: dict[str, frozenset[str]] = field(default_factory=dict)
    dependencies: tuple[RawDependency, ...] = ()


@dataclass(frozen=True, slots=True)
class MavenResult:
    dependencies: tuple[Dependency, ...]
    warnings: tuple[str, ...] = ()
    #: True when at least one graph was reconstructed rather than read from a file.
    approximate: bool = False


@dataclass(frozen=True, slots=True)
class MavenUnit:
    """One module's declared dependencies, resolved on its own.

    Maven resolves each module against its own effective POM; siblings share a parent,
    not a graph. Keeping them apart is what stops one module's nearest-wins choice
    deciding another's versions.
    """

    directory: PurePath
    dependencies: tuple[Dependency, ...]


@dataclass(frozen=True, slots=True)
class _Branch:
    """One node on the breadth-first frontier."""

    coordinate: Coordinate
    scope: Scope
    #: Exclusion patterns accumulated from every edge on the path to this node.
    exclusions: frozenset[str]
    #: The ``<dependency>`` element that introduced this branch, carried down so that
    #: a transitive names the declaration which actually pulled it in rather than
    #: whichever file happened to be walked first.
    source: SourceLocation


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
        #: Nodes walked across every unit this resolver has expanded. The cap is
        #: deliberately scan-wide rather than per-module: it exists to bound an
        #: unbounded fetch loop against Central, and a nine-module reactor must not
        #: get nine times the budget just for being split up.
        self._nodes = 0
        self._warnings: list[str] = []

    # -- public ------------------------------------------------------------

    async def expand_units(
        self,
        declared: tuple[Dependency, ...],
        units: Sequence[MavenUnit],
        root: Path | None = None,
    ) -> MavenResult:
        """Expand several modules, each against its own POM.

        ``declared`` is the whole scan's dependency list and ``units`` groups the Maven
        part of it by module. Everything else flows through untouched and in place, so
        the only difference a non-Maven project sees is that nothing happened.

        One resolver instance serves every unit, so the POM cache, the connection pool
        and the node budget are shared. A fresh resolver per module would refetch
        Central for every coordinate the modules have in common — on a reactor, most
        of them.
        """
        resolved: dict[Dependency, Dependency] = {}
        transitive: list[Dependency] = []
        warnings: list[str] = []
        approximate = False

        for unit in units:
            result = await self.expand(unit.dependencies, root)
            # ``expand`` returns this unit's declarations first, in the order it was
            # given them, followed by whatever the walk found beneath them.
            count = len(unit.dependencies)
            resolved.update(
                zip(unit.dependencies, result.dependencies[:count], strict=True)
            )
            transitive.extend(result.dependencies[count:])
            warnings.extend(result.warnings)
            approximate = approximate or result.approximate

        return MavenResult(
            dependencies=tuple(resolved.get(dep, dep) for dep in declared)
            + tuple(transitive),
            warnings=tuple(dict.fromkeys(warnings)),
            approximate=approximate,
        )

    async def expand(
        self, declared: tuple[Dependency, ...], root: Path | None = None
    ) -> MavenResult:
        """Walk the graph beneath one module's declared Maven dependencies.

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

        # Warnings accumulate on the instance so that one shared resolver can serve
        # every unit; slicing from here keeps a module's result to its own problems
        # instead of repeating the previous module's.
        first_warning = len(self._warnings)

        declared = await self._backfill(declared, root)
        roots = [dep for dep in declared if dep.ref.ecosystem is EcosystemId.MAVEN]

        found = await self._walk(roots)
        known = {dep.ref.name for dep in declared}
        transitive = tuple(dep for dep in found if dep.ref.name not in known)

        return MavenResult(
            dependencies=declared + transitive,
            warnings=tuple(dict.fromkeys(self._warnings[first_warning:])),
            approximate=True,
        )

    async def _backfill(
        self, declared: tuple[Dependency, ...], root: Path | None
    ) -> tuple[Dependency, ...]:
        """Fill in what the project's own dependencyManagement supplies.

        The synchronous parser can only see literal versions in the file it was
        handed. A ``<scope>import</scope>`` BOM lives on Maven Central, so resolving
        it needs the network and has to happen here.

        Only this unit's own POMs are read. Pooling every POM in the tree would let a
        BOM imported by one module supply versions to another, which no Maven build
        does and which quietly attributes one module's choices to another.
        """
        if root is None:
            return declared

        unresolved = {
            dep.source.path
            for dep in declared
            if dep.ref.ecosystem is EcosystemId.MAVEN and dep.ref.version is None
        }
        # Still gated on an unresolved version, so a fully-versioned project pays no
        # network cost it did not pay before. Same-file management exclusions are
        # already applied by the parser; what this adds is the BOM-supplied ones,
        # which is the case that needs Central anyway.
        if not unresolved:
            return declared

        managed: dict[str, str] = {}
        managed_exclusions: dict[str, frozenset[str]] = {}
        for relative in sorted(unresolved):
            path = root / relative
            if path.name.lower() != "pom.xml":
                continue  # Gradle has no equivalent we can read statically
            try:
                pom = parse_pom(
                    path.read_text(encoding="utf-8", errors="replace"), source=str(path)
                )
            except Exception as exc:  # noqa: BLE001 — never fail the scan
                logger.debug("could not re-read %s: %s", path, exc)
                continue

            properties = dict(pom.properties)
            properties.setdefault("project.version", pom.coordinate.version or "")
            properties.setdefault("project.groupId", pom.coordinate.group)
            await self._apply_management(
                pom, properties, managed, {}, managed_exclusions
            )

        if not managed and not managed_exclusions:
            return declared

        return tuple(
            self._backfilled(dep, managed, managed_exclusions) for dep in declared
        )

    @staticmethod
    def _backfilled(
        dep: Dependency,
        managed: dict[str, str],
        managed_exclusions: dict[str, frozenset[str]],
    ) -> Dependency:
        """Apply management-supplied versions and exclusions to one declaration."""
        if dep.ref.ecosystem is not EcosystemId.MAVEN:
            return dep

        inherited = managed_exclusions.get(dep.ref.name, frozenset())
        exclusions = dep.exclusions | inherited
        version = managed.get(dep.ref.name) if dep.ref.version is None else None

        if version is None and exclusions == dep.exclusions:
            return dep
        if version is None:
            return replace(dep, exclusions=exclusions)

        return replace(
            dep,
            ref=PackageRef(EcosystemId.MAVEN, dep.ref.name, version),
            pin=Pin.PINNED,
            exclusions=exclusions,
        )

    # -- traversal ---------------------------------------------------------

    async def _walk(self, roots: list[Dependency]) -> list[Dependency]:
        """Breadth-first, nearest-wins, over one module.

        Maven resolves a version conflict by taking the declaration closest to the
        root, so a breadth-first walk that ignores any coordinate already seen
        reproduces that rule exactly — the first time a ``group:artifact`` is
        reached is by definition its shortest path.

        ``seen`` is local to one call, and one call covers one module. Sharing it
        across modules would let whichever module was walked first decide the others'
        versions, which is not what Maven does and not what their builds produce.
        """
        seen: dict[str, str | None] = {}
        results: list[Dependency] = []

        frontier: list[_Branch] = []
        for dep in roots:
            group, _, artifact = dep.ref.name.partition(":")
            seen[dep.ref.name] = dep.ref.version
            if dep.ref.version and dep.scope not in (Scope.TEST,):
                frontier.append(
                    _Branch(
                        coordinate=Coordinate(group, artifact, dep.ref.version),
                        scope=dep.scope,
                        # A declaration's own <exclusions> apply to everything beneath
                        # it. They are checked against children only, so a dependency
                        # is never removed by its own exclusion list.
                        exclusions=dep.exclusions,
                        source=dep.source,
                    )
                )
        self._nodes += len(seen)

        depth = 0
        while frontier and depth < self._max_depth and self._nodes < self._max_nodes:
            depth += 1
            poms = await asyncio.gather(
                *(self._effective(branch.coordinate) for branch in frontier),
                return_exceptions=True,
            )

            next_frontier: list[_Branch] = []
            for branch, pom in zip(frontier, poms, strict=True):
                if isinstance(pom, BaseException) or pom is None:
                    logger.debug("could not resolve %s: %s", branch.coordinate, pom)
                    continue

                parent = PackageRef(
                    EcosystemId.MAVEN, branch.coordinate.key, branch.coordinate.version
                )
                for child, version, scope in self._children(pom, branch.scope):
                    if is_excluded(child.key, branch.exclusions) or child.key in seen:
                        continue
                    if self._nodes >= self._max_nodes:
                        break

                    seen[child.key] = version
                    self._nodes += 1
                    results.append(
                        Dependency(
                            ref=PackageRef(EcosystemId.MAVEN, child.key, version),
                            scope=scope,
                            direct=False,
                            source=branch.source,
                            pin=Pin.PINNED if version else Pin.UNRESOLVED,
                            parents=(parent,),
                        )
                    )
                    if version:
                        next_frontier.append(
                            _Branch(
                                coordinate=Coordinate(
                                    child.group, child.artifact, version
                                ),
                                scope=scope,
                                exclusions=branch.exclusions | child.exclusions,
                                source=branch.source,
                            )
                        )

            frontier = next_frontier

        if self._nodes >= self._max_nodes:
            self._warnings.append(
                f"Maven graph truncated at {self._max_nodes} packages across the "
                "scan; the dependency list is incomplete"
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
            if entry.optional:
                continue

            group = interpolate(entry.group, pom.properties) or entry.group
            artifact = interpolate(entry.artifact, pom.properties) or entry.artifact
            key = f"{group}:{artifact}"

            # A dependency that declares no scope takes the one dependencyManagement
            # gives it, which is how a BOM pins a whole family to ``test``. Reading
            # the declared scope only would treat every such entry as ``compile``.
            scope_name = entry.scope or pom.managed_scopes.get(key) or DEFAULT_SCOPE
            if scope_name.lower() in NON_TRANSITIVE_SCOPES:
                continue

            version = interpolate(entry.version, pom.properties)
            if not version or has_unresolved_property(version):
                version = pom.managed.get(key)
            if version and has_unresolved_property(version):
                version = None
            # A version range is a resolution problem we do not solve; treat it as
            # unknown rather than pretending the bracket text is a version.
            if version and version.startswith(("[", "(")):
                version = None

            scope = maven_scope(scope_name)
            # A dependency of a build-scoped dependency is itself build-scoped.
            if parent_scope is not Scope.RUNTIME:
                scope = parent_scope

            resolved = RawDependency(
                group=group,
                artifact=artifact,
                version=version,
                scope=entry.scope,
                # Maven merges the two lists rather than letting either replace the
                # other, which is how a parent centralises an exclusion for a
                # dependency that declares none of its own.
                exclusions=entry.exclusions
                | pom.managed_exclusions.get(key, frozenset()),
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
        managed_exclusions: dict[str, frozenset[str]] = {}

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
            await self._apply_management(
                entry, properties, managed, managed_scopes, managed_exclusions
            )

        return EffectivePom(
            coordinate=coordinate,
            properties=properties,
            managed=managed,
            managed_scopes=managed_scopes,
            managed_exclusions=managed_exclusions,
            dependencies=pom.dependencies,
        )

    async def _apply_management(
        self,
        pom: Pom,
        properties: dict[str, str],
        managed: dict[str, str],
        managed_scopes: dict[str, str],
        managed_exclusions: dict[str, frozenset[str]],
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
                    for key, bom_exclusions in bom.managed_exclusions.items():
                        managed_exclusions.setdefault(key, bom_exclusions)
                continue

            key = f"{group}:{artifact}"
            if version and not has_unresolved_property(version):
                managed[key] = version
            if entry.scope:
                managed_scopes[key] = entry.scope
            if entry.exclusions:
                managed_exclusions[key] = entry.exclusions

    async def _fetch_pom(self, coordinate: Coordinate) -> Pom | None:
        """Fetch and parse one POM, cached for a week.

        POMs at a released version are immutable, so a long TTL is safe — Central
        does not permit republishing a version.
        """
        if not coordinate.version or not coordinate.group or not coordinate.artifact:
            return None
        if not _is_fetchable(coordinate):
            logger.debug("refusing to fetch implausible coordinate %s", coordinate)
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
            except (httpx.HTTPError, httpx.InvalidURL) as exc:
                # InvalidURL is not an HTTPError. Left uncaught it escapes the whole
                # resolver — including the BOM path, which no gather() shields — and
                # ends a scan over one odd coordinate in one file.
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


def _is_fetchable(coordinate: Coordinate) -> bool:
    """True when a coordinate is safe to turn into a Maven Central path."""
    return all(
        _VALID_COMPONENT.match(component)
        for component in (
            coordinate.group,
            coordinate.artifact,
            coordinate.version or "",
        )
    )
