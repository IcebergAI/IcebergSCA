"""Turning declared constraints into the versions a fresh install would get."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, replace

from icebergsca.core.models import Dependency, EcosystemId, PackageRef, Pin
from icebergsca.registry import RegistryClient
from icebergsca.resolve.ranges import best_match

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ResolutionResult:
    dependencies: tuple[Dependency, ...]
    resolved: int = 0
    #: Constraints we could not evaluate, or packages the registry did not know.
    #: These stay unresolved and are queried against OSV without a version.
    unresolved: int = 0
    warnings: tuple[str, ...] = ()


class Resolver:
    """Resolves unpinned dependencies against their registries."""

    def __init__(self, registry: RegistryClient) -> None:
        self._registry = registry

    async def resolve(self, dependencies: tuple[Dependency, ...]) -> ResolutionResult:
        """Fill in versions for dependencies that a lockfile did not pin.

        Anything already pinned is left alone: a lockfile is a stronger statement
        than anything a registry can tell us today.
        """
        pending = [
            dep
            for dep in dependencies
            if dep.ref.version is None and dep.pin is not Pin.PINNED
        ]
        if not pending:
            return ResolutionResult(dependencies)

        # One lookup per unique package, however many manifests declare it.
        wanted = {(dep.ref.ecosystem, dep.ref.name) for dep in pending}
        listings = await self._fetch_all(wanted)

        by_ref: dict[tuple[EcosystemId, str, str | None], str] = {}
        # Counted per distinct constraint, not per declaration. The same package
        # pinned the same way in six manifests of a monorepo is one constraint we
        # could not resolve, and the warning built from this number says so.
        attempted: set[tuple[EcosystemId, str, str | None]] = set()
        resolved = 0
        unresolved = 0

        for dep in pending:
            key = (dep.ref.ecosystem, dep.ref.name, dep.constraint)
            if key in attempted:
                continue
            attempted.add(key)

            versions = listings.get((dep.ref.ecosystem, dep.ref.name))
            chosen = (
                best_match(dep.ref.ecosystem, versions, dep.constraint)
                if versions
                else None
            )
            if chosen is None:
                unresolved += 1
                continue
            by_ref[key] = chosen
            resolved += 1

        updated = tuple(
            self._apply(
                dep, by_ref.get((dep.ref.ecosystem, dep.ref.name, dep.constraint))
            )
            for dep in dependencies
        )
        return ResolutionResult(
            dependencies=updated,
            resolved=resolved,
            unresolved=unresolved,
            warnings=tuple(dict.fromkeys(self._registry.warnings)),
        )

    async def _fetch_all(
        self, wanted: set[tuple[EcosystemId, str]]
    ) -> dict[tuple[EcosystemId, str], list[str] | None]:
        ordered = sorted(wanted, key=lambda pair: (pair[0].value, pair[1]))
        results = await asyncio.gather(
            *(self._registry.versions(ecosystem, name) for ecosystem, name in ordered),
            return_exceptions=True,
        )
        listings: dict[tuple[EcosystemId, str], list[str] | None] = {}
        for key, result in zip(ordered, results, strict=True):
            if isinstance(result, BaseException):
                logger.debug("registry lookup failed for %s: %s", key, result)
                listings[key] = None
            else:
                listings[key] = result
        return listings

    @staticmethod
    def _apply(dep: Dependency, version: str | None) -> Dependency:
        """Attach a resolved version, marking it RESOLVED rather than PINNED.

        The distinction is the whole point of being lockfile-first, so it survives
        all the way into the rendered output.
        """
        if version is None or dep.ref.version is not None or dep.pin is Pin.PINNED:
            return dep
        return replace(
            dep,
            ref=PackageRef(dep.ref.ecosystem, dep.ref.name, version),
            pin=Pin.RESOLVED,
        )
