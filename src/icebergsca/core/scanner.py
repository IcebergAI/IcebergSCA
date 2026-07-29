"""Scan orchestration.

Runs the five stages — discover, parse, resolve, scan, report — and assembles a
:class:`~icebergsca.core.models.ScanReport`. This is the library entry point; the
CLI is a presentation layer over :func:`scan` and nothing here prints or exits.

Resolution covers two things a lockfile would otherwise have told us: Maven's
transitive graph, reconstructed from Central, and version ranges in manifests with no
lockfile at all. Both are optional, both are recorded when they fail, and neither can
turn a failure into a silently clean report.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path, PurePath

import httpx

from icebergsca import __version__
from icebergsca.cache import Cache
from icebergsca.core import triage
from icebergsca.core.discovery import Discovery, DiscoveryOptions, ScanUnit, discover
from icebergsca.core.errors import CacheError, ParseError
from icebergsca.core.graph import most_included
from icebergsca.core.models import (
    NON_RUNTIME_SCOPES,
    Dependency,
    EcosystemId,
    Finding,
    ManifestResult,
    PackageRef,
    ScanReport,
    ScanStatus,
    Scope,
    SkippedFile,
)
from icebergsca.core.triage import IgnoreRule
from icebergsca.ecosystems import get as get_ecosystem
from icebergsca.ecosystems.base import FileParser
from icebergsca.ecosystems.maven import MavenResolver, MavenResult, MavenUnit
from icebergsca.osv.client import USER_AGENT, OSVClient, OSVResult
from icebergsca.registry import RegistryClient
from icebergsca.resolve import Resolver

logger = logging.getLogger(__name__)

#: Scopes included when the caller does not say otherwise. Dev and test are out by
#: default; build stays in, because a compromised build tool reaches the artefact
#: just as surely as a compromised runtime library.
DEFAULT_SCOPES: frozenset[Scope] = frozenset(Scope) - NON_RUNTIME_SCOPES


@dataclass(frozen=True, slots=True)
class ScanOptions:
    discovery: DiscoveryOptions = field(default_factory=DiscoveryOptions)
    scopes: frozenset[Scope] = DEFAULT_SCOPES
    #: Serve from cache only; never reach the network. Packages with no cached
    #: result are reported as unchecked rather than assumed clean.
    offline: bool = False
    #: Maximum concurrent upstream requests.
    concurrency: int = 10
    #: Bypass the on-disk cache entirely, using a throwaway in-memory one.
    no_cache: bool = False
    #: Override the cache location. ``None`` uses the per-user cache directory.
    cache_path: Path | None = None
    #: Resolve unpinned constraints against their registries. Costs one request per
    #: package but turns "flask >=2.0" into the version a fresh install would get.
    resolve_ranges: bool = True
    #: Reconstruct Maven's transitive graph from Central. Without it, Java projects
    #: report direct dependencies only.
    resolve_maven: bool = True
    #: Run the OSV lookup. Turning it off produces a dependency inventory with no
    #: findings — and the report says so via ``vulnerabilities_checked`` rather than
    #: presenting an empty finding list as a clean result.
    check_vulnerabilities: bool = True
    #: Accepted findings, already parsed. A plain value like every other option: the
    #: CLI locates and reads ``.icebergsca.toml``, because tool configuration is its
    #: business, not the scanner's.
    ignore_rules: tuple[IgnoreRule, ...] = ()


async def scan(root: Path, options: ScanOptions | None = None) -> ScanReport:
    """Scan a project tree and return a complete report.

    Never raises for findings, and never raises for a single unparseable file — both
    are recorded in the report. Only a failure to walk the target at all propagates.
    """
    options = options or ScanOptions()
    started_at = datetime.now(UTC)

    discovery = discover(root, options.discovery)
    kept, results, skipped, warnings = _parse_all(discovery, options.scopes)

    outcome = await _resolve_and_check(kept, discovery.units, options, discovery.root)

    return ScanReport(
        root=discovery.root,
        started_at=started_at,
        finished_at=datetime.now(UTC),
        status=_status(results, outcome.result.failed),
        manifests=_finalise_manifests(
            results, outcome.dependencies, outcome.maven_approximate
        ),
        dependencies=outcome.dependencies,
        findings=outcome.findings,
        skipped=tuple(discovery.skipped) + skipped,
        scan_failed=outcome.result.failed,
        vulnerabilities_checked=outcome.checked,
        warnings=warnings + outcome.warnings + outcome.result.warnings,
        tool_version=__version__,
    )


def build_http_client(options: ScanOptions) -> httpx.AsyncClient:
    """Construct the HTTP client used for every upstream call.

    A single named seam rather than an inline constructor: tests replace this with a
    mock transport so that nothing in the suite can reach the network by accident,
    and a caller embedding the library can supply its own connection policy.
    """
    return httpx.AsyncClient(
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
        timeout=httpx.Timeout(30.0, connect=10.0),
        limits=httpx.Limits(max_connections=max(4, options.concurrency * 2)),
    )


@dataclass(frozen=True, slots=True)
class _VulnOutcome:
    dependencies: tuple[Dependency, ...]
    findings: tuple[Finding, ...]
    result: OSVResult
    #: False when the lookup stage did not run at all, which renderers must
    #: distinguish from "ran and found nothing".
    checked: bool
    warnings: tuple[str, ...] = ()
    #: True when a Maven graph was reconstructed rather than read from a lockfile.
    maven_approximate: bool = False


async def _resolve_and_check(
    dependencies: tuple[Dependency, ...],
    units: tuple[ScanUnit, ...],
    options: ScanOptions,
    root: Path,
) -> _VulnOutcome:
    """Stages 3 and 4: resolve unpinned constraints, then look everything up in OSV.

    Both share one HTTP client and one cache, so a scan opens a single connection
    pool regardless of how many registries and how many packages are involved.

    A package appearing in three manifests is queried once and reported once, with
    all three introduction sites attached — which is what makes a monorepo scan
    readable rather than triplicated.
    """
    if not dependencies:
        # Nothing to check is not the same as nothing found, but with no packages at
        # all the distinction cannot mislead anyone: report it as checked.
        return _VulnOutcome((), (), OSVResult(), checked=True)

    try:
        cache = Cache.memory() if options.no_cache else Cache.open(options.cache_path)
    except CacheError as exc:
        # An unusable cache is a performance problem, not a correctness one, so the
        # scan continues in memory rather than reporting nothing.
        logger.warning("cache unavailable, continuing without it: %s", exc)
        cache = Cache.memory()

    warnings: tuple[str, ...] = ()
    maven = MavenResult(())

    try:
        async with build_http_client(options) as http:
            if options.resolve_maven:
                maven = await MavenResolver(
                    http,
                    cache,
                    offline=options.offline,
                    concurrency=options.concurrency,
                ).expand_units(
                    dependencies, _maven_units(dependencies, units), root=root
                )
                dependencies = tuple(
                    dep for dep in maven.dependencies if dep.scope in options.scopes
                )
                warnings += maven.warnings

            if options.resolve_ranges:
                resolution = await Resolver(
                    RegistryClient(
                        http,
                        cache,
                        offline=options.offline,
                        concurrency=options.concurrency,
                    )
                ).resolve(dependencies)
                dependencies = resolution.dependencies
                warnings += resolution.warnings
                if resolution.unresolved:
                    warnings += (
                        f"{resolution.unresolved} constraint(s) could not be resolved "
                        "to a version; those packages were checked against every "
                        "advisory for the package, so findings may not apply to the "
                        "version you install",
                    )

            introducers: dict[PackageRef, list[Dependency]] = defaultdict(list)
            for dep in dependencies:
                introducers[dep.ref].append(dep)

            if not options.check_vulnerabilities:
                return _VulnOutcome(
                    dependencies, (), OSVResult(), checked=False, warnings=warnings
                )

            client = OSVClient(
                http,
                cache,
                offline=options.offline,
                concurrency=options.concurrency,
            )
            result = await client.scan(list(introducers))
    finally:
        cache.close()

    findings = tuple(
        Finding(
            package=ref,
            advisory=hit.advisory,
            fixed_version=hit.fixed_version,
            introduced_by=tuple(introducers[ref]),
        )
        for ref, hits in result.advisories.items()
        for hit in hits
    )
    # Applied here, at the one place findings are built, so the accepted ones are the
    # same objects the report ships. Note this is below the ``check_vulnerabilities``
    # early return above: there is nothing to accept when nothing was looked up, and
    # marking an empty list as triaged would be a clean result nobody earned.
    findings, ignore_warnings = triage.apply(findings, options.ignore_rules)

    return _VulnOutcome(
        dependencies,
        findings,
        result,
        checked=True,
        warnings=warnings + ignore_warnings,
        maven_approximate=maven.approximate,
    )


def _maven_units(
    dependencies: tuple[Dependency, ...], units: tuple[ScanUnit, ...]
) -> tuple[MavenUnit, ...]:
    """Regroup the flat dependency list back onto the scan units it came from.

    Discovery assigns every file to exactly one (ecosystem, directory) unit, and the
    parsers stamp each dependency with the file it was declared in, so ``source.path``
    identifies a dependency's unit exactly. Regrouping here rather than threading units
    through the parse stage keeps ``_parse_all`` unchanged and — because it happens
    after ``_dedupe`` — guarantees the resolver sees the same list the report will.

    A Maven dependency whose path belongs to no unit still gets a unit of its own.
    Silently dropping it would remove packages from the report, which is the one thing
    this stage must never do.
    """
    owner = {
        path: PurePath(unit.directory)
        for unit in units
        if unit.ecosystem is EcosystemId.MAVEN
        for path in unit.files
    }

    grouped: dict[PurePath, list[Dependency]] = defaultdict(list)
    for dep in dependencies:
        if dep.ref.ecosystem is not EcosystemId.MAVEN:
            continue
        path = PurePath(dep.source.path)
        grouped[owner.get(path, path.parent)].append(dep)

    return tuple(
        MavenUnit(directory=directory, dependencies=tuple(deps))
        for directory, deps in grouped.items()
    )


def _finalise_manifests(
    results: tuple[ManifestResult, ...],
    dependencies: tuple[Dependency, ...],
    approximate: bool,
) -> tuple[ManifestResult, ...]:
    """Restate per-manifest counts against the finished dependency list.

    Parsing counts what a file declared; resolution then adds Maven's transitive
    closure. Leaving the parse-time number in place would print a manifest total that
    does not sum to the report total — the same inconsistency, one stage later.

    Maven results are also flagged approximate here: we will never be bit-identical
    to Maven's own resolution, and the report should say so rather than presenting a
    reconstructed graph with the confidence a lockfile would earn.
    """
    counts: dict[Path, int] = defaultdict(int)
    for dep in dependencies:
        counts[dep.source.path] += 1

    return tuple(
        replace(
            result,
            dependency_count=sum(counts.get(path, 0) for path in result.parsed),
            approximate=approximate and result.ecosystem is EcosystemId.MAVEN,
        )
        for result in results
    )


def _status(
    results: tuple[ManifestResult, ...], scan_failed: tuple[PackageRef, ...]
) -> ScanStatus:
    """Derive the overall status.

    Findings never enter into this. A scan is only degraded when we failed to look
    at something we were asked to look at.
    """
    if scan_failed:
        return ScanStatus.PARTIAL
    if results and all(result.error for result in results):
        return ScanStatus.FAILED
    if any(result.error for result in results):
        return ScanStatus.PARTIAL
    return ScanStatus.OK


def _parse_all(
    discovery: Discovery, scopes: frozenset[Scope]
) -> tuple[
    tuple[Dependency, ...],
    tuple[ManifestResult, ...],
    tuple[SkippedFile, ...],
    tuple[str, ...],
]:
    """Parse every scan unit, collecting dependencies, per-unit results and problems.

    Scope filtering happens here rather than after the fact so that each unit's
    reported count and the report total are the same number.
    """
    dependencies: list[Dependency] = []
    results: list[ManifestResult] = []
    skipped: list[SkippedFile] = []
    warnings: list[str] = []

    for unit in discovery.units:
        parsed, result, unit_skipped, unit_warnings = _parse_unit(
            discovery.root, unit, scopes
        )
        dependencies.extend(parsed)
        results.append(result)
        skipped.extend(unit_skipped)
        warnings.extend(unit_warnings)

    return _dedupe(dependencies), tuple(results), tuple(skipped), tuple(warnings)


def _parse_unit(
    root: Path, unit: ScanUnit, scopes: frozenset[Scope]
) -> tuple[list[Dependency], ManifestResult, list[SkippedFile], list[str]]:
    """Parse one scan unit, preferring its lockfile.

    When a lockfile is present but cannot be parsed we fall back to the manifest and
    say so in a warning. Falling back silently would present range-derived versions
    with the confidence of pinned ones.
    """
    spec = get_ecosystem(unit.ecosystem)
    skipped: list[SkippedFile] = []
    warnings: list[str] = []

    if unit.lockfiles:
        outcome = _parse_files(root, unit.lockfiles, spec.parse_lockfile)
        skipped.extend(outcome.failures)
        if outcome.used:
            # The manifest is parsed too, but only for what it alone knows: which
            # packages the project actually asked for, and under what scope. Several
            # lockfile formats (poetry.lock, Pipfile.lock, Cargo.lock) record neither.
            hints = _parse_files(root, unit.manifests, spec.parse_manifest)
            merged = _apply_manifest_hints(outcome.dependencies, hints.dependencies)
            kept = [dep for dep in merged if dep.scope in scopes]
            return (
                kept,
                _result(unit, kept, outcome.used, from_lockfile=True),
                skipped,
                warnings,
            )

        if unit.manifests:
            warnings.append(
                f"{unit.directory}: could not read {_names(unit.lockfiles)}; "
                f"falling back to {_names(unit.manifests)} — versions are declared, "
                "not installed"
            )

    if not unit.manifests:
        reason = _names(unit.lockfiles) or "no readable file"
        return (
            [],
            _result(unit, [], (), error=f"could not parse {reason}"),
            skipped,
            warnings,
        )

    outcome = _parse_files(root, unit.manifests, spec.parse_manifest)
    skipped.extend(outcome.failures)
    kept = [dep for dep in outcome.dependencies if dep.scope in scopes]
    error = None if outcome.used else f"could not parse {_names(unit.manifests)}"
    return kept, _result(unit, kept, outcome.used, error=error), skipped, warnings


def _apply_manifest_hints(
    locked: list[Dependency], declared: list[Dependency]
) -> list[Dependency]:
    """Mark locked packages the manifest declared as direct, at the declared scope.

    The lockfile is authoritative about *versions*; the manifest is authoritative
    about *intent*. Merging the two is what lets a poetry.lock — which records a
    package's group but never whether the project asked for it — still report
    directness, and it is what makes "why is this here" answerable.

    A manifest scope only ever widens inclusion (dev → runtime, never the reverse),
    so a package that ships cannot be reclassified out of the default scan by a
    stray dev-group declaration elsewhere.
    """
    if not declared:
        return locked

    intent: dict[str, Scope] = {}
    for dep in declared:
        if not dep.direct:
            continue
        current = intent.get(dep.ref.name)
        intent[dep.ref.name] = most_included(
            [dep.scope] if current is None else [dep.scope, current]
        )

    return [
        replace(
            dep, direct=True, scope=most_included([dep.scope, intent[dep.ref.name]])
        )
        if dep.ref.name in intent
        else dep
        for dep in locked
    ]


@dataclass(frozen=True, slots=True)
class _ParseOutcome:
    """What came out of parsing a group of files, and which of them actually worked."""

    dependencies: list[Dependency]
    #: Files parsed without error. Distinct from the files we were handed, so the
    #: report can name what it actually read rather than what it hoped to read.
    used: tuple[PurePath, ...]
    failures: list[SkippedFile]


def _parse_files(
    root: Path,
    paths: tuple[PurePath, ...],
    parse: FileParser,
) -> _ParseOutcome:
    """Run one parser over several files, isolating each failure to its own file."""
    dependencies: list[Dependency] = []
    failures: list[SkippedFile] = []
    used: list[PurePath] = []

    for relative in paths:
        try:
            content = (root / relative).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            failures.append(
                SkippedFile(Path(relative), f"unreadable: {exc.strerror or exc}")
            )
            continue

        try:
            dependencies.extend(parse(Path(relative), content))
        except ParseError as exc:
            failures.append(SkippedFile(Path(relative), exc.reason))
        except Exception as exc:  # pragma: no cover — defensive
            logger.exception("unexpected failure parsing %s", relative)
            failures.append(SkippedFile(Path(relative), f"parser error: {exc}"))
        else:
            used.append(relative)

    return _ParseOutcome(dependencies, tuple(used), failures)


def _result(
    unit: ScanUnit,
    kept: list[Dependency],
    used: tuple[PurePath, ...],
    *,
    from_lockfile: bool = False,
    error: str | None = None,
) -> ManifestResult:
    return ManifestResult(
        ecosystem=unit.ecosystem,
        directory=Path(unit.directory),
        manifests=tuple(Path(p) for p in unit.manifests),
        lockfiles=tuple(Path(p) for p in unit.lockfiles),
        parsed=tuple(Path(p) for p in used),
        dependency_count=len(kept),
        from_lockfile=from_lockfile,
        error=error,
    )


def _names(paths: tuple[PurePath, ...]) -> str:
    return ", ".join(path.name for path in paths)


def _dedupe(dependencies: list[Dependency]) -> tuple[Dependency, ...]:
    """Drop exact duplicates, preserving first-seen order.

    Deduplication is deliberately exact: the same package declared in two manifests
    stays twice, because the report needs to name every file a finding came from.
    """
    return tuple(dict.fromkeys(dependencies))
