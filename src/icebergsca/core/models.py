"""Core data model.

Every type here is a frozen dataclass with no I/O and no framework imports, so the
same objects flow from the parsers straight through to the renderers unchanged.

Two conventions worth stating up front:

* ``None`` and ``""`` mean different things. ``None`` is "upstream does not expose
  this"; ``""`` is "upstream says there is none". Collapsing the two produces
  confident-looking output backed by nothing.
* A package's identity is the :class:`PackageRef` itself, which is hashable and used
  directly as a dict key for deduplication. The Package URL is derived from it on
  demand for output, never stored, so the two cannot drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from packageurl import PackageURL

SCHEMA_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Ecosystems
# ---------------------------------------------------------------------------


class EcosystemId(StrEnum):
    """The ecosystems we scan.

    The member value is the user-facing key accepted by ``--ecosystem``. The OSV
    ecosystem string and the Package URL type are both derived from it, since the
    three vocabularies disagree (``go`` vs ``Go`` vs ``golang``) and hard-coding
    that mapping in three places is how they end up out of sync.
    """

    PYPI = "pypi"
    NPM = "npm"
    MAVEN = "maven"
    GO = "go"
    CARGO = "cargo"
    NUGET = "nuget"
    RUBYGEMS = "rubygems"

    @property
    def osv_name(self) -> str:
        """The ecosystem string OSV expects in a query."""
        return _OSV_ECOSYSTEM[self]

    @property
    def purl_type(self) -> str:
        """The Package URL type for this ecosystem."""
        return _PURL_TYPE[self]

    @property
    def label(self) -> str:
        """Human-readable name for report output."""
        return _LABEL[self]


_OSV_ECOSYSTEM: dict[EcosystemId, str] = {
    EcosystemId.PYPI: "PyPI",
    EcosystemId.NPM: "npm",
    EcosystemId.MAVEN: "Maven",
    EcosystemId.GO: "Go",
    EcosystemId.CARGO: "crates.io",
    EcosystemId.NUGET: "NuGet",
    EcosystemId.RUBYGEMS: "RubyGems",
}

_PURL_TYPE: dict[EcosystemId, str] = {
    EcosystemId.PYPI: "pypi",
    EcosystemId.NPM: "npm",
    EcosystemId.MAVEN: "maven",
    EcosystemId.GO: "golang",
    EcosystemId.CARGO: "cargo",
    EcosystemId.NUGET: "nuget",
    EcosystemId.RUBYGEMS: "gem",
}

_LABEL: dict[EcosystemId, str] = {
    EcosystemId.PYPI: "Python",
    EcosystemId.NPM: "npm",
    EcosystemId.MAVEN: "Maven",
    EcosystemId.GO: "Go",
    EcosystemId.CARGO: "Rust",
    EcosystemId.NUGET: ".NET",
    EcosystemId.RUBYGEMS: "Ruby",
}


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Scope(StrEnum):
    """Where in the build a dependency is used.

    Captured at parse time so that filtering is a free operation later. Anything a
    manifest does not distinguish defaults to :attr:`RUNTIME` — over-reporting is
    the safe direction.
    """

    RUNTIME = "runtime"
    DEV = "dev"
    TEST = "test"
    BUILD = "build"
    OPTIONAL = "optional"


#: Scopes excluded unless ``--include-dev`` is passed. Build-time dependencies stay
#: in by default: a compromised build tool reaches the artefact just as surely as a
#: compromised runtime library does.
NON_RUNTIME_SCOPES: frozenset[Scope] = frozenset({Scope.DEV, Scope.TEST})


class Pin(StrEnum):
    """How confident we are in a dependency's version.

    This distinction is the whole point of being lockfile-first, so it is carried
    all the way through to the rendered output rather than being flattened away.
    """

    #: Read from a lockfile — this is what is actually installed.
    PINNED = "pinned"
    #: A range resolved against the registry — what a fresh install would get today.
    RESOLVED = "resolved"
    #: A constraint we could not evaluate. Queried against OSV without a version,
    #: so findings may not apply to the installed version.
    UNRESOLVED = "unresolved"


class SeverityLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"
    #: The advisory carries no severity data at all — distinct from a scored zero.
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        """Sort key, highest severity first when sorting descending."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[SeverityLevel, int] = {
    SeverityLevel.CRITICAL: 5,
    SeverityLevel.HIGH: 4,
    SeverityLevel.MEDIUM: 3,
    SeverityLevel.LOW: 2,
    SeverityLevel.UNKNOWN: 1,
    SeverityLevel.NONE: 0,
}


class ScanStatus(StrEnum):
    """Outcome of the scan as a whole — never a statement about findings.

    A scan that finds forty critical vulnerabilities is :attr:`OK`. A scan that
    could not reach OSV is not.
    """

    OK = "ok"
    #: Some packages could not be checked. Results are incomplete and say so.
    PARTIAL = "partial"
    #: Nothing usable was produced.
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Package identity
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PackageRef:
    """A specific package at a specific version.

    ``version`` is ``None`` only when the constraint could not be resolved; such a
    reference is still queryable against OSV, just without version filtering.
    """

    ecosystem: EcosystemId
    name: str
    version: str | None = None

    @property
    def purl(self) -> str:
        """Package URL — canonical identity for SBOM output and cross-tool dedup."""
        namespace, name = _purl_namespace(self.ecosystem, self.name)
        return PackageURL(
            type=self.ecosystem.purl_type,
            namespace=namespace,
            name=name,
            version=self.version,
        ).to_string()

    @property
    def coordinate(self) -> str:
        """Compact ``name@version`` form for terminal output."""
        return f"{self.name}@{self.version}" if self.version else self.name


def _purl_namespace(ecosystem: EcosystemId, name: str) -> tuple[str | None, str]:
    """Split a package name into the (namespace, name) pair the purl spec expects.

    Each ecosystem hides its hierarchy in the name differently: Maven joins group and
    artifact with a colon, npm prefixes a scope with ``@``, and Go uses the last path
    segment as the name. Everything else is flat.
    """
    if ecosystem is EcosystemId.MAVEN:
        group, _, artifact = name.partition(":")
        return (group, artifact) if artifact else (None, name)

    if ecosystem is EcosystemId.NPM and name.startswith("@"):
        scope, _, package = name.partition("/")
        return (scope, package) if package else (None, name)

    if ecosystem is EcosystemId.GO:
        prefix, _, module = name.rpartition("/")
        return (prefix or None, module or name)

    if ecosystem is EcosystemId.PYPI:
        # PEP 503 normalisation — the purl spec requires it, and it also makes
        # "Flask" and "flask" dedup correctly across manifests.
        return None, name.lower().replace("_", "-").replace(".", "-")

    return None, name


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """Where a dependency was declared.

    ``line`` is populated for line-oriented formats and left ``None`` for JSON and
    XML, where pointing at a line number would be guesswork. SARIF output degrades
    to a file-level result when it is absent.
    """

    path: Path
    line: int | None = None

    def __str__(self) -> str:
        return f"{self.path}:{self.line}" if self.line else str(self.path)


@dataclass(frozen=True, slots=True)
class Dependency:
    """A single declared or resolved dependency, with full provenance."""

    ref: PackageRef
    scope: Scope
    direct: bool
    source: SourceLocation
    pin: Pin
    #: The raw constraint text as written, kept verbatim so the resolver has
    #: something to work with and the report can explain itself.
    constraint: str | None = None
    #: Packages that pull this one in. Only populated for lockfiles that record
    #: edges; empty is "we don't know", never "nothing depends on it".
    parents: tuple[PackageRef, ...] = ()
    #: ``group:artifact`` keys this dependency must not drag in — Maven
    #: ``<exclusions>`` today, Gradle ``exclude`` and npm ``overrides`` later.
    #: Empty means "nothing was excluded", and deliberately not ``None`` for "we
    #: could not tell": a parser that cannot read exclusions leaves this empty and
    #: the graph over-reports, which is the safe way round.
    exclusions: frozenset[str] = frozenset()

    @property
    def is_runtime(self) -> bool:
        return self.scope not in NON_RUNTIME_SCOPES


# ---------------------------------------------------------------------------
# Advisories and findings
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Severity:
    level: SeverityLevel
    #: CVSS base score, when the advisory carries a parseable vector.
    score: float | None = None
    #: The CVSS vector string itself, preserved so users can check our arithmetic.
    vector: str | None = None


@dataclass(frozen=True, slots=True)
class Advisory:
    """An OSV advisory, hydrated from ``/v1/vulns/{id}``.

    ``modified`` comes back from ``querybatch`` alongside the ID, which is what lets
    the detail cache be keyed exactly rather than guessed at with a TTL.
    """

    id: str
    modified: str
    aliases: tuple[str, ...] = ()
    summary: str = ""
    details: str = ""
    severity: Severity | None = None
    published: str | None = None
    references: tuple[str, ...] = ()

    @property
    def is_malicious(self) -> bool:
        """True for OSV malicious-package advisories rather than ordinary CVEs."""
        return self.id.startswith("MAL-")

    @property
    def level(self) -> SeverityLevel:
        if self.severity is not None:
            return self.severity.level
        # A package published specifically to attack its consumers is critical
        # whether or not anyone got round to scoring it.
        return SeverityLevel.CRITICAL if self.is_malicious else SeverityLevel.UNKNOWN

    @property
    def cve_ids(self) -> tuple[str, ...]:
        return tuple(a for a in self.aliases if a.startswith("CVE-"))


@dataclass(frozen=True, slots=True)
class Finding:
    """One advisory affecting one package, with every path that introduced it."""

    package: PackageRef
    advisory: Advisory
    #: Lowest fixed version above the installed one, or ``None`` if no fix is known.
    fixed_version: str | None = None
    introduced_by: tuple[Dependency, ...] = ()

    @property
    def level(self) -> SeverityLevel:
        return self.advisory.level

    @property
    def is_direct(self) -> bool:
        return any(dep.direct for dep in self.introduced_by)

    @property
    def sources(self) -> tuple[SourceLocation, ...]:
        """Every manifest that pulls this package in, deduplicated, order preserved."""
        seen: dict[SourceLocation, None] = {}
        for dep in self.introduced_by:
            seen.setdefault(dep.source, None)
        return tuple(seen)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SkippedFile:
    """A file we recognised but did not scan, and why.

    Skips are always reported. A scanner that quietly drops a manifest is
    indistinguishable from one that found nothing wrong with it.
    """

    path: Path
    reason: str


@dataclass(frozen=True, slots=True)
class ManifestResult:
    """Per-scan-unit outcome: one ecosystem rooted at one directory."""

    ecosystem: EcosystemId
    directory: Path
    manifests: tuple[Path, ...] = ()
    lockfiles: tuple[Path, ...] = ()
    #: The files actually read, which is not always the files found — a lockfile we
    #: cannot parse falls back to the manifest. Reporting the discovered file rather
    #: than the used one would credit the output with a precision it does not have.
    parsed: tuple[Path, ...] = ()
    #: Dependencies contributed *after* scope filtering, so these sum to the report
    #: total rather than to some larger pre-filter number.
    dependency_count: int = 0
    #: True when the graph came from a lockfile, so versions are exact.
    from_lockfile: bool = False
    #: True when the graph was reconstructed rather than read — currently Maven,
    #: whose resolution we approximate rather than reproduce exactly.
    approximate: bool = False
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ScanReport:
    """The complete result of a scan. Every renderer consumes exactly this."""

    root: Path
    started_at: datetime
    finished_at: datetime
    status: ScanStatus = ScanStatus.OK
    manifests: tuple[ManifestResult, ...] = ()
    dependencies: tuple[Dependency, ...] = ()
    findings: tuple[Finding, ...] = ()
    skipped: tuple[SkippedFile, ...] = ()
    #: Packages that could not be checked against OSV. Non-empty means the report
    #: is incomplete, and the exit code says so.
    scan_failed: tuple[PackageRef, ...] = ()
    #: Whether the vulnerability lookup stage actually ran. Renderers must not say
    #: "no vulnerabilities found" when this is False — an empty finding list because
    #: nothing was checked is not the same as a clean result, and conflating the two
    #: is the single most dangerous thing this tool could do.
    vulnerabilities_checked: bool = False
    warnings: tuple[str, ...] = ()
    schema_version: str = SCHEMA_VERSION
    tool_version: str = field(default="")

    @property
    def packages(self) -> tuple[PackageRef, ...]:
        """Unique packages across all manifests, in first-seen order."""
        seen: dict[PackageRef, None] = {}
        for dep in self.dependencies:
            seen.setdefault(dep.ref, None)
        return tuple(seen)

    @property
    def direct_count(self) -> int:
        return sum(1 for dep in self.dependencies if dep.direct)

    @property
    def transitive_count(self) -> int:
        return len(self.dependencies) - self.direct_count

    @property
    def is_complete(self) -> bool:
        """False when any package went unchecked — findings may be missing."""
        return (
            self.vulnerabilities_checked
            and not self.scan_failed
            and self.status is ScanStatus.OK
        )

    def counts_by_severity(self) -> dict[SeverityLevel, int]:
        """Finding counts per severity, highest first, omitting empty levels."""
        counts: dict[SeverityLevel, int] = {}
        for finding in self.findings:
            counts[finding.level] = counts.get(finding.level, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: item[0].rank, reverse=True))

    def sorted_findings(self) -> tuple[Finding, ...]:
        """Findings ordered most severe first, then by package for stable output."""
        return tuple(
            sorted(
                self.findings,
                key=lambda f: (-f.level.rank, f.package.name, f.advisory.id),
            )
        )
