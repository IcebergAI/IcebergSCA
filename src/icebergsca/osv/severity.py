"""Reading severity and fix information out of an OSV advisory.

``querybatch`` returns only an ID and a modified timestamp, so everything here works
on the full record fetched from ``/v1/vulns/{id}``.
"""

from __future__ import annotations

import logging
from typing import Any

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

from icebergsca.core.models import EcosystemId, PackageRef, Severity, SeverityLevel
from icebergsca.core.versions import is_newer
from icebergsca.core.versions import parse as parse_version

logger = logging.getLogger(__name__)

#: Preferred first. A v4 vector says more than a v3 one, and both beat a
#: database-specific label.
_CVSS_PARSERS: tuple[tuple[str, type[CVSS2] | type[CVSS3] | type[CVSS4]], ...] = (
    ("CVSS_V4", CVSS4),
    ("CVSS_V3", CVSS3),
    ("CVSS_V2", CVSS2),
)

#: Standard CVSS v3 qualitative bands, lowest bound first.
_BANDS: tuple[tuple[float, SeverityLevel], ...] = (
    (9.0, SeverityLevel.CRITICAL),
    (7.0, SeverityLevel.HIGH),
    (4.0, SeverityLevel.MEDIUM),
    (0.1, SeverityLevel.LOW),
)

#: GitHub Advisory labels, which OSV passes through in ``database_specific``.
_LABELS: dict[str, SeverityLevel] = {
    "CRITICAL": SeverityLevel.CRITICAL,
    "HIGH": SeverityLevel.HIGH,
    "MODERATE": SeverityLevel.MEDIUM,
    "MEDIUM": SeverityLevel.MEDIUM,
    "LOW": SeverityLevel.LOW,
}

#: Range types whose events are commit hashes rather than versions. There is no
#: "upgrade to this" to offer from a git range.
_UNORDERABLE_RANGES = frozenset({"GIT"})


def level_for_score(score: float) -> SeverityLevel:
    for lower_bound, level in _BANDS:
        if score >= lower_bound:
            return level
    return SeverityLevel.NONE


def extract(vuln: dict[str, Any]) -> Severity | None:
    """Best available severity for an advisory, or ``None`` if it carries none.

    ``None`` is a real answer here and is rendered as "unknown" rather than being
    quietly turned into a zero score, which would sort a genuinely unassessed
    advisory below a confirmed-harmless one.
    """
    scored = _from_vectors(_severity_entries(vuln))
    if scored is not None:
        return scored

    for label in _labels(vuln):
        level = _LABELS.get(label.upper())
        if level is not None:
            return Severity(level=level)

    return None


def _severity_entries(vuln: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect severity blocks from the advisory and from each affected package."""
    entries = list(vuln.get("severity") or [])
    for affected in vuln.get("affected") or []:
        if isinstance(affected, dict):
            entries.extend(affected.get("severity") or [])
    return [entry for entry in entries if isinstance(entry, dict)]


def _from_vectors(entries: list[dict[str, Any]]) -> Severity | None:
    for wanted, parser in _CVSS_PARSERS:
        for entry in entries:
            if entry.get("type") != wanted:
                continue
            vector = entry.get("score")
            if not isinstance(vector, str):
                continue
            try:
                score = float(parser(vector).base_score)
            except (CVSSError, ValueError) as exc:
                logger.debug("unparseable %s vector %r: %s", wanted, vector, exc)
                continue
            return Severity(level=level_for_score(score), score=score, vector=vector)
    return None


def _labels(vuln: dict[str, Any]) -> list[str]:
    labels: list[str] = []
    specific = vuln.get("database_specific")
    if isinstance(specific, dict) and isinstance(specific.get("severity"), str):
        labels.append(specific["severity"])
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        for key in ("database_specific", "ecosystem_specific"):
            block = affected.get(key)
            if isinstance(block, dict) and isinstance(block.get("severity"), str):
                labels.append(block["severity"])
    return labels


def fixed_version(vuln: dict[str, Any], ref: PackageRef) -> str | None:
    """The lowest released fix above the installed version, if one is known.

    Only ``fixed`` events count: a ``last_affected`` event tells you where the
    problem stops, not where to upgrade to. Returns ``None`` when the advisory lists
    no fix, when the installed version is unknown, or when the versions cannot be
    ordered — in every one of those cases we genuinely do not know what to recommend.
    """
    candidates = _fix_candidates(vuln, ref)
    if not candidates:
        return None

    if ref.version is None:
        return min(candidates, key=lambda v: _sort_key(ref.ecosystem, v))

    ahead = [v for v in candidates if is_newer(ref.ecosystem, v, ref.version)]
    if not ahead:
        return None
    return min(ahead, key=lambda v: _sort_key(ref.ecosystem, v))


def _fix_candidates(vuln: dict[str, Any], ref: PackageRef) -> list[str]:
    candidates: list[str] = []
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict) or not _matches(affected, ref):
            continue
        for entry in affected.get("ranges") or []:
            if not isinstance(entry, dict) or entry.get("type") in _UNORDERABLE_RANGES:
                continue
            for event in entry.get("events") or []:
                fixed = event.get("fixed") if isinstance(event, dict) else None
                if isinstance(fixed, str) and fixed:
                    candidates.append(fixed)
    return candidates


def _matches(affected: dict[str, Any], ref: PackageRef) -> bool:
    """True when an ``affected`` block describes the package we asked about.

    An advisory can cover several packages — a monorepo's worth of Go modules, say —
    and taking the first block's fix would recommend upgrading the wrong one.
    """
    package = affected.get("package")
    if not isinstance(package, dict):
        return False
    if package.get("ecosystem") not in (ref.ecosystem.osv_name, None):
        # OSV suffixes some ecosystems ("Alpine:v3.19"); match on the base name.
        ecosystem = str(package.get("ecosystem", ""))
        if ecosystem.split(":", 1)[0] != ref.ecosystem.osv_name:
            return False
    return _same_name(str(package.get("name", "")), ref.name, ref.ecosystem)


def _same_name(candidate: str, name: str, ecosystem: EcosystemId) -> bool:
    if ecosystem is EcosystemId.PYPI:
        return candidate.replace("_", "-").replace(".", "-").lower() == name.lower()
    return candidate == name


def _sort_key(ecosystem: EcosystemId, version: str) -> tuple[int, object]:
    """Order fix candidates, pushing unorderable ones last rather than dropping them."""
    key = parse_version(ecosystem, version)
    return (1, version) if key is None else (0, key)
