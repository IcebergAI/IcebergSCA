"""Canonical JSON report.

This is the full-fidelity document every other consumer is expected to build on, so
the shape is written out explicitly rather than derived with ``dataclasses.asdict``.
An accidental field rename is a breaking change for anyone parsing it; making the
serialisation deliberate is what keeps ``schema_version`` meaningful.
"""

from __future__ import annotations

import json
from typing import Any

from icebergsca.core.models import (
    Advisory,
    Dependency,
    Finding,
    ManifestResult,
    PackageRef,
    ScanReport,
)


def render(report: ScanReport, *, color: bool = True, width: int | None = None) -> str:
    """Serialise a report. ``color`` and ``width`` are ignored."""
    return json.dumps(to_dict(report), indent=2, sort_keys=False) + "\n"


def to_dict(report: ScanReport) -> dict[str, Any]:
    return {
        "schema_version": report.schema_version,
        "tool": {"name": "icebergsca", "version": report.tool_version},
        "scan": {
            "root": str(report.root),
            "started_at": report.started_at.isoformat(),
            "finished_at": report.finished_at.isoformat(),
            "status": report.status.value,
            # Explicit rather than implied by an empty findings list: consumers must
            # be able to tell "checked, nothing found" from "never checked".
            "vulnerabilities_checked": report.vulnerabilities_checked,
            "complete": report.is_complete,
        },
        "summary": {
            "dependencies": len(report.dependencies),
            "direct": report.direct_count,
            "transitive": report.transitive_count,
            "packages": len(report.packages),
            # Outstanding findings. ``suppressed`` is reported beside it rather than
            # inside it, so a consumer reading only ``findings`` under-states nothing:
            # the total is findings + suppressed, and both are named.
            "findings": len(report.active_findings),
            "suppressed": len(report.suppressed_findings),
            "by_severity": {
                level.value: count
                for level, count in report.counts_by_severity().items()
            },
            "unchecked_packages": len(report.scan_failed),
            "skipped_files": len(report.skipped),
        },
        "manifests": [_manifest(result) for result in report.manifests],
        "dependencies": [_dependency(dep) for dep in report.dependencies],
        "findings": [_finding(finding) for finding in report.sorted_findings()],
        # The rules, not a second copy of the findings. Duplicating finding objects
        # across two arrays invites double-counting, and lets a consumer read
        # ``findings`` alone and never learn some were accepted — which is why the
        # per-finding state lives on the finding itself. What is here instead is the
        # audit trail: which entry accepted what, and which did no work at all.
        "suppressed": _suppressions(report),
        "unchecked_packages": [_package(ref) for ref in report.scan_failed],
        "skipped": [
            {"path": str(entry.path), "reason": entry.reason}
            for entry in report.skipped
        ],
        "warnings": list(report.warnings),
    }


def _suppressions(report: ScanReport) -> list[dict[str, Any]]:
    """One entry per ignore rule that fired, with what it accepted."""
    grouped: dict[str, dict[str, Any]] = {}
    for finding in report.sorted_findings():
        rule = finding.suppression
        if rule is None:
            continue
        entry = grouped.setdefault(
            rule.rule,
            {
                "rule": rule.rule,
                "reason": rule.reason,
                "expires": rule.expires.isoformat(),
                "findings": [],
            },
        )
        entry["findings"].append(
            {"advisory": finding.advisory.id, "purl": finding.package.purl}
        )
    return list(grouped.values())


def _package(ref: PackageRef) -> dict[str, Any]:
    return {
        "ecosystem": ref.ecosystem.osv_name,
        "name": ref.name,
        "version": ref.version,
        "purl": ref.purl,
    }


def _manifest(result: ManifestResult) -> dict[str, Any]:
    return {
        "ecosystem": result.ecosystem.osv_name,
        "directory": str(result.directory),
        "manifests": [str(path) for path in result.manifests],
        "lockfiles": [str(path) for path in result.lockfiles],
        "parsed": [str(path) for path in result.parsed],
        "dependency_count": result.dependency_count,
        "from_lockfile": result.from_lockfile,
        "approximate": result.approximate,
        "error": result.error,
    }


def _dependency(dep: Dependency) -> dict[str, Any]:
    return {
        "package": _package(dep.ref),
        "scope": dep.scope.value,
        "direct": dep.direct,
        "pin": dep.pin.value,
        "constraint": dep.constraint,
        "source": {"path": str(dep.source.path), "line": dep.source.line},
        "parents": [ref.purl for ref in dep.parents],
        # Emitted so that a removal stays auditable. An exclusion is the one thing
        # here that takes a package *out* of the graph, and a reader has no other way
        # to tell a package that was excluded from one that was never there.
        "exclusions": sorted(dep.exclusions),
    }


def _advisory(advisory: Advisory) -> dict[str, Any]:
    severity = advisory.severity
    return {
        "id": advisory.id,
        "modified": advisory.modified,
        "aliases": list(advisory.aliases),
        "summary": advisory.summary,
        "details": advisory.details,
        "published": advisory.published,
        "malicious": advisory.is_malicious,
        "severity": {
            "level": advisory.level.value,
            "score": severity.score if severity else None,
            "vector": severity.vector if severity else None,
        },
        "references": list(advisory.references),
    }


def _finding(finding: Finding) -> dict[str, Any]:
    return {
        "package": _package(finding.package),
        "advisory": _advisory(finding.advisory),
        "fixed_version": finding.fixed_version,
        "direct": finding.is_direct,
        "introduced_by": [
            {
                "path": str(dep.source.path),
                "line": dep.source.line,
                "scope": dep.scope.value,
                "direct": dep.direct,
            }
            for dep in finding.introduced_by
        ],
        # Present on every finding, ``null`` when nothing accepted it, so that reading
        # this field is never optional. A consumer that skips it counts an accepted
        # finding as outstanding, which is the harmless direction.
        "suppression": (
            None
            if finding.suppression is None
            else {
                "reason": finding.suppression.reason,
                "expires": finding.suppression.expires.isoformat(),
                "rule": finding.suppression.rule,
            }
        ),
    }
