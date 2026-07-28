"""CycloneDX 1.6 JSON — an SBOM and a VEX document in one file.

CycloneDX was chosen over SPDX because it has a first-class ``vulnerabilities`` array.
SPDX can describe the same components but has no native way to say "and this one is
affected by CVE-2021-44228", which would mean shipping the interesting half of the
report in a separate file.

Written by hand rather than through ``cyclonedx-python-lib``. A dependency scanner
that drags in a large dependency tree of its own is a poor advertisement for itself,
and the document is a few nested dictionaries. Correctness is held by validating the
output against the published schema in the test suite.
"""

from __future__ import annotations

import json
from typing import Any

from icebergsca.core.models import (
    Dependency,
    Finding,
    PackageRef,
    ScanReport,
    SeverityLevel,
)

SPEC_VERSION = "1.6"
BOM_FORMAT = "CycloneDX"

#: CycloneDX severity vocabulary. It has "info" and "none" where we have "none" and
#: "unknown", so the mapping is not quite one to one.
_SEVERITY: dict[SeverityLevel, str] = {
    SeverityLevel.CRITICAL: "critical",
    SeverityLevel.HIGH: "high",
    SeverityLevel.MEDIUM: "medium",
    SeverityLevel.LOW: "low",
    SeverityLevel.NONE: "none",
    SeverityLevel.UNKNOWN: "unknown",
}

#: Rating method, from the vector we parsed.
_METHOD_BY_PREFIX = (("CVSS:4", "CVSSv4"), ("CVSS:3", "CVSSv31"), ("AV:", "CVSSv2"))


def render(report: ScanReport, *, color: bool = True, width: int | None = None) -> str:
    """Serialise as CycloneDX. ``color`` and ``width`` are ignored."""
    return json.dumps(to_dict(report), indent=2) + "\n"


def to_dict(
    report: ScanReport, *, include_vulnerabilities: bool = True
) -> dict[str, Any]:
    """Build the document.

    ``include_vulnerabilities=False`` produces a plain SBOM, which is what the
    ``sbom`` subcommand emits when asked not to scan.
    """
    components = {dep.ref: dep for dep in report.dependencies}

    document: dict[str, Any] = {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": _metadata(report),
        "components": [_component(ref, dep) for ref, dep in components.items()],
        "dependencies": _dependency_graph(report),
    }

    if include_vulnerabilities:
        document["vulnerabilities"] = [
            _vulnerability(finding) for finding in report.sorted_findings()
        ]

    return document


def _metadata(report: ScanReport) -> dict[str, Any]:
    return {
        "timestamp": report.finished_at.isoformat().replace("+00:00", "Z"),
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "icebergsca",
                    "version": report.tool_version or "0.0.0",
                }
            ]
        },
        "component": {
            "type": "application",
            "bom-ref": "root",
            "name": report.root.name or "project",
        },
        "properties": [
            # Consumers must be able to tell an SBOM whose vulnerabilities were
            # checked from one whose were not. An empty array means neither on its own.
            {
                "name": "icebergsca:vulnerabilitiesChecked",
                "value": str(report.vulnerabilities_checked).lower(),
            },
            {"name": "icebergsca:complete", "value": str(report.is_complete).lower()},
        ],
    }


def _component(ref: PackageRef, dep: Dependency) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": ref.purl,
        "name": ref.name,
        "purl": ref.purl,
        "properties": [
            {"name": "icebergsca:scope", "value": dep.scope.value},
            {"name": "icebergsca:direct", "value": str(dep.direct).lower()},
            # Whether the version was read from a lockfile or resolved from a range
            # changes how much the rest of the document can be trusted.
            {"name": "icebergsca:pin", "value": dep.pin.value},
        ],
    }
    if ref.version:
        component["version"] = ref.version
    if dep.source.path:
        component["properties"].append(
            {"name": "icebergsca:source", "value": dep.source.path.as_posix()}
        )
    return component


def _dependency_graph(report: ScanReport) -> list[dict[str, Any]]:
    """Emit edges wherever a lockfile recorded them.

    Direct dependencies hang off the root component; everything with known parents
    is listed under each of them. Formats that record no edges simply contribute
    fewer entries rather than a fabricated flat tree.
    """
    children: dict[str, list[str]] = {"root": []}

    for dep in report.dependencies:
        if dep.direct and dep.ref.purl not in children["root"]:
            children["root"].append(dep.ref.purl)
        for parent in dep.parents:
            children.setdefault(parent.purl, [])
            if dep.ref.purl not in children[parent.purl]:
                children[parent.purl].append(dep.ref.purl)

    # Every component needs an entry, even an empty one, for the graph to be valid.
    for dep in report.dependencies:
        children.setdefault(dep.ref.purl, [])

    return [
        {"ref": ref, "dependsOn": sorted(dependencies)}
        for ref, dependencies in children.items()
    ]


def _vulnerability(finding: Finding) -> dict[str, Any]:
    advisory = finding.advisory
    entry: dict[str, Any] = {
        "bom-ref": f"{finding.package.purl}#{advisory.id}",
        "id": advisory.id,
        "source": {
            "name": "OSV",
            "url": f"https://osv.dev/vulnerability/{advisory.id}",
        },
        "ratings": _ratings(finding),
        "affects": [{"ref": finding.package.purl}],
    }

    if advisory.aliases:
        entry["references"] = [
            {
                "id": alias,
                "source": {"name": _alias_source(alias)},
            }
            for alias in advisory.aliases
        ]
    if advisory.summary:
        entry["description"] = advisory.summary
    if advisory.details:
        entry["detail"] = advisory.details
    if advisory.published:
        entry["published"] = advisory.published
    if advisory.modified:
        entry["updated"] = advisory.modified
    if advisory.references:
        entry["advisories"] = [{"url": url} for url in advisory.references]
    if finding.fixed_version:
        entry["recommendation"] = (
            f"Upgrade {finding.package.name} to {finding.fixed_version} or later."
        )

    return entry


def _alias_source(alias: str) -> str:
    if alias.startswith("CVE-"):
        return "NVD"
    if alias.startswith("GHSA-"):
        return "GitHub Advisory Database"
    return "OSV"


def _ratings(finding: Finding) -> list[dict[str, Any]]:
    severity = finding.advisory.severity
    rating: dict[str, Any] = {
        "source": {"name": "OSV"},
        "severity": _SEVERITY[finding.level],
    }
    if severity is not None and severity.score is not None:
        rating["score"] = severity.score
    if severity is not None and severity.vector:
        rating["vector"] = severity.vector
        rating["method"] = _method(severity.vector)
    else:
        # "other" is the honest answer when the rating came from a qualitative label
        # rather than a scored vector.
        rating["method"] = "other"
    return [rating]


def _method(vector: str) -> str:
    for prefix, method in _METHOD_BY_PREFIX:
        if vector.startswith(prefix):
            return method
    return "other"
