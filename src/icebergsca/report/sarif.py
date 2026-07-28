"""SARIF 2.1.0 output, for GitHub code scanning.

Uploaded with ``github/codeql-action/upload-sarif``, findings appear inline on the
pull request that introduced them.

Two details make the difference between a usable SARIF file and a noisy one:

* **Stable fingerprints.** GitHub tracks a result across runs by its
  ``partialFingerprints``. Deriving ours from the package URL and advisory ID — never
  from a line number — means reformatting a manifest does not close every alert and
  immediately reopen it as new.
* **security-severity.** GitHub reads this numeric property, not the SARIF ``level``,
  to decide whether an alert is critical or low. Omitting it makes every finding
  render as a warning regardless of how bad it is.
"""

from __future__ import annotations

import json
from typing import Any

from icebergsca.core.models import Finding, ScanReport, SeverityLevel

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
VERSION = "2.1.0"

INFORMATION_URI = "https://github.com/IcebergAI/IcebergSCA"

#: SARIF has three usable levels; CVSS has five bands. Anything at high or above is
#: an error, so a critical finding cannot be filtered out as a mere warning.
_LEVEL: dict[SeverityLevel, str] = {
    SeverityLevel.CRITICAL: "error",
    SeverityLevel.HIGH: "error",
    SeverityLevel.MEDIUM: "warning",
    SeverityLevel.LOW: "note",
    SeverityLevel.UNKNOWN: "warning",
    SeverityLevel.NONE: "note",
}

#: Representative scores for advisories with a qualitative rating but no CVSS vector.
#: GitHub needs a number; these are the midpoints of each band.
_FALLBACK_SCORE: dict[SeverityLevel, float] = {
    SeverityLevel.CRITICAL: 9.5,
    SeverityLevel.HIGH: 8.0,
    SeverityLevel.MEDIUM: 5.5,
    SeverityLevel.LOW: 2.0,
    SeverityLevel.UNKNOWN: 5.5,
    SeverityLevel.NONE: 0.0,
}


def render(report: ScanReport, *, color: bool = True, width: int | None = None) -> str:
    """Serialise findings as SARIF. ``color`` and ``width`` are ignored."""
    return json.dumps(to_dict(report), indent=2) + "\n"


def to_dict(report: ScanReport) -> dict[str, Any]:
    findings = report.sorted_findings()
    rules = _rules(findings)

    return {
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "IcebergSCA",
                        "informationUri": INFORMATION_URI,
                        "version": report.tool_version or "0.0.0",
                        "rules": rules,
                    }
                },
                "results": [_result(finding) for finding in findings],
                "invocations": [
                    {
                        "executionSuccessful": report.is_complete,
                        "startTimeUtc": _timestamp(report.started_at.isoformat()),
                        "endTimeUtc": _timestamp(report.finished_at.isoformat()),
                        # Warnings ride along so an incomplete scan is visible in the
                        # uploaded artefact, not only in the terminal it ran in.
                        "toolExecutionNotifications": [
                            {
                                "level": "warning",
                                "message": {"text": warning},
                            }
                            for warning in report.warnings
                        ],
                    }
                ],
            }
        ],
    }


def _timestamp(value: str) -> str:
    """SARIF requires a trailing ``Z`` rather than a ``+00:00`` offset."""
    return value.replace("+00:00", "Z")


def _rule_id(finding: Finding) -> str:
    return finding.advisory.id


def _rules(findings: tuple[Finding, ...]) -> list[dict[str, Any]]:
    seen: dict[str, Finding] = {}
    for finding in findings:
        seen.setdefault(_rule_id(finding), finding)

    return [
        {
            "id": rule_id,
            "name": _rule_name(finding),
            "shortDescription": {"text": _summary(finding)},
            "fullDescription": {"text": _description(finding)},
            "help": {
                "text": _help_text(finding),
                "markdown": _help_markdown(finding),
            },
            "helpUri": f"https://osv.dev/vulnerability/{rule_id}",
            "properties": {
                "tags": [
                    "security",
                    "supply-chain",
                    finding.package.ecosystem.osv_name,
                ],
                "security-severity": str(_score(finding)),
                "precision": "high",
            },
            "defaultConfiguration": {"level": _LEVEL[finding.level]},
        }
        for rule_id, finding in seen.items()
    ]


def _rule_name(finding: Finding) -> str:
    """A CamelCase identifier, which is what SARIF consumers expect of a rule name."""
    kind = (
        "MaliciousPackage" if finding.advisory.is_malicious else "VulnerableDependency"
    )
    return f"{kind}/{finding.package.ecosystem.osv_name}"


def _summary(finding: Finding) -> str:
    if finding.advisory.summary:
        return finding.advisory.summary
    return f"{finding.package.name} is affected by {finding.advisory.id}"


def _description(finding: Finding) -> str:
    return finding.advisory.details or _summary(finding)


def _score(finding: Finding) -> float:
    severity = finding.advisory.severity
    if severity is not None and severity.score is not None:
        return severity.score
    return _FALLBACK_SCORE[finding.level]


def _help_text(finding: Finding) -> str:
    if finding.fixed_version:
        return f"Upgrade {finding.package.name} to {finding.fixed_version} or later."
    return (
        f"No fixed version is known for {finding.advisory.id}. "
        "Consider replacing or removing this dependency."
    )


def _help_markdown(finding: Finding) -> str:
    lines = [f"**{finding.advisory.id}** — {_summary(finding)}", ""]
    if finding.advisory.aliases:
        lines.append(f"Aliases: {', '.join(finding.advisory.aliases)}")
    lines.append(f"Installed: `{finding.package.coordinate}`")
    if finding.fixed_version:
        lines.append(f"Fixed in: `{finding.fixed_version}`")
    if finding.advisory.references:
        lines.append("")
        lines.extend(f"- {url}" for url in finding.advisory.references[:5])
    return "\n".join(lines)


def _result(finding: Finding) -> dict[str, Any]:
    return {
        "ruleId": _rule_id(finding),
        "level": _LEVEL[finding.level],
        "message": {"text": _message(finding)},
        "locations": [_location(finding)],
        # Derived from identity, not position: a reformatted manifest must not close
        # every alert and reopen it as new.
        "partialFingerprints": {
            "icebergsca/v1": f"{finding.package.purl}#{finding.advisory.id}"
        },
        "properties": {
            "purl": finding.package.purl,
            "ecosystem": finding.package.ecosystem.osv_name,
            "fixedVersion": finding.fixed_version,
            "direct": finding.is_direct,
        },
    }


def _message(finding: Finding) -> str:
    identifier = (
        finding.advisory.cve_ids[0] if finding.advisory.cve_ids else finding.advisory.id
    )
    parts = [f"{finding.package.coordinate} is affected by {identifier}"]
    if finding.advisory.summary:
        parts.append(f": {finding.advisory.summary}")
    if finding.fixed_version:
        parts.append(f" Upgrade to {finding.fixed_version} or later.")
    if not finding.is_direct:
        parts.append(" (a transitive dependency)")
    return "".join(parts)


def _location(finding: Finding) -> dict[str, Any]:
    sources = finding.sources
    if not sources:
        # Anchor to the manifest we know least about rather than dropping the result:
        # a finding with no location is still a finding.
        return {"physicalLocation": {"artifactLocation": {"uri": "."}}}

    location = sources[0]
    physical: dict[str, Any] = {
        "artifactLocation": {"uri": location.path.as_posix()},
    }
    if location.line:
        physical["region"] = {"startLine": location.line}
    return {"physicalLocation": physical}
