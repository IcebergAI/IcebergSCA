"""Flat CSV report, one row per finding per introducing manifest.

Deliberately denormalised: a package pulled in by three manifests produces three
rows, so that filtering the file by path answers "what does this team have to fix"
without any further processing.

The header row is always written, even when there are no findings — an empty file
and a failed run look identical, and only one of them is fine.
"""

from __future__ import annotations

import csv
from io import StringIO
from typing import Any

from icebergsca.core.models import ScanReport

#: Characters a spreadsheet treats as the start of a formula. A cell beginning with
#: one is prefixed with an apostrophe before being written.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

_COLUMNS = (
    "severity",
    "cvss_score",
    "advisory_id",
    "cve",
    "ecosystem",
    "package",
    "version",
    "fixed_version",
    "purl",
    "scope",
    "direct",
    "pin",
    "source_file",
    "source_line",
    "summary",
    # Appended, never inserted: consumers index these columns positionally and a
    # spreadsheet built last quarter should still line up.
    "suppressed",
    "suppression_reason",
)


def _defuse(value: Any) -> Any:
    """Neutralise a cell a spreadsheet would evaluate as a formula.

    Almost everything in a row is attacker-influenced: advisory summaries come from
    OSV, and package names, versions and paths come out of the repository being
    scanned. A summary of ``=HYPERLINK(...)`` in a file people are expected to open
    in Excel is a real payload, so a leading formula character is escaped with the
    apostrophe spreadsheets treat as "this is text".
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return f"'{value}"
    return value


def render(report: ScanReport, *, color: bool = True, width: int | None = None) -> str:
    """Serialise findings as CSV. ``color`` and ``width`` are ignored."""
    buffer = StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(_COLUMNS)

    for finding in report.sorted_findings():
        advisory = finding.advisory
        severity = advisory.severity
        cves = advisory.cve_ids

        # A finding with no recorded introducer still gets one row; losing it
        # because provenance was unavailable would understate the results.
        introducers = finding.introduced_by or (None,)
        for dep in introducers:
            row = (
                finding.level.value,
                "" if severity is None or severity.score is None else severity.score,
                advisory.id,
                cves[0] if cves else "",
                finding.package.ecosystem.osv_name,
                finding.package.name,
                finding.package.version or "",
                finding.fixed_version or "",
                finding.package.purl,
                dep.scope.value if dep else "",
                ("true" if dep.direct else "false") if dep else "",
                dep.pin.value if dep else "",
                str(dep.source.path) if dep else "",
                (dep.source.line or "") if dep else "",
                advisory.summary.replace("\n", " ").strip(),
                "true" if finding.is_suppressed else "false",
                # User-supplied text bound for a spreadsheet. It goes through _defuse
                # with every other cell below, which is what keeps a reason beginning
                # "=" from becoming a formula.
                finding.suppression.reason if finding.suppression else "",
            )
            writer.writerow([_defuse(cell) for cell in row])

    return buffer.getvalue()
