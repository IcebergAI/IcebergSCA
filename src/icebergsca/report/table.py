"""Human-readable terminal report."""

from __future__ import annotations

import shutil
from io import StringIO

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from icebergsca.core.models import Finding, ScanReport, SeverityLevel

_SEVERITY_STYLE: dict[SeverityLevel, str] = {
    SeverityLevel.CRITICAL: "bold bright_red",
    SeverityLevel.HIGH: "red",
    SeverityLevel.MEDIUM: "yellow",
    SeverityLevel.LOW: "cyan",
    SeverityLevel.UNKNOWN: "dim",
    SeverityLevel.NONE: "green",
}

#: Fall-back width when output is not a terminal. Wide enough for the findings table
#: without wrapping the columns that matter.
_DEFAULT_WIDTH = 100


def render(report: ScanReport, *, color: bool = True, width: int | None = None) -> str:
    console = Console(
        file=StringIO(),
        force_terminal=color,
        no_color=not color,
        width=width or _terminal_width(),
        highlight=False,
        soft_wrap=False,
    )

    _render_header(console, report)
    _render_manifests(console, report)
    _render_findings(console, report)
    _render_problems(console, report)

    assert isinstance(console.file, StringIO)
    return console.file.getvalue()


def _terminal_width() -> int:
    return max(
        _DEFAULT_WIDTH, min(shutil.get_terminal_size((_DEFAULT_WIDTH, 24)).columns, 160)
    )


def _render_header(console: Console, report: ScanReport) -> None:
    elapsed = (report.finished_at - report.started_at).total_seconds()
    console.print()
    console.print(f"[bold]IcebergSCA[/bold] [dim]{escape(str(report.root))}[/dim]")
    console.print(
        f"[dim]{len(report.dependencies)} dependencies "
        f"({report.direct_count} direct, {report.transitive_count} transitive) "
        f"in {len(report.manifests)} manifest group(s) · {elapsed:.2f}s[/dim]"
    )
    console.print()


def _render_manifests(console: Console, report: ScanReport) -> None:
    if not report.manifests:
        console.print("[yellow]No dependency manifests or lockfiles found.[/yellow]")
        console.print()
        return

    table = Table(box=None, pad_edge=False, header_style="bold dim")
    table.add_column("Ecosystem")
    table.add_column("Location")
    table.add_column("Source")
    table.add_column("Deps", justify="right")

    for result in report.manifests:
        if result.error:
            source = f"[red]{escape(result.error)}[/red]"
        else:
            # Name the files actually parsed, not the ones discovered — after a
            # lockfile falls back to its manifest those are different, and showing
            # the lockfile would imply a precision the numbers do not have.
            names = ", ".join(escape(path.name) for path in result.parsed)
            kind = "lockfile" if result.from_lockfile else "declared"
            marker = " [yellow]~[/yellow]" if result.approximate else ""
            source = f"{names or '—'} [dim]({kind})[/dim]{marker}"

        table.add_row(
            result.ecosystem.label,
            escape(str(result.directory)),
            source,
            str(result.dependency_count),
        )

    console.print(table)
    console.print()


def _render_findings(console: Console, report: ScanReport) -> None:
    if not report.vulnerabilities_checked:
        # Say nothing was checked rather than nothing was found. An empty finding
        # list because the lookup never ran must never read as a clean bill of health.
        console.print(
            "[yellow]Vulnerability lookup did not run — no packages were checked "
            "against OSV.[/yellow]"
        )
        console.print()
        return

    if not report.findings:
        checked = len(report.packages) - len(report.scan_failed)
        if checked == 0 and report.scan_failed:
            # Never lead with a clean-sounding sentence when the count behind it is
            # zero. "No known vulnerabilities in 0 packages" reads as reassurance.
            console.print(
                f"[red]No packages could be checked — all {len(report.scan_failed)} "
                "lookups failed. This is not a clean result.[/red]"
            )
        else:
            message = (
                f"[green]No known vulnerabilities in {checked} package(s).[/green]"
            )
            if report.scan_failed:
                message += (
                    f" [yellow]{len(report.scan_failed)} package(s) could not be "
                    "checked — this result is incomplete.[/yellow]"
                )
            console.print(message)
        console.print()
        return

    table = Table(box=None, pad_edge=False, header_style="bold dim")
    table.add_column("Severity")
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("Advisory")
    table.add_column("Fixed in")
    table.add_column("Via")

    for finding in report.sorted_findings():
        style = _SEVERITY_STYLE[finding.level]
        table.add_row(
            f"[{style}]{finding.level.value}[/{style}]",
            escape(finding.package.name),
            escape(finding.package.version or "?"),
            escape(_advisory_label(finding)),
            escape(finding.fixed_version or "—"),
            escape(_via_label(finding)),
        )

    console.print(table)
    console.print()
    _render_summary(console, report)


def _advisory_label(finding: Finding) -> str:
    """Prefer a CVE identifier — it is the one users can look up anywhere."""
    cves = finding.advisory.cve_ids
    return cves[0] if cves else finding.advisory.id


def _via_label(finding: Finding) -> str:
    if finding.is_direct:
        return "direct"
    sources = finding.sources
    return str(sources[0].path) if sources else "transitive"


def _render_summary(console: Console, report: ScanReport) -> None:
    parts = [
        f"[{_SEVERITY_STYLE[level]}]{count} {level.value}[/{_SEVERITY_STYLE[level]}]"
        for level, count in report.counts_by_severity().items()
    ]
    console.print(
        f"[bold]{len(report.findings)} finding(s):[/bold] " + "  ".join(parts)
    )
    console.print()


def _render_problems(console: Console, report: ScanReport) -> None:
    for warning in report.warnings:
        console.print(f"[yellow]warning:[/yellow] {escape(warning)}")

    if report.scan_failed:
        console.print(
            f"[red]{len(report.scan_failed)} package(s) could not be checked "
            "against OSV:[/red]"
        )
        for ref in report.scan_failed[:10]:
            console.print(f"  [red]·[/red] {escape(ref.coordinate)}")
        if len(report.scan_failed) > 10:
            console.print(f"  [dim]… and {len(report.scan_failed) - 10} more[/dim]")

    if report.skipped:
        console.print(f"[dim]{len(report.skipped)} file(s) skipped:[/dim]")
        for entry in report.skipped[:10]:
            console.print(
                f"  [dim]· {escape(str(entry.path))} — {escape(entry.reason)}[/dim]"
            )
        if len(report.skipped) > 10:
            console.print(f"  [dim]… and {len(report.skipped) - 10} more[/dim]")

    if report.warnings or report.scan_failed or report.skipped:
        console.print()
