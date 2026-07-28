"""Typer application.

A thin presentation layer: parse flags, call :func:`icebergsca.core.scanner.scan`,
render, choose an exit code. Any logic worth testing belongs in ``core`` instead.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from enum import IntEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from icebergsca import __version__
from icebergsca.cache import Cache, cache_path
from icebergsca.core.discovery import DiscoveryOptions
from icebergsca.core.errors import IcebergSCAError
from icebergsca.core.models import EcosystemId, ScanReport, ScanStatus, Scope
from icebergsca.core.scanner import DEFAULT_SCOPES, ScanOptions, scan
from icebergsca.report import OutputFormat, cyclonedx, render


class ExitCode(IntEnum):
    """Process exit codes.

    Findings deliberately do not appear here. A scan that reports forty critical
    vulnerabilities has done its job and exits :attr:`OK`; severity gating arrives
    later as an explicit ``--fail-on`` flag.

    :attr:`USAGE` is 2 rather than 1 because Typer's vendored Click reserves that
    code for usage errors, and remapping it would mean overriding framework
    internals for nothing.
    """

    OK = 0
    #: The scan itself failed, or completed without checking everything it was asked
    #: to check. Results are incomplete and must not be read as a clean result.
    SCAN_FAILED = 1
    USAGE = 2


app = typer.Typer(
    name="icebergsca",
    help="Software composition analysis: find dependencies, check them against OSV.",
    no_args_is_help=True,
    add_completion=False,
    # Stated rather than left to the default so that help output does not change
    # shape depending on what else happens to be installed.
    rich_markup_mode="rich",
)

logger = logging.getLogger("icebergsca")


def _fail(message: str) -> NoReturn:
    typer.secho(f"error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(ExitCode.SCAN_FAILED)


def _configure_logging(verbosity: int, quiet: bool) -> None:
    """Send logs to stderr so that ``--format json | jq`` is never polluted."""
    level = (
        logging.ERROR
        if quiet
        else (logging.WARNING, logging.INFO, logging.DEBUG)[min(verbosity, 2)]
    )
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"icebergsca {__version__}")
        raise typer.Exit(ExitCode.OK)


@app.callback()
def _main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    pass


@app.command("scan")
def scan_command(
    path: Annotated[
        Path,
        typer.Argument(
            help="Project directory, or a single manifest or lockfile.",
            show_default=False,
        ),
    ],
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Report format."),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the report here instead of stdout."),
    ] = None,
    include_dev: Annotated[
        bool,
        typer.Option(
            "--include-dev",
            help="Include dev and test dependencies, which are excluded by default.",
        ),
    ] = False,
    scopes: Annotated[
        list[Scope] | None,
        typer.Option(
            "--scope",
            help="Scope to include, overriding --include-dev. Repeatable.",
        ),
    ] = None,
    ecosystems: Annotated[
        list[EcosystemId] | None,
        typer.Option("--ecosystem", help="Ecosystem to restrict to. Repeatable."),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", help="Glob to skip. Repeatable."),
    ] = None,
    max_depth: Annotated[
        int | None,
        typer.Option("--max-depth", help="Maximum directory depth to walk."),
    ] = None,
    follow_symlinks: Annotated[
        bool,
        typer.Option("--follow-symlinks", help="Follow symlinked directories."),
    ] = False,
    offline: Annotated[
        bool,
        typer.Option(
            "--offline",
            help="Use cached OSV data only. Uncached packages are reported as "
            "unchecked, never as clean.",
        ),
    ] = False,
    no_cache: Annotated[
        bool, typer.Option("--no-cache", help="Ignore and do not write the disk cache.")
    ] = False,
    refresh: Annotated[
        bool, typer.Option("--refresh", help="Discard cached OSV data before scanning.")
    ] = False,
    concurrency: Annotated[
        int, typer.Option("--concurrency", min=1, max=64, help="Concurrent requests.")
    ] = 10,
    no_resolve: Annotated[
        bool,
        typer.Option(
            "--no-resolve",
            help="Do not resolve unpinned ranges against registries. Faster, but "
            "range-only dependencies are then checked without a version.",
        ),
    ] = False,
    no_color: Annotated[
        bool, typer.Option("--no-color", help="Disable coloured output.")
    ] = False,
    verbose: Annotated[
        int, typer.Option("-v", "--verbose", count=True, help="Increase log verbosity.")
    ] = 0,
    quiet: Annotated[
        bool, typer.Option("-q", "--quiet", help="Only log errors.")
    ] = False,
) -> None:
    """Scan a project for dependencies and known vulnerabilities."""
    _configure_logging(verbose, quiet)

    if scopes:
        scope_set = frozenset(scopes)
    elif include_dev:
        scope_set = frozenset(Scope)
    else:
        scope_set = DEFAULT_SCOPES

    if refresh and not no_cache:
        _refresh_cache()

    options = ScanOptions(
        discovery=DiscoveryOptions(
            exclude=tuple(exclude or ()),
            max_depth=max_depth,
            follow_symlinks=follow_symlinks,
            ecosystems=frozenset(ecosystems) if ecosystems else None,
        ),
        scopes=scope_set,
        offline=offline,
        concurrency=concurrency,
        no_cache=no_cache,
        resolve_ranges=not no_resolve,
    )

    try:
        report = asyncio.run(scan(path, options))
    except IcebergSCAError as exc:
        _fail(str(exc))

    _write(report, output_format, output, color=_use_color(no_color, output))

    if report.status is not ScanStatus.OK or report.scan_failed:
        typer.secho(
            "scan incomplete — some files or packages could not be checked",
            fg=typer.colors.YELLOW,
            err=True,
        )
        raise typer.Exit(ExitCode.SCAN_FAILED)


def _use_color(no_color: bool, output: Path | None) -> bool:
    """Colour only when writing to a terminal, honouring the NO_COLOR convention."""
    if no_color or os.environ.get("NO_COLOR"):
        return False
    return output is None and sys.stdout.isatty()


def _write(
    report: ScanReport,
    output_format: OutputFormat,
    output: Path | None,
    *,
    color: bool,
) -> None:
    try:
        text = render(report, output_format, color=color)
    except IcebergSCAError as exc:
        _fail(str(exc))

    if output is None:
        sys.stdout.write(text)
        return

    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    except OSError as exc:
        _fail(f"could not write {output}: {exc.strerror or exc}")

    typer.secho(f"wrote {output}", fg=typer.colors.GREEN, err=True)


@app.command("sbom")
def sbom_command(
    path: Annotated[
        Path, typer.Argument(help="Project directory or manifest.", show_default=False)
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write here instead of stdout."),
    ] = None,
    include_dev: Annotated[
        bool, typer.Option("--include-dev", help="Include dev and test dependencies.")
    ] = False,
    with_vulnerabilities: Annotated[
        bool,
        typer.Option(
            "--with-vulnerabilities/--components-only",
            help="Include OSV findings as a VEX section. Off means components only, "
            "and no network calls to OSV.",
        ),
    ] = False,
    verbose: Annotated[
        int, typer.Option("-v", "--verbose", count=True, help="Increase log verbosity.")
    ] = 0,
    quiet: Annotated[
        bool, typer.Option("-q", "--quiet", help="Only log errors.")
    ] = False,
) -> None:
    """Emit a CycloneDX 1.6 SBOM.

    Equivalent to [bold]scan --format cyclonedx[/bold], except that it defaults to
    components only — an SBOM is often wanted for inventory rather than for findings.
    """
    _configure_logging(verbose, quiet)

    options = ScanOptions(
        scopes=frozenset(Scope) if include_dev else DEFAULT_SCOPES,
        # Skipping the OSV stage entirely is the point of --components-only: an
        # inventory should not need to ask anyone about vulnerabilities.
        check_vulnerabilities=with_vulnerabilities,
    )

    try:
        report = asyncio.run(scan(path, options))
    except IcebergSCAError as exc:
        _fail(str(exc))

    document = cyclonedx.to_dict(report, include_vulnerabilities=with_vulnerabilities)
    text = json.dumps(document, indent=2) + "\n"

    if output is None:
        sys.stdout.write(text)
    else:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(text, encoding="utf-8")
        except OSError as exc:
            _fail(f"could not write {output}: {exc.strerror or exc}")
        typer.secho(f"wrote {output}", fg=typer.colors.GREEN, err=True)

    if report.status is not ScanStatus.OK:
        raise typer.Exit(ExitCode.SCAN_FAILED)


# ---------------------------------------------------------------------------
# cache
# ---------------------------------------------------------------------------

cache_app = typer.Typer(
    help="Inspect and manage the on-disk OSV cache.",
    no_args_is_help=True,
)
app.add_typer(cache_app, name="cache")


@contextmanager
def _open_cache() -> Iterator[Cache]:
    """Open the cache, reporting an unusable one as an error rather than a traceback.

    A scan can carry on without a cache, so it only logs. These commands are *about*
    the cache, so for them a failure to open one is the answer.
    """
    try:
        cache = Cache.open()
    except IcebergSCAError as exc:
        _fail(str(exc))
    try:
        with cache:
            yield cache
    except IcebergSCAError as exc:
        _fail(str(exc))


def _refresh_cache() -> None:
    with _open_cache() as cache:
        cache.clear()


@cache_app.command("info")
def cache_info() -> None:
    """Show where the cache lives and what is in it."""
    path = cache_path()
    typer.echo(f"location: {path}")
    if not path.exists():
        typer.echo("no cache yet — it is created on the first scan")
        return

    typer.echo(f"size:     {path.stat().st_size:,} bytes")
    with _open_cache() as cache:
        rows = list(cache.stats())
    if not rows:
        typer.echo("cache is empty")
        return
    for namespace, count, stale in rows:
        suffix = f" ({stale} stale)" if stale else ""
        typer.echo(f"  {namespace:<12} {count:>7} entries{suffix}")


@cache_app.command("clear")
def cache_clear() -> None:
    """Delete every cached entry."""
    with _open_cache() as cache:
        typer.echo(f"cleared {cache.clear()} entries")


@cache_app.command("prune")
def cache_prune() -> None:
    """Delete expired entries, keeping advisory detail.

    Advisory records are keyed by their modified timestamp, so they can never go
    stale and are always worth keeping.
    """
    with _open_cache() as cache:
        typer.echo(f"pruned {cache.prune()} expired entries")


def main() -> None:
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
