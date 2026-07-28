"""Report renderers.

Every renderer has the same shape — take a :class:`~icebergsca.core.models.ScanReport`,
return a string — so the CLI never branches on format beyond looking one up here.
``color`` and ``width`` are honoured by the table renderer and ignored by the
machine-readable ones; passing ``color=False`` makes output deterministic, which is
what the golden-file tests rely on.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum

from icebergsca.core.errors import IcebergSCAError
from icebergsca.core.models import ScanReport
from icebergsca.report import csv_, cyclonedx, json_, sarif, table


class OutputFormat(StrEnum):
    TABLE = "table"
    JSON = "json"
    CSV = "csv"
    SARIF = "sarif"
    CYCLONEDX = "cyclonedx"


Renderer = Callable[..., str]

_RENDERERS: dict[OutputFormat, Renderer] = {
    OutputFormat.TABLE: table.render,
    OutputFormat.JSON: json_.render,
    OutputFormat.CSV: csv_.render,
    OutputFormat.SARIF: sarif.render,
    OutputFormat.CYCLONEDX: cyclonedx.render,
}


def render(
    report: ScanReport,
    fmt: OutputFormat,
    *,
    color: bool = True,
    width: int | None = None,
) -> str:
    renderer = _RENDERERS.get(fmt)
    if renderer is None:
        # ``str`` rather than ``.value``: this is a library entry point, and a caller
        # passing a plain string deserves the error it asked for, not an AttributeError.
        raise IcebergSCAError(f"the {fmt} output format is not implemented yet")
    return renderer(report, color=color, width=width)


__all__ = ["OutputFormat", "render"]
