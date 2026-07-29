"""Exception hierarchy.

Every error raised deliberately by IcebergSCA derives from :class:`IcebergSCAError`,
so the CLI can distinguish "our problem, report it nicely" from a genuine bug that
should surface with a traceback.

Note what is *not* here: there is no exception for "a vulnerability was found".
Findings are data, not errors, and never affect the exit code.
"""

from __future__ import annotations


class IcebergSCAError(Exception):
    """Base class for all expected IcebergSCA failures."""


class DiscoveryError(IcebergSCAError):
    """The scan target could not be walked (missing path, unreadable directory)."""


class ParseError(IcebergSCAError):
    """A file we claim to support could not be parsed.

    Carries the offending path so the CLI can report *which* file failed without
    the parser needing to know anything about presentation.
    """

    def __init__(self, path: str, reason: str) -> None:
        super().__init__(f"{path}: {reason}")
        self.path = path
        self.reason = reason


class UnsupportedFileError(ParseError):
    """The file matched a name we recognise but a variant we cannot handle.

    Raised for things like a ``yarn.lock`` in an unknown lockfile version. Kept
    distinct from :class:`ParseError` because a clear "unsupported version" message
    is far better than emitting a silently wrong dependency graph.
    """


class ResolutionError(IcebergSCAError):
    """A dependency's version could not be resolved against its registry."""


class UpstreamError(IcebergSCAError):
    """An upstream service (OSV, a package registry) could not be reached.

    Raised only after retries are exhausted. The scanner catches this, marks the
    affected packages as failed, and downgrades the scan to partial — it never
    silently reports a clean result.
    """


class CacheError(IcebergSCAError):
    """The on-disk cache could not be opened or written."""


class ConfigError(IcebergSCAError):
    """The user's own configuration file is malformed.

    Deliberately strict, unlike the parsers: a third-party manifest we did not write
    gets the benefit of the doubt and anything unrecognised is skipped, because the
    alternative is refusing to scan a project over a field we never needed. An ignore
    file is the opposite case. It exists to *remove* findings, so a mistyped key that
    silently suppresses nothing — or everything — is precisely the failure this tool
    must not have. Say so and stop.
    """

    def __init__(self, path: str, reason: str) -> None:
        super().__init__(f"{path}: {reason}")
        self.path = path
        self.reason = reason
