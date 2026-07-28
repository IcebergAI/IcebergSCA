"""Version ordering.

Needed in two places: choosing the lowest fix above an installed version, and
picking the highest release satisfying a range. Both only ever compare versions of
*one* package within *one* ecosystem, which is what makes a single loose comparator
workable where a fully faithful implementation of seven versioning schemes would not.

Python gets the real thing via ``packaging``. Everything else uses a common
dotted-numeric-with-prerelease ordering, which is exactly right for semver
ecosystems (npm, crates.io, Go) and close enough for the rest.
"""

from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version

from icebergsca.core.models import EcosystemId

#: Splits a version into its numeric and alphabetic runs, so that "1.0.0rc1" and
#: "1.0.0-rc.1" produce comparable shapes.
_SEGMENTS = re.compile(r"\d+|[A-Za-z]+")

#: Sorts below any numeric segment, so a pre-release loses to its own release.
_ALPHA_RANK = -1

#: Release tuples are padded to this length before comparison, so that ``1.0`` and
#: ``1.0.0`` compare equal. Without it a shorter tuple sorts below a longer one and
#: an inclusive upper bound of ``2.0`` would exclude ``2.0.0``.
_RELEASE_WIDTH = 4

VersionKey = tuple[tuple[int, ...], int, tuple[tuple[int, str], ...]]


def _pad(release: tuple[int, ...]) -> tuple[int, ...]:
    return release + (0,) * (_RELEASE_WIDTH - len(release))


def parse(ecosystem: EcosystemId, version: str) -> VersionKey | None:
    """Return a sortable key for ``version``, or ``None`` if it is not orderable.

    ``None`` means "we cannot place this" — a git SHA, a local path, a
    ``${revision}`` placeholder. Callers must treat that as unknown rather than
    coercing it to a zero that would compare as older than everything.
    """
    version = version.strip()
    if not version:
        return None

    if ecosystem is EcosystemId.PYPI:
        try:
            parsed = Version(version)
        except InvalidVersion:
            return _loose(version)
        return (
            _pad(parsed.release),
            0 if parsed.is_prerelease else 1,
            ((0, str(parsed.pre or parsed.dev or "")),),
        )

    return _loose(version)


def _loose(version: str) -> VersionKey | None:
    """Generic dotted ordering with pre-release handling.

    ``1.2.3`` outranks ``1.2.3-rc.1`` because the presence of a pre-release suffix
    is itself part of the key, ranked below "no suffix" — the same rule semver, PEP
    440 and RubyGems all independently arrived at.
    """
    # Strip a leading "v", which Go modules and many git tags carry.
    body = version[1:] if version[:1] in "vV" and version[1:2].isdigit() else version
    # Build metadata never affects precedence.
    body = body.split("+", 1)[0]

    # A version starts with a number. Without this check a commit hash such as
    # "abcdef123456" yields a release of (123456,) and silently orders as a version.
    if not body[:1].isdigit():
        return None

    release_text, separator, prerelease_text = body.partition("-")
    release = tuple(
        int(segment) for segment in _SEGMENTS.findall(release_text) if segment.isdigit()
    )
    if not release:
        return None
    release = _pad(release)

    prerelease: tuple[tuple[int, str], ...] = tuple(
        (int(segment), "") if segment.isdigit() else (_ALPHA_RANK, segment.lower())
        for segment in _SEGMENTS.findall(prerelease_text)
    )
    return release, 0 if separator else 1, prerelease


def compare(ecosystem: EcosystemId, left: str, right: str) -> int | None:
    """Return -1, 0 or 1 — or ``None`` when either version cannot be ordered."""
    a, b = parse(ecosystem, left), parse(ecosystem, right)
    if a is None or b is None:
        return None
    return (a > b) - (a < b)


def is_newer(ecosystem: EcosystemId, candidate: str, than: str) -> bool:
    """True only when we are *certain* ``candidate`` is the newer of the two."""
    result = compare(ecosystem, candidate, than)
    return result == 1
