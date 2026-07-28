"""Version-range matching, per ecosystem.

Python delegates to ``packaging``, which implements PEP 440 exactly. The rest share
one comparator engine, because npm, Cargo, RubyGems and NuGet all ultimately express
the same idea — a set of lower and upper bounds — behind different syntax. Each
ecosystem's job is reduced to expanding its own shorthand (``^``, ``~>``, ``[1.0,2.0)``)
into those bounds.

Implemented here rather than pulled in from a semver package: every dependency this
tool takes on is one more thing its own users have to trust.

Every entry point can return ``None``, meaning "this syntax is beyond us". That is
deliberately distinct from "nothing matched" — the caller marks such dependencies
unresolved and queries OSV without a version rather than silently skipping them.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from icebergsca.core.models import EcosystemId
from icebergsca.core.versions import VersionKey, parse

#: A single comparator: an optional operator followed by a partial version.
_COMPARATOR = re.compile(r"^(?P<op>[<>]=?|=|\^|~>|~|!=)?\s*(?P<version>[0-9xX*].*|\*)$")

#: ``1.2.3 - 2.3.4`` — an inclusive range, spaces around the hyphen required.
_HYPHEN = re.compile(r"^(?P<low>\S+)\s+-\s+(?P<high>\S+)$")

#: A NuGet interval: ``[1.0,2.0)``, ``[1.0,]``, ``(,2.0]``, ``[1.0]``.
_INTERVAL = re.compile(r"^(?P<open>[\[(])(?P<body>[^\])]*)(?P<close>[\])])$")

_WILDCARDS = ("x", "X", "*")

#: Ecosystems where a bare version means "compatible with", not "exactly".
_CARET_BY_DEFAULT = frozenset({EcosystemId.CARGO})

#: NuGet reads a bare version as a *minimum*: "1.0" means "1.0 or newer".
_GTE_BY_DEFAULT = frozenset({EcosystemId.NUGET})

#: An operator may be separated from its version by spaces — RubyGems writes
#: ``~> 1.2`` — so the gap is closed before the clause is split on whitespace.
#: Otherwise ``~>`` and ``1.2`` become two tokens and neither parses.
_OPERATOR_GAP = re.compile(r"(~>|[<>]=?|[\^~=!]=?)\s+(?=[\d*xX])")

Bound = tuple[str, VersionKey]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def satisfies(ecosystem: EcosystemId, version: str, constraint: str) -> bool | None:
    """Does ``version`` satisfy ``constraint``? ``None`` if we cannot tell."""
    if ecosystem is EcosystemId.PYPI:
        return _pep440_satisfies(version, constraint)

    clauses = _parse_range(ecosystem, constraint)
    if clauses is None:
        return None

    key = parse(ecosystem, version)
    if key is None:
        return None

    return any(all(_compare(key, bound) for bound in clause) for clause in clauses)


def best_match(
    ecosystem: EcosystemId, versions: Iterable[str], constraint: str | None
) -> str | None:
    """Highest version satisfying ``constraint``, or ``None`` if none does.

    Pre-releases are excluded unless the constraint asks for one. A scan that
    recommended ``3.0.0-rc1`` as the version a fresh install would get would be
    wrong about the one thing this function exists to answer.
    """
    candidates = [v for v in versions if v]
    if not candidates:
        return None

    wants_prerelease = bool(constraint) and _mentions_prerelease(str(constraint))
    scored: list[tuple[VersionKey, str]] = []

    for version in candidates:
        key = parse(ecosystem, version)
        if key is None:
            continue
        if not wants_prerelease and _is_prerelease(key):
            continue
        if constraint and satisfies(ecosystem, version, constraint) is not True:
            continue
        scored.append((key, version))

    if not scored:
        return None
    return max(scored, key=lambda pair: pair[0])[1]


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def _pep440_satisfies(version: str, constraint: str) -> bool | None:
    try:
        specifier = SpecifierSet(constraint)
    except InvalidSpecifier:
        return None
    try:
        return specifier.contains(Version(version), prereleases=True)
    except InvalidVersion:
        return None


# ---------------------------------------------------------------------------
# Range parsing
# ---------------------------------------------------------------------------


def _parse_range(ecosystem: EcosystemId, constraint: str) -> list[list[Bound]] | None:
    """Expand a constraint into alternative clauses of bounds (an OR of ANDs)."""
    text = constraint.strip()
    if not text or text in ("*", "latest", "any"):
        return [[]]  # an empty clause matches everything

    if ecosystem is EcosystemId.NUGET and _INTERVAL.match(text):
        return _parse_interval(text)

    clauses: list[list[Bound]] = []
    for alternative in text.split("||"):
        clause = _parse_clause(ecosystem, alternative.strip())
        if clause is None:
            return None
        clauses.append(clause)
    return clauses


def _parse_clause(ecosystem: EcosystemId, text: str) -> list[Bound] | None:
    if not text:
        return []

    hyphen = _HYPHEN.match(text)
    if hyphen:
        low = parse(ecosystem, hyphen.group("low"))
        high = _upper_bound_for_partial(ecosystem, hyphen.group("high"))
        if low is None or high is None:
            return None
        return [(">=", low), ("<", high)]

    bounds: list[Bound] = []
    for token in re.split(r"[\s,]+", _OPERATOR_GAP.sub(r"\1", text)):
        if not token:
            continue
        expanded = _expand(ecosystem, token)
        if expanded is None:
            return None
        bounds.extend(expanded)
    return bounds


def _expand(ecosystem: EcosystemId, token: str) -> list[Bound] | None:
    """Turn one comparator into explicit bounds."""
    match = _COMPARATOR.match(token.strip())
    if match is None:
        return None

    operator = match.group("op") or ""
    raw = match.group("version").strip()

    if raw in _WILDCARDS:
        return []

    if operator in ("^",) or (not operator and ecosystem in _CARET_BY_DEFAULT):
        return _caret(ecosystem, raw)
    if operator in ("~", "~>"):
        return _tilde(ecosystem, raw, pessimistic=operator == "~>")

    if _has_wildcard(raw):
        lower = parse(ecosystem, _fill(raw, 0))
        upper = _upper_bound_for_partial(ecosystem, raw)
        if lower is None or upper is None:
            return None
        return [(">=", lower), ("<", upper)]

    key = parse(ecosystem, raw)
    if key is None:
        return None
    default = ">=" if ecosystem in _GTE_BY_DEFAULT else "="
    return [(operator or default, key)]


def _caret(ecosystem: EcosystemId, raw: str) -> list[Bound] | None:
    """``^1.2.3`` — anything up to the next change in the leftmost non-zero part.

    The zero-major rule matters: ``^0.2.3`` allows ``0.2.9`` but not ``0.3.0``,
    because pre-1.0 packages treat the minor as a breaking-change marker.
    """
    parts = _numeric_parts(raw)
    if not parts:
        return None
    lower = parse(ecosystem, _fill(raw, 0))
    if lower is None:
        return None

    index = next((i for i, value in enumerate(parts) if value != 0), len(parts) - 1)
    index = min(index, 2)
    upper_parts = list(parts[: index + 1]) + [0] * (2 - index)
    upper_parts[index] += 1

    upper = parse(ecosystem, ".".join(str(p) for p in upper_parts))
    return None if upper is None else [(">=", lower), ("<", upper)]


def _tilde(
    ecosystem: EcosystemId, raw: str, *, pessimistic: bool
) -> list[Bound] | None:
    """``~1.2.3`` and RubyGems' ``~> 1.2.3``.

    Both allow changes to the last specified component only, so ``~> 1.2`` permits
    ``1.9`` while ``~> 1.2.3`` stops at ``1.2.x``.
    """
    parts = _numeric_parts(raw)
    if not parts:
        return None
    lower = parse(ecosystem, _fill(raw, 0))
    if lower is None:
        return None

    # Pessimistic (``~>``) drops the last component and increments the one before
    # it; npm's ``~`` pins the minor when one was given, the major otherwise.
    index = max(0, len(parts) - 2) if pessimistic else min(1, len(parts) - 1)

    upper_parts = list(parts[: index + 1])
    upper_parts[index] += 1
    upper = parse(ecosystem, ".".join(str(p) for p in upper_parts))
    return None if upper is None else [(">=", lower), ("<", upper)]


def _parse_interval(text: str) -> list[list[Bound]] | None:
    """NuGet interval notation, where brackets mean inclusive and parens exclusive."""
    match = _INTERVAL.match(text)
    if match is None:
        return None

    body = match.group("body")
    inclusive_low = match.group("open") == "["
    inclusive_high = match.group("close") == "]"

    if "," not in body:
        version = parse(EcosystemId.NUGET, body.strip())
        return None if version is None else [[("=", version)]]

    low_text, _, high_text = body.partition(",")
    bounds: list[Bound] = []

    if low_text.strip():
        low = parse(EcosystemId.NUGET, low_text.strip())
        if low is None:
            return None
        bounds.append((">=" if inclusive_low else ">", low))

    if high_text.strip():
        high = parse(EcosystemId.NUGET, high_text.strip())
        if high is None:
            return None
        bounds.append(("<=" if inclusive_high else "<", high))

    return [bounds]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _compare(key: VersionKey, bound: Bound) -> bool:
    operator, target = bound
    if operator in (">=", ""):
        return key >= target
    if operator == ">":
        return key > target
    if operator == "<=":
        return key <= target
    if operator == "<":
        return key < target
    if operator == "!=":
        return key != target
    return key == target


def _numeric_parts(raw: str) -> list[int]:
    parts: list[int] = []
    for segment in raw.split("+")[0].split("-")[0].split("."):
        if segment in _WILDCARDS or not segment:
            break
        cleaned = segment.lstrip("vV")
        if not cleaned.isdigit():
            break
        parts.append(int(cleaned))
    return parts


def _fill(raw: str, filler: int) -> str:
    """Complete a partial version, so ``1.2`` becomes ``1.2.0``."""
    parts = _numeric_parts(raw)
    while len(parts) < 3:
        parts.append(filler)
    suffix = raw.split("-", 1)[1] if "-" in raw and not _has_wildcard(raw) else ""
    body = ".".join(str(p) for p in parts)
    return f"{body}-{suffix}" if suffix else body


def _has_wildcard(raw: str) -> bool:
    return any(segment in _WILDCARDS for segment in raw.split("."))


def _upper_bound_for_partial(ecosystem: EcosystemId, raw: str) -> VersionKey | None:
    """The exclusive upper bound implied by a partial or wildcard version."""
    parts = _numeric_parts(raw)
    if not parts:
        # A bare "x" or "*" has no upper bound; use an unreachable one.
        return parse(ecosystem, "999999.0.0")
    if len(parts) >= 3:
        parts = parts[:3]
        parts[2] += 1
    else:
        parts[-1] += 1
    return parse(ecosystem, ".".join(str(p) for p in parts))


def _is_prerelease(key: VersionKey) -> bool:
    return key[1] == 0


def _mentions_prerelease(constraint: str) -> bool:
    return bool(re.search(r"\d-[0-9A-Za-z]", constraint)) or "rc" in constraint.lower()
