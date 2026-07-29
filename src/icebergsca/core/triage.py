"""Accepting a finding, on the record.

A weekly scheduled scan is the right way to run this tool, because most new findings
arrive when an advisory is published rather than when code changes. But it means a
project with one unfixable transitive advisory gets a red build every week forever,
with nowhere to say that somebody assessed it. That ends in ``|| true`` on the command
or the job quietly deleted, which is worse than the finding.

So: an ignore file. Everything here is shaped by the fact that it is the one feature
whose job is to make findings go away, and therefore the one most able to undermine the
rest of the tool:

* A suppressed finding stays in the report, marked. It never vanishes.
* A reason is required. Without one, an entry is indistinguishable from a mistake.
* An expiry always exists, defaulting rather than being optional, so that no entry
  becomes permanent by accident. Past it, the finding comes back.
* Matching is exact. A rule names one advisory and one package, so it can never grow
  to swallow a second, unrelated finding.
* A rule that matches nothing says so, because a typo that silently suppresses nothing
  looks identical to a rule that is working.

Parsing takes text, never a path — file reading lives in the layer above, as it does
for every other parser here.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, replace
from datetime import date, timedelta
from typing import Any

from icebergsca.core.errors import ConfigError
from icebergsca.core.models import Finding, PackageRef, Suppression

#: How long an entry lasts when it does not say. Long enough not to be busywork, short
#: enough that a yearly audit is not the first time anyone revisits it.
DEFAULT_EXPIRY_DAYS = 90

_ENTRY_KEYS = frozenset({"advisory", "package", "reason", "expires"})
_REQUIRED_KEYS = ("advisory", "package", "reason")


@dataclass(frozen=True, slots=True)
class IgnoreRule:
    """One ``[[ignore]]`` entry."""

    #: An OSV ID or any of its aliases — ``GHSA-...``, ``CVE-...``, ``PYSEC-...``.
    #: Matching either means a user can write the CVE they were sent even though OSV
    #: answers with a GHSA.
    advisory: str
    #: A bare ``name`` (``group:artifact`` for Maven), or a purl with or without a
    #: version. Never a pattern. The versioned form pins the decision to the version
    #: assessed, so an upgrade brings the finding back for a fresh look; the other two
    #: forms outlive it. Both are legitimate — which one is right depends on whether
    #: the reason was about this version or about how the package is used.
    package: str
    reason: str
    expires: date

    @property
    def key(self) -> str:
        return f"{self.advisory}@{self.package}"

    def is_expired(self, today: date) -> bool:
        return today > self.expires

    def matches(self, finding: Finding) -> bool:
        """Exact match on advisory (or alias) and package (purl or bare name).

        Deliberately not a substring or glob test. A rule for ``GHSA-aaaa`` must not
        reach ``GHSA-aaaa-bbbb``, and one written for a package must not travel to
        another that merely shares a prefix.
        """
        advisory = self.advisory.lower()
        known = {finding.advisory.id.lower()}
        known.update(alias.lower() for alias in finding.advisory.aliases)
        if advisory not in known:
            return False

        ref = finding.package
        unversioned = PackageRef(ref.ecosystem, ref.name).purl
        return self.package in (ref.purl, unversioned, ref.name)


def parse_ignore_file(
    path: str, content: str, *, today: date | None = None
) -> tuple[IgnoreRule, ...]:
    """Parse ``.icebergsca.toml`` into rules, refusing anything it does not understand.

    Every parser in this codebase is forgiving, skipping what it cannot read, because a
    third-party manifest is not ours to police and refusing to scan over an unknown
    field would be worse. This one is the opposite: the file is the user's own, it
    exists to remove findings, and a key silently ignored because it was misspelled is
    the difference between a finding being assessed and being invisible.
    """
    today = today or date.today()

    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(path, f"invalid TOML: {exc}") from exc

    raw = data.get("ignore", [])
    if not isinstance(raw, list):
        raise ConfigError(path, "'ignore' must be a list of [[ignore]] entries")

    rules: list[IgnoreRule] = []
    for index, entry in enumerate(raw, start=1):
        rules.append(_rule(path, index, entry, today))

    _reject_duplicates(path, rules)
    return tuple(rules)


def apply(
    findings: tuple[Finding, ...],
    rules: tuple[IgnoreRule, ...],
    *,
    today: date | None = None,
) -> tuple[tuple[Finding, ...], tuple[str, ...]]:
    """Mark findings their rules accept, and report on the rules themselves.

    Returns the findings — all of them, with the accepted ones marked — and warnings
    about rules that did no work. A rule matching nothing is worth saying out loud: it
    is either a typo, or an entry left behind after the upgrade that fixed it, and both
    look exactly like a rule that is quietly working.
    """
    if not rules:
        return findings, ()

    today = today or date.today()
    live = [rule for rule in rules if not rule.is_expired(today)]
    expired = [rule for rule in rules if rule.is_expired(today)]

    used: set[str] = set()
    marked: list[Finding] = []
    for finding in findings:
        rule = next((r for r in live if r.matches(finding)), None)
        if rule is None:
            marked.append(finding)
            continue
        used.add(rule.key)
        marked.append(
            replace(
                finding,
                suppression=Suppression(
                    reason=rule.reason, expires=rule.expires, rule=rule.key
                ),
            )
        )

    warnings: list[str] = []
    for rule in expired:
        # Not an error, and emphatically not a reason to fail the scan: the finding
        # simply stops being accepted and shows up again, which is the point.
        warnings.append(
            f"ignore entry {rule.key} expired on {rule.expires.isoformat()}; "
            "the finding is reported again"
        )
    for rule in live:
        if rule.key not in used:
            warnings.append(
                f"ignore entry {rule.key} matched no finding; "
                "it may be misspelled, or the finding may already be resolved"
            )

    return tuple(marked), tuple(warnings)


def _rule(path: str, index: int, entry: Any, today: date) -> IgnoreRule:
    where = f"ignore entry {index}"
    if not isinstance(entry, dict):
        raise ConfigError(path, f"{where} must be a table")

    unknown = sorted(set(entry) - _ENTRY_KEYS)
    if unknown:
        known = ", ".join(sorted(_ENTRY_KEYS))
        raise ConfigError(
            path, f"{where} has unknown key(s) {', '.join(unknown)}; expected {known}"
        )

    values: dict[str, str] = {}
    for key in _REQUIRED_KEYS:
        value = entry.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ConfigError(path, f"{where} needs a non-empty '{key}'")
        values[key] = value.strip()

    return IgnoreRule(
        advisory=values["advisory"],
        package=values["package"],
        reason=values["reason"],
        expires=_expires(path, where, entry.get("expires"), today),
    )


def _expires(path: str, where: str, value: Any, today: date) -> date:
    """A date, or a default — never "no expiry".

    TOML has a native date type, so an unquoted ``2026-10-27`` arrives as a ``date``. A
    quoted one arrives as a string and is parsed, because the difference is invisible in
    a text editor and refusing it would teach nothing.
    """
    if value is None:
        return today + timedelta(days=DEFAULT_EXPIRY_DAYS)
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError as exc:
            raise ConfigError(
                path, f"{where} has an unparseable 'expires': {exc}"
            ) from exc
    raise ConfigError(path, f"{where} 'expires' must be a date like 2026-10-27")


def _reject_duplicates(path: str, rules: list[IgnoreRule]) -> None:
    """Two entries for the same advisory and package mean one of them does nothing.

    Which one wins is an implementation detail nobody should have to know, and the
    second is usually an edit that was meant to replace the first.
    """
    seen: set[str] = set()
    for rule in rules:
        if rule.key in seen:
            raise ConfigError(path, f"duplicate ignore entry for {rule.key}")
        seen.add(rule.key)
