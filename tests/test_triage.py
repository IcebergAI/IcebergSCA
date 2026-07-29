"""The ignore file.

The negative assertions carry the weight here. This is the one feature whose purpose is
to make findings disappear, so a rule that reaches further than it was written to reach
hides a real vulnerability — the failure this codebase is otherwise arranged to make
impossible.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from icebergsca.core.errors import ConfigError
from icebergsca.core.models import (
    Advisory,
    EcosystemId,
    Finding,
    PackageRef,
    Severity,
    SeverityLevel,
)
from icebergsca.core.triage import DEFAULT_EXPIRY_DAYS, apply, parse_ignore_file

TODAY = date(2026, 7, 29)


def finding(
    advisory_id: str = "GHSA-aaaa",
    name: str = "pyyaml",
    *,
    aliases: tuple[str, ...] = (),
    ecosystem: EcosystemId = EcosystemId.PYPI,
    version: str = "5.1",
) -> Finding:
    return Finding(
        package=PackageRef(ecosystem, name, version),
        advisory=Advisory(
            id=advisory_id,
            modified="2026-01-01T00:00:00Z",
            aliases=aliases,
            severity=Severity(SeverityLevel.HIGH, 7.5),
        ),
    )


def entry(**overrides: str) -> str:
    fields = {
        "advisory": "GHSA-aaaa",
        "package": "pyyaml",
        "reason": "Unreachable from our code paths",
    } | overrides
    body = "\n".join(f'{key} = "{value}"' for key, value in fields.items())
    return f"[[ignore]]\n{body}\n"


def rules(text: str, *, today: date = TODAY) -> tuple:
    return parse_ignore_file(".icebergsca.toml", text, today=today)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def test_a_minimal_entry_parses() -> None:
    (rule,) = rules(entry())
    assert rule.advisory == "GHSA-aaaa"
    assert rule.package == "pyyaml"
    assert rule.reason == "Unreachable from our code paths"


def test_no_ignore_file_content_is_no_rules() -> None:
    assert rules("") == ()


def test_expiry_defaults_rather_than_being_absent() -> None:
    """An ignore file with no dates becomes permanent by accident. This is the guard."""
    (rule,) = rules(entry())
    assert rule.expires == TODAY + timedelta(days=DEFAULT_EXPIRY_DAYS)


def test_an_explicit_expiry_is_honoured() -> None:
    (rule,) = rules(entry() + 'expires = "2026-12-25"\n')
    assert rule.expires == date(2026, 12, 25)


def test_a_native_toml_date_is_accepted_as_well_as_a_quoted_one() -> None:
    """Quoted and unquoted look identical in an editor; refusing one teaches nothing."""
    (rule,) = rules(entry() + "expires = 2026-12-25\n")
    assert rule.expires == date(2026, 12, 25)


@pytest.mark.parametrize("missing", ["advisory", "package", "reason"])
def test_a_missing_required_field_is_an_error(missing: str) -> None:
    fields = {
        "advisory": "GHSA-aaaa",
        "package": "pyyaml",
        "reason": "because",
    }
    del fields[missing]
    text = "[[ignore]]\n" + "\n".join(f'{k} = "{v}"' for k, v in fields.items())
    with pytest.raises(ConfigError, match=missing):
        rules(text)


def test_an_empty_reason_is_an_error() -> None:
    """An entry with no justification is indistinguishable from a mistake later."""
    with pytest.raises(ConfigError, match="reason"):
        rules(entry(reason="   "))


def test_an_unknown_key_is_an_error_rather_than_being_skipped() -> None:
    """The deliberate divergence from every other parser here.

    A misspelled key in a third-party manifest should be skipped. A misspelled key in
    the file that decides which vulnerabilities you stop seeing should not.
    """
    with pytest.raises(ConfigError, match="advisroy"):
        rules('[[ignore]]\nadvisroy = "GHSA-aaaa"\npackage = "p"\nreason = "r"\n')


def test_an_unparseable_expiry_is_an_error() -> None:
    with pytest.raises(ConfigError, match="expires"):
        rules(entry() + 'expires = "next tuesday"\n')


def test_invalid_toml_names_the_file() -> None:
    with pytest.raises(ConfigError, match="invalid TOML"):
        rules("[[ignore]\n")


def test_a_duplicate_entry_is_an_error() -> None:
    """Two entries for the same pair mean one silently does nothing."""
    with pytest.raises(ConfigError, match="duplicate"):
        rules(entry() + entry())


def test_ignore_must_be_a_list_of_tables() -> None:
    with pytest.raises(ConfigError, match="list"):
        rules('ignore = "GHSA-aaaa"\n')


# ---------------------------------------------------------------------------
# Matching — the half that must never over-reach
# ---------------------------------------------------------------------------


def test_a_matching_rule_suppresses() -> None:
    marked, warnings = apply((finding(),), rules(entry()), today=TODAY)
    assert marked[0].is_suppressed
    assert marked[0].suppression is not None
    assert marked[0].suppression.reason == "Unreachable from our code paths"
    assert warnings == ()


def test_a_cve_alias_matches_the_ghsa_it_belongs_to() -> None:
    """Users are sent CVE numbers; OSV answers in GHSA. Both must work."""
    target = finding("GHSA-aaaa", aliases=("CVE-2026-1234",))
    marked, _ = apply((target,), rules(entry(advisory="CVE-2026-1234")), today=TODAY)
    assert marked[0].is_suppressed


def test_an_unversioned_purl_matches_as_well_as_a_bare_name() -> None:
    marked, _ = apply(
        (finding(),), rules(entry(package="pkg:pypi/pyyaml")), today=TODAY
    )
    assert marked[0].is_suppressed


def test_a_versioned_purl_pins_the_decision_to_that_version() -> None:
    """Writing the version means the acceptance does not survive an upgrade."""
    accepted, _ = apply(
        (finding(),), rules(entry(package="pkg:pypi/pyyaml@5.1")), today=TODAY
    )
    assert accepted[0].is_suppressed

    upgraded, _ = apply(
        (finding(version="5.4"),),
        rules(entry(package="pkg:pypi/pyyaml@5.1")),
        today=TODAY,
    )
    assert not upgraded[0].is_suppressed


def test_a_rule_does_not_reach_a_longer_advisory_id() -> None:
    """``GHSA-aaaa`` must not swallow ``GHSA-aaaa-bbbb``. No substrings, ever."""
    marked, _ = apply((finding("GHSA-aaaa-bbbb"),), rules(entry()), today=TODAY)
    assert not marked[0].is_suppressed


def test_a_rule_does_not_reach_a_longer_package_name() -> None:
    marked, _ = apply((finding(name="pyyaml-extra"),), rules(entry()), today=TODAY)
    assert not marked[0].is_suppressed


def test_a_rule_for_one_package_does_not_suppress_the_same_advisory_elsewhere() -> None:
    """The same CVE often affects several packages. A rule accepts one of them."""
    same_advisory = finding("GHSA-aaaa", name="other-package")
    marked, _ = apply((finding(), same_advisory), rules(entry()), today=TODAY)
    assert marked[0].is_suppressed
    assert not marked[1].is_suppressed


def test_a_rule_for_one_advisory_does_not_suppress_another_on_the_same_package() -> (
    None
):
    marked, _ = apply((finding("GHSA-bbbb"),), rules(entry()), today=TODAY)
    assert not marked[0].is_suppressed


def test_matching_is_case_insensitive_on_the_advisory_id() -> None:
    marked, _ = apply((finding(),), rules(entry(advisory="ghsa-aaaa")), today=TODAY)
    assert marked[0].is_suppressed


# ---------------------------------------------------------------------------
# Rules that do no work
# ---------------------------------------------------------------------------


def test_an_expired_entry_stops_suppressing_and_says_so() -> None:
    """Expiry surfaces the finding again. It never fails the scan."""
    text = entry() + 'expires = "2026-01-01"\n'
    marked, warnings = apply((finding(),), rules(text), today=TODAY)
    assert not marked[0].is_suppressed
    assert any("expired" in w for w in warnings)


def test_an_entry_expiring_today_still_applies() -> None:
    text = entry() + f'expires = "{TODAY.isoformat()}"\n'
    marked, _ = apply((finding(),), rules(text), today=TODAY)
    assert marked[0].is_suppressed


def test_a_rule_matching_nothing_is_reported() -> None:
    """A typo suppresses nothing and looks exactly like a rule that is working."""
    _, warnings = apply((finding("GHSA-bbbb"),), rules(entry()), today=TODAY)
    assert any("matched no finding" in w for w in warnings)


def test_no_rules_means_no_warnings_and_no_changes() -> None:
    original = (finding(),)
    marked, warnings = apply(original, (), today=TODAY)
    assert marked == original
    assert warnings == ()
