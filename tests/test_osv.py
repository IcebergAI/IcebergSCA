"""OSV client, cache and severity extraction.

Every test here runs against a mock transport. The transport 404s anything not
explicitly mocked, so a test that reaches the network fails rather than passing for
the wrong reason.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import pytest

from icebergsca.cache import Cache
from icebergsca.cache.store import NAMESPACE_TTL
from icebergsca.core.models import (
    Advisory,
    EcosystemId,
    PackageRef,
    Severity,
    SeverityLevel,
)
from icebergsca.osv import client as client_module
from icebergsca.osv import severity
from icebergsca.osv.client import (
    QUERYBATCH_URL,
    VULN_URL,
    OSVClient,
    VulnHit,
    merge_aliases,
)
from tests.conftest import MockTransport

REQUESTS = PackageRef(EcosystemId.PYPI, "requests", "2.19.1")
FLASK = PackageRef(EcosystemId.PYPI, "flask", "3.0.0")

GHSA = "GHSA-9wx4-h78v-vm56"

ADVISORY: dict[str, Any] = {
    "id": GHSA,
    "modified": "2024-11-01T00:00:00Z",
    "published": "2023-05-26T00:00:00Z",
    "aliases": ["CVE-2023-32681", "PYSEC-2023-74"],
    "summary": "Requests leaks Proxy-Authorization headers",
    "details": "Long description.",
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N"}
    ],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.31.0"}],
                }
            ],
        }
    ],
    "references": [{"type": "ADVISORY", "url": "https://example.invalid/advisory"}],
}


def batch(*vuln_lists: list[dict[str, str]]) -> dict[str, Any]:
    return {"results": [{"vulns": vulns} for vulns in vuln_lists]}


@pytest.fixture(autouse=True)
def _fast_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Collapse retry delays so the suite is not paced by real backoff.

    The backoff schedule itself is asserted separately in
    :func:`test_backoff_grows_between_attempts`, which patches ``asyncio.sleep``
    rather than shortening it.
    """
    monkeypatch.setattr(client_module, "_BACKOFF_BASE", 0.0001)
    monkeypatch.setattr(client_module, "_BACKOFF_CAP", 0.001)


def make_client(
    responses: dict[str, Any], **kwargs: Any
) -> tuple[OSVClient, MockTransport, Cache]:
    transport = MockTransport(responses)
    cache = Cache.memory()
    client = OSVClient(httpx.AsyncClient(transport=transport), cache, **kwargs)
    return client, transport, cache


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_finds_and_hydrates_an_advisory() -> None:
    client, _, _ = make_client(
        {
            f"POST:{QUERYBATCH_URL}": batch(
                [{"id": GHSA, "modified": ADVISORY["modified"]}]
            ),
            f"GET:{VULN_URL}/{GHSA}": ADVISORY,
        }
    )
    result = await client.scan([REQUESTS])

    (hit,) = result.advisories[REQUESTS]
    assert hit.advisory.id == GHSA
    # querybatch alone returns none of this — it is the whole reason for stage two.
    assert hit.advisory.summary.startswith("Requests leaks")
    assert hit.advisory.cve_ids == ("CVE-2023-32681",)
    assert hit.advisory.level is SeverityLevel.MEDIUM
    assert hit.fixed_version == "2.31.0"
    assert result.failed == ()


async def test_clean_package_produces_no_findings_but_no_failure() -> None:
    client, _, _ = make_client({f"POST:{QUERYBATCH_URL}": batch([])})
    result = await client.scan([FLASK])
    assert result.advisories == {}
    assert result.failed == ()


async def test_versionless_reference_is_queried_without_a_version() -> None:
    """An unresolved constraint still gets asked about — blind spots are worse."""
    client, transport, _ = make_client({f"POST:{QUERYBATCH_URL}": batch([])})
    await client.scan([PackageRef(EcosystemId.PYPI, "requests")])
    assert transport.calls == [("POST", QUERYBATCH_URL)]


async def test_results_are_matched_to_packages_positionally() -> None:
    client, _, _ = make_client(
        {
            f"POST:{QUERYBATCH_URL}": batch(
                [], [{"id": GHSA, "modified": ADVISORY["modified"]}]
            ),
            f"GET:{VULN_URL}/{GHSA}": ADVISORY,
        }
    )
    result = await client.scan([FLASK, REQUESTS])
    assert FLASK not in result.advisories
    assert REQUESTS in result.advisories


async def test_short_batch_response_does_not_misattribute_advisories() -> None:
    """A truncated results array must not shift one package's hits onto another."""
    client, _, _ = make_client({f"POST:{QUERYBATCH_URL}": {"results": []}})
    result = await client.scan([REQUESTS, FLASK])
    assert result.advisories == {}


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------


async def test_second_scan_makes_no_requests() -> None:
    responses = {
        f"POST:{QUERYBATCH_URL}": batch(
            [{"id": GHSA, "modified": ADVISORY["modified"]}]
        ),
        f"GET:{VULN_URL}/{GHSA}": ADVISORY,
    }
    transport = MockTransport(responses)
    cache = Cache.memory()

    first = OSVClient(httpx.AsyncClient(transport=transport), cache)
    await first.scan([REQUESTS])
    calls_after_first = len(transport.calls)

    second = OSVClient(httpx.AsyncClient(transport=transport), cache)
    result = await second.scan([REQUESTS])

    assert len(transport.calls) == calls_after_first
    assert result.advisories[REQUESTS][0].advisory.id == GHSA


async def test_advisory_detail_is_keyed_by_modified_timestamp() -> None:
    """A revised advisory lands under a new key, so no TTL has to be guessed at."""
    cache = Cache.memory()
    transport = MockTransport(
        {
            f"POST:{QUERYBATCH_URL}": batch([{"id": GHSA, "modified": "2026-01-01"}]),
            f"GET:{VULN_URL}/{GHSA}": {**ADVISORY, "summary": "revised text"},
        }
    )
    cache.set("osv_vuln", f"{GHSA}@2024-11-01T00:00:00Z", ADVISORY)

    client = OSVClient(httpx.AsyncClient(transport=transport), cache)
    result = await client.scan([REQUESTS])

    assert result.advisories[REQUESTS][0].advisory.summary == "revised text"


def test_advisory_detail_never_expires() -> None:
    assert NAMESPACE_TTL["osv_vuln"] is None


def test_cache_withholds_stale_entries_unless_asked() -> None:
    cache = Cache.memory()
    cache.set("osv_query", "k", [{"id": "X"}])
    cache._connection.execute(  # noqa: SLF001 — reaching in to age the row
        "UPDATE entries SET fetched_at = ?", (int(time.time()) - 10**6,)
    )

    assert cache.get("osv_query", "k") is None
    stale = cache.get("osv_query", "k", allow_stale=True)
    assert stale is not None
    assert stale.stale is True
    assert stale.age_seconds > 0


def test_cache_prune_keeps_advisory_detail() -> None:
    cache = Cache.memory()
    cache.set("osv_query", "q", [])
    cache.set("osv_vuln", "v", ADVISORY)
    cache._connection.execute(  # noqa: SLF001
        "UPDATE entries SET fetched_at = ?", (int(time.time()) - 10**6,)
    )

    assert cache.prune() == 1
    assert cache.get("osv_vuln", "v") is not None


def test_cache_survives_a_corrupt_entry() -> None:
    cache = Cache.memory()
    cache._connection.execute(  # noqa: SLF001
        "INSERT INTO entries VALUES ('osv_query', 'k', 'not json', ?)",
        (int(time.time()),),
    )
    assert cache.get("osv_query", "k") is None


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------


async def test_unreachable_osv_marks_packages_unchecked_not_clean() -> None:
    """The single worst failure mode: reporting clean because the network died."""
    client, _, _ = make_client({})  # every request 404s
    result = await client.scan([REQUESTS])

    assert result.advisories == {}
    assert result.failed == (REQUESTS,)
    assert any("failed after retries" in w for w in result.warnings)


async def test_server_errors_are_retried_then_reported() -> None:
    transport = MockTransport(
        {f"POST:{QUERYBATCH_URL}": httpx.Response(503, json={"error": "busy"})}
    )
    client = OSVClient(httpx.AsyncClient(transport=transport), Cache.memory())
    result = await client.scan([REQUESTS])

    assert len(transport.calls) > 1  # retried rather than given up on
    assert result.failed == (REQUESTS,)


async def test_backoff_grows_between_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Retries must space out, or a rate-limited batch just gets limited again."""
    monkeypatch.setattr(client_module, "_BACKOFF_BASE", 1.0)
    monkeypatch.setattr(client_module, "_BACKOFF_CAP", 60.0)

    delays: list[float] = []

    async def record(seconds: float) -> None:
        delays.append(seconds)

    monkeypatch.setattr(client_module.asyncio, "sleep", record)

    transport = MockTransport({f"POST:{QUERYBATCH_URL}": httpx.Response(429)})
    await OSVClient(httpx.AsyncClient(transport=transport), Cache.memory()).scan(
        [REQUESTS]
    )

    assert len(delays) >= 3
    assert delays[1] > delays[0]
    assert delays[2] > delays[1]


async def test_retry_after_header_is_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    delays: list[float] = []

    async def record(seconds: float) -> None:
        delays.append(seconds)

    monkeypatch.setattr(client_module, "_BACKOFF_CAP", 60.0)
    monkeypatch.setattr(client_module.asyncio, "sleep", record)

    transport = MockTransport(
        {f"POST:{QUERYBATCH_URL}": httpx.Response(429, headers={"Retry-After": "7"})}
    )
    await OSVClient(httpx.AsyncClient(transport=transport), Cache.memory()).scan(
        [REQUESTS]
    )

    assert delays and all(delay == 7.0 for delay in delays)


async def test_stale_cache_is_used_when_osv_is_down_and_says_so() -> None:
    cache = Cache.memory()
    cache.set("osv_query", "PyPI:requests:2.19.1", [{"id": GHSA, "modified": "old"}])
    cache.set("osv_vuln", f"{GHSA}@old", ADVISORY)
    cache._connection.execute(  # noqa: SLF001
        "UPDATE entries SET fetched_at = ? WHERE namespace = 'osv_query'",
        (int(time.time()) - 10**6,),
    )

    client = OSVClient(httpx.AsyncClient(transport=MockTransport({})), cache)
    result = await client.scan([REQUESTS])

    assert result.advisories[REQUESTS][0].advisory.id == GHSA
    assert result.failed == ()
    assert any("expired cache" in w for w in result.warnings)


async def test_offline_mode_makes_no_requests() -> None:
    client, transport, _ = make_client({}, offline=True)
    result = await client.scan([REQUESTS])

    assert transport.calls == []
    assert result.failed == (REQUESTS,)
    assert any("offline" in w for w in result.warnings)


async def test_pagination_is_disclosed_rather_than_silently_truncated() -> None:
    client, _, _ = make_client(
        {
            f"POST:{QUERYBATCH_URL}": {
                "results": [{"vulns": [], "next_page_token": "more"}]
            }
        }
    )
    result = await client.scan([REQUESTS])
    assert any("incomplete" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# Alias merging
# ---------------------------------------------------------------------------


def hit(
    advisory_id: str,
    *,
    aliases: tuple[str, ...] = (),
    level: SeverityLevel | None = None,
    fixed: str | None = None,
    summary: str = "",
) -> VulnHit:
    return VulnHit(
        advisory=Advisory(
            id=advisory_id,
            modified="2026-01-01",
            aliases=aliases,
            summary=summary,
            severity=None if level is None else Severity(level, 7.5),
        ),
        fixed_version=fixed,
    )


def test_ghsa_and_pysec_for_one_cve_become_one_finding() -> None:
    """OSV carries a record per database; reported raw that is one CVE listed twice."""
    merged = merge_aliases(
        [
            hit("GHSA-aaaa", aliases=("CVE-2024-0001",), level=SeverityLevel.HIGH),
            hit("PYSEC-2024-1", aliases=("CVE-2024-0001",)),
        ]
    )
    assert len(merged) == 1


def test_the_scored_record_wins_so_severity_is_not_lost() -> None:
    """GHSA usually carries a CVSS vector and PYSEC usually does not."""
    merged = merge_aliases(
        [
            hit("PYSEC-2024-1", aliases=("CVE-2024-0001",)),
            hit("GHSA-aaaa", aliases=("CVE-2024-0001",), level=SeverityLevel.HIGH),
        ]
    )
    assert merged[0].advisory.level is SeverityLevel.HIGH
    assert "CVE-2024-0001" in merged[0].advisory.aliases
    assert "PYSEC-2024-1" in merged[0].advisory.aliases


def test_a_fix_version_survives_from_whichever_record_had_it() -> None:
    merged = merge_aliases(
        [
            hit("GHSA-aaaa", aliases=("CVE-2024-0001",), level=SeverityLevel.HIGH),
            hit("PYSEC-2024-1", aliases=("CVE-2024-0001",), fixed="2.31.0"),
        ]
    )
    assert merged[0].fixed_version == "2.31.0"


def test_records_linked_only_through_a_third_are_still_merged() -> None:
    """Grouping is transitive: A↔B and B↔C means all three are one vulnerability."""
    merged = merge_aliases(
        [
            hit("GHSA-aaaa", aliases=("CVE-2024-0001",)),
            hit("CVE-2024-0001", aliases=("PYSEC-2024-1",)),
            hit("PYSEC-2024-1"),
        ]
    )
    assert len(merged) == 1


def test_unrelated_advisories_are_kept_apart() -> None:
    merged = merge_aliases(
        [
            hit("GHSA-aaaa", aliases=("CVE-2024-0001",)),
            hit("GHSA-bbbb", aliases=("CVE-2024-0002",)),
        ]
    )
    assert len(merged) == 2


def test_merging_is_deterministic_regardless_of_input_order() -> None:
    a = hit("GHSA-aaaa", aliases=("CVE-2024-0001",), level=SeverityLevel.HIGH)
    b = hit("GHSA-bbbb", aliases=("CVE-2024-0001",), level=SeverityLevel.HIGH)
    assert merge_aliases([a, b])[0].advisory.id == merge_aliases([b, a])[0].advisory.id


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (9.8, SeverityLevel.CRITICAL),
        (7.5, SeverityLevel.HIGH),
        (5.3, SeverityLevel.MEDIUM),
        (3.1, SeverityLevel.LOW),
        (0.0, SeverityLevel.NONE),
    ],
)
def test_cvss_bands(score: float, expected: SeverityLevel) -> None:
    assert severity.level_for_score(score) is expected


V3_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
V4_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def test_cvss_v4_is_preferred_over_v3() -> None:
    result = severity.extract(
        {
            "severity": [
                {"type": "CVSS_V3", "score": V3_VECTOR},
                {"type": "CVSS_V4", "score": V4_VECTOR},
            ]
        }
    )
    assert result is not None
    assert result.vector is not None
    assert result.vector.startswith("CVSS:4.0")


def test_github_severity_label_is_used_when_no_vector_is_present() -> None:
    result = severity.extract({"database_specific": {"severity": "MODERATE"}})
    assert result is not None
    assert result.level is SeverityLevel.MEDIUM
    # A label carries no score, and inventing one would be a fabrication.
    assert result.score is None


def test_missing_severity_stays_unknown_rather_than_zero() -> None:
    assert severity.extract({"id": "OSV-1"}) is None


def test_unparseable_vector_is_ignored() -> None:
    assert (
        severity.extract({"severity": [{"type": "CVSS_V3", "score": "nonsense"}]})
        is None
    )


# ---------------------------------------------------------------------------
# Fix versions
# ---------------------------------------------------------------------------


def test_fixed_version_is_the_lowest_release_above_the_installed_one() -> None:
    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.20.0"},
                            {"introduced": "2.25.0"},
                            {"fixed": "2.31.0"},
                        ],
                    }
                ],
            }
        ]
    }
    assert severity.fixed_version(vuln, REQUESTS) == "2.20.0"


def test_fixed_version_ignores_other_packages_in_the_same_advisory() -> None:
    """One advisory can cover several packages; the wrong fix is worse than none."""
    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "urllib3"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.26.5"}]}],
            },
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.31.0"}]}],
            },
        ]
    }
    assert severity.fixed_version(vuln, REQUESTS) == "2.31.0"


def test_git_ranges_yield_no_fix_version() -> None:
    """Their events are commit hashes; "upgrade to 4f2a91c" helps nobody."""
    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [{"type": "GIT", "events": [{"fixed": "4f2a91cdeadbeef"}]}],
            }
        ]
    }
    assert severity.fixed_version(vuln, REQUESTS) is None


def test_no_fix_above_the_installed_version_returns_none() -> None:
    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.0.0"}]}],
            }
        ]
    }
    assert severity.fixed_version(vuln, REQUESTS) is None


def test_python_name_normalisation_when_matching_affected_packages() -> None:
    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "Pydantic_Core"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.20.0"}]}],
            }
        ]
    }
    ref = PackageRef(EcosystemId.PYPI, "pydantic-core", "2.18.0")
    assert severity.fixed_version(vuln, ref) == "2.20.0"
