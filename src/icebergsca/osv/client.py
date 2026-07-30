"""OSV API client.

Two calls, in two stages:

``POST /v1/querybatch``
    Up to 1000 package queries per request. Returns only an ID and a ``modified``
    timestamp per hit — not the summary or severity, despite what a quick read of a
    response suggests.

``GET /v1/vulns/{id}``
    The full record, fetched once per unique advisory.

That ``modified`` timestamp is what makes the detail cache exact: keying it
``{id}@{modified}`` means a revised advisory lands under a different key and a
stale one is impossible, so no TTL has to be guessed at.

The other thing worth stating plainly is the failure policy. Every upstream error is
retried and then, if it still fails, recorded against the affected packages. Nothing
here ever swallows an error and returns an empty advisory list: reporting "no
vulnerabilities found" because the network was down is the single worst thing this
tool could do.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import random
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import httpx

from icebergsca.cache import Cache
from icebergsca.core.models import Advisory, PackageRef
from icebergsca.osv import severity as severity_module

logger = logging.getLogger(__name__)

QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns"

#: OSV's documented maximum queries per batch request.
BATCH_LIMIT = 1000

#: Retried rather than treated as fatal: rate limiting and transient server faults.
_RETRY_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})

_MAX_ATTEMPTS = 4
_BACKOFF_BASE = 0.5  # seconds; doubles each attempt
_BACKOFF_CAP = 8.0
_REQUEST_TIMEOUT = 30.0

USER_AGENT = "icebergsca (+https://github.com/IcebergAI/IcebergSCA)"


@dataclass(frozen=True, slots=True)
class VulnHit:
    """One advisory affecting one package, with the upgrade target if there is one."""

    advisory: Advisory
    fixed_version: str | None = None


@dataclass(frozen=True, slots=True)
class OSVResult:
    advisories: dict[PackageRef, tuple[VulnHit, ...]] = field(default_factory=dict)
    #: Packages we could not check. A non-empty value makes the whole report partial.
    failed: tuple[PackageRef, ...] = ()
    warnings: tuple[str, ...] = ()
    cache_hits: int = 0
    cache_misses: int = 0


class OSVClient:
    """Looks packages up in OSV, caching both stages on disk."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        cache: Cache,
        *,
        offline: bool = False,
        concurrency: int = 10,
    ) -> None:
        self._client = client
        self._cache = cache
        self._offline = offline
        self._semaphore = asyncio.Semaphore(max(1, concurrency))
        self._warnings: list[str] = []
        self._stale_used = False

    async def scan(self, refs: Sequence[PackageRef]) -> OSVResult:
        """Check every reference, returning hits plus whatever could not be checked."""
        unique = list(dict.fromkeys(refs))
        if not unique:
            return OSVResult()

        summaries, failed = await self._query_all(unique)
        details = await self._fetch_details(summaries)

        advisories: dict[PackageRef, tuple[VulnHit, ...]] = {}
        for ref, entries in summaries.items():
            hits = [
                VulnHit(
                    advisory=_advisory(record),
                    fixed_version=severity_module.fixed_version(record, ref),
                )
                # querybatch already said this advisory affects the package; a failed
                # detail fetch costs the severity and fix version, never the finding.
                if (record := details.get(_detail_key(entry))) is not None
                else VulnHit(advisory=_skeleton(entry))
                for entry in entries
            ]
            if hits:
                merged = merge_aliases(hits)
                advisories[ref] = tuple(sorted(merged, key=lambda hit: hit.advisory.id))

        if self._stale_used:
            self._warnings.append(
                "some results came from expired cache entries because OSV could not "
                "be reached — advisories published since then are not included"
            )

        return OSVResult(
            advisories=advisories,
            failed=tuple(failed),
            warnings=tuple(dict.fromkeys(self._warnings)),
            cache_hits=self._cache.hits,
            cache_misses=self._cache.misses,
        )

    # -- stage 1: querybatch ----------------------------------------------

    async def _query_all(
        self, refs: Sequence[PackageRef]
    ) -> tuple[dict[PackageRef, list[dict[str, str]]], list[PackageRef]]:
        summaries: dict[PackageRef, list[dict[str, str]]] = {}
        pending: list[PackageRef] = []

        for ref in refs:
            entry = self._cache.get("osv_query", _query_key(ref))
            if entry is None:
                pending.append(ref)
            else:
                summaries[ref] = entry.payload

        failed: list[PackageRef] = []
        for start in range(0, len(pending), BATCH_LIMIT):
            chunk = pending[start : start + BATCH_LIMIT]
            results = await self._post_batch(chunk)
            if results is None:
                failed.extend(self._fall_back_to_stale(chunk, summaries))
                continue

            # Results are positional. A short array means OSV did not answer for the
            # tail of the batch, and those packages are unchecked — never clean.
            # Padding them with an empty advisory list here would cache "no known
            # vulnerabilities" for a package nobody ever looked up.
            answered = min(len(results), len(chunk))
            for ref, vulns in zip(chunk[:answered], results, strict=False):
                summaries[ref] = vulns
                self._cache.set("osv_query", _query_key(ref), vulns)
            if answered < len(chunk):
                self._warnings.append(
                    f"OSV answered {answered} of {len(chunk)} queries in a batch; "
                    "the rest are reported as unchecked"
                )
                failed.extend(self._fall_back_to_stale(chunk[answered:], summaries))

        self._cache.commit()
        return summaries, failed

    def _fall_back_to_stale(
        self,
        refs: Sequence[PackageRef],
        summaries: dict[PackageRef, list[dict[str, str]]],
    ) -> list[PackageRef]:
        """Use expired cache entries when live data is unavailable.

        Stale data clearly labelled as stale beats no data. Anything with no cache
        entry at all is reported as unchecked rather than assumed clean.
        """
        unchecked: list[PackageRef] = []
        for ref in refs:
            entry = self._cache.get("osv_query", _query_key(ref), allow_stale=True)
            if entry is None:
                unchecked.append(ref)
            else:
                summaries[ref] = entry.payload
                self._stale_used = True
        return unchecked

    async def _post_batch(
        self, refs: Sequence[PackageRef]
    ) -> list[list[dict[str, str]]] | None:
        if self._offline:
            self._warnings.append(
                f"offline: {len(refs)} package(s) had no cached OSV result"
            )
            return None

        payload = {"queries": [_query(ref) for ref in refs]}
        response = await self._request("POST", QUERYBATCH_URL, json=payload)
        if response is None:
            return None

        try:
            data = response.json()
        except ValueError as exc:
            self._warnings.append(f"OSV returned an unreadable batch response: {exc}")
            return None

        results = data.get("results")
        if not isinstance(results, list):
            self._warnings.append("OSV batch response had no results array")
            return None

        out: list[list[dict[str, str]]] = []
        for index, result in enumerate(results):
            vulns = result.get("vulns") if isinstance(result, dict) else None
            out.append(
                [
                    {"id": v["id"], "modified": v.get("modified", "")}
                    for v in (vulns or [])
                    if isinstance(v, dict) and isinstance(v.get("id"), str)
                ]
            )
            # A package with more advisories than one page holds is rare but real;
            # say so rather than quietly reporting a truncated list.
            if isinstance(result, dict) and result.get("next_page_token"):
                name = refs[index].coordinate if index < len(refs) else "a package"
                self._warnings.append(
                    f"{name} has more advisories than one OSV page returns; "
                    "the list shown is incomplete"
                )

        # Never padded and never truncated silently: results are positional, so the
        # caller pairs off what came back and treats any shortfall as unchecked.
        if len(out) > len(refs):
            self._warnings.append(
                "OSV returned more results than queries; the extra entries were "
                "discarded because they cannot be attributed to a package"
            )
            del out[len(refs) :]
        return out

    # -- stage 2: advisory detail ------------------------------------------

    async def _fetch_details(
        self, summaries: dict[PackageRef, list[dict[str, str]]]
    ) -> dict[str, dict[str, Any]]:
        wanted: dict[str, str] = {}
        for entries in summaries.values():
            for entry in entries:
                wanted.setdefault(_detail_key(entry), entry["id"])

        records: dict[str, dict[str, Any]] = {}
        missing: list[tuple[str, str]] = []

        for key, advisory_id in wanted.items():
            cached = self._cache.get("osv_vuln", key)
            if cached is None:
                missing.append((key, advisory_id))
            else:
                records[key] = cached.payload

        if missing:
            fetched = await asyncio.gather(
                *(self._fetch_one(key, vid) for key, vid in missing)
            )
            for key, record in fetched:
                if record is not None:
                    records[key] = record
                    self._cache.set("osv_vuln", key, record)
            self._cache.commit()

        return records

    async def _fetch_one(
        self, key: str, advisory_id: str
    ) -> tuple[str, dict[str, Any] | None]:
        if self._offline:
            entry = self._cache.get("osv_vuln", key, allow_stale=True)
            return key, entry.payload if entry else None

        # The ID is upstream data being interpolated into a request path; quoting it
        # keeps a malformed advisory record from steering the request elsewhere.
        async with self._semaphore:
            response = await self._request(
                "GET", f"{VULN_URL}/{quote(advisory_id, safe='')}"
            )

        if response is None:
            # Losing detail for one advisory does not invalidate the finding — the
            # ID is still reported, just without severity or a fix version.
            self._warnings.append(f"could not fetch details for {advisory_id}")
            return key, None

        try:
            record = response.json()
        except ValueError:
            return key, None
        return key, record if isinstance(record, dict) else None

    # -- transport ---------------------------------------------------------

    async def _request(
        self, method: str, url: str, **kwargs: Any
    ) -> httpx.Response | None:
        """Issue a request with retry and backoff, or ``None`` if it never lands."""
        last_error = ""

        for attempt in range(_MAX_ATTEMPTS):
            # Nothing follows the final attempt, so sleeping after it would only
            # delay the failure the caller is already going to be told about.
            final = attempt == _MAX_ATTEMPTS - 1
            retry_after: str | None = None

            try:
                response = await self._client.request(
                    method, url, timeout=_REQUEST_TIMEOUT, **kwargs
                )
            except httpx.HTTPError as exc:
                last_error = str(exc) or exc.__class__.__name__
            else:
                if response.status_code < 400:
                    return response
                last_error = f"HTTP {response.status_code}"
                if response.status_code not in _RETRY_STATUS:
                    break
                retry_after = response.headers.get("Retry-After")

            if final:
                break
            await self._sleep(attempt, retry_after)

        self._warnings.append(f"{method} {url} failed after retries: {last_error}")
        logger.warning("%s %s failed: %s", method, url, last_error)
        return None

    @staticmethod
    async def _sleep(attempt: int, retry_after: str | None) -> None:
        """Exponential backoff with jitter, honouring Retry-After when OSV sends it.

        Jitter matters because a scan fires many requests at once: without it every
        retry from a rate-limited batch would return in the same instant and be
        rate-limited again.
        """
        if retry_after:
            try:
                await asyncio.sleep(min(float(retry_after), _BACKOFF_CAP))
                return
            except ValueError:
                pass
        delay = min(_BACKOFF_BASE * (2**attempt), _BACKOFF_CAP)
        await asyncio.sleep(delay * (0.5 + random.random() / 2))  # noqa: S311


# ---------------------------------------------------------------------------
# Alias merging
# ---------------------------------------------------------------------------


def merge_aliases(hits: list[VulnHit]) -> list[VulnHit]:
    """Collapse advisories that describe the same vulnerability into one finding.

    OSV carries a separate record per database, so one CVE routinely comes back as
    both a GHSA and a PYSEC entry. Reported verbatim that is one vulnerability listed
    twice — and worse, at two different severities, because the GHSA record usually
    carries a CVSS vector and the PYSEC one usually does not.

    Records are grouped by the transitive closure of their IDs and aliases, then the
    best-informed member of each group represents it, inheriting the others' aliases
    and a fix version if it lacked one.
    """
    if len(hits) < 2:
        return hits

    parent: dict[str, str] = {}

    def find(key: str) -> str:
        parent.setdefault(key, key)
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    def union(a: str, b: str) -> None:
        root_a, root_b = find(a), find(b)
        if root_a != root_b:
            parent[root_b] = root_a

    for hit in hits:
        for alias in hit.advisory.aliases:
            union(hit.advisory.id, alias)

    groups: dict[str, list[VulnHit]] = {}
    for hit in hits:
        groups.setdefault(find(hit.advisory.id), []).append(hit)

    return [_representative(group) for group in groups.values()]


def _informativeness(hit: VulnHit) -> tuple[int, int, int, str]:
    """Rank records so the one carrying the most usable detail wins.

    Severity first: an advisory with a CVSS vector is the reason we can say "high"
    rather than "unknown". The ID breaks ties so the choice is deterministic.
    """
    return (
        1 if hit.advisory.severity is not None else 0,
        1 if hit.fixed_version else 0,
        1 if hit.advisory.summary else 0,
        hit.advisory.id,
    )


def _representative(group: list[VulnHit]) -> VulnHit:
    if len(group) == 1:
        return group[0]

    best = max(group, key=_informativeness)

    aliases = {
        alias
        for hit in group
        for alias in (*hit.advisory.aliases, hit.advisory.id)
        if alias != best.advisory.id
    }
    fixed = best.fixed_version or next(
        (hit.fixed_version for hit in group if hit.fixed_version), None
    )

    return VulnHit(
        advisory=dataclasses.replace(best.advisory, aliases=tuple(sorted(aliases))),
        fixed_version=fixed,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _query(ref: PackageRef) -> dict[str, Any]:
    query: dict[str, Any] = {
        "package": {"name": ref.name, "ecosystem": ref.ecosystem.osv_name}
    }
    # Omitting the version asks OSV for every advisory ever filed against the
    # package, which is the right question when we could not resolve a constraint.
    if ref.version:
        query["version"] = ref.version
    return query


def _query_key(ref: PackageRef) -> str:
    return f"{ref.ecosystem.osv_name}:{ref.name}:{ref.version or '*'}"


def _detail_key(entry: dict[str, str]) -> str:
    """Cache key for advisory detail — exact, because ``modified`` is part of it."""
    return f"{entry['id']}@{entry.get('modified', '')}"


def _skeleton(entry: dict[str, str]) -> Advisory:
    """An advisory built from querybatch data alone, for when detail never arrived.

    Carries only the ID and modified timestamp, so it renders with an unknown
    severity and no fix version — under-informed, but reported. Dropping the hit
    instead would present a package OSV said is affected as if it were clean.
    """
    return Advisory(id=entry["id"], modified=entry.get("modified", ""))


def _advisory(record: dict[str, Any]) -> Advisory:
    references = tuple(
        reference["url"]
        for reference in record.get("references") or []
        if isinstance(reference, dict) and isinstance(reference.get("url"), str)
    )
    return Advisory(
        id=record.get("id", "UNKNOWN"),
        modified=record.get("modified", ""),
        aliases=tuple(a for a in record.get("aliases") or [] if isinstance(a, str)),
        summary=record.get("summary") or "",
        details=record.get("details") or "",
        severity=severity_module.extract(record),
        published=record.get("published"),
        references=references,
    )
