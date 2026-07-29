"""Shared fixtures.

``MockTransport`` is lifted from johnnydep's test suite. Its important property is
that it returns 404 for anything not explicitly mocked, so a test that accidentally
reaches the network fails loudly instead of quietly hitting the internet and passing
for the wrong reason.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from icebergsca.core import scanner
from icebergsca.core.models import (
    Advisory,
    Dependency,
    EcosystemId,
    PackageRef,
    Pin,
    ScanReport,
    Scope,
    Severity,
    SeverityLevel,
    SourceLocation,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Fixed timestamps so rendered output is byte-identical between runs.
FIXED_START = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
FIXED_END = datetime(2026, 1, 1, 12, 0, 1, tzinfo=UTC)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class MockTransport(httpx.AsyncBaseTransport):
    """Serve canned responses keyed by ``"METHOD:url"``; 404 everything else."""

    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[tuple[str, str]] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        key = f"{request.method}:{request.url}"
        self.calls.append((request.method, str(request.url)))
        if key not in self.responses:
            return httpx.Response(404, json={"error": "not mocked"}, request=request)

        payload = self.responses[key]
        if isinstance(payload, httpx.Response):
            return payload
        return httpx.Response(200, content=json.dumps(payload), request=request)


@pytest.fixture
def null_client() -> httpx.AsyncClient:
    """A client that fails every request — proves a code path stays offline."""
    return httpx.AsyncClient(transport=MockTransport({}))


class _EmptyOSVTransport(httpx.AsyncBaseTransport):
    """Answer OSV querybatch with "no vulnerabilities"; serve anything else from a
    canned ``"METHOD:url"`` map and 404 the rest.

    The canned map is what lets a scanner-level test reach a registry — Maven Central,
    say — without weakening the 404-everything-unmocked guarantee that makes a stray
    request fail loudly instead of silently degrading the result.
    """

    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self.responses = responses or {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/querybatch"):
            body = json.loads(request.content or b'{"queries": []}')
            results = [{"vulns": []} for _ in body.get("queries", [])]
            return httpx.Response(200, json={"results": results}, request=request)

        payload = self.responses.get(f"{request.method}:{request.url}")
        if isinstance(payload, httpx.Response):
            return payload
        if payload is not None:
            return httpx.Response(200, content=json.dumps(payload), request=request)
        return httpx.Response(404, json={"error": "not mocked"}, request=request)


@pytest.fixture
def canned_upstream(
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[[dict[str, Any]], None]:
    """Re-point ``build_http_client`` at a transport that also serves a registry.

    Autouse fixtures are set up before explicitly requested ones, so this reliably
    replaces what ``_no_network`` installed rather than racing it.
    """

    def install(responses: dict[str, Any]) -> None:
        monkeypatch.setattr(
            scanner,
            "build_http_client",
            lambda options: httpx.AsyncClient(transport=_EmptyOSVTransport(responses)),
        )

    return install


@pytest.fixture(autouse=True)
def _no_network(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Keep every test off the network and out of the user's real cache directory.

    Applied automatically. Tests that need specific OSV responses build their own
    ``OSVClient`` with a ``MockTransport``, which this does not interfere with.
    """
    from icebergsca.cache import store
    from icebergsca.core import scanner

    monkeypatch.setattr(
        scanner,
        "build_http_client",
        lambda options: httpx.AsyncClient(transport=_EmptyOSVTransport()),
    )
    cache_dir = tmp_path_factory.mktemp("cache")
    monkeypatch.setattr(store, "cache_path", lambda: cache_dir / "cache.db")


# ---------------------------------------------------------------------------
# Model factories
# ---------------------------------------------------------------------------


def make_dependency(
    name: str = "requests",
    version: str | None = "2.31.0",
    *,
    ecosystem: EcosystemId = EcosystemId.PYPI,
    scope: Scope = Scope.RUNTIME,
    direct: bool = True,
    pin: Pin = Pin.PINNED,
    path: str = "requirements.txt",
    line: int | None = 1,
    constraint: str | None = None,
    exclusions: frozenset[str] = frozenset(),
) -> Dependency:
    return Dependency(
        ref=PackageRef(ecosystem, name, version),
        scope=scope,
        direct=direct,
        source=SourceLocation(Path(path), line),
        pin=pin,
        constraint=constraint,
        exclusions=exclusions,
    )


def make_advisory(
    advisory_id: str = "GHSA-xxxx-yyyy-zzzz",
    *,
    level: SeverityLevel | None = SeverityLevel.HIGH,
    score: float | None = 7.5,
    aliases: tuple[str, ...] = ("CVE-2024-0001",),
    summary: str = "Example vulnerability",
) -> Advisory:
    return Advisory(
        id=advisory_id,
        modified="2026-01-01T00:00:00Z",
        aliases=aliases,
        summary=summary,
        severity=None if level is None else Severity(level, score, "CVSS:3.1/AV:N"),
    )


def make_report(**overrides: Any) -> ScanReport:
    """A minimal report with deterministic timestamps."""
    defaults: dict[str, Any] = {
        "root": Path("/project"),
        "started_at": FIXED_START,
        "finished_at": FIXED_END,
        "tool_version": "0.0.0-test",
    }
    return ScanReport(**{**defaults, **overrides})
