"""Fetching the list of published versions for a package.

Used only when a project has no lockfile and a constraint has to be resolved. One
request per package, cached for a day, answering exactly one question: which versions
exist? Nothing here fetches package metadata, download counts or maintainer lists —
that is not what this tool is for.

Every package name is validated against an ecosystem-specific allowlist before it is
interpolated into a URL. Names come from files inside a scanned repository, which is
untrusted input; a name like ``../../admin`` must never become a request path.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any
from urllib.parse import quote

import httpx

from icebergsca.cache import Cache
from icebergsca.core.models import EcosystemId

logger = logging.getLogger(__name__)

_TIMEOUT = 15.0

#: Name patterns each registry actually permits. Anything else is refused rather
#: than escaped, because a name that cannot be legal is not worth a request.
_VALID_NAME: dict[EcosystemId, re.Pattern[str]] = {
    EcosystemId.PYPI: re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$"),
    EcosystemId.NPM: re.compile(
        r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$", re.IGNORECASE
    ),
    EcosystemId.CARGO: re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$"),
    EcosystemId.NUGET: re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    EcosystemId.RUBYGEMS: re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    EcosystemId.GO: re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~/-]*$"),
    EcosystemId.MAVEN: re.compile(
        r"^[A-Za-z0-9][A-Za-z0-9._-]*:[A-Za-z0-9][A-Za-z0-9._-]*$"
    ),
}


def _go_escape(module: str) -> str:
    """Escape a Go module path for the proxy.

    The proxy is case-insensitive on some filesystems, so uppercase letters are
    encoded as ``!`` followed by the lowercase letter — ``github.com/BurntSushi/toml``
    becomes ``github.com/!burnt!sushi/toml``.
    """
    return "".join(f"!{char.lower()}" if char.isupper() else char for char in module)


def version_list_url(ecosystem: EcosystemId, name: str) -> str | None:
    """The URL listing every published version, or ``None`` if unsupported."""
    if ecosystem is EcosystemId.PYPI:
        return f"https://pypi.org/simple/{quote(name, safe='')}/"
    if ecosystem is EcosystemId.NPM:
        # The scope separator stays literal. That is safe only because the name has
        # already been matched against a pattern permitting at most one slash, with
        # each segment required to start alphanumerically — so no traversal is possible.
        return f"https://registry.npmjs.org/{quote(name, safe='@/')}"
    if ecosystem is EcosystemId.CARGO:
        return f"https://crates.io/api/v1/crates/{quote(name, safe='')}/versions"
    if ecosystem is EcosystemId.NUGET:
        lower = quote(name.lower(), safe="")
        return f"https://api.nuget.org/v3-flatcontainer/{lower}/index.json"
    if ecosystem is EcosystemId.RUBYGEMS:
        return f"https://rubygems.org/api/v1/versions/{quote(name, safe='')}.json"
    if ecosystem is EcosystemId.GO:
        return f"https://proxy.golang.org/{_go_escape(name)}/@v/list"
    return None


#: Registries that need a specific Accept header to return the compact form.
_ACCEPT: dict[EcosystemId, str] = {
    EcosystemId.PYPI: "application/vnd.pypi.simple.v1+json",
    EcosystemId.NPM: "application/vnd.npm.install-v1+json",
}


class RegistryClient:
    """Returns published version lists, cached on disk for a day."""

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
        self.warnings: list[str] = []

    async def versions(self, ecosystem: EcosystemId, name: str) -> list[str] | None:
        """Every published version, newest last. ``None`` if it could not be fetched.

        ``None`` and ``[]`` mean different things: the first is "we do not know",
        the second is "this package has no releases". Only the second is safe to
        treat as a resolution failure rather than a scan gap.
        """
        pattern = _VALID_NAME.get(ecosystem)
        if pattern is None or not pattern.match(name):
            logger.debug("refusing to query %s for invalid name %r", ecosystem, name)
            return None

        key = f"{ecosystem.value}:{name}"
        cached = self._cache.get("registry", key)
        if cached is not None:
            return list(cached.payload)

        if self._offline:
            stale = self._cache.get("registry", key, allow_stale=True)
            return list(stale.payload) if stale else None

        url = version_list_url(ecosystem, name)
        if url is None:
            return None

        async with self._semaphore:
            payload = await self._fetch(url, ecosystem)

        if payload is None:
            return None

        versions = _extract(ecosystem, payload)
        self._cache.set("registry", key, versions)
        self._cache.commit()
        return versions

    async def _fetch(self, url: str, ecosystem: EcosystemId) -> Any | None:
        headers = {}
        accept = _ACCEPT.get(ecosystem)
        if accept:
            headers["Accept"] = accept

        try:
            response = await self._client.get(url, headers=headers, timeout=_TIMEOUT)
        except httpx.HTTPError as exc:
            self.warnings.append(f"registry request failed: {url}: {exc}")
            return None

        if response.status_code == 404:
            # A package that does not exist is a finding about the manifest, not a
            # transport failure, so it is reported quietly rather than as an error.
            logger.debug("registry 404 for %s", url)
            return None
        if response.status_code >= 400:
            self.warnings.append(
                f"registry returned HTTP {response.status_code} for {url}"
            )
            return None

        if ecosystem is EcosystemId.GO:
            return response.text
        try:
            return response.json()
        except (ValueError, json.JSONDecodeError):
            self.warnings.append(f"registry returned unreadable JSON for {url}")
            return None


def _extract(ecosystem: EcosystemId, payload: Any) -> list[str]:
    """Pull the version strings out of each registry's own response shape."""
    if ecosystem is EcosystemId.GO:
        return [line.strip() for line in str(payload).splitlines() if line.strip()]

    if ecosystem is EcosystemId.PYPI:
        versions = payload.get("versions") if isinstance(payload, dict) else None
        return [v for v in versions or [] if isinstance(v, str)]

    if ecosystem is EcosystemId.NPM:
        versions = payload.get("versions") if isinstance(payload, dict) else None
        return list(versions) if isinstance(versions, dict) else []

    if ecosystem is EcosystemId.CARGO:
        entries = payload.get("versions") if isinstance(payload, dict) else None
        return [
            entry["num"]
            for entry in entries or []
            # A yanked release is still installable by exact version but is never
            # what a fresh resolve would choose.
            if isinstance(entry, dict)
            and isinstance(entry.get("num"), str)
            and not entry.get("yanked")
        ]

    if ecosystem is EcosystemId.NUGET:
        versions = payload.get("versions") if isinstance(payload, dict) else None
        return [v for v in versions or [] if isinstance(v, str)]

    if ecosystem is EcosystemId.RUBYGEMS:
        return [
            entry["number"]
            for entry in payload or []
            if isinstance(entry, dict) and isinstance(entry.get("number"), str)
        ]

    return []
