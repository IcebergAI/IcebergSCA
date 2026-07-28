"""SQLite-backed response cache.

One file rather than a directory of JSON blobs: a CI runner may have several scans
in flight at once, and SQLite in WAL mode handles that safely without a lock file or
a directory holding tens of thousands of entries.

Expired entries are kept rather than deleted. When OSV is unreachable, stale data
labelled with its age is far more useful than no data — the report can then say
"this is what we knew four days ago" instead of silently reporting nothing.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from collections.abc import Iterator
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from platformdirs import user_cache_dir

from icebergsca.core.errors import CacheError

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    namespace  TEXT NOT NULL,
    key        TEXT NOT NULL,
    payload    TEXT NOT NULL,
    fetched_at INTEGER NOT NULL,
    PRIMARY KEY (namespace, key)
);
CREATE INDEX IF NOT EXISTS entries_fetched_at ON entries (fetched_at);
"""

#: Namespaces and how long an entry stays fresh.
#:
#: ``osv_vuln`` never expires: advisory detail is keyed by the ``modified`` timestamp
#: that ``querybatch`` returns alongside the ID, so a changed advisory produces a
#: different key. That is exact invalidation rather than a guess, and it is the one
#: place in the cache where a TTL would only ever be wrong.
NAMESPACE_TTL: dict[str, int | None] = {
    "osv_query": 24 * 3600,
    "osv_vuln": None,
    "registry": 24 * 3600,
    "maven_pom": 7 * 24 * 3600,
}


def cache_path() -> Path:
    return Path(user_cache_dir("icebergsca")) / "cache.db"


@dataclass(frozen=True, slots=True)
class CacheEntry:
    payload: Any
    age_seconds: int
    stale: bool


class Cache:
    """A namespaced key/value store with per-namespace freshness.

    Used as a context manager so the connection is always closed::

        with Cache.open() as cache:
            cache.set("osv_query", key, payload)
    """

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        self.hits = 0
        self.misses = 0

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    def open(cls, path: Path | None = None) -> Cache:
        path = path or cache_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(path, timeout=10.0)
            # WAL lets concurrent scans read while one writes, which is the normal
            # case on a CI runner building several projects at once.
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(_SCHEMA)
            connection.commit()
        except (OSError, sqlite3.Error) as exc:
            raise CacheError(f"could not open cache at {path}: {exc}") from exc
        return cls(connection)

    @classmethod
    def memory(cls) -> Cache:
        """An in-memory cache, for ``--no-cache`` and for tests."""
        connection = sqlite3.connect(":memory:")
        connection.executescript(_SCHEMA)
        connection.commit()
        return cls(connection)

    def close(self) -> None:
        with closing(self._connection):
            self._connection.commit()

    def __enter__(self) -> Cache:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- access ------------------------------------------------------------

    def get(
        self, namespace: str, key: str, *, allow_stale: bool = False
    ) -> CacheEntry | None:
        """Return a cached payload, or ``None``.

        A stale entry is withheld unless ``allow_stale`` is set, so the normal path
        refetches while the failure path can still fall back to it.
        """
        row = self._connection.execute(
            "SELECT payload, fetched_at FROM entries WHERE namespace = ? AND key = ?",
            (namespace, key),
        ).fetchone()
        if row is None:
            self.misses += 1
            return None

        payload, fetched_at = row
        age = max(0, int(time.time()) - int(fetched_at))
        ttl = NAMESPACE_TTL.get(namespace)
        stale = ttl is not None and age > ttl

        if stale and not allow_stale:
            self.misses += 1
            return None

        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError:
            logger.debug("discarding corrupt cache entry %s:%s", namespace, key)
            self.misses += 1
            return None

        self.hits += 1
        return CacheEntry(payload=decoded, age_seconds=age, stale=stale)

    def set(self, namespace: str, key: str, payload: Any) -> None:
        try:
            self._connection.execute(
                "INSERT OR REPLACE INTO entries (namespace, key, payload, fetched_at) "
                "VALUES (?, ?, ?, ?)",
                (namespace, key, json.dumps(payload), int(time.time())),
            )
        except sqlite3.Error as exc:
            # A cache that cannot be written is a performance problem, never a
            # correctness one — the scan carries on against the live API.
            logger.warning("could not write cache entry %s:%s: %s", namespace, key, exc)

    def commit(self) -> None:
        self._connection.commit()

    # -- maintenance -------------------------------------------------------

    def stats(self) -> Iterator[tuple[str, int, int]]:
        """Yield ``(namespace, entries, stale)`` for the ``cache info`` command."""
        now = int(time.time())
        rows = self._connection.execute(
            "SELECT namespace, COUNT(*), MIN(fetched_at) FROM entries "
            "GROUP BY namespace"
        ).fetchall()
        for namespace, count, oldest in rows:
            ttl = NAMESPACE_TTL.get(namespace)
            stale = 0
            if ttl is not None:
                stale = self._connection.execute(
                    "SELECT COUNT(*) FROM entries "
                    "WHERE namespace = ? AND fetched_at < ?",
                    (namespace, now - ttl),
                ).fetchone()[0]
            logger.debug("%s: oldest entry %ss", namespace, now - int(oldest or now))
            yield namespace, count, stale

    def prune(self) -> int:
        """Delete expired entries, returning the count. Never touches ``osv_vuln``."""
        now = int(time.time())
        removed = 0
        for namespace, ttl in NAMESPACE_TTL.items():
            if ttl is None:
                continue
            cursor = self._connection.execute(
                "DELETE FROM entries WHERE namespace = ? AND fetched_at < ?",
                (namespace, now - ttl),
            )
            removed += cursor.rowcount
        self._connection.commit()
        return removed

    def clear(self) -> int:
        cursor = self._connection.execute("DELETE FROM entries")
        self._connection.commit()
        return int(cursor.rowcount)
