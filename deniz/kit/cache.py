# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""SQLite-backed HTTP cache with TTL.

The cache is deliberately boring: content-hash key, status/headers/body,
expiry. It makes runs reproducible and keeps provider load low.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path


def cache_key(method: str, url: str, params: dict[str, str] | None = None, body: bytes | None = None) -> str:
    payload = json.dumps(
        {"m": method.upper(), "u": url, "p": params or {}, "b": (body or b"").hex()},
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True)
class CachedResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    stored_at: float
    sha256: str


class Cache:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._con = sqlite3.connect(path, check_same_thread=False)
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.execute(
            """
            CREATE TABLE IF NOT EXISTS http_cache (
                key TEXT PRIMARY KEY,
                status INTEGER NOT NULL,
                headers TEXT NOT NULL,
                body BLOB NOT NULL,
                stored_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                sha256 TEXT NOT NULL
            )
            """
        )
        self._con.commit()

    def get(self, key: str) -> CachedResponse | None:
        now = time.time()
        with self._lock:
            row = self._con.execute(
                "SELECT status, headers, body, stored_at, expires_at, sha256 FROM http_cache WHERE key=?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        status, headers, body, stored_at, expires_at, digest = row
        if expires_at < now:
            self.delete(key)
            return None
        return CachedResponse(
            status=status,
            headers=json.loads(headers),
            body=bytes(body),
            stored_at=stored_at,
            sha256=digest,
        )

    def set(
        self,
        key: str,
        status: int,
        headers: dict[str, str],
        body: bytes,
        ttl: float,
    ) -> None:
        now = time.time()
        digest = hashlib.sha256(body).hexdigest()
        with self._lock:
            self._con.execute(
                "INSERT OR REPLACE INTO http_cache VALUES (?,?,?,?,?,?,?)",
                (key, status, json.dumps(headers), sqlite3.Binary(body), now, now + ttl, digest),
            )
            self._con.commit()

    def delete(self, key: str) -> None:
        with self._lock:
            self._con.execute("DELETE FROM http_cache WHERE key=?", (key,))
            self._con.commit()

    def clear(self) -> int:
        with self._lock:
            count = self._con.execute("SELECT COUNT(*) FROM http_cache").fetchone()[0]
            self._con.execute("DELETE FROM http_cache")
            self._con.commit()
        return int(count)

    def prune(self) -> int:
        with self._lock:
            count = self._con.execute("SELECT COUNT(*) FROM http_cache WHERE expires_at < ?", (time.time(),)).fetchone()[0]
            self._con.execute("DELETE FROM http_cache WHERE expires_at < ?", (time.time(),))
            self._con.commit()
        return int(count)

    def stats(self) -> dict[str, int]:
        with self._lock:
            total = self._con.execute("SELECT COUNT(*) FROM http_cache").fetchone()[0]
            live = self._con.execute("SELECT COUNT(*) FROM http_cache WHERE expires_at >= ?", (time.time(),)).fetchone()[0]
            size = self._con.execute("SELECT COALESCE(SUM(LENGTH(body)),0) FROM http_cache").fetchone()[0]
        return {"entries": int(total), "live": int(live), "bytes": int(size)}

