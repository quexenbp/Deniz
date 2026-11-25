# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Provider health ledger.

A provider that is blocked or whose parser broke should not silently look
"empty". Health is recorded per call and shown by ``deniz providers``.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

OK = "ok"
FAIL = "fail"
BLOCKED = "blocked"
PARSE = "parse_changed"
RATE = "rate_limited"
HIDE_MIN_SAMPLES = 5
HIDE_BELOW = 0.5


class HealthStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._con = sqlite3.connect(path, check_same_thread=False)
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.execute(
            "CREATE TABLE IF NOT EXISTS provider_health (provider TEXT, ts REAL, kind TEXT)"
        )
        self._con.commit()

    def record(self, provider: str, kind: str) -> None:
        with self._lock:
            self._con.execute("INSERT INTO provider_health VALUES (?,?,?)", (provider, time.time(), kind))
            self._con.commit()

    def window(self, provider: str, days: int = 7) -> dict[str, int]:
        since = time.time() - days * 86400
        with self._lock:
            rows = self._con.execute(
                "SELECT kind, COUNT(*) FROM provider_health WHERE provider=? AND ts>=? GROUP BY kind",
                (provider, since),
            ).fetchall()
        return {kind: int(count) for kind, count in rows}

    def score(self, provider: str, days: int = 7) -> float | None:
        counts = self.window(provider, days)
        total = sum(counts.values())
        if total == 0:
            return None
        return counts.get(OK, 0) / total

    def samples(self, provider: str, days: int = 7) -> int:
        return sum(self.window(provider, days).values())

    def hidden(self, provider: str, days: int = 7) -> bool:
        """True when a provider has enough evidence and is below the threshold."""

        counts = self.window(provider, days)
        total = sum(counts.values())
        if total < HIDE_MIN_SAMPLES:
            return False
        return counts.get(OK, 0) / total < HIDE_BELOW

    def snapshot(self, providers: list[str]) -> dict[str, dict[str, int]]:
        return {name: self.window(name) for name in providers}

