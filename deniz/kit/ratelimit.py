# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Per-host token buckets.

Provider metadata declares requests/second and burst. The limiter keys on
hostname so two providers sharing a host share the budget.
"""

from __future__ import annotations

import threading
import time


class TokenBucket:
    def __init__(self, rate: float, burst: int) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self.rate = rate
        self.burst = max(1, burst)
        self._tokens = float(self.burst)
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> float:
        """Block until tokens are available. Returns seconds waited."""
        waited = 0.0
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.burst, self._tokens + (now - self._updated) * self.rate)
                self._updated = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return waited
                missing = tokens - self._tokens
                delay = missing / self.rate
            time.sleep(min(delay, 1.0))
            waited += delay

    def try_acquire(self, tokens: float = 1.0) -> bool:
        with self._lock:
            now = time.monotonic()
            self._tokens = min(self.burst, self._tokens + (now - self._updated) * self.rate)
            self._updated = now
            if self._tokens < tokens:
                return False
            self._tokens -= tokens
            return True


class Limiter:
    def __init__(self) -> None:
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def bucket(self, host: str, rate: float, burst: int) -> TokenBucket:
        key = host.lower()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(rate, burst)
                self._buckets[key] = bucket
            return bucket

