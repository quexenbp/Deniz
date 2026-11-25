# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

import time
from pathlib import Path

from deniz.kit.cache import Cache, cache_key


def test_cache_roundtrip(tmp_path: Path) -> None:
    cache = Cache(tmp_path / "c.sqlite3")
    key = cache_key("GET", "https://example.com", {"a": "b"})
    assert cache.get(key) is None
    cache.set(key, 200, {"content-type": "text/plain"}, b"hello", ttl=60)
    hit = cache.get(key)
    assert hit is not None
    assert hit.body == b"hello"
    assert cache.stats()["live"] == 1


def test_cache_expiry(tmp_path: Path) -> None:
    cache = Cache(tmp_path / "c.sqlite3")
    key = cache_key("GET", "https://example.com")
    cache.set(key, 200, {}, b"x", ttl=-1)
    time.sleep(0.01)
    assert cache.get(key) is None
    assert cache.stats()["entries"] == 0

