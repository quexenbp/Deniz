# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from pathlib import Path

import pytest

from deniz.kit.cache import Cache
from deniz.kit.errors import CacheMiss
from deniz.kit.http import HttpClient, HttpConfig
from deniz.kit.ratelimit import Limiter


def test_offline_miss_and_hit(tmp_path: Path) -> None:
    cache = Cache(tmp_path / "c.sqlite3")
    client = HttpClient(cache, Limiter(), HttpConfig(offline=True))
    with pytest.raises(CacheMiss):
        client.get("https://example.test/", cache_ttl=60)
    cache.set("irrelevant", 200, {}, b"", 60)
    key = __import__("deniz.kit.cache", fromlist=["cache_key"]).cache_key("GET", "https://example.test/", {})
    cache.set(key, 200, {}, b"ok", 60)
    assert client.get("https://example.test/", cache_ttl=60).content == b"ok"

