# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from deniz.kit.cache import Cache
from deniz.kit.errors import RateLimited
from deniz.kit.http import HttpClient, HttpConfig
from deniz.kit.ratelimit import Limiter


def make(tmp_path: Path, handler, **cfg) -> HttpClient:
    cache = Cache(tmp_path / "c.sqlite3")
    return HttpClient(
        cache,
        Limiter(),
        HttpConfig(backoff=0.001, **cfg),
        transport=httpx.MockTransport(handler),
    )


def test_retries_then_succeeds(tmp_path: Path) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(503)
        return httpx.Response(200, text="ok")

    client = make(tmp_path, handler, retries=3)
    resp = client.get("https://example.test/", cache_ttl=0)
    assert resp.status == 200
    assert calls["n"] == 3
    assert client.stats.retries == 2


def test_cache_avoids_second_request(tmp_path: Path) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, text="ok")

    client = make(tmp_path, handler)
    first = client.get("https://example.test/", cache_ttl=60)
    second = client.get("https://example.test/", cache_ttl=60)
    assert calls["n"] == 1
    assert second.from_cache is True
    assert first.content == second.content


def test_rate_limit_raises(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"retry-after": "0"})

    client = make(tmp_path, handler, retries=0)
    with pytest.raises(RateLimited):
        client.get("https://example.test/", cache_ttl=0)


def test_5xx_negative_cached(tmp_path: Path) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503)

    client = make(tmp_path, handler, retries=0)
    assert client.get("https://example.test/", cache_ttl=600).status == 503
    assert client.get("https://example.test/", cache_ttl=600).from_cache is True
    assert calls["n"] == 1


def test_response_text_limit() -> None:
    from deniz.kit.http import Response

    response = Response(status=200, headers={}, content=b"a" * 10, url="u")
    assert response.text == "a" * 10
    assert response.text_limited(3) == "aaa"


def test_401_is_blocked(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    client = make(tmp_path, handler, retries=0)
    from deniz.kit.errors import Blocked

    with pytest.raises(Blocked):
        client.get("https://example.test/", cache_ttl=0)

