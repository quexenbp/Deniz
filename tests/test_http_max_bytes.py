from __future__ import annotations

from pathlib import Path

import httpx

from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.ratelimit import Limiter


def test_max_bytes_truncates(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="a" * 5000, headers={"content-type": "text/plain"})

    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    response = client.get("https://example.test/", max_bytes=1000)
    assert response.status == 200
    assert len(response.content) == 1000


def test_config_default_limit(tmp_path: Path, monkeypatch) -> None:
    from deniz.kit.http import HttpConfig

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="b" * 5000)

    client = HttpClient(
        Cache(tmp_path / "c.sqlite3"), Limiter(), HttpConfig(max_bytes=200), transport=httpx.MockTransport(handler)
    )
    assert len(client.get("https://example.test/").content) == 200


def test_limits_use_separate_cache_entries(tmp_path: Path) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, text="c" * 5000)

    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    assert len(client.get("https://example.test/", max_bytes=100).content) == 100
    assert len(client.get("https://example.test/", max_bytes=200).content) == 200
    assert calls["n"] == 2
    assert len(client.get("https://example.test/").content) == 5000
    assert calls["n"] == 3
