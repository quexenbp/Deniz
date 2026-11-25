from __future__ import annotations

import json
from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.xsearch import XSearch
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def test_parse(tmp_path: Path) -> None:
    payload = {
        "data": [{"id": "1", "text": "hello", "author_id": "u1", "public_metrics": {"like_count": 2}}],
        "includes": {"users": [{"id": "u1", "username": "alice"}]},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer k"
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    path = tmp_path / "providers.toml"
    path.write_text('[x]\ntoken = "k"\n', encoding="utf-8")
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(path))
    items = XSearch(client).run(Target(type="keyword", value="osint"), ctx)
    assert items[0].value == "https://x.com/alice/status/1"
    assert items[0].attrs["metrics"]["like_count"] == 2
