from __future__ import annotations

import json
from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.wayback import Wayback
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def test_parse(tmp_path: Path) -> None:
    payload = [["original", "timestamp", "statuscode"], ["https://a.example.com/x", "20200101000000", "200"]]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))
    items = Wayback(client).run(Target(type="domain", value="example.com"), ctx)
    assert items[0].value == "https://a.example.com/x"
    assert any(i.type == "hostname" and i.value == "a.example.com" for i in items)
