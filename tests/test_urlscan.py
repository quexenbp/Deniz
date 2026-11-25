from __future__ import annotations

import json
from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.urlscan import Urlscan
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def test_parse(tmp_path: Path) -> None:
    payload = {
        "results": [
            {
                "task": {"url": "https://urlscan.io/result/1/"},
                "page": {"url": "https://vpn.example.com/", "ip": "192.0.2.7", "server": "nginx", "domain": "vpn.example.com"},
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))
    items = Urlscan(client).run(Target(type="domain", value="example.com"), ctx)
    assert items[0].value == "https://vpn.example.com/"
    assert items[1].type == "ip" and items[1].attrs["host"] == "vpn.example.com"
