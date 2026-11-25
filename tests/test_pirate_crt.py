from __future__ import annotations

import json
from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.crtsearch import CrtSearch
from deniz.kit.providers.piratebay import PirateBay
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler):
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    return client, Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))


def test_piratebay(tmp_path: Path) -> None:
    payload = [{"id": "7", "name": "Ubuntu", "seeders": "10", "leechers": "2", "size": "100", "info_hash": "abc"}]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    client, ctx = make(tmp_path, handler)
    items = PirateBay(client).run(Target(type="keyword", value="ubuntu"), ctx)
    assert items[0].value == "https://thepiratebay.org/description.php?id=7"
    assert items[0].attrs["seeders"] == "10"


def test_crtsearch(tmp_path: Path) -> None:
    payload = [{"id": 9, "name_value": "a.example.com\n*.example.com", "common_name": "example.com", "issuer_name": "CA"}]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    client, ctx = make(tmp_path, handler)
    items = CrtSearch(client).run(Target(type="keyword", value="example.com"), ctx)
    assert items[0].value == "https://crt.sh/?id=9"
    assert "a.example.com" in items[0].attrs["names"]
