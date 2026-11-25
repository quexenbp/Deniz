from __future__ import annotations

from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.darkweb import DarkWeb
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope

SEARCH = '<a href="http://abcdefghijklmnop.onion/page">Market <b>One</b></a>'
PAGE = "<html><head><title>Market One</title></head><body><a href='http://xyz.onion/a'>x</a></body></html>"


def make(tmp_path: Path, handler):
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    return client, Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))


def test_search_only_without_proxy(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("DENIZ_PROXY", raising=False)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=SEARCH, headers={"content-type": "text/html"})

    client, ctx = make(tmp_path, handler)
    items = DarkWeb(client).run(Target(type="keyword", value="market"), ctx)
    assert items[0].attrs["fetched"] is False
    assert items[0].attrs["title"] == "Market One"
    assert items[0].confidence == 0.5


def test_fetch_with_proxy(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DENIZ_PROXY", "socks5h://127.0.0.1:9050")

    def handler(request: httpx.Request) -> httpx.Response:
        if "ahmia.fi" in str(request.url):
            return httpx.Response(200, text=SEARCH, headers={"content-type": "text/html"})
        return httpx.Response(200, text=PAGE, headers={"content-type": "text/html"})

    client, ctx = make(tmp_path, handler)
    items = DarkWeb(client).run(Target(type="keyword", value="market"), ctx)
    assert items[0].attrs["fetched"] is True
    assert items[0].confidence == 0.6
    assert items[0].attrs["page_title"] == "Market One"
    assert "http://xyz.onion/a" in items[0].attrs["links"]


def test_depth_two_adds_child_links(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DENIZ_PROXY", "socks5h://127.0.0.1:9050")

    def handler(request: httpx.Request) -> httpx.Response:
        if "ahmia.fi" in str(request.url):
            return httpx.Response(200, text=SEARCH, headers={"content-type": "text/html"})
        return httpx.Response(200, text=PAGE, headers={"content-type": "text/html"})

    client, ctx = make(tmp_path, handler)
    ctx.options["depth"] = 2
    items = DarkWeb(client).run(Target(type="keyword", value="market"), ctx)
    children = [item for item in items if item.attrs.get("depth") == 2]
    assert children and children[0].value == "http://xyz.onion/a"
    assert children[0].attrs["parent"].endswith("/page")
