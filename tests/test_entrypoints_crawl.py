from __future__ import annotations

from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.crawl import Crawl
from deniz.kit.providers.entrypoints import EntryPoints
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler):
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    return client, Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))


def test_entrypoints(tmp_path: Path) -> None:
    html = """
    <form action="/login" method="POST"><input name="user" type="text"><input name="pass" type="password"></form>
    <a href="/search?q=x&page=2">next</a>
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=html, headers={"content-type": "text/html"})

    client, ctx = make(tmp_path, handler)
    items = EntryPoints(client).run(Target(type="hostname", value="example.com"), ctx)
    form = next(i for i in items if i.attrs.get("kind") == "form")
    assert form.value == "https://example.com/login"
    assert form.attrs["method"] == "post"
    params = next(i for i in items if i.attrs.get("record") == "PARAMS")
    assert "q" in params.attrs["params"] and "page" in params.attrs["params"]


def test_crawl_same_origin(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text='<a href="/a">A</a><a href="https://other.test/x">B</a><a href="https://example.com/b">C</a>',
            headers={"content-type": "text/html"},
        )

    client, ctx = make(tmp_path, handler)
    items = Crawl(client).run(Target(type="hostname", value="example.com"), ctx)
    assert {i.value for i in items} == {"https://example.com/a", "https://example.com/b"}


def test_crawl_regex(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, text='<a href="/team">team</a>', headers={"content-type": "text/html"})
        return httpx.Response(200, text="mail ali@example.com and bob@example.com", headers={"content-type": "text/html"})

    client, ctx = make(tmp_path, handler)
    ctx.options["crawl_regex"] = r"[\w.]+@example\.com"
    items = Crawl(client).run(Target(type="hostname", value="example.com"), ctx)
    hits = [i for i in items if i.attrs.get("record") == "regex"]
    assert {hit.value for hit in hits} == {"ali@example.com", "bob@example.com"}
    assert hits[0].sources[0].url == "https://example.com/team"


def test_crawl_bad_regex(tmp_path: Path) -> None:
    import pytest

    from deniz.kit.errors import ParseChanged

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="", headers={"content-type": "text/html"})

    client, ctx = make(tmp_path, handler)
    ctx.options["crawl_regex"] = "("
    with pytest.raises(ParseChanged):
        Crawl(client).run(Target(type="hostname", value="example.com"), ctx)
