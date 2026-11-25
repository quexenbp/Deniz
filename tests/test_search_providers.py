from __future__ import annotations

import json
from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient, HttpConfig
from deniz.kit.models import Target
from deniz.kit.providers.arxiv import Arxiv
from deniz.kit.providers.base import Context
from deniz.kit.providers.reddit import Reddit
from deniz.kit.providers.wikipedia import Wikipedia
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler):
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), HttpConfig(backoff=0.001), transport=httpx.MockTransport(handler))
    return Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))


def test_wikipedia(tmp_path: Path) -> None:
    payload = {"query": {"search": [{"title": "OWASP", "snippet": "<span class=\"searchmatch\">web</span> security"}]}}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    ctx = make(tmp_path, handler)
    items = Wikipedia(ctx.http).run(Target(type="keyword", value="owasp"), ctx)
    assert items[0].value == "https://en.wikipedia.org/wiki/OWASP"
    assert "web security" in items[0].attrs["snippet"]


def test_arxiv(tmp_path: Path) -> None:
    xml = """<feed xmlns="http://www.w3.org/2005/Atom"><entry>
    <id>http://arxiv.org/abs/2401.00001v1</id><title>OSINT with LLMs</title>
    <published>2024-01-01T00:00:00Z</published><summary>text</summary></entry></feed>"""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=xml, headers={"content-type": "application/atom+xml"})

    ctx = make(tmp_path, handler)
    items = Arxiv(ctx.http).run(Target(type="keyword", value="osint"), ctx)
    assert items[0].attrs["title"] == "OSINT with LLMs"


def test_reddit(tmp_path: Path) -> None:
    payload = {"data": {"children": [{"data": {"permalink": "/r/osint/comments/x/", "title": "Thread", "subreddit": "osint", "score": 5}}]}}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    ctx = make(tmp_path, handler)
    items = Reddit(ctx.http).run(Target(type="keyword", value="osint"), ctx)
    assert items[0].value == "https://www.reddit.com/r/osint/comments/x/"


def test_reddit_oauth(tmp_path: Path) -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if "access_token" in str(request.url):
            return httpx.Response(200, json={"access_token": "tok"})
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"data": {"children": []}})

    path = tmp_path / "providers.toml"
    path.write_text('[reddit]\nclient_id = "id"\nclient_secret = "secret"\n', encoding="utf-8")
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), HttpConfig(), transport=httpx.MockTransport(handler))
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(path))
    Reddit(client).run(Target(type="keyword", value="osint"), ctx)
    assert seen["auth"] == "Bearer tok"
