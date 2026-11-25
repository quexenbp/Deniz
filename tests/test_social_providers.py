from __future__ import annotations

import json
from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.hackernews import HackerNews
from deniz.kit.providers.lemmy import Lemmy
from deniz.kit.providers.mastodon import Mastodon
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler, config: str | None = None):
    path = tmp_path / "providers.toml"
    if config:
        path.write_text(config, encoding="utf-8")
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    return client, Context(http=client, scope=Scope(), auth=AuthStore(path))


def test_hackernews(tmp_path: Path) -> None:
    payload = {
        "hits": [
            {"objectID": "1", "title": "OSINT post", "url": "https://blog.test/osint", "author": "alice", "points": 42},
            {"objectID": "2", "story_title": "Ask HN", "author": "bob"},
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    client, ctx = make(tmp_path, handler)
    items = HackerNews(client).run(Target(type="keyword", value="osint"), ctx)
    assert items[0].value == "https://blog.test/osint"
    assert items[0].attrs["points"] == 42
    assert items[1].value == "https://news.ycombinator.com/item?id=2"


def test_lemmy(tmp_path: Path) -> None:
    payload = {
        "posts": [
            {
                "post": {"id": 7, "name": "Federated post", "url": "https://example.test/post", "score": 5},
                "community": {"name": "osint"},
                "creator": {"name": "carol"},
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    client, ctx = make(tmp_path, handler)
    items = Lemmy(client).run(Target(type="keyword", value="osint"), ctx)
    assert items[0].value == "https://example.test/post"
    assert items[0].attrs["community"] == "osint"


def test_mastodon_hashtag(tmp_path: Path) -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        payload = [
            {
                "url": "https://mastodon.social/@alice/1",
                "account": {"acct": "alice", "url": "https://mastodon.social/@alice"},
                "content": "<p>Hello <b>OSINT</b></p>",
                "reblogs_count": 2,
            }
        ]
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    client, ctx = make(tmp_path, handler, config='[mastodon]\nurl = "https://social.test"\n')
    items = Mastodon(client).run(Target(type="keyword", value="#OSINT"), ctx)
    assert seen["url"].startswith("https://social.test/api/v1/timelines/tag/osint")
    assert items[0].value == "https://mastodon.social/@alice/1"
    assert items[0].attrs["author"] == "alice"
    assert "OSINT" in items[0].attrs["content"]
