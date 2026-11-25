from __future__ import annotations

from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.sentiment import Sentiment
from deniz.kit.providers.telegram import Telegram
from deniz.kit.providers.wikileaks import WikiLeaks
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler):
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    return client, Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))


def test_telegram(tmp_path: Path) -> None:
    html = '<li class="search-result"><div title="channel"></div><p><a href="https://t.me/osint_channel">OSINT Channel</a></p></li>'

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=html, headers={"content-type": "text/html"})

    client, ctx = make(tmp_path, handler)
    items = Telegram(client).run(Target(type="keyword", value="osint"), ctx)
    assert items[0].value == "https://t.me/osint_channel"
    assert items[0].attrs["kind"] == "channel"
    assert items[0].attrs["handle"] == "osint_channel"


def test_wikileaks(tmp_path: Path) -> None:
    html = '<a href="https://wikileaks.org/plusd/cables/10STATE1.html">Cable one</a><a href="https://wikileaks.org/about.html">About</a>'

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=html, headers={"content-type": "text/html"})

    client, ctx = make(tmp_path, handler)
    items = WikiLeaks(client).run(Target(type="keyword", value="state"), ctx)
    assert [i.value for i in items] == ["https://wikileaks.org/plusd/cables/10STATE1.html"]
    assert items[0].attrs["title"] == "Cable one"


def test_sentiment(tmp_path: Path) -> None:
    client, ctx = make(tmp_path, lambda request: httpx.Response(200))
    good = Sentiment(client).run(Target(type="text", value="I love this, it is excellent"), ctx)
    bad = Sentiment(client).run(Target(type="text", value="Terrible, awful and broken"), ctx)
    assert good[0].attrs["label"] == "positive"
    assert bad[0].attrs["label"] == "negative"
