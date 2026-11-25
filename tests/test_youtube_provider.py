from __future__ import annotations

from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.youtube import YouTube
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def test_parse(tmp_path: Path) -> None:
    html = '"videoId":"abc12345678" "title":{"runs":[{"text":"OSINT basics"}]} "videoId":"xyz98765432"'

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=html, headers={"content-type": "text/html"})

    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))
    items = YouTube(client).run(Target(type="keyword", value="osint"), ctx)
    assert [i.value for i in items] == [
        "https://www.youtube.com/watch?v=abc12345678",
        "https://www.youtube.com/watch?v=xyz98765432",
    ]
