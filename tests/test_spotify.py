from __future__ import annotations

from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.spotify import Spotify
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def test_oauth_and_parse(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "accounts.spotify.com" in str(request.url):
            assert request.headers["authorization"].startswith("Basic ")
            return httpx.Response(200, json={"access_token": "tok"})
        assert request.headers["authorization"] == "Bearer tok"
        return httpx.Response(
            200,
            json={"tracks": {"items": [{"name": "Song", "external_urls": {"spotify": "https://open.spotify.com/track/1"}}]}},
        )

    path = tmp_path / "providers.toml"
    path.write_text('[spotify]\nclient_id = "id"\nclient_secret = "secret"\n', encoding="utf-8")
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(path))
    items = Spotify(client).run(Target(type="keyword", value="song"), ctx)
    assert items[0].value == "https://open.spotify.com/track/1"
    assert items[0].attrs["title"] == "Song"
