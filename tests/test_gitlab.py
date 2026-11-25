from __future__ import annotations

from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.gitlab import Gitlab
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def test_two_step_parse(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/users"):
            return httpx.Response(200, json=[{"id": 7, "username": "alice"}])
        return httpx.Response(200, json=[{"web_url": "https://gitlab.com/alice/app", "path_with_namespace": "alice/app", "visibility": "public"}])

    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))
    items = Gitlab(client).run(Target(type="username", value="alice"), ctx)
    assert items[0].value == "https://gitlab.com/alice/app"
    assert items[0].attrs["visibility"] == "public"
