from __future__ import annotations

from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.files import Files
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def test_only_interesting_paths(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.env":
            return httpx.Response(200, text="SECRET=1")
        if request.url.path == "/admin/":
            return httpx.Response(403)
        return httpx.Response(404)

    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))
    items = Files(client).run(Target(type="hostname", value="example.com"), ctx)
    assert {i.attrs["path"] for i in items} == {"/.env", "/admin/"}
    assert all(i.type == "url" for i in items)
