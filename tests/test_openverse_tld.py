from __future__ import annotations

import json
from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers import tldbrute as tld_mod
from deniz.kit.providers.base import Context
from deniz.kit.providers.openverse import Openverse
from deniz.kit.providers.tldbrute import TldBrute
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler):
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    return client, Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))


def test_openverse(tmp_path: Path) -> None:
    payload = {"results": [{"url": "https://img.test/a.jpg", "title": "A", "license": "cc0", "source": "flickr"}]}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    client, ctx = make(tmp_path, handler)
    items = Openverse(client).run(Target(type="keyword", value="owasp"), ctx)
    assert items[0].value == "https://img.test/a.jpg"
    assert items[0].attrs["license"] == "cc0"


def test_tldbrute(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(tld_mod, "resolves", lambda host: host in {"acme.io", "acme.dev"})
    client, ctx = make(tmp_path, lambda request: httpx.Response(200))
    items = TldBrute(client).run(Target(type="domain", value="acme.com"), ctx)
    assert {i.value for i in items} == {"acme.io", "acme.dev"}
    assert all(i.attrs["tld_variant"] for i in items)
