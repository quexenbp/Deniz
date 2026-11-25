from __future__ import annotations

from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.fingerprint import Fingerprint
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def test_headers_and_tech(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text='<meta name="generator" content="WordPress 6.5">',
            headers={"server": "nginx", "x-powered-by": "PHP/8.3", "content-security-policy": "default-src 'self'"},
        )

    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))
    items = Fingerprint(client).run(Target(type="hostname", value="example.com"), ctx)
    headers = {i.attrs["header"]: i for i in items if i.type == "note"}
    assert headers["content-security-policy"].attrs["present"] is True
    assert headers["strict-transport-security"].attrs["present"] is False
    tech = {i.value for i in items if i.type == "technology"}
    assert "nginx" in tech and "PHP/8.3" in tech and "WordPress 6.5" in tech
