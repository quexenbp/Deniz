from __future__ import annotations

from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.discovery import Discovery
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def test_parses_three_files(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /admin\n", headers={"content-type": "text/plain"})
        if path == "/sitemap.xml":
            return httpx.Response(
                200,
                text="<urlset><url><loc>https://cdn.example.com/app</loc></url></urlset>",
                headers={"content-type": "application/xml"},
            )
        if path == "/.well-known/security.txt":
            return httpx.Response(200, text="Contact: mailto:sec@example.com\n", headers={"content-type": "text/plain"})
        return httpx.Response(404)

    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))
    items = Discovery(client).run(Target(type="hostname", value="example.com"), ctx)

    kinds = {i.attrs.get("kind") for i in items if i.type == "url"}
    assert {"robots", "robots_path", "sitemap", "sitemap_url", "security_txt"} <= kinds
    assert any(i.type == "hostname" and i.value == "cdn.example.com" for i in items)
    security = next(i for i in items if i.attrs.get("kind") == "security_txt")
    assert security.attrs["contacts"] == ["mailto:sec@example.com"]
