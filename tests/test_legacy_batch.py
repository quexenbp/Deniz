from __future__ import annotations

import json
from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers import dnsbl as dnsbl_mod
from deniz.kit.providers.ahmia import Ahmia
from deniz.kit.providers.base import Context
from deniz.kit.providers.dnsbl import Dnsbl
from deniz.kit.providers.suggest import Suggest
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler):
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    return client, Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))


def test_suggest_dedupes(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        values = ["owasp", "owasp top 10"] if "google" in host else ["owasp", "owasp testing"]
        return httpx.Response(200, text=json.dumps(["q", values]), headers={"content-type": "application/json"})

    client, ctx = make(tmp_path, handler)
    items = Suggest(client).run(Target(type="keyword", value="owasp"), ctx)
    values = {i.value for i in items}
    assert {"owasp", "owasp top 10", "owasp testing"} <= values
    assert len(items) == 3


class Answer:
    def __init__(self, values):
        self.rrset = bool(values)
        self._values = values

    def __iter__(self):
        return iter(self._values)


def test_dnsbl_listed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(dnsbl_mod, "_resolve", lambda host: ["192.0.2.10"])

    def resolve(self, name, record, **kwargs):
        if name.startswith("10.2.0.192.zen"):
            return Answer(["127.0.0.2"])
        return Answer([])

    monkeypatch.setattr(dnsbl_mod.dns.resolver.Resolver, "resolve", resolve)
    client, ctx = make(tmp_path, lambda request: httpx.Response(200))
    items = Dnsbl(client).run(Target(type="domain", value="example.com"), ctx)
    record = items[0]
    assert record.attrs["clean"] is False
    assert record.attrs["listed"][0]["zone"] == "zen.spamhaus.org"


def test_ahmia_parse(tmp_path: Path) -> None:
    html = '<a href="http://abcdefghijklmnop.onion/page">Market <b>One</b></a>'

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=html, headers={"content-type": "text/html"})

    client, ctx = make(tmp_path, handler)
    items = Ahmia(client).run(Target(type="keyword", value="market"), ctx)
    assert items[0].value == "http://abcdefghijklmnop.onion/page"
    assert items[0].attrs["onion"] is True
    assert "Market" in items[0].attrs["title"]
