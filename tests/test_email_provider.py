from __future__ import annotations

import json
from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers import email as email_mod
from deniz.kit.providers.base import Context
from deniz.kit.providers.email import Email
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler, token: str | None = None):
    path = tmp_path / "providers.toml"
    if token:
        path.write_text(f'[email]\ntoken = "{token}"\n', encoding="utf-8")
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    return client, Context(http=client, scope=Scope(), auth=AuthStore(path))


class Answer:
    rrset = True


def test_pattern_fallback(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(email_mod.dns.resolver.Resolver, "resolve", lambda *a, **k: Answer())
    client, ctx = make(tmp_path, lambda request: httpx.Response(404))
    items = Email(client).run(Target(type="domain", value="example.com"), ctx)
    assert {i.value for i in items} >= {"info@example.com", "security@example.com"}
    assert all(i.attrs["guess"] for i in items)


def test_hunter_path(tmp_path: Path) -> None:
    payload = {"data": {"emails": [{"value": "Alice@Example.com", "confidence": 90, "first_name": "Alice"}]}}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    client, ctx = make(tmp_path, handler, token="k")
    items = Email(client).run(Target(type="domain", value="example.com"), ctx)
    assert items[0].value == "alice@example.com"
    assert items[0].confidence == 0.9
    assert items[0].attrs["pattern"] is False
