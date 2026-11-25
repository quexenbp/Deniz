# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.errors import AuthRequired
from deniz.kit.http import HttpClient, HttpConfig
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.hibp import Hibp
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler, key: str | None = "k") -> tuple[Hibp, Context]:
    path = tmp_path / "providers.toml"
    if key:
        path.write_text(f'[hibp]\ntoken = "{key}"\n', encoding="utf-8")
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), HttpConfig(), transport=httpx.MockTransport(handler))
    return Hibp(client), Context(http=client, scope=Scope(), auth=AuthStore(path))


def test_requires_key(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    provider, ctx = make(tmp_path, handler, key=None)
    with pytest.raises(AuthRequired):
        provider.run(Target(type="email", value="a@example.com"), ctx)


def test_breach_parse_and_404(tmp_path: Path) -> None:
    payload = [
        {
            "Name": "ExampleBreach",
            "Title": "Example",
            "Domain": "example.com",
            "BreachDate": "2020-01-01",
            "DataClasses": ["Emails", "Passwords"],
            "Description": "<b>desc</b>",
            "IsVerified": True,
        }
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        if "missing" in str(request.url):
            return httpx.Response(404)
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    provider, ctx = make(tmp_path, handler)
    items = provider.run(Target(type="email", value="a@example.com"), ctx)
    assert items[0].type == "breach"
    assert items[0].attrs["description"] == "desc"
    assert provider.run(Target(type="email", value="missing@example.com"), ctx) == []

