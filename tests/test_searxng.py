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
from deniz.kit.providers.searxng import Searx
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler, url: str | None = "https://searx.example") -> tuple[Searx, Context]:
    path = tmp_path / "providers.toml"
    if url:
        path.write_text(f'[searxng]\nurl = "{url}"\n', encoding="utf-8")
    auth = AuthStore(path)
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), HttpConfig(backoff=0.001), transport=httpx.MockTransport(handler))
    return Searx(client), Context(http=client, scope=Scope(allow=["example.com"]), auth=auth)


def test_requires_url(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    provider, ctx = make(tmp_path, handler, url=None)
    with pytest.raises(AuthRequired):
        provider.run(Target(type="domain", value="example.com"), ctx)


def test_filters_results(tmp_path: Path) -> None:
    payload = {
        "results": [
            {"url": "https://a.example.com/x", "title": "A"},
            {"url": "https://a.example.com/y", "title": "dup"},
            {"url": "https://other.test/", "title": "out"},
            {"url": "https://b.example.com/", "title": "B"},
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    provider, ctx = make(tmp_path, handler)
    out = provider.run(Target(type="domain", value="example.com"), ctx)
    assert {o.value for o in out} == {"a.example.com", "b.example.com"}

