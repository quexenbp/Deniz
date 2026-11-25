# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.errors import Blocked, ParseChanged
from deniz.kit.http import HttpClient, HttpConfig
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.crtsh import Crtsh
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def ctx(tmp_path: Path, scope: Scope | None = None) -> Context:
    cache = Cache(tmp_path / "ctx.sqlite3")
    return Context(
        http=HttpClient(cache, Limiter(), HttpConfig(backoff=0.001)),
        scope=scope or Scope(allow=["example.com"]),
        auth=AuthStore(tmp_path / "providers.toml"),
    )


def provider(tmp_path: Path, handler) -> Crtsh:
    cache = Cache(tmp_path / "prov.sqlite3")
    return Crtsh(HttpClient(cache, Limiter(), HttpConfig(backoff=0.001), transport=httpx.MockTransport(handler)))


def test_json_parse_dedupes_and_filters(tmp_path: Path) -> None:
    payload = [
        {"name_value": "*.api.example.com\nwww.example.com", "not_before": "2026-01-01T00:00:00", "id": 1},
        {"name_value": "www.example.com", "id": 2},
        {"name_value": "unrelated.test", "id": 3},
        {"name_value": "*.example.com", "id": 4},
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    out = provider(tmp_path, handler).run(Target(type="domain", value="example.com"), ctx(tmp_path))
    assert {o.value for o in out} == {"api.example.com", "www.example.com", "example.com"}
    assert all(o.type == "hostname" for o in out)


def test_html_fallback(tmp_path: Path) -> None:
    body = "<html><table><tr><td>a.example.com</td><td>b.example.com</td></tr></table></html>"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=body, headers={"content-type": "text/html"})

    out = provider(tmp_path, handler).run(Target(type="domain", value="example.com"), ctx(tmp_path))
    assert {o.value for o in out} == {"a.example.com", "b.example.com"}


def test_blocked_and_parse_changed(tmp_path: Path) -> None:
    def forbidden(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403)

    def garbage(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not a result", headers={"content-type": "text/plain"})

    with pytest.raises(Blocked):
        provider(tmp_path, forbidden).run(Target(type="domain", value="example.com"), ctx(tmp_path))
    with pytest.raises(ParseChanged):
        provider(tmp_path, garbage).run(Target(type="domain", value="example.com"), ctx(tmp_path))

