from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.errors import ParseChanged
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.anubis import Anubis
from deniz.kit.providers.base import Context
from deniz.kit.providers.rapiddns import RapidDns
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler):
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    return client, Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))


def test_rapiddns_table(tmp_path: Path) -> None:
    html = "<table><tr><td>a.example.com</td></tr><tr><td>example.com</td></tr><tr><td>other.test</td></tr></table>"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=html, headers={"content-type": "text/html"})

    client, ctx = make(tmp_path, handler)
    items = RapidDns(client).run(Target(type="domain", value="example.com"), ctx)
    assert {item.value for item in items} == {"a.example.com", "example.com"}


def test_anubis_json(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["a.example.com", "b.example.com", "other.test"])

    client, ctx = make(tmp_path, handler)
    items = Anubis(client).run(Target(type="domain", value="example.com"), ctx)
    assert {item.value for item in items} == {"a.example.com", "b.example.com"}


def test_anubis_bad_json(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>", headers={"content-type": "text/html"})

    client, ctx = make(tmp_path, handler)
    with pytest.raises(ParseChanged):
        Anubis(client).run(Target(type="domain", value="example.com"), ctx)
