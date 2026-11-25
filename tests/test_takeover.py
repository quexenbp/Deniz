# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from pathlib import Path

import dns.resolver
import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers import takeover as mod
from deniz.kit.providers.base import Context
from deniz.kit.providers.takeover import Takeover
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


class Rdata:
    def __init__(self, target):
        self.target = target


class Answer:
    def __init__(self, targets=None):
        self.rrset = bool(targets)
        self._targets = targets or []

    def __iter__(self):
        return iter(Rdata(t) for t in self._targets)


def make(tmp_path: Path, handler) -> tuple[Takeover, Context]:
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    return Takeover(client), Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))


def test_marker_match(tmp_path: Path, monkeypatch) -> None:
    def resolve(self, name, record, **kwargs):
        if record == "CNAME":
            return Answer(["site.github.io."])
        return Answer(["1.2.3.4."])

    monkeypatch.setattr(mod.dns.resolver.Resolver, "resolve", resolve)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="There isn't a GitHub Pages site here")

    provider, ctx = make(tmp_path, handler)
    items = provider.run(Target(type="hostname", value="blog.example.com"), ctx)
    assert items[0].attrs["marker_match"] is True
    assert items[0].confidence == 0.9
    assert "github.io" in items[0].value


def test_dangling(tmp_path: Path, monkeypatch) -> None:
    def resolve(self, name, record, **kwargs):
        if record == "CNAME":
            return Answer(["gone.herokuapp.com."])
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(mod.dns.resolver.Resolver, "resolve", resolve)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="oops")

    provider, ctx = make(tmp_path, handler)
    items = provider.run(Target(type="hostname", value="old.example.com"), ctx)
    assert items[0].attrs["dangling"] is True
    assert items[0].confidence == 0.7


def test_no_cname(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(mod.dns.resolver.Resolver, "resolve", lambda *a, **k: Answer([]))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    provider, ctx = make(tmp_path, handler)
    assert provider.run(Target(type="hostname", value="a.example.com"), ctx) == []

