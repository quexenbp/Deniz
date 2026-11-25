from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers import axfr as mod
from deniz.kit.providers.axfr import Axfr
from deniz.kit.providers.base import Context
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


class Name:
    def __init__(self, text):
        self.text = text

    def to_text(self):
        return self.text


class Answer:
    rrset = True

    def __iter__(self):
        return iter([type("R", (), {"target": "ns1.example.com."})()])


class Zone:
    nodes: ClassVar = {Name("vpn"): None, Name("mail"): None, Name("@"): None}


def test_transfer(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(mod.dns.resolver.Resolver, "resolve", lambda *a, **k: Answer())
    monkeypatch.setattr(mod.dns.query, "xfr", lambda *a, **k: object())
    monkeypatch.setattr(mod.dns.zone, "from_xfr", lambda *a, **k: Zone())
    monkeypatch.setattr(mod.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("192.0.2.53", 53))])

    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter())
    ctx = Context(http=client, scope=Scope(allow=["example.com"]), auth=AuthStore(tmp_path / "p.toml"))
    items = Axfr(client).run(Target(type="domain", value="example.com"), ctx)
    assert {i.value for i in items} == {"vpn.example.com", "mail.example.com"}
    assert all(i.attrs["axfr"] for i in items)
