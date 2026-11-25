from __future__ import annotations

from pathlib import Path

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers import dnsbrute as mod
from deniz.kit.providers.base import Context
from deniz.kit.providers.dnsbrute import DnsBrute
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def test_resolves_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(mod, "words", lambda: ["vpn", "mail", "missing"])
    monkeypatch.setattr(mod, "resolves", lambda host: ["192.0.2.1"] if host in {"vpn.example.com", "mail.example.com"} else [])
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter())
    ctx = Context(http=client, scope=Scope(allow=["example.com"]), auth=AuthStore(tmp_path / "p.toml"))
    items = DnsBrute(client).run(Target(type="domain", value="example.com"), ctx)
    assert {i.value for i in items} == {"vpn.example.com", "mail.example.com"}
    assert all(i.attrs["brute"] for i in items)
