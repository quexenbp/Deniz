from __future__ import annotations

from pathlib import Path

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers import asn as mod
from deniz.kit.providers.asn import Asn
from deniz.kit.providers.base import Context
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def test_query_name() -> None:
    assert mod._query_name("192.0.2.10") == "10.2.0.192.origin.asn.cymru.com"
    assert mod._query_name("2001:db8::1").endswith(".origin6.asn.cymru.com")


def test_parse_asn(tmp_path: Path, monkeypatch) -> None:
    def fake_txt(resolver, name):
        if name.startswith("10.2.0.192"):
            return ["13335 | 192.0.2.0/24 | US | arin | 2020-01-01"]
        if name.startswith("AS13335"):
            return ["13335 | US | arin | 2020-01-01 | CLOUDFLARENET"]
        return []

    monkeypatch.setattr(mod, "_txt", fake_txt)
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter())
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))
    items = Asn(client).run(Target(type="ip", value="192.0.2.10"), ctx)
    record = items[0]
    assert record.type == "asn"
    assert record.value == "AS13335"
    assert record.attrs["prefix"] == "192.0.2.0/24"
    assert record.attrs["as_name"] == "CLOUDFLARENET"
