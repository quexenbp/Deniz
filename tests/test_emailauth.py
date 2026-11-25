# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from pathlib import Path

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers import emailauth as mod
from deniz.kit.providers.base import Context
from deniz.kit.providers.emailauth import EmailAuth
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


class Mx:
    rrset = True

    class record:
        preference = 10
        exchange = "mx.example.com."

        def __str__(self):
            return self.exchange

    def __iter__(self):
        return iter([self.record()])


def test_policy_notes(tmp_path: Path, monkeypatch) -> None:
    def fake_txt(resolver, name):
        if name == "example.com":
            return ["v=spf1 include:_spf.example.com -all"]
        if name == "_dmarc.example.com":
            return ["v=DMARC1; p=reject; rua=mailto:d@example.com"]
        if name.startswith("default._domainkey"):
            return ["v=DKIM1; k=rsa; p=abc"]
        return []

    monkeypatch.setattr(mod, "_txt", fake_txt)
    monkeypatch.setattr(mod.dns.resolver.Resolver, "resolve", lambda self, *a, **k: Mx())

    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter())
    provider = EmailAuth(client)
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))
    items = provider.run(Target(type="domain", value="example.com"), ctx)
    by_record = {i.attrs.get("record"): i for i in items}
    assert by_record["SPF"].attrs["strict"] is True
    assert by_record["DMARC"].attrs["enforcing"] is True
    assert by_record["DKIM"].attrs["selectors"] == ["default"]
    assert any(i.type == "hostname" and i.attrs.get("mx") for i in items)

