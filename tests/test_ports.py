# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from pathlib import Path

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers import ports as mod
from deniz.kit.providers.base import Context
from deniz.kit.providers.ports import Ports
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def test_open_ports_dedupe(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(mod, "_addresses", lambda host: ["192.0.2.1", "192.0.2.2"])

    def fake_check(address, port):
        if port in (80, 443):
            return port, "HTTP/1.1 200" if port == 80 else None
        return None

    monkeypatch.setattr(mod, "_check", fake_check)
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter())
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"), max_workers=4)
    items = Ports(client).run(Target(type="hostname", value="example.com"), ctx)
    assert {i.attrs["port"] for i in items} == {80, 443}
    assert len(items) == 2
    assert next(i for i in items if i.attrs["port"] == 443).attrs["tls"] is True

