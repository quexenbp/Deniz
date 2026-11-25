# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient, HttpConfig
from deniz.kit.models import Target
from deniz.kit.providers import username as username_mod
from deniz.kit.providers.base import Context
from deniz.kit.providers.username import Username
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler) -> tuple[Username, Context]:
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), HttpConfig(), transport=httpx.MockTransport(handler))
    return Username(client), Context(
        http=client, scope=Scope(), auth=AuthStore(tmp_path / "providers.toml"), max_workers=4
    )


def test_found_and_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        username_mod,
        "_load",
        lambda: {
            "Good": {"status": "404", "error": ["not found"], "url": "https://good.test/{}", "rank": "1"},
            "Bad": {"status": "404", "error": ["not found"], "url": "https://bad.test/{}", "rank": "2"},
        },
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if "good.test" in str(request.url):
            return httpx.Response(200, text="profile")
        return httpx.Response(404, text="not found")

    provider, ctx = make(tmp_path, handler)
    items = provider.run(Target(type="username", value="alice"), ctx)
    assert [i.value for i in items] == ["https://good.test/alice"]

