# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.errors import TimeoutError_
from deniz.kit.http import HttpClient, HttpConfig
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.http_probe import HttpProbe
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler) -> tuple[HttpProbe, Context]:
    client = HttpClient(
        Cache(tmp_path / "c.sqlite3"),
        Limiter(),
        HttpConfig(backoff=0.001, retries=0),
        transport=httpx.MockTransport(handler),
    )
    return HttpProbe(client), Context(
        http=client, scope=Scope(allow=["example.com"]), auth=AuthStore(tmp_path / "providers.toml")
    )


def test_probe_captures_title_and_status(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html><title>Hi</title></html>", headers={"server": "test"})

    probe, ctx = make(tmp_path, handler)
    items = probe.run(Target(type="hostname", value="example.com"), ctx)
    url = next(i for i in items if i.type == "url")
    assert url.attrs["status"] == 200
    assert url.attrs["server"] == "test"
    assert any(i.type == "title" and i.value == "Hi" for i in items)


def test_probe_dead_host_raises(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("nope", request=request)

    probe, ctx = make(tmp_path, handler)
    with pytest.raises(TimeoutError_):
        probe.run(Target(type="hostname", value="example.com"), ctx)

