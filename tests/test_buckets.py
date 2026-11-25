# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient, HttpConfig
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.buckets import Bucket, candidates
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def test_candidates() -> None:
    names = candidates("example.com")
    assert "example" in names
    assert "example-dev" in names
    assert len(names) == len(set(names))


def test_existence_and_public_flag(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "s3.amazonaws.com" in url:
            return httpx.Response(200, text="<ListBucketResult>")
        if "storage.googleapis.com" in url:
            return httpx.Response(403)
        return httpx.Response(404)

    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), HttpConfig(), transport=httpx.MockTransport(handler))
    provider = Bucket(client)
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"), max_workers=4)
    items = provider.run(Target(type="domain", value="example.com"), ctx)
    public = [i for i in items if i.attrs["public_listing"]]
    private = [i for i in items if i.attrs["cloud"] == "gcs"]
    assert public and public[0].value.startswith("s3://")
    assert private and private[0].attrs["status"] == 403

