from __future__ import annotations

import json
from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.openalex import OpenAlex
from deniz.kit.providers.photon import Photon
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler):
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    return Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))


def test_openalex(tmp_path: Path) -> None:
    payload = {"results": [{"doi": "https://doi.org/10.1/x", "id": "https://openalex.org/W1", "title": "Paper", "publication_year": 2024}]}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    ctx = make(tmp_path, handler)
    items = OpenAlex(ctx.http).run(Target(type="keyword", value="osint"), ctx)
    assert items[0].value == "https://doi.org/10.1/x"
    assert items[0].attrs["year"] == 2024


def test_photon(tmp_path: Path) -> None:
    payload = {"features": [{"properties": {"name": "Cafe", "city": "Berlin", "osm_id": 1}, "geometry": {"coordinates": [13.4, 52.5]}}]}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    ctx = make(tmp_path, handler)
    items = Photon(ctx.http).run(Target(type="keyword", value="cafe berlin"), ctx)
    assert items[0].attrs["lat"] == 52.5
    assert "Cafe" in items[0].value
