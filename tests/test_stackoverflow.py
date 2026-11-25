from __future__ import annotations

import json
from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.stackoverflow import StackOverflow
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def test_parse(tmp_path: Path) -> None:
    payload = {"items": [{"link": "https://stackoverflow.com/q/1", "title": "How?", "score": 10, "is_answered": True, "tags": ["python"]}]}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))
    items = StackOverflow(client).run(Target(type="keyword", value="python"), ctx)
    assert items[0].value == "https://stackoverflow.com/q/1"
    assert items[0].attrs["answered"] is True
