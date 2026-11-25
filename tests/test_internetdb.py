from __future__ import annotations

import json
from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.internetdb import InternetDb
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def test_parse(tmp_path: Path) -> None:
    payload = {"ports": [443, 8443], "hostnames": ["vpn.example.com"], "cpes": ["cpe:/a:nginx"], "tags": ["vpn"], "vulns": ["CVE-2023-1"]}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))
    items = InternetDb(client).run(Target(type="ip", value="192.0.2.9"), ctx)
    kinds = {i.type for i in items}
    assert {"service", "hostname", "technology", "note"} <= kinds
    note = next(i for i in items if i.attrs.get("record") == "INTERNETDB")
    assert note.attrs["vulns"] == ["CVE-2023-1"]
