from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.rdap import Rdap
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def payload(days: int = 200, status: str = "active") -> dict:
    expires = (datetime.now(UTC) + timedelta(days=days)).isoformat().replace("+00:00", "Z")
    return {
        "status": [status],
        "events": [{"eventAction": "expiration", "eventDate": expires}],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "ACME Registrar"]]]}],
        "nameservers": [{"ldhName": "NS1.ACME.TEST"}],
    }


def run(tmp_path: Path, body: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(body), headers={"content-type": "application/json"})

    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))
    return Rdap(client).run(Target(type="domain", value="acme.test"), ctx)


def test_parse(tmp_path: Path) -> None:
    items = run(tmp_path, payload())
    record = next(i for i in items if i.attrs.get("record") == "RDAP")
    assert record.attrs["registrar"] == "ACME Registrar"
    assert record.attrs["nameservers"] == ["ns1.acme.test"]
    assert any(i.type == "hostname" and i.value == "ns1.acme.test" for i in items)


def test_risky_status_and_expiry(tmp_path: Path) -> None:
    items = run(tmp_path, payload(days=5, status="client hold"))
    record = next(i for i in items if i.attrs.get("record") == "RDAP")
    assert record.attrs["risky_status"] == ["client hold"]
    expiry = next(i for i in items if i.attrs.get("record") == "RDAP_EXPIRY")
    assert expiry.attrs["days"] <= 5
