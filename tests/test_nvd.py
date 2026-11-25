# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

import json
from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient, HttpConfig
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.nvd import Nvd
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope

PAYLOAD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [{"lang": "en", "value": "Log4Shell"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
                "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}],
                "published": "2021-12-10T00:00:00",
                "lastModified": "2021-12-10T00:00:00",
                "vulnStatus": "Analyzed",
            }
        }
    ]
}


def test_nvd_parses_and_sends_key(tmp_path: Path) -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["key"] = request.headers.get("apikey")
        return httpx.Response(200, text=json.dumps(PAYLOAD), headers={"content-type": "application/json"})

    path = tmp_path / "providers.toml"
    path.write_text('[nvd]\ntoken = "secret"\n', encoding="utf-8")
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), HttpConfig(), transport=httpx.MockTransport(handler))
    provider = Nvd(client)
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(path))
    items = provider.run(Target(type="keyword", value="log4j"), ctx)
    assert seen["key"] == "secret"
    assert items[0].value == "CVE-2021-44228"
    assert items[0].attrs["cvss"] == 10.0
    assert items[0].attrs["severity"] == "CRITICAL"

