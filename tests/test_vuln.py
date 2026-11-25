# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

import json
from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.config import Config
from deniz.kit.http import HttpClient, HttpConfig
from deniz.kit.models import Observation, Source
from deniz.kit.pipeline.vuln import run_vuln
from deniz.kit.providers.base import ProviderInfo
from deniz.kit.providers.health import HealthStore
from deniz.kit.ratelimit import Limiter


class FakeNvd:
    info = ProviderInfo(name="nvd", title="nvd", capabilities=frozenset({"vuln"}))

    def __init__(self, http):
        pass

    def run(self, target, ctx):
        return [
            Observation(
                type="cve",
                value=cve,
                confidence=0.9,
                sources=[Source(provider="nvd", url="https://nvd")],
                attrs={"cvss": score},
            )
            for cve, score in (("CVE-2021-1", 5.0), ("CVE-2021-2", 9.8))
        ]


class Registry:
    def get(self, name):
        return FakeNvd


def test_vuln_sorts_and_enriches(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "first.org" in str(request.url):
            payload = {"data": [{"cve": "CVE-2021-2", "epss": 0.9, "percentile": 0.99}]}
            return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})
        return httpx.Response(200, json={})

    cache = Cache(tmp_path / "c.sqlite3")
    result = run_vuln(
        "test",
        config=Config(home=tmp_path).ensure(),
        http=HttpClient(cache, Limiter(), HttpConfig(), transport=httpx.MockTransport(handler)),
        cache=cache,
        health=HealthStore(tmp_path / "s.sqlite3"),
        registry=Registry(),  # type: ignore[arg-type]
        auth=AuthStore(tmp_path / "providers.toml"),
    )
    assert [item.value for item in result.items] == ["CVE-2021-2", "CVE-2021-1"]
    assert result.items[0].attrs["epss"] == 0.9

