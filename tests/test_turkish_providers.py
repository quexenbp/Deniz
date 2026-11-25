from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.errors import ParseChanged
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.kap import Kap
from deniz.kit.providers.uyap import Uyap
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler):
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    return Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))


def test_kap_search(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        body = json.loads(request.content)
        assert body["term"] == "tahsis"
        payload = [{"disclosureIndex": 123, "kapMemberTitle": "ACME A.Ş.", "subject": "Yeni iş ilişkisi", "publishDate": "2026-11-25"}]
        return httpx.Response(200, json=payload)

    ctx = make(tmp_path, handler)
    items = Kap(ctx.http).run(Target(type="keyword", value="tahsis"), ctx)
    assert items[0].value == "https://www.kap.org.tr/tr/bildirim/123"
    assert items[0].attrs["company"] == "ACME A.Ş."
    assert items[0].attrs["subject"] == "Yeni iş ilişkisi"


def test_uyap_search(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["data"]["aranan"] == "tahliye"
        payload = {
            "data": {
                "recordsTotal": 1,
                "data": [{"id": 99, "daire": "İstanbul BAM 1. Hukuk Dairesi", "esasNo": "2024/1", "kararNo": "2025/2", "kararTarihi": "01.02.2025"}],
            }
        }
        return httpx.Response(200, json=payload)

    ctx = make(tmp_path, handler)
    items = Uyap(ctx.http).run(Target(type="keyword", value="tahliye"), ctx)
    assert items[0].value == "https://mevzuat.adalet.gov.tr/ictihat/99"
    assert items[0].attrs["citation"].startswith("İstanbul BAM")


def test_waf_html_is_parse_changed(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>blocked</html>", headers={"content-type": "text/html"})

    ctx = make(tmp_path, handler)
    with pytest.raises(ParseChanged):
        Kap(ctx.http).run(Target(type="keyword", value="xx"), ctx)


def test_uyap_error_metadata(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"metadata": {"FMTY": "ERROR", "FMTE": "boş"}, "data": {}})

    ctx = make(tmp_path, handler)
    with pytest.raises(ParseChanged):
        Uyap(ctx.http).run(Target(type="keyword", value="tahliye"), ctx)
