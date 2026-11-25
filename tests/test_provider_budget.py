from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from deniz.kit.cache import Cache
from deniz.kit.errors import BudgetExceeded
from deniz.kit.http import HttpClient, ProviderHttp
from deniz.kit.ratelimit import Limiter


def client(tmp_path: Path, size: int = 400) -> HttpClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="a" * size)

    return HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))


def test_request_cap_is_applied(tmp_path: Path) -> None:
    view = ProviderHttp(client=client(tmp_path), provider="p", defaults={"max_bytes": 100})
    assert len(view.get("https://a.test/").content) == 100


def test_explicit_cap_wins(tmp_path: Path) -> None:
    view = ProviderHttp(client=client(tmp_path), provider="p", defaults={"max_bytes": 100})
    assert len(view.get("https://a.test/?x=1", max_bytes=250).content) == 250


def test_budget_stops_further_requests(tmp_path: Path) -> None:
    view = ProviderHttp(client=client(tmp_path), provider="p", budget=500)
    view.get("https://a.test/")
    view.get("https://a.test/?page=2")
    assert view.used_bytes == 800
    with pytest.raises(BudgetExceeded):
        view.get("https://a.test/?page=3")


def test_no_budget_means_unlimited(tmp_path: Path) -> None:
    view = ProviderHttp(client=client(tmp_path), provider="p")
    for page in range(5):
        view.get(f"https://a.test/?p={page}")
    assert view.used_bytes == 2000
