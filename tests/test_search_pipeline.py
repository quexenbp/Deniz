from __future__ import annotations

from pathlib import Path

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.config import Config
from deniz.kit.http import HttpClient
from deniz.kit.models import Observation, Source
from deniz.kit.pipeline.search import run_search
from deniz.kit.providers.base import ProviderInfo
from deniz.kit.providers.health import HealthStore
from deniz.kit.ratelimit import Limiter


class A:
    info = ProviderInfo(name="a", title="a", capabilities=frozenset({"web"}))

    def __init__(self, http):
        pass

    def run(self, target, ctx):
        return [Observation(type="url", value="https://a.test/x", sources=[Source(provider="a", url="u")], attrs={"title": "A"})]


class B:
    info = ProviderInfo(name="b", title="b", capabilities=frozenset({"web"}))

    def __init__(self, http):
        pass

    def run(self, target, ctx):
        return [Observation(type="url", value="https://b.test/y", sources=[Source(provider="b", url="u")])]


class Registry:
    def select(self, caps):
        return [A, B]


def test_merges_and_dedupes(tmp_path: Path) -> None:
    cache = Cache(tmp_path / "c.sqlite3")
    result = run_search(
        "query",
        config=Config(home=tmp_path).ensure(),
        http=HttpClient(cache, Limiter()),
        cache=cache,
        health=HealthStore(tmp_path / "h.sqlite3"),
        registry=Registry(),  # type: ignore[arg-type]
        auth=AuthStore(tmp_path / "p.toml"),
    )
    assert {i.value for i in result.items} == {"https://a.test/x", "https://b.test/y"}
    assert set(result.stats.providers_used) == {"a", "b"}


def test_filetype_and_site_dork(tmp_path: Path) -> None:
    seen: dict[str, str] = {}

    class C:
        info = ProviderInfo(name="c", title="c", capabilities=frozenset({"web"}))

        def __init__(self, http):
            pass

        def run(self, target, ctx):
            seen["value"] = target.value
            return []

    class R:
        def select(self, caps):
            return [C]

    cache = Cache(tmp_path / "c.sqlite3")
    result = run_search(
        "acme",
        config=Config(home=tmp_path).ensure(),
        http=HttpClient(cache, Limiter()),
        cache=cache,
        health=HealthStore(tmp_path / "h.sqlite3"),
        registry=R(),  # type: ignore[arg-type]
        auth=AuthStore(tmp_path / "p.toml"),
        filetype="pdf",
        site="example.com",
    )
    assert "filetype:pdf" in seen["value"]
    assert "site:example.com" in seen["value"]
    assert result.module == "search.docs"
    assert result.target.value == "acme"
