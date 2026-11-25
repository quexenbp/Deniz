# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from pathlib import Path

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.config import Config
from deniz.kit.http import HttpClient
from deniz.kit.models import Observation, Source
from deniz.kit.pipeline.domain import run_domain, validate_domain
from deniz.kit.providers.base import ProviderInfo
from deniz.kit.providers.health import HealthStore
from deniz.kit.ratelimit import Limiter


class Ct:
    info = ProviderInfo(name="crtsh", title="ct", capabilities=frozenset({"subdomains"}))

    def __init__(self, http):
        pass

    def run(self, target, ctx):
        return [
            Observation(
                type="hostname",
                value=v,
                confidence=0.8,
                sources=[Source(provider="crtsh", url="https://ct")],
            )
            for v in ("a.example.com", "b.example.com", "evil.test")
        ]


class Dns:
    info = ProviderInfo(name="dns", title="dns", capabilities=frozenset({"dns"}))

    def __init__(self, http):
        pass

    def run(self, target, ctx):
        if target.value == "a.example.com":
            return [Observation(type="ip", value="192.0.2.1", sources=[Source(provider="dns", url="dns://a")])]
        return []


class Http:
    info = ProviderInfo(name="http", title="http", capabilities=frozenset({"http"}))

    def __init__(self, http):
        pass

    def run(self, target, ctx):
        return [
            Observation(
                type="url",
                value=f"https://{target.value}/",
                sources=[Source(provider="http", url=f"https://{target.value}/")],
                attrs={"status": 200},
            )
        ]


class Registry:
    def get(self, name):
        return {"crtsh": Ct, "dns": Dns, "http": Http}[name]


class CtDead:
    info = ProviderInfo(name="crtsh", title="ct", capabilities=frozenset({"subdomains"}))

    def __init__(self, http):
        pass

    def run(self, target, ctx):
        from deniz.kit.errors import ProviderDead

        raise ProviderDead("down")


class CtFallback(Ct):
    info = ProviderInfo(name="certspotter", title="ct2", capabilities=frozenset({"subdomains"}))


class RegistryFallback(Registry):
    def get(self, name):
        return {"crtsh": CtDead, "certspotter": CtFallback, "dns": Dns, "http": Http}[name]


def test_validate_domain() -> None:
    assert validate_domain("https://Example.com/path") == "example.com"


def test_pipeline_filters_and_probes(tmp_path: Path) -> None:
    config = Config(home=tmp_path).ensure()
    cache = Cache(tmp_path / "c.sqlite3")
    result = run_domain(
        "example.com",
        config=config,
        http=HttpClient(cache, Limiter()),
        cache=cache,
        health=HealthStore(tmp_path / "s.sqlite3"),
        registry=Registry(),  # type: ignore[arg-type]
        auth=AuthStore(tmp_path / 'providers.toml'),
        typosquat=False,
        emailauth=False,
        rdap=False,
        asn=False,
        dnsbl=False,
        entrypoints=False,
        discovery=False,
        urlscan=False,
        internetdb=False,
        wayback=False,
        takeover=False,
        fingerprint=False,
        max_workers=2,
    )
    hosts = {i.value for i in result.items if i.type == "hostname"}
    assert "evil.test" not in hosts
    assert {"example.com", "a.example.com", "b.example.com"} <= hosts
    live = [i for i in result.items if i.type == "url"]
    assert [i.value for i in live] == ["https://a.example.com/"]
    assert result.stats.requests >= 0


def test_pipeline_falls_back_when_first_provider_dies(tmp_path: Path) -> None:
    config = Config(home=tmp_path).ensure()
    cache = Cache(tmp_path / "c.sqlite3")
    result = run_domain(
        "example.com",
        config=config,
        http=HttpClient(cache, Limiter()),
        cache=cache,
        health=HealthStore(tmp_path / "s.sqlite3"),
        registry=RegistryFallback(),  # type: ignore[arg-type]
        auth=AuthStore(tmp_path / 'providers.toml'),
        typosquat=False,
        emailauth=False,
        rdap=False,
        asn=False,
        dnsbl=False,
        entrypoints=False,
        discovery=False,
        urlscan=False,
        internetdb=False,
        wayback=False,
        takeover=False,
        fingerprint=False,
        max_workers=2,
        probe=False,
    )
    hosts = {i.value for i in result.items if i.type == "hostname"}
    assert "a.example.com" in hosts
    assert any(e.provider == "crtsh" for e in result.errors)














