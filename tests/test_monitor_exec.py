# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from pathlib import Path

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.cases import CaseStore
from deniz.kit.config import Config
from deniz.kit.graph import GraphStore
from deniz.kit.http import HttpClient
from deniz.kit.models import Observation, Source
from deniz.kit.monitors import Dependencies, MonitorStore, execute, run_due
from deniz.kit.providers.base import ProviderInfo
from deniz.kit.providers.health import HealthStore
from deniz.kit.ratelimit import Limiter
from deniz.kit.store import RunStore


class Profile:
    info = ProviderInfo(name="username", title="p", capabilities=frozenset({"identity"}))

    def __init__(self, http):
        pass

    def run(self, target, ctx):
        return [Observation(type="url", value="https://a.test/x", sources=[Source(provider="username", url="https://a.test")])]


class ProfileGrows(Profile):
    calls = 0

    def run(self, target, ctx):
        type(self).calls += 1
        items = [Observation(type="url", value="https://a.test/x", sources=[Source(provider="username", url="https://a.test")])]
        if type(self).calls > 1:
            items.append(Observation(type="url", value="https://b.test/x", sources=[Source(provider="username", url="https://b.test")]))
        return items


class ProfileBoom(Profile):
    def run(self, target, ctx):
        raise RuntimeError("boom")


class Registry:
    def __init__(self, cls):
        self.cls = cls

    def get(self, name):
        return self.cls


def deps(tmp_path: Path, cls) -> Dependencies:
    config = Config(home=tmp_path).ensure()
    cache = Cache(tmp_path / "c.sqlite3")
    return Dependencies(
        config=config,
        http=HttpClient(cache, Limiter()),
        cache=cache,
        health=HealthStore(tmp_path / "h.sqlite3"),
        registry=Registry(cls),  # type: ignore[arg-type]
        auth=AuthStore(tmp_path / "p.toml"),
        runs=RunStore(tmp_path / "runs"),
        graph=GraphStore(tmp_path / "g.sqlite3"),
        cases=CaseStore(tmp_path / "cases.sqlite3"),
        monitors=MonitorStore(tmp_path / "m.sqlite3"),
    )


def test_baseline_is_silent_then_delta_alerts(tmp_path: Path) -> None:
    ProfileGrows.calls = 0
    dependencies = deps(tmp_path, ProfileGrows)
    case = dependencies.cases.create("acme")
    monitor = dependencies.monitors.add(case.id, "identity", "alice", 60)
    execute(monitor, dependencies)
    assert dependencies.monitors.alerts() == []
    execute(dependencies.monitors.get(monitor.id), dependencies)
    alerts = dependencies.monitors.alerts()
    assert len(alerts) == 1
    assert alerts[0]["details"]["added"] == [{"type": "url", "value": "https://b.test/x"}]


def test_failure_creates_alert(tmp_path: Path) -> None:
    dependencies = deps(tmp_path, ProfileBoom)
    case = dependencies.cases.create("acme")
    dependencies.monitors.add(case.id, "identity", "alice", 60)
    assert run_due(dependencies)
    alerts = dependencies.monitors.alerts()
    assert alerts[0]["kind"] == "failure"
    assert "boom" in alerts[0]["summary"]


def test_webhook_delivery(tmp_path: Path, monkeypatch) -> None:
    ProfileGrows.calls = 0
    import deniz.kit.monitors as monitors

    dependencies = deps(tmp_path, ProfileGrows)
    case = dependencies.cases.create("acme")
    monitor = dependencies.monitors.add(case.id, "identity", "alice", 60)
    execute(monitor, dependencies)
    monkeypatch.setenv("DENIZ_WEBHOOK_URL", "https://hook.test/x")

    class Resp:
        status_code = 204

    calls = []

    def fake_post(url, json, timeout):
        calls.append((url, json))
        return Resp()

    monkeypatch.setattr(monitors.httpx, "post", fake_post)
    execute(dependencies.monitors.get(monitor.id), dependencies)
    assert calls and calls[0][0] == "https://hook.test/x"
    assert dependencies.monitors.alerts()[0]["delivered"] is True


def test_webhook_slack_style(tmp_path: Path, monkeypatch) -> None:
    import deniz.kit.monitors as monitors

    dependencies = deps(tmp_path, ProfileGrows)
    ProfileGrows.calls = 0
    case = dependencies.cases.create("acme")
    monitor = dependencies.monitors.add(case.id, "identity", "alice", 60)
    execute(monitor, dependencies)
    monkeypatch.setenv("DENIZ_WEBHOOK_URL", "https://hooks.slack.test/x")
    monkeypatch.setenv("DENIZ_WEBHOOK_STYLE", "slack")
    calls = []

    class Resp:
        status_code = 200

    monkeypatch.setattr(monitors.httpx, "post", lambda url, json, timeout: (calls.append(json), Resp())[1])
    execute(dependencies.monitors.get(monitor.id), dependencies)
    assert "text" in calls[0] and "content" not in calls[0]


