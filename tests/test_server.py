# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.cases import CaseStore
from deniz.kit.config import Config
from deniz.kit.findings import FindingStore
from deniz.kit.graph import GraphStore
from deniz.kit.http import HttpClient
from deniz.kit.models import Observation, Result, Source, Target
from deniz.kit.monitors import Dependencies, MonitorStore
from deniz.kit.providers.health import HealthStore
from deniz.kit.providers.registry import Registry
from deniz.kit.ratelimit import Limiter
from deniz.kit.server import serve, start_background
from deniz.kit.store import RunStore
from deniz.kit.tokens import ApiToken


def parts(tmp_path: Path):
    config = Config(home=tmp_path).ensure()
    cache = Cache(tmp_path / "c.sqlite3")
    http = HttpClient(cache, Limiter())
    cases = CaseStore(tmp_path / "cases.sqlite3")
    runs = RunStore(tmp_path / "runs")
    graph = GraphStore(tmp_path / "g.sqlite3")
    monitors = MonitorStore(tmp_path / "m.sqlite3")
    findings = FindingStore(tmp_path / "f.sqlite3")
    deps = Dependencies(
        config=config,
        http=http,
        cache=cache,
        health=HealthStore(tmp_path / "h.sqlite3"),
        registry=Registry(),
        auth=AuthStore(tmp_path / "p.toml"),
        runs=runs,
        graph=graph,
        cases=cases,
        monitors=monitors,
    )
    return {
        "cases": cases,
        "runs": runs,
        "graph": graph,
        "monitors": monitors,
        "deps": deps,
        "findings": findings,
        "tick": lambda: [],
        "registry": Registry(),
    }


def test_loopback_without_token(tmp_path: Path) -> None:
    server, _ = start_background(**parts(tmp_path), port=0)
    port = server.server_address[1]
    try:
        assert httpx.get(f"http://127.0.0.1:{port}/health").status_code == 200
        assert httpx.get(f"http://127.0.0.1:{port}/api/cases").status_code == 200
    finally:
        server.shutdown()
        server.server_close()


def test_token_required(tmp_path: Path) -> None:
    server, _ = start_background(**parts(tmp_path), port=0, token="s3cret")
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    try:
        assert httpx.get(f"{base}/health").status_code == 200
        assert httpx.get(f"{base}/api/cases").status_code == 401
        assert httpx.get(f"{base}/api/cases", headers={"authorization": "Bearer s3cret"}).status_code == 200
        assert httpx.get(f"{base}/api/providers", headers={"authorization": "Bearer s3cret"}).json()[0]["health_7d"] is None
        assert httpx.get(f"{base}/api/schema", headers={"authorization": "Bearer s3cret"}).json()["title"] == "Result"
        assert httpx.get(f"{base}/api/cases?token=s3cret").status_code == 200
        assert httpx.get(f"{base}/api/cases", headers={"authorization": "Bearer wrong"}).status_code == 401
        page = httpx.get(f"{base}/?token=s3cret")
        assert page.status_code == 200
        assert "caseForm" in page.text and '"s3cret"' in page.text
    finally:
        server.shutdown()
        server.server_close()


def test_roles(tmp_path: Path) -> None:
    tokens = [
        ApiToken("viewer", "v", "viewer"),
        ApiToken("operator", "o", "operator"),
        ApiToken("admin", "a", "admin"),
    ]
    server, _ = start_background(**parts(tmp_path), port=0, tokens=tokens)
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    try:
        assert httpx.get(f"{base}/api/cases", headers={"authorization": "Bearer v"}).status_code == 200
        assert httpx.post(f"{base}/api/cases", headers={"authorization": "Bearer v"}, json={"name": "nope"}).status_code == 403
        created = httpx.post(f"{base}/api/cases", headers={"authorization": "Bearer o"}, json={"name": "ops"})
        assert created.status_code == 201
        case_id = created.json()["id"]
        assert httpx.delete(f"{base}/api/cases/{case_id}", headers={"authorization": "Bearer o"}).status_code == 403
        assert httpx.delete(f"{base}/api/cases/{case_id}", headers={"authorization": "Bearer a"}).status_code == 200
        assert httpx.get(f"{base}/api/cases", headers={"authorization": "Bearer nope"}).status_code == 401
    finally:
        server.shutdown()
        server.server_close()


def test_api_audit(tmp_path: Path) -> None:
    tokens = [ApiToken("alice", "a", "admin")]
    server, _ = start_background(**parts(tmp_path), port=0, tokens=tokens)
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    headers = {"authorization": "Bearer a"}
    try:
        created = httpx.post(f"{base}/api/cases", headers=headers, json={"name": "audited"})
        assert created.status_code == 201
        page = httpx.get(f"{base}/api/audit", headers=headers, params={"action": "case.create"})
        assert page.status_code == 200
        assert page.headers["x-total-count"] == "1"
        assert page.json()[0]["actor"] == "alice"
        assert page.json()[0]["target"] == created.json()["id"]
    finally:
        server.shutdown()
        server.server_close()


def test_cors_allowlist(tmp_path: Path) -> None:
    tokens = [ApiToken("admin", "a", "admin")]
    server, _ = start_background(**parts(tmp_path), port=0, tokens=tokens, cors_origins=["https://app.test"])
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    try:
        allowed = httpx.get(f"{base}/health", headers={"origin": "https://app.test"})
        assert allowed.headers["access-control-allow-origin"] == "https://app.test"
        assert "origin" in allowed.headers["vary"].lower()

        blocked = httpx.get(f"{base}/health", headers={"origin": "https://other.test"})
        assert "access-control-allow-origin" not in blocked.headers

        preflight = httpx.request(
            "OPTIONS",
            f"{base}/api/cases",
            headers={"origin": "https://app.test", "access-control-request-method": "POST"},
        )
        assert preflight.status_code == 200
        assert preflight.headers["access-control-allow-origin"] == "https://app.test"
    finally:
        server.shutdown()
        server.server_close()


def test_non_loopback_needs_decision(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        serve(**parts(tmp_path), host="0.0.0.0", port=0)
    server = serve(**parts(tmp_path), host="0.0.0.0", port=0, allow_anonymous=True)
    server.server_close()


def test_rate_limit(tmp_path: Path) -> None:
    server, _ = start_background(**parts(tmp_path), port=0, limit_per_second=0.001, limit_burst=1)
    port = server.server_address[1]
    try:
        assert httpx.get(f"http://127.0.0.1:{port}/api/cases").status_code == 200
        limited = httpx.get(f"http://127.0.0.1:{port}/api/cases")
        assert limited.status_code == 429
        assert limited.headers["retry-after"] == "1"
        assert httpx.get(f"http://127.0.0.1:{port}/health").status_code == 200
    finally:
        server.shutdown()
        server.server_close()


def test_pagination(tmp_path: Path) -> None:
    server, _ = start_background(**parts(tmp_path), port=0, token="t")
    port = server.server_address[1]
    headers = {"authorization": "Bearer t"}
    try:
        for name in ("a", "b", "c"):
            assert httpx.post(f"http://127.0.0.1:{port}/api/cases", headers=headers, json={"name": name}).status_code == 201
        page = httpx.get(f"http://127.0.0.1:{port}/api/cases?limit=1&offset=1", headers=headers)
        assert page.status_code == 200
        assert len(page.json()) == 1
        assert page.headers["x-total-count"] == "3"
        assert page.headers["x-offset"] == "1"
    finally:
        server.shutdown()
        server.server_close()


def test_cursor_pagination(tmp_path: Path) -> None:
    server, _ = start_background(**parts(tmp_path), port=0, token="t")
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    headers = {"authorization": "Bearer t"}
    try:
        for name in ("a", "b", "c"):
            assert httpx.post(f"{base}/api/cases", headers=headers, json={"name": name}).status_code == 201

        seen: list[str] = []
        cursor = None
        first_cursor = None
        for _ in range(4):
            params = {"limit": 1}
            if cursor:
                params["cursor"] = cursor
            page = httpx.get(f"{base}/api/cases", headers=headers, params=params)
            assert page.status_code == 200
            assert page.headers["x-total-count"] == "3"
            seen.extend(item["id"] for item in page.json())
            cursor = page.headers.get("x-next-cursor")
            first_cursor = first_cursor or cursor
            if not cursor:
                break
        assert len(seen) == 3
        assert len(set(seen)) == 3
        assert cursor is None
        assert first_cursor

        wrong_scope = httpx.get(f"{base}/api/alerts", headers=headers, params={"cursor": first_cursor})
        assert wrong_scope.status_code == 400
        assert "invalid cursor" in wrong_scope.json()["error"]

        garbage = httpx.get(f"{base}/api/cases", headers=headers, params={"cursor": "not-a-token"})
        assert garbage.status_code == 400

        bad_limit = httpx.get(f"{base}/api/cases", headers=headers, params={"limit": "many"})
        assert bad_limit.status_code == 400
    finally:
        server.shutdown()
        server.server_close()


def test_alert_cursor_and_real_total(tmp_path: Path) -> None:
    stores = parts(tmp_path)
    case = stores["cases"].create("alert-case")
    monitor = stores["monitors"].add(case.id, "vuln", "log4j", 60)
    for index in range(3):
        stores["monitors"].add_alert(monitor, "delta", f"alert {index}", {})

    server, _ = start_background(**stores, port=0, token="t")
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    headers = {"authorization": "Bearer t"}
    try:
        seen: list[str] = []
        cursor = None
        for _ in range(4):
            params = {"limit": 1}
            if cursor:
                params["cursor"] = cursor
            page = httpx.get(f"{base}/api/alerts", headers=headers, params=params)
            assert page.status_code == 200
            assert page.headers["x-total-count"] == "3"
            seen.extend(item["id"] for item in page.json())
            cursor = page.headers.get("x-next-cursor")
            if not cursor:
                break
        assert len(seen) == 3
        assert len(set(seen)) == 3

        unacked = httpx.get(f"{base}/api/alerts?acked&limit=1", headers=headers)
        assert unacked.status_code == 200
        assert unacked.headers["x-total-count"] == "3"
    finally:
        server.shutdown()
        server.server_close()


def test_case_search_cursor(tmp_path: Path) -> None:
    stores = parts(tmp_path)
    case = stores["cases"].create("search-case")
    result = Result(module="test", target=Target(type="domain", value="example.com"))
    for value in ("x.example.com", "y.example.com"):
        result.add(Observation(type="takeover", value=value, confidence=0.9, sources=[Source(provider="t", url="u")]))
    stores["graph"].record(result)
    stores["cases"].add_run(case.id, result.run_id)

    server, _ = start_background(**stores, port=0, token="t")
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    headers = {"authorization": "Bearer t"}
    try:
        first = httpx.get(f"{base}/api/cases/{case.id}/search", headers=headers, params={"q": "example", "limit": 1})
        assert first.status_code == 200
        assert first.headers["x-total-count"] == "2"
        assert len(first.json()) == 1
        cursor = first.headers.get("x-next-cursor")
        assert cursor

        second = httpx.get(
            f"{base}/api/cases/{case.id}/search",
            headers=headers,
            params={"q": "example", "limit": 1, "cursor": cursor},
        )
        assert second.status_code == 200
        assert len(second.json()) == 1
        assert second.json()[0]["value"] != first.json()[0]["value"]
        assert "x-next-cursor" not in second.headers

        wrong_scope = httpx.get(f"{base}/api/cases/{case.id}/search", headers=headers, params={"q": "other", "cursor": cursor})
        assert wrong_scope.status_code == 400
    finally:
        server.shutdown()
        server.server_close()


def test_legacy_bridge_and_cors(tmp_path: Path) -> None:
    server, _ = start_background(**parts(tmp_path), port=0, token="t")
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    headers = {"authorization": "Bearer t"}
    try:
        preflight = httpx.request("OPTIONS", f"{base}/api/modules", headers={"origin": "https://app.test"})
        assert preflight.status_code == 200
        assert preflight.headers["access-control-allow-origin"] == "*"
        assert "authorization" in preflight.headers["access-control-allow-headers"]

        index = httpx.get(f"{base}/api", headers=headers)
        assert index.status_code == 200
        assert "/api/schema" in index.json()["endpoints"]
        assert index.headers["access-control-allow-origin"] == "*"

        modules = httpx.get(f"{base}/api/modules?_module=github", headers=headers)
        assert modules.status_code == 410
        assert modules.json()["legacy_module"] == "github"

        framework = httpx.get(f"{base}/api/framework?command=show+modules", headers=headers)
        assert framework.status_code == 410
        assert "run <provider>" in framework.json()["replacement"]
    finally:
        server.shutdown()
        server.server_close()


def test_write_endpoints(tmp_path: Path) -> None:
    parts_cache = parts(tmp_path)
    server, _ = start_background(**parts_cache, port=0, token="t")
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    headers = {"authorization": "Bearer t"}
    try:
        created = httpx.post(f"{base}/api/cases", headers=headers, json={"name": "api-case", "allow": ["example.com"]})
        assert created.status_code == 201
        case_id = created.json()["id"]
        added = httpx.post(
            f"{base}/api/monitor",
            headers=headers,
            json={"case": case_id, "kind": "identity", "target": "alice", "every": 15},
        )
        assert added.status_code == 201
        assert added.json()["target"] == "alice"
        assert httpx.post(f"{base}/api/alerts/ack", headers=headers, json={"all": True}).status_code == 200
        assert httpx.post(f"{base}/api/cases", headers=headers, json={}).status_code == 400
        assert httpx.post(f"{base}/api/cases/{case_id}/archive", headers=headers).status_code == 200
        assert httpx.post(f"{base}/api/cases/{case_id}/export", headers=headers).status_code == 200
        runs = parts_cache["runs"]
        run = runs.begin("test")
        from deniz.kit.models import Result, Target

        result = Result(module="test", target=Target(type="domain", value="example.com"))
        runs.write(run, result)
        assert httpx.post(f"{base}/api/runs/{run.run_id}/report", headers=headers).status_code == 200
        assert httpx.delete(f"{base}/api/cases/{case_id}", headers=headers).status_code == 200
    finally:
        server.shutdown()
        server.server_close()

