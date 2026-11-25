from __future__ import annotations

import json
from pathlib import Path

from deniz.kit.cli import _runtime
from deniz.kit.models import Observation, Result, Source, Target
from deniz.mcp import handle


def call(name: str, arguments: dict) -> dict:
    response = handle({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": name, "arguments": arguments}})
    assert response
    assert response["result"]["isError"] is False
    return json.loads(response["result"]["content"][0]["text"])


def seed(tmp_path: Path) -> str:
    rt = _runtime()
    case = rt.cases.create("mcp-page")
    monitor = rt.monitors.add(case.id, "vuln", "log4j", 60)
    for index in range(3):
        rt.monitors.add_alert(monitor, "delta", f"alert {index}", {})
    result = Result(module="test", target=Target(type="domain", value="example.com"))
    result.add(Observation(type="takeover", value="x.example.com -> github.io", confidence=0.9, sources=[Source(provider="t", url="u")]))
    result.add(Observation(type="takeover", value="y.example.com -> netlify.app", confidence=0.9, sources=[Source(provider="t", url="u")]))
    rt.graph.record(result)
    rt.cases.add_run(case.id, result.run_id)
    rt.findings.refresh(case.id, [result.run_id], rt.graph)
    rt.client.close()
    return case.id


def test_alerts_pagination(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DENIZ_HOME", str(tmp_path))
    seed(tmp_path)
    page = call("deniz_alerts", {"limit": 2, "offset": 1})
    assert page["total"] == 3
    assert page["offset"] == 1
    assert len(page["alerts"]) == 2


def test_findings_pagination(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DENIZ_HOME", str(tmp_path))
    case_id = seed(tmp_path)
    page = call("deniz_findings", {"case": case_id, "limit": 1})
    assert page["total"] >= 1
    assert len(page["findings"]) == 1


def test_case_search_pagination(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DENIZ_HOME", str(tmp_path))
    case_id = seed(tmp_path)
    page = call("deniz_case", {"action": "search", "ref": case_id, "value": "example", "limit": 1})
    assert page["total"] >= 2
    assert len(page["items"]) == 1
    assert "example" in page["items"][0]["value"]
    assert page["next"]

    second = call("deniz_case", {"action": "search", "ref": case_id, "value": "example", "limit": 1, "cursor": page["next"]})
    assert len(second["items"]) == 1
    assert second["items"][0]["value"] != page["items"][0]["value"]
    assert len({page["items"][0]["value"], second["items"][0]["value"]}) == 2


def test_alert_cursor(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DENIZ_HOME", str(tmp_path))
    seed(tmp_path)
    seen: list[str] = []
    cursor = None
    for _ in range(4):
        page = call("deniz_alerts", {"limit": 1, **({"cursor": cursor} if cursor else {})})
        assert page["total"] == 3
        assert len(page["alerts"]) == 1
        seen.append(page["alerts"][0]["id"])
        cursor = page["next"]
        if not cursor:
            break
    assert len(seen) == 3
    assert len(set(seen)) == 3
    assert cursor is None


def test_finding_cursor(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DENIZ_HOME", str(tmp_path))
    case_id = seed(tmp_path)
    first = call("deniz_findings", {"case": case_id, "limit": 1})
    assert first["total"] == 2
    assert len(first["findings"]) == 1
    assert first["next"]
    second = call("deniz_findings", {"case": case_id, "limit": 1, "cursor": first["next"]})
    assert len(second["findings"]) == 1
    assert second["findings"][0]["id"] != first["findings"][0]["id"]
    assert second["next"] is None


def test_case_list_cursor(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DENIZ_HOME", str(tmp_path))
    rt = _runtime()
    for name in ("a", "b", "c"):
        rt.cases.create(name)
    rt.client.close()
    seen: list[str] = []
    cursor = None
    for _ in range(4):
        page = call("deniz_case", {"limit": 1, **({"cursor": cursor} if cursor else {})})
        assert page["total"] == 3
        assert len(page["cases"]) == 1
        seen.append(page["cases"][0]["id"])
        cursor = page["next"]
        if not cursor:
            break
    assert len(seen) == 3
    assert len(set(seen)) == 3


def test_monitor_list_cursor(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DENIZ_HOME", str(tmp_path))
    rt = _runtime()
    case = rt.cases.create("monitors")
    for target in ("a.example", "b.example"):
        rt.monitors.add(case.id, "domain", target, 60)
    rt.client.close()
    first = call("deniz_monitor", {"limit": 1})
    assert first["total"] == 2
    assert len(first["monitors"]) == 1
    assert first["next"]
    second = call("deniz_monitor", {"limit": 1, "cursor": first["next"]})
    assert len(second["monitors"]) == 1
    assert second["monitors"][0]["id"] != first["monitors"][0]["id"]
    assert second["next"] is None


def test_invalid_cursor_is_an_error(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DENIZ_HOME", str(tmp_path))
    seed(tmp_path)
    response = handle(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": "deniz_alerts", "arguments": {"cursor": "not-a-token"}},
        }
    )
    assert response
    assert response["result"]["isError"] is True
    assert "invalid cursor" in response["result"]["content"][0]["text"]
