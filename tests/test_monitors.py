# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from pathlib import Path

from deniz.kit.cases import CaseStore
from deniz.kit.monitors import MonitorStore


def test_monitor_crud_and_due(tmp_path: Path) -> None:
    cases = CaseStore(tmp_path / "cases.sqlite3")
    case = cases.create("acme")
    store = MonitorStore(tmp_path / "m.sqlite3")
    monitor = store.add(case.id, "domain", "acme.test", 15)
    assert store.get(monitor.id).target == "acme.test"
    assert any(m.id == monitor.id for m in store.due())
    store.schedule_next(monitor, "run-1")
    assert store.get(monitor.id).last_run_id == "run-1"
    store.set_enabled(monitor.id, False)
    assert store.get(monitor.id).enabled is False
    store.remove(monitor.id)


def test_delete_case_cleans(tmp_path: Path) -> None:
    cases = CaseStore(tmp_path / "cases.sqlite3")
    case = cases.create("acme")
    store = MonitorStore(tmp_path / "m.sqlite3")
    monitor = store.add(case.id, "vuln", "log4j", 60)
    store.add_alert(monitor, "delta", "1", {})
    assert store.delete_case(case.id) == 2
    assert store.list_monitors() == []
    assert store.alerts() == []


def test_alerts_ack(tmp_path: Path) -> None:
    cases = CaseStore(tmp_path / "cases.sqlite3")
    case = cases.create("acme")
    store = MonitorStore(tmp_path / "m.sqlite3")
    monitor = store.add(case.id, "vuln", "log4j", 60)
    alert_id = store.add_alert(monitor, "delta", "1 new cve", {"added": [{"type": "cve", "value": "CVE-1"}]})
    assert store.alerts()[0]["summary"] == "1 new cve"
    store.ack(alert_id)
    assert store.alerts()[0]["acked"] is True
    assert store.alerts(include_acked=False) == []


def test_claim_is_atomic_and_backoff(tmp_path: Path) -> None:
    cases = CaseStore(tmp_path / "cases.sqlite3")
    case = cases.create("acme")
    store = MonitorStore(tmp_path / "m.sqlite3")
    monitor = store.add(case.id, "vuln", "log4j", 10)
    claimed = store.claim_due()
    assert [m.id for m in claimed] == [monitor.id]
    assert store.claim_due() == []
    store.finish(monitor, False, "boom")
    again = store.get(monitor.id)
    assert again.fail_count == 1
    assert again.running is False
    assert again.next_run_at > again.last_run_at if again.last_run_at else True
    assert again.last_error == "boom"

