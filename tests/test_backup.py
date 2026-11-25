from __future__ import annotations

import json
from pathlib import Path

import pytest

from deniz.kit.audit import AuditStore
from deniz.kit.backup import export_backup, restore_backup
from deniz.kit.cases import CaseStore
from deniz.kit.findings import FindingStore
from deniz.kit.graph import GraphStore
from deniz.kit.models import Observation, Result, Source, Target
from deniz.kit.monitors import MonitorStore
from deniz.kit.store import RunStore


def stores(root: Path):
    return {
        "runs": RunStore(root / "runs"),
        "cases": CaseStore(root / "cases.sqlite3"),
        "monitors": MonitorStore(root / "m.sqlite3"),
        "findings": FindingStore(root / "f.sqlite3"),
        "graph": GraphStore(root / "g.sqlite3"),
    }


def seed(root: Path):
    s = stores(root)
    case = s["cases"].create("acme")
    run = s["runs"].begin("test")
    result = Result(run_id=run.run_id, module="test", target=Target(type="domain", value="acme.test"))
    result.add(Observation(type="hostname", value="a.acme.test", sources=[Source(provider="t", url="u")]))
    s["runs"].write(run, result)
    s["graph"].record(result)
    s["cases"].add_run(case.id, run.run_id)
    monitor = s["monitors"].add(case.id, "domain", "acme.test", 30)
    s["monitors"].add_alert(monitor, "delta", "1 new hostname", {"added": []})
    s["findings"].refresh(case.id, [run.run_id], s["graph"])
    return s


def test_roundtrip(tmp_path: Path) -> None:
    source = seed(tmp_path / "one")
    out = export_backup(tmp_path / "backup", **source)
    assert (out / "manifest.json").exists()

    target = stores(tmp_path / "two")
    counts = restore_backup(out, **target)
    assert counts["cases"] == 1
    assert target["cases"].get("acme").name == "acme"
    assert any(p.is_dir() for p in target["runs"].root.iterdir())


def test_force_clears(tmp_path: Path) -> None:
    source = seed(tmp_path / "one")
    out = export_backup(tmp_path / "backup", **source)
    target = stores(tmp_path / "two")
    target["cases"].create("other")
    restore_backup(out, **target, force=True)
    names = [c.name for c in target["cases"].list_cases()]
    assert names == ["acme"]


def test_audit_roundtrip(tmp_path: Path) -> None:
    source = seed(tmp_path / "one")
    source_audit = AuditStore(tmp_path / "one" / "audit.sqlite3")
    source_audit.record("cli", "case.create", "x")
    out = export_backup(tmp_path / "backup", **source, audit=source_audit)

    target = stores(tmp_path / "two")
    target_audit = AuditStore(tmp_path / "two" / "audit.sqlite3")
    target_audit.record("cli", "stale")
    counts = restore_backup(out, **target, force=True, audit=target_audit)
    assert counts["audit"] == 1
    assert [row["action"] for row in target_audit.list()] == ["case.create"]


def test_bad_schema(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text(json.dumps({"schema": "nope"}), encoding="utf-8")
    (tmp_path / "backup.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError):
        restore_backup(tmp_path, **stores(tmp_path / "two"))
