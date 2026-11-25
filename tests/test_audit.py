from __future__ import annotations

import json
from pathlib import Path

from deniz.cli import main
from deniz.kit.audit import AuditStore


def test_record_list_count_prune(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "audit.sqlite3")
    store.record("alice", "case.create", "c1", details={"name": "x"})
    store.record("bob", "case.delete", "c1")
    assert store.count() == 2
    assert store.count(actor="alice") == 1
    rows = store.list(actor="alice")
    assert rows[0]["action"] == "case.create"
    assert rows[0]["details"] == {"name": "x"}
    assert store.prune(days=0) == 2
    assert store.count() == 0


def test_cli_writes_and_lists_audit(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("DENIZ_HOME", str(tmp_path))
    assert main(["case", "new", "old"]) == 0
    capsys.readouterr()
    assert main(["case", "archive", "old"]) == 0
    capsys.readouterr()
    assert main(["case", "prune", "--days", "0", "--yes"]) == 0
    assert "pruned 1" in capsys.readouterr().out

    assert main(["audit", "list", "--event", "case.prune", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 1
    assert rows[0]["action"] == "case.prune"
    assert rows[0]["actor"] == "cli"


def test_audit_prune_cli(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("DENIZ_HOME", str(tmp_path))
    store = AuditStore(Path(tmp_path) / "audit.sqlite3")
    store.record("cli", "x")
    capsys.readouterr()
    assert main(["audit", "prune", "--days", "0"]) == 2
    assert main(["audit", "prune", "--days", "0", "--yes"]) == 0
    assert "pruned 1" in capsys.readouterr().out
