"""Versioned backup and restore.

Backups are JSON + run files. The format is explicit (``deniz.backup/1``) so
a later Postgres migration can consume the same dump.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

from .audit import AuditStore
from .cases import CaseStore
from .db import Database
from .findings import FindingStore
from .graph import GraphStore
from .monitors import MonitorStore
from .store import RunStore

SCHEMA = "deniz.backup/1"


def _dump(db: Database, table: str) -> list[dict]:
    cur = db.execute(f"SELECT * FROM {table}")
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, row, strict=False)) for row in cur.fetchall()]


def export_backup(
    out_dir: Path,
    *,
    runs: RunStore,
    cases: CaseStore,
    monitors: MonitorStore,
    findings: FindingStore,
    graph: GraphStore,
    include_files: bool = True,
    audit: AuditStore | None = None,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": SCHEMA,
        "created_at": datetime.now(UTC).isoformat(),
        "cases": _dump(cases.db, "cases"),
        "case_runs": _dump(cases.db, "case_runs"),
        "monitors": _dump(monitors.db, "monitors"),
        "alerts": _dump(monitors.db, "alerts"),
        "findings": _dump(findings.db, "findings"),
        "runs": _dump(graph.db, "runs"),
        "entities": _dump(graph.db, "entities"),
        "observations": _dump(graph.db, "observations"),
        "edges": _dump(graph.db, "edges"),
    }
    if audit is not None:
        payload["audit"] = _dump(audit.db, "audit")
    (out_dir / "backup.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    if include_files:
        dst = out_dir / "runs"
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(runs.root, dst)
    (out_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema": SCHEMA,
                "created_at": payload["created_at"],
                "counts": {k: len(v) for k, v in payload.items() if isinstance(v, list)},
                "files": include_files,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return out_dir


def _insert(db: Database, table: str, rows: list[dict]) -> int:
    if not rows:
        return 0
    cols = list(rows[0])
    placeholders = ",".join("?" for _ in cols)
    if db.dialect == "sqlite":
        sql = f"INSERT OR REPLACE INTO {table} ({','.join(cols)}) VALUES ({placeholders})"
    else:
        sql = f"INSERT INTO {table} ({','.join(cols)}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"
    db.executemany(sql, [[row.get(c) for c in cols] for row in rows])
    db.commit()
    return len(rows)


def restore_backup(
    in_dir: Path,
    *,
    runs: RunStore,
    cases: CaseStore,
    monitors: MonitorStore,
    findings: FindingStore,
    graph: GraphStore,
    force: bool = False,
    audit: AuditStore | None = None,
) -> dict[str, int]:
    manifest = json.loads((in_dir / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != SCHEMA:
        raise ValueError(f"unsupported backup schema: {manifest.get('schema')}")
    payload = json.loads((in_dir / "backup.json").read_text(encoding="utf-8"))

    if force:
        for con, tables in (
            (cases._con, ("case_runs", "cases")),
            (monitors._con, ("alerts", "monitors")),
            (findings._con, ("findings",)),
            (graph._con, ("edges", "observations", "entities", "runs")),
        ):
            for table in tables:
                con.execute(f"DELETE FROM {table}")
            con.commit()
        if audit is not None:
            audit._con.execute("DELETE FROM audit")
            audit._con.commit()

    counts: dict[str, int] = {}
    counts["cases"] = _insert(cases.db, "cases", payload["cases"])
    counts["case_runs"] = _insert(cases.db, "case_runs", payload["case_runs"])
    counts["monitors"] = _insert(monitors.db, "monitors", payload["monitors"])
    counts["alerts"] = _insert(monitors.db, "alerts", payload["alerts"])
    counts["findings"] = _insert(findings.db, "findings", payload["findings"])
    counts["runs"] = _insert(graph.db, "runs", payload["runs"])
    counts["entities"] = _insert(graph.db, "entities", payload["entities"])
    counts["observations"] = _insert(graph.db, "observations", payload["observations"])
    counts["edges"] = _insert(graph.db, "edges", payload["edges"])
    if audit is not None:
        counts["audit"] = _insert(audit.db, "audit", payload.get("audit", []))

    if manifest.get("files"):
        src = in_dir / "runs"
        if src.exists():
            runs.root.mkdir(parents=True, exist_ok=True)
            for path in src.iterdir():
                target = runs.root / path.name
                if target.exists() and force:
                    if target.is_dir():
                        shutil.rmtree(target)
                    else:
                        target.unlink()
                if not target.exists():
                    if path.is_dir():
                        shutil.copytree(path, target)
                    else:
                        shutil.copy2(path, target)
    return counts

