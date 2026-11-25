# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Append-only audit log for state-changing actions.

The log records who did what to which object, with a small JSON detail bag. It
is written by the CLI, the HTTP API and the MCP server; reads are exposed by
``deniz audit list`` and ``GET /api/audit``.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .db import Database, connect


def _now() -> str:
    return datetime.now(UTC).isoformat()


class AuditStore:
    def __init__(self, target: str | Path) -> None:
        self._con: Database = connect(target)
        self._lock = threading.Lock()
        self._con.execute(
            "CREATE TABLE IF NOT EXISTS audit ("
            "id TEXT PRIMARY KEY, created_at TEXT NOT NULL, actor TEXT NOT NULL, "
            "action TEXT NOT NULL, target TEXT NOT NULL, outcome TEXT NOT NULL, details TEXT NOT NULL)"
        )
        self._con.commit()

    @property
    def db(self) -> Database:
        return self._con

    def record(
        self,
        actor: str,
        action: str,
        target: str = "",
        *,
        outcome: str = "ok",
        details: dict | None = None,
    ) -> str:
        audit_id = uuid.uuid4().hex
        with self._lock:
            self._con.execute(
                "INSERT INTO audit (id, created_at, actor, action, target, outcome, details) VALUES (?,?,?,?,?,?,?)",
                (audit_id, _now(), actor, action, target, outcome, json.dumps(details or {}, ensure_ascii=False)),
            )
            self._con.commit()
        return audit_id

    def _where(self, actor: str | None, action: str | None) -> tuple[str, list[object]]:
        clauses: list[str] = []
        args: list[object] = []
        if actor:
            clauses.append("actor=?")
            args.append(actor)
        if action:
            clauses.append("action=?")
            args.append(action)
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", args

    def list(
        self,
        limit: int = 100,
        offset: int = 0,
        actor: str | None = None,
        action: str | None = None,
    ) -> list[dict]:
        where, args = self._where(actor, action)
        sql = "SELECT id, created_at, actor, action, target, outcome, details FROM audit" + where
        sql += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
        args.extend([max(1, limit), max(0, offset)])
        with self._lock:
            rows = self._con.execute(sql, args).fetchall()
        return [
            {
                "id": row[0],
                "created_at": row[1],
                "actor": row[2],
                "action": row[3],
                "target": row[4],
                "outcome": row[5],
                "details": json.loads(row[6] or "{}"),
            }
            for row in rows
        ]

    def count(self, actor: str | None = None, action: str | None = None) -> int:
        where, args = self._where(actor, action)
        with self._lock:
            row = self._con.execute("SELECT COUNT(*) FROM audit" + where, args).fetchone()
        return int(row[0])

    def prune(self, days: int = 90) -> int:
        now = datetime.now(UTC)
        cutoff = (now - timedelta(days=max(0, days)) + timedelta(seconds=1 if days <= 0 else 0)).isoformat()
        with self._lock:
            cursor = self._con.execute("DELETE FROM audit WHERE created_at < ?", (cutoff,))
            self._con.commit()
        return int(cursor.rowcount)
