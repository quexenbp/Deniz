# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Scheduled monitors and delta alerts.

A monitor re-runs one collection profile against one target inside a case and
raises an alert only for entities that were not present in the previous run.
Baselines are silent by design.
"""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from .auth import AuthStore
from .cache import Cache
from .cases import CaseStore
from .config import Config
from .db import Database, connect
from .errors import DenizError
from .graph import GraphStore
from .http import HttpClient
from .models import Result, Target
from .pagination import Page, decode_cursor, page_from
from .pipeline.domain import run_domain
from .pipeline.vuln import run_vuln
from .providers.base import Context
from .providers.health import HealthStore
from .providers.registry import Registry
from .scope import Scope
from .store import RunStore

KINDS = ("domain", "vuln", "buckets", "identity")
PRIMARY = {"domain": "hostname", "vuln": "cve", "buckets": "bucket", "identity": "url"}


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.isoformat()


@dataclass
class Monitor:
    id: str
    case_id: str
    kind: str
    target: str
    every_minutes: int
    alert_removed: bool
    enabled: bool
    created_at: str
    last_run_at: str | None = None
    last_run_id: str | None = None
    next_run_at: str = ""
    meta: dict[str, Any] = field(default_factory=dict)
    running: bool = False
    lease_until: str | None = None
    fail_count: int = 0
    last_error: str | None = None


class MonitorStore:
    def __init__(self, path: Path | str) -> None:
        self._lock = threading.Lock()
        self.db: Database = connect(path)
        self._con = self.db._raw
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS monitors (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                target TEXT NOT NULL,
                every_minutes INTEGER NOT NULL,
                alert_removed INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_run_at TEXT,
                last_run_id TEXT,
                next_run_at TEXT NOT NULL,
                meta_json TEXT NOT NULL DEFAULT '{}',
                running INTEGER NOT NULL DEFAULT 0,
                lease_until TEXT,
                fail_count INTEGER NOT NULL DEFAULT 0,
                last_error TEXT
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                monitor_id TEXT NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
                case_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                kind TEXT NOT NULL,
                summary TEXT NOT NULL,
                details_json TEXT NOT NULL,
                acked INTEGER NOT NULL DEFAULT 0,
                delivered INTEGER NOT NULL DEFAULT 0,
                delivery_error TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_monitors_due ON monitors(enabled, next_run_at);
            CREATE INDEX IF NOT EXISTS idx_alerts_case ON alerts(case_id, acked);
            """
        )
        self._con.commit()
        self._migrate()

    def _migrate(self) -> None:
        columns = self.db.columns("monitors")
        additions = {
            "running": "INTEGER NOT NULL DEFAULT 0",
            "lease_until": "TEXT",
            "fail_count": "INTEGER NOT NULL DEFAULT 0",
            "last_error": "TEXT",
        }
        for name, ddl in additions.items():
            if name not in columns:
                self._con.execute(f"ALTER TABLE monitors ADD COLUMN {name} {ddl}")
        self._con.commit()

    def add(self, case_id: str, kind: str, target: str, every_minutes: int, alert_removed: bool = False) -> Monitor:
        if kind not in KINDS:
            raise ValueError(f"unknown monitor kind: {kind}")
        every_minutes = max(5, min(int(every_minutes), 43200))
        monitor = Monitor(
            id=uuid.uuid4().hex,
            case_id=case_id,
            kind=kind,
            target=target,
            every_minutes=every_minutes,
            alert_removed=alert_removed,
            enabled=True,
            created_at=_iso(_now()),
            next_run_at=_iso(_now()),
        )
        with self._lock:
            self._con.execute(
                "INSERT INTO monitors VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    monitor.id,
                    monitor.case_id,
                    monitor.kind,
                    monitor.target,
                    monitor.every_minutes,
                    int(monitor.alert_removed),
                    int(monitor.enabled),
                    monitor.created_at,
                    None,
                    None,
                    monitor.next_run_at,
                    "{}",
                    0,
                    None,
                    0,
                    None,
                ),
            )
            self._con.commit()
        return monitor

    def get(self, ref: str) -> Monitor:
        with self._lock:
            row = self._con.execute("SELECT * FROM monitors WHERE id=?", (ref,)).fetchone()
            if row is None:
                matches = self._con.execute("SELECT * FROM monitors WHERE id LIKE ?", (ref + "%",)).fetchall()
                row = matches[0] if len(matches) == 1 else None
        if row is None:
            raise KeyError(ref)
        return self._row(row)

    @staticmethod
    def _row(row: tuple) -> Monitor:
        return Monitor(
            id=row[0],
            case_id=row[1],
            kind=row[2],
            target=row[3],
            every_minutes=row[4],
            alert_removed=bool(row[5]),
            enabled=bool(row[6]),
            created_at=row[7],
            last_run_at=row[8],
            last_run_id=row[9],
            next_run_at=row[10],
            meta=json.loads(row[11] or "{}"),
            running=bool(row[12]),
            lease_until=row[13],
            fail_count=int(row[14] or 0),
            last_error=row[15],
        )

    def list_monitors(self, case_id: str | None = None) -> list[Monitor]:
        sql = "SELECT * FROM monitors"
        args: list[object] = []
        if case_id:
            sql += " WHERE case_id=?"
            args.append(case_id)
        sql += " ORDER BY created_at DESC"
        with self._lock:
            rows = self._con.execute(sql, args).fetchall()
        return [self._row(r) for r in rows]

    def due(self, limit: int = 20) -> list[Monitor]:
        with self._lock:
            rows = self._con.execute(
                "SELECT * FROM monitors WHERE enabled=1 AND next_run_at<=? ORDER BY next_run_at LIMIT ?",
                (_iso(_now()), limit),
            ).fetchall()
        return [self._row(r) for r in rows]

    def claim_due(self, limit: int = 20, lease_minutes: int = 15) -> list[Monitor]:
        """Atomically lease due monitors. Stale leases are reclaimable."""
        now = _now()
        stale = _iso(now - timedelta(minutes=lease_minutes))
        lease = _iso(now + timedelta(minutes=lease_minutes))
        claimed: list[Monitor] = []
        with self._lock:
            rows = self._con.execute(
                "SELECT id FROM monitors WHERE enabled=1 AND next_run_at<=? AND (running=0 OR lease_until<?) "
                "ORDER BY next_run_at LIMIT ?",
                (_iso(now), stale, limit),
            ).fetchall()
            for (monitor_id,) in rows:
                cur = self._con.execute(
                    "UPDATE monitors SET running=1, lease_until=? WHERE id=? AND (running=0 OR lease_until<?)",
                    (lease, monitor_id, stale),
                )
                if cur.rowcount:
                    claimed.append(self._row(self._con.execute("SELECT * FROM monitors WHERE id=?", (monitor_id,)).fetchone()))
            self._con.commit()
        return claimed

    def remove(self, ref: str) -> None:
        monitor = self.get(ref)
        with self._lock:
            self._con.execute("DELETE FROM monitors WHERE id=?", (monitor.id,))
            self._con.commit()

    def delete_case(self, case_id: str) -> int:
        with self._lock:
            alerts = self._con.execute("DELETE FROM alerts WHERE case_id=?", (case_id,)).rowcount
            monitors = self._con.execute("DELETE FROM monitors WHERE case_id=?", (case_id,)).rowcount
            self._con.commit()
        return int(monitors) + int(alerts)

    def set_enabled(self, ref: str, enabled: bool) -> Monitor:
        monitor = self.get(ref)
        with self._lock:
            self._con.execute("UPDATE monitors SET enabled=? WHERE id=?", (int(enabled), monitor.id))
            self._con.commit()
        return self.get(monitor.id)

    def mark_run(self, monitor: Monitor, run_id: str) -> None:
        with self._lock:
            self._con.execute(
                "UPDATE monitors SET last_run_at=?, last_run_id=? WHERE id=?",
                (_iso(_now()), run_id, monitor.id),
            )
            self._con.commit()

    def finish(self, monitor: Monitor, success: bool, error: str | None = None) -> None:
        if success:
            delay = monitor.every_minutes
            fails = 0
        else:
            fails = monitor.fail_count + 1
            delay = min(monitor.every_minutes * (2**fails), 1440)
        with self._lock:
            self._con.execute(
                "UPDATE monitors SET running=0, lease_until=NULL, fail_count=?, last_error=?, next_run_at=? WHERE id=?",
                (fails, error, _iso(_now() + timedelta(minutes=delay)), monitor.id),
            )
            self._con.commit()

    def schedule_next(self, monitor: Monitor, run_id: str | None) -> None:
        nxt = _now() + timedelta(minutes=monitor.every_minutes)
        with self._lock:
            self._con.execute(
                "UPDATE monitors SET last_run_at=?, last_run_id=COALESCE(?, last_run_id), next_run_at=?, "
                "running=0, lease_until=NULL WHERE id=?",
                (_iso(_now()), run_id, _iso(nxt), monitor.id),
            )
            self._con.commit()

    def add_alert(
        self,
        monitor: Monitor,
        kind: str,
        summary: str,
        details: dict,
        *,
        delivered: bool = False,
        delivery_error: str | None = None,
    ) -> str:
        alert_id = uuid.uuid4().hex
        with self._lock:
            self._con.execute(
                "INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    alert_id,
                    monitor.id,
                    monitor.case_id,
                    _iso(_now()),
                    kind,
                    summary,
                    json.dumps(details, ensure_ascii=False),
                    0,
                    int(delivered),
                    delivery_error,
                ),
            )
            self._con.commit()
        return alert_id

    def _alert_where(
        self,
        case_id: str | None,
        include_acked: bool,
        before: tuple[str, str] | None = None,
    ) -> tuple[str, list[object]]:
        clauses = []
        args: list[object] = []
        if case_id:
            clauses.append("case_id=?")
            args.append(case_id)
        if not include_acked:
            clauses.append("acked=0")
        if before:
            clauses.append("(created_at < ? OR (created_at = ? AND id < ?))")
            args.extend([before[0], before[0], before[1]])
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, args

    def count_alerts(
        self,
        case_id: str | None = None,
        include_acked: bool = True,
        before: tuple[str, str] | None = None,
    ) -> int:
        where, args = self._alert_where(case_id, include_acked, before)
        with self._lock:
            row = self._con.execute("SELECT COUNT(*) FROM alerts" + where, args).fetchone()
        return int(row[0])

    def alerts(
        self,
        case_id: str | None = None,
        include_acked: bool = True,
        limit: int = 100,
        before: tuple[str, str] | None = None,
        offset: int = 0,
    ) -> list[dict]:
        where, args = self._alert_where(case_id, include_acked, before)
        sql = "SELECT * FROM alerts" + where + " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
        args.extend([limit, max(0, offset)])
        with self._lock:
            rows = self._con.execute(sql, args).fetchall()
        return [
            {
                "id": r[0],
                "monitor_id": r[1],
                "case_id": r[2],
                "created_at": r[3],
                "kind": r[4],
                "summary": r[5],
                "details": json.loads(r[6]),
                "acked": bool(r[7]),
                "delivered": bool(r[8]),
                "delivery_error": r[9],
            }
            for r in rows
        ]

    def page_alerts(
        self,
        *,
        include_acked: bool = True,
        limit: int = 100,
        cursor: str | None = None,
        offset: int = 0,
        case_id: str | None = None,
    ) -> Page:
        scope = f"alerts:case={case_id or '-'}:acked={int(include_acked)}"
        total = self.count_alerts(case_id, include_acked)
        marker = decode_cursor(cursor, scope) if cursor else None
        start = self.count_alerts(case_id, include_acked, before=marker) if marker else min(max(0, offset), total)
        rows = self.alerts(
            case_id,
            include_acked,
            limit=limit + 1,
            before=marker,
            offset=0 if marker else start,
        )
        return page_from(
            rows,
            key=lambda alert: (str(alert["created_at"]), str(alert["id"])),
            scope=scope,
            limit=limit,
            total=total,
            offset=start,
        )

    def ack(self, alert_id: str) -> None:
        with self._lock:
            self._con.execute("UPDATE alerts SET acked=1 WHERE id=?", (alert_id,))
            self._con.commit()

    def ack_all(self, case_id: str | None = None) -> int:
        with self._lock:
            if case_id:
                cur = self._con.execute("UPDATE alerts SET acked=1 WHERE acked=0 AND case_id=?", (case_id,))
            else:
                cur = self._con.execute("UPDATE alerts SET acked=1 WHERE acked=0")
            self._con.commit()
        return int(cur.rowcount)

    def _mark_delivery(self, alert_id: str, delivered: bool, error: str | None) -> None:
        with self._lock:
            self._con.execute(
                "UPDATE alerts SET delivered=?, delivery_error=? WHERE id=?", (int(delivered), error, alert_id)
            )
            self._con.commit()


@dataclass
class Dependencies:
    config: Config
    http: HttpClient
    cache: Cache
    health: HealthStore
    registry: Registry
    auth: AuthStore
    runs: RunStore
    graph: GraphStore
    cases: CaseStore
    monitors: MonitorStore


def _provider_result(kind: str, target: str, scope: Scope, deps: Dependencies) -> Result:
    provider_name = "buckets" if kind == "buckets" else "username"
    target_type = "domain" if kind == "buckets" else "username"
    provider = deps.registry.get(provider_name)
    result = Result(schema="deniz.result/1", module=f"monitor.{kind}", provider=provider_name,
                    target=Target(type=target_type, value=target))  # type: ignore[arg-type]
    ctx = Context(http=deps.http, scope=scope, auth=deps.auth)
    try:
        for item in provider(deps.http).run(result.target, ctx):
            result.add(item)
    except DenizError as exc:
        result.error(exc.kind.value, str(exc), provider=provider_name)
    return result


def execute(monitor: Monitor, deps: Dependencies) -> dict:
    case = deps.cases.get(monitor.case_id)
    scope = case.scope()
    if monitor.kind == "domain":
        result = run_domain(
            monitor.target,
            config=deps.config,
            http=deps.http,
            cache=deps.cache,
            health=deps.health,
            registry=deps.registry,
            auth=deps.auth,
            scope=scope,
        )
        result.module = "monitor.domain"
    elif monitor.kind == "vuln":
        result = run_vuln(
            monitor.target,
            config=deps.config,
            http=deps.http,
            cache=deps.cache,
            health=deps.health,
            registry=deps.registry,
            auth=deps.auth,
        )
        result.module = "monitor.vuln"
    else:
        result = _provider_result(monitor.kind, monitor.target, scope, deps)
        result.module = f"monitor.{monitor.kind}"

    run = deps.runs.begin(result.module)
    result.run_id = run.run_id
    deps.runs.write(run, result)
    deps.graph.record(result)
    deps.cases.add_run(case.id, run.run_id)

    alert = None
    if monitor.last_run_id:
        delta = deps.graph.diff_typed(monitor.last_run_id, run.run_id)
        primary = PRIMARY[monitor.kind]
        added = [row for row in delta["added"] if row["type"] == primary]
        removed = [row for row in delta["removed"] if row["type"] == primary]
        if added or (monitor.alert_removed and removed):
            summary = f"{len(added)} new {primary}" + (f", {len(removed)} gone" if removed else "")
            details = {"added": added[:200], "removed": removed[:200], "run_id": run.run_id, "path": str(run.path)}
            alert_id = deps.monitors.add_alert(monitor, "delta", summary, details)
            alert = {"id": alert_id, "summary": summary, "details": details}
            _deliver(monitor, alert_id, summary, details, deps)
    deps.monitors.mark_run(monitor, run.run_id)
    return {"run_id": run.run_id, "counts": result.summary(), "errors": len(result.errors), "alert": alert}


def run_due(deps: Dependencies, limit: int = 20) -> list[dict]:
    out = []
    for monitor in deps.monitors.claim_due(limit):
        try:
            result = execute(monitor, deps)
            deps.monitors.finish(monitor, True)
            out.append({"monitor": monitor.id, "kind": monitor.kind, "target": monitor.target, **result})
        except Exception as exc:  # one broken monitor must not stop the tick
            message = f"{type(exc).__name__}: {exc}"
            deps.monitors.add_alert(monitor, "failure", message, {})
            deps.monitors.finish(monitor, False, message)
            out.append({"monitor": monitor.id, "error": str(exc)})
    return out


def _deliver(monitor: Monitor, alert_id: str, summary: str, details: dict, deps: Dependencies) -> None:
    import os

    url = os.environ.get("DENIZ_WEBHOOK_URL")
    if not url:
        return
    style = os.environ.get("DENIZ_WEBHOOK_STYLE", "generic").lower()
    payload: dict[str, object]
    if style == "slack":
        payload = {"text": f"[deniz] {summary} (case {monitor.case_id}, monitor {monitor.id})"}
    elif style == "discord":
        payload = {"content": f"[deniz] {summary} (case {monitor.case_id})"}
    else:
        payload = {"alert": alert_id, "case": monitor.case_id, "monitor": monitor.id, "summary": summary, "details": details}
    try:
        resp = httpx.post(url, json=payload, timeout=10)
        if resp.status_code >= 300:
            raise httpx.HTTPError(f"HTTP {resp.status_code}")
    except httpx.HTTPError as exc:
        deps.monitors._mark_delivery(alert_id, False, str(exc))
    else:
        deps.monitors._mark_delivery(alert_id, True, None)



