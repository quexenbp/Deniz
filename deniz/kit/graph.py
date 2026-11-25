# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Entity / observation / edge graph.

The graph is the durable part of a case: runs decay, but who resolves to what
should survive. Kept in SQLite; Postgres is a later concern.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from .db import Database, connect
from .models import Result

RELATIONS = {
    "hostname": "has_host",
    "ip": "resolves_to",
    "url": "serves",
    "title": "has_title",
    "certificate": "certificate_of",
    "technology": "uses",
    "cve": "affects",
    "breach": "leaked_in",
    "bucket": "has_bucket",
    "note": "noted",
    "service": "listens",
    "takeover": "takeover_risk",
}


class GraphStore:
    def __init__(self, path: Path | str) -> None:
        self._lock = threading.Lock()
        self.db: Database = connect(path)
        self._con = self.db._raw
        if self.db.dialect == "sqlite":
            self._con.execute("PRAGMA foreign_keys=ON")
        serial = "BIGSERIAL PRIMARY KEY" if self.db.dialect == "postgres" else "INTEGER PRIMARY KEY"
        self.db.executescript(
            f"""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                module TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_value TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS entities (
                id {serial},
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(type, value)
            );
            CREATE TABLE IF NOT EXISTS observations (
                id {serial},
                run_id TEXT NOT NULL REFERENCES runs(run_id),
                entity_id INTEGER NOT NULL REFERENCES entities(id),
                provider TEXT,
                confidence REAL NOT NULL,
                attrs TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS edges (
                id {serial},
                run_id TEXT NOT NULL REFERENCES runs(run_id),
                src INTEGER NOT NULL REFERENCES entities(id),
                dst INTEGER NOT NULL REFERENCES entities(id),
                relation TEXT NOT NULL,
                confidence REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_obs_entity ON observations(entity_id);
            CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src);
            CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst);
            """
        )
        self._con.commit()

    def _upsert_entity(self, kind: str, value: str, seen: str) -> int:
        row = self._con.execute("SELECT id FROM entities WHERE type=? AND value=?", (kind, value)).fetchone()
        if row:
            lo, hi = ("LEAST", "GREATEST") if self.db.dialect == "postgres" else ("MIN", "MAX")
            self._con.execute(
                f"UPDATE entities SET first_seen={lo}(first_seen, ?), last_seen={hi}(last_seen, ?) WHERE id=?",
                (seen, seen, row[0]),
            )
            return int(row[0])
        cur = self._con.execute(
            "INSERT INTO entities(type, value, first_seen, last_seen) VALUES (?,?,?,?) RETURNING id",
            (kind, value, seen, seen),
        )
        return int(cur.fetchone()[0])

    def record(self, result: Result) -> None:
        seen = result.observed_at.isoformat()
        with self._lock:
            self._con.execute(
                "INSERT INTO runs(run_id, module, target_type, target_value, observed_at) VALUES (?,?,?,?,?) "
                "ON CONFLICT(run_id) DO UPDATE SET module=excluded.module, target_type=excluded.target_type, "
                "target_value=excluded.target_value, observed_at=excluded.observed_at",
                (result.run_id, result.module, result.target.type, result.target.value, seen),
            )
            target_id = self._upsert_entity(result.target.type, result.target.value, seen)
            for item in result.items:
                entity_id = self._upsert_entity(item.type, item.value, seen)
                self._con.execute(
                    "INSERT INTO observations(run_id, entity_id, provider, confidence, attrs, observed_at) VALUES (?,?,?,?,?,?)",
                    (
                        result.run_id,
                        entity_id,
                        item.sources[0].provider if item.sources else None,
                        item.confidence,
                        json.dumps(item.attrs, ensure_ascii=False),
                        seen,
                    ),
                )
                source_id = target_id
                host = item.attrs.get("host")
                if host and item.type != "hostname":
                    source_id = self._upsert_entity("hostname", str(host), seen)
                relation = RELATIONS.get(item.type, "observed")
                self._con.execute(
                    "INSERT INTO edges(run_id, src, dst, relation, confidence) VALUES (?,?,?,?,?)",
                    (result.run_id, source_id, entity_id, relation, item.confidence),
                )
            self._con.commit()

    def entities(self, kind: str | None = None, limit: int = 100, run_ids: list[str] | None = None) -> list[dict]:
        sql = "SELECT DISTINCT e.type, e.value, e.first_seen, e.last_seen FROM entities e"
        clauses = []
        args: list[object] = []
        if run_ids is not None:
            if not run_ids:
                return []
            placeholders = ",".join("?" for _ in run_ids)
            sql += " JOIN observations o ON o.entity_id=e.id"
            clauses.append(f"o.run_id IN ({placeholders})")
            args.extend(run_ids)
        if kind:
            clauses.append("e.type=?")
            args.append(kind)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY e.last_seen DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._con.execute(sql, args).fetchall()
        return [{"type": r[0], "value": r[1], "first_seen": r[2], "last_seen": r[3]} for r in rows]

    def show(self, value: str, run_ids: list[str] | None = None) -> dict:
        clause = ""
        args_tail: list[object] = []
        if run_ids is not None:
            placeholders = ",".join("?" for _ in run_ids) or "''"
            clause = f" AND o.run_id IN ({placeholders})"
            args_tail.extend(run_ids)
        with self._lock:
            entity = self._con.execute(
                "SELECT id, type, value, first_seen, last_seen FROM entities WHERE value=?", (value,)
            ).fetchone()
            if not entity:
                return {}
            observations = self._con.execute(
                "SELECT o.provider, o.confidence, o.attrs, o.observed_at FROM observations o WHERE o.entity_id=?"
                + clause
                + " ORDER BY o.id DESC LIMIT 100",
                (entity[0], *args_tail),
            ).fetchall()
            edge_clause = clause.replace("o.run_id", "ed.run_id")
            incoming = self._con.execute(
                "SELECT e.value, ed.relation FROM edges ed JOIN entities e ON e.id=ed.src WHERE ed.dst=?"
                + edge_clause
                + " LIMIT 100",
                (entity[0], *args_tail),
            ).fetchall()
            outgoing = self._con.execute(
                "SELECT e.value, ed.relation FROM edges ed JOIN entities e ON e.id=ed.dst WHERE ed.src=?"
                + edge_clause
                + " LIMIT 100",
                (entity[0], *args_tail),
            ).fetchall()
        return {
            "entity": {"type": entity[1], "value": entity[2], "first_seen": entity[3], "last_seen": entity[4]},
            "observations": [
                {"provider": o[0], "confidence": o[1], "attrs": json.loads(o[2]), "at": o[3]} for o in observations
            ],
            "incoming": [{"value": v, "relation": r} for v, r in incoming],
            "outgoing": [{"value": v, "relation": r} for v, r in outgoing],
        }

    def diff(self, run_a: str, run_b: str) -> dict[str, list[str]]:
        def values(run: str) -> set[str]:
            with self._lock:
                rows = self._con.execute(
                    "SELECT DISTINCT e.value FROM observations o JOIN entities e ON e.id=o.entity_id WHERE o.run_id=?",
                    (run,),
                ).fetchall()
            return {r[0] for r in rows}

        before, after = values(run_a), values(run_b)
        return {"added": sorted(after - before), "removed": sorted(before - after)}

    def diff_typed(self, run_a: str, run_b: str) -> dict[str, list[dict[str, str]]]:
        def rows(run: str) -> set[tuple[str, str]]:
            with self._lock:
                data = self._con.execute(
                    "SELECT DISTINCT e.type, e.value FROM observations o JOIN entities e ON e.id=o.entity_id WHERE o.run_id=?",
                    (run,),
                ).fetchall()
            return {(r[0], r[1]) for r in data}

        before, after = rows(run_a), rows(run_b)
        return {
            "added": [{"type": t, "value": v} for t, v in sorted(after - before)],
            "removed": [{"type": t, "value": v} for t, v in sorted(before - after)],
        }

    def stats(self) -> dict[str, int]:
        with self._lock:
            entities = self._con.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
            observations = self._con.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
            edges = self._con.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        return {"entities": int(entities), "observations": int(observations), "edges": int(edges)}

    def export_graph(self, run_ids: list[str]) -> dict:
        if not run_ids:
            return {"nodes": [], "edges": []}
        placeholders = ",".join("?" for _ in run_ids)
        with self._lock:
            nodes = self._con.execute(
                "SELECT DISTINCT e.id, e.type, e.value FROM observations o JOIN entities e ON e.id=o.entity_id "
                f"WHERE o.run_id IN ({placeholders})",
                run_ids,
            ).fetchall()
            edges = self._con.execute(
                "SELECT DISTINCT ed.src, ed.dst, ed.relation, ed.confidence FROM edges ed "
                f"WHERE ed.run_id IN ({placeholders})",
                run_ids,
            ).fetchall()
        return {
            "nodes": [{"id": n[0], "type": n[1], "value": n[2]} for n in nodes],
            "edges": [{"source": e[0], "target": e[1], "relation": e[2], "confidence": e[3]} for e in edges],
        }

    def search(self, run_ids: list[str], text: str, limit: int = 100) -> list[dict]:
        if not run_ids or not text.strip():
            return []
        placeholders = ",".join("?" for _ in run_ids)
        like = f"%{text.strip()}%"
        with self._lock:
            rows = self._con.execute(
                "SELECT e.type, e.value, MIN(o.provider), MAX(o.observed_at) "
                "FROM observations o JOIN entities e ON e.id=o.entity_id "
                f"WHERE o.run_id IN ({placeholders}) AND (e.value LIKE ? OR o.attrs LIKE ?) "
                "GROUP BY e.id ORDER BY MAX(o.observed_at) DESC LIMIT ?",
                (*run_ids, like, like, limit),
            ).fetchall()
        return [{"type": r[0], "value": r[1], "provider": r[2], "seen": r[3]} for r in rows]

    def timeline(self, run_ids: list[str]) -> list[dict]:
        if not run_ids:
            return []
        placeholders = ",".join("?" for _ in run_ids)
        with self._lock:
            rows = self._con.execute(
                "SELECT r.run_id, r.observed_at, r.module, COUNT(DISTINCT o.entity_id) "
                f"FROM runs r LEFT JOIN observations o ON o.run_id=r.run_id WHERE r.run_id IN ({placeholders}) "
                "GROUP BY r.run_id ORDER BY r.observed_at",
                run_ids,
            ).fetchall()
        out = []
        previous: str | None = None
        for run_id, observed_at, module, total in rows:
            added = 0
            if previous:
                added = len(self.diff_typed(previous, run_id)["added"])
            out.append({"run_id": run_id, "observed_at": observed_at, "module": module, "total": int(total), "new": added})
            previous = run_id
        return out

    def drop_runs(self, run_ids: list[str]) -> dict[str, int]:
        if not run_ids:
            return {"observations": 0, "edges": 0, "runs": 0, "entities": 0}
        placeholders = ",".join("?" for _ in run_ids)
        with self._lock:
            obs = self._con.execute(
                f"DELETE FROM observations WHERE run_id IN ({placeholders})", run_ids
            ).rowcount
            edges = self._con.execute(f"DELETE FROM edges WHERE run_id IN ({placeholders})", run_ids).rowcount
            runs = self._con.execute(f"DELETE FROM runs WHERE run_id IN ({placeholders})", run_ids).rowcount
            entities = self._con.execute(
                "DELETE FROM entities WHERE id NOT IN (SELECT DISTINCT entity_id FROM observations) "
                "AND id NOT IN (SELECT src FROM edges) AND id NOT IN (SELECT dst FROM edges)"
            ).rowcount
            self._con.commit()
        return {
            "observations": int(obs),
            "edges": int(edges),
            "runs": int(runs),
            "entities": int(entities),
        }

    def prune(self, days: int = 90) -> dict[str, int]:
        from datetime import UTC, datetime, timedelta

        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        with self._lock:
            obs = self._con.execute("DELETE FROM observations WHERE observed_at < ?", (cutoff,)).rowcount
            edges = self._con.execute(
                "DELETE FROM edges WHERE run_id IN (SELECT run_id FROM runs WHERE observed_at < ?)", (cutoff,)
            ).rowcount
            runs = self._con.execute("DELETE FROM runs WHERE observed_at < ?", (cutoff,)).rowcount
            entities = self._con.execute(
                "DELETE FROM entities WHERE id NOT IN (SELECT DISTINCT entity_id FROM observations) "
                "AND id NOT IN (SELECT src FROM edges) AND id NOT IN (SELECT dst FROM edges)"
            ).rowcount
            self._con.commit()
        return {"observations": obs, "edges": edges, "runs": runs, "entities": entities}


