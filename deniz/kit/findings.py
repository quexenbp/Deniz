"""Derive findings from observations.

Findings are the analyst-facing layer: one row per actionable condition, with
severity, evidence pointer and acknowledgement state. Raw observations stay
untouched.
"""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .db import Database, connect
from .graph import GraphStore

HIGH_PORTS = {21, 23, 3306, 3389, 5432, 6379, 9200}


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class Finding:
    id: str
    case_id: str
    key: str
    kind: str
    severity: str
    title: str
    value: str
    run_id: str
    created_at: str
    acked: bool = False
    severity_override: str | None = None
    note: str | None = None


def _severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def derive(case_id: str, run_ids: list[str], graph: GraphStore) -> list[tuple]:
    """Return finding tuples for a case. Pure computation, no writes."""
    if not run_ids:
        return []
    placeholders = ",".join("?" for _ in run_ids)
    with graph._lock:
        rows = graph._con.execute(
            f"SELECT e.type, e.value, o.confidence, o.attrs, o.run_id FROM observations o "
            f"JOIN entities e ON e.id=o.entity_id WHERE o.run_id IN ({placeholders})",
            run_ids,
        ).fetchall()
    out: list[tuple] = []

    def add(kind: str, severity: str, title: str, value: str, run_id: str) -> None:
        out.append((kind, severity, title, value, run_id))

    for kind, value, confidence, attrs_json, run_id in rows:
        attrs = json.loads(attrs_json or "{}")
        if kind == "takeover":
            severity = "high" if confidence >= 0.8 else "medium" if confidence >= 0.5 else "low"
            add("takeover", severity, f"Takeover candidate: {value}", value, run_id)
        elif kind == "cve":
            score = attrs.get("cvss")
            add("cve", _severity_from_cvss(float(score) if score is not None else None), f"{value} (CVSS {score})", value, run_id)
        elif kind == "bucket":
            if attrs.get("public_listing"):
                add("bucket_public", "high", f"Public bucket listing: {value}", value, run_id)
            else:
                add("bucket_exists", "info", f"Bucket exists: {value}", value, run_id)
        elif kind == "breach":
            classes = [str(c).lower() for c in attrs.get("data_classes", [])]
            severity = "high" if "passwords" in classes else "medium"
            add("breach", severity, f"Breach: {value}", value, run_id)
        elif kind == "url" and attrs.get("kind") == "path":
            value_low = str(value).lower()
            if any(marker in value_low for marker in (".git", ".env", ".ds_store", ".svn", "backup", "dump.sql", "db.sql")):
                add("exposed_file", "high", f"Exposed sensitive path: {value}", value, run_id)
            elif any(marker in value_low for marker in ("swagger", "openapi", "phpinfo", "server-status")):
                add("exposed_debug", "medium", f"Exposed debug/API path: {value}", value, run_id)
        elif kind == "url" and attrs.get("kind") == "security_txt":
            add("security_txt", "info", "security.txt published", value, run_id)
        elif kind == "url" and attrs.get("kind") == "sitemap":
            add("sitemap", "info", "Sitemap published", value, run_id)
        elif kind == "service":
            port = int(attrs.get("port") or 0)
            if port in HIGH_PORTS:
                add("exposed_service", "medium", f"Exposed service: {value}", value, run_id)
        elif kind == "note" and attrs.get("record") == "SPF":
            if attrs.get("all") in ("missing", "+all", "?all", "none"):
                add("spf_weak", "medium", f"Weak SPF ({attrs.get('all')})", value, run_id)
        elif kind == "note" and attrs.get("record") == "DMARC":
            if attrs.get("policy") in ("missing", "none"):
                add("dmarc_weak", "medium", f"Weak DMARC ({attrs.get('policy')})", value, run_id)
        elif kind == "note" and attrs.get("record") == "RDAP":
            if attrs.get("risky_status"):
                add("domain_status", "high", f"Risky domain status: {', '.join(attrs['risky_status'])}", value, run_id)
        elif kind == "note" and attrs.get("record") == "RDAP_EXPIRY":
            days = int(attrs.get("days") or 9999)
            if days < 30:
                add("domain_expiry", "high" if days < 7 else "medium", f"Domain expires in {days} days", value, run_id)
        elif kind == "note" and attrs.get("record") == "DNSBL":
            if attrs.get("listed"):
                add("dnsbl_listed", "medium", f"Listed on {len(attrs['listed'])} DNSBL(s)", value, run_id)
        elif kind == "note" and attrs.get("record") == "INTERNETDB":
            vulns = attrs.get("vulns") or []
            if vulns:
                add("known_vuln", "high", f"InternetDB known vulns: {len(vulns)}", value, run_id)
        elif kind == "note" and attrs.get("record") == "header" and not attrs.get("present"):
            header = str(attrs.get("header", ""))
            severity = "low" if header in ("content-security-policy", "strict-transport-security", "x-frame-options") else "info"
            add("header_missing", severity, f"Missing {header}", value, run_id)
        elif kind == "note" and attrs.get("null_mx"):
            add("null_mx", "info", "Null MX (no mail)", value, run_id)
    return out


class FindingStore:
    def __init__(self, path: Path | str) -> None:
        self._lock = threading.Lock()
        self.db: Database = connect(path)
        self._con = self.db._raw
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                key TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                value TEXT NOT NULL,
                run_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                acked INTEGER NOT NULL DEFAULT 0,
                severity_override TEXT,
                note TEXT
            )
            """
        )
        self._con.commit()
        self._migrate()

    def _migrate(self) -> None:
        columns = self.db.columns("findings")
        if "severity_override" not in columns:
            self._con.execute("ALTER TABLE findings ADD COLUMN severity_override TEXT")
        if "note" not in columns:
            self._con.execute("ALTER TABLE findings ADD COLUMN note TEXT")
        self._con.commit()

    def refresh(self, case_id: str, run_ids: list[str], graph: GraphStore) -> list[Finding]:
        derived = derive(case_id, run_ids, graph)
        now = _now()
        with self._lock:
            for kind, severity, title, value, run_id in derived:
                key = f"{kind}|{value}"
                row = self._con.execute("SELECT id, severity FROM findings WHERE key=?", (key,)).fetchone()
                if row:
                    self._con.execute(
                        "UPDATE findings SET severity=?, title=?, run_id=? WHERE id=?",
                        (severity, title, run_id, row[0]),
                    )
                else:
                    self._con.execute(
                        "INSERT INTO findings (id,case_id,key,kind,severity,title,value,run_id,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                        (uuid.uuid4().hex, case_id, key, kind, severity, title, value, run_id, now),
                    )
            self._con.commit()
        return self.list(case_id)

    def list(self, case_id: str, include_acked: bool = True) -> list[Finding]:
        sql = (
            "SELECT id, case_id, key, kind, severity, title, value, run_id, created_at, acked, "
            "severity_override, note FROM findings WHERE case_id=?"
        )
        if not include_acked:
            sql += " AND acked=0"
        sql += (
            " ORDER BY CASE COALESCE(severity_override, severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
            " WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, created_at DESC"
        )
        with self._lock:
            rows = self._con.execute(sql, (case_id,)).fetchall()
        return [
            Finding(
                id=row[0],
                case_id=row[1],
                key=row[2],
                kind=row[3],
                severity=row[4],
                title=row[5],
                value=row[6],
                run_id=row[7],
                created_at=row[8],
                acked=bool(row[9]),
                severity_override=row[10],
                note=row[11],
            )
            for row in rows
        ]

    def _resolve(self, finding_id: str) -> str:
        with self._lock:
            row = self._con.execute("SELECT id FROM findings WHERE id=?", (finding_id,)).fetchone()
            if row:
                return str(row[0])
            rows = self._con.execute("SELECT id FROM findings WHERE id LIKE ?", (finding_id + "%",)).fetchall()
        if len(rows) != 1:
            raise KeyError(finding_id)
        return str(rows[0][0])

    def set(self, finding_id: str, severity: str | None = None, note: str | None = None) -> None:
        allowed = {"critical", "high", "medium", "low", "info"}
        if severity is not None and severity not in allowed:
            raise ValueError(f"bad severity: {severity}")
        resolved = self._resolve(finding_id)
        with self._lock:
            if severity is not None:
                self._con.execute("UPDATE findings SET severity_override=? WHERE id=?", (severity, resolved))
            if note is not None:
                self._con.execute("UPDATE findings SET note=? WHERE id=?", (note, resolved))
            self._con.commit()

    def ack(self, finding_id: str) -> None:
        resolved = self._resolve(finding_id)
        with self._lock:
            self._con.execute("UPDATE findings SET acked=1 WHERE id=?", (resolved,))
            self._con.commit()

    def ack_all(self, case_id: str) -> int:
        with self._lock:
            cur = self._con.execute("UPDATE findings SET acked=1 WHERE case_id=? AND acked=0", (case_id,))
            self._con.commit()
        return int(cur.rowcount)

    def stats(self, case_id: str) -> dict[str, int]:
        with self._lock:
            rows = self._con.execute(
                "SELECT COALESCE(severity_override, severity), COUNT(*) FROM findings WHERE case_id=? AND acked=0 GROUP BY 1",
                (case_id,),
            ).fetchall()
        return {row[0]: int(row[1]) for row in rows}

    def global_stats(self) -> dict[str, int]:
        with self._lock:
            rows = self._con.execute(
                "SELECT COALESCE(severity_override, severity), COUNT(*) FROM findings WHERE acked=0 GROUP BY 1"
            ).fetchall()
        return {row[0]: int(row[1]) for row in rows}

    def delete_case(self, case_id: str) -> int:
        with self._lock:
            deleted = self._con.execute("DELETE FROM findings WHERE case_id=?", (case_id,)).rowcount
            self._con.commit()
        return int(deleted)

