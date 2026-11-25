# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Cases: a durable container for runs, scope and notes.

A run answers one question. A case is the investigation. Cases store scope so
every run inside one case is evaluated against the same allow/deny list.
"""

from __future__ import annotations

import html
import json
import shutil
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .db import Database, connect
from .findings import FindingStore
from .graph import GraphStore
from .models import Result
from .privacy import redact_result, redact_text
from .report import LABELS, render_html, render_stix
from .scope import Scope
from .store import RunStore, write_run_files


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class Case:
    id: str
    name: str
    created_at: str
    updated_at: str
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    notes: list[dict] = field(default_factory=list)
    runs: list[str] = field(default_factory=list)
    archived: bool = False
    archived_at: str | None = None
    tags: list[str] = field(default_factory=list)

    def scope(self) -> Scope:
        return Scope(allow=self.allow, deny=self.deny)


class CaseStore:
    def __init__(self, path: Path | str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.db: Database = connect(path)
        self._con = self.db._raw
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                allow_json TEXT NOT NULL,
                deny_json TEXT NOT NULL,
                notes_json TEXT NOT NULL,
                archived INTEGER NOT NULL DEFAULT 0,
                archived_at TEXT,
                tags_json TEXT NOT NULL DEFAULT '[]'
            );
            CREATE TABLE IF NOT EXISTS case_runs (
                case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                run_id TEXT NOT NULL,
                added_at TEXT NOT NULL,
                PRIMARY KEY (case_id, run_id)
            );
            """
        )
        self._con.commit()
        self._migrate()

    def _migrate(self) -> None:
        columns = self.db.columns("cases")
        if "archived" not in columns:
            self._con.execute("ALTER TABLE cases ADD COLUMN archived INTEGER NOT NULL DEFAULT 0")
        if "archived_at" not in columns:
            self._con.execute("ALTER TABLE cases ADD COLUMN archived_at TEXT")
        if "tags_json" not in columns:
            self._con.execute("ALTER TABLE cases ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]'")
        self._con.commit()

    def create(self, name: str, allow: list[str] | None = None, deny: list[str] | None = None, tags: list[str] | None = None) -> Case:
        name = name.strip()
        if not name:
            raise ValueError("case name is empty")
        case = Case(id=uuid.uuid4().hex, name=name, created_at=_now(), updated_at=_now(), allow=allow or [], deny=deny or [], tags=tags or [])
        with self._lock:
            try:
                self._con.execute(
                    "INSERT INTO cases (id,name,created_at,updated_at,allow_json,deny_json,notes_json,tags_json) VALUES (?,?,?,?,?,?,?,?)",
                    (case.id, case.name, case.created_at, case.updated_at, json.dumps(case.allow), json.dumps(case.deny), "[]", json.dumps(case.tags)),
                )
            except Exception as exc:
                if "unique" in str(exc).lower():
                    raise ValueError(f"case already exists: {name}") from exc
                raise
            self._con.commit()
        return case

    def get(self, ref: str) -> Case:
        ref = ref.strip()
        with self._lock:
            row = self._con.execute("SELECT * FROM cases WHERE id=? OR name=?", (ref, ref)).fetchone()
            if row is None:
                matches = self._con.execute("SELECT * FROM cases WHERE id LIKE ?", (ref + "%",)).fetchall()
                row = matches[0] if len(matches) == 1 else None
            if row is None:
                raise KeyError(ref)
            runs = [r[0] for r in self._con.execute("SELECT run_id FROM case_runs WHERE case_id=? ORDER BY added_at", (row[0],))]
        return Case(
            id=row[0],
            name=row[1],
            created_at=row[2],
            updated_at=row[3],
            allow=json.loads(row[4]),
            deny=json.loads(row[5]),
            notes=json.loads(row[6]),
            runs=runs,
            archived=bool(row[7]),
            archived_at=row[8],
            tags=json.loads(row[9] or "[]"),
        )

    def list_cases(self, include_archived: bool = False) -> list[Case]:
        with self._lock:
            sql = "SELECT id FROM cases"
            if not include_archived:
                sql += " WHERE archived=0"
            sql += " ORDER BY updated_at DESC"
            rows = self._con.execute(sql).fetchall()
        return [self.get(row[0]) for row in rows]

    def archive(self, ref: str) -> Case:
        case = self.get(ref)
        with self._lock:
            self._con.execute("UPDATE cases SET archived=1, archived_at=?, updated_at=? WHERE id=?", (_now(), _now(), case.id))
            self._con.commit()
        return self.get(case.id)

    def unarchive(self, ref: str) -> Case:
        case = self.get(ref)
        with self._lock:
            self._con.execute("UPDATE cases SET archived=0, archived_at=NULL, updated_at=? WHERE id=?", (_now(), case.id))
            self._con.commit()
        return self.get(case.id)

    def delete(self, ref: str) -> None:
        case = self.get(ref)
        with self._lock:
            self._con.execute("DELETE FROM case_runs WHERE case_id=?", (case.id,))
            self._con.execute("DELETE FROM cases WHERE id=?", (case.id,))
            self._con.commit()

    def add_run(self, ref: str, run_id: str) -> Case:
        case = self.get(ref)
        with self._lock:
            self._con.execute(
                "INSERT INTO case_runs VALUES (?,?,?) ON CONFLICT DO NOTHING", (case.id, run_id, _now())
            )
            self._con.execute("UPDATE cases SET updated_at=? WHERE id=?", (_now(), case.id))
            self._con.commit()
        return self.get(case.id)

    def add_tag(self, ref: str, tag: str) -> Case:
        case = self.get(ref)
        tag = tag.strip().lower()
        tags = sorted({*case.tags, tag}) if tag else case.tags
        with self._lock:
            self._con.execute("UPDATE cases SET tags_json=?, updated_at=? WHERE id=?", (json.dumps(tags), _now(), case.id))
            self._con.commit()
        return self.get(case.id)

    def remove_tag(self, ref: str, tag: str) -> Case:
        case = self.get(ref)
        tag = tag.strip().lower()
        with self._lock:
            self._con.execute(
                "UPDATE cases SET tags_json=?, updated_at=? WHERE id=?",
                (json.dumps([t for t in case.tags if t != tag]), _now(), case.id),
            )
            self._con.commit()
        return self.get(case.id)

    def add_note(self, ref: str, text: str) -> Case:
        case = self.get(ref)
        notes = [*case.notes, {"at": _now(), "text": text.strip()}]
        with self._lock:
            self._con.execute(
                "UPDATE cases SET notes_json=?, updated_at=? WHERE id=?",
                (json.dumps(notes), _now(), case.id),
            )
            self._con.commit()
        return self.get(case.id)

    def export(
        self,
        ref: str,
        run_store: RunStore,
        out_dir: Path,
        findings: FindingStore | None = None,
        graph: GraphStore | None = None,
        as_zip: bool = False,
        redact: bool = False,
        lang: str = "en",
    ) -> Path:
        case = self.get(ref)
        out_dir.mkdir(parents=True, exist_ok=True)
        runs_dir = out_dir / "runs"
        runs_dir.mkdir(exist_ok=True)
        results: list[Result] = []
        entries = []
        for run_id in case.runs:
            try:
                src = run_store.resolve(run_id)
            except FileNotFoundError:
                continue
            result = Result.model_validate_json((src / "result.json").read_text(encoding="utf-8"))
            if redact:
                result = redact_result(result)
            results.append(result)
            dst = runs_dir / src.name
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
            if redact:
                write_run_files(dst, result)
            (dst / "report.html").write_text(render_html(result, lang), encoding="utf-8")
            entries.append(
                {
                    "run_id": result.run_id,
                    "module": result.module,
                    "target": result.target.value,
                    "counts": result.summary(),
                    "path": f"runs/{src.name}/report.html",
                }
            )

        findings_rows = findings.list(case.id) if findings else []
        notes = (
            [{"at": note["at"], "text": redact_text(note["text"])} for note in case.notes]
            if redact
            else case.notes
        )
        case_json = {
            "schema": "deniz.case/1",
            "id": case.id,
            "name": case.name,
            "created_at": case.created_at,
            "updated_at": case.updated_at,
            "scope": {"allow": case.allow, "deny": case.deny},
            "notes": notes,
            "runs": entries,
            "tags": case.tags,
            "archived": case.archived,
        }
        (out_dir / "case.json").write_text(json.dumps(case_json, indent=2, ensure_ascii=False), encoding="utf-8")
        (out_dir / "case.stix.json").write_text(
            json.dumps(self._stix(case, results, findings_rows, redact=redact), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        if findings is not None:
            rows = [
                {
                    "kind": f.kind,
                    "severity": f.severity_override or f.severity,
                    "title": redact_text(f.title) if redact else f.title,
                    "value": redact_text(f.value) if redact else f.value,
                    "acked": f.acked,
                    "note": redact_text(f.note) if redact and f.note else f.note,
                }
                for f in findings_rows
            ]
            (out_dir / "findings.json").write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
            case_json["findings"] = rows
            (out_dir / "case.json").write_text(json.dumps(case_json, indent=2, ensure_ascii=False), encoding="utf-8")
        trend = graph.timeline(case.runs) if graph is not None else []
        if trend:
            (out_dir / "trend.json").write_text(json.dumps(trend, indent=2, ensure_ascii=False), encoding="utf-8")
            case_json["trend"] = trend
            (out_dir / "case.json").write_text(json.dumps(case_json, indent=2, ensure_ascii=False), encoding="utf-8")
        (out_dir / "case.html").write_text(
            self._index(case, entries, findings_rows, trend, notes=notes, redact=redact, lang=lang), encoding="utf-8"
        )
        if as_zip:
            archive = Path(shutil.make_archive(str(out_dir), "zip", root_dir=out_dir))
            return archive
        return out_dir

    @staticmethod
    def _stix(case: Case, results: list[Result], findings: list | None = None, redact: bool = False) -> dict:
        objects: dict[str, dict] = {}
        for result in results:
            bundle = render_stix(result)
            for obj in bundle["objects"]:
                objects.setdefault(obj["id"], obj)
        now = _now()
        for finding in findings or []:
            note_id = "note--" + str(uuid.uuid5(uuid.UUID("6f6d6172-7961-6d00-8000-000000000001"), "finding|" + finding.key))
            abstract = redact_text(finding.title) if redact else finding.title
            content = (finding.note or finding.value)
            if redact:
                content = redact_text(content)
            objects.setdefault(
                note_id,
                {
                    "type": "note",
                    "spec_version": "2.1",
                    "id": note_id,
                    "created": now,
                    "modified": now,
                    "abstract": abstract,
                    "content": content,
                    "labels": [finding.severity_override or finding.severity, finding.kind],
                },
            )
        return {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid5(uuid.UUID("6f6d6172-7961-6d00-8000-000000000001"), "case|" + case.id)),
            "objects": list(objects.values()),
        }

    @staticmethod
    def _index(
        case: Case,
        entries: list[dict],
        findings: list,
        trend: list[dict],
        notes: list[dict] | None = None,
        redact: bool = False,
        lang: str = "en",
    ) -> str:
        labels = LABELS.get(lang, LABELS["en"])
        rows = "".join(
            f"<tr><td><a href='{html.escape(e['path'], quote=True)}'>{html.escape(e['run_id'][:12])}</a></td>"
            f"<td>{html.escape(e['module'])}</td><td>{html.escape(e['target'])}</td>"
            f"<td>{html.escape(json.dumps(e['counts']))}</td></tr>"
            for e in entries
        )
        finding_rows = "".join(
            f"<tr><td>{html.escape(f.severity_override or f.severity)}</td>"
            f"<td>{html.escape(redact_text(f.title) if redact else f.title)}</td>"
            f"<td>{html.escape(redact_text(f.note or '') if redact else (f.note or ''))}</td>"
            f"<td>{'yes' if f.acked else 'no'}</td></tr>"
            for f in findings
        )
        selected_notes = notes if notes is not None else case.notes
        notes_html = "".join(f"<li><time>{html.escape(n['at'])}</time> {html.escape(n['text'])}</li>" for n in selected_notes)
        peak = max((t["total"] for t in trend), default=1) or 1
        bars = "".join(
            f"<div><span style='display:inline-block;height:8px;background:#36c;width:{int(t['total'] / peak * 300)}px'></span> "
            f"{html.escape(t['observed_at'][:19])} · {t['total']} (+{t['new']})</div>"
            for t in trend
        )
        return f"""<!doctype html><html lang="{lang}"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>{labels['case']} — {html.escape(case.name)}</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%;margin-bottom:1.5rem}}th,td{{border-bottom:1px solid #ddd;padding:.4rem;text-align:left}}
code{{font-size:.85em}}</style></head><body>
<h1>{html.escape(case.name)}</h1>
<p>{labels['case']} {html.escape(case.id)} · {labels['updated']} {html.escape(case.updated_at)}</p>
<p>{labels['scope']}: allow {html.escape(json.dumps(case.allow))} · deny {html.escape(json.dumps(case.deny))} · {labels['tags']} {html.escape(json.dumps(case.tags))}</p>
<h2>{labels['findings']} ({len(findings)})</h2>
<table><thead><tr><th>{labels['severity']}</th><th>{labels['finding']}</th><th>{labels['note']}</th><th>{labels['acked']}</th></tr></thead><tbody>{finding_rows or f'<tr><td colspan="4">{labels["none"]}</td></tr>'}</tbody></table>
<h2>{labels['timeline']}</h2>
<div>{bars or labels['none']}</div>
<h2>{labels['note']}</h2><ul>{notes_html or f'<li>{labels["none"]}</li>'}</ul>
<h2>{labels['runs']} ({len(entries)})</h2>
<table><thead><tr><th>{labels['run']}</th><th>{labels['module']}</th><th>{labels['target']}</th><th>{labels['counts']}</th></tr></thead><tbody>{rows or f'<tr><td colspan="4">{labels["none"]}</td></tr>'}</tbody></table>
<p><a href="case.json">case.json</a> · <a href="case.stix.json">STIX 2.1</a></p>
</body></html>
"""


