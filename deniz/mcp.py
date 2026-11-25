# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Minimal read-only MCP server over stdio.

Protocol: JSON-RPC 2.0, one object per line. Logs go to stderr so stdout
stays clean. Tools are read-only (domain collection, graph lookup, diffs).
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar

from .kit.cli import _deps, _runtime
from .kit.errors import DenizError
from .kit.models import Result
from .kit.monitors import execute as execute_monitor
from .kit.monitors import run_due
from .kit.pagination import InvalidCursor, paginate
from .kit.pipeline.domain import run_domain, validate_domain
from .kit.pipeline.search import run_search
from .kit.pipeline.social import SITES as SOCIAL_SITES
from .kit.pipeline.social import run_social
from .kit.pipeline.vuln import run_vuln
from .kit.providers.registry import Registry
from .kit.report import write_report
from .kit.store import RunStore

PROTOCOL = "2024-11-05"
SERVER_NAME = "deniz"
SERVER_VERSION = "0.1.0"
FINDING_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

TOOLS = [
    {
        "name": "deniz_domain",
        "description": "Passive CT, DNS, HTTP and lookalike discovery for a domain. Read-only.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "max_hosts": {"type": "integer", "default": 50, "minimum": 1, "maximum": 500},
                "probe": {"type": "boolean", "default": True},
                "typosquat": {"type": "boolean", "default": True},
                "emailauth": {"type": "boolean", "default": True},
                "rdap": {"type": "boolean", "default": True},
                "asn": {"type": "boolean", "default": True},
                "dnsbl": {"type": "boolean", "default": True},
                "tlds": {"type": "boolean", "default": False},
                "entrypoints": {"type": "boolean", "default": True},
                "crawl": {"type": "boolean", "default": False},
                "crawl_regex": {"type": "string", "description": "extract matches from crawled pages"},
                "files": {"type": "boolean", "default": False},
                "dnsbrute": {"type": "boolean", "default": False},
                "discovery": {"type": "boolean", "default": True},
                "urlscan": {"type": "boolean", "default": True},
                "internetdb": {"type": "boolean", "default": True},
                "wayback": {"type": "boolean", "default": True},
                "axfr": {"type": "boolean", "default": False},
                "ports": {"type": "boolean", "default": False},
                "takeover": {"type": "boolean", "default": True},
                "fingerprint": {"type": "boolean", "default": True},
                "case": {"type": "string", "description": "case name or id"},
                "fields": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Observation fields to return (default: type,value,confidence)",
                },
            },
            "required": ["domain"],
            "additionalProperties": False,
        },
    },
    {
        "name": "deniz_providers",
        "description": "List providers with capabilities, auth requirement and health.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "deniz_graph_entity",
        "description": "Look up one entity, its observations and edges.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "value": {"type": "string"},
                "case": {"type": "string", "description": "case name or id"},
            },
            "required": ["value"],
            "additionalProperties": False,
        },
    },
    {
        "name": "deniz_run_diff",
        "description": "Added and removed entities between two runs.",
        "inputSchema": {
            "type": "object",
            "properties": {"run_a": {"type": "string"}, "run_b": {"type": "string"}},
            "required": ["run_a", "run_b"],
            "additionalProperties": False,
        },
    },
    {
        "name": "deniz_vuln",
        "description": "NVD CVE search with EPSS enrichment.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": 20, "minimum": 1, "maximum": 100},
                "case": {"type": "string", "description": "case name or id"},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "deniz_report",
        "description": "Render a stored run as HTML, STIX 2.1 or JSONL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string"},
                "format": {"type": "string", "enum": ["html", "stix", "jsonl", "pdf"], "default": "html"},
                "redact": {"type": "boolean", "default": False, "description": "mask PII in the output"},
                "lang": {"type": "string", "enum": ["en", "tr"], "default": "en"},
            },
            "required": ["run_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "deniz_identity",
        "description": "Username profile enumeration across public sites.",
        "inputSchema": {
            "type": "object",
            "properties": {"username": {"type": "string"}},
            "required": ["username"],
            "additionalProperties": False,
        },
    },
    {
        "name": "deniz_buckets",
        "description": "Cloud bucket existence check (S3, GCS, Azure) for a domain.",
        "inputSchema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
            "additionalProperties": False,
        },
    },
    {
        "name": "deniz_case",
        "description": "List cases, show one, or export it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["list", "show", "export", "search"], "default": "list"},
                "ref": {"type": "string"},
                "value": {"type": "string", "description": "search text"},
                "limit": {"type": "integer", "default": 100, "minimum": 1, "maximum": 500},
                "offset": {"type": "integer", "default": 0, "minimum": 0},
                "cursor": {"type": "string", "description": "next-page token from a previous response"},
                "redact": {"type": "boolean", "default": False, "description": "mask PII in exports"},
                "lang": {"type": "string", "enum": ["en", "tr"], "default": "en"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "deniz_monitor",
        "description": "Manage scheduled monitors and run due ones.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["list", "add", "run", "tick"], "default": "list"},
                "ref": {"type": "string", "description": "case id (add) or monitor id"},
                "kind": {"type": "string", "enum": ["domain", "vuln", "buckets", "identity"]},
                "target": {"type": "string"},
                "every": {"type": "integer", "default": 60},
                "limit": {"type": "integer", "default": 100, "minimum": 1, "maximum": 500},
                "offset": {"type": "integer", "default": 0, "minimum": 0},
                "cursor": {"type": "string", "description": "next-page token from a previous response"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "deniz_alerts",
        "description": "List or acknowledge monitor alerts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["list", "ack"], "default": "list"},
                "ref": {"type": "string"},
                "all": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "default": 100, "minimum": 1, "maximum": 500},
                "offset": {"type": "integer", "default": 0, "minimum": 0},
                "cursor": {"type": "string", "description": "next-page token from a previous response"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "deniz_findings",
        "description": "Derive, list or acknowledge case findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["list", "refresh", "ack", "set"], "default": "list"},
                "case": {"type": "string"},
                "ref": {"type": "string"},
                "value": {"type": "string", "description": "severity for set"},
                "note": {"type": "string"},
                "all": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "default": 100, "minimum": 1, "maximum": 500},
                "offset": {"type": "integer", "default": 0, "minimum": 0},
                "cursor": {"type": "string", "description": "next-page token from a previous response"},
            },
            "required": ["case"],
            "additionalProperties": False,
        },
    },
    {
        "name": "deniz_search",
        "description": "Multi-provider web search.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": 25, "minimum": 1, "maximum": 100},
                "per_provider": {"type": "integer", "default": 10, "minimum": 1, "maximum": 25},
                "code": {"type": "boolean", "default": False},
                "filetype": {"type": "string", "description": "dork filter, e.g. pdf"},
                "site": {"type": "string", "description": "restrict to a domain"},
                "case": {"type": "string"},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "deniz_social",
        "description": "Site-scoped social search (Instagram, TikTok, LinkedIn, Facebook, Quora, Trello) via headless Chromium.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "sites": {"type": "array", "items": {"type": "string", "enum": sorted(SOCIAL_SITES)}},
                "limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": 200},
                "per_site": {"type": "integer", "default": 10, "minimum": 1, "maximum": 25},
                "case": {"type": "string"},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
]


def _text(payload: Any, error: bool = False) -> dict:
    if not isinstance(payload, str):
        payload = json.dumps(payload, ensure_ascii=False, indent=2)
    return {"content": [{"type": "text", "text": payload}], "isError": error}


def _audit(rt, action: str, target: str = "", details: dict | None = None) -> None:
    with contextlib.suppress(Exception):
        rt.audit.record("mcp", action, target, details=details)


def _tool_domain(args: dict) -> dict:
    try:
        domain = validate_domain(str(args.get("domain", "")))
    except ValueError as exc:
        return _text(str(exc), True)
    rt = _runtime()
    store = RunStore(rt.config.runs_dir)
    run = store.begin("domain.mcp")
    try:
        result = run_domain(
            domain,
            config=rt.config,
            http=rt.client,
            cache=rt.cache,
            health=rt.health,
            registry=Registry(),
            auth=rt.auth,
            max_hosts=int(args.get("max_hosts", 50)),
            probe=bool(args.get("probe", True)),
            typosquat=bool(args.get("typosquat", True)),
            emailauth=bool(args.get("emailauth", True)),
            rdap=bool(args.get("rdap", True)),
            asn=bool(args.get("asn", True)),
            dnsbl=bool(args.get("dnsbl", True)),
            tlds=bool(args.get("tlds", False)),
            entrypoints=bool(args.get("entrypoints", True)),
            crawl=bool(args.get("crawl", False)),
            crawl_regex=str(args.get("crawl_regex") or "") or None,
            files=bool(args.get("files", False)),
            dnsbrute=bool(args.get("dnsbrute", False)),
            discovery=bool(args.get("discovery", True)),
            urlscan=bool(args.get("urlscan", True)),
            internetdb=bool(args.get("internetdb", True)),
            wayback=bool(args.get("wayback", True)),
            axfr=bool(args.get("axfr", False)),
            ports=bool(args.get("ports", False)),
            takeover=bool(args.get("takeover", True)),
            fingerprint=bool(args.get("fingerprint", True)),
        )
    except DenizError as exc:
        return _text(str(exc), True)
    finally:
        rt.client.close()
    result.run_id = run.run_id
    store.write(run, result)
    rt.graph.record(result)
    _audit(rt, f"run.{result.module}", result.target.value, {"run_id": run.run_id, "items": len(result.items)})
    if args.get("case"):
        with contextlib.suppress(KeyError):
            rt.cases.add_run(str(args["case"]), run.run_id)
    fields = args.get("fields") or ["type", "value", "confidence"]
    items = []
    for item in result.items[:300]:
        row = {field: getattr(item, field, item.attrs.get(field)) for field in fields}
        items.append(row)
    return _text(
        {
            "run_id": result.run_id,
            "target": result.target.value,
            "counts": result.summary(),
            "errors": [e.model_dump() for e in result.errors],
            "items": items,
            "truncated": len(result.items) > len(items),
        }
    )


def _tool_providers(_: dict) -> dict:
    rt = _runtime()
    rows = []
    for info in Registry().infos():
        score = rt.health.score(info.name)
        rows.append(
            {
                "name": info.name,
                "capabilities": sorted(info.capabilities),
                "auth": info.auth,
                "cost": info.cost,
                "credential": rt.auth.source(info.name),
                "health_7d": score,
            }
        )
    rt.client.close()
    return _text(rows)


def _tool_graph(args: dict) -> dict:
    rt = _runtime()
    run_ids = None
    if args.get("case"):
        try:
            run_ids = rt.cases.get(str(args["case"])).runs
        except KeyError:
            rt.client.close()
            return _text("case not found", True)
    data = rt.graph.show(str(args.get("value", "")), run_ids)
    rt.client.close()
    return _text(data or "not found", not data)


def _tool_diff(args: dict) -> dict:
    rt = _runtime()
    return _text(rt.graph.diff(str(args.get("run_a", "")), str(args.get("run_b", ""))))


def _tool_vuln(args: dict) -> dict:
    query = str(args.get("query", "")).strip()
    if len(query) < 2:
        return _text("query too short", True)
    rt = _runtime()
    store = RunStore(rt.config.runs_dir)
    run = store.begin("vuln.search")
    try:
        result = run_vuln(
            query,
            config=rt.config,
            http=rt.client,
            cache=rt.cache,
            health=rt.health,
            registry=Registry(),
            auth=rt.auth,
            limit=int(args.get("limit", 20)),
        )
    except DenizError as exc:
        return _text(str(exc), True)
    finally:
        rt.client.close()
    result.run_id = run.run_id
    store.write(run, result)
    rt.graph.record(result)
    _audit(rt, f"run.{result.module}", result.target.value, {"run_id": run.run_id, "items": len(result.items)})
    if args.get("case"):
        with contextlib.suppress(KeyError):
            rt.cases.add_run(str(args["case"]), run.run_id)
    return _text(
        {
            "run_id": result.run_id,
            "counts": result.summary(),
            "items": [
                {"cve": i.value, "cvss": i.attrs.get("cvss"), "epss": i.attrs.get("epss"), "severity": i.attrs.get("severity")}
                for i in result.items
            ],
        }
    )


def _tool_report(args: dict) -> dict:
    rt = _runtime()
    store = RunStore(rt.config.runs_dir)
    try:
        path = store.resolve(str(args.get("run_id", "")))
    except FileNotFoundError:
        rt.client.close()
        return _text("run not found", True)
    rt.client.close()
    result = Result.model_validate_json((path / "result.json").read_text(encoding="utf-8"))
    written = write_report(
        result,
        str(args.get("format", "html")),
        path / "reports",
        redact=bool(args.get("redact")),
        lang=str(args.get("lang", "en")),
    )
    _audit(rt, "report.render", result.run_id, {"path": str(written), "redact": bool(args.get("redact"))})
    return _text({"path": str(written)})


def _tool_single(provider_name: str, value: str, kind: str) -> dict:
    from .kit.models import Target
    from .kit.providers.base import Context
    from .kit.scope import Scope

    rt = _runtime()
    result = Result(
        schema="deniz.result/1", module=f"provider.{provider_name}", provider=provider_name,
        target=Target(type=kind, value=value),  # type: ignore[arg-type]
    )
    ctx = Context(http=rt.client, scope=Scope(), auth=rt.auth)
    try:
        for item in Registry().get(provider_name)(rt.client).run(result.target, ctx):
            result.add(item)
    except DenizError as exc:
        return _text(str(exc), True)
    finally:
        rt.client.close()
    result.dedupe()
    return _text({"counts": result.summary(), "items": [{"type": i.type, "value": i.value} for i in result.items[:200]]})


def _tool_identity(args: dict) -> dict:
    return _tool_single("username", str(args.get("username", "")), "username")


def _tool_buckets(args: dict) -> dict:
    return _tool_single("buckets", str(args.get("domain", "")), "domain")


def _tool_case(args: dict) -> dict:
    rt = _runtime()
    action = str(args.get("action", "list"))
    if action == "list":
        offset = max(0, int(args.get("offset", 0)))
        limit = min(500, max(1, int(args.get("limit", 100))))
        cursor = str(args.get("cursor") or "") or None
        try:
            page = paginate(
                rt.cases.list_cases(),
                key=lambda c: (c.updated_at, c.id),
                scope="cases:mcp:archived=0",
                limit=limit,
                cursor=cursor,
                offset=offset,
            )
        except InvalidCursor as exc:
            rt.client.close()
            return _text(f"invalid cursor: {exc}", True)
        rt.client.close()
        return _text(
            {
                "total": page.total,
                "offset": page.offset,
                "next": page.next_cursor,
                "cases": [
                    {"id": c.id, "name": c.name, "runs": len(c.runs), "updated_at": c.updated_at}
                    for c in page.items
                ],
            }
        )
    ref = str(args.get("ref", ""))
    try:
        case = rt.cases.get(ref)
    except KeyError:
        rt.client.close()
        return _text(f"case not found: {ref}", True)
    if action == "show":
        rt.client.close()
        return _text(
            {
                "id": case.id,
                "name": case.name,
                "scope": {"allow": case.allow, "deny": case.deny},
                "notes": case.notes,
                "runs": case.runs,
                "tags": case.tags,
            }
        )
    if action == "search":
        text = str(args.get("value", "")).strip()
        offset = max(0, int(args.get("offset", 0)))
        limit = min(500, max(1, int(args.get("limit", 100))))
        cursor = str(args.get("cursor") or "") or None
        rows = rt.graph.search(case.runs, text, limit=10000)
        rt.client.close()
        try:
            page = paginate(
                rows,
                key=lambda row: (str(row["seen"]), str(row["value"])),
                scope=f"case-search:{case.id}:{text}",
                limit=limit,
                cursor=cursor,
                offset=offset,
            )
        except InvalidCursor as exc:
            return _text(f"invalid cursor: {exc}", True)
        return _text({"total": page.total, "offset": page.offset, "next": page.next_cursor, "items": page.items})
    path = rt.cases.export(
        case.id,
        RunStore(rt.config.runs_dir),
        rt.config.home / "exports" / case.name,
        redact=bool(args.get("redact")),
        lang=str(args.get("lang", "en")),
    )
    _audit(rt, "case.export", case.id, {"path": str(path)})
    rt.client.close()
    return _text({"path": str(path)})


def _tool_monitor(args: dict) -> dict:
    rt = _runtime()
    action = str(args.get("action", "list"))
    if action == "list":
        offset = max(0, int(args.get("offset", 0)))
        limit = min(500, max(1, int(args.get("limit", 100))))
        cursor = str(args.get("cursor") or "") or None
        try:
            page = paginate(
                rt.monitors.list_monitors(),
                key=lambda m: (m.created_at, m.id),
                scope="monitors",
                limit=limit,
                cursor=cursor,
                offset=offset,
            )
        except InvalidCursor as exc:
            rt.client.close()
            return _text(f"invalid cursor: {exc}", True)
        rt.client.close()
        return _text(
            {
                "total": page.total,
                "offset": page.offset,
                "next": page.next_cursor,
                "monitors": [
                    {"id": m.id, "kind": m.kind, "target": m.target, "every": m.every_minutes, "enabled": m.enabled}
                    for m in page.items
                ],
            }
        )
    if action == "tick":
        results = run_due(_deps(rt))
        _audit(rt, "monitor.tick", details={"ran": len(results)})
        rt.client.close()
        return _text(results)
    if action == "add":
        try:
            case = rt.cases.get(str(args.get("ref", "")))
        except KeyError:
            rt.client.close()
            return _text("case not found", True)
        kind = str(args.get("kind", "domain"))
        target = str(args.get("target", ""))
        if kind in ("domain", "buckets"):
            target = validate_domain(target)
        monitor = rt.monitors.add(case.id, kind, target, int(args.get("every", 60)))
        _audit(rt, "monitor.add", monitor.id, {"case": case.id, "kind": kind, "target": target})
        rt.client.close()
        return _text({"id": monitor.id, "kind": monitor.kind, "target": monitor.target})
    try:
        monitor = rt.monitors.get(str(args.get("ref", "")))
    except KeyError:
        rt.client.close()
        return _text("monitor not found", True)
    try:
        result = execute_monitor(monitor, _deps(rt))
    except Exception as exc:
        rt.monitors.finish(monitor, False, str(exc))
        _audit(rt, "monitor.run", monitor.id, {"error": str(exc)})
        rt.client.close()
        return _text(f"{type(exc).__name__}: {exc}", True)
    rt.monitors.finish(monitor, True)
    _audit(rt, "monitor.run", monitor.id)
    rt.client.close()
    return _text(result)


def _tool_alerts(args: dict) -> dict:
    rt = _runtime()
    if args.get("action") == "ack":
        if args.get("all"):
            count = rt.monitors.ack_all()
            _audit(rt, "alerts.ack_all", details={"acked": count})
        else:
            rt.monitors.ack(str(args.get("ref", "")))
            _audit(rt, "alerts.ack", str(args.get("ref", "")))
            count = 1
        rt.client.close()
        return _text({"acked": count})
    offset = max(0, int(args.get("offset", 0)))
    limit = min(500, max(1, int(args.get("limit", 100))))
    cursor = str(args.get("cursor") or "") or None
    try:
        page = rt.monitors.page_alerts(
            include_acked=bool(args.get("all")),
            limit=limit,
            cursor=cursor,
            offset=offset,
        )
    except InvalidCursor as exc:
        rt.client.close()
        return _text(f"invalid cursor: {exc}", True)
    items = [
        {k: alert[k] for k in ("id", "kind", "summary", "created_at", "acked")}
        for alert in page.items
    ]
    rt.client.close()
    return _text({"total": page.total, "offset": page.offset, "next": page.next_cursor, "alerts": items})


def _tool_findings(args: dict) -> dict:
    rt = _runtime()
    try:
        case = rt.cases.get(str(args.get("case", "")))
    except KeyError:
        rt.client.close()
        return _text("case not found", True)
    action = str(args.get("action", "list"))
    if action == "refresh":
        rows = rt.findings.refresh(case.id, case.runs, rt.graph)
        _audit(rt, "findings.refresh", case.id, {"findings": len(rows)})
    if action == "ack":
        if args.get("all"):
            count = rt.findings.ack_all(case.id)
            _audit(rt, "findings.ack_all", case.id, {"acked": count})
        else:
            try:
                rt.findings.ack(str(args.get("ref", "")))
            except KeyError:
                rt.client.close()
                return _text("finding not found", True)
            _audit(rt, "findings.ack", str(args.get("ref", "")))
            count = 1
        rt.client.close()
        return _text({"acked": count})
    if action == "set":
        try:
            rt.findings.set(str(args.get("ref", "")), args.get("value"), args.get("note"))
        except KeyError:
            rt.client.close()
            return _text("finding not found", True)
        except ValueError as exc:
            rt.client.close()
            return _text(str(exc), True)
        _audit(rt, "findings.set", str(args.get("ref", "")), {"severity": args.get("value")})
        rt.client.close()
        return _text({"ok": True})
    findings = rt.findings.list(case.id, include_acked=bool(args.get("all")))
    offset = max(0, int(args.get("offset", 0)))
    limit = min(500, max(1, int(args.get("limit", 100))))
    cursor = str(args.get("cursor") or "") or None
    try:
        page = paginate(
            findings,
            key=lambda f: (FINDING_RANK.get(f.severity_override or f.severity, 0), f.created_at, f.id),
            scope=f"findings:case={case.id}:acked={int(bool(args.get('all')))}",
            limit=limit,
            cursor=cursor,
            offset=offset,
        )
    except InvalidCursor as exc:
        rt.client.close()
        return _text(f"invalid cursor: {exc}", True)
    rows = [
        {
            "id": f.id,
            "severity": f.severity_override or f.severity,
            "kind": f.kind,
            "title": f.title,
            "acked": f.acked,
            "note": f.note,
        }
        for f in page.items
    ]
    rt.client.close()
    return _text({"total": page.total, "offset": page.offset, "next": page.next_cursor, "findings": rows})


def _tool_search(args: dict) -> dict:
    query = str(args.get("query", "")).strip()
    if len(query) < 2:
        return _text("query too short", True)
    rt = _runtime()
    store = RunStore(rt.config.runs_dir)
    run = store.begin("search.web")
    try:
        result = run_search(
            query,
            config=rt.config,
            http=rt.client,
            cache=rt.cache,
            health=rt.health,
            registry=Registry(),
            auth=rt.auth,
            limit=int(args.get("limit", 25)),
            per_provider=int(args.get("per_provider", 10)),
            include_code=bool(args.get("code", False)),
            filetype=str(args.get("filetype") or "") or None,
            site=str(args.get("site") or "") or None,
        )
    except DenizError as exc:
        rt.client.close()
        return _text(str(exc), True)
    finally:
        rt.client.close()
    result.run_id = run.run_id
    store.write(run, result)
    rt.graph.record(result)
    _audit(rt, f"run.{result.module}", result.target.value, {"run_id": run.run_id, "items": len(result.items)})
    if args.get("case"):
        with contextlib.suppress(KeyError):
            rt.cases.add_run(str(args["case"]), run.run_id)
    return _text(
        {
            "run_id": result.run_id,
            "counts": result.summary(),
            "errors": [e.model_dump() for e in result.errors],
            "items": [
                {"provider": i.sources[0].provider, "type": i.type, "value": i.value, "title": i.attrs.get("title")}
                for i in result.items
            ],
        }
    )


def _tool_social(args: dict) -> dict:
    query = str(args.get("query", "")).strip()
    if len(query) < 2:
        return _text("query too short", True)
    rt = _runtime()
    store = RunStore(rt.config.runs_dir)
    run = store.begin("social.mcp")
    try:
        result = run_social(
            query,
            config=rt.config,
            http=rt.client,
            cache=rt.cache,
            health=rt.health,
            registry=Registry(),
            auth=rt.auth,
            sites=[str(s) for s in args.get("sites") or []] or None,
            limit=int(args.get("limit", 50)),
            per_site=int(args.get("per_site", 10)),
        )
    except DenizError as exc:
        rt.client.close()
        return _text(str(exc), True)
    finally:
        rt.client.close()
    result.run_id = run.run_id
    store.write(run, result)
    rt.graph.record(result)
    _audit(rt, f"run.{result.module}", result.target.value, {"run_id": run.run_id, "items": len(result.items)})
    if args.get("case"):
        with contextlib.suppress(KeyError):
            rt.cases.add_run(str(args["case"]), run.run_id)
    return _text(
        {
            "run_id": result.run_id,
            "counts": result.summary(),
            "errors": [e.model_dump() for e in result.errors],
            "items": [
                {"site": i.attrs.get("site"), "kind": i.attrs.get("kind"), "url": i.value, "title": i.attrs.get("title")}
                for i in result.items
            ],
        }
    )


HANDLERS = {
    "deniz_domain": _tool_domain,
    "deniz_providers": _tool_providers,
    "deniz_graph_entity": _tool_graph,
    "deniz_run_diff": _tool_diff,
    "deniz_vuln": _tool_vuln,
    "deniz_report": _tool_report,
    "deniz_identity": _tool_identity,
    "deniz_buckets": _tool_buckets,
    "deniz_case": _tool_case,
    "deniz_monitor": _tool_monitor,
    "deniz_alerts": _tool_alerts,
    "deniz_findings": _tool_findings,
    "deniz_search": _tool_search,
    "deniz_social": _tool_social,
}


def handle(request: dict) -> dict | None:
    method = request.get("method")
    req_id = request.get("id")
    if method == "initialize":
        version = (request.get("params") or {}).get("protocolVersion") or PROTOCOL
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = request.get("params") or {}
        name = params.get("name")
        handler = HANDLERS.get(name)
        if not handler:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": _text(f"unknown tool: {name}", True),
            }
        try:
            return {"jsonrpc": "2.0", "id": req_id, "result": handler(params.get("arguments") or {})}
        except Exception as exc:  # tool errors must stay in-band
            return {"jsonrpc": "2.0", "id": req_id, "result": _text(f"{type(exc).__name__}: {exc}", True)}
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"method not found: {method}"},
    }


def _http_body(handler: BaseHTTPRequestHandler, limit: int = 2_000_000) -> dict:
    length = int(handler.headers.get("content-length", "0"))
    if length > limit:
        raise ValueError("body too large")
    raw = handler.rfile.read(length) if length else b""
    data = json.loads(raw or b"{}")
    if not isinstance(data, dict):
        raise ValueError("body must be an object")
    return data


class _HttpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "DenizMCP/0.1"
    sessions: ClassVar[set[str]] = set()
    lock = threading.Lock()

    def log_message(self, fmt: str, *args) -> None:
        if os.environ.get("DENIZ_HTTP_LOG"):
            super().log_message(fmt, *args)

    def _cors(self) -> None:
        self.send_header("access-control-allow-origin", "*")
        self.send_header("access-control-allow-methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("access-control-allow-headers", "authorization, content-type, mcp-session-id, mcp-protocol-version")
        self.send_header("access-control-expose-headers", "mcp-session-id")

    def _authorised(self) -> bool:
        expected = os.environ.get("DENIZ_MCP_TOKEN")
        if not expected:
            return True
        supplied = self.headers.get("authorization", "")
        return supplied == f"Bearer {expected}"

    def _json(self, status: int, payload: dict | None, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else b""
        self.send_response(status)
        if payload is not None:
            self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self._cors()
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _sse_open(self, headers: dict[str, str] | None = None) -> None:
        self.send_response(200)
        self.send_header("content-type", "text/event-stream; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("connection", "close")
        self._cors()
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.close_connection = True

    def _sse_event(self, payload: dict) -> None:
        self.wfile.write(b"event: message\ndata: " + json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n\n")
        self.wfile.flush()

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._cors()
        self.send_header("content-length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        if self.path.rstrip("/") not in ("/mcp", ""):
            return self._json(404, {"error": "not found"})
        if not self._authorised():
            return self._json(401, {"error": "unauthorized"})
        self._sse_open()
        self.wfile.write(b": deniz mcp stream\nevent: endpoint\ndata: /mcp\n\n")
        self.wfile.flush()

    def do_DELETE(self) -> None:
        if not self._authorised():
            return self._json(401, {"error": "unauthorized"})
        session = self.headers.get("mcp-session-id")
        with self.lock:
            known = bool(session and session in self.sessions)
            self.sessions.discard(session or "")
        if session and not known:
            return self._json(404, {"error": "unknown session"})
        self.send_response(HTTPStatus.NO_CONTENT)
        self._cors()
        self.send_header("content-length", "0")
        self.end_headers()

    def do_POST(self) -> None:
        if self.path.rstrip("/") not in ("/mcp", ""):
            return self._json(404, {"error": "not found"})
        try:
            request = _http_body(self)
        except (ValueError, json.JSONDecodeError) as exc:
            return self._json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}})
        if not self._authorised():
            return self._json(401, {"error": "unauthorized"})

        session = self.headers.get("mcp-session-id")
        with self.lock:
            known = session is None or session in self.sessions
        if not known:
            return self._json(404, {"error": "unknown session"})
        headers: dict[str, str] = {}
        if request.get("method") == "initialize":
            session = uuid.uuid4().hex
            with self.lock:
                self.sessions.add(session)
            headers["mcp-session-id"] = session

        progress = None
        params = request.get("params") or {}
        if request.get("method") == "tools/call" and isinstance(params.get("_meta"), dict):
            progress = params["_meta"].get("progressToken")

        try:
            response = handle(request)
        except Exception as exc:  # keep tool errors in-band
            response = {"jsonrpc": "2.0", "id": request.get("id"), "result": _text(f"{type(exc).__name__}: {exc}", True)}

        if response is None:
            return self._json(202, None, headers)
        if "text/event-stream" in self.headers.get("accept", ""):
            self._sse_open(headers)
            if progress is not None:
                self._sse_event({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": progress, "progress": 0, "total": 1}})
            self._sse_event(response)
            if progress is not None:
                self._sse_event({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": progress, "progress": 1, "total": 1}})
            return
        self._json(200, response, headers)


def serve_http(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), _HttpHandler)
    server.daemon_threads = True
    return server


def start_http_background(host: str = "127.0.0.1", port: int = 0) -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = serve_http(host, port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def serve() -> int:
    print(f"deniz mcp {SERVER_VERSION} ready on stdio", file=sys.stderr, flush=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError:
            print(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}), flush=True)
            continue
        response = handle(request)
        if response is not None:
            print(json.dumps(response, ensure_ascii=False), flush=True)
    return 0

