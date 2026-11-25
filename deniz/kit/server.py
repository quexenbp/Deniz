# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Read-only HTTP API and dashboard.

Bind loopback by default. Set ``DENIZ_API_TOKEN`` before exposing the port;
without it the server refuses non-loopback binds unless ``--allow-anonymous``
is passed.
"""

from __future__ import annotations

import hmac
import html
import json
import os
import threading
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .audit import AuditStore
from .cases import CaseStore
from .findings import FindingStore
from .graph import GraphStore
from .models import Target
from .monitors import Dependencies, MonitorStore, execute
from .pagination import InvalidCursor, Page, paginate
from .ratelimit import Limiter
from .store import RunStore
from .tokens import ApiToken

FINDING_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class Api:
    def __init__(
        self,
        *,
        cases: CaseStore,
        runs: RunStore,
        graph: GraphStore,
        monitors: MonitorStore,
        deps: Dependencies,
        findings: FindingStore,
        tick,
        token: str | None = None,
        tokens: list[ApiToken] | None = None,
        cors_origins: list[str] | None = None,
        audit: AuditStore | None = None,
        limit_per_second: float = 5.0,
        limit_burst: int = 30,
    ) -> None:
        self.cases = cases
        self.runs = runs
        self.graph = graph
        self.monitors = monitors
        self.deps = deps
        self.findings = findings
        self.tick = tick
        self.token = token
        self.tokens = tokens if tokens is not None else ([ApiToken("default", token, "admin")] if token else [])
        self.cors_origins = cors_origins or ["*"]
        self.audit = audit or AuditStore(deps.config.store("audit"))
        self.limiter = Limiter()
        self.limit_per_second = limit_per_second
        self.limit_burst = limit_burst

    def allow(self, ip: str) -> bool:
        return self.limiter.bucket(ip, self.limit_per_second, self.limit_burst).try_acquire()

    def identify(self, header: str | None, query: dict[str, list[str]]) -> ApiToken | None:
        if not self.tokens:
            return ApiToken(name="anonymous", secret="", role="admin")
        supplied = None
        if header and header.lower().startswith("bearer "):
            supplied = header[7:].strip()
        elif "token" in query:
            supplied = query["token"][0]
        if supplied is None:
            return None
        for token in self.tokens:
            if hmac.compare_digest(supplied, token.secret):
                return token
        return None

    def authorised(self, header: str | None, query: dict[str, list[str]]) -> bool:
        return self.identify(header, query) is not None

    @staticmethod
    def permitted(token: ApiToken, method: str) -> bool:
        return token.permits(method)


def _cors(handler: BaseHTTPRequestHandler) -> None:
    origins = getattr(handler, "cors_origins", ["*"])
    origin = handler.headers.get("origin")
    if "*" in origins:
        handler.send_header("access-control-allow-origin", "*")
    elif origin and origin in origins:
        handler.send_header("access-control-allow-origin", origin)
        handler.send_header("vary", "origin")
    elif origin:
        handler.send_header("vary", "origin")
    handler.send_header("access-control-allow-methods", "GET, POST, DELETE, OPTIONS")
    handler.send_header("access-control-allow-headers", "authorization, content-type")
    handler.send_header("access-control-expose-headers", "x-total-count, x-offset, x-next-cursor")


def _json(handler: BaseHTTPRequestHandler, status: int, payload: object, headers: dict[str, str] | None = None) -> None:
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", "application/json; charset=utf-8")
    handler.send_header("content-length", str(len(body)))
    handler.send_header("cache-control", "no-store")
    handler.send_header("x-content-type-options", "nosniff")
    _cors(handler)
    for key, value in (headers or {}).items():
        handler.send_header(key, value)
    handler.end_headers()
    handler.wfile.write(body)


def _html(handler: BaseHTTPRequestHandler, status: int, body: str) -> None:
    data = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", "text/html; charset=utf-8")
    handler.send_header("content-length", str(len(data)))
    handler.send_header("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
    _cors(handler)
    handler.end_headers()
    handler.wfile.write(data)


def _page_query(query: dict[str, list[str]], default_limit: int, max_limit: int) -> tuple[str | None, int, int]:
    try:
        offset = max(0, int(query.get("offset", ["0"])[0]))
        limit = min(max_limit, max(1, int(query.get("limit", [str(default_limit)])[0])))
    except ValueError as exc:
        raise InvalidCursor("limit and offset must be integers") from exc
    cursor = query.get("cursor", [""])[0].strip() or None
    return cursor, offset, limit


def _page_headers(page: Page) -> dict[str, str]:
    headers = {"x-total-count": str(page.total), "x-offset": str(page.offset)}
    if page.next_cursor:
        headers["x-next-cursor"] = page.next_cursor
    return headers


def _run_key(path) -> tuple[int, str]:
    try:
        return (path.stat().st_mtime_ns, path.name)
    except OSError:
        return (0, path.name)


def _finding_key(finding) -> tuple[int, str, str]:
    severity = finding.severity_override or finding.severity
    return (FINDING_RANK.get(severity, 0), finding.created_at, finding.id)


def _dashboard(api: Api, token: str | None = None) -> str:
    cases = api.cases.list_cases()
    alerts = api.monitors.alerts(include_acked=False, limit=50)
    stats = api.graph.stats()
    rows = "".join(
        f"<tr><td><a href='/api/cases/{c.id}'>{html.escape(c.name)}</a></td><td>{len(c.runs)}</td>"
        f"<td>{html.escape(c.updated_at[:19])}</td></tr>"
        for c in cases
    )
    alert_rows = "".join(
        f"<tr><td>{html.escape(a['created_at'][:19])}</td><td>{html.escape(a['kind'])}</td>"
        f"<td>{html.escape(a['summary'])}</td>"
        f"<td><button onclick=\"ack('{html.escape(a['id'])}\')\">ack</button></td></tr>"
        for a in alerts
    )
    provider_rows = "".join(
        f"<tr><td>{html.escape(i.name)}</td><td>{','.join(sorted(i.capabilities))}</td>"
        f"<td>{'unknown' if (s := api.deps.health.score(i.name)) is None else f'{s:.0%}'}</td></tr>"
        for i in api.deps.registry.infos()
    )
    case_options = "".join(f"<option value='{html.escape(c.id)}'>{html.escape(c.name)}</option>" for c in cases)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Deniz</title>
<style>
body{{font:14px/1.5 system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#111}}
table{{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}}th,td{{border-bottom:1px solid #ddd;padding:.4rem;text-align:left}}
.muted{{color:#666}}code{{font-size:.85em}}
form{{display:flex;gap:.4rem;flex-wrap:wrap;margin:.5rem 0 1.5rem}}input,select,button{{padding:.3rem .4rem}}
</style></head><body>
<h1>Deniz</h1>
<p class="muted">entities {stats['entities']} · observations {stats['observations']} · edges {stats['edges']}</p>
<h2>Open alerts ({len(alerts)})</h2>
<table><thead><tr><th>at</th><th>kind</th><th>summary</th><th></th></tr></thead><tbody>{alert_rows or '<tr><td colspan="4">none</td></tr>'}</tbody></table>
<h2>Cases ({len(cases)})</h2>
<table><thead><tr><th>name</th><th>runs</th><th>updated</th></tr></thead><tbody>{rows or '<tr><td colspan="3">none</td></tr>'}</tbody></table>
<form id="caseForm"><input name="name" placeholder="new case name" required><input name="allow" placeholder="allow (optional)"><button>create case</button></form>
<h2>Add monitor</h2>
<form id="monitorForm">
<select name="case" required>{case_options}</select>
<select name="kind"><option>domain</option><option>vuln</option><option>buckets</option><option>identity</option></select>
<input name="target" placeholder="target" required>
<input name="every" type="number" value="60" min="5">
<button>add</button>
</form>
<h2>Providers</h2>
<table><thead><tr><th>provider</th><th>capabilities</th><th>health 7d</th></tr></thead><tbody>{provider_rows}</tbody></table>
<p class="muted">API: <code>/health</code>, <code>/api/cases</code>, <code>/api/runs</code>, <code>/api/providers</code>, <code>/api/alerts</code>, <code>/api/findings?case=</code>, <code>/api/graph/&lt;value&gt;</code>.</p>
<script>
const TOKEN = {json.dumps(token)};
function headers() {{ const h = {{'content-type':'application/json'}}; if (TOKEN) h.authorization = 'Bearer ' + TOKEN; return h; }}
async function post(url, body) {{
  const r = await fetch(url, {{method:'POST', headers: headers(), body: JSON.stringify(body)}});
  if (!r.ok) {{ alert(await r.text()); return; }}
  location.reload();
}}
document.getElementById('caseForm').addEventListener('submit', e => {{
  e.preventDefault();
  const f = new FormData(e.target);
  post('/api/cases', {{name: f.get('name'), allow: f.get('allow') ? [f.get('allow')] : []}});
}});
document.getElementById('monitorForm').addEventListener('submit', e => {{
  e.preventDefault();
  const f = new FormData(e.target);
  post('/api/monitor', {{case: f.get('case'), kind: f.get('kind'), target: f.get('target'), every: Number(f.get('every'))}});
}});
function ack(id) {{ post('/api/alerts/ack', {{id}}); }}
</script>
</body></html>
"""


def make_handler(api: Api, registry) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "Deniz/0.1"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args) -> None:
            if os.environ.get("DENIZ_HTTP_LOG"):
                super().log_message(fmt, *args)

        def _body(self) -> dict:
            length = int(self.headers.get("content-length", "0"))
            if length > 1_000_000:
                raise ValueError("body too large")
            raw = self.rfile.read(length) if length else b"{}"
            data = json.loads(raw or b"{}")
            if not isinstance(data, dict):
                raise ValueError("body must be an object")
            return data

        def _audit(self, action: str, target: str = "", details: dict | None = None) -> None:
            api.audit.record(getattr(self, "token_name", "api"), action, target, details=details)

        def _route(self) -> None:
            self.cors_origins = api.cors_origins
            parts = urlsplit(self.path)
            path = parts.path.rstrip("/") or "/"
            query = parse_qs(parts.query)
            if path == "/health":
                return _json(self, 200, {"ok": True})
            if self.command == "OPTIONS":
                return _json(self, 200, {"ok": True})
            if not api.allow(self.client_address[0]):
                return _json(self, 429, {"error": "rate limited"}, {"retry-after": "1"})
            token = api.identify(self.headers.get("authorization"), query)
            if token is None:
                return _json(self, HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            if not api.permitted(token, self.command):
                return _json(self, HTTPStatus.FORBIDDEN, {"error": f"role {token.role} cannot {self.command}"})
            self.token_name = token.name

            if path == "/api":
                return _json(
                    self,
                    200,
                    {
                        "service": "deniz",
                        "schema": "deniz.result/1",
                        "endpoints": [
                            "/api/schema",
                            "/api/stats",
                            "/api/audit",
                            "/api/providers",
                            "/api/cases",
                            "/api/runs",
                            "/api/graph/<value>",
                            "/api/alerts",
                            "/api/findings?case=",
                        ],
                        "legacy": {
                            "/api/framework": "replaced by typed commands; run them in the CLI",
                            "/api/modules": "replaced by providers and `deniz run <provider>`",
                        },
                    },
                )
            if path == "/api/framework":
                return _json(
                    self,
                    410,
                    {
                        "error": "the REPL framework bridge is gone",
                        "replacement": "deniz domain|search|vuln|run <provider> (same operations, typed JSON)",
                        "legacy_command": query.get("command", [None])[0],
                    },
                )
            if path == "/api/modules":
                return _json(
                    self,
                    410,
                    {
                        "error": "legacy module execution is gone",
                        "replacement": "deniz run <provider> <value> --type <kind>",
                        "legacy_module": query.get("_module", [None])[0],
                        "providers": "/api/providers",
                    },
                )

            if self.command == "POST":
                if path == "/api/cases":
                    body = self._body()
                    name = str(body.get("name", "")).strip()
                    if not name:
                        return _json(self, 400, {"error": "name required"})
                    try:
                        case = api.cases.create(name, allow=list(body.get("allow") or []), deny=list(body.get("deny") or []), tags=list(body.get("tags") or []))
                    except ValueError as exc:
                        return _json(self, 409, {"error": str(exc)})
                    self._audit("case.create", case.id, {"name": case.name})
                    return _json(self, 201, {"id": case.id, "name": case.name})
                if path == "/api/monitor":
                    body = self._body()
                    try:
                        case = api.cases.get(str(body.get("case", "")))
                    except KeyError:
                        return _json(self, 404, {"error": "case not found"})
                    kind = str(body.get("kind", "domain"))
                    target = str(body.get("target", ""))
                    target_type = {"domain": "domain", "buckets": "domain", "vuln": "keyword", "identity": "username"}.get(kind)
                    if not target_type:
                        return _json(self, 400, {"error": "bad kind"})
                    try:
                        Target(type=target_type, value=target)  # type: ignore[arg-type]
                    except ValueError as exc:
                        return _json(self, 400, {"error": str(exc)})
                    monitor = api.monitors.add(case.id, kind, target, int(body.get("every", 60)))
                    self._audit("monitor.add", monitor.id, {"case": case.id, "kind": kind, "target": target})
                    return _json(self, 201, {"id": monitor.id, "kind": monitor.kind, "target": monitor.target})
                if path.startswith("/api/cases/") and path.endswith(("/archive", "/unarchive")):
                    case_id = path.split("/")[3]
                    try:
                        if path.endswith("/archive"):
                            api.cases.archive(case_id)
                        else:
                            api.cases.unarchive(case_id)
                    except KeyError:
                        return _json(self, 404, {"error": "not found"})
                    self._audit("case.archive" if path.endswith("/archive") else "case.unarchive", case_id)
                    return _json(self, 200, {"ok": True})
                if path.startswith("/api/cases/") and path.endswith("/export"):
                    case_id = path.split("/")[3]
                    try:
                        case = api.cases.get(case_id)
                    except KeyError:
                        return _json(self, 404, {"error": "not found"})
                    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                    out = api.deps.config.home / "exports" / f"{case.name}-{stamp}"
                    body = self._body()
                    written = api.cases.export(
                        case.id, api.runs, out, api.findings, api.graph, as_zip=True, redact=bool(body.get("redact"))
                    )
                    self._audit("case.export", case.id, {"path": str(written), "redact": bool(body.get("redact"))})
                    return _json(self, 200, {"path": str(written)})
                if path.startswith("/api/runs/") and path.endswith("/report"):
                    run_id = path.split("/")[3]
                    try:
                        run_path = api.runs.resolve(run_id)
                    except FileNotFoundError:
                        return _json(self, 404, {"error": "not found"})
                    from .models import Result
                    from .report import write_report

                    result = Result.model_validate_json((run_path / "result.json").read_text(encoding="utf-8"))
                    body = self._body()
                    written = write_report(result, "html", run_path / "reports", redact=bool(body.get("redact")))
                    self._audit("report.render", run_id, {"path": str(written), "redact": bool(body.get("redact"))})
                    return _json(self, 200, {"path": str(written)})
                if path.startswith("/api/monitor/") and path.endswith("/run"):
                    monitor_id = path.split("/")[3]
                    try:
                        monitor = api.monitors.get(monitor_id)
                    except KeyError:
                        return _json(self, 404, {"error": "monitor not found"})
                    try:
                        result = execute(monitor, api.deps)
                    except Exception as exc:
                        api.monitors.finish(monitor, False, str(exc))
                        return _json(self, 500, {"error": f"{type(exc).__name__}: {exc}"})
                    api.monitors.finish(monitor, True)
                    self._audit("monitor.run", monitor.id)
                    return _json(self, 200, result)
                if path == "/api/alerts/ack":
                    body = self._body()
                    if body.get("all"):
                        count = api.monitors.ack_all()
                        self._audit("alerts.ack_all", details={"acked": count})
                        return _json(self, 200, {"acked": count})
                    alert_id = str(body.get("id", ""))
                    if not alert_id:
                        return _json(self, 400, {"error": "id required"})
                    api.monitors.ack(alert_id)
                    self._audit("alerts.ack", alert_id)
                    return _json(self, 200, {"acked": 1})
                if path == "/api/monitor/tick":
                    results = api.tick()
                    self._audit("monitor.tick", details={"ran": len(results)})
                    return _json(self, 200, results)
                if path == "/api/findings/set":
                    body = self._body()
                    finding_id = str(body.get("id", ""))
                    if not finding_id:
                        return _json(self, 400, {"error": "id required"})
                    try:
                        api.findings.set(finding_id, body.get("severity"), body.get("note"))
                    except KeyError:
                        return _json(self, 404, {"error": "not found"})
                    except ValueError as exc:
                        return _json(self, 400, {"error": str(exc)})
                    self._audit("findings.set", finding_id, {"severity": body.get("severity")})
                    return _json(self, 200, {"ok": True})
                if path == "/api/findings/refresh":
                    body = self._body()
                    try:
                        case = api.cases.get(str(body.get("case", "")))
                    except KeyError:
                        return _json(self, 404, {"error": "case not found"})
                    rows = api.findings.refresh(case.id, case.runs, api.graph)
                    self._audit("findings.refresh", case.id, {"findings": len(rows)})
                    return _json(self, 200, {"findings": len(rows)})
                if path == "/api/findings/ack":
                    body = self._body()
                    if body.get("all"):
                        try:
                            case = api.cases.get(str(body.get("case", "")))
                        except KeyError:
                            return _json(self, 404, {"error": "case not found"})
                        count = api.findings.ack_all(case.id)
                        self._audit("findings.ack_all", case.id, {"acked": count})
                        return _json(self, 200, {"acked": count})
                    finding_id = str(body.get("id", ""))
                    if not finding_id:
                        return _json(self, 400, {"error": "id required"})
                    try:
                        api.findings.ack(finding_id)
                    except KeyError:
                        return _json(self, 404, {"error": "not found"})
                    self._audit("findings.ack", finding_id)
                    return _json(self, 200, {"acked": 1})
                return _json(self, 404, {"error": "not found"})

            if path == "/" and self.command == "GET":
                return _html(self, 200, _dashboard(api, query.get("token", [None])[0]))
            if path == "/api/schema":
                from .models import Result

                return _json(self, 200, Result.model_json_schema(by_alias=True))
            if path == "/api/stats":
                cases_all = api.cases.list_cases(include_archived=True)
                return _json(
                    self,
                    200,
                    {
                        "cases": len(cases_all),
                        "runs": len(api.runs.list(100000)),
                        "alerts_open": len(api.monitors.alerts(include_acked=False, limit=10000)),
                        "findings_open": api.findings.global_stats(),
                        "graph": api.graph.stats(),
                    },
                )
            if path == "/api/audit":
                try:
                    offset = max(0, int(query.get("offset", ["0"])[0]))
                    limit = min(1000, max(1, int(query.get("limit", ["100"])[0])))
                except ValueError:
                    return _json(self, 400, {"error": "limit and offset must be integers"})
                actor = query.get("actor", [""])[0] or None
                event = query.get("action", [""])[0] or None
                return _json(
                    self,
                    200,
                    api.audit.list(limit, offset, actor, event),
                    {"x-total-count": str(api.audit.count(actor, event)), "x-offset": str(offset)},
                )
            if path == "/api/providers":
                return _json(
                    self,
                    200,
                    [
                        {
                            "name": i.name,
                            "capabilities": sorted(i.capabilities),
                            "auth": i.auth,
                            "health_7d": api.deps.health.score(i.name),
                        }
                        for i in registry.infos()
                    ],
                )
            if path == "/api/cases":
                archived = "archived" in query
                all_cases = api.cases.list_cases(archived)
                try:
                    cursor, offset, limit = _page_query(query, 100, 100)
                    page = paginate(
                        all_cases,
                        key=lambda c: (c.updated_at, c.id),
                        scope=f"cases:archived={int(archived)}",
                        limit=limit,
                        cursor=cursor,
                        offset=offset,
                    )
                except InvalidCursor as exc:
                    return _json(self, 400, {"error": f"invalid cursor: {exc}"})
                return _json(
                    self,
                    200,
                    [
                        {"id": c.id, "name": c.name, "runs": len(c.runs), "archived": c.archived, "updated_at": c.updated_at}
                        for c in page.items
                    ],
                    _page_headers(page),
                )
            if path.startswith("/api/cases/") and path.endswith("/search"):
                try:
                    case = api.cases.get(path.split("/")[3])
                except KeyError:
                    return _json(self, 404, {"error": "not found"})
                text = query.get("q", [""])[0].strip()
                hits = api.graph.search(case.runs, text, limit=10000)
                try:
                    cursor, offset, limit = _page_query(query, 100, 500)
                    page = paginate(
                        hits,
                        key=lambda hit: (str(hit["seen"]), str(hit["value"])),
                        scope=f"case-search:{case.id}:{text}",
                        limit=limit,
                        cursor=cursor,
                        offset=offset,
                    )
                except InvalidCursor as exc:
                    return _json(self, 400, {"error": f"invalid cursor: {exc}"})
                return _json(self, 200, page.items, _page_headers(page))
            if path.startswith("/api/cases/"):
                try:
                    case = api.cases.get(path.rsplit("/", 1)[1])
                except KeyError:
                    return _json(self, 404, {"error": "not found"})
                return _json(
                    self,
                    200,
                    {"id": case.id, "name": case.name, "scope": {"allow": case.allow, "deny": case.deny}, "notes": case.notes, "runs": case.runs, "tags": case.tags},
                )
            if path == "/api/runs":
                all_runs = api.runs.list(100000)
                try:
                    cursor, offset, limit = _page_query(query, 20, 1000)
                    page = paginate(
                        all_runs,
                        key=_run_key,
                        scope="runs",
                        limit=limit,
                        cursor=cursor,
                        offset=offset,
                    )
                except InvalidCursor as exc:
                    return _json(self, 400, {"error": f"invalid cursor: {exc}"})
                return _json(
                    self,
                    200,
                    [p.name for p in page.items],
                    _page_headers(page),
                )
            if path.startswith("/api/runs/"):
                try:
                    run_path = api.runs.resolve(path.rsplit("/", 1)[1])
                except FileNotFoundError:
                    return _json(self, 404, {"error": "not found"})
                return _json(self, 200, json.loads((run_path / "result.json").read_text(encoding="utf-8")))
            if path.startswith("/api/graph/"):
                value = path[len("/api/graph/") :]
                data = api.graph.show(value)
                return _json(self, 200 if data else 404, data or {"error": "not found"})
            if path == "/api/alerts":
                include_acked = "acked" in query
                try:
                    cursor, offset, limit = _page_query(query, 100, 1000)
                    page = api.monitors.page_alerts(
                        include_acked=include_acked,
                        limit=limit,
                        cursor=cursor,
                        offset=offset,
                    )
                except InvalidCursor as exc:
                    return _json(self, 400, {"error": f"invalid cursor: {exc}"})
                return _json(self, 200, page.items, _page_headers(page))
            if path == "/api/findings":
                try:
                    case = api.cases.get(query.get("case", [""])[0])
                except KeyError:
                    return _json(self, 404, {"error": "case not found"})
                include_acked = "acked" in query
                all_findings = api.findings.list(case.id, include_acked=include_acked)
                try:
                    cursor, offset, limit = _page_query(query, 100, 1000)
                    page = paginate(
                        all_findings,
                        key=_finding_key,
                        scope=f"findings:case={case.id}:acked={int(include_acked)}",
                        limit=limit,
                        cursor=cursor,
                        offset=offset,
                    )
                except InvalidCursor as exc:
                    return _json(self, 400, {"error": f"invalid cursor: {exc}"})
                frows = [
                    {"id": f.id, "severity": f.severity_override or f.severity, "kind": f.kind, "title": f.title, "acked": f.acked}
                    for f in page.items
                ]
                return _json(self, 200, frows, _page_headers(page))
            if path == "/api/monitor/tick" and self.command == "POST":
                return _json(self, 200, api.tick())
            return _json(self, 404, {"error": "not found"})

        def do_GET(self) -> None:
            try:
                self._route()
            except Exception as exc:
                _json(self, 500, {"error": f"{type(exc).__name__}: {exc}"})

        def do_OPTIONS(self) -> None:
            self.cors_origins = api.cors_origins
            _json(self, 200, {"ok": True})

        def do_POST(self) -> None:
            try:
                self._route()
            except Exception as exc:
                _json(self, 500, {"error": f"{type(exc).__name__}: {exc}"})

        def do_DELETE(self) -> None:
            self.cors_origins = api.cors_origins
            parts = urlsplit(self.path)
            path = parts.path.rstrip("/") or "/"
            token = api.identify(self.headers.get("authorization"), parse_qs(parts.query))
            if token is None:
                return _json(self, HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            if not api.permitted(token, "DELETE"):
                return _json(self, HTTPStatus.FORBIDDEN, {"error": f"role {token.role} cannot DELETE"})
            self.token_name = token.name
            if path.startswith("/api/cases/"):
                case_ref = path.rsplit("/", 1)[1]
                try:
                    case = api.cases.get(case_ref)
                except KeyError:
                    return _json(self, 404, {"error": "not found"})
                api.monitors.delete_case(case.id)
                api.findings.delete_case(case.id)
                api.cases.delete(case.id)
                self._audit("case.delete", case.id, {"name": case.name})
                return _json(self, 200, {"deleted": True})
            return _json(self, 404, {"error": "not found"})

    return Handler


def serve(
    *,
    cases: CaseStore,
    runs: RunStore,
    graph: GraphStore,
    monitors: MonitorStore,
    deps: Dependencies,
    findings: FindingStore,
    tick,
    registry,
    host: str = "127.0.0.1",
    port: int = 8787,
    token: str | None = None,
    tokens: list[ApiToken] | None = None,
    cors_origins: list[str] | None = None,
    audit: AuditStore | None = None,
    allow_anonymous: bool = False,
    limit_per_second: float = 5.0,
    limit_burst: int = 30,
) -> ThreadingHTTPServer:
    if not token and not tokens and host not in ("127.0.0.1", "localhost", "::1") and not allow_anonymous:
        raise ValueError("non-loopback bind needs DENIZ_API_TOKEN or --allow-anonymous")
    api = Api(
        cases=cases,
        runs=runs,
        graph=graph,
        monitors=monitors,
        deps=deps,
        findings=findings,
        tick=tick,
        token=token,
        tokens=tokens,
        cors_origins=cors_origins,
        audit=audit,
        limit_per_second=limit_per_second,
        limit_burst=limit_burst,
    )
    server = ThreadingHTTPServer((host, port), make_handler(api, registry))
    server.daemon_threads = True
    return server


def start_background(**kwargs) -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = serve(**kwargs)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


