# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Deniz command line.

New commands live here. Unknown commands fall through to the legacy REPL so
existing module usage keeps working during the migration.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .audit import AuditStore
from .auth import AuthStore
from .backup import export_backup, restore_backup
from .cache import Cache
from .cases import CaseStore
from .config import Config
from .config import load as load_config
from .errors import DenizError
from .findings import FindingStore
from .graph import GraphStore
from .http import HttpClient, HttpConfig
from .importer import KINDS as IMPORT_KINDS
from .importer import run_import, run_import_nmap
from .models import Result, Target
from .monitors import KINDS, Dependencies, MonitorStore, execute, run_due
from .pipeline.domain import run_domain, validate_domain
from .pipeline.search import run_search
from .pipeline.social import SITES as SOCIAL_SITES
from .pipeline.social import run_social
from .pipeline.vuln import run_vuln
from .providers.base import Context
from .providers.health import HealthStore
from .providers.registry import Registry
from .ratelimit import Limiter
from .report import write_report
from .scope import Scope
from .store import RunStore


@dataclass
class Runtime:
    config: Config
    cache: Cache
    health: HealthStore
    auth: AuthStore
    client: HttpClient
    graph: GraphStore
    cases: CaseStore
    monitors: MonitorStore
    findings: FindingStore
    audit: AuditStore


def _runtime(offline: bool = False) -> Runtime:
    config = load_config()
    cache = Cache(config.cache_db)
    health = HealthStore(config.state_db)
    auth = AuthStore(config.providers_file)
    graph = GraphStore(config.store("graph"))
    cases = CaseStore(config.store("cases"))
    monitors = MonitorStore(config.store("monitors"))
    findings = FindingStore(config.store("findings"))
    audit = AuditStore(config.store("audit"))
    client = HttpClient(cache, Limiter(), HttpConfig(offline=offline))
    return Runtime(config, cache, health, auth, client, graph, cases, monitors, findings, audit)


def _deps(rt: Runtime) -> Dependencies:
    return Dependencies(
        config=rt.config,
        http=rt.client,
        cache=rt.cache,
        health=rt.health,
        registry=Registry(),
        auth=rt.auth,
        runs=RunStore(rt.config.runs_dir),
        graph=rt.graph,
        cases=rt.cases,
        monitors=rt.monitors,
    )


def _print_table(rows: list[list[str]], headers: list[str]) -> None:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))


def cmd_version(args: argparse.Namespace) -> int:
    print(f"deniz {__version__}")
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    if getattr(args, "token", None):
        os.environ["DENIZ_MCP_TOKEN"] = args.token
    if getattr(args, "http", False):
        from deniz.mcp import serve_http

        server = serve_http(args.host, args.port)
        print(f"deniz mcp on http://{args.host}:{server.server_address[1]}/mcp", file=sys.stderr)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0
    from deniz.mcp import serve

    return serve()


def cmd_doctor(args: argparse.Namespace) -> int:
    rt = _runtime()
    checks: list[tuple[str, str, str]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append((name, "ok" if ok else "FAIL", detail))

    add("python", sys.version_info >= (3, 11), f"{sys.version.split()[0]} (need >=3.11)")
    for module in ("httpx", "pydantic", "dns"):
        try:
            __import__(module)
        except ImportError as exc:
            add(f"import:{module}", False, str(exc))
        else:
            add(f"import:{module}", True, "present")
    add("home", True, str(rt.config.home))
    try:
        probe = rt.config.home / ".write-test"
        probe.write_text("x", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        add("home-writable", False, str(exc))
    else:
        add("home-writable", True, "yes")
    add("tls-verify", rt.client.config.verify, "enabled")
    add("cache", True, str(rt.cache.stats()))
    add("graph", True, str(rt.graph.stats()))
    add("database", True, "postgres" if rt.config.db_url else "sqlite")
    proxy = rt.client.config.proxy or os.environ.get("DENIZ_PROXY")
    if proxy:
        parsed = urlsplit(proxy)
        host, port = parsed.hostname or "", parsed.port or 1080
        try:
            with socket.create_connection((host, port), timeout=3):
                pass
        except OSError as exc:
            add("proxy", False, f"{host}:{port}: {exc}")
        else:
            add("proxy", True, f"{host}:{port}")
    else:
        add("proxy", True, "none")
    if rt.config.db_url:
        try:
            import psycopg

            with psycopg.connect(rt.config.db_url, connect_timeout=5) as con:
                con.execute("SELECT 1")
        except Exception as exc:
            add("database-ping", False, str(exc))
        else:
            add("database-ping", True, "select 1 ok")

    scope_path = rt.config.scope_file
    if scope_path:
        try:
            scope = Scope.from_file(scope_path)
            add("scope", True, f"{scope_path} ({len(scope.allow)} allow / {len(scope.deny)} deny)")
        except (OSError, ValueError) as exc:
            add("scope", False, f"{scope_path}: {exc}")
    else:
        add("scope", True, "none (target only)")
    add("providers-file", True, str(rt.config.providers_file) if rt.config.providers_file.exists() else "none")

    warning = rt.auth.file_mode_warning()
    add("providers-mode", warning is None, warning or ("n/a" if not rt.config.providers_file.exists() else "ok"))
    add("searxng", True, "configured" if rt.auth.configured("searxng", "url") else "not configured")

    free = shutil.disk_usage(rt.config.home).free
    add("disk", free > 500 * 1024 * 1024, f"{free // (1024 * 1024)} MB free")

    _print_table([[n, s, d] for n, s, d in checks], ["check", "state", "detail"])
    rt.client.close()
    if args.network:
        try:
            resp = rt.client.get("https://example.com/", cache_ttl=0, rate=2, burst=1)
        except DenizError as exc:
            print(f"\nnetwork: FAIL {exc}")
            return 1
        print(f"\nnetwork: ok ({resp.status})")
    failed = [c for c in checks if c[1] != "ok"]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed")
    return 1 if failed else 0


def cmd_providers(args: argparse.Namespace) -> int:
    registry = Registry()
    rt = _runtime()
    if args.action == "check":
        if not args.name:
            print("provider name required", file=sys.stderr)
            return 2
        try:
            info = registry.get(args.name).info
        except KeyError as exc:
            print(exc, file=sys.stderr)
            return 2
        print(f"{info.name}: {info.title}")
        print(f"capabilities: {', '.join(sorted(info.capabilities))}")
        print(f"auth: {info.auth}  cost: {info.cost}  rate: {info.rate}/s")
        source = rt.auth.source(info.name)
        print(f"credential: {source or 'not configured'}")
        score = rt.health.score(info.name)
        print(f"health(7d): {'unknown' if score is None else f'{score:.0%}'}")
        print(f"hidden: {'yes' if rt.health.hidden(info.name) else 'no'} ({rt.health.samples(info.name)} samples)")
        rt.client.close()
        return 0

    rows = []
    for info in registry.infos():
        hidden = rt.health.hidden(info.name)
        if hidden and not args.all:
            continue
        score = rt.health.score(info.name)
        rows.append(
            [
                info.name + (" (hidden)" if hidden else ""),
                ",".join(sorted(info.capabilities)),
                info.auth,
                info.cost,
                f"{info.rate:g}/s",
                rt.auth.source(info.name) or "-",
                "unknown" if score is None else f"{score:.0%}",
                info.notes,
            ]
        )
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        _print_table(rows, ["provider", "capabilities", "auth", "cost", "rate", "cred", "health7d", "notes"])
    rt.client.close()
    return 0


def cmd_domain(args: argparse.Namespace) -> int:
    try:
        domain = validate_domain(args.domain)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    rt = _runtime(offline=args.offline)
    store = RunStore(rt.config.runs_dir)
    run = store.begin("domain.quick")
    case_scope = None
    if args.case:
        try:
            case_scope = rt.cases.get(args.case).scope()
        except KeyError:
            print(f"case not found: {args.case}", file=sys.stderr)
            return 2
    try:
        result = run_domain(
            domain,
            config=rt.config,
            http=rt.client,
            cache=rt.cache,
            health=rt.health,
            registry=Registry(),
            auth=rt.auth,
            scope=case_scope,
            max_hosts=args.max_hosts,
            probe=not args.no_probe,
            resolve=not args.no_dns,
            typosquat=not args.no_typosquat and not args.offline,
            emailauth=not args.no_emailauth and not args.offline,
            rdap=not args.no_rdap and not args.offline,
            asn=not args.no_asn,
            dnsbl=not args.no_dnsbl,
            tlds=args.tlds,
            entrypoints=not args.no_entrypoints and not args.offline,
            crawl=args.crawl and not args.offline,
            crawl_regex=args.crawl_regex,
            files=args.files and not args.offline,
            dnsbrute=args.dnsbrute,
            discovery=not args.no_discovery and not args.offline,
            urlscan=not args.no_urlscan and not args.offline,
            internetdb=not args.no_internetdb and not args.offline,
            wayback=not args.no_wayback and not args.offline,
            axfr=args.axfr,
            takeover=not args.no_takeover and not args.offline,
            fingerprint=not args.no_fingerprint and not args.offline,
            ports=args.ports and not args.offline,
            max_workers=args.concurrency,
        )
    except DenizError as exc:
        print(f"error: {exc}", file=sys.stderr)
        rt.client.close()
        return 1
    finally:
        rt.client.close()

    result.run_id = run.run_id
    result.module = "domain.quick"
    store.write(run, result)
    rt.graph.record(result)
    if args.case:
        rt.cases.add_run(args.case, run.run_id)

    if args.json:
        print(json.dumps(result.model_dump(mode="json", by_alias=True), indent=2, ensure_ascii=False))
        return 0

    ips: dict[str, list[str]] = {}
    meta: dict[str, dict] = {}
    titles: dict[str, str] = {}
    typo: dict[str, str] = {}
    for item in result.items:
        if item.type == "ip":
            ips.setdefault(item.attrs.get("host", "?"), []).append(item.value)
        elif item.type == "url":
            meta[item.value] = item.attrs
        elif item.type == "title":
            titles[item.attrs.get("url", "")] = item.value
        elif item.attrs.get("typosquat"):
            typo[item.value] = str(item.attrs["typosquat"])

    hosts = [i.value for i in result.items if i.type == "hostname"]
    rows = []
    for host in hosts:
        url = f"https://{host}/"
        attrs = meta.get(url) or meta.get(f"http://{host}/") or {}
        rows.append(
            [
                host,
                ",".join(sorted(set(ips.get(host, [])))) or "-",
                str(attrs.get("status", "-")),
                attrs.get("server", "-") or "-",
                titles.get(url, "-")[:60],
                typo.get(host, ""),
            ]
        )
    print(f"target: {domain}")
    _print_table(rows, ["host", "ip", "http", "server", "title", "typo"])
    posture = [i for i in result.items if i.type == "note" and i.attrs.get("record") in ("SPF", "DMARC", "DKIM", "MX", "RDAP", "RDAP_EXPIRY", "DNSBL")]
    if posture:
        print("\nemail posture:")
        for note in posture:
            print(f"  {note.value}")
    asn_rows = [i for i in result.items if i.type == "asn"]
    if asn_rows:
        print("\nASN: " + ", ".join(sorted({f"{i.value} ({i.attrs.get('prefix') or '-'})" for i in asn_rows})))
    services = [i for i in result.items if i.type == "service"]
    if services:
        print("\nopen ports:")
        for svc in services:
            print(f"  {svc.value}  {'tls' if svc.attrs.get('tls') else ''}")
    takeovers = [i for i in result.items if i.type == "takeover"]
    if takeovers:
        print("\ntakeover candidates:")
        for item in takeovers:
            print(f"  [{item.confidence:.2f}] {item.value}")
    tech = [i for i in result.items if i.type == "technology"]
    if tech:
        print("\ntechnology: " + ", ".join(sorted({i.value for i in tech})))
    missing = [i for i in result.items if i.attrs.get("record") == "header" and not i.attrs.get("present")]
    if missing:
        print("\nmissing headers: " + ", ".join(sorted({i.attrs["header"] for i in missing})))
    found = [i for i in result.items if i.attrs.get("kind") in ("security_txt", "sitemap", "robots")]
    if found:
        print("\ndiscovery: " + ", ".join(sorted({f"{i.attrs['kind']}={i.value}" for i in found})))
    print(
        f"\n{len(hosts)} hosts, {sum(1 for i in result.items if i.type == 'url')} live, "
        f"{len(typo)} lookalikes, {len(result.errors)} errors"
    )
    print(f"run: {run.path}")
    return 0


def cmd_vuln(args: argparse.Namespace) -> int:
    query = args.query.strip()
    if len(query) < 2:
        print("query too short", file=sys.stderr)
        return 2
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
            limit=args.limit,
        )
    except DenizError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        rt.client.close()

    result.run_id = run.run_id
    store.write(run, result)
    rt.graph.record(result)
    if args.case:
        try:
            rt.cases.add_run(args.case, run.run_id)
        except KeyError:
            print(f"case not found: {args.case}", file=sys.stderr)
    if args.json:
        print(json.dumps(result.model_dump(mode="json", by_alias=True), indent=2, ensure_ascii=False))
        return 0
    rows = []
    for item in result.items:
        rows.append(
            [
                item.value,
                f"{item.attrs.get('cvss', 0):.1f}",
                f"{item.attrs.get('epss', 0):.3f}",
                str(item.attrs.get("severity") or "-"),
                str(item.attrs.get("description", ""))[:70],
            ]
        )
    _print_table(rows, ["CVE", "CVSS", "EPSS", "severity", "description"])
    print(f"\n{len(rows)} CVEs, {len(result.errors)} errors\nrun: {run.path}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    store = RunStore(load_config().runs_dir)
    try:
        path = store.resolve(args.run_id)
    except FileNotFoundError:
        print("run not found", file=sys.stderr)
        return 2
    from .models import Result

    result = Result.model_validate_json((path / "result.json").read_text(encoding="utf-8"))
    out_dir = Path(args.out) if args.out else (path / "reports")
    lang = args.lang or os.environ.get("DENIZ_LANG") or "en"
    try:
        written = write_report(result, args.format, out_dir, redact=args.redact, lang=lang)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(written)
    return 0


def _run_single(
    provider_name: str,
    value: str,
    kind: str,
    json_out: bool = False,
    case_ref: str | None = None,
    options: dict | None = None,
) -> int:
    registry = Registry()
    try:
        provider_cls = registry.get(provider_name)
    except KeyError as exc:
        print(exc, file=sys.stderr)
        return 2
    try:
        target = Target(type=kind, value=value)  # type: ignore[arg-type]
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    rt = _runtime()
    store = RunStore(rt.config.runs_dir)
    run = store.begin(f"provider.{provider_name}")
    ctx = Context(http=rt.client, scope=Scope(allow=[value]), auth=rt.auth)
    if options:
        ctx.options.update(options)
    result = Result(schema="deniz.result/1", module=f"provider.{provider_name}", provider=provider_name, target=target)
    try:
        for item in provider_cls(rt.client).run(target, ctx):
            result.add(item)
    except DenizError as exc:
        result.error(exc.kind.value, str(exc), provider=provider_name)
    finally:
        rt.client.close()
    result.dedupe()
    result.run_id = run.run_id
    store.write(run, result)
    rt.graph.record(result)
    if case_ref:
        try:
            rt.cases.add_run(case_ref, run.run_id)
        except KeyError:
            print(f"case not found: {case_ref}", file=sys.stderr)
    if json_out:
        print(json.dumps(result.model_dump(mode="json", by_alias=True), indent=2, ensure_ascii=False))
    else:
        for item in result.items:
            print(f"{item.type:12} {item.value}  ({item.confidence:.2f})")
        print(f"\n{len(result.items)} items, {len(result.errors)} errors\nrun: {run.path}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    try:
        info = Registry().get(args.provider).info
    except KeyError as exc:
        print(exc, file=sys.stderr)
        return 2
    kind = args.type or ("keyword" if "vuln" in info.capabilities else "domain")
    options = {}
    if getattr(args, "depth", None):
        options["depth"] = args.depth
    if getattr(args, "regex", None):
        options["crawl_regex"] = args.regex
    return _run_single(args.provider, args.value, kind, args.json, args.case, options)


def cmd_identity(args: argparse.Namespace) -> int:
    return _run_single("username", args.username, "username", args.json, args.case)


def cmd_buckets(args: argparse.Namespace) -> int:
    try:
        domain = validate_domain(args.domain)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    return _run_single("buckets", domain, "domain", args.json, args.case)


def cmd_case(args: argparse.Namespace) -> int:
    rt = _runtime()
    if args.action == "new":
        if not args.ref:
            print("case name required", file=sys.stderr)
            return 2
        try:
            case = rt.cases.create(args.ref, allow=args.allow or [], deny=args.deny or [])
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 2
        print(f"{case.id}  {case.name}")
        rt.audit.record("cli", "case.create", case.id, details={"name": case.name})
        return 0
    if args.action == "list":
        rows = [[c.id[:12], c.name, str(len(c.runs)), ",".join(c.tags), "yes" if c.archived else "no", c.updated_at] for c in rt.cases.list_cases(args.archived)]
        _print_table(rows, ["id", "name", "runs", "tags", "archived", "updated"])
        return 0
    if args.action == "prune":
        if args.days is None:
            print("--days is required for prune", file=sys.stderr)
            return 2
        if not args.yes:
            print(f"will delete archived cases older than {args.days} days; pass --yes", file=sys.stderr)
            return 2
        cutoff = datetime.now(UTC) - timedelta(days=args.days)
        removed = 0
        for item in rt.cases.list_cases(include_archived=True):
            if not item.archived:
                continue
            try:
                updated = datetime.fromisoformat(item.updated_at)
            except ValueError:
                continue
            if updated >= cutoff:
                continue
            rt.monitors.delete_case(item.id)
            rt.findings.delete_case(item.id)
            rt.cases.delete(item.id)
            removed += 1
        print(f"pruned {removed} archived cases older than {args.days} days")
        rt.audit.record("cli", "case.prune", "", details={"days": args.days, "removed": removed})
        return 0
    if not args.ref:
        print("case reference required", file=sys.stderr)
        return 2
    try:
        case = rt.cases.get(args.ref)
    except KeyError:
        print(f"case not found: {args.ref}", file=sys.stderr)
        return 2
    if args.action == "show":
        print(
            json.dumps(
                {
                    "id": case.id,
                    "name": case.name,
                    "created_at": case.created_at,
                    "updated_at": case.updated_at,
                    "scope": {"allow": case.allow, "deny": case.deny},
                    "notes": case.notes,
                    "runs": case.runs,
                    "tags": case.tags,
                    "archived": case.archived,
                    "archived_at": case.archived_at,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    if args.action == "note":
        if not args.value:
            print("note text required", file=sys.stderr)
            return 2
        rt.cases.add_note(case.id, args.value)
        rt.audit.record("cli", "case.note", case.id)
        print("note added")
        return 0
    if args.action == "add":
        if not args.value:
            print("run id required", file=sys.stderr)
            return 2
        try:
            rt.cases.add_run(case.id, args.value)
        except KeyError:
            print("run not found", file=sys.stderr)
            return 2
        print(f"added {args.value} to {case.name}")
        return 0
    if args.action in ("tag", "untag"):
        if not args.value:
            print("tag required", file=sys.stderr)
            return 2
        if args.action == "tag":
            rt.cases.add_tag(case.id, args.value)
        else:
            rt.cases.remove_tag(case.id, args.value)
        rt.audit.record("cli", f"case.{args.action}", case.id, details={"tag": args.value})
        print("updated")
        return 0
    if args.action in ("archive", "unarchive"):
        if args.action == "archive":
            rt.cases.archive(case.id)
        else:
            rt.cases.unarchive(case.id)
        rt.audit.record("cli", f"case.{args.action}", case.id)
        print(args.action + "d")
        return 0
    if args.action == "delete":
        if not args.yes:
            print(f"will delete {case.name}; pass --yes", file=sys.stderr)
            return 2
        rt.monitors.delete_case(case.id)
        rt.findings.delete_case(case.id)
        rt.cases.delete(case.id)
        rt.audit.record("cli", "case.delete", case.id, details={"name": case.name})
        print("deleted")
        return 0
    if args.action == "search":
        if not args.value:
            print("search text required", file=sys.stderr)
            return 2
        found = rt.graph.search(case.runs, args.value, args.limit)
        table = [[r["type"], r["value"], r["provider"], r["seen"][:19] if r["seen"] else ""] for r in found]
        _print_table(table, ["type", "value", "provider", "seen"])
        return 0
    if args.action == "trend":
        trend = rt.graph.timeline(case.runs)
        table = [[r["observed_at"][:19], r["module"], str(r["total"]), str(r["new"])] for r in trend]
        _print_table(table, ["at", "module", "entities", "new"])
        return 0
    if args.action == "export":
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        out = Path(args.out) if args.out else (rt.config.home / "exports" / f"{case.name}-{stamp}")
        path = rt.cases.export(
            case.id,
            RunStore(rt.config.runs_dir),
            out,
            rt.findings,
            rt.graph,
            args.zip,
            args.redact,
            args.lang or os.environ.get("DENIZ_LANG") or "en",
        )
        rt.audit.record("cli", "case.export", case.id, details={"path": str(path), "redact": args.redact})
        print(path)
        return 0
    print(f"unknown action: {args.action}", file=sys.stderr)
    return 2


def cmd_monitor(args: argparse.Namespace) -> int:
    rt = _runtime()
    if args.action == "list":
        case_id = None
        if args.case:
            try:
                case_id = rt.cases.get(args.case).id
            except KeyError:
                print(f"case not found: {args.case}", file=sys.stderr)
                return 2
        rows = [
            [m.id[:12], m.kind, m.target, f"{m.every_minutes}m", "on" if m.enabled else "off", m.next_run_at]
            for m in rt.monitors.list_monitors(case_id)
        ]
        _print_table(rows, ["id", "kind", "target", "every", "enabled", "next"])
        return 0
    if args.action == "tick":
        results = run_due(_deps(rt), args.limit)
        rt.audit.record("cli", "monitor.tick", details={"ran": len(results)})
        print(json.dumps(results, indent=2, default=str))
        return 0
    if args.action == "daemon":
        print(f"monitor daemon every {args.poll}s (ctrl-c to stop)", file=sys.stderr)
        try:
            while True:
                for result in run_due(_deps(rt), args.limit):
                    print(json.dumps(result, default=str), flush=True)
                time.sleep(args.poll)
        except KeyboardInterrupt:
            return 0
    if args.action == "add":
        if not (args.ref and args.kind and args.target):
            print("usage: monitor add <case> <kind> <target>", file=sys.stderr)
            return 2
        try:
            case = rt.cases.get(args.ref)
        except KeyError:
            print(f"case not found: {args.ref}", file=sys.stderr)
            return 2
        target = args.target.strip()
        if args.kind in ("domain", "buckets"):
            target = validate_domain(target)
        monitor = rt.monitors.add(case.id, args.kind, target, args.every, args.alert_removed)
        rt.audit.record("cli", "monitor.add", monitor.id, details={"case": case.id, "kind": monitor.kind, "target": target})
        print(f"{monitor.id}  {monitor.kind} {monitor.target} every {monitor.every_minutes}m")
        return 0
    if not args.ref:
        print("monitor id required", file=sys.stderr)
        return 2
    try:
        monitor = rt.monitors.get(args.ref)
    except KeyError:
        print(f"monitor not found: {args.ref}", file=sys.stderr)
        return 2
    if args.action == "remove":
        rt.monitors.remove(monitor.id)
        rt.audit.record("cli", "monitor.remove", monitor.id)
        print("removed")
        return 0
    if args.action in ("enable", "disable"):
        rt.monitors.set_enabled(monitor.id, args.action == "enable")
        rt.audit.record("cli", f"monitor.{args.action}", monitor.id)
        print(args.action + "d")
        return 0
    if args.action == "run":
        try:
            result = execute(monitor, _deps(rt))
        except Exception as exc:
            rt.monitors.finish(monitor, False, str(exc))
            rt.audit.record("cli", "monitor.run", monitor.id, outcome="error", details={"error": str(exc)})
            print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        rt.monitors.finish(monitor, True)
        rt.audit.record("cli", "monitor.run", monitor.id)
        print(json.dumps(result, indent=2, default=str))
        return 0
    print(f"unknown action: {args.action}", file=sys.stderr)
    return 2


def cmd_alerts(args: argparse.Namespace) -> int:
    rt = _runtime()
    if args.action == "ack":
        if args.all:
            count = rt.monitors.ack_all()
            rt.audit.record("cli", "alerts.ack_all", details={"acked": count})
            print(f"acked {count}")
            return 0
        if not args.ref:
            print("alert id required", file=sys.stderr)
            return 2
        rt.monitors.ack(args.ref)
        rt.audit.record("cli", "alerts.ack", args.ref)
        print("acked")
        return 0
    case_id = None
    if args.case:
        try:
            case_id = rt.cases.get(args.case).id
        except KeyError:
            print(f"case not found: {args.case}", file=sys.stderr)
            return 2
    rows = []
    for alert in rt.monitors.alerts(case_id=case_id, include_acked=args.acked):
        rows.append(
            [
                alert["id"][:12],
                alert["created_at"][:19],
                alert["kind"],
                "yes" if alert["acked"] else "no",
                alert["summary"],
                json.dumps(alert["details"].get("added", [])[:3], ensure_ascii=False),
            ]
        )
    _print_table(rows, ["id", "at", "kind", "acked", "summary", "added"])
    return 0


def cmd_plugins(args: argparse.Namespace) -> int:
    registry = Registry()
    if args.action == "path":
        path = registry.plugin_dir()
        print(path)
        return 0
    rows = [[info.name, ",".join(sorted(info.capabilities)), "plugin" if registry.is_plugin(info.name) else "builtin"] for info in registry.infos()]
    _print_table(rows, ["provider", "capabilities", "origin"])
    if registry.errors:
        print("\nplugin errors:")
        for err in registry.errors:
            print(f"  {err.source}: {err.error}")
    return 0 if not registry.errors else 1


def cmd_new_provider(args: argparse.Namespace) -> int:
    from .scaffold import new_provider

    try:
        paths = new_provider(Path(args.root), args.name, args.title, force=args.force)
    except (ValueError, FileExistsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for path in paths:
        print(path)
    print("next: fill ProviderInfo and run the generated test")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from . import server as server_mod
    from .tokens import ApiToken, load_tokens

    rt = _runtime()
    token = args.token or os.environ.get("DENIZ_API_TOKEN")
    tokens = load_tokens(rt.config.home)
    if token and token not in {t.secret for t in tokens}:
        tokens.append(ApiToken(name="cli", secret=token, role="admin"))
    cors = args.cors_origin or [item.strip() for item in os.environ.get("DENIZ_CORS_ORIGINS", "").split(",") if item.strip()]
    try:
        srv = server_mod.serve(
            cases=rt.cases,
            runs=RunStore(rt.config.runs_dir),
            graph=rt.graph,
            monitors=rt.monitors,
            deps=_deps(rt),
            findings=rt.findings,
            tick=lambda: run_due(_deps(rt), 50),
            registry=Registry(),
            host=args.host,
            port=args.port,
            token=token,
            tokens=tokens,
            cors_origins=cors or None,
            audit=rt.audit,
            allow_anonymous=args.allow_anonymous,
        )
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"deniz api on http://{args.host}:{srv.server_address[1]}  (tokens: {len(tokens)})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    rt = _runtime()
    if args.action == "set":
        if not args.ref or not args.value:
            print("usage: findings set <id> <severity> [--note TEXT]", file=sys.stderr)
            return 2
        try:
            rt.findings.set(args.ref, args.value, args.note)
        except KeyError:
            print("finding not found", file=sys.stderr)
            return 2
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 2
        print("updated")
        rt.audit.record("cli", "findings.set", args.ref, details={"severity": args.value})
        return 0
    if args.action == "ack" and args.ref and not args.all:
        try:
            rt.findings.ack(args.ref)
        except KeyError:
            print("finding not found", file=sys.stderr)
            return 2
        rt.audit.record("cli", "findings.ack", args.ref)
        print("acked")
        return 0
    if not args.case:
        print("--case required", file=sys.stderr)
        return 2
    try:
        case = rt.cases.get(args.case)
    except KeyError:
        print(f"case not found: {args.case}", file=sys.stderr)
        return 2
    if args.action == "refresh":
        rows = rt.findings.refresh(case.id, case.runs, rt.graph)
        rt.audit.record("cli", "findings.refresh", case.id, details={"findings": len(rows)})
        print(f"{len(rows)} findings")
        return 0
    if args.action == "ack":
        count = rt.findings.ack_all(case.id)
        rt.audit.record("cli", "findings.ack_all", case.id, details={"acked": count})
        print(f"acked {count}")
        return 0
    table = []
    for finding in rt.findings.list(case.id, include_acked=args.acked):
        effective = finding.severity_override or finding.severity
        if args.severity and effective != args.severity:
            continue
        if args.kind and finding.kind != args.kind:
            continue
        table.append(
            [
                finding.severity_override or finding.severity,
                finding.kind,
                finding.title,
                "yes" if finding.acked else "no",
                finding.note or "",
                finding.id[:12],
            ]
        )
    _print_table(table, ["severity", "kind", "finding", "acked", "note", "id"])
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    query = args.query.strip()
    if len(query) < 2:
        print("query too short", file=sys.stderr)
        return 2
    filetype = (args.filetype or "").lower().lstrip(".")
    if filetype and (not filetype.isalnum() or len(filetype) > 6):
        print("invalid --filetype", file=sys.stderr)
        return 2
    site = None
    if args.site:
        try:
            site = validate_domain(args.site)
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 2
    rt = _runtime()
    store = RunStore(rt.config.runs_dir)
    run = store.begin("search.docs" if filetype else "search.web")
    try:
        result = run_search(
            query,
            config=rt.config,
            http=rt.client,
            cache=rt.cache,
            health=rt.health,
            registry=Registry(),
            auth=rt.auth,
            limit=args.limit,
            per_provider=args.per_provider,
            include_code=args.code,
            filetype=filetype or None,
            site=site,
        )
    except DenizError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        rt.client.close()
    result.run_id = run.run_id
    store.write(run, result)
    rt.graph.record(result)
    if args.case:
        try:
            rt.cases.add_run(args.case, run.run_id)
        except KeyError:
            print(f"case not found: {args.case}", file=sys.stderr)
    if args.json:
        print(json.dumps(result.model_dump(mode="json", by_alias=True), indent=2, ensure_ascii=False))
        return 0
    rows = []
    for item in result.items:
        rows.append([item.sources[0].provider, item.type, item.value[:100], str(item.attrs.get("title", ""))[:60]])
    _print_table(rows, ["provider", "type", "value", "title"])
    print(f"\n{len(rows)} results, {len(result.errors)} errors\nrun: {run.path}")
    return 0


def cmd_social(args: argparse.Namespace) -> int:
    query = args.query.strip()
    if len(query) < 2:
        print("query too short", file=sys.stderr)
        return 2
    rt = _runtime()
    store = RunStore(rt.config.runs_dir)
    run = store.begin("social.web")
    try:
        result = run_social(
            query,
            config=rt.config,
            http=rt.client,
            cache=rt.cache,
            health=rt.health,
            registry=Registry(),
            auth=rt.auth,
            sites=args.site,
            limit=args.limit,
            per_site=args.per_site,
        )
    except DenizError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        rt.client.close()
    result.run_id = run.run_id
    store.write(run, result)
    rt.graph.record(result)
    if args.case:
        try:
            rt.cases.add_run(args.case, run.run_id)
        except KeyError:
            print(f"case not found: {args.case}", file=sys.stderr)
    if args.json:
        print(json.dumps(result.model_dump(mode="json", by_alias=True), indent=2, ensure_ascii=False))
        return 0
    rows = [[str(item.attrs.get("site", "")), str(item.attrs.get("kind", "")), item.value[:110], str(item.attrs.get("title", ""))[:50]] for item in result.items]
    _print_table(rows, ["site", "kind", "url", "title"])
    print(f"\n{len(rows)} results, {len(result.errors)} errors\nrun: {run.path}")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    rt = _runtime()
    try:
        case = rt.cases.get(args.case)
    except KeyError:
        print(f"case not found: {args.case}", file=sys.stderr)
        return 2
    if args.file == "-":
        text = sys.stdin.read()
        source = "stdin://import"
    else:
        try:
            text = Path(args.file).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        source = f"file://{Path(args.file).name}"
    runs = RunStore(rt.config.runs_dir)
    if args.kind == "nmap":
        try:
            result = run_import_nmap(text, source_url=source, runs=runs, graph=rt.graph)
        except (ValueError, ET.ParseError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    else:
        result = run_import(
            args.kind,
            text.splitlines(),
            case_id=case.id,
            source_url=source,
            runs=runs,
            graph=rt.graph,
        )
    rt.cases.add_run(case.id, result.run_id)
    rt.audit.record("cli", "import", case.id, details={"kind": args.kind, "items": len(result.items)})
    print(f"{len(result.items)} {args.kind} imported\nrun: {result.run_id}")
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    rt = _runtime()
    out = Path(args.out).expanduser()
    path = export_backup(
        out,
        runs=RunStore(rt.config.runs_dir),
        cases=rt.cases,
        monitors=rt.monitors,
        findings=rt.findings,
        graph=rt.graph,
        include_files=not args.no_files,
        audit=rt.audit,
    )
    print(path)
    rt.audit.record("cli", "backup", str(path))
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    rt = _runtime()
    try:
        counts = restore_backup(
            Path(args.dir).expanduser(),
            runs=RunStore(rt.config.runs_dir),
            cases=rt.cases,
            monitors=rt.monitors,
            findings=rt.findings,
            graph=rt.graph,
            force=args.force,
            audit=rt.audit,
        )
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(counts, indent=2))
    rt.audit.record("cli", "restore", args.dir, details=counts)
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    rt = _runtime()
    if args.action == "prune":
        if not args.yes:
            print(f"will delete audit entries older than {args.days} days; pass --yes", file=sys.stderr)
            return 2
        removed = rt.audit.prune(args.days)
        print(f"pruned {removed} audit entries")
        return 0
    if args.json:
        print(json.dumps(rt.audit.list(args.limit, args.offset, args.actor, args.event), indent=2, ensure_ascii=False))
        return 0
    rows = [
        [row["created_at"][:19], row["actor"], row["action"], row["target"], row["outcome"]]
        for row in rt.audit.list(args.limit, args.offset, args.actor, args.event)
    ]
    _print_table(rows, ["at", "actor", "action", "target", "outcome"])
    print(f"\n{rt.audit.count(args.actor, args.event)} entries")
    return 0


def cmd_tui(args: argparse.Namespace) -> int:
    try:
        from .tui import run
    except ImportError:
        print("TUI needs: pip install 'deniz[tui]'", file=sys.stderr)
        return 1
    return run()


def cmd_schema(args: argparse.Namespace) -> int:
    from .models import Result

    print(json.dumps(Result.model_json_schema(by_alias=True), indent=2))
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    rt = _runtime()
    cases = rt.cases.list_cases(include_archived=True)
    data = {
        "cases": len(cases),
        "cases_archived": sum(1 for c in cases if c.archived),
        "runs": len(RunStore(rt.config.runs_dir).list(100000)),
        "monitors": len(rt.monitors.list_monitors()),
        "alerts_open": len(rt.monitors.alerts(include_acked=False, limit=10000)),
        "findings_open": rt.findings.global_stats(),
        "graph": rt.graph.stats(),
        "cache": rt.cache.stats(),
        "providers": {i.name: rt.health.score(i.name) for i in Registry().infos()},
    }
    print(json.dumps(data, indent=2))
    return 0


def cmd_cache(args: argparse.Namespace) -> int:
    rt = _runtime()
    if args.action == "clear":
        print(f"removed {rt.cache.clear()} entries")
    elif args.action == "prune":
        print(f"pruned {rt.cache.prune()} expired entries")
    else:
        print(json.dumps(rt.cache.stats(), indent=2))
    return 0


def cmd_runs(args: argparse.Namespace) -> int:
    store = RunStore(load_config().runs_dir)
    if args.action == "prune" and args.prune_days is None:
        args.prune_days = 30
    if args.prune_days is not None:
        import time

        keep: set[str] = set()
        rt = _runtime()
        if not args.include_case_runs:
            for case in rt.cases.list_cases(include_archived=True):
                keep.update(case.runs)
        cutoff = time.time() - args.prune_days * 86400
        removed: list[str] = []
        for path in store.list(100000):
            run_id = path.name.split("-")[0]
            if run_id in keep or path.stat().st_mtime > cutoff:
                continue
            shutil.rmtree(path)
            removed.append(run_id)
        dropped = rt.graph.drop_runs(removed)
        rt.audit.record("cli", "runs.prune", details={"days": args.prune_days, "removed": len(removed)})
        print(f"removed {len(removed)} run directories, {dropped['observations']} observations")
        return 0
    if args.show:
        try:
            path = store.resolve(args.show)
        except FileNotFoundError:
            print("run not found", file=sys.stderr)
            return 2
        print((path / "summary.json").read_text(encoding="utf-8"))
        return 0
    if args.diff:
        if len(args.diff) != 2:
            print("diff needs two run ids", file=sys.stderr)
            return 2
        rt = _runtime()
        print(json.dumps(rt.graph.diff(args.diff[0], args.diff[1]), indent=2))
        return 0
    for path in store.list(args.limit):
        print(path.name)
    return 0


def cmd_graph(args: argparse.Namespace) -> int:
    rt = _runtime()
    run_ids = None
    if args.case:
        try:
            run_ids = rt.cases.get(args.case).runs
        except KeyError:
            print(f"case not found: {args.case}", file=sys.stderr)
            return 2
    if args.action == "stats":
        print(json.dumps(rt.graph.stats(), indent=2))
        return 0
    if args.action == "entities":
        for row in rt.graph.entities(args.type, args.limit, run_ids):
            print(f"{row['type']:12} {row['value']}  {row['first_seen']} .. {row['last_seen']}")
        return 0
    if args.action == "export":
        if not run_ids:
            print("--case required for export", file=sys.stderr)
            return 2
        data = rt.graph.export_graph(run_ids or [])
        prefix = Path(args.out) if args.out else (rt.config.home / "exports" / "graph")
        if args.format == "json":
            path = prefix.with_suffix(".json")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        else:
            import csv

            prefix.parent.mkdir(parents=True, exist_ok=True)
            nodes_path = prefix.with_suffix(".nodes.csv")
            edges_path = prefix.with_suffix(".edges.csv")
            with nodes_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["id", "type", "value"])
                writer.writeheader()
                writer.writerows(data["nodes"])
            with edges_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["source", "target", "relation", "confidence"])
                writer.writeheader()
                writer.writerows(data["edges"])
            print(f"{nodes_path}\n{edges_path}")
            return 0
        print(path)
        return 0
    if args.action == "prune":
        print(json.dumps(rt.graph.prune(args.days), indent=2))
        return 0
    data = rt.graph.show(args.value or "", run_ids)
    if not data:
        print("not found", file=sys.stderr)
        return 2
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="deniz", description="Deniz OSINT workbench")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("version", help="show version")
    p.set_defaults(func=cmd_version)

    p = sub.add_parser("stats", help="overall state summary")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("tui", help="interactive console (needs deniz[tui])")
    p.set_defaults(func=cmd_tui)

    p = sub.add_parser("schema", help="print the result JSON Schema")
    p.set_defaults(func=cmd_schema)

    p = sub.add_parser("mcp", help="run the read-only MCP server (stdio or HTTP)")
    p.add_argument("--http", action="store_true", help="serve JSON-RPC over HTTP with SSE responses")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--token", help="bearer token; defaults to DENIZ_MCP_TOKEN")
    p.set_defaults(func=cmd_mcp)

    p = sub.add_parser("doctor", help="check environment")
    p.add_argument("--network", action="store_true", help="run a live TLS check")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("providers", help="list or inspect providers")
    p.add_argument("action", nargs="?", default="list", choices=["list", "check"])
    p.add_argument("name", nargs="?")
    p.add_argument("--json", action="store_true")
    p.add_argument("--all", action="store_true", help="include quarantined providers")
    p.set_defaults(func=cmd_providers)

    p = sub.add_parser("domain", help="quick attack-surface pass: CT, DNS, HTTP, lookalikes")
    p.add_argument("domain")
    p.add_argument("--max-hosts", type=int, default=200)
    p.add_argument("--concurrency", type=int, default=16)
    p.add_argument("--no-dns", action="store_true")
    p.add_argument("--no-probe", action="store_true")
    p.add_argument("--no-typosquat", action="store_true")
    p.add_argument("--no-emailauth", action="store_true")
    p.add_argument("--no-rdap", action="store_true")
    p.add_argument("--no-asn", action="store_true")
    p.add_argument("--no-dnsbl", action="store_true")
    p.add_argument("--tlds", action="store_true", help="resolve popular TLD variants")
    p.add_argument("--no-entrypoints", action="store_true")
    p.add_argument("--crawl", action="store_true", help="one-level same-origin crawl")
    p.add_argument("--crawl-regex", help="extract matches from crawled pages")
    p.add_argument("--files", action="store_true", help="probe common sensitive paths")
    p.add_argument("--dnsbrute", action="store_true", help="active DNS brute force")
    p.add_argument("--no-discovery", action="store_true")
    p.add_argument("--no-urlscan", action="store_true")
    p.add_argument("--no-internetdb", action="store_true")
    p.add_argument("--no-wayback", action="store_true")
    p.add_argument("--axfr", action="store_true", help="attempt DNS zone transfer")
    p.add_argument("--no-takeover", action="store_true")
    p.add_argument("--no-fingerprint", action="store_true")
    p.add_argument("--ports", action="store_true", help="TCP check on common ports")
    p.add_argument("--offline", action="store_true", help="use HTTP cache only")
    p.add_argument("--case", help="case name or id")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_domain)

    p = sub.add_parser("cache", help="cache statistics")
    p.add_argument("action", nargs="?", default="stats", choices=["stats", "clear", "prune"])
    p.set_defaults(func=cmd_cache)

    p = sub.add_parser("vuln", help="search NVD with EPSS enrichment")
    p.add_argument("query")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--case", help="case name or id")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_vuln)

    p = sub.add_parser("report", help="render a stored run")
    p.add_argument("run_id")
    p.add_argument("--format", choices=["html", "stix", "jsonl", "pdf"], default="html")
    p.add_argument("--out")
    p.add_argument("--redact", action="store_true", help="mask e-mail local parts and phone numbers")
    p.add_argument("--lang", choices=["en", "tr"], help="report language; defaults to DENIZ_LANG or en")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("run", help="run one provider directly")
    p.add_argument("provider")
    p.add_argument("value")
    p.add_argument("--type")
    p.add_argument("--case", help="case name or id")
    p.add_argument("--json", action="store_true")
    p.add_argument("--depth", type=int, help="darkweb crawl depth (1-3)")
    p.add_argument("--regex", help="crawl page regex")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("identity", help="username profile enumeration")
    p.add_argument("username")
    p.add_argument("--case", help="case name or id")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_identity)

    p = sub.add_parser("buckets", help="cloud bucket existence check for a domain")
    p.add_argument("domain")
    p.add_argument("--case", help="case name or id")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_buckets)

    p = sub.add_parser("case", help="manage investigation cases")
    p.add_argument("action", choices=["new", "list", "show", "note", "add", "export", "trend", "archive", "unarchive", "delete", "prune", "search", "tag", "untag"])
    p.add_argument("ref", nargs="?", help="case name or id")
    p.add_argument("value", nargs="?", help="note text or run id")
    p.add_argument("--allow", action="append")
    p.add_argument("--deny", action="append")
    p.add_argument("--archived", action="store_true", help="include archived cases in list")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--zip", action="store_true")
    p.add_argument("--redact", action="store_true", help="mask e-mail local parts and phone numbers on export")
    p.add_argument("--lang", choices=["en", "tr"], help="HTML language; defaults to DENIZ_LANG or en")
    p.add_argument("--days", type=int, help="prune archived cases older than N days")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--out")
    p.set_defaults(func=cmd_case)

    p = sub.add_parser("monitor", help="scheduled monitors")
    p.add_argument("action", choices=["add", "list", "run", "remove", "enable", "disable", "tick", "daemon"])
    p.add_argument("ref", nargs="?", help="case id (add) or monitor id")
    p.add_argument("kind", nargs="?", choices=KINDS)
    p.add_argument("target", nargs="?")
    p.add_argument("--every", type=int, default=60, help="minutes between runs (min 5)")
    p.add_argument("--alert-removed", action="store_true")
    p.add_argument("--case")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--poll", type=int, default=30)
    p.set_defaults(func=cmd_monitor)

    p = sub.add_parser("alerts", help="review monitor alerts")
    p.add_argument("action", choices=["list", "ack"], nargs="?", default="list")
    p.add_argument("ref", nargs="?")
    p.add_argument("--case")
    p.add_argument("--all", action="store_true")
    p.add_argument("--acked", action="store_true", help="include acknowledged")
    p.set_defaults(func=cmd_alerts)

    p = sub.add_parser("audit", help="inspect or prune the audit log")
    p.add_argument("action", nargs="?", choices=["list", "prune"], default="list")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--actor")
    p.add_argument("--event", help="filter by action name")
    p.add_argument("--days", type=int, default=90)
    p.add_argument("--json", action="store_true")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("serve", help="read-only HTTP API and dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--token")
    p.add_argument("--cors-origin", action="append", help="allowed browser origin; repeatable, default *")
    p.add_argument("--allow-anonymous", action="store_true")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("plugins", help="list provider plugins")
    p.add_argument("action", nargs="?", default="list", choices=["list", "path"])
    p.set_defaults(func=cmd_plugins)

    p = sub.add_parser("new-provider", help="scaffold a provider and its contract test")
    p.add_argument("name")
    p.add_argument("--title")
    p.add_argument("--root", default=".")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_new_provider)

    p = sub.add_parser("findings", help="derived findings for a case")
    p.add_argument("action", choices=["list", "refresh", "ack", "set"], nargs="?", default="list")
    p.add_argument("ref", nargs="?")
    p.add_argument("value", nargs="?")
    p.add_argument("--case")
    p.add_argument("--note")
    p.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"])
    p.add_argument("--kind")
    p.add_argument("--all", action="store_true")
    p.add_argument("--acked", action="store_true", help="include acknowledged")
    p.set_defaults(func=cmd_findings)

    p = sub.add_parser("backup", help="export state to a directory")
    p.add_argument("out")
    p.add_argument("--no-files", action="store_true")
    p.set_defaults(func=cmd_backup)

    p = sub.add_parser("restore", help="restore state from a backup")
    p.add_argument("dir")
    p.add_argument("--force", action="store_true", help="clear current state first")
    p.set_defaults(func=cmd_restore)

    p = sub.add_parser("import", help="import a list into a case")
    p.add_argument("case")
    p.add_argument("kind", choices=sorted([*IMPORT_KINDS, "nmap"]))
    p.add_argument("file", help="path or - for stdin")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("search", help="multi-provider web search")
    p.add_argument("query")
    p.add_argument("--limit", type=int, default=25)
    p.add_argument("--per-provider", type=int, default=10)
    p.add_argument("--code", action="store_true", help="include code search (token required)")
    p.add_argument("--filetype", help="dork filter, e.g. pdf, docx, xlsx")
    p.add_argument("--site", help="restrict to a domain")
    p.add_argument("--case")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("social", help="site-scoped social search via headless Chromium")
    p.add_argument("query")
    p.add_argument("--site", action="append", choices=sorted(SOCIAL_SITES), help="repeat for several sites")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--per-site", type=int, default=10)
    p.add_argument("--case")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_social)

    p = sub.add_parser("runs", help="list stored runs")
    p.add_argument("action", nargs="?", choices=["list", "prune"], default="list")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--show", help="show a run summary by id prefix")
    p.add_argument("--diff", nargs="+", metavar="RUN", help="diff two run ids")
    p.add_argument("--prune-days", type=int)
    p.add_argument("--include-case-runs", action="store_true")
    p.set_defaults(func=cmd_runs)

    p = sub.add_parser("graph", help="inspect the entity graph")
    p.add_argument("action", nargs="?", default="stats", choices=["stats", "entities", "show", "prune", "export"])
    p.add_argument("value", nargs="?")
    p.add_argument("--type")
    p.add_argument("--case")
    p.add_argument("--out")
    p.add_argument("--format", choices=["json", "csv"], default="json")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--days", type=int, default=90)
    p.set_defaults(func=cmd_graph)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    if not argv:
        parser.print_help()
        return 0
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:  # provider/db failures should not print a traceback
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


