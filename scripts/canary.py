# SPDX-License-Identifier: GPL-3.0-or-later
"""Nightly keyless canary: one live query per provider, record health.

Exit code is 1 when fewer than half of the providers answer. Results are
JSON on stdout; health lands in ``$DENIZ_HOME/state.sqlite3``.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.config import load
from deniz.kit.errors import DenizError, ErrorKind
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.health import BLOCKED, FAIL, OK, PARSE, RATE, HealthStore
from deniz.kit.providers.registry import Registry
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope

CASES = [
    ("openalex", "keyword", "osint"),
    ("arxiv", "keyword", "osint"),
    ("pubmed", "keyword", "osint"),
    ("stackoverflow", "keyword", "python"),
    ("hackernews", "keyword", "osint"),
    ("lemmy", "keyword", "osint"),
    ("mastodon", "keyword", "osint"),
    ("kap", "keyword", "tahsis"),
    ("uyap", "keyword", "tahliye"),
]

MAP = {
    ErrorKind.BLOCKED: BLOCKED,
    ErrorKind.PARSE_CHANGED: PARSE,
    ErrorKind.RATE_LIMITED: RATE,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--only", action="append")
    args = parser.parse_args()

    config = load()
    cache = Cache(config.cache_db)
    health = HealthStore(config.state_db)
    auth = AuthStore(config.providers_file)
    client = HttpClient(cache, Limiter())
    registry = Registry()
    wanted = set(args.only or [])
    rows = []
    for name, kind, value in CASES:
        if wanted and name not in wanted:
            continue
        try:
            provider = registry.get(name)(client)
        except KeyError:
            rows.append({"provider": name, "ok": False, "error": "not registered"})
            continue
        ctx = Context(http=client, scope=Scope(), auth=auth)
        started = time.perf_counter()
        try:
            items = provider.run(Target(type=kind, value=value), ctx)
        except DenizError as exc:
            health.record(name, MAP.get(exc.kind, FAIL))
            rows.append(
                {
                    "provider": name,
                    "ok": False,
                    "kind": exc.kind.value,
                    "error": str(exc),
                    "ms": int((time.perf_counter() - started) * 1000),
                }
            )
        except Exception as exc:  # a canary must not die on one provider
            health.record(name, FAIL)
            rows.append(
                {
                    "provider": name,
                    "ok": False,
                    "kind": type(exc).__name__,
                    "error": str(exc),
                    "ms": int((time.perf_counter() - started) * 1000),
                }
            )
        else:
            health.record(name, OK)
            rows.append(
                {
                    "provider": name,
                    "ok": True,
                    "items": len(items),
                    "ms": int((time.perf_counter() - started) * 1000),
                }
            )
    client.close()
    passed = sum(1 for row in rows if row["ok"])
    summary = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "passed": passed, "total": len(rows), "rows": rows}
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        for row in rows:
            state = "ok" if row["ok"] else f"fail ({row.get('kind', '?')})"
            print(f"{row['provider']:16} {state} {row.get('ms', 0)} ms")
        print(f"\n{passed}/{len(rows)} providers answered")
    return 0 if rows and passed / len(rows) >= 0.5 else 1


if __name__ == "__main__":
    sys.exit(main())
