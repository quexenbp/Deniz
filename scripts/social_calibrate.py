# SPDX-License-Identifier: GPL-3.0-or-later
"""Per-site social search calibration.

Needs the browser extra and Chromium. Run on a network without a filtering
proxy; each site is timed separately and failures are reported, not retried.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.config import load
from deniz.kit.errors import DenizError, DependencyMissing
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.social import SITES, Social
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("query", nargs="?", default="owasp")
    parser.add_argument("--site", action="append", choices=sorted(SITES))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--per-site", type=int, default=5)
    args = parser.parse_args()

    config = load()
    client = HttpClient(Cache(config.cache_db), Limiter())
    auth = AuthStore(config.providers_file)
    provider = Social(client)
    rows = []
    for site in args.site or sorted(SITES):
        ctx = Context(http=client, scope=Scope(), auth=auth, options={"sites": [site], "per_site": args.per_site})
        started = time.perf_counter()
        try:
            items = provider.run(Target(type="keyword", value=args.query), ctx)
        except DependencyMissing as exc:
            print(str(exc))
            return 2
        except DenizError as exc:
            rows.append({"site": site, "ok": False, "kind": exc.kind.value, "error": str(exc), "ms": int((time.perf_counter() - started) * 1000)})
        except Exception as exc:
            rows.append({"site": site, "ok": False, "kind": type(exc).__name__, "error": str(exc), "ms": int((time.perf_counter() - started) * 1000)})
        else:
            rows.append({"site": site, "ok": True, "items": len(items), "ms": int((time.perf_counter() - started) * 1000)})
    client.close()
    passed = sum(1 for row in rows if row["ok"])
    if args.json:
        print(json.dumps({"passed": passed, "total": len(rows), "rows": rows}, indent=2))
    else:
        for row in rows:
            print(f"{row['site']:12} {'ok' if row['ok'] else 'fail'} {row.get('items', 0):2} items {row['ms']:5} ms {row.get('error', '')}")
        print(f"\n{passed}/{len(rows)} sites")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
