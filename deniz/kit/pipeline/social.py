# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Site-scoped social search over a browser session."""

from __future__ import annotations

import time

from ..auth import AuthStore
from ..cache import Cache
from ..config import Config
from ..errors import DenizError, ErrorKind
from ..http import HttpClient
from ..models import Result, Target
from ..providers.base import Context
from ..providers.health import BLOCKED, FAIL, OK, PARSE, RATE, HealthStore
from ..providers.registry import Registry
from ..providers.social import SITES, Social
from ..scope import Scope


def run_social(
    query: str,
    *,
    config: Config,
    http: HttpClient,
    cache: Cache,
    health: HealthStore,
    registry: Registry,
    auth: AuthStore,
    sites: list[str] | None = None,
    limit: int = 50,
    per_site: int = 10,
) -> Result:
    target = Target(type="keyword", value=query)
    result = Result(schema="deniz.result/1", module="social.web", provider="social", target=target)
    ctx = Context(
        http=http,
        scope=Scope(),
        auth=auth,
        max_items=limit,
        options={"sites": sites or [], "per_site": per_site},
    )
    started = time.perf_counter()
    provider = Social(http)
    try:
        items = provider.run(target, ctx)
    except DenizError as exc:
        mapping = {
            ErrorKind.BLOCKED: BLOCKED,
            ErrorKind.PARSE_CHANGED: PARSE,
            ErrorKind.RATE_LIMITED: RATE,
            ErrorKind.AUTH_REQUIRED: FAIL,
        }
        health.record(provider.info.name, mapping.get(exc.kind, FAIL))
        result.error(exc.kind.value, str(exc), provider=provider.info.name, retryable=exc.retryable)
        items = []
    else:
        health.record(provider.info.name, OK)
        result.stats.providers_used.append(provider.info.name)

    for item in items[:limit]:
        result.add(item)
    result.stats.duration_ms = int((time.perf_counter() - started) * 1000)
    result.stats.requests = http.stats.requests
    result.stats.cache_hits = http.stats.cache_hits
    result.stats.providers_used = list(dict.fromkeys(result.stats.providers_used))
    return result


__all__ = ["SITES", "run_social"]
