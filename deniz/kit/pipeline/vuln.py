# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Vulnerability search with NVD + EPSS enrichment."""

from __future__ import annotations

import time

from ..auth import AuthStore
from ..cache import Cache
from ..config import Config
from ..errors import DenizError, ErrorKind
from ..http import HttpClient
from ..models import Observation, Result, Source, Target
from ..providers.base import Context
from ..providers.health import BLOCKED, FAIL, OK, PARSE, RATE, HealthStore
from ..providers.registry import Registry
from ..scope import Scope

EPSS_URL = "https://api.first.org/data/v1/epss"


def _call(provider, target, ctx, result: Result, health: HealthStore):
    try:
        observations = provider.run(target, ctx)
    except DenizError as exc:
        mapping = {
            ErrorKind.BLOCKED: BLOCKED,
            ErrorKind.PARSE_CHANGED: PARSE,
            ErrorKind.RATE_LIMITED: RATE,
            ErrorKind.AUTH_REQUIRED: FAIL,
        }
        health.record(provider.info.name, mapping.get(exc.kind, FAIL))
        result.error(exc.kind.value, str(exc), provider=provider.info.name, retryable=exc.retryable)
        return []
    health.record(provider.info.name, OK)
    result.stats.providers_used.append(provider.info.name)
    return observations


def run_vuln(
    query: str,
    *,
    config: Config,
    http: HttpClient,
    cache: Cache,
    health: HealthStore,
    registry: Registry,
    auth: AuthStore,
    limit: int = 20,
) -> Result:
    target = Target(type="keyword", value=query)
    result = Result(schema="deniz.result/1", module="vuln.search", provider="nvd", target=target)
    ctx = Context(http=http, scope=Scope(), auth=auth)
    started = time.perf_counter()

    items = _call(registry.get("nvd")(http), target, ctx, result, health)
    items.sort(key=lambda item: float(item.attrs.get("cvss") or 0), reverse=True)
    items = items[:limit]
    for item in items:
        result.add(item)

    ids = [item.value for item in items]
    if ids:
        try:
            resp = http.get(EPSS_URL, params={"cve": ",".join(ids)}, cache_ttl=3600, rate=1, burst=1)
            data = resp.json().get("data", []) if resp.status == 200 else []
        except (DenizError, ValueError):
            data = []
            result.error("epss_failed", "EPSS enrichment unavailable", provider="epss")
        scores = {str(row.get("cve")): row for row in data}
        for item in items:
            row = scores.get(item.value)
            if row:
                item.attrs["epss"] = float(row.get("epss", 0))
                item.attrs["epss_percentile"] = float(row.get("percentile", 0))

    result.dedupe()
    result.stats.duration_ms = int((time.perf_counter() - started) * 1000)
    result.stats.requests = http.stats.requests
    result.stats.cache_hits = http.stats.cache_hits
    return result


def epss_observation(cve: str, score: float, source_url: str) -> Observation:
    return Observation(
        type="note",
        value=f"EPSS {score:.3f}",
        sources=[Source(provider="epss", url=source_url)],
        attrs={"cve": cve},
    )

