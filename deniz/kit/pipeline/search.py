"""Multi-provider web search."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import zip_longest

from ..auth import AuthStore
from ..cache import Cache
from ..config import Config
from ..errors import DenizError, ErrorKind
from ..http import HttpClient
from ..models import Observation, Result, Target
from ..providers.base import Context
from ..providers.health import BLOCKED, FAIL, OK, PARSE, RATE, HealthStore
from ..providers.registry import Registry
from ..scope import Scope

CAPABILITIES = {"web"}


def run_search(
    query: str,
    *,
    config: Config,
    http: HttpClient,
    cache: Cache,
    health: HealthStore,
    registry: Registry,
    auth: AuthStore,
    limit: int = 25,
    per_provider: int = 10,
    include_code: bool = False,
    filetype: str | None = None,
    site: str | None = None,
) -> Result:
    target = Target(type="keyword", value=query)
    dork = " ".join(part for part in (f"site:{site}" if site else "", f"filetype:{filetype}" if filetype else "", query) if part)
    result = Result(schema="deniz.result/1", module="search.docs" if filetype else "search.web", provider="multi", target=target)
    search_target = Target(type="keyword", value=dork)
    ctx = Context(http=http, scope=Scope(), auth=auth, max_items=per_provider)
    started = time.perf_counter()

    candidates = [cls for cls in registry.select(CAPABILITIES) if cls.info.name != "searxng" or auth.get("searxng", "url")]
    classes = [cls for cls in candidates if not health.hidden(cls.info.name)]
    if not classes:
        classes = candidates
    if include_code:
        classes.extend(registry.select({"code"}))

    def call(cls):
        provider = cls(http)
        try:
            return provider.info.name, provider.run(search_target, ctx), None
        except DenizError as exc:
            return provider.info.name, [], exc

    with ThreadPoolExecutor(max_workers=min(len(classes), 6)) as pool:
        futures = [pool.submit(call, cls) for cls in classes]
        for future in as_completed(futures):
            name, items, exc = future.result()
            if exc:
                mapping = {
                    ErrorKind.BLOCKED: BLOCKED,
                    ErrorKind.PARSE_CHANGED: PARSE,
                    ErrorKind.RATE_LIMITED: RATE,
                    ErrorKind.AUTH_REQUIRED: FAIL,
                }
                health.record(name, mapping.get(exc.kind, FAIL))
                result.error(exc.kind.value, str(exc), provider=name, retryable=exc.retryable)
                continue
            if name not in result.stats.providers_used:
                result.stats.providers_used.append(name)
            health.record(name, OK)
            for item in items[:per_provider]:
                result.add(item)

    result.dedupe()
    groups: dict[str, list] = {}
    for item in result.items:
        groups.setdefault(item.sources[0].provider, []).append(item)
    for group in groups.values():
        group.sort(key=lambda i: -i.confidence)
    merged: list[Observation] = []
    for row in zip_longest(*groups.values()):
        merged.extend(item for item in row if item)
    result.items = merged[:limit]
    result.stats.duration_ms = int((time.perf_counter() - started) * 1000)
    result.stats.requests = http.stats.requests
    result.stats.cache_hits = http.stats.cache_hits
    return result
