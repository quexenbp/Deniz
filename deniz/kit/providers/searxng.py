# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""SearXNG JSON search provider.

Self-hosted SearXNG is the escape hatch from Google/Bing scraping. It is
optional: set ``DENIZ_SEARXNG_URL`` or ``[searxng] url`` in providers.toml.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..errors import AuthRequired, Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import normalize_hostname
from .base import Context, Provider, ProviderInfo


class Searx(Provider):
    info = ProviderInfo(
        name="searxng",
        title="SearXNG (self-hosted)",
        capabilities=frozenset({"web", "subdomains"}),
        auth="url",
        cost="free",
        rate=1.0,
        burst=2,
        notes="Set DENIZ_SEARXNG_URL. site: queries surface hostnames.",
    )
    cache_ttl = 900.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        base = ctx.auth.get("searxng", "url")
        if not base:
            raise AuthRequired("DENIZ_SEARXNG_URL is not set", provider=self.info.name)
        if target.type != "domain":
            raise ParseChanged("searxng hostname search expects a domain target")
        base = base.rstrip("/")
        token = ctx.auth.get("searxng", "token")
        headers = {"authorization": f"Bearer {token}"} if token else {}
        resp = self.client.get(
            f"{base}/search",
            params={"q": f"site:{target.value}", "format": "json", "categories": "general"},
            headers=headers,
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("searxng rate limit", provider=self.info.name)
        if resp.status in (401, 403):
            raise Blocked(f"searxng returned {resp.status}", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"searxng returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"searxng returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ParseChanged("searxng returned invalid JSON (format=json enabled?)", provider=self.info.name) from exc

        found: dict[str, Observation] = {}
        source_url = f"{base}/search?q=site:{target.value}"
        for result in data.get("results", []) if isinstance(data, dict) else []:
            url = result.get("url") or ""
            host = normalize_hostname(urlsplit(url).hostname or "")
            if not host or not host.endswith("." + target.value):
                continue
            if not ctx.scope.allows(host) or host in found:
                continue
            found[host] = Observation(
                type="hostname",
                value=host,
                confidence=0.5,
                sources=[Source(provider=self.info.name, url=source_url)],
                attrs={"url": url[:300], "title": str(result.get("title", ""))[:200]},
            )
            if len(found) >= ctx.max_items:
                break
        return list(found.values())

