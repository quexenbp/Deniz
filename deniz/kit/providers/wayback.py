"""Wayback Machine CDX URL history."""

from __future__ import annotations

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import normalize_hostname
from .base import Context, Provider, ProviderInfo


class Wayback(Provider):
    info = ProviderInfo(
        name="wayback",
        title="Wayback Machine CDX",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=1.0,
        burst=1,
        tos_url="https://archive.org/developers/tutorial-getting-started-with-the-cdx-api",
        homepage="https://web.archive.org/",
        notes="URL history only; archived content is not fetched.",
    )
    cache_ttl = 3600.0
    API = "https://web.archive.org/cdx/search/cdx"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "domain":
            raise ParseChanged("wayback expects a domain target")
        resp = self.client.get(
            self.API,
            params={
                "url": f"{target.value}/*",
                "output": "json",
                "fl": "original,timestamp,statuscode",
                "collapse": "urlkey",
                "filter": "statuscode:200",
                "limit": 500,
            },
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("wayback rate limit", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"wayback returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"wayback returned {resp.status}", provider=self.info.name)
        try:
            rows = resp.json()
        except ValueError as exc:
            raise ParseChanged("wayback returned invalid JSON", provider=self.info.name) from exc
        if not isinstance(rows, list) or len(rows) < 2:
            return []

        out: list[Observation] = []
        seen: set[str] = set()
        for url, timestamp, _status in rows[1:]:
            if url in seen or len(seen) >= ctx.max_items:
                continue
            seen.add(url)
            source = [Source(provider=self.info.name, url=f"https://web.archive.org/web/{timestamp}/{url}")]
            out.append(
                Observation(
                    type="url",
                    value=str(url),
                    confidence=0.5,
                    sources=source,
                    attrs={"timestamp": timestamp, "host": target.value},
                )
            )
            host = normalize_hostname(str(url).split("/")[2] if "//" in str(url) else "")
            if host:
                out.append(Observation(type="hostname", value=host, confidence=0.4, sources=source))
        return out
