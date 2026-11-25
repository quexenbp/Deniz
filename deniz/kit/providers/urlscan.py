"""URLScan.io public search for a domain."""

from __future__ import annotations

from ..errors import Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import normalize_hostname
from .base import Context, Provider, ProviderInfo


class Urlscan(Provider):
    info = ProviderInfo(
        name="urlscan",
        title="URLScan.io search",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="quota",
        rate=0.2,
        burst=1,
        tos_url="https://urlscan.io/about-api/",
        homepage="https://urlscan.io/",
        notes="Public search; anonymous quota is small.",
    )
    cache_ttl = 1800.0
    API = "https://urlscan.io/api/v1/search/"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "domain":
            raise ParseChanged("urlscan expects a domain target")
        resp = self.client.get(
            self.API,
            params={"q": f"page.domain:{target.value}", "size": 100},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("urlscan rate limit", provider=self.info.name)
        if resp.status in (401, 403):
            raise Blocked(f"urlscan returned {resp.status}", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"urlscan returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"urlscan returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ParseChanged("urlscan returned invalid JSON", provider=self.info.name) from exc

        out: list[Observation] = []
        seen_urls: set[str] = set()
        for result in data.get("results", []):
            page = result.get("page") or {}
            url = str(page.get("url") or "")
            ip = str(page.get("ip") or "")
            source = [Source(provider=self.info.name, url=str(result.get("task", {}).get("url") or url))]
            if url and url not in seen_urls:
                seen_urls.add(url)
                out.append(
                    Observation(
                        type="url",
                        value=url,
                        confidence=0.7,
                        sources=source,
                        attrs={
                            "server": page.get("server"),
                            "asn": page.get("asnname"),
                            "country": page.get("country"),
                            "status": page.get("status"),
                        },
                    )
                )
            if ip:
                out.append(
                    Observation(
                        type="ip",
                        value=ip,
                        confidence=0.7,
                        sources=source,
                        attrs={"host": normalize_hostname(page.get("domain") or "") or target.value},
                    )
                )
        return out
