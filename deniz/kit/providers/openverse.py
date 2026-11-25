"""Openverse image search."""

from __future__ import annotations

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo


class Openverse(Provider):
    info = ProviderInfo(
        name="openverse",
        title="Openverse image search",
        capabilities=frozenset({"images"}),
        auth="none",
        cost="quota",
        rate=1.0,
        burst=1,
        tos_url="https://api.openverse.org/v1/",
        homepage="https://openverse.org/",
        notes="CC-licensed images; anonymous quota is limited.",
    )
    cache_ttl = 1800.0
    API = "https://api.openverse.org/v1/images/"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("openverse expects a keyword target")
        resp = self.client.get(
            self.API, params={"q": target.value, "page_size": 20}, rate=self.info.rate, burst=self.info.burst
        )
        if resp.status == 429:
            raise RateLimited("openverse rate limit", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"openverse returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"openverse returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ParseChanged("openverse returned invalid JSON", provider=self.info.name) from exc

        out = []
        for item in data.get("results", []) if isinstance(data, dict) else []:
            url = item.get("url")
            if not url:
                continue
            out.append(
                Observation(
                    type="url",
                    value=str(url),
                    confidence=0.5,
                    sources=[Source(provider=self.info.name, url=str(item.get("foreign_landing_url") or url))],
                    attrs={
                        "title": clip(str(item.get("title") or ""), 200),
                        "creator": item.get("creator"),
                        "license": item.get("license"),
                        "source": item.get("source"),
                        "thumbnail": item.get("thumbnail"),
                    },
                )
            )
        return out
