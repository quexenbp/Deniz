"""Stack Overflow question search through the Stack Exchange API."""

from __future__ import annotations

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo


class StackOverflow(Provider):
    info = ProviderInfo(
        name="stackoverflow",
        title="Stack Overflow search",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="quota",
        rate=2.0,
        burst=2,
        tos_url="https://api.stackexchange.com/docs",
        homepage="https://stackoverflow.com/",
        notes="Burst-limited; 300 requests/day anonymous.",
    )
    cache_ttl = 900.0
    API = "https://api.stackexchange.com/2.3/search/advanced"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("stackoverflow expects a keyword target")
        resp = self.client.get(
            self.API,
            params={"order": "desc", "sort": "relevance", "q": target.value, "site": "stackoverflow", "pagesize": 25},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("stackexchange quota", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"stackexchange returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"stackexchange returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ParseChanged("stackexchange returned invalid JSON", provider=self.info.name) from exc

        out: list[Observation] = []
        for item in data.get("items", []) if isinstance(data, dict) else []:
            link = item.get("link")
            if not link:
                continue
            out.append(
                Observation(
                    type="url",
                    value=str(link),
                    confidence=0.6,
                    sources=[Source(provider=self.info.name, url=str(link))],
                    attrs={
                        "title": clip(str(item.get("title", "")), 300),
                        "score": item.get("score"),
                        "answered": item.get("is_answered"),
                        "tags": (item.get("tags") or [])[:10],
                    },
                )
            )
        return out
