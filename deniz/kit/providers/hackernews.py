"""Hacker News search through the Algolia API."""

from __future__ import annotations

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo


class HackerNews(Provider):
    info = ProviderInfo(
        name="hackernews",
        title="Hacker News search",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=2.0,
        burst=2,
        tos_url="https://hn.algolia.com/api",
        homepage="https://news.ycombinator.com/",
        notes="Algolia index; stories and comments.",
    )
    cache_ttl = 900.0
    API = "https://hn.algolia.com/api/v1/search"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("hackernews expects a keyword")
        resp = self.client.get(
            self.API,
            params={"query": target.value, "hitsPerPage": 30, "tags": "(story,comment)"},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("hn rate limit", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"hn returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"hn returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ParseChanged("hn returned invalid JSON", provider=self.info.name) from exc

        out: list[Observation] = []
        seen: set[str] = set()
        for hit in data.get("hits", []) if isinstance(data, dict) else []:
            object_id = hit.get("objectID")
            if not object_id:
                continue
            url = hit.get("url")
            value = str(url) if url else f"https://news.ycombinator.com/item?id={object_id}"
            if value in seen:
                continue
            seen.add(value)
            out.append(
                Observation(
                    type="url",
                    value=value,
                    confidence=0.6,
                    sources=[Source(provider=self.info.name, url=f"https://news.ycombinator.com/item?id={object_id}")],
                    attrs={
                        "title": clip(str(hit.get("title") or hit.get("story_title") or ""), 300),
                        "author": hit.get("author"),
                        "points": hit.get("points"),
                        "comments": hit.get("num_comments"),
                        "created": hit.get("created_at"),
                        "hn_id": object_id,
                    },
                )
            )
        return out
