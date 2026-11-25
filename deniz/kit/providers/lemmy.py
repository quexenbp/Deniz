"""Lemmy federated post search."""

from __future__ import annotations

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo


class Lemmy(Provider):
    info = ProviderInfo(
        name="lemmy",
        title="Lemmy post search",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=1.0,
        burst=1,
        tos_url="https://join-lemmy.org/",
        homepage="https://lemmy.world/",
        notes="Public search on lemmy.world; federated posts.",
    )
    cache_ttl = 900.0
    API = "https://lemmy.world/api/v3/search"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("lemmy expects a keyword")
        resp = self.client.get(
            self.API,
            params={"q": target.value, "type_": "Posts", "limit": 25, "sort": "TopAll"},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("lemmy rate limit", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"lemmy returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"lemmy returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ParseChanged("lemmy returned invalid JSON", provider=self.info.name) from exc

        out: list[Observation] = []
        for item in data.get("posts", []) if isinstance(data, dict) else []:
            post = item.get("post") or {}
            url = post.get("url") or (f"https://lemmy.world/post/{post['id']}" if post.get("id") else None)
            if not url:
                continue
            out.append(
                Observation(
                    type="url",
                    value=str(url),
                    confidence=0.55,
                    sources=[Source(provider=self.info.name, url=f"https://lemmy.world/post/{post.get('id', '')}")],
                    attrs={
                        "title": clip(str(post.get("name") or ""), 300),
                        "community": (item.get("community") or {}).get("name"),
                        "creator": (item.get("creator") or {}).get("name"),
                        "score": post.get("score"),
                        "comments": post.get("comments"),
                        "published": post.get("published"),
                    },
                )
            )
        return out
