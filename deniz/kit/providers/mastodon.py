"""Mastodon hashtag timeline."""

from __future__ import annotations

import re

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo

TAG = re.compile(r"[^\w]+")


class Mastodon(Provider):
    info = ProviderInfo(
        name="mastodon",
        title="Mastodon hashtag timeline",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=1.0,
        burst=1,
        tos_url="https://docs.joinmastodon.org/api/",
        homepage="https://mastodon.social/",
        notes="Public hashtag timeline; instance URL may be set in providers.toml.",
    )
    cache_ttl = 600.0

    def _base(self, ctx: Context) -> str:
        return (ctx.auth.get("mastodon", "url") or "https://mastodon.social").rstrip("/")

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("mastodon expects a keyword or hashtag")
        tag = TAG.sub("", target.value.lower()) or target.value.lower()
        base = self._base(ctx)
        resp = self.client.get(
            f"{base}/api/v1/timelines/tag/{tag}",
            params={"limit": 25},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("mastodon rate limit", provider=self.info.name)
        if resp.status == 404:
            raise ProviderDead(f"no #{tag} timeline", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"mastodon returned {resp.status}", provider=self.info.name)
        try:
            statuses = resp.json()
        except ValueError as exc:
            raise ParseChanged("mastodon returned invalid JSON", provider=self.info.name) from exc

        out: list[Observation] = []
        for status in statuses if isinstance(statuses, list) else []:
            url = status.get("url")
            if not url:
                continue
            account = status.get("account") or {}
            out.append(
                Observation(
                    type="url",
                    value=str(url),
                    confidence=0.5,
                    sources=[Source(provider=self.info.name, url=str(url))],
                    attrs={
                        "author": account.get("acct"),
                        "account_url": account.get("url"),
                        "content": clip(re.sub(r"<[^>]+>", " ", str(status.get("content") or "")), 500),
                        "created": status.get("created_at"),
                        "reblogs": status.get("reblogs_count"),
                        "favourites": status.get("favourites_count"),
                    },
                )
            )
        return out
