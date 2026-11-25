"""Telegram channel/bot search through Lyzem."""

from __future__ import annotations

import re

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo

RESULT = re.compile(
    r'<li class="search-result">.*?title="([^"]*)".*?<a href="(https://t\.me/[^"]+)"[^>]*>\s*(.*?)\s*</a>',
    re.I | re.S,
)


class Telegram(Provider):
    info = ProviderInfo(
        name="telegram",
        title="Telegram channel search (Lyzem)",
        capabilities=frozenset({"social"}),
        auth="none",
        cost="free",
        rate=0.4,
        burst=1,
        tos_url="https://lyzem.com/",
        homepage="https://telegram.org/",
        notes="Lyzem index; channels and bots.",
    )
    cache_ttl = 1800.0
    URL = "https://lyzem.com/search"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("telegram expects a keyword")
        resp = self.client.get(
            self.URL,
            params={"q": target.value, "type": "channels"},
            headers={"accept-language": "en-US,en;q=0.9"},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("lyzem rate limit", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"lyzem returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"lyzem returned {resp.status}", provider=self.info.name)

        out: list[Observation] = []
        seen: set[str] = set()
        for kind, url, title in RESULT.findall(resp.text_limited(500_000)):
            handle = url.rstrip("/").rsplit("/", 1)[-1]
            if handle in seen:
                continue
            seen.add(handle)
            clean_title = clip(re.sub(r"<[^>]+>", " ", title), 200)
            out.append(
                Observation(
                    type="url",
                    value=url,
                    confidence=0.5,
                    sources=[Source(provider=self.info.name, url=url)],
                    attrs={"kind": kind or "unknown", "title": clean_title, "handle": handle},
                )
            )
            if len(out) >= ctx.max_items:
                break
        return out
