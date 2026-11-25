"""Wikileaks search (search.wikileaks.org)."""

from __future__ import annotations

import re

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo

RESULT = re.compile(r'<a[^>]+href="([^"]*wikileaks\.org[^"]*)"[^>]*>(.*?)</a>', re.I | re.S)


class WikiLeaks(Provider):
    info = ProviderInfo(
        name="wikileaks",
        title="Wikileaks search",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=0.3,
        burst=1,
        tos_url="https://wikileaks.org/",
        homepage="https://wikileaks.org/",
        notes="Cable/leak links only; site is frequently unreachable.",
    )
    cache_ttl = 3600.0
    URL = "https://search.wikileaks.org/"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("wikileaks expects a keyword")
        resp = self.client.get(
            self.URL,
            params={"q": target.value, "sort": 0},
            headers={"user-agent": "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("wikileaks rate limit", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"wikileaks returned {resp.status}", provider=self.info.name)

        out: list[Observation] = []
        seen: set[str] = set()
        for url, raw_title in RESULT.findall(resp.text_limited(800_000)):
            if url in seen:
                continue
            if not any(marker in url for marker in ("/leak/", "/plusd/", "/cable/", "/gifiles/")):
                continue
            seen.add(url)
            out.append(
                Observation(
                    type="url",
                    value=url,
                    confidence=0.6,
                    sources=[Source(provider=self.info.name, url=url)],
                    attrs={"title": clip(re.sub(r"<[^>]+>", " ", raw_title), 300)},
                )
            )
            if len(out) >= ctx.max_items:
                break
        return out
