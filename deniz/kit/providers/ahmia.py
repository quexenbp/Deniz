"""Ahmia search for .onion services."""

from __future__ import annotations

import re
from urllib.parse import quote

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo

RESULT = re.compile(r'<a[^>]+href="(http://[a-z2-7]{16,56}\.onion[^"]*)"[^>]*>(.*?)</a>', re.I | re.S)


class Ahmia(Provider):
    info = ProviderInfo(
        name="ahmia",
        title="Ahmia .onion search",
        capabilities=frozenset({"darkweb"}),
        auth="none",
        cost="free",
        rate=0.2,
        burst=1,
        tos_url="https://ahmia.fi/",
        homepage="https://ahmia.fi/",
        notes="Clearnet search page; results are .onion URLs.",
    )
    cache_ttl = 1800.0
    URL = "https://ahmia.fi/search/"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("ahmia expects a keyword target")
        resp = self.client.get(
            self.URL, params={"q": target.value}, rate=self.info.rate, burst=self.info.burst
        )
        if resp.status == 429:
            raise RateLimited("ahmia rate limit", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"ahmia returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"ahmia returned {resp.status}", provider=self.info.name)

        out: list[Observation] = []
        seen: set[str] = set()
        for url, raw_title in RESULT.findall(resp.text_limited(500_000)):
            if url in seen:
                continue
            seen.add(url)
            title = clip(re.sub(r"<[^>]+>", " ", raw_title), 200)
            out.append(
                Observation(
                    type="url",
                    value=url,
                    confidence=0.6,
                    sources=[Source(provider=self.info.name, url=f"{self.URL}?q={quote(target.value)}")],
                    attrs={"title": title, "onion": True},
                )
            )
        return out
