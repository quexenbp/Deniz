"""Dark-web crawl: search Ahmia, then fetch .onion pages through a proxy.

Set ``DENIZ_PROXY=socks5h://127.0.0.1:9050`` for Tor. Without a proxy the
search still runs on clearnet; page fetches fail per host instead.
"""

from __future__ import annotations

import os
import re

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo

AHMIA = "https://ahmia.fi/search/"
ONION = re.compile(r'<a[^>]+href="(http://[a-z2-7]{16,56}\.onion[^"]*)"[^>]*>(.*?)</a>', re.I | re.S)
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
HREF = re.compile(r"href=[\"']([^\"'#]+)[\"']", re.I)
MAX_PAGES = 5


def _clean(raw: str, limit: int) -> str:
    return clip(re.sub(r"<[^>]+>", " ", raw), limit).strip()


class DarkWeb(Provider):
    info = ProviderInfo(
        name="darkweb",
        title="Dark-web crawl (Ahmia + onion fetch)",
        capabilities=frozenset({"darkweb"}),
        auth="none",
        cost="free",
        rate=0.2,
        burst=1,
        max_bytes=500_000,
        budget=3_000_000,
        tos_url="https://ahmia.fi/",
        homepage="https://ahmia.fi/",
        notes="Needs DENIZ_PROXY (socks5h://127.0.0.1:9050) for page fetches.",
    )
    cache_ttl = 3600.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("darkweb expects a keyword")
        depth = min(3, max(1, int(ctx.options.get("depth", 1))))
        search = self.client.get(
            AHMIA, params={"q": target.value}, rate=self.info.rate, burst=self.info.burst
        )
        if search.status == 429:
            raise RateLimited("ahmia rate limit", provider=self.info.name)
        if search.status != 200:
            raise ProviderDead(f"ahmia returned {search.status}", provider=self.info.name)

        proxies = bool(os.environ.get("DENIZ_PROXY"))
        out: list[Observation] = []
        seen: set[str] = set()
        for url, raw_title in ONION.findall(search.text_limited(500_000)):
            if url in seen:
                continue
            seen.add(url)
            title = _clean(raw_title, 200)
            attrs = {"onion": True, "title": title, "fetched": False, "proxy": proxies}
            if proxies:
                try:
                    page = self.client.get(
                        url, rate=self.info.rate, burst=self.info.burst, cache_ttl=self.cache_ttl, timeout=30
                    )
                except Exception:
                    page = None
                if page is not None and page.ok:
                    body = page.text_limited(300_000)
                    attrs["fetched"] = True
                    attrs["status"] = page.status
                    title_match = TITLE.search(body)
                    attrs["page_title"] = _clean(title_match.group(1), 200) if title_match else None
                    links = [
                        href for href in HREF.findall(body)
                        if href.startswith("http") and href != url
                    ]
                    page_links = list(dict.fromkeys(links))[:20]
                    attrs["links"] = page_links
                    if depth > 1:
                        for link in page_links:
                            if ".onion" not in link or link in seen:
                                continue
                            seen.add(link)
                            out.append(
                                Observation(
                                    type="url",
                                    value=link,
                                    confidence=0.45,
                                    sources=[Source(provider=self.info.name, url=url)],
                                    attrs={"onion": True, "depth": 2, "fetched": False, "parent": url},
                                )
                            )
                            if len(out) >= MAX_PAGES * depth:
                                break
            out.append(
                Observation(
                    type="url",
                    value=url,
                    confidence=0.6 if attrs["fetched"] else 0.5,
                    sources=[Source(provider=self.info.name, url=AHMIA)],
                    attrs=attrs,
                )
            )
            if len(out) >= MAX_PAGES * depth:
                break
        return out
