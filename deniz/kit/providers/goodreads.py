"""Goodreads book search (server-rendered results)."""

from __future__ import annotations

import re

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo

ANCHOR = re.compile(
    r'<a[^>]+class="bookTitle"[^>]+href="(/book/show/[^"]+)"[^>]*>(.*?)</a>', re.I | re.S
)
TITLE_ATTR = re.compile(r'title="([^"]+)"', re.I)
AUTHOR = re.compile(r'class="authorName"[^>]*>(?:<span[^>]*>)?(.*?)(?:</span>)?</a>', re.I | re.S)
RATING = re.compile(r'<span class="minirating">(.*?)</span>', re.I | re.S)


def _text(raw: str) -> str:
    return clip(re.sub(r"<[^>]+>", " ", raw), 300).strip()


class Goodreads(Provider):
    info = ProviderInfo(
        name="goodreads",
        title="Goodreads book search",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=0.5,
        burst=1,
        tos_url="https://www.goodreads.com/about/us",
        homepage="https://www.goodreads.com/",
        notes="HTML result page; title, author and rating only.",
    )
    cache_ttl = 1800.0
    URL = "https://www.goodreads.com/search"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("goodreads expects a keyword")
        resp = self.client.get(
            self.URL, params={"q": target.value}, rate=self.info.rate, burst=self.info.burst
        )
        if resp.status == 429:
            raise RateLimited("goodreads rate limit", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"goodreads returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"goodreads returned {resp.status}", provider=self.info.name)

        body = resp.text_limited(800_000)
        out: list[Observation] = []
        seen: set[str] = set()
        for match in ANCHOR.finditer(body):
            path, inner = match.group(1), match.group(2)
            url = f"https://www.goodreads.com{path.split('?', 1)[0]}"
            if url in seen:
                continue
            seen.add(url)
            attr = TITLE_ATTR.search(match.group(0))
            title = clip(attr.group(1), 300) if attr else _text(inner)
            if not title:
                continue
            window = body[match.end() : match.end() + 1200]
            author = AUTHOR.search(window)
            rating = RATING.search(window)
            out.append(
                Observation(
                    type="url",
                    value=url,
                    confidence=0.5,
                    sources=[Source(provider=self.info.name, url=url)],
                    attrs={
                        "title": title,
                        "author": _text(author.group(1)) if author else None,
                        "rating": _text(rating.group(1)) if rating else None,
                    },
                )
            )
            if len(out) >= ctx.max_items:
                break
        return out
