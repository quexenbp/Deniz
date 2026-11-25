"""Wikipedia full-text search."""

from __future__ import annotations

from urllib.parse import quote

from ..errors import ParseChanged
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo


class Wikipedia(Provider):
    info = ProviderInfo(
        name="wikipedia",
        title="Wikipedia search",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=2.0,
        burst=2,
        tos_url="https://www.mediawiki.org/wiki/API:Search",
        homepage="https://www.wikipedia.org/",
        notes="MediaWiki API, English Wikipedia.",
    )
    cache_ttl = 900.0
    API = "https://en.wikipedia.org/w/api.php"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("wikipedia expects a keyword target")
        resp = self.client.get(
            self.API,
            params={"action": "query", "list": "search", "srsearch": target.value, "format": "json", "srlimit": 20},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status != 200:
            raise ParseChanged(f"wikipedia returned {resp.status}", provider=self.info.name)
        try:
            pages = resp.json().get("query", {}).get("search", [])
        except ValueError as exc:
            raise ParseChanged("wikipedia returned invalid JSON", provider=self.info.name) from exc

        out = []
        for page in pages:
            title = str(page.get("title", ""))
            if not title:
                continue
            url = f"https://en.wikipedia.org/wiki/{quote(title.replace(' ', '_'))}"
            out.append(
                Observation(
                    type="url",
                    value=url,
                    confidence=0.6,
                    sources=[Source(provider=self.info.name, url=url)],
                    attrs={"title": title, "snippet": clip(str(page.get("snippet", "")).replace("<span class=\"searchmatch\">", "").replace("</span>", ""), 300)},
                )
            )
        return out
