"""Person profile from Wikipedia search and summary."""

from __future__ import annotations

from urllib.parse import quote

from ..errors import ParseChanged, ProviderDead
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo


class Person(Provider):
    info = ProviderInfo(
        name="person",
        title="Person profile (Wikipedia)",
        capabilities=frozenset({"identity"}),
        auth="none",
        cost="free",
        rate=0.5,
        burst=1,
        tos_url="https://www.mediawiki.org/wiki/API:Main_page",
        homepage="https://en.wikipedia.org/",
        notes="Search + summary; no social profiles.",
    )
    cache_ttl = 3600.0
    API = "https://en.wikipedia.org/w/api.php"
    SUMMARY = "https://en.wikipedia.org/api/rest_v1/page/summary/"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("person expects a name")
        search = self.client.get(
            self.API,
            params={"action": "query", "list": "search", "srsearch": target.value, "srlimit": 5, "format": "json"},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if search.status != 200:
            raise ProviderDead(f"wikipedia returned {search.status}", provider=self.info.name)
        try:
            pages = search.json().get("query", {}).get("search", [])
        except ValueError as exc:
            raise ParseChanged("wikipedia returned invalid JSON", provider=self.info.name) from exc
        if not pages:
            return []

        title = str(pages[0].get("title", ""))
        summary = self.client.get(self.SUMMARY + quote(title.replace(" ", "_")), rate=self.info.rate, burst=self.info.burst)
        if summary.status != 200:
            raise ProviderDead(f"wikipedia summary returned {summary.status}", provider=self.info.name)
        try:
            data = summary.json()
        except ValueError as exc:
            raise ParseChanged("invalid summary JSON", provider=self.info.name) from exc

        url = data.get("content_urls", {}).get("desktop", {}).get("page") or f"https://en.wikipedia.org/wiki/{quote(title.replace(' ', '_'))}"
        source = [Source(provider=self.info.name, url=url)]
        out = [
            Observation(
                type="url",
                value=url,
                confidence=0.7,
                sources=source,
                attrs={"title": title, "description": clip(str(data.get("description") or ""), 300)},
            )
        ]
        extract = data.get("extract")
        if extract:
            out.append(
                Observation(
                    type="note",
                    value=clip(extract, 1200),
                    confidence=0.6,
                    sources=source,
                    attrs={"record": "BIO", "person": title},
                )
            )
        image = (data.get("thumbnail") or {}).get("source")
        if image:
            out.append(Observation(type="url", value=image, confidence=0.5, sources=source, attrs={"kind": "portrait"}))
        return out
