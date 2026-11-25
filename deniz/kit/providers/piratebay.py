"""The Pirate Bay search through the apibay JSON endpoint."""

from __future__ import annotations

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo


class PirateBay(Provider):
    info = ProviderInfo(
        name="piratebay",
        title="The Pirate Bay",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=0.5,
        burst=1,
        tos_url="https://apibay.org/",
        homepage="https://thepiratebay.org/",
        notes="apibay.org JSON mirror.",
    )
    cache_ttl = 900.0
    API = "https://apibay.org/q.php"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("piratebay expects a keyword")
        resp = self.client.get(self.API, params={"q": target.value, "cat": 0}, rate=self.info.rate, burst=self.info.burst)
        if resp.status == 429:
            raise RateLimited("apibay rate limit", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"apibay returned {resp.status}", provider=self.info.name)
        try:
            entries = resp.json()
        except ValueError as exc:
            raise ParseChanged("apibay returned invalid JSON", provider=self.info.name) from exc

        out = []
        for entry in entries if isinstance(entries, list) else []:
            if str(entry.get("id")) == "0":
                continue
            name = entry.get("name")
            if not name:
                continue
            url = f"https://thepiratebay.org/description.php?id={entry['id']}"
            out.append(
                Observation(
                    type="url",
                    value=url,
                    confidence=0.6,
                    sources=[Source(provider=self.info.name, url=url)],
                    attrs={
                        "title": clip(str(name), 300),
                        "seeders": entry.get("seeders"),
                        "leechers": entry.get("leechers"),
                        "size": entry.get("size"),
                        "category": entry.get("category"),
                        "info_hash": entry.get("info_hash"),
                    },
                )
            )
        return out
