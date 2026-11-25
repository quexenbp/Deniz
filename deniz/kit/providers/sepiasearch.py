"""SepiaSearch (PeerTube) video search."""

from __future__ import annotations

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo


class SepiaSearch(Provider):
    info = ProviderInfo(
        name="sepiasearch",
        title="SepiaSearch (PeerTube)",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=1.0,
        burst=1,
        tos_url="https://sepiasearch.org/",
        homepage="https://sepiasearch.org/",
        notes="Federated PeerTube index.",
    )
    cache_ttl = 1800.0
    API = "https://sepiasearch.org/api/v1/search/videos"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("sepiasearch expects a keyword")
        resp = self.client.get(
            self.API,
            params={"search": target.value, "count": 20},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("sepiasearch rate limit", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"sepiasearch returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ParseChanged("sepiasearch returned invalid JSON", provider=self.info.name) from exc

        out = []
        for item in data.get("data", []) if isinstance(data, dict) else []:
            url = item.get("url")
            if not url:
                continue
            out.append(
                Observation(
                    type="url",
                    value=str(url),
                    confidence=0.6,
                    sources=[Source(provider=self.info.name, url=str(url))],
                    attrs={
                        "title": clip(str(item.get("name") or ""), 300),
                        "author": item.get("account", {}).get("displayName"),
                        "duration": item.get("duration"),
                        "published": item.get("publishedAt"),
                    },
                )
            )
        return out
