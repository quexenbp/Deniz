"""OpenAlex scholarly search."""

from __future__ import annotations

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo


class OpenAlex(Provider):
    info = ProviderInfo(
        name="openalex",
        title="OpenAlex scholarly search",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=2.0,
        burst=2,
        tos_url="https://docs.openalex.org/",
        homepage="https://openalex.org/",
        notes="Works search; DOI links only.",
    )
    cache_ttl = 3600.0
    API = "https://api.openalex.org/works"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("openalex expects a keyword target")
        resp = self.client.get(
            self.API,
            params={"search": target.value, "per_page": 25, "mailto": "deniz@example.invalid"},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("openalex rate limit", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"openalex returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"openalex returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ParseChanged("openalex returned invalid JSON", provider=self.info.name) from exc

        out: list[Observation] = []
        for work in data.get("results", []) if isinstance(data, dict) else []:
            doi = work.get("doi")
            url = doi if isinstance(doi, str) else work.get("id")
            if not url:
                continue
            out.append(
                Observation(
                    type="url",
                    value=str(url),
                    confidence=0.7,
                    sources=[Source(provider=self.info.name, url=str(work.get("id") or url))],
                    attrs={
                        "title": clip(str(work.get("title") or ""), 300),
                        "year": work.get("publication_year"),
                        "citations": work.get("cited_by_count"),
                        "type": work.get("type"),
                    },
                )
            )
        return out
