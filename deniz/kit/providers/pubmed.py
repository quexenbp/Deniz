"""PubMed search through NCBI E-utilities."""

from __future__ import annotations

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo


class PubMed(Provider):
    info = ProviderInfo(
        name="pubmed",
        title="PubMed search",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=3.0,
        burst=3,
        tos_url="https://www.ncbi.nlm.nih.gov/home/about/policies/",
        homepage="https://pubmed.ncbi.nlm.nih.gov/",
        notes="NCBI E-utilities; anonymous limit 3 req/s.",
    )
    cache_ttl = 3600.0
    ESEARCH = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi"
    ESUMMARY = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("pubmed expects a keyword target")
        search = self.client.get(
            self.ESEARCH,
            params={"db": "pubmed", "term": target.value, "retmode": "json", "retmax": 20},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if search.status == 429:
            raise RateLimited("pubmed rate limit", provider=self.info.name)
        if search.status != 200:
            raise ProviderDead(f"pubmed returned {search.status}", provider=self.info.name)
        try:
            ids = search.json().get("esearchresult", {}).get("idlist", [])
        except ValueError as exc:
            raise ParseChanged("pubmed returned invalid JSON", provider=self.info.name) from exc
        if not ids:
            return []

        summary = self.client.get(
            self.ESUMMARY,
            params={"db": "pubmed", "id": ",".join(ids), "retmode": "json"},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if summary.status != 200:
            raise ProviderDead(f"pubmed summary returned {summary.status}", provider=self.info.name)
        try:
            result = summary.json().get("result", {})
        except ValueError as exc:
            raise ParseChanged("pubmed summary invalid JSON", provider=self.info.name) from exc

        out = []
        for pubmed_id in ids:
            entry = result.get(pubmed_id) or {}
            title = entry.get("title")
            if not title:
                continue
            url = f"https://pubmed.ncbi.nlm.nih.gov/{pubmed_id}/"
            out.append(
                Observation(
                    type="url",
                    value=url,
                    confidence=0.7,
                    sources=[Source(provider=self.info.name, url=url)],
                    attrs={
                        "title": clip(str(title), 300),
                        "journal": entry.get("fulljournalname"),
                        "published": entry.get("pubdate"),
                        "authors": [a.get("name") for a in entry.get("authors", [])[:5]],
                    },
                )
            )
        return out
