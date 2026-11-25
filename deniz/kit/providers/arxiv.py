"""arXiv search through the Atom API."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from ..errors import ParseChanged, ProviderDead
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo

NS = {"a": "http://www.w3.org/2005/Atom"}


class Arxiv(Provider):
    info = ProviderInfo(
        name="arxiv",
        title="arXiv search",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=0.34,
        burst=1,
        tos_url="https://info.arxiv.org/help/api/tou.html",
        homepage="https://arxiv.org/",
        notes="Atom API; keep volume low.",
    )
    cache_ttl = 3600.0
    API = "https://export.arxiv.org/api/query"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("arxiv expects a keyword target")
        resp = self.client.get(
            self.API,
            params={"search_query": f"all:{target.value}", "max_results": 20},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status != 200:
            raise ProviderDead(f"arxiv returned {resp.status}", provider=self.info.name)
        try:
            root = ET.fromstring(resp.text)
        except ET.ParseError as exc:
            raise ParseChanged("arxiv returned invalid XML", provider=self.info.name) from exc
        out = []
        for entry in root.findall("a:entry", NS):
            url = (entry.findtext("a:id", default="", namespaces=NS) or "").strip()
            title = clip(entry.findtext("a:title", default="", namespaces=NS) or "", 300)
            if not url or not title:
                continue
            out.append(
                Observation(
                    type="url",
                    value=url,
                    confidence=0.7,
                    sources=[Source(provider=self.info.name, url=url)],
                    attrs={
                        "title": title,
                        "published": entry.findtext("a:published", default="", namespaces=NS),
                        "summary": clip(entry.findtext("a:summary", default="", namespaces=NS) or "", 500),
                    },
                )
            )
        return out
