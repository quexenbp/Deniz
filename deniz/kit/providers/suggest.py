"""Search-engine query suggestions."""

from __future__ import annotations

from ..errors import ParseChanged
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo

ENDPOINTS = {
    "google": ("https://suggestqueries.google.com/complete/search", {"client": "firefox", "q": "{q}"}),
    "bing": ("https://api.bing.com/osjson.aspx", {"query": "{q}"}),
    "duckduckgo": ("https://duckduckgo.com/ac/", {"q": "{q}", "type": "list"}),
}


class Suggest(Provider):
    info = ProviderInfo(
        name="suggest",
        title="Search suggestions",
        capabilities=frozenset({"suggest"}),
        auth="none",
        cost="free",
        rate=2.0,
        burst=2,
        notes="Google, Bing and DuckDuckGo autocomplete endpoints.",
    )
    cache_ttl = 3600.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("suggest expects a keyword target")
        found: dict[str, Observation] = {}
        errors = 0
        for name, (url, template) in ENDPOINTS.items():
            params = {key: value.format(q=target.value) for key, value in template.items()}
            try:
                resp = self.client.get(url, params=params, rate=self.info.rate, burst=self.info.burst)
                data = resp.json()
            except (Exception, ValueError):
                errors += 1
                continue
            suggestions = data[1] if isinstance(data, list) and len(data) > 1 else []
            for raw in suggestions:
                suggestion = clip(str(raw), 200)
                if not suggestion:
                    continue
                if suggestion in found:
                    found[suggestion].sources.append(Source(provider=self.info.name, url=f"{url}?q={target.value}"))
                    continue
                found[suggestion] = Observation(
                    type="note",
                    value=suggestion,
                    confidence=0.4,
                    sources=[Source(provider=self.info.name, url=f"{url}?q={target.value}")],
                    attrs={"record": "SUGGESTION", "engine": name},
                )
        if errors == len(ENDPOINTS):
            raise ParseChanged("all suggestion endpoints failed", provider=self.info.name)
        return list(found.values())
