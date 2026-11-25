"""Pastebin search through psbdmp.ws."""

from __future__ import annotations

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo


class Pastebin(Provider):
    info = ProviderInfo(
        name="pastebin",
        title="Pastebin search (psbdmp)",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=0.5,
        burst=1,
        tos_url="https://psbdmp.ws/",
        homepage="https://pastebin.com/",
        notes="psbdmp indexes public Pastebin dumps.",
    )
    cache_ttl = 1800.0
    API = "https://psbdmp.ws/api/search/"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("pastebin expects a keyword target")
        resp = self.client.get(
            self.API + target.value.replace(" ", "%20"), rate=self.info.rate, burst=self.info.burst
        )
        if resp.status == 429:
            raise RateLimited("psbdmp rate limit", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"psbdmp returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"psbdmp returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ParseChanged("psbdmp returned invalid JSON", provider=self.info.name) from exc

        entries = data.get("data", []) if isinstance(data, dict) else []
        out = []
        for entry in entries[: ctx.max_items]:
            paste_id = entry.get("id") or entry.get("key")
            if not paste_id:
                continue
            url = f"https://pastebin.com/{paste_id}"
            out.append(
                Observation(
                    type="url",
                    value=url,
                    confidence=0.6,
                    sources=[Source(provider=self.info.name, url=url)],
                    attrs={"tags": entry.get("tags"), "time": entry.get("time")},
                )
            )
        return out
