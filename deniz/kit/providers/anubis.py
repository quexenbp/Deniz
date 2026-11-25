# SPDX-License-Identifier: GPL-3.0-or-later
"""Anubis passive subdomain JSON endpoint."""

from __future__ import annotations

from ..errors import Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo


class Anubis(Provider):
    info = ProviderInfo(
        name="anubis",
        title="Anubis passive subdomains",
        capabilities=frozenset({"subdomain"}),
        auth="none",
        cost="free",
        rate=0.5,
        burst=1,
        max_bytes=600_000,
        notes="Community JSON service; availability varies.",
        tos_url="https://jldc.me/",
        homepage="https://jldc.me/anubis/subdomains",
    )
    cache_ttl = 1800.0
    API = "https://jldc.me/anubis/subdomains/{domain}"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type not in ("domain", "hostname"):
            raise ParseChanged("anubis expects a domain")
        url = self.API.format(domain=target.value)
        resp = self.client.get(url, rate=self.info.rate, burst=self.info.burst)
        if resp.status == 429:
            raise RateLimited("anubis rate limit", provider=self.info.name)
        if resp.status in (403, 503):
            raise Blocked(f"anubis returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"anubis returned {resp.status}", provider=self.info.name)
        try:
            rows = resp.json()
        except ValueError as exc:
            raise ParseChanged("anubis returned invalid JSON", provider=self.info.name) from exc
        out: list[Observation] = []
        seen: set[str] = set()
        for host in rows if isinstance(rows, list) else []:
            host = str(host).lower().rstrip(".")
            if host in seen or not (host == target.value or host.endswith("." + target.value)):
                continue
            seen.add(host)
            out.append(
                Observation(
                    type="hostname",
                    value=host,
                    confidence=0.55,
                    sources=[Source(provider=self.info.name, url=url)],
                )
            )
        return out
