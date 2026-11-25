# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Hackertarget hostsearch fallback."""

from __future__ import annotations

from ..errors import Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import normalize_hostname
from .base import Context, Provider, ProviderInfo


class Hackertarget(Provider):
    info = ProviderInfo(
        name="hackertarget",
        title="Hackertarget hostsearch",
        capabilities=frozenset({"subdomains", "passive"}),
        auth="none",
        cost="quota",
        rate=0.1,
        burst=1,
        tos_url="https://hackertarget.com/",
        homepage="https://hackertarget.com/",
        notes="Free tier is heavily rate limited; CSV host,ip response.",
    )
    cache_ttl = 3600.0
    URL = "https://api.hackertarget.com/hostsearch/"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "domain":
            raise ParseChanged("hackertarget expects a domain target")
        resp = self.client.get(self.URL, params={"q": target.value}, rate=self.info.rate, burst=self.info.burst)
        if resp.status == 429:
            raise RateLimited("hackertarget quota", provider=self.info.name)
        if resp.status in (401, 403):
            raise Blocked(f"hackertarget returned {resp.status}", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"hackertarget returned {resp.status}", provider=self.info.name)
        text = resp.text.strip()
        if not text or "error" in text.lower()[:80]:
            raise ParseChanged(f"hackertarget says: {text[:120]}", provider=self.info.name)

        found: dict[str, Observation] = {}
        for line in text.splitlines():
            parts = line.split(",")
            if len(parts) != 2:
                continue
            host = normalize_hostname(parts[0])
            if not host or not (host == target.value or host.endswith("." + target.value)):
                continue
            if not ctx.scope.allows(host) or host in found:
                continue
            found[host] = Observation(
                type="hostname",
                value=host,
                confidence=0.65,
                sources=[Source(provider=self.info.name, url=f"{self.URL}?q={target.value}")],
                attrs={"ip": parts[1].strip()},
            )
            if len(found) >= ctx.max_items:
                break
        return list(found.values())

