# SPDX-License-Identifier: GPL-3.0-or-later
"""RapidDNS passive subdomain listing (HTML table)."""

from __future__ import annotations

import re

from ..errors import Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo

HOST = re.compile(r"<td>([A-Za-z0-9_*-][A-Za-z0-9_.-]*\.[A-Za-z]{2,})</td>", re.I)


class RapidDns(Provider):
    info = ProviderInfo(
        name="rapiddns",
        title="RapidDNS passive subdomains",
        capabilities=frozenset({"subdomain"}),
        auth="none",
        cost="free",
        rate=0.5,
        burst=1,
        max_bytes=600_000,
        notes="HTML table; may rate-limit datacenter IPs.",
        tos_url="https://rapiddns.io/",
        homepage="https://rapiddns.io/",
    )
    cache_ttl = 1800.0
    API = "https://rapiddns.io/subdomain/{domain}?full=1"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type not in ("domain", "hostname"):
            raise ParseChanged("rapiddns expects a domain")
        url = self.API.format(domain=target.value)
        resp = self.client.get(url, rate=self.info.rate, burst=self.info.burst)
        if resp.status == 429:
            raise RateLimited("rapiddns rate limit", provider=self.info.name)
        if resp.status in (403, 503):
            raise Blocked(f"rapiddns returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"rapiddns returned {resp.status}", provider=self.info.name)
        out: list[Observation] = []
        seen: set[str] = set()
        for host in HOST.findall(resp.text_limited(600_000)):
            host = host.lower().rstrip(".")
            if host in seen or not (host == target.value or host.endswith("." + target.value)):
                continue
            seen.add(host)
            out.append(
                Observation(
                    type="hostname",
                    value=host,
                    confidence=0.6,
                    sources=[Source(provider=self.info.name, url=url)],
                )
            )
        return out
