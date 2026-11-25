# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Certificate Transparency via the Cert Spotter API (fallback for crt.sh)."""

from __future__ import annotations

from datetime import datetime

from ..errors import Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import normalize_hostname
from .base import Context, Provider, ProviderInfo


def _when(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class Certspotter(Provider):
    info = ProviderInfo(
        name="certspotter",
        title="Cert Spotter issuances API",
        capabilities=frozenset({"subdomains", "passive"}),
        auth="none",
        cost="quota",
        rate=0.05,
        burst=1,
        tos_url="https://sslmate.com/ct_search_api/",
        homepage="https://sslmate.com/certspotter/",
        notes="Unauthenticated quota is low; use a token for volume.",
    )
    cache_ttl = 3600.0
    URL = "https://api.certspotter.com/v1/issuances"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "domain":
            raise ParseChanged("certspotter expects a domain target")
        token = ctx.auth.get("certspotter")
        headers = {"authorization": f"Bearer {token}"} if token else {}
        resp = self.client.get(
            self.URL,
            params={"domain": target.value, "include_subdomains": "true", "expand": "dns_names"},
            headers=headers,
            rate=0.5 if token else self.info.rate,
            burst=2 if token else self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("certspotter quota", provider=self.info.name)
        if resp.status in (401, 403):
            raise Blocked(f"certspotter returned {resp.status}", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"certspotter returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"certspotter returned {resp.status}", provider=self.info.name)
        try:
            entries = resp.json()
        except ValueError as exc:
            raise ParseChanged("certspotter returned invalid JSON", provider=self.info.name) from exc

        found: dict[str, Observation] = {}
        for entry in entries if isinstance(entries, list) else []:
            for raw in entry.get("dns_names") or []:
                host = normalize_hostname(str(raw))
                if not host or not (host == target.value or host.endswith("." + target.value)):
                    continue
                if not ctx.scope.allows(host) or host in found:
                    continue
                found[host] = Observation(
                    type="hostname",
                    value=host,
                    confidence=0.7,
                    sources=[Source(provider=self.info.name, url=f"{self.URL}?domain={target.value}")],
                    first_seen=_when(entry.get("not_before")),
                    last_seen=_when(entry.get("not_after")),
                    attrs={"certificate_id": entry.get("id"), "issuer": str(entry.get("issuer", {}).get("name", ""))[:200]},
                )
                if len(found) >= ctx.max_items:
                    return list(found.values())
        return list(found.values())

