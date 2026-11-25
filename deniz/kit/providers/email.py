"""Email discovery: Hunter.io when configured, pattern + MX fallback otherwise."""

from __future__ import annotations

import dns.exception
import dns.resolver

from ..errors import Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo

PATTERNS = ("info", "admin", "support", "sales", "security", "contact", "hr", "jobs", "billing", "devops", "hello")


class Email(Provider):
    info = ProviderInfo(
        name="email",
        title="Email discovery",
        capabilities=frozenset({"identity"}),
        auth="key",
        cost="quota",
        rate=1.0,
        burst=1,
        tos_url="https://hunter.io/api-documentation",
        homepage="https://hunter.io/",
        notes="Hunter token optional; without it patterns are guesses verified only by MX.",
    )
    cache_ttl = 3600.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "domain":
            raise ParseChanged("email expects a domain target")
        token = ctx.auth.get("email")
        if token:
            return self._hunter(target.value, token, ctx)
        return self._patterns(target.value)

    def _hunter(self, domain: str, token: str, ctx: Context) -> list[Observation]:
        resp = self.client.get(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": domain, "api_key": token, "limit": 100},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("hunter rate limit", provider=self.info.name)
        if resp.status in (401, 403):
            raise Blocked(f"hunter returned {resp.status}", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"hunter returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"hunter returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json().get("data", {})
        except ValueError as exc:
            raise ParseChanged("hunter returned invalid JSON", provider=self.info.name) from exc

        out = []
        for entry in data.get("emails", [])[: ctx.max_items]:
            address = entry.get("value")
            if not address:
                continue
            out.append(
                Observation(
                    type="email",
                    value=str(address).lower(),
                    confidence=min(1.0, float(entry.get("confidence") or 50) / 100),
                    sources=[Source(provider=self.info.name, url=f"https://hunter.io/search/{domain}")],
                    attrs={
                        "first_name": entry.get("first_name"),
                        "last_name": entry.get("last_name"),
                        "position": entry.get("position"),
                        "department": entry.get("department"),
                        "pattern": False,
                    },
                )
            )
        return out

    def _patterns(self, domain: str) -> list[Observation]:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8
        try:
            answer = resolver.resolve(domain, "MX", raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
        if not answer.rrset:
            return []
        source = [Source(provider=self.info.name, url=f"dns://MX/{domain}")]
        return [
            Observation(
                type="email",
                value=f"{pattern}@{domain}",
                confidence=0.4,
                sources=source,
                attrs={"pattern": True, "local": pattern, "guess": True},
            )
            for pattern in PATTERNS
        ]
