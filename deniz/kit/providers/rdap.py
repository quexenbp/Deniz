"""RDAP domain registration data."""

from __future__ import annotations

from datetime import UTC, datetime

from ..errors import Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo

RISKY_STATUS = {"client hold", "server hold", "pending delete", "redemption period"}


class Rdap(Provider):
    info = ProviderInfo(
        name="rdap",
        title="RDAP registration record",
        capabilities=frozenset({"whois"}),
        auth="none",
        cost="free",
        rate=1.0,
        burst=2,
        tos_url="https://about.rdap.org/",
        homepage="https://rdap.org/",
        notes="JSON RDAP via the rdap.org redirector.",
    )
    cache_ttl = 21600.0
    URL = "https://rdap.org/domain/"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "domain":
            raise ParseChanged("rdap expects a domain target")
        resp = self.client.get(self.URL + target.value, rate=self.info.rate, burst=self.info.burst)
        if resp.status == 404:
            raise ProviderDead(f"no RDAP record for {target.value}", provider=self.info.name)
        if resp.status == 429:
            raise RateLimited("rdap rate limit", provider=self.info.name)
        if resp.status in (401, 403):
            raise Blocked(f"rdap returned {resp.status}", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"rdap returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"rdap returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ParseChanged("rdap returned invalid JSON", provider=self.info.name) from exc

        source = [Source(provider=self.info.name, url=f"{self.URL}{target.value}")]
        out: list[Observation] = []
        statuses = [str(s) for s in data.get("status", [])]
        events = {str(e.get("eventAction")): str(e.get("eventDate")) for e in data.get("events", [])}
        registrar = None
        for entity in data.get("entities", []):
            roles = [str(r) for r in entity.get("roles", [])]
            if "registrar" in roles:
                for item in entity.get("vcardArray", [None, []])[1]:
                    if item and item[0] == "fn":
                        registrar = str(item[3])
                        break
        nameservers = [str(ns.get("ldhName", "")).lower() for ns in data.get("nameservers", []) if ns.get("ldhName")]

        out.append(
            Observation(
                type="note",
                value=f"RDAP: {len(statuses)} status, registrar {registrar or 'unknown'}",
                confidence=0.9,
                sources=source,
                attrs={
                    "record": "RDAP",
                    "statuses": statuses,
                    "risky_status": [s for s in statuses if s.lower() in RISKY_STATUS],
                    "registrar": registrar,
                    "expires": events.get("expiration"),
                    "registered": events.get("registration"),
                    "updated": events.get("last changed"),
                    "nameservers": nameservers[:20],
                    "host": target.value,
                },
            )
        )
        expires = events.get("expiration")
        if expires:
            try:
                delta = datetime.fromisoformat(expires.replace("Z", "+00:00")) - datetime.now(UTC)
                out.append(
                    Observation(
                        type="note",
                        value=f"Domain expires in {delta.days} days",
                        confidence=0.9,
                        sources=source,
                        attrs={"record": "RDAP_EXPIRY", "days": delta.days, "host": target.value},
                    )
                )
            except ValueError:
                pass
        for ns in nameservers[:20]:
            out.append(
                Observation(
                    type="hostname",
                    value=clip(ns, 253),
                    confidence=0.8,
                    sources=source,
                    attrs={"nameserver": True, "host": target.value},
                )
            )
        return out
