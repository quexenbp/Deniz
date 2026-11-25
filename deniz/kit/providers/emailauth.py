# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Email authentication posture: SPF, DMARC, DKIM, MX.

Read-only DNS. Emits notes with structured attributes rather than prose so a
report or an agent can reason about the policy.
"""

from __future__ import annotations

import dns.exception
import dns.resolver

from ..errors import ProviderDead
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "s1", "mail", "dkim", "smtp")


def _txt(resolver: dns.resolver.Resolver, name: str) -> list[str]:
    try:
        answer = resolver.resolve(name, "TXT", raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    if answer.rrset is None:
        return []
    return [b"".join(record.strings).decode("utf-8", "replace") for record in answer]


class EmailAuth(Provider):
    info = ProviderInfo(
        name="emailauth",
        title="SPF / DMARC / DKIM posture",
        capabilities=frozenset({"emailauth"}),
        auth="none",
        cost="free",
        rate=15.0,
        burst=8,
        notes="DNS TXT lookups only; reports policy, not deliverability.",
    )
    cache_ttl = 3600.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "domain":
            from ..errors import ParseChanged

            raise ParseChanged("emailauth expects a domain target")
        domain = target.value
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8
        out: list[Observation] = []
        answered = False
        source = [Source(provider=self.info.name, url=f"dns://TXT/{domain}")]

        spf = [r for r in _txt(resolver, domain) if r.lower().startswith("v=spf1")]
        if spf:
            answered = True
            all_mech = next((part for part in spf[0].split() if part.endswith("all")), "none")
            out.append(
                Observation(
                    type="note",
                    value=f"SPF: {all_mech}",
                    confidence=0.9,
                    sources=source,
                    attrs={"record": "SPF", "all": all_mech, "raw": spf[0][:500], "strict": all_mech == "-all"},
                )
            )
        else:
            out.append(
                Observation(
                    type="note", value="SPF: missing", confidence=0.9, sources=source,
                    attrs={"record": "SPF", "all": "missing", "strict": False},
                )
            )

        dmarc = [r for r in _txt(resolver, f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
        if dmarc:
            answered = True
            policy = "none"
            for part in dmarc[0].split(";"):
                piece = part.strip()
                if piece.lower().startswith("p="):
                    policy = piece[2:].strip().lower()
            out.append(
                Observation(
                    type="note",
                    value=f"DMARC: p={policy}",
                    confidence=0.95,
                    sources=source,
                    attrs={"record": "DMARC", "policy": policy, "raw": dmarc[0][:500], "enforcing": policy in ("quarantine", "reject")},
                )
            )
        else:
            out.append(
                Observation(
                    type="note", value="DMARC: missing", confidence=0.95, sources=source,
                    attrs={"record": "DMARC", "policy": "missing", "enforcing": False},
                )
            )

        found_selectors = []
        for selector in DKIM_SELECTORS:
            records = [r for r in _txt(resolver, f"{selector}._domainkey.{domain}") if "v=dkim1" in r.lower()]
            if records:
                answered = True
                found_selectors.append(selector)
        out.append(
            Observation(
                type="note",
                value=f"DKIM selectors: {', '.join(found_selectors) or 'none'}",
                confidence=0.85,
                sources=source,
                attrs={"record": "DKIM", "selectors": found_selectors},
            )
        )

        try:
            mx = resolver.resolve(domain, "MX", raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            mx = None
        if mx and mx.rrset:
            answered = True
            for record in mx:
                raw = str(record.exchange).rstrip(".").lower()
                if not raw:
                    out.append(
                        Observation(
                            type="note", value="MX: null", confidence=0.9, sources=source,
                            attrs={"record": "MX", "mx": True, "null_mx": True},
                        )
                    )
                    continue
                out.append(
                    Observation(
                        type="hostname",
                        value=raw,
                        confidence=0.85,
                        sources=source,
                        attrs={"mx": True, "preference": record.preference},
                    )
                )
        if not answered:
            raise ProviderDead(f"no DNS answers for {domain}", provider=self.info.name)
        return out

