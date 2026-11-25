# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Subdomain takeover candidates.

Two signals: a CNAME into a takeover-prone service, and the service's
"unclaimed" page marker. A CNAME alone is a candidate, a marker match is a
finding.
"""

from __future__ import annotations

import dns.exception
import dns.resolver

from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo

SERVICES = (
    ("s3.amazonaws.com", "NoSuchBucket"),
    ("github.io", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "No such app"),
    ("azurewebsites.net", "404 Web Site not found"),
    ("cloudapp.azure.com", "404 Web Site not found"),
    ("trafficmanager.net", "404 Web Site not found"),
    ("shopify.com", "Sorry, this shop is currently unavailable"),
    ("fastly.net", "Fastly error: unknown domain"),
    ("unbouncepages.com", "The page you're looking for doesn't exist"),
    ("pantheonsite.io", "The gods are wise"),
    ("surge.sh", "project not found"),
    ("bitbucket.io", "Repository not found"),
    ("ghost.io", "Domain error"),
    ("netlify.app", "Not Found - Request ID"),
    ("vercel.app", "The deployment could not be found"),
    ("webflow.io", "This site is not published"),
    ("readthedocs.io", "Unknown"),
    ("cargo.site", "404"),
)


class Takeover(Provider):
    info = ProviderInfo(
        name="takeover",
        title="Subdomain takeover candidates",
        capabilities=frozenset({"takeover"}),
        auth="none",
        cost="free",
        rate=8.0,
        burst=4,
        notes="CNAME fingerprint plus unclaimed-page marker; verify before claiming.",
    )
    cache_ttl = 1800.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        host = target.value
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8
        try:
            answer = resolver.resolve(host, "CNAME", raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
        if not answer.rrset:
            return []

        cnames = [str(r.target).rstrip(".").lower() for r in answer]
        if not cnames:
            return []
        full = " -> ".join([host, *cnames])
        service, marker = next(
            ((svc, mark) for cname in cnames for svc, mark in SERVICES if cname.endswith(svc)), (None, None)
        )
        dangling = self._dangling(resolver, cnames[-1])

        if not service and not dangling:
            return []

        body = ""
        status = None
        try:
            resp = self.client.get(f"https://{host}/", cache_ttl=self.cache_ttl, rate=self.info.rate, burst=self.info.burst)
            status, body = resp.status, resp.text.lower()
        except Exception:
            pass
        hit = marker is not None and marker.lower() in body
        confidence = 0.9 if hit else (0.7 if dangling else 0.5)
        attrs = {
            "host": host,
            "cname": full,
            "service": service or "unknown",
            "dangling": dangling,
            "marker_match": hit,
            "http_status": status,
            "evidence": clip(body[:400], 200) if hit else None,
        }
        if hit:
            value = f"{host} -> {service} (unclaimed page)"
        elif dangling:
            value = f"{host} -> {cnames[-1]} (dangling CNAME)"
        else:
            value = f"{host} -> {service} (CNAME only)"
        return [
            Observation(
                type="takeover",
                value=value,
                confidence=confidence,
                sources=[Source(provider=self.info.name, url=f"dns://CNAME/{host}")],
                attrs=attrs,
            )
        ]

    @staticmethod
    def _dangling(resolver: dns.resolver.Resolver, name: str) -> bool:
        try:
            resolver.resolve(name, "A", raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return True
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            return False
        return False

