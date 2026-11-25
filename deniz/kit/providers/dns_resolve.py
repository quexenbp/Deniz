# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""DNS resolution of a hostname (A, AAAA, CNAME)."""

from __future__ import annotations

import dns.exception
import dns.resolver

from ..errors import TimeoutError_
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo


class DnsResolve(Provider):
    info = ProviderInfo(
        name="dns",
        title="System DNS resolver",
        capabilities=frozenset({"dns"}),
        auth="none",
        cost="free",
        rate=20.0,
        burst=10,
        notes="A/AAAA/CNAME lookups through the OS resolver.",
    )
    cache_ttl = 300.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        host = target.value
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8
        out: list[Observation] = []
        saw_response = False

        cnames = self._query(resolver, host, "CNAME")
        if cnames:
            saw_response = True
            for cname in cnames:
                out.append(self._obs("note", cname, host, 0.9, {"record": "CNAME"}))

        for record in ("A", "AAAA"):
            answers = self._query(resolver, host, record)
            if answers:
                saw_response = True
            for answer in answers:
                out.append(self._obs("ip", answer, host, 0.95, {"record": record}))

        if not saw_response and target.type == "hostname":
            raise TimeoutError_(f"no DNS answer for {host}", provider=self.info.name)
        return out

    @staticmethod
    def _query(resolver: dns.resolver.Resolver, host: str, record: str) -> list[str]:
        try:
            answer = resolver.resolve(host, record, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return []
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
        if answer.rrset is None:
            return []
        values = []
        for item in answer:
            value = str(item.target) if record == "CNAME" else str(item)
            values.append(value.rstrip("."))
        return values

    def _obs(self, kind: str, value: str, host: str, confidence: float, attrs: dict) -> Observation:
        return Observation(
            type=kind,  # type: ignore[arg-type]
            value=value,
            confidence=confidence,
            sources=[Source(provider=self.info.name, url=f"dns://{attrs['record']}/{host}")],
            attrs={"host": host, **attrs},
        )

