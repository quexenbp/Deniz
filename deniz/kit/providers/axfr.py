"""DNS zone transfer attempt against authoritative nameservers."""

from __future__ import annotations

import socket

import dns.exception
import dns.query
import dns.resolver
import dns.zone

from ..errors import ProviderDead
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo


class Axfr(Provider):
    info = ProviderInfo(
        name="axfr",
        title="DNS zone transfer",
        capabilities=frozenset({"dns"}),
        auth="none",
        cost="free",
        rate=1.0,
        burst=1,
        notes="TCP AXFR; succeeds only when the zone is open.",
    )
    cache_ttl = 3600.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "domain":
            from ..errors import ParseChanged

            raise ParseChanged("axfr expects a domain target")
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8
        try:
            answer = resolver.resolve(target.value, "NS", raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            raise ProviderDead(f"no NS records for {target.value}", provider=self.info.name) from exc
        if not answer.rrset:
            raise ProviderDead(f"no NS records for {target.value}", provider=self.info.name)

        nameservers = [str(r.target).rstrip(".") for r in answer]
        out: list[Observation] = []
        transferred = False
        for server in nameservers[:5]:
            try:
                addresses = sorted({str(i[4][0]) for i in socket.getaddrinfo(server, 53, proto=socket.IPPROTO_TCP)})
            except OSError:
                continue
            for address in addresses[:2]:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(address, target.value, timeout=8))
                except Exception:
                    continue
                transferred = True
                break
            if not transferred:
                continue
            source = [Source(provider=self.info.name, url=f"axfr://{server}/{target.value}")]
            for name in zone.nodes:
                hostname = name.to_text().rstrip(".")
                if hostname == "@":
                    hostname = target.value
                elif not hostname.endswith(target.value):
                    hostname = f"{hostname}.{target.value}"
                if hostname == target.value or not ctx.scope.allows(hostname):
                    continue
                out.append(
                    Observation(
                        type="hostname",
                        value=hostname.lower(),
                        confidence=0.95,
                        sources=source,
                        attrs={"axfr": True, "nameserver": server},
                    )
                )
        if not transferred:
            raise ProviderDead("all nameservers refused AXFR", provider=self.info.name)
        return out
