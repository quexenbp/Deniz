"""DNS blocklist (DNSBL) checks for resolved IPv4 addresses."""

from __future__ import annotations

import ipaddress
import socket

import dns.exception
import dns.resolver

from ..errors import ProviderDead
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo

ZONES = (
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "bl.spamcop.net",
    "psbl.surriel.com",
)


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    return sorted({str(info[4][0]) for info in infos})


def _reversed_ipv4(address: str) -> str | None:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if not isinstance(parsed, ipaddress.IPv4Address):
        return None
    return ".".join(reversed(str(parsed).split(".")))


class Dnsbl(Provider):
    info = ProviderInfo(
        name="dnsbl",
        title="DNS blocklists",
        capabilities=frozenset({"reputation"}),
        auth="none",
        cost="free",
        rate=10.0,
        burst=5,
        tos_url="https://www.spamhaus.org/",
        notes="DNS queries only; free DNSBL usage has limits.",
    )
    cache_ttl = 1800.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type == "ip":
            addresses = [target.value]
        elif target.type in ("domain", "hostname"):
            addresses = _resolve(target.value)
        else:
            from ..errors import ParseChanged

            raise ParseChanged("dnsbl expects a domain or IP")
        if not addresses:
            raise ProviderDead(f"{target.value} does not resolve", provider=self.info.name)

        resolver = dns.resolver.Resolver()
        resolver.timeout = 4
        resolver.lifetime = 6
        out: list[Observation] = []
        for address in addresses[:5]:
            reversed_ip = _reversed_ipv4(address)
            if not reversed_ip:
                continue
            listed = []
            for zone in ZONES:
                query = f"{reversed_ip}.{zone}"
                try:
                    answer = resolver.resolve(query, "A", raise_on_no_answer=False)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                    continue
                if answer.rrset:
                    codes = [str(item) for item in answer if not str(item).startswith("127.255.255.")]
                    if codes:
                        listed.append({"zone": zone, "codes": codes})
            source = [Source(provider=self.info.name, url=f"dnsbl://{address}")]
            if listed:
                out.append(
                    Observation(
                        type="note",
                        value=f"{address} listed on {len(listed)} DNSBL(s)",
                        confidence=0.9,
                        sources=source,
                        attrs={"record": "DNSBL", "address": address, "listed": listed, "clean": False},
                    )
                )
            else:
                out.append(
                    Observation(
                        type="note",
                        value=f"{address} not listed",
                        confidence=0.7,
                        sources=source,
                        attrs={"record": "DNSBL", "address": address, "listed": [], "clean": True},
                    )
                )
        return out
