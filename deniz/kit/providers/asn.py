"""ASN and prefix attribution through Team Cymru's DNS service."""

from __future__ import annotations

import ipaddress
import socket

import dns.exception
import dns.resolver

from ..errors import ProviderDead
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    return sorted({str(info[4][0]) for info in infos})


def _query_name(address: str) -> str:
    parsed = ipaddress.ip_address(address)
    if isinstance(parsed, ipaddress.IPv4Address):
        return ".".join(reversed(str(parsed).split("."))) + ".origin.asn.cymru.com"
    nibbles = parsed.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def _txt(resolver: dns.resolver.Resolver, name: str) -> list[str]:
    try:
        answer = resolver.resolve(name, "TXT", raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    if answer.rrset is None:
        return []
    return [b"".join(record.strings).decode("utf-8", "replace") for record in answer]


class Asn(Provider):
    info = ProviderInfo(
        name="asn",
        title="ASN attribution (Team Cymru DNS)",
        capabilities=frozenset({"asn"}),
        auth="none",
        cost="free",
        rate=10.0,
        burst=5,
        tos_url="https://team-cymru.com/community-services/ip-asn-mapping/",
        notes="DNS TXT only. No HTTP.",
    )
    cache_ttl = 3600.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type == "ip":
            addresses = [target.value]
        elif target.type in ("domain", "hostname"):
            addresses = _resolve(target.value)
        else:
            from ..errors import ParseChanged

            raise ParseChanged("asn expects an ip or hostname")
        if not addresses:
            raise ProviderDead(f"{target.value} does not resolve", provider=self.info.name)

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8
        out: list[Observation] = []
        for address in addresses[:5]:
            records = _txt(resolver, _query_name(address))
            if not records:
                continue
            parts = [p.strip() for p in records[0].split("|")]
            asn = parts[0] if parts else ""
            prefix = parts[1] if len(parts) > 1 else None
            country = parts[2] if len(parts) > 2 else None
            registry = parts[3] if len(parts) > 3 else None
            name = None
            for suffix in ("AS" + asn, asn):
                names = _txt(resolver, f"{suffix}.asn.cymru.com")
                if names:
                    segments = [p.strip() for p in names[0].split("|")]
                    if len(segments) > 4:
                        name = segments[4]
                    break
            source = [Source(provider=self.info.name, url=f"dns://TXT/{_query_name(address)}")]
            out.append(
                Observation(
                    type="asn",
                    value=f"AS{asn}",
                    confidence=0.9,
                    sources=source,
                    attrs={
                        "address": address,
                        "prefix": prefix,
                        "country": country,
                        "registry": registry,
                        "as_name": name,
                        "host": target.value,
                    },
                )
            )
            if prefix:
                out.append(
                    Observation(
                        type="note",
                        value=f"{address} in {prefix}",
                        confidence=0.9,
                        sources=source,
                        attrs={"record": "ASN", "address": address, "prefix": prefix, "host": target.value},
                    )
                )
        return out
