"""Shodan InternetDB for an IP: ports, hostnames, CPEs, tags, vulns."""

from __future__ import annotations

import socket

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import normalize_hostname
from .base import Context, Provider, ProviderInfo


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    return sorted({str(info[4][0]) for info in infos})


class InternetDb(Provider):
    info = ProviderInfo(
        name="internetdb",
        title="Shodan InternetDB",
        capabilities=frozenset({"ipintel"}),
        auth="none",
        cost="free",
        rate=1.0,
        burst=1,
        tos_url="https://internetdb.shodan.io/",
        homepage="https://www.shodan.io/",
        notes="Free IP summary: open ports, hostnames, CPEs, tags, known vulns.",
    )
    cache_ttl = 3600.0
    API = "https://internetdb.shodan.io/"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type == "ip":
            addresses = [target.value]
        elif target.type in ("domain", "hostname"):
            addresses = _resolve(target.value)
        else:
            raise ParseChanged("internetdb expects an ip or hostname")
        if not addresses:
            raise ProviderDead(f"{target.value} does not resolve", provider=self.info.name)

        out: list[Observation] = []
        for address in addresses[:3]:
            resp = self.client.get(self.API + address, rate=self.info.rate, burst=self.info.burst)
            if resp.status == 404:
                continue
            if resp.status == 429:
                raise RateLimited("internetdb rate limit", provider=self.info.name)
            if resp.status != 200:
                raise ProviderDead(f"internetdb returned {resp.status}", provider=self.info.name)
            try:
                data = resp.json()
            except ValueError as exc:
                raise ParseChanged("internetdb returned invalid JSON", provider=self.info.name) from exc
            source = [Source(provider=self.info.name, url=f"{self.API}{address}")]
            for port in data.get("ports", []):
                out.append(
                    Observation(
                        type="service",
                        value=f"{target.value}:{port}",
                        confidence=0.6,
                        sources=source,
                        attrs={"port": int(port), "address": address, "source": "internetdb"},
                    )
                )
            for host in data.get("hostnames", []):
                name = normalize_hostname(str(host))
                if name:
                    out.append(Observation(type="hostname", value=name, confidence=0.5, sources=source,
                                           attrs={"address": address, "source": "internetdb"}))
            for cpe in data.get("cpes", []):
                out.append(Observation(type="technology", value=str(cpe), confidence=0.5, sources=source,
                                       attrs={"address": address, "source": "internetdb"}))
            tags = data.get("tags", [])
            vulns = data.get("vulns", [])
            if tags or vulns:
                out.append(
                    Observation(
                        type="note",
                        value=f"InternetDB {address}: {len(vulns)} vulns, tags {', '.join(tags) or '-'}",
                        confidence=0.7,
                        sources=source,
                        attrs={"record": "INTERNETDB", "address": address, "vulns": vulns[:50], "tags": tags[:20]},
                    )
                )
        return out
