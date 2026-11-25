# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""TCP connect check for common service ports."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from ..errors import ProviderDead
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo

PORTS = (21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200)
BANNER_PORTS = {21, 22, 25, 3306, 6379}
TLS_PORTS = {443, 8443}


def _addresses(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    addresses: set[str] = set()
    for info in infos:
        addresses.add(str(info[4][0]))
    return sorted(addresses)


def _check(address: str, port: int) -> tuple[int, str | None] | None:
    try:
        with socket.create_connection((address, port), timeout=1.5) as sock:
            banner = None
            if port in BANNER_PORTS:
                sock.settimeout(1.0)
                try:
                    banner = sock.recv(80).decode("utf-8", "replace").strip() or None
                except OSError:
                    banner = None
            return port, banner
    except OSError:
        return None


class Ports(Provider):
    info = ProviderInfo(
        name="ports",
        title="TCP common-port check",
        capabilities=frozenset({"ports"}),
        auth="none",
        cost="free",
        rate=10.0,
        burst=10,
        notes="Connect-only, no payloads. Common ports only.",
    )
    cache_ttl = 900.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type not in ("domain", "hostname"):
            from ..errors import ParseChanged

            raise ParseChanged("ports expects a hostname")
        addresses = _addresses(target.value)
        if not addresses:
            raise ProviderDead(f"{target.value} does not resolve", provider=self.info.name)
        out: list[Observation] = []
        seen: set[int] = set()
        with ThreadPoolExecutor(max_workers=min(ctx.max_workers, 20)) as pool:
            futures = {(address, port): pool.submit(_check, address, port) for address in addresses for port in PORTS}
            for (_address, port), future in futures.items():
                result = future.result()
                if not result:
                    continue
                port, banner = result
                if port in seen:
                    continue
                seen.add(port)
                attrs = {"port": port, "tls": port in TLS_PORTS, "addresses": addresses}
                if banner:
                    attrs["banner"] = banner[:120]
                out.append(
                    Observation(
                        type="service",
                        value=f"{target.value}:{port}",
                        confidence=0.9,
                        sources=[Source(provider=self.info.name, url=f"tcp://{target.value}:{port}")],
                        attrs=attrs,
                    )
                )
        return out

