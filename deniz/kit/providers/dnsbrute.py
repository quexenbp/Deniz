"""Active DNS brute force with the bundled wordlist."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import dns.exception
import dns.resolver

from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo

WORDLIST = Path(__file__).resolve().parents[2] / "data" / "dnsnames.txt"


def words() -> list[str]:
    try:
        return [line.strip() for line in WORDLIST.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    except OSError:
        return []


def resolves(host: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 4
    try:
        answer = resolver.resolve(host, "A", raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    if not answer.rrset:
        return []
    return [str(item) for item in answer]


class DnsBrute(Provider):
    info = ProviderInfo(
        name="dnsbrute",
        title="DNS brute force",
        capabilities=frozenset({"subdomains"}),
        auth="none",
        cost="free",
        rate=20.0,
        burst=10,
        notes="Active: one DNS query per word. Uses the bundled list.",
    )
    cache_ttl = 1800.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "domain":
            from ..errors import ParseChanged

            raise ParseChanged("dnsbrute expects a domain")
        words_list = words()
        if not words_list:
            from ..errors import ProviderDead

            raise ProviderDead("wordlist missing", provider=self.info.name)
        out: list[Observation] = []
        limit = min(len(words_list), max(ctx.max_items * 4, 2000))
        with ThreadPoolExecutor(max_workers=min(ctx.max_workers, 32)) as pool:
            futures = {word: pool.submit(resolves, f"{word}.{target.value}") for word in words_list[:limit]}
            for word, future in futures.items():
                addresses = future.result()
                if not addresses:
                    continue
                host = f"{word}.{target.value}".lower()
                if not ctx.scope.allows(host):
                    continue
                out.append(
                    Observation(
                        type="hostname",
                        value=host,
                        confidence=0.9,
                        sources=[Source(provider=self.info.name, url=f"dns://A/{host}")],
                        attrs={"brute": True, "addresses": addresses},
                    )
                )
                if len(out) >= ctx.max_items:
                    break
        return out
