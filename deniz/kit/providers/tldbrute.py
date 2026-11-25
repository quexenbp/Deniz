"""TLD variation discovery for a domain stem."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo

TLDS = (
    "com", "net", "org", "io", "co", "dev", "app", "ai", "me", "info", "biz", "xyz",
    "online", "site", "store", "tech", "cloud", "pro", "tr", "com.tr", "net.tr",
    "org.tr", "de", "uk", "fr", "nl", "es", "it", "ru", "cn", "jp", "in", "br",
    "au", "ca", "us", "eu", "tv", "cc", "shop",
)


def candidates(domain: str) -> list[str]:
    stem = domain.rsplit(".", 1)[0]
    out = []
    for tld in TLDS:
        value = f"{stem}.{tld}"
        if value != domain and value not in out:
            out.append(value)
    return out


def resolves(host: str) -> bool:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 4
    try:
        answer = resolver.resolve(host, "A", raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return False
    return bool(answer.rrset)


class TldBrute(Provider):
    info = ProviderInfo(
        name="tldbrute",
        title="TLD variation resolver",
        capabilities=frozenset({"domains"}),
        auth="none",
        cost="free",
        rate=20.0,
        burst=10,
        notes="Resolves the same stem across popular TLDs; only registered domains are returned.",
    )
    cache_ttl = 3600.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "domain":
            from ..errors import ParseChanged

            raise ParseChanged("tldbrute expects a domain")
        hosts = candidates(target.value)
        out = []
        with ThreadPoolExecutor(max_workers=min(ctx.max_workers, 24)) as pool:
            futures = {host: pool.submit(resolves, host) for host in hosts}
            for host, future in futures.items():
                if not future.result():
                    continue
                out.append(
                    Observation(
                        type="hostname",
                        value=host,
                        confidence=0.6,
                        sources=[Source(provider=self.info.name, url=f"dns://A/{host}")],
                        attrs={"tld_variant": True, "relation": "tld"},
                    )
                )
                if len(out) >= ctx.max_items:
                    break
        return out
