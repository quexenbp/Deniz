# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Typosquat / lookalike domain discovery.

Generates permutations and keeps the ones that resolve. No external API.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo

TLDS = ("com", "net", "org", "io", "co", "tr", "com.tr", "net.tr", "dev", "app")
KEYBOARD = {
    "q": "wa",
    "w": "qe",
    "e": "wr",
    "r": "et",
    "t": "ry",
    "y": "tu",
    "u": "yi",
    "i": "uo",
    "o": "ip",
    "p": "o",
    "a": "sz",
    "s": "ad",
    "d": "sf",
    "f": "dg",
    "g": "fh",
    "h": "gj",
    "j": "hk",
    "k": "jl",
    "l": "k",
    "z": "xa",
    "x": "zc",
    "c": "xv",
    "v": "cb",
    "b": "vn",
    "n": "bm",
    "m": "n",
}
HOMOGLYPHS = (("o", "0"), ("l", "1"), ("i", "1"), ("rn", "m"), ("m", "rn"), ("vv", "w"), ("w", "vv"), ("s", "5"))


def permutations(domain: str, limit: int = 250) -> list[tuple[str, str]]:
    parts = domain.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"com", "net", "org", "gov", "edu", "co"}:
        stem, tld = ".".join(parts[:-2]), ".".join(parts[-2:])
    else:
        stem, _, tld = domain.rpartition(".")
    if not stem or not tld:
        return []
    base = stem.rsplit(".", 1)[-1]
    out: dict[str, str] = {}

    def add(value: str, kind: str) -> None:
        value = value.lower().strip(".")
        if value and value != domain and "." in value and value not in out:
            out[value] = kind

    for i in range(len(base)):
        add(stem[: stem.rfind(base)] + base[:i] + base[i + 1 :] + "." + tld, "omission")
        add(stem[: stem.rfind(base)] + base[:i] + base[i] * 2 + base[i + 1 :] + "." + tld, "repetition")
        if base[i] in KEYBOARD:
            for char in KEYBOARD[base[i]]:
                add(stem[: stem.rfind(base)] + base[:i] + char + base[i + 1 :] + "." + tld, "keyboard")
    for i in range(len(base) - 1):
        add(stem[: stem.rfind(base)] + base[:i] + base[i + 1] + base[i] + base[i + 2 :] + "." + tld, "transposition")
    for old, new in HOMOGLYPHS:
        if old in base:
            add(stem[: stem.rfind(base)] + base.replace(old, new, 1) + "." + tld, "homoglyph")
    if "." not in stem:
        add(stem + "-" + tld + "." + tld, "hyphenation")
    add(stem.replace("-", "") + "." + tld, "hyphenation")
    for prefix in ("www", "mail", "login", "secure"):
        add(f"{prefix}-{stem}.{tld}", "prefix")
    for other in TLDS:
        add(f"{base}.{other}", "tld")
    return list(out.items())[:limit]


def resolves(host: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 4
    addresses: list[str] = []
    for record in ("A", "AAAA"):
        try:
            answer = resolver.resolve(host, record, raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        if answer.rrset:
            addresses.extend(str(item).rstrip(".") for item in answer)
    return addresses


class Typosquat(Provider):
    info = ProviderInfo(
        name="typosquat",
        title="Typosquat / lookalike resolver",
        capabilities=frozenset({"typosquat"}),
        auth="none",
        cost="free",
        rate=15.0,
        burst=10,
        notes="Permutation generation + DNS; only registered lookalikes are returned.",
    )
    cache_ttl = 1800.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        candidates = permutations(target.value)
        found: dict[str, list[Observation]] = {}
        count = 0
        with ThreadPoolExecutor(max_workers=min(ctx.max_workers, 24)) as pool:
            futures = {pool.submit(resolves, host): (host, kind) for host, kind in candidates}
            for future in futures:
                host, kind = futures[future]
                try:
                    addresses = future.result()
                except Exception:
                    continue
                if not addresses:
                    continue
                source = [Source(provider=self.info.name, url=f"dns://A/{host}")]
                group = [
                    Observation(
                        type="hostname",
                        value=host,
                        confidence=0.5,
                        sources=source,
                        attrs={"typosquat": kind, "addresses": addresses, "relation": "typosquat"},
                    )
                ]
                for address in addresses:
                    group.append(
                        Observation(
                            type="ip",
                            value=address,
                            confidence=0.6,
                            sources=source,
                            attrs={"host": host, "typosquat": kind},
                        )
                    )
                found[host] = group
                count += 1
                if count >= ctx.max_items:
                    break
        return [item for group in found.values() for item in group]

