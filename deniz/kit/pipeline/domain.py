# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Domain / attack-surface profile: CT -> DNS -> HTTP."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..auth import AuthStore
from ..cache import Cache
from ..config import Config
from ..errors import DenizError, ErrorKind, OutOfScope
from ..http import HttpClient
from ..models import Observation, Result, Source, Target
from ..providers.base import Context
from ..providers.health import BLOCKED, FAIL, OK, PARSE, RATE, HealthStore
from ..providers.registry import Registry
from ..scope import Scope
from ..util import is_valid_hostname, normalize_domain

SEED_PROVIDER = "input"


def _scope_for(config: Config, domain: str) -> Scope:
    path = config.scope_file
    if path:
        return Scope.from_file(path)
    return Scope(allow=[domain], include_apex=True)


def _record(health: HealthStore, provider: str, exc: DenizError | None) -> None:
    if exc is None:
        health.record(provider, OK)
        return
    mapping = {
        ErrorKind.BLOCKED: BLOCKED,
        ErrorKind.PARSE_CHANGED: PARSE,
        ErrorKind.RATE_LIMITED: RATE,
        ErrorKind.AUTH_REQUIRED: FAIL,
    }
    health.record(provider, mapping.get(exc.kind, FAIL))


def order_chain(chain: list[str], health: HealthStore) -> list[str]:
    """Put healthy providers first; unknown sits mid, 0% goes last."""

    def key(name: str) -> float:
        score = health.score(name)
        return 0.5 if score is None else score

    return sorted(chain, key=key, reverse=True)


def _call(provider, target, ctx: Context, result: Result, health: HealthStore):
    try:
        observations = provider.run(target, ctx)
    except DenizError as exc:
        _record(health, provider.info.name, exc)
        result.error(exc.kind.value, str(exc), provider=provider.info.name, retryable=exc.retryable)
        return []
    _record(health, provider.info.name, None)
    if provider.info.name not in result.stats.providers_used:
        result.stats.providers_used.append(provider.info.name)
    return observations


def run_domain(
    domain: str,
    *,
    config: Config,
    http: HttpClient,
    cache: Cache,
    health: HealthStore,
    registry: Registry,
    auth: AuthStore,
    scope: Scope | None = None,
    max_hosts: int = 200,
    probe: bool = True,
    resolve: bool = True,
    typosquat: bool = True,
    emailauth: bool = True,
    rdap: bool = True,
    asn: bool = True,
    discovery: bool = True,
    urlscan: bool = True,
    internetdb: bool = True,
    wayback: bool = True,
    axfr: bool = False,
    dnsbl: bool = True,
    tlds: bool = False,
    entrypoints: bool = True,
    crawl: bool = False,
    crawl_regex: str | None = None,
    files: bool = False,
    dnsbrute: bool = False,
    ports: bool = False,
    takeover: bool = True,
    fingerprint: bool = True,
    max_workers: int = 16,
) -> Result:
    domain = normalize_domain(domain)
    target = Target(type="domain", value=domain)
    result = Result(schema="deniz.result/1", module="domain.quick", provider="crtsh", target=target)
    ctx = Context(http=http, scope=scope or _scope_for(config, domain), auth=auth, max_workers=max_workers)
    if crawl_regex:
        ctx.options["crawl_regex"] = crawl_regex
    started = time.perf_counter()

    result.add(
        Observation(
            type="hostname",
            value=domain,
            confidence=1.0,
            sources=[Source(provider=SEED_PROVIDER, url="cli://target")],
        )
    )

    hosts: list[str] = [domain]
    if not ctx.scope.allows(domain):
        raise OutOfScope(f"{domain} is outside scope")

    chain = ["crtsh", "certspotter", "hackertarget", "rapiddns", "anubis"]
    if ctx.auth.get("searxng", "url"):
        chain.append("searxng")
    collected = []
    for name in order_chain(chain, health):
        provider = registry.get(name)(http)
        collected = _call(provider, target, ctx, result, health)
        if collected:
            break
    seed_addresses: dict[str, list[str]] = {}
    for obs in collected:
        if obs.type == "hostname":
            if not (obs.value == domain or obs.value.endswith("." + domain)):
                continue
            if not ctx.scope.allows(obs.value):
                continue
            if obs.value not in hosts:
                hosts.append(obs.value)
            if obs.attrs.get("ip"):
                seed_addresses.setdefault(obs.value, []).append(str(obs.attrs["ip"]))
        result.add(obs)

    if typosquat:
        typo = registry.get("typosquat")(http)
        budget = max(0, max_hosts - len(hosts))
        added = 0
        for obs in _call(typo, target, ctx, result, health):
            keep = obs.attrs.get("host") in hosts if obs.type == "ip" else obs.value in hosts
            if obs.type == "hostname" and obs.value not in hosts and added < budget:
                hosts.append(obs.value)
                seed_addresses[obs.value] = [str(a) for a in obs.attrs.get("addresses", [])]
                keep = True
                added += 1
            if keep:
                result.add(obs)
    if emailauth:
        for obs in _call(registry.get("emailauth")(http), target, ctx, result, health):
            result.add(obs)
    if rdap:
        for obs in _call(registry.get("rdap")(http), target, ctx, result, health):
            if obs.type == "hostname" and obs.value in hosts:
                continue
            result.add(obs)
    if urlscan:
        for obs in _call(registry.get("urlscan")(http), target, ctx, result, health):
            result.add(obs)
    if internetdb:
        for obs in _call(registry.get("internetdb")(http), target, ctx, result, health):
            result.add(obs)
    if wayback:
        for obs in _call(registry.get("wayback")(http), target, ctx, result, health):
            result.add(obs)
    if axfr:
        for obs in _call(registry.get("axfr")(http), target, ctx, result, health):
            result.add(obs)

    hosts = hosts[:max_hosts]

    by_host: dict[str, list[str]] = {h: seed_addresses.get(h, []) for h in hosts}
    cname_hosts: set[str] = set()
    if resolve:
        dns_cls = registry.get("dns")
        dns = dns_cls(http)
        to_resolve = [h for h in hosts if not by_host[h]]
        with ThreadPoolExecutor(max_workers=min(max_workers, 32)) as pool:
            futures = {pool.submit(_call, dns, Target(type="hostname", value=h), ctx, result, health): h for h in to_resolve}
            for future in as_completed(futures):
                host = futures[future]
                try:
                    obs_list = future.result()
                except Exception as exc:  # defensive: one host must not kill the run
                    result.error(ErrorKind.INTERNAL.value, f"{host}: {exc}", provider="dns")
                    continue
                for obs in obs_list:
                    if obs.type == "ip":
                        by_host[host].append(obs.value)
                    if obs.type == "note" and obs.attrs.get("record") == "CNAME":
                        cname_hosts.add(host)
                    result.add(obs)

    alive = [h for h in hosts if by_host.get(h)] if resolve else hosts
    ctx.allow_out_of_scope = True
    if asn:
        for obs in _call(registry.get("asn")(http), target, ctx, result, health):
            result.add(obs)
    if dnsbl:
        for obs in _call(registry.get("dnsbl")(http), target, ctx, result, health):
            result.add(obs)
    if tlds:
        for obs in _call(registry.get("tldbrute")(http), target, ctx, result, health):
            result.add(obs)
    if takeover:
        takeover_targets = list(dict.fromkeys([*alive, *sorted(cname_hosts)]))[:50]
        takeover_provider = registry.get("takeover")(http)
        for host in takeover_targets:
            for obs in _call(takeover_provider, Target(type="hostname", value=host), ctx, result, health):
                result.add(obs)
    if ports:
        port_provider = registry.get("ports")(http)
        for host in [domain, *alive[:9]]:
            for obs in _call(port_provider, Target(type="hostname", value=host), ctx, result, health):
                result.add(obs)
    if probe:
        http_cls = registry.get("http")
        probe_obj = http_cls(http)
        with ThreadPoolExecutor(max_workers=min(max_workers, 16)) as pool:
            futures = {pool.submit(_call, probe_obj, Target(type="hostname", value=h), ctx, result, health): h for h in alive}
            for future in as_completed(futures):
                try:
                    for obs in future.result():
                        result.add(obs)
                except Exception as exc:
                    result.error(ErrorKind.INTERNAL.value, str(exc), provider="http")
    if fingerprint:
        fp = registry.get("fingerprint")(http)
        for host in alive[:20]:
            for obs in _call(fp, Target(type="hostname", value=host), ctx, result, health):
                result.add(obs)
    if discovery:
        disc = registry.get("discovery")(http)
        for host in alive[:10]:
            for obs in _call(disc, Target(type="hostname", value=host), ctx, result, health):
                result.add(obs)
    if entrypoints:
        ep = registry.get("entrypoints")(http)
        for host in alive[:10]:
            for obs in _call(ep, Target(type="hostname", value=host), ctx, result, health):
                result.add(obs)
    if crawl or crawl_regex:
        crawler = registry.get("crawl")(http)
        for host in alive[:5]:
            for obs in _call(crawler, Target(type="hostname", value=host), ctx, result, health):
                result.add(obs)
    if files:
        files_provider = registry.get("files")(http)
        for host in alive[:10]:
            for obs in _call(files_provider, Target(type="hostname", value=host), ctx, result, health):
                result.add(obs)
    if dnsbrute:
        for obs in _call(registry.get("dnsbrute")(http), target, ctx, result, health):
            result.add(obs)

    result.dedupe()
    result.stats.duration_ms = int((time.perf_counter() - started) * 1000)
    result.stats.requests = http.stats.requests
    result.stats.cache_hits = http.stats.cache_hits
    return result


def validate_domain(domain: str) -> str:
    value = normalize_domain(domain)
    if not is_valid_hostname(value):
        raise ValueError(f"invalid domain: {domain}")
    return value

