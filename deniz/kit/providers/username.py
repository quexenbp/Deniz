# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Username enumeration across public profile URLs.

Ported from the legacy ``username_search`` module, but with typed output,
bounded concurrency and per-site error fingerprints from the shipped data.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo

DATA = Path(__file__).resolve().parents[2] / "data" / "username_checker.json"


def _load() -> dict[str, dict]:
    try:
        return json.loads(DATA.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


class Username(Provider):
    info = ProviderInfo(
        name="username",
        title="Username profile checker",
        capabilities=frozenset({"identity"}),
        auth="none",
        cost="free",
        rate=8.0,
        burst=8,
        notes="Checks public profile URLs; sites rotate and false positives happen.",
    )
    cache_ttl = 1800.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "username":
            from ..errors import ParseChanged

            raise ParseChanged("username expects a username target")
        sites = _load()
        if not sites:
            from ..errors import ProviderDead

            raise ProviderDead("username_checker.json missing", provider=self.info.name)

        encoded = quote(target.value, safe="").replace(".", "%2E")
        found: dict[str, Observation] = {}

        def check(site: str, meta: dict) -> Observation | None:
            template = meta.get("url")
            if not template:
                return None
            url = template.replace("{}", encoded)
            try:
                resp = self.client.get(
                    url, cache_ttl=0, rate=self.info.rate, burst=self.info.burst, timeout=8, retries=0
                )
            except Exception:
                return None
            body = resp.text.lower()
            if str(resp.status) == str(meta.get("status")) and any(
                err.lower() in body for err in meta.get("error", [])
            ):
                return None
            if str(resp.status)[:1] not in ("2", "3"):
                return None
            return Observation(
                type="url",
                value=url,
                confidence=0.7,
                sources=[Source(provider=self.info.name, url=url)],
                attrs={"site": site, "rank": meta.get("rank")},
            )

        with ThreadPoolExecutor(max_workers=min(ctx.max_workers, 32)) as pool:
            futures = [pool.submit(check, site, meta) for site, meta in sites.items()]
            for future in futures:
                obs = future.result()
                if obs and obs.value not in found:
                    found[obs.value] = obs
                if len(found) >= ctx.max_items:
                    break
        items = sorted(found.values(), key=lambda o: int(o.attrs.get("rank") or 999999))
        for item in items:
            item.attrs["title"] = clip(str(item.attrs.get("site", "")), 80)
        return items

