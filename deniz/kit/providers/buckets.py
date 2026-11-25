# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Cloud storage bucket discovery (S3, GCS, Azure Blob)."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo

SUFFIXES = ("", "-dev", "-staging", "-prod", "-backup", "-assets", "-static", "-data", "-files", "-media", "-logs", "-cdn", "-uploads")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")


def candidates(domain: str) -> list[str]:
    stem = domain.split(".")[0].replace("_", "-")
    out = []
    for suffix in SUFFIXES:
        name = f"{stem}{suffix}"
        if NAME_RE.match(name) and name not in out:
            out.append(name)
    return out


ENDPOINTS = {
    "s3": "https://{name}.s3.amazonaws.com/",
    "gcs": "https://storage.googleapis.com/{name}",
    "azure": "https://{name}.blob.core.windows.net/?comp=list",
}


class Bucket(Provider):
    info = ProviderInfo(
        name="buckets",
        title="Cloud bucket existence check",
        capabilities=frozenset({"storage"}),
        auth="none",
        cost="free",
        rate=10.0,
        burst=6,
        notes="GET/HEAD only. Existence, not full enumeration; public listing is flagged.",
    )
    cache_ttl = 1800.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "domain":
            from ..errors import ParseChanged

            raise ParseChanged("buckets expects a domain target")
        names = candidates(target.value)

        def check(name: str, cloud: str) -> Observation | None:
            url = ENDPOINTS[cloud].format(name=name)
            try:
                resp = self.client.get(url, cache_ttl=self.cache_ttl, rate=self.info.rate, burst=self.info.burst)
            except Exception:
                return None
            if resp.status not in (200, 403):
                return None
            public = resp.status == 200 and any(
                marker in resp.text[:500] for marker in ("<ListBucketResult", "<EnumerationResults")
            )
            return Observation(
                type="bucket",
                value=f"{cloud}://{name}",
                confidence=0.6,
                sources=[Source(provider=self.info.name, url=url)],
                attrs={"cloud": cloud, "name": name, "status": resp.status, "public_listing": public},
            )

        out: list[Observation] = []
        with ThreadPoolExecutor(max_workers=min(ctx.max_workers, 12)) as pool:
            futures = [pool.submit(check, name, cloud) for name in names for cloud in ENDPOINTS]
            for future in futures:
                obs = future.result()
                if obs:
                    out.append(obs)
                if len(out) >= ctx.max_items:
                    break
        return out

