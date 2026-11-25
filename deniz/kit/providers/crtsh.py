# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Certificate Transparency subdomain discovery via crt.sh.

Passive: queries the public CT log search. Emits hostnames only; DNS and
HTTP probing are separate providers so a crt.sh failure never hides a live
host that another source already found.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from urllib.parse import quote

from ..errors import Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import normalize_hostname
from .base import Context, Provider, ProviderInfo

HOST_IN_TEXT = re.compile(r"(?<![\w.-])(?:\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)", re.I)


def _parse_when(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class Crtsh(Provider):
    info = ProviderInfo(
        name="crtsh",
        title="crt.sh certificate transparency",
        capabilities=frozenset({"subdomains", "passive"}),
        auth="none",
        cost="free",
        rate=0.5,
        burst=1,
        tos_url="https://crt.sh/",
        homepage="https://crt.sh/",
        notes="Public CT log search. Can return 502/HTML challenge under load.",
    )
    cache_ttl = 3600.0
    URL = "https://crt.sh/"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "domain":
            raise ParseChanged("crtsh expects a domain target")
        query = f"%.{target.value}"
        resp = self.client.get(
            self.URL,
            params={"q": query, "output": "json", "exclude": "expired"},
            headers={"accept": "application/json"},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("crt.sh rate limit", provider=self.info.name)
        if resp.status in (401, 403):
            raise Blocked(f"crt.sh returned {resp.status}", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"crt.sh returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"crt.sh returned {resp.status}", provider=self.info.name)

        entries = self._entries(resp.text, resp.headers.get("content-type", ""))
        if entries is None:
            raise ParseChanged("crt.sh response is neither JSON nor a recognizable result page", provider=self.info.name)

        source_url = f"{self.URL}?q={quote(query)}&output=json"
        found: dict[str, Observation] = {}
        for entry in entries:
            names: list[str] = []
            for field in ("name_value", "common_name"):
                raw = entry.get(field) or ""
                names.extend(str(raw).splitlines())
            for raw in names:
                host = normalize_hostname(raw)
                if not host:
                    continue
                if not (host == target.value or host.endswith("." + target.value)):
                    continue
                if not ctx.scope.allows(host):
                    continue
                if host in found:
                    continue
                ib = _parse_when(entry.get("not_before"))
                ia = _parse_when(entry.get("not_after"))
                found[host] = Observation(
                    type="hostname",
                    value=host,
                    confidence=0.75,
                    sources=[
                        Source(
                            provider=self.info.name,
                            url=source_url,
                            sha256=(entry.get("id") and str(entry["id"])) or None,
                        )
                    ],
                    first_seen=ib,
                    last_seen=ia,
                    attrs={
                        "issuer": str(entry.get("issuer_name") or "")[:200],
                        "certificate_id": entry.get("id"),
                        "not_before": entry.get("not_before"),
                        "not_after": entry.get("not_after"),
                    },
                )
                if len(found) >= ctx.max_items:
                    return list(found.values())
        return list(found.values())

    @staticmethod
    def _entries(text: str, content_type: str) -> list[dict] | None:
        stripped = text.lstrip()
        if "json" in content_type or stripped.startswith("["):
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError:
                return None
            return data if isinstance(data, list) else None
        if "<" in stripped[:200].lower() or "<html" in text[:500].lower():
            hosts = HOST_IN_TEXT.findall(text)
            if not hosts:
                return None
            return [{"name_value": "\n".join(hosts)}]
        return None

