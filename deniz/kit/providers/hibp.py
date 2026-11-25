# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Have I Been Pwned breach lookup."""

from __future__ import annotations

import re

from ..errors import AuthRequired, Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo

TAG = re.compile(r"<[^>]+>")


class Hibp(Provider):
    info = ProviderInfo(
        name="hibp",
        title="Have I Been Pwned",
        capabilities=frozenset({"breach"}),
        auth="key",
        cost="paid",
        rate=0.5,
        burst=1,
        tos_url="https://haveibeenpwned.com/API/v3",
        homepage="https://haveibeenpwned.com/",
        notes="Requires a paid API key: DENIZ_HIBP_TOKEN.",
    )
    cache_ttl = 3600.0
    URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "email":
            raise ParseChanged("hibp expects an email target")
        token = ctx.auth.get("hibp")
        if not token:
            raise AuthRequired("DENIZ_HIBP_TOKEN is not set", provider=self.info.name)
        resp = self.client.get(
            self.URL + target.value,
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": token, "user-agent": "Deniz/0.1"},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 404:
            return []
        if resp.status == 429:
            raise RateLimited("hibp rate limit", provider=self.info.name)
        if resp.status in (401, 403):
            raise Blocked(f"hibp returned {resp.status}", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"hibp returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"hibp returned {resp.status}", provider=self.info.name)
        try:
            breaches = resp.json()
        except ValueError as exc:
            raise ParseChanged("hibp returned invalid JSON", provider=self.info.name) from exc

        out = []
        for breach in breaches if isinstance(breaches, list) else []:
            name = breach.get("Name")
            if not name:
                continue
            out.append(
                Observation(
                    type="breach",
                    value=str(name),
                    confidence=0.95,
                    sources=[Source(provider=self.info.name, url=f"https://haveibeenpwned.com/PwnedWebsites#{name}")],
                    attrs={
                        "title": breach.get("Title"),
                        "domain": breach.get("Domain"),
                        "breach_date": breach.get("BreachDate"),
                        "added_date": breach.get("AddedDate"),
                        "pwn_count": breach.get("PwnCount"),
                        "data_classes": breach.get("DataClasses", [])[:10],
                        "verified": breach.get("IsVerified"),
                        "description": TAG.sub("", str(breach.get("Description", "")))[:1000],
                    },
                )
            )
        return out

