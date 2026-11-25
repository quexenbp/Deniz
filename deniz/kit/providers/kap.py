# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""KAP (Kamuyu Aydınlatma Platformu) disclosure search.

KAP's public web endpoint is a Next.js API behind a WAF. It is the same endpoint
the site's search page calls; no key is required for low-volume use.
"""

from __future__ import annotations

from typing import Any

from ..errors import Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo

PAYLOAD: dict[str, Any] = {
    "bdkMemberOidList": [],
    "bdkReview": "",
    "discIndex": [],
    "disclosureClass": "",
    "fromDate": "",
    "fromSrc": "Y",
    "inactiveMkkMemberOidList": [],
    "index": "",
    "isLate": "",
    "mainSector": "",
    "market": "",
    "memberType": None,
    "mkkMemberOidList": [],
    "prd": "",
    "ruleType": "",
    "sector": "",
    "srcCategory": "4",
    "subjectList": [],
    "subSector": "",
    "toDate": "",
    "year": "",
}


class Kap(Provider):
    info = ProviderInfo(
        name="kap",
        title="KAP disclosure search",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=1.0,
        burst=1,
        tos_url="https://www.kap.org.tr/tr/kap-hakkinda",
        homepage="https://www.kap.org.tr/",
        notes="Turkish public disclosure platform; WAF may block datacenter IPs.",
    )
    cache_ttl = 600.0
    API = "https://www.kap.org.tr/tr/api/memberDisclosureQuery"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("kap expects a keyword target")
        payload = {**PAYLOAD, "term": target.value, "kw": target.value}
        resp = self.client.post(
            self.API,
            json=payload,
            rate=self.info.rate,
            burst=self.info.burst,
            headers={"origin": "https://www.kap.org.tr", "referer": "https://www.kap.org.tr/tr/bildirim-sorgu"},
        )
        if resp.status == 429:
            raise RateLimited("kap rate limit", provider=self.info.name)
        if resp.status in (403, 503):
            raise Blocked(f"kap returned {resp.status}", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"kap returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"kap returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ParseChanged("kap returned non-JSON (WAF page?)", provider=self.info.name) from exc

        rows = data.get("data") if isinstance(data, dict) else data
        if isinstance(rows, dict):
            rows = rows.get("data")
        if not isinstance(rows, list):
            raise ParseChanged("kap response has no result list", provider=self.info.name)

        out: list[Observation] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            index = row.get("disclosureIndex") or row.get("index")
            if not index:
                continue
            url = f"https://www.kap.org.tr/tr/bildirim/{index}"
            out.append(
                Observation(
                    type="url",
                    value=url,
                    confidence=0.75,
                    sources=[Source(provider=self.info.name, url=url)],
                    attrs={
                        "company": row.get("kapMemberTitle") or row.get("companyTitle"),
                        "subject": clip(str(row.get("subject") or row.get("summary") or ""), 300),
                        "published_at": row.get("publishDate") or row.get("disclosureDate"),
                        "class": row.get("disclosureClass"),
                    },
                )
            )
        return out
