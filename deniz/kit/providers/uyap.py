# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""UYAP Emsal precedent search.

The endpoint is the one the public Emsal search page calls. It returns docket
metadata; the readable page lives under mevzuat.adalet.gov.tr.
"""

from __future__ import annotations

from ..errors import Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo


class Uyap(Provider):
    info = ProviderInfo(
        name="uyap",
        title="UYAP Emsal precedent search",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=1.0,
        burst=1,
        tos_url="https://emsal.uyap.gov.tr/",
        homepage="https://emsal.uyap.gov.tr/",
        notes="Docket metadata only; open the linked page for full text.",
    )
    cache_ttl = 900.0
    API = "https://emsal.uyap.gov.tr/aramalist"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("uyap expects a keyword target")
        payload = {"data": {"aranan": target.value, "arananKelime": target.value, "pageSize": 20, "pageNumber": 1}}
        resp = self.client.post(self.API, json=payload, rate=self.info.rate, burst=self.info.burst)
        if resp.status == 429:
            raise RateLimited("uyap rate limit", provider=self.info.name)
        if resp.status in (403, 503):
            raise Blocked(f"uyap returned {resp.status}", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"uyap returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"uyap returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ParseChanged("uyap returned non-JSON (captcha or WAF page?)", provider=self.info.name) from exc

        if (data.get("metadata") or {}).get("FMTY") == "ERROR":
            raise ParseChanged(str((data.get("metadata") or {}).get("FMTE") or "uyap search error"), provider=self.info.name)
        rows = (data.get("data") or {}).get("data")
        if not isinstance(rows, list):
            raise ParseChanged("uyap response has no result list", provider=self.info.name)

        out: list[Observation] = []
        for row in rows:
            if not isinstance(row, dict) or not row.get("id"):
                continue
            doc_id = str(row["id"])
            url = f"https://mevzuat.adalet.gov.tr/ictihat/{doc_id}"
            court = str(row.get("daire") or "").strip()
            esas = str(row.get("esasNo") or "").strip()
            karar = str(row.get("kararNo") or "").strip()
            date = str(row.get("kararTarihi") or "").strip()
            citation = f"{court}, E.{esas} K.{karar}, T.{date}".strip(", ")
            out.append(
                Observation(
                    type="url",
                    value=url,
                    confidence=0.6,
                    sources=[Source(provider=self.info.name, url=self.API)],
                    attrs={
                        "court": court,
                        "case_no": esas,
                        "decision_no": karar,
                        "decided_at": date,
                        "status": row.get("durum"),
                        "citation": citation,
                    },
                )
            )
        return out
