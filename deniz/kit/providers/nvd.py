# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""NVD CVE search (API 2.0)."""

from __future__ import annotations

from ..errors import Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo


class Nvd(Provider):
    info = ProviderInfo(
        name="nvd",
        title="NIST NVD CVE API 2.0",
        capabilities=frozenset({"vuln"}),
        auth="key",
        cost="free",
        rate=0.2,
        burst=1,
        tos_url="https://nvd.nist.gov/developers/terms-of-use",
        homepage="https://nvd.nist.gov/developers/vulnerabilities",
        notes="Unauthenticated limit is 5 requests / 30s; a key raises it.",
    )
    cache_ttl = 3600.0
    URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("nvd expects a keyword target")
        key = ctx.auth.get("nvd")
        headers = {"apiKey": key} if key else {}
        resp = self.client.get(
            self.URL,
            params={"keywordSearch": target.value, "resultsPerPage": 50},
            headers=headers,
            rate=1.5 if key else self.info.rate,
            burst=3 if key else self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("nvd rate limit", provider=self.info.name)
        if resp.status in (401, 403):
            raise Blocked(f"nvd returned {resp.status}", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"nvd returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"nvd returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ParseChanged("nvd returned invalid JSON", provider=self.info.name) from exc

        out: list[Observation] = []
        for entry in data.get("vulnerabilities", []):
            cve = entry.get("cve") or {}
            cve_id = cve.get("id")
            if not cve_id:
                continue
            description = next(
                (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
            )
            score, severity = self._score(cve.get("metrics") or {})
            refs = [r.get("url") for r in (cve.get("references") or []) if r.get("url")][:5]
            out.append(
                Observation(
                    type="cve",
                    value=str(cve_id),
                    confidence=0.9,
                    sources=[Source(provider=self.info.name, url=f"https://nvd.nist.gov/vuln/detail/{cve_id}")],
                    attrs={
                        "description": description[:2000],
                        "cvss": score,
                        "severity": severity,
                        "published": cve.get("published"),
                        "modified": cve.get("lastModified"),
                        "references": refs,
                        "status": cve.get("vulnStatus"),
                    },
                )
            )
        return out

    @staticmethod
    def _score(metrics: dict) -> tuple[float | None, str | None]:
        for group in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(group) or []
            if not entries:
                continue
            data = entries[0].get("cvssData") or {}
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
            return (float(score) if score is not None else None, severity)
        return None, None

