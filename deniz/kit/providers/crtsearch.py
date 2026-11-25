"""crt.sh certificate search by arbitrary identity."""

from __future__ import annotations

from ..errors import Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip, normalize_hostname
from .base import Context, Provider, ProviderInfo


class CrtSearch(Provider):
    info = ProviderInfo(
        name="crtsearch",
        title="crt.sh certificate search",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=0.5,
        burst=1,
        tos_url="https://crt.sh/",
        homepage="https://crt.sh/",
        notes="Raw certificate entries for a keyword/identity.",
    )
    cache_ttl = 1800.0
    URL = "https://crt.sh/"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("crtsearch expects a keyword")
        resp = self.client.get(
            self.URL, params={"q": target.value, "output": "json", "exclude": "expired"},
            rate=self.info.rate, burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("crt.sh rate limit", provider=self.info.name)
        if resp.status in (401, 403):
            raise Blocked(f"crt.sh returned {resp.status}", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"crt.sh returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"crt.sh returned {resp.status}", provider=self.info.name)
        try:
            entries = resp.json()
        except ValueError as exc:
            raise ParseChanged("crt.sh returned invalid JSON", provider=self.info.name) from exc

        out = []
        for entry in entries if isinstance(entries, list) else []:
            cert_id = entry.get("id")
            if not cert_id:
                continue
            url = f"https://crt.sh/?id={cert_id}"
            names = [normalize_hostname(n) for n in str(entry.get("name_value", "")).splitlines()]
            out.append(
                Observation(
                    type="url",
                    value=url,
                    confidence=0.5,
                    sources=[Source(provider=self.info.name, url=url)],
                    attrs={
                        "common_name": clip(str(entry.get("common_name") or ""), 200),
                        "names": [n for n in names if n][:20],
                        "issuer": clip(str(entry.get("issuer_name") or ""), 200),
                        "not_before": entry.get("not_before"),
                        "not_after": entry.get("not_after"),
                    },
                )
            )
        return out
