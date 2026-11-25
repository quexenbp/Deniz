"""Technology fingerprint and browser security-header audit."""

from __future__ import annotations

import re

from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo

SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)
TECH_HEADERS = ("server", "x-powered-by", "x-generator", "x-aspnet-version")
GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)


class Fingerprint(Provider):
    info = ProviderInfo(
        name="fingerprint",
        title="Technology and security headers",
        capabilities=frozenset({"fingerprint"}),
        auth="none",
        cost="free",
        rate=8.0,
        burst=4,
        notes="One GET; reads headers, generator meta and technology hints.",
    )
    cache_ttl = 900.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        host = target.value
        source = [Source(provider=self.info.name, url=f"https://{host}/")]
        try:
            resp = self.client.get(f"https://{host}/", rate=self.info.rate, burst=self.info.burst)
        except Exception:
            return []

        out: list[Observation] = [
            Observation(
                type="note",
                value=f"{name}: {'present' if resp.headers.get(name) else 'missing'}",
                confidence=0.7,
                sources=source,
                attrs={
                    "record": "header",
                    "header": name,
                    "present": bool(resp.headers.get(name)),
                    "value": clip(resp.headers.get(name, ""), 300),
                    "host": host,
                },
            )
            for name in SECURITY_HEADERS
        ]
        for name in TECH_HEADERS:
            value = resp.headers.get(name)
            if value:
                out.append(
                    Observation(
                        type="technology",
                        value=clip(value, 120),
                        confidence=0.8,
                        sources=source,
                        attrs={"header": name, "host": host},
                    )
                )
        generator = GENERATOR.search(resp.text_limited(20_000))
        if generator:
            out.append(
                Observation(
                    type="technology",
                    value=clip(generator.group(1), 120),
                    confidence=0.8,
                    sources=source,
                    attrs={"header": "generator", "host": host},
                )
            )
        return out
