"""robots.txt, sitemap.xml and security.txt discovery."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from ..models import Observation, Source, Target
from ..util import clip, normalize_hostname
from .base import Context, Provider, ProviderInfo

LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)


class Discovery(Provider):
    info = ProviderInfo(
        name="discovery",
        title="robots.txt / sitemap / security.txt",
        capabilities=frozenset({"discovery"}),
        auth="none",
        cost="free",
        rate=6.0,
        burst=3,
        notes="Three GETs; sitemap URLs capped.",
    )
    cache_ttl = 1800.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        host = target.value
        origin = f"https://{host}"
        out: list[Observation] = []
        source_for = {name: [Source(provider=self.info.name, url=f"{origin}/{name}")] for name in ("robots.txt", "sitemap.xml", ".well-known/security.txt")}

        robots = self._get(f"{origin}/robots.txt")
        if robots:
            body, _ = robots
            out.append(
                Observation(type="url", value=f"{origin}/robots.txt", confidence=0.7, sources=source_for["robots.txt"],
                            attrs={"kind": "robots", "host": host})
            )
            disallow = [clip(line.split(":", 1)[1].strip(), 200) for line in body.splitlines() if line.lower().startswith("disallow:")]
            disallow = [p for p in disallow if p and p != "/"][:50]
            for path in disallow:
                out.append(
                    Observation(type="url", value=urljoin(origin + "/", path.lstrip("/")), confidence=0.5,
                                sources=source_for["robots.txt"], attrs={"kind": "robots_path", "host": host, "path": path})
                )

        sitemap = self._get(f"{origin}/sitemap.xml")
        if sitemap:
            body, _ = sitemap
            out.append(
                Observation(type="url", value=f"{origin}/sitemap.xml", confidence=0.7, sources=source_for["sitemap.xml"],
                            attrs={"kind": "sitemap", "host": host})
            )
            seen: set[str] = set()
            for url in LOC.findall(body):
                if url in seen or len(seen) >= 100:
                    continue
                seen.add(url)
                out.append(Observation(type="url", value=clip(url, 500), confidence=0.6,
                                       sources=source_for["sitemap.xml"], attrs={"kind": "sitemap_url", "host": host}))
                parsed = normalize_hostname(url.split("/")[2] if "//" in url else "")
                if parsed:
                    out.append(Observation(type="hostname", value=parsed, confidence=0.6,
                                           sources=source_for["sitemap.xml"]))

        security = self._get(f"{origin}/.well-known/security.txt")
        if security:
            body, _ = security
            contacts = [clip(line.split(":", 1)[1].strip(), 200) for line in body.splitlines() if line.lower().startswith("contact:")]
            out.append(
                Observation(type="url", value=f"{origin}/.well-known/security.txt", confidence=0.8,
                            sources=source_for[".well-known/security.txt"],
                            attrs={"kind": "security_txt", "host": host, "contacts": contacts[:5]})
            )
        return out

    def _get(self, url: str) -> tuple[str, int] | None:
        try:
            resp = self.client.get(url, rate=self.info.rate, burst=self.info.burst)
        except Exception:
            return None
        if resp.status != 200 or "html" in resp.headers.get("content-type", ""):
            return None
        return resp.text_limited(200_000), resp.status
