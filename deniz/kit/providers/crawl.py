"""One-level same-origin crawler, optionally extracting a regex."""

from __future__ import annotations

import html as html_lib
import re
from urllib.parse import urljoin, urlsplit

from ..errors import ParseChanged
from ..models import Observation, Source, Target
from ..util import normalize_hostname
from .base import Context, Provider, ProviderInfo

LINK = re.compile(r'href=["\']([^"\'#]+)', re.I)


class Crawl(Provider):
    info = ProviderInfo(
        name="crawl",
        title="Same-origin link crawl",
        capabilities=frozenset({"crawl"}),
        auth="none",
        cost="free",
        rate=5.0,
        burst=3,
        max_bytes=500_000,
        budget=4_000_000,
        notes="Homepage plus one level of same-origin links; opt-in. Set crawl_regex to extract matches.",
    )
    cache_ttl = 1800.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        host = target.value
        origin = f"https://{host}"
        pattern = str(ctx.options.get("crawl_regex") or "")
        try:
            regex = re.compile(pattern) if pattern else None
        except re.error as exc:
            raise ParseChanged(f"bad crawl regex: {exc}", provider=self.info.name) from exc
        try:
            home = self.client.get(f"{origin}/", rate=self.info.rate, burst=self.info.burst)
        except Exception:
            return []
        if home.status != 200:
            return []
        source = [Source(provider=self.info.name, url=f"{origin}/")]
        seen: set[str] = set()
        out: list[Observation] = []
        links = []
        for href in LINK.findall(home.text_limited(500_000)):
            if href.startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            url = urljoin(origin + "/", html_lib.unescape(href))
            parsed = urlsplit(url)
            if normalize_hostname(parsed.hostname or "") != host:
                continue
            if url not in seen:
                seen.add(url)
                links.append(url)
        for url in links[:50]:
            out.append(Observation(type="url", value=url, confidence=0.6, sources=source, attrs={"crawl_depth": 1}))

        if regex is not None:
            for url in links[:10]:
                try:
                    page = self.client.get(url, rate=self.info.rate, burst=self.info.burst)
                except Exception:
                    continue
                if page.status != 200:
                    continue
                seen_matches: set[str] = set()
                for match in regex.finditer(page.text_limited(300_000)):
                    value = match.group(0)[:500]
                    if value in seen_matches:
                        continue
                    seen_matches.add(value)
                    out.append(
                        Observation(
                            type="note",
                            value=value,
                            confidence=0.7,
                            sources=[Source(provider=self.info.name, url=url)],
                            attrs={"record": "regex", "pattern": pattern, "page": url},
                        )
                    )
        return out

