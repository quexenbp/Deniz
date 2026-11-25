"""YouTube search by parsing the results page."""

from __future__ import annotations

import re
from urllib.parse import quote

from ..errors import Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo

VIDEO_ID = re.compile(r'"videoId":"([A-Za-z0-9_-]{11})"')
TITLE = re.compile(r'"title":\{"runs":\[\{"text":"((?:[^"\\]|\\.){1,300})"')


class YouTube(Provider):
    info = ProviderInfo(
        name="youtube",
        title="YouTube search",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=0.5,
        burst=1,
        tos_url="https://www.youtube.com/",
        homepage="https://www.youtube.com/",
        notes="HTML result page parse; no API key.",
    )
    cache_ttl = 900.0
    URL = "https://www.youtube.com/results"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("youtube expects a keyword")
        resp = self.client.get(
            self.URL,
            params={"search_query": target.value},
            headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36"},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("youtube rate limit", provider=self.info.name)
        if resp.status in (401, 403):
            raise Blocked(f"youtube returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"youtube returned {resp.status}", provider=self.info.name)
        body = resp.text_limited(2_000_000)
        ids = list(dict.fromkeys(VIDEO_ID.findall(body)))[:20]
        titles = [t.encode().decode("unicode_escape", "replace") for t in TITLE.findall(body)[:20]]
        source = [Source(provider=self.info.name, url=f"{self.URL}?search_query={quote(target.value)}")]
        out = []
        for index, video_id in enumerate(ids):
            url = f"https://www.youtube.com/watch?v={video_id}"
            out.append(
                Observation(
                    type="url",
                    value=url,
                    confidence=0.6,
                    sources=source,
                    attrs={"title": titles[index] if index < len(titles) else None, "video_id": video_id},
                )
            )
        return out
