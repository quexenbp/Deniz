"""X/Twitter recent search through API v2."""

from __future__ import annotations

from ..errors import AuthRequired, Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo


class XSearch(Provider):
    info = ProviderInfo(
        name="x",
        title="X recent search",
        capabilities=frozenset({"social"}),
        auth="key",
        cost="quota",
        rate=0.2,
        burst=1,
        tos_url="https://developer.x.com/en/docs/x-api",
        homepage="https://x.com/",
        notes="Needs DENIZ_X_TOKEN. Recent search window only.",
    )
    cache_ttl = 300.0
    API = "https://api.x.com/2/tweets/search/recent"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("x expects a keyword target")
        token = ctx.auth.get("x")
        if not token:
            raise AuthRequired("DENIZ_X_TOKEN is not set", provider=self.info.name)
        resp = self.client.get(
            self.API,
            params={
                "query": f"{target.value} -is:retweet",
                "max_results": 25,
                "tweet.fields": "created_at,public_metrics,author_id",
                "expansions": "author_id",
                "user.fields": "username",
            },
            headers={"authorization": f"Bearer {token}"},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("x rate limit", provider=self.info.name)
        if resp.status in (401, 403):
            raise Blocked(f"x returned {resp.status} (token)", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"x returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"x returned {resp.status}", provider=self.info.name)
        try:
            payload = resp.json()
        except ValueError as exc:
            raise ParseChanged("x returned invalid JSON", provider=self.info.name) from exc

        users = {u.get("id"): u.get("username") for u in payload.get("includes", {}).get("users", [])}
        out = []
        for tweet in payload.get("data", []):
            tweet_id = tweet.get("id")
            username = users.get(tweet.get("author_id"))
            if not tweet_id or not username:
                continue
            url = f"https://x.com/{username}/status/{tweet_id}"
            out.append(
                Observation(
                    type="url",
                    value=url,
                    confidence=0.7,
                    sources=[Source(provider=self.info.name, url=url)],
                    attrs={
                        "text": clip(str(tweet.get("text", "")), 500),
                        "created_at": tweet.get("created_at"),
                        "metrics": tweet.get("public_metrics"),
                        "author": username,
                    },
                )
            )
        return out
