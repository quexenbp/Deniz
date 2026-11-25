"""Reddit search through the public JSON endpoints."""

from __future__ import annotations

from ..errors import Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo


class Reddit(Provider):
    info = ProviderInfo(
        name="reddit",
        title="Reddit search",
        capabilities=frozenset({"web"}),
        auth="key",
        cost="quota",
        rate=0.5,
        burst=1,
        tos_url="https://www.reddit.com/wiki/api",
        homepage="https://www.reddit.com/",
        notes="Set reddit client_id/client_secret for app-only OAuth; anonymous is often 403.",
    )
    cache_ttl = 600.0
    API = "https://oauth.reddit.com/search"
    TOKEN = "https://www.reddit.com/api/v1/access_token"

    def _token(self, ctx: Context) -> str | None:
        client_id = ctx.auth.get("reddit", "client_id")
        secret = ctx.auth.get("reddit", "client_secret")
        if not client_id or not secret:
            return None
        import base64

        basic = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
        resp = self.client.client._client.post(
            self.TOKEN,
            data={"grant_type": "client_credentials"},
            headers={"authorization": f"Basic {basic}", "user-agent": "Deniz/0.1"},
        )
        if resp.status_code != 200:
            return None
        try:
            return str(resp.json().get("access_token") or "") or None
        except ValueError:
            return None

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("reddit expects a keyword target")
        token = self._token(ctx)
        headers = {"accept": "application/json"}
        if token:
            headers["authorization"] = f"Bearer {token}"
        resp = self.client.get(
            self.API,
            params={"q": target.value, "limit": 25, "sort": "relevance", "raw_json": 1},
            rate=self.info.rate,
            burst=self.info.burst,
            headers=headers,
        )
        if resp.status == 429:
            raise RateLimited("reddit rate limit", provider=self.info.name)
        if resp.status in (401, 403):
            raise Blocked(f"reddit returned {resp.status}", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"reddit returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"reddit returned {resp.status}", provider=self.info.name)
        try:
            children = resp.json().get("data", {}).get("children", [])
        except ValueError as exc:
            raise ParseChanged("reddit returned invalid JSON", provider=self.info.name) from exc

        out = []
        for child in children:
            data = child.get("data") or {}
            permalink = data.get("permalink")
            if not permalink:
                continue
            url = f"https://www.reddit.com{permalink}"
            out.append(
                Observation(
                    type="url",
                    value=url,
                    confidence=0.6,
                    sources=[Source(provider=self.info.name, url=url)],
                    attrs={
                        "title": clip(str(data.get("title", "")), 300),
                        "subreddit": data.get("subreddit"),
                        "score": data.get("score"),
                        "created": data.get("created_utc"),
                    },
                )
            )
        return out
