"""GitHub code search for leaked strings, keys and configuration."""

from __future__ import annotations

from ..errors import AuthRequired, Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo


class GithubLeaks(Provider):
    info = ProviderInfo(
        name="github_leaks",
        title="GitHub code search",
        capabilities=frozenset({"code"}),
        auth="key",
        cost="quota",
        rate=0.3,
        burst=1,
        tos_url="https://docs.github.com/en/rest/search",
        homepage="https://github.com/search",
        notes="Code search requires DENIZ_GITHUB_TOKEN.",
    )
    cache_ttl = 900.0
    API = "https://api.github.com/search/code"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("github_leaks expects a keyword target")
        token = ctx.auth.get("github")
        if not token:
            raise AuthRequired("code search needs DENIZ_GITHUB_TOKEN", provider=self.info.name)
        resp = self.client.get(
            self.API,
            params={"q": target.value, "per_page": 100},
            headers={
                "accept": "application/vnd.github.text-match+json",
                "authorization": f"Bearer {token}",
                "x-github-api-version": "2022-11-28",
            },
            rate=1.0,
            burst=2,
        )
        if resp.status == 422:
            raise ParseChanged("github rejected the query", provider=self.info.name)
        if resp.status == 429:
            raise RateLimited("github rate limit", provider=self.info.name)
        if resp.status in (401, 403):
            raise Blocked(f"github returned {resp.status} (token/quota)", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"github returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"github returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ParseChanged("github returned invalid JSON", provider=self.info.name) from exc

        out = []
        for item in data.get("items", []) if isinstance(data, dict) else []:
            html_url = item.get("html_url")
            if not html_url:
                continue
            fragments = [
                str(match.get("fragment", ""))[:400]
                for text in item.get("text_matches", [])
                for match in text.get("matches", [])
            ]
            out.append(
                Observation(
                    type="url",
                    value=str(html_url),
                    confidence=0.8,
                    sources=[Source(provider=self.info.name, url=str(item.get("url") or html_url))],
                    attrs={
                        "repo": (item.get("repository") or {}).get("full_name"),
                        "path": item.get("path"),
                        "fragments": fragments[:3],
                    },
                )
            )
        return out
