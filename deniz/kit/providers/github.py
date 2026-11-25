"""GitHub organization / user repository inventory."""

from __future__ import annotations

from ..errors import AuthRequired, Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo


class Github(Provider):
    info = ProviderInfo(
        name="github",
        title="GitHub repositories",
        capabilities=frozenset({"repos"}),
        auth="key",
        cost="quota",
        rate=0.5,
        burst=2,
        tos_url="https://docs.github.com/en/rest",
        homepage="https://github.com",
        notes="Optional token: DENIZ_GITHUB_TOKEN. Unauthenticated is 60 req/h.",
    )
    cache_ttl = 900.0
    API = "https://api.github.com"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type not in ("org", "username"):
            raise ParseChanged("github expects an org or username target")
        token = ctx.auth.get("github")
        headers = {"accept": "application/vnd.github+json", "x-github-api-version": "2022-11-28"}
        if token:
            headers["authorization"] = f"Bearer {token}"
        kind = "orgs" if target.type == "org" else "users"
        if target.type == "org" and not token:
            raise AuthRequired("org listing needs DENIZ_GITHUB_TOKEN", provider=self.info.name)
        resp = self.client.get(
            f"{self.API}/{kind}/{target.value}/repos",
            params={"per_page": 100, "sort": "updated"},
            headers=headers,
            rate=1.0 if token else self.info.rate,
            burst=3 if token else self.info.burst,
        )
        if resp.status == 404:
            raise ProviderDead(f"github {target.type} not found", provider=self.info.name)
        if resp.status == 429:
            raise RateLimited("github rate limit", provider=self.info.name)
        if resp.status in (401, 403):
            raise Blocked(f"github returned {resp.status} (token/quota)", provider=self.info.name)
        if resp.status >= 500:
            raise ProviderDead(f"github returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"github returned {resp.status}", provider=self.info.name)
        try:
            repos = resp.json()
        except ValueError as exc:
            raise ParseChanged("github returned invalid JSON", provider=self.info.name) from exc

        out = []
        for repo in repos if isinstance(repos, list) else []:
            url = repo.get("html_url")
            if not url:
                continue
            out.append(
                Observation(
                    type="url",
                    value=str(url),
                    confidence=0.95,
                    sources=[Source(provider=self.info.name, url=str(repo.get("url") or url))],
                    attrs={
                        "repo": repo.get("full_name"),
                        "description": str(repo.get("description") or "")[:300],
                        "language": repo.get("language"),
                        "stars": repo.get("stargazers_count"),
                        "archived": repo.get("archived"),
                        "private": repo.get("private"),
                        "fork": repo.get("fork"),
                        "updated_at": repo.get("updated_at"),
                    },
                )
            )
        return out
