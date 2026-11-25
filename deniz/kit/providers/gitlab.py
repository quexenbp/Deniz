"""GitLab user/group project inventory."""

from __future__ import annotations

from ..errors import ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo


class Gitlab(Provider):
    info = ProviderInfo(
        name="gitlab",
        title="GitLab projects",
        capabilities=frozenset({"repos"}),
        auth="none",
        cost="free",
        rate=1.0,
        burst=2,
        tos_url="https://docs.gitlab.com/ee/api/rest/",
        homepage="https://gitlab.com/",
        notes="Public API; no token needed for public projects.",
    )
    cache_ttl = 900.0
    API = "https://gitlab.com/api/v4"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type not in ("username", "org"):
            raise ParseChanged("gitlab expects a username or org target")
        collection = "users" if target.type == "username" else "groups"
        listing = self.client.get(
            f"{self.API}/{collection}",
            params={"username" if collection == "users" else "search": target.value},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if listing.status == 429:
            raise RateLimited("gitlab rate limit", provider=self.info.name)
        if listing.status != 200:
            raise ProviderDead(f"gitlab returned {listing.status}", provider=self.info.name)
        try:
            entries = listing.json()
        except ValueError as exc:
            raise ParseChanged("gitlab returned invalid JSON", provider=self.info.name) from exc
        match = next(
            (e for e in entries if str(e.get("username") or e.get("full_path") or e.get("path")) == target.value),
            entries[0] if entries else None,
        )
        if not match:
            raise ProviderDead(f"gitlab {target.type} not found", provider=self.info.name)

        resp = self.client.get(
            f"{self.API}/{collection}/{match['id']}/projects",
            params={"per_page": 100, "order_by": "last_activity_at"},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("gitlab rate limit", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"gitlab returned {resp.status}", provider=self.info.name)
        try:
            projects = resp.json()
        except ValueError as exc:
            raise ParseChanged("gitlab returned invalid JSON", provider=self.info.name) from exc

        out = []
        for project in projects if isinstance(projects, list) else []:
            url = project.get("web_url")
            if not url:
                continue
            out.append(
                Observation(
                    type="url",
                    value=str(url),
                    confidence=0.85,
                    sources=[Source(provider=self.info.name, url=str(project.get("web_url") or url))],
                    attrs={
                        "repo": project.get("path_with_namespace"),
                        "description": str(project.get("description") or "")[:300],
                        "visibility": project.get("visibility"),
                        "archived": project.get("archived"),
                        "last_activity": project.get("last_activity_at"),
                    },
                )
            )
        return out
