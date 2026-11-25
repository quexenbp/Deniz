"""Spotify search through the Web API (client credentials)."""

from __future__ import annotations

import base64

from ..errors import AuthRequired, Blocked, ParseChanged, ProviderDead, RateLimited
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo


class Spotify(Provider):
    info = ProviderInfo(
        name="spotify",
        title="Spotify search",
        capabilities=frozenset({"social"}),
        auth="key",
        cost="quota",
        rate=1.0,
        burst=1,
        tos_url="https://developer.spotify.com/documentation/web-api",
        homepage="https://spotify.com/",
        notes="Needs client_id/client_secret for client-credentials OAuth.",
    )
    cache_ttl = 900.0
    TOKEN = "https://accounts.spotify.com/api/token"
    API = "https://api.spotify.com/v1/search"

    def _token(self, ctx: Context) -> str:
        client_id = ctx.auth.get("spotify", "client_id")
        secret = ctx.auth.get("spotify", "client_secret")
        if not client_id or not secret:
            raise AuthRequired("spotify needs client_id/client_secret", provider=self.info.name)
        basic = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
        resp = self.client.client._client.post(
            self.TOKEN,
            data={"grant_type": "client_credentials"},
            headers={"authorization": f"Basic {basic}"},
        )
        if resp.status_code != 200:
            raise Blocked(f"spotify token returned {resp.status_code}", provider=self.info.name)
        try:
            return str(resp.json()["access_token"])
        except (ValueError, KeyError) as exc:
            raise ParseChanged("spotify token response invalid", provider=self.info.name) from exc

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("spotify expects a keyword")
        token = self._token(ctx)
        resp = self.client.get(
            self.API,
            params={"q": target.value, "type": "track,artist,album", "limit": 10},
            headers={"authorization": f"Bearer {token}"},
            rate=self.info.rate,
            burst=self.info.burst,
        )
        if resp.status == 429:
            raise RateLimited("spotify rate limit", provider=self.info.name)
        if resp.status in (401, 403):
            raise Blocked(f"spotify returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"spotify returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ParseChanged("spotify returned invalid JSON", provider=self.info.name) from exc

        out = []
        for kind in ("tracks", "artists", "albums"):
            for item in (data.get(kind) or {}).get("items", [])[:10]:
                url = (item.get("external_urls") or {}).get("spotify")
                name = item.get("name")
                if not url or not name:
                    continue
                out.append(
                    Observation(
                        type="url",
                        value=str(url),
                        confidence=0.5,
                        sources=[Source(provider=self.info.name, url=str(url))],
                        attrs={
                            "kind": kind[:-1],
                            "title": clip(str(name), 200),
                            "artists": [a.get("name") for a in item.get("artists", [])[:3]],
                        },
                    )
                )
        return out
