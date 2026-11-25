"""Dictionary definitions."""

from __future__ import annotations

from ..errors import ParseChanged, ProviderDead
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo


class Dictionary(Provider):
    info = ProviderInfo(
        name="dictionary",
        title="Dictionary API",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=2.0,
        burst=2,
        tos_url="https://dictionaryapi.dev/",
        homepage="https://dictionaryapi.dev/",
        notes="Free Dictionary API by meetDeveloper.",
    )
    cache_ttl = 86400.0
    API = "https://api.dictionaryapi.dev/api/v2/entries/en/"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("dictionary expects a word")
        resp = self.client.get(self.API + target.value, rate=self.info.rate, burst=self.info.burst)
        if resp.status == 404:
            raise ProviderDead(f"no entry for {target.value}", provider=self.info.name)
        if resp.status != 200:
            raise ProviderDead(f"dictionary returned {resp.status}", provider=self.info.name)
        try:
            entries = resp.json()
        except ValueError as exc:
            raise ParseChanged("dictionary returned invalid JSON", provider=self.info.name) from exc

        out = []
        for entry in entries if isinstance(entries, list) else []:
            source = [Source(provider=self.info.name, url=entry.get("sourceUrls", [self.API])[0])]
            for meaning in entry.get("meanings", [])[:10]:
                part = meaning.get("partOfSpeech")
                for definition in meaning.get("definitions", [])[:10]:
                    text = definition.get("definition")
                    if not text:
                        continue
                    out.append(
                        Observation(
                            type="note",
                            value=clip(f"{part}: {text}", 500),
                            confidence=0.8,
                            sources=source,
                            attrs={"record": "DEFINITION", "word": target.value, "part": part},
                        )
                    )
        return out
