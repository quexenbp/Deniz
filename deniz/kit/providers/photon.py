"""Photon (Komoot) geocoding."""

from __future__ import annotations

from ..errors import ParseChanged, ProviderDead
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo


class Photon(Provider):
    info = ProviderInfo(
        name="photon",
        title="Photon geocoder",
        capabilities=frozenset({"geo"}),
        auth="none",
        cost="free",
        rate=1.0,
        burst=1,
        tos_url="https://photon.komoot.io/",
        homepage="https://photon.komoot.io/",
        notes="Coordinates and OSM identifiers; no map tiles.",
    )
    cache_ttl = 3600.0
    API = "https://photon.komoot.io/api/"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("photon expects a keyword target")
        resp = self.client.get(self.API, params={"q": target.value, "limit": 15}, rate=self.info.rate, burst=self.info.burst)
        if resp.status != 200:
            raise ProviderDead(f"photon returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ParseChanged("photon returned invalid JSON", provider=self.info.name) from exc

        out: list[Observation] = []
        for feature in data.get("features", []) if isinstance(data, dict) else []:
            props = feature.get("properties") or {}
            coords = (feature.get("geometry") or {}).get("coordinates") or []
            if len(coords) != 2:
                continue
            label = ", ".join(
                str(props.get(key)) for key in ("name", "street", "city", "state", "country") if props.get(key)
            )
            out.append(
                Observation(
                    type="note",
                    value=f"{label or target.value} @ {coords[1]:.5f},{coords[0]:.5f}",
                    confidence=0.6,
                    sources=[Source(provider=self.info.name, url=self.API)],
                    attrs={
                        "record": "GEO",
                        "lat": coords[1],
                        "lon": coords[0],
                        "osm_id": props.get("osm_id"),
                        "osm_type": props.get("osm_type"),
                        "label": clip(label, 300),
                    },
                )
            )
        return out
