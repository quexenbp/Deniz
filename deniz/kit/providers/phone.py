"""Offline phone number validation and carrier lookup."""

from __future__ import annotations

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from ..errors import ParseChanged
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo


class Phone(Provider):
    info = ProviderInfo(
        name="phone",
        title="Phone number analysis",
        capabilities=frozenset({"identity"}),
        auth="none",
        cost="free",
        rate=10.0,
        burst=5,
        notes="Offline libphonenumber data; no network.",
    )
    cache_ttl = 86400.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "phone":
            from ..errors import ParseChanged as PC

            raise PC("phone expects a phone target")
        try:
            parsed = phonenumbers.parse(target.value, None)
        except phonenumbers.NumberParseException as exc:
            raise ParseChanged(f"invalid number: {exc}") from exc

        source = [Source(provider=self.info.name, url=f"tel:{target.value}")]
        valid = phonenumbers.is_valid_number(parsed)
        attrs = {
            "record": "PHONE",
            "valid": valid,
            "possible": phonenumbers.is_possible_number(parsed),
            "country": phonenumbers.region_code_for_number(parsed),
            "country_name": geocoder.description_for_number(parsed, "en"),
            "carrier": carrier.name_for_number(parsed, "en") or None,
            "timezones": list(timezone.time_zones_for_number(parsed))[:5],
            "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        }
        return [
            Observation(
                type="note",
                value=f"{attrs['e164']} valid={valid} carrier={attrs['carrier'] or '-'}",
                confidence=0.9,
                sources=source,
                attrs=attrs,
            )
        ]
