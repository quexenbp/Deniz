# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""PII redaction for reports and case exports.

Redaction is deliberately conservative: it masks e-mail local parts and
phone-like numbers, but does not touch names, usernames, domains or IPs.
Phone matching uses libphonenumber through the ``phonenumbers`` dependency;
free-form local numbers are only recognised when they look international or
when the observation itself is typed as a phone.
"""

from __future__ import annotations

import re
from typing import Any

from .models import Result

EMAIL = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![\w.-])")


def _mask_digits(raw: str) -> str:
    digits = [index for index, char in enumerate(raw) if char.isdigit()]
    if len(digits) < 3:
        return "***"
    keep = set(digits[-2:])
    return "".join(char if (not char.isdigit() or index in keep) else "*" for index, char in enumerate(raw))


def mask_email_local(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        local, domain = match.group(1), match.group(2)
        head = local[0] if local else ""
        return f"{head}***@{domain}"

    return EMAIL.sub(replace, text)


def mask_phones(text: str) -> str:
    try:
        import phonenumbers
    except ImportError:  # pragma: no cover - base dependency, but stay safe
        return text
    out: list[str] = []
    last = 0
    try:
        matches = phonenumbers.PhoneNumberMatcher(text, None)
        for match in matches:
            out.append(text[last : match.start])
            out.append(_mask_digits(text[match.start : match.end]))
            last = match.end
    except Exception:  # pragma: no cover - third-party matcher edge cases
        return text
    out.append(text[last:])
    return "".join(out)


def redact_text(text: str) -> str:
    return mask_phones(mask_email_local(text))


def redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_obj(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_obj(item) for item in value)
    if isinstance(value, dict):
        return {key: redact_obj(item) for key, item in value.items()}
    return value


def redact_result(result: Result) -> Result:
    """Return a deep redacted copy; the original run stays untouched."""

    data = result.model_dump(mode="python")
    redacted = redact_obj(data)
    if isinstance(redacted.get("target"), dict):
        target = redacted["target"]
        if target.get("type") == "phone" and isinstance(target.get("value"), str):
            target["value"] = _mask_digits(target["value"])
    for item in redacted.get("items", []):
        if not isinstance(item, dict):
            continue
        if item.get("type") == "phone" and isinstance(item.get("value"), str):
            item["value"] = _mask_digits(item["value"])
    return Result.model_validate(redacted)
