# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Small shared helpers."""

from __future__ import annotations

import hashlib
import html
import re
from urllib.parse import urlsplit

HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
SPACE_RE = re.compile(r"\s+")


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        value = urlsplit(value).hostname or value
    value = value.split("/", 1)[0].split(":", 1)[0].strip(".")
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        value = value.encode("idna").decode("ascii")
    return value


def is_valid_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    return bool(HOST_RE.match(host.lower().rstrip(".")))


def normalize_hostname(host: str) -> str | None:
    host = host.strip().lower().strip(".")
    if host.startswith("*."):
        host = host[2:]
    if not is_valid_hostname(host):
        return None
    return host


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_title(body: str, limit: int = 160) -> str | None:
    match = TITLE_RE.search(body)
    if not match:
        return None
    title = SPACE_RE.sub(" ", html.unescape(match.group(1))).strip()
    return title[:limit] or None


def clip(value: str, limit: int = 300) -> str:
    value = SPACE_RE.sub(" ", value).strip()
    return value[:limit]

