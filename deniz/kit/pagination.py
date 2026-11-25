# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Opaque, scope-bound pagination tokens for list surfaces.

A token remembers the sort key of the last item served, not an offset. New
items inserted at the top of a list therefore do not shift the next page and
cause duplicates. Keys are tuples ordered descending; each store already
sorts by the same fields and appends a unique id or name as the tie-breaker.

Tokens are base64url JSON without a signature. They hide the key from clients
and bind it to a scope string so a token from one query (for example,
findings of case A) is rejected by another (case B). They are not secrets.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, TypeVar

PAGE_VERSION = 1
MAX_TOKEN = 1024

T = TypeVar("T")


class InvalidCursor(ValueError):
    """A pagination token is malformed or belongs to a different query."""


@dataclass(frozen=True)
class Page:
    items: list[Any]
    total: int
    offset: int
    next_cursor: str | None


def encode_cursor(key: tuple[Any, ...], scope: str) -> str:
    payload = json.dumps(
        {"v": PAGE_VERSION, "s": scope, "k": list(key)},
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return base64.urlsafe_b64encode(payload.encode("ascii")).decode("ascii").rstrip("=")


def decode_cursor(token: str, scope: str) -> tuple[Any, ...]:
    if not token or len(token) > MAX_TOKEN:
        raise InvalidCursor("cursor is empty or too long")
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        data = json.loads(raw)
    except (binascii.Error, UnicodeError, ValueError) as exc:
        raise InvalidCursor("cursor is not valid base64 JSON") from exc
    if not isinstance(data, dict) or data.get("v") != PAGE_VERSION:
        raise InvalidCursor("unsupported cursor version")
    if data.get("s") != scope:
        raise InvalidCursor("cursor does not belong to this query")
    key = data.get("k")
    if not isinstance(key, list) or not key:
        raise InvalidCursor("cursor has no key")
    if any(isinstance(part, (dict, list)) or part is None for part in key):
        raise InvalidCursor("cursor key has unsupported values")
    return tuple(key)


def paginate(
    items: Iterable[T],
    *,
    key: Callable[[T], tuple[Any, ...]],
    scope: str,
    limit: int,
    cursor: str | None = None,
    offset: int = 0,
) -> Page:
    """Return one page in descending key order.

    ``offset`` applies only when no cursor is given, which keeps the old
    offset-based clients working. A cursor always wins over an offset.
    """

    limit = max(1, int(limit))
    ordered = sorted(items, key=key, reverse=True)
    total = len(ordered)
    if cursor:
        marker = decode_cursor(cursor, scope)
        start = 0
        try:
            while start < total and key(ordered[start]) >= marker:
                start += 1
        except TypeError as exc:
            raise InvalidCursor("cursor key has the wrong shape") from exc
    else:
        start = min(max(0, int(offset)), total)
    page = ordered[start : start + limit]
    next_cursor = encode_cursor(key(page[-1]), scope) if page and start + limit < total else None
    return Page(items=page, total=total, offset=start, next_cursor=next_cursor)


def page_from(
    rows: list[T],
    *,
    key: Callable[[T], tuple[Any, ...]],
    scope: str,
    limit: int,
    total: int,
    offset: int,
) -> Page:
    """Build a page from rows fetched with ``limit + 1``.

    Used when the store pages in SQL and already knows the real total; the
    extra row tells us whether another page exists.
    """

    limit = max(1, int(limit))
    page = rows[:limit]
    next_cursor = encode_cursor(key(page[-1]), scope) if len(rows) > limit and page else None
    return Page(items=page, total=total, offset=offset, next_cursor=next_cursor)
