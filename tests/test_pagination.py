from __future__ import annotations

import base64
import json

import pytest

from deniz.kit.pagination import InvalidCursor, decode_cursor, encode_cursor, paginate


def test_cursor_roundtrip() -> None:
    scope = "findings:case=abc:acked=0"
    token = encode_cursor((4, "2026-11-25T10:00:00+00:00", "f1"), scope)
    assert decode_cursor(token, scope) == (4, "2026-11-25T10:00:00+00:00", "f1")


def test_cursor_is_url_safe_and_unpadded() -> None:
    token = encode_cursor(("2026-11-25", "/path with spaces"), "s")
    assert "=" not in token
    assert all(ch.isalnum() or ch in "-_" for ch in token)


def test_cursor_scope_mismatch() -> None:
    token = encode_cursor(("a",), "alerts:acked=0")
    with pytest.raises(InvalidCursor):
        decode_cursor(token, "alerts:acked=1")


def test_cursor_rejects_garbage_and_versions() -> None:
    for token in ("", "!!!", "bm90LWpzb24", "a" * 2000):
        with pytest.raises(InvalidCursor):
            decode_cursor(token, "s")
    payload = base64.urlsafe_b64encode(json.dumps({"v": 99, "s": "s", "k": ["x"]}).encode()).decode().rstrip("=")
    with pytest.raises(InvalidCursor):
        decode_cursor(payload, "s")


def test_paginate_walks_without_duplicates() -> None:
    items = [5, 4, 3, 2, 1]
    seen: list[int] = []
    cursor = None
    while True:
        page = paginate(items, key=lambda value: (value,), scope="numbers", limit=2, cursor=cursor)
        seen.extend(page.items)
        cursor = page.next_cursor
        if not cursor:
            break
    assert seen == [5, 4, 3, 2, 1]


def test_cursor_is_stable_when_items_are_inserted() -> None:
    items = [5, 4, 3, 2, 1]
    first = paginate(items, key=lambda value: (value,), scope="numbers", limit=2)
    assert first.items == [5, 4]
    assert first.next_cursor

    items.append(9)  # a new item at the top of the list
    second = paginate(items, key=lambda value: (value,), scope="numbers", limit=2, cursor=first.next_cursor)
    assert second.items == [3, 2]
    assert second.offset == 3  # the new 9 shifted the absolute position, not the page

    third = paginate(items, key=lambda value: (value,), scope="numbers", limit=2, cursor=second.next_cursor)
    assert third.items == [1]
    assert third.next_cursor is None
    assert sorted([*first.items, *second.items, *third.items]) == [1, 2, 3, 4, 5]


def test_cursor_key_shape_mismatch() -> None:
    token = encode_cursor(("x",), "numbers")
    with pytest.raises(InvalidCursor):
        paginate([1, 2, 3], key=lambda value: (value,), scope="numbers", limit=1, cursor=token)


def test_offset_still_works() -> None:
    items = [5, 4, 3, 2, 1]
    page = paginate(items, key=lambda value: (value,), scope="numbers", limit=2, offset=1)
    assert page.items == [4, 3]
    assert page.offset == 1
    assert page.next_cursor
