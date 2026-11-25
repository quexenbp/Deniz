# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from deniz.kit.providers.typosquat import permutations


def test_permutations_cover_kinds() -> None:
    values = dict(permutations("example.com"))
    assert values.get("exmple.com") == "omission"
    assert values.get("exmaple.com") == "transposition"
    assert values.get("examp1e.com") == "homoglyph"
    assert values.get("example.net") == "tld"
    assert "example.com" not in values
    assert len(values) == len(set(values))


def test_limit() -> None:
    assert len(permutations("example.com", limit=10)) == 10


def test_multi_label_suffix() -> None:
    values = dict(permutations("example.com.tr"))
    assert values.get("exmple.com.tr") == "omission"
    assert values.get("example.net") == "tld"
    assert "examplecom.tr" not in values

