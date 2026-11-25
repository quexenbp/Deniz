# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from deniz.kit.scope import Scope


def test_empty_scope_allows_all() -> None:
    assert Scope().allows("anything.test")


def test_suffix_and_apex() -> None:
    scope = Scope(allow=["example.com"])
    assert scope.allows("example.com")
    assert scope.allows("a.b.example.com")
    assert not scope.allows("badexample.com")


def test_wildcard_and_deny() -> None:
    scope = Scope(allow=["*.example.com"], deny=["dev.example.com"])
    assert scope.allows("api.example.com")
    assert scope.allows("example.com")
    assert not scope.allows("dev.example.com")
    assert not scope.allows("example.net")


def test_wildcard_without_apex() -> None:
    scope = Scope(allow=["*.example.com"], include_apex=False)
    assert scope.allows("api.example.com")
    assert not scope.allows("example.com")

