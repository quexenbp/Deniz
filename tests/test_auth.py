# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from pathlib import Path

from deniz.kit.auth import AuthStore


def test_env_precedence(monkeypatch, tmp_path: Path) -> None:
    path = tmp_path / "providers.toml"
    path.write_text('[certspotter]\ntoken = "file-token"\n', encoding="utf-8")
    store = AuthStore(path)
    assert store.get("certspotter") == "file-token"
    assert store.source("certspotter") == "file"
    monkeypatch.setenv("DENIZ_CERTSPOTTER_TOKEN", "env-token")
    assert store.get("certspotter") == "env-token"
    assert store.source("certspotter") == "env"


def test_settings(tmp_path: Path) -> None:
    path = tmp_path / "providers.toml"
    path.write_text('[searxng]\nurl = "https://searx.example"\n', encoding="utf-8")
    store = AuthStore(path)
    assert store.get("searxng", "url") == "https://searx.example"
    assert store.configured("searxng", "url")
    assert store.get("searxng") is None

