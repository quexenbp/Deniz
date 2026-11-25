from __future__ import annotations

import json
from pathlib import Path

from deniz.kit.tokens import ROLES, ApiToken, load_tokens


def test_roles() -> None:
    assert ApiToken("v", "x", "viewer").permits("GET")
    assert not ApiToken("v", "x", "viewer").permits("POST")
    assert ApiToken("o", "x", "operator").permits("POST")
    assert not ApiToken("o", "x", "operator").permits("DELETE")
    assert ApiToken("a", "x", "admin").permits("DELETE")
    assert set(ROLES) == {"viewer", "operator", "admin"}


def test_env_json_tokens(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(
        "DENIZ_API_TOKENS",
        json.dumps([{"name": "reader", "token": "r", "role": "viewer"}, {"name": "ops", "token": "o", "role": "operator"}]),
    )
    tokens = load_tokens(tmp_path)
    assert [(t.name, t.role) for t in tokens] == [("reader", "viewer"), ("ops", "operator")]


def test_toml_tokens(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("DENIZ_API_TOKENS", raising=False)
    (tmp_path / "tokens.toml").write_text(
        '[[tokens]]\nname = "alice"\nvalue = "a"\nrole = "admin"\n',
        encoding="utf-8",
    )
    tokens = load_tokens(tmp_path)
    assert tokens == [ApiToken("alice", "a", "admin")]


def test_legacy_token_and_bad_role(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("DENIZ_API_TOKENS", raising=False)
    monkeypatch.setenv("DENIZ_API_TOKEN", "legacy")
    monkeypatch.setenv("DENIZ_API_TOKENS", json.dumps([{"name": "x", "token": "x", "role": "wizard"}]))
    tokens = load_tokens(tmp_path)
    assert tokens[0].role == "viewer"
    assert tokens[-1] == ApiToken("legacy", "legacy", "admin")


def test_duplicate_secrets_are_dropped(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(
        "DENIZ_API_TOKENS",
        json.dumps([{"name": "a", "token": "same", "role": "viewer"}, {"name": "b", "token": "same", "role": "admin"}]),
    )
    tokens = load_tokens(tmp_path)
    assert len(tokens) == 1
    assert tokens[0].name == "a"
