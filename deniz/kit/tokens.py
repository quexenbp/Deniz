# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""API tokens and roles.

Precedence: ``DENIZ_API_TOKENS`` JSON > ``~/.deniz/tokens.toml`` >
``DENIZ_API_TOKEN``. The legacy single token is an admin token, so existing
deployments keep working. Secrets are compared by the server, never printed.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


ROLES = {
    "viewer": frozenset({"GET"}),
    "operator": frozenset({"GET", "POST"}),
    "admin": frozenset({"GET", "POST", "DELETE"}),
}


@dataclass(frozen=True)
class ApiToken:
    name: str
    secret: str
    role: str = "admin"

    def permits(self, method: str) -> bool:
        return method.upper() in ROLES.get(self.role, ROLES["viewer"])


def _token(name: object, secret: object, role: object = "admin") -> ApiToken | None:
    if not isinstance(secret, str) or not secret:
        return None
    role_name = str(role or "admin")
    if role_name not in ROLES:
        role_name = "viewer"
    return ApiToken(name=str(name or "default"), secret=secret, role=role_name)


def load_tokens(home: Path) -> list[ApiToken]:
    tokens: list[ApiToken] = []
    raw = os.environ.get("DENIZ_API_TOKENS")
    if raw:
        try:
            data = json.loads(raw)
        except ValueError:
            data = []
        rows = data if isinstance(data, list) else data.get("tokens", []) if isinstance(data, dict) else []
        for row in rows:
            if isinstance(row, dict):
                item = _token(row.get("name"), row.get("token") or row.get("secret"), row.get("role"))
                if item:
                    tokens.append(item)
    path = home / "tokens.toml"
    if path.exists():
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        for row in data.get("tokens", []) if isinstance(data, dict) else []:
            if isinstance(row, dict):
                item = _token(row.get("name"), row.get("value") or row.get("token"), row.get("role"))
                if item:
                    tokens.append(item)
    legacy = os.environ.get("DENIZ_API_TOKEN")
    if legacy:
        tokens.append(ApiToken(name="legacy", secret=legacy, role="admin"))
    seen: set[str] = set()
    unique: list[ApiToken] = []
    for token in tokens:
        if token.secret in seen:
            continue
        seen.add(token.secret)
        unique.append(token)
    return unique
