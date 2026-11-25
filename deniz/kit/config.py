# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Runtime configuration and on-disk layout."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

APP_DIR_NAME = ".deniz"


@dataclass(frozen=True)
class Config:
    home: Path

    @property
    def cache_db(self) -> Path:
        return self.home / "cache.sqlite3"

    @property
    def state_db(self) -> Path:
        return self.home / "state.sqlite3"

    @property
    def runs_dir(self) -> Path:
        return self.home / "runs"

    @property
    def db_url(self) -> str | None:
        return os.environ.get("DENIZ_DB_URL") or None

    def store(self, name: str) -> str | Path:
        return self.db_url or (self.home / f"{name}.sqlite3")

    @property
    def providers_file(self) -> Path:
        return self.home / "providers.toml"

    @property
    def scope_file(self) -> Path | None:
        env = os.environ.get("DENIZ_SCOPE")
        if env:
            return Path(env).expanduser()
        local = Path.cwd() / "scope.toml"
        if local.exists():
            return local
        user = self.home / "scope.toml"
        return user if user.exists() else None

    def ensure(self) -> Config:
        self.home.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        return self


def load() -> Config:
    raw = os.environ.get("DENIZ_HOME")
    home = Path(raw).expanduser() if raw else Path.home() / APP_DIR_NAME
    return Config(home=home).ensure()

