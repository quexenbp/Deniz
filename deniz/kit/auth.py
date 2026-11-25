# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Provider credentials and per-provider settings.

Precedence: environment > ``~/.deniz/providers.toml``. Environment names are
``DENIZ_<PROVIDER>_<KEY>`` (for example ``DENIZ_CERTSPOTTER_TOKEN``).

The file is never printed by the CLI; ``source()`` only reports where a value
came from.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


class AuthStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: dict[str, dict[str, str]] = {}
        if path.exists():
            try:
                raw = tomllib.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raw = {}
            for provider, values in raw.items():
                if isinstance(values, dict):
                    self._data[str(provider)] = {str(k): str(v) for k, v in values.items()}

    def get(self, provider: str, key: str = "token") -> str | None:
        env = os.environ.get(f"DENIZ_{provider.upper()}_{key.upper()}")
        if env:
            return env
        return self._data.get(provider, {}).get(key)

    def source(self, provider: str, key: str = "token") -> str | None:
        if os.environ.get(f"DENIZ_{provider.upper()}_{key.upper()}"):
            return "env"
        if self._data.get(provider, {}).get(key):
            return "file"
        return None

    def configured(self, provider: str, key: str = "token") -> bool:
        return self.get(provider, key) is not None

    def file_mode_warning(self) -> str | None:
        if not self.path.exists():
            return None
        if os.name == "nt":
            return None
        mode = stat.S_IMODE(self.path.stat().st_mode)
        if mode & 0o077:
            return f"{self.path} is {oct(mode)}; run: chmod 600 {self.path}"
        return None

