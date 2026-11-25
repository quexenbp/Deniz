# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Scope enforcement.

Even when the CLI target is trusted, passive providers return hosts outside
the target (shared certificates, wildcard SANs). Scope drops them unless the
operator opted in.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.11+ has tomllib
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass
class Scope:
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    include_apex: bool = True

    @classmethod
    def from_file(cls, path: Path) -> Scope:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        return cls(
            allow=[x.lower().strip() for x in data.get("allow", [])],
            deny=[x.lower().strip() for x in data.get("deny", [])],
            include_apex=bool(data.get("include_apex", True)),
        )

    def _matches(self, host: str, pattern: str) -> bool:
        host = host.lower().rstrip(".")
        pattern = pattern.lower().rstrip(".")
        if pattern.startswith("*."):
            base = pattern[2:]
            return host.endswith("." + base) or (self.include_apex and host == base)
        return host == pattern or host.endswith("." + pattern) or fnmatch.fnmatch(host, pattern)

    def allows(self, host: str) -> bool:
        if any(self._matches(host, p) for p in self.deny):
            return False
        if not self.allow:
            return True
        return any(self._matches(host, p) for p in self.allow)

