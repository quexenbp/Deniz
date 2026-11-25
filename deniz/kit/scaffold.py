# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Skeleton for a new provider.

The generator writes a compiling provider with a matching contract test, and
registers the provider in ``registry.BUILTIN`` when that file exists. It never
overwrites unless ``force`` is set.
"""

from __future__ import annotations

import re
from pathlib import Path
from string import Template

NAME = re.compile(r"^[a-z][a-z0-9_]{1,30}$")

PROVIDER = Template(
    '''# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""$title."""

from __future__ import annotations

from ..errors import ParseChanged, ProviderDead
from ..models import Observation, Source, Target
from .base import CONTRACT_VERSION, Context, Provider, ProviderInfo


class $cls(Provider):
    API_VERSION = CONTRACT_VERSION
    info = ProviderInfo(
        name="$name",
        title="$title",
        capabilities=frozenset({"web"}),
        auth="none",
        cost="free",
        rate=1.0,
        burst=1,
        tos_url="",
        homepage="",
        notes="TODO: describe auth, limits and terms.",
    )
    cache_ttl = 900.0
    API = "https://example.invalid/api"

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("$name expects a keyword target")
        resp = self.client.get(self.API, params={"q": target.value}, rate=self.info.rate, burst=self.info.burst)
        if resp.status >= 500:
            raise ProviderDead(f"$name returned {resp.status}", provider=self.info.name)
        if resp.status != 200:
            raise ParseChanged(f"$name returned {resp.status}", provider=self.info.name)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ParseChanged("$name returned invalid JSON", provider=self.info.name) from exc

        out: list[Observation] = []
        for row in data.get("results", []) if isinstance(data, dict) else []:
            url = row.get("url") if isinstance(row, dict) else None
            if not url:
                continue
            out.append(
                Observation(
                    type="url",
                    value=str(url),
                    confidence=0.5,
                    sources=[Source(provider=self.info.name, url=str(url))],
                    attrs={"title": str(row.get("title") or "")[:300]},
                )
            )
        return out
'''
)

PROVIDER_TEST = Template(
    '''from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.errors import ProviderDead
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.$name import $cls
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler):
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    return Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))


def test_${name}_parses(tmp_path: Path) -> None:
    payload = {"results": [{"url": "https://example.invalid/a", "title": "A"}]}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    ctx = make(tmp_path, handler)
    items = $cls(ctx.http).run(Target(type="keyword", value="osint"), ctx)
    assert items[0].value == "https://example.invalid/a"
    assert items[0].sources[0].provider == "$name"


def test_${name}_dead(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="down")

    ctx = make(tmp_path, handler)
    with pytest.raises(ProviderDead):
        $cls(ctx.http).run(Target(type="keyword", value="osint"), ctx)
'''
)

def _cls(name: str) -> str:
    return "".join(part.title() for part in name.split("_"))


def _write(path: Path, text: str, force: bool) -> Path:
    if path.exists() and not force:
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def new_provider(root: Path, name: str, title: str | None = None, *, force: bool = False) -> list[Path]:
    name = name.strip().lower().replace("-", "_")
    if not NAME.match(name):
        raise ValueError("provider name must match ^[a-z][a-z0-9_]{1,30}$")
    provider = root / "deniz" / "kit" / "providers" / f"{name}.py"
    test = root / "tests" / f"test_{name}.py"
    label = (title or name.replace("_", " ").title()).strip()
    fields = {"name": name, "cls": _cls(name), "title": label}
    written = [
        _write(provider, PROVIDER.substitute(fields), force),
        _write(test, PROVIDER_TEST.substitute(fields), force),
    ]
    registry = root / "deniz" / "kit" / "providers" / "registry.py"
    if registry.exists():
        text = registry.read_text(encoding="utf-8")
        if f'"{name}":' not in text and "BUILTIN = {" in text:
            text = text.replace(
                "BUILTIN = {\n",
                f'BUILTIN = {{\n    "{name}": "deniz.kit.providers.{name}:{_cls(name)}",\n',
                1,
            )
            registry.write_text(text, encoding="utf-8")
    return written

