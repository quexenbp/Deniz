from __future__ import annotations

from pathlib import Path

import pytest

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.openalex import OpenAlex
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


@pytest.mark.vcr
def test_openalex_recorded(tmp_path: Path) -> None:
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter())
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))
    items = OpenAlex(client).run(Target(type="keyword", value="osint"), ctx)
    assert items
    assert items[0].value.startswith("https://doi.org/")
