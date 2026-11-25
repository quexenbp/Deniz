from __future__ import annotations

from pathlib import Path

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.phone import Phone
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def test_valid_and_invalid() -> None:
    client = HttpClient(Cache(Path.cwd() / ".test-phone.sqlite3"), Limiter())
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(Path.cwd() / ".test-phone.toml"))
    items = Phone(client).run(Target(type="phone", value="+14155552671"), ctx)
    assert items[0].attrs["valid"] is True
    assert items[0].attrs["country"] == "US"
    assert items[0].attrs["e164"] == "+14155552671"
