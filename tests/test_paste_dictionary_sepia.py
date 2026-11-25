from __future__ import annotations

import json
from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.dictionary import Dictionary
from deniz.kit.providers.pastebin import Pastebin
from deniz.kit.providers.sepiasearch import SepiaSearch
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler):
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    return client, Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))


def test_pastebin(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"id": "abc123", "tags": ["osint"]}]})

    client, ctx = make(tmp_path, handler)
    items = Pastebin(client).run(Target(type="keyword", value="osint"), ctx)
    assert items[0].value == "https://pastebin.com/abc123"


def test_dictionary(tmp_path: Path) -> None:
    payload = [{"meanings": [{"partOfSpeech": "noun", "definitions": [{"definition": "a thing"}]}], "sourceUrls": ["https://dict"]}]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    client, ctx = make(tmp_path, handler)
    items = Dictionary(client).run(Target(type="keyword", value="thing"), ctx)
    assert items[0].attrs["record"] == "DEFINITION"
    assert "a thing" in items[0].value


def test_sepiasearch(tmp_path: Path) -> None:
    payload = {"data": [{"url": "https://video.test/w/1", "name": "Video", "account": {"displayName": "alice"}}]}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    client, ctx = make(tmp_path, handler)
    items = SepiaSearch(client).run(Target(type="keyword", value="osint"), ctx)
    assert items[0].value == "https://video.test/w/1"
    assert items[0].attrs["author"] == "alice"
