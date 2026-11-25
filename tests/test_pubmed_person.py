from __future__ import annotations

from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.person import Person
from deniz.kit.providers.pubmed import PubMed
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler):
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    return client, Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))


def test_pubmed(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "esearch" in str(request.url):
            return httpx.Response(200, json={"esearchresult": {"idlist": ["1"]}})
        return httpx.Response(200, json={"result": {"1": {"title": "Paper", "fulljournalname": "J"}}})

    client, ctx = make(tmp_path, handler)
    items = PubMed(client).run(Target(type="keyword", value="osint"), ctx)
    assert items[0].value == "https://pubmed.ncbi.nlm.nih.gov/1/"


def test_person(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "api.php" in str(request.url):
            return httpx.Response(200, json={"query": {"search": [{"title": "Ada Lovelace"}]}})
        return httpx.Response(
            200,
            json={"description": "Mathematician", "extract": "Ada was...", "content_urls": {"desktop": {"page": "https://en.wikipedia.org/wiki/Ada_Lovelace"}}},
        )

    client, ctx = make(tmp_path, handler)
    items = Person(client).run(Target(type="keyword", value="ada lovelace"), ctx)
    assert items[0].value == "https://en.wikipedia.org/wiki/Ada_Lovelace"
    assert any(i.attrs.get("record") == "BIO" for i in items)
