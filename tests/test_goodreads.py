from __future__ import annotations

from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.goodreads import Goodreads
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope

HTML = """
<div>
  <a title="Hack the World with OSINT" class="bookTitle" href="/book/show/43561823-hack-the-world?from_search=true">
    <span>Hack the World with OSINT</span>
  </a>
  <a class="authorName" href="/author/show/1"><span>Jane Doe</span></a>
  <span class="minirating">4.2 avg rating — 10 ratings</span>
</div>
<div>
  <a class="bookTitle" href="/book/show/2-other"><span>Other Book</span></a>
</div>
"""


def test_parse(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=HTML, headers={"content-type": "text/html"})

    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(handler))
    ctx = Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))
    items = Goodreads(client).run(Target(type="keyword", value="osint"), ctx)
    assert items[0].value == "https://www.goodreads.com/book/show/43561823-hack-the-world"
    assert items[0].attrs["title"] == "Hack the World with OSINT"
    assert items[0].attrs["author"] == "Jane Doe"
    assert "ratings" in items[0].attrs["rating"]
    assert items[1].value == "https://www.goodreads.com/book/show/2-other"
