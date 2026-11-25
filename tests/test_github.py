from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.errors import AuthRequired
from deniz.kit.http import HttpClient, HttpConfig
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.github import Github
from deniz.kit.providers.github_leaks import GithubLeaks
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def make(tmp_path: Path, handler, key: str | None = "k"):
    path = tmp_path / "providers.toml"
    if key:
        path.write_text(f'[github]\ntoken = "{key}"\n', encoding="utf-8")
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), HttpConfig(), transport=httpx.MockTransport(handler))
    return client, Context(http=client, scope=Scope(), auth=AuthStore(path))


def test_repos_parse(tmp_path: Path) -> None:
    payload = [{"html_url": "https://github.com/acme/app", "full_name": "acme/app", "language": "Go", "stargazers_count": 5}]
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    client, ctx = make(tmp_path, handler)
    items = Github(client).run(Target(type="org", value="acme"), ctx)
    assert items[0].value == "https://github.com/acme/app"
    assert items[0].attrs["language"] == "Go"
    assert seen["auth"] == "Bearer k"
    assert "/orgs/acme/repos" in seen["url"]


def test_org_requires_token(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    client, ctx = make(tmp_path, handler, key=None)
    with pytest.raises(AuthRequired):
        Github(client).run(Target(type="org", value="acme"), ctx)


def test_code_search(tmp_path: Path) -> None:
    payload = {
        "items": [
            {
                "html_url": "https://github.com/acme/app/blob/main/.env",
                "path": ".env",
                "repository": {"full_name": "acme/app"},
                "text_matches": [{"matches": [{"fragment": "SECRET=abc"}]}],
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(payload), headers={"content-type": "application/json"})

    client, ctx = make(tmp_path, handler)
    items = GithubLeaks(client).run(Target(type="keyword", value="SECRET"), ctx)
    assert items[0].attrs["fragments"] == ["SECRET=abc"]
