from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from deniz.kit.auth import AuthStore
from deniz.kit.browser import extract_anchors
from deniz.kit.cache import Cache
from deniz.kit.errors import DependencyMissing
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers import social as social_mod
from deniz.kit.providers.base import Context
from deniz.kit.providers.social import SITES, Social, classify, normalize_url
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope

IG_HTML = """
<a href="https://www.instagram.com/owasp/">OWASP</a>
<a href="/explore/tags/owasp/?__a=1">#owasp</a>
<a href="https://www.instagram.com/p/ABC123/?utm_source=ig_web">Post</a>
<a href="https://www.instagram.com/explore/">Explore</a>
<a href="https://www.instagram.com/owasp/">OWASP again</a>
<a href="https://www.instagram.com/accounts/login/">Login</a>
"""

TT_HTML = """
<a href="https://www.tiktok.com/@owasp/video/7312345678901234567">Video</a>
<a href="https://www.tiktok.com/@owasp">Profile</a>
<a href="https://www.tiktok.com/tag/owasp">Tag</a>
<a href="https://www.tiktok.com/login">Login</a>
"""


class FakeBrowser:
    def __init__(self, pages: dict[str, str], fail: Exception | None = None) -> None:
        self.pages = pages
        self.fail = fail
        self.urls: list[str] = []

    def __enter__(self) -> FakeBrowser:
        if self.fail:
            raise self.fail
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def html(self, url: str) -> tuple[str, str]:
        self.urls.append(url)
        return url, self.pages[url]


def make(tmp_path: Path):
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    return client, Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))


def test_extract_anchors_resolves_relative() -> None:
    anchors = extract_anchors('<a href="/x?b=1">Hi <b>there</b></a>', "https://a.test/search?q=x")
    assert anchors[0].url == "https://a.test/x?b=1"
    assert anchors[0].text == "Hi there"


def test_classify_filters_site_and_generic_paths() -> None:
    assert classify(SITES["instagram"], "https://www.instagram.com/owasp/") == "profile"
    assert classify(SITES["instagram"], "https://www.instagram.com/p/ABC123/") == "post"
    assert classify(SITES["instagram"], "https://www.instagram.com/explore/") is None
    assert classify(SITES["tiktok"], "https://www.tiktok.com/@owasp/video/123") == "video"
    assert classify(SITES["linkedin"], "https://de.linkedin.com/in/alice") == "person"
    assert classify(SITES["trello"], "https://evil.test/b/1") is None
    assert classify(SITES["facebook"], "https://www.facebook.com/profile.php?id=9") == "profile"
    assert classify(SITES["discord"], "https://discord.com/servers/123") == "server"
    assert classify(SITES["discord"], "https://discord.gg/abc-1") == "invite"


def test_normalize_url_strips_tracking_and_www() -> None:
    assert (
        normalize_url("https://www.instagram.com/p/ABC/?utm_source=x&igsh=1#frag")
        == "https://instagram.com/p/ABC"
    )
    assert normalize_url("https://www.facebook.com/profile.php?id=9&ref=bookmarks") == (
        "https://facebook.com/profile.php?id=9"
    )


def test_provider_keeps_only_site_matches(tmp_path: Path, monkeypatch) -> None:
    pages = {
        "https://www.instagram.com/explore/search/keyword/?q=owasp": IG_HTML,
        "https://www.tiktok.com/search?q=owasp": TT_HTML,
    }
    browser = FakeBrowser(pages)
    monkeypatch.setattr(social_mod, "BrowserSession", lambda: browser)
    client, ctx = make(tmp_path)
    ctx.options = {"sites": ["instagram", "tiktok"], "per_site": 5}
    items = Social(client).run(Target(type="keyword", value="owasp"), ctx)
    values = [i.value for i in items]
    assert "https://instagram.com/owasp" in values
    assert "https://instagram.com/p/ABC123" in values
    assert "https://tiktok.com/@owasp/video/7312345678901234567" in values
    assert "https://instagram.com/explore" not in values
    assert "https://tiktok.com/login" not in values
    assert values.count("https://instagram.com/owasp") == 1
    assert all(i.confidence == 0.45 for i in items)


def test_provider_respects_per_site_cap(tmp_path: Path, monkeypatch) -> None:
    html = "\n".join(f'<a href="https://www.instagram.com/user{i}/">u</a>' for i in range(20))
    url = "https://www.instagram.com/explore/search/keyword/?q=owasp"
    monkeypatch.setattr(social_mod, "BrowserSession", lambda: FakeBrowser({url: html}))
    client, ctx = make(tmp_path)
    ctx.options = {"sites": ["instagram"], "per_site": 3}
    items = Social(client).run(Target(type="keyword", value="owasp"), ctx)
    assert len(items) == 3


def test_provider_unknown_site(tmp_path: Path, monkeypatch) -> None:
    client, ctx = make(tmp_path)
    ctx.options = {"sites": ["myspace"]}
    with pytest.raises(Exception) as info:
        Social(client).run(Target(type="keyword", value="owasp"), ctx)
    assert "unknown social sites" in str(info.value)


def test_provider_reports_missing_browser(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(social_mod, "BrowserSession", lambda: FakeBrowser({}, fail=DependencyMissing("no playwright")))
    client, ctx = make(tmp_path)
    with pytest.raises(DependencyMissing):
        Social(client).run(Target(type="keyword", value="owasp"), ctx)
