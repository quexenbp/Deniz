# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Site-scoped social search through headless Chromium.

The legacy site modules (Instagram, TikTok, LinkedIn, Facebook, Quora, Trello,
Discord) all did ``site:<domain> <query>`` against a search engine. Anonymous
HTML now 403s on them, so this provider renders each site's own search page
once and keeps only links that match that site's public object patterns.

Optional extra: ``pip install 'deniz[browser]'`` then
``python -m playwright install chromium``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote_plus, urlencode, urlsplit, urlunsplit

from ..browser import BrowserSession, extract_anchors
from ..errors import Blocked, DependencyMissing, ParseChanged
from ..models import Observation, Source, Target
from ..util import clip, normalize_hostname
from .base import Context, Provider, ProviderInfo

TRACKING = ("utm_", "fbclid", "gclid", "ref_src", "ref_url", "lang")


@dataclass(frozen=True)
class Site:
    name: str
    search: str
    hosts: tuple[str, ...]
    kinds: tuple[tuple[str, str], ...]


SITES: dict[str, Site] = {
    "instagram": Site(
        name="instagram",
        search="https://www.instagram.com/explore/search/keyword/?q={q}",
        hosts=("instagram.com",),
        kinds=(
            ("hashtag", r"^/explore/tags/([^/?#]+)"),
            ("post", r"^/(?:p|reel|tv)/([^/?#]+)"),
            ("profile", r"^/([A-Za-z0-9_.]{2,30})/?$"),
        ),
    ),
    "tiktok": Site(
        name="tiktok",
        search="https://www.tiktok.com/search?q={q}",
        hosts=("tiktok.com",),
        kinds=(
            ("video", r"^/@([^/?#]+)/video/(\d+)"),
            ("tag", r"^/tag/([^/?#]+)"),
            ("music", r"^/music/([^/?#]+)"),
            ("profile", r"^/@([^/?#]+)/?$"),
        ),
    ),
    "linkedin": Site(
        name="linkedin",
        search="https://www.linkedin.com/search/results/all/?keywords={q}",
        hosts=("linkedin.com",),
        kinds=(
            ("person", r"^/in/([^/?#]+)"),
            ("company", r"^/company/([^/?#]+)"),
            ("school", r"^/school/([^/?#]+)"),
            ("post", r"^/(?:posts|pulse)/([^/?#]+)"),
        ),
    ),
    "facebook": Site(
        name="facebook",
        search="https://www.facebook.com/search/top?q={q}",
        hosts=("facebook.com",),
        kinds=(
            ("profile", r"^/profile\.php$"),
            ("post", r"^/[^/?#]+/posts/([^/?#]+)"),
            ("group", r"^/groups/([^/?#]+)"),
            ("event", r"^/events/([^/?#]+)"),
            ("video", r"^/(?:watch/?|reel/)([^/?#]*)"),
        ),
    ),
    "quora": Site(
        name="quora",
        search="https://www.quora.com/search?q={q}",
        hosts=("quora.com",),
        kinds=(
            ("profile", r"^/profile/([^/?#]+)"),
            ("question", r"^/q/([^/?#]+)"),
            ("topic", r"^/topic/([^/?#]+)"),
        ),
    ),
    "trello": Site(
        name="trello",
        search="https://trello.com/search?q={q}",
        hosts=("trello.com",),
        kinds=(
            ("board", r"^/b/([^/?#]+)"),
            ("card", r"^/c/([^/?#]+)"),
            ("member", r"^/u/([^/?#]+)"),
        ),
    ),
    "discord": Site(
        name="discord",
        search="https://discord.com/servers?query={q}",
        hosts=("discord.com", "discord.gg"),
        kinds=(
            ("server", r"^/servers/(?:[^/?#]*-)?(\d+)$"),
            ("invite", r"^/invite/([^/?#]+)"),
        ),
    ),
}

DENY_PROFILE = {
    "explore",
    "accounts",
    "direct",
    "about",
    "developer",
    "developers",
    "legal",
    "web",
    "reels",
    "stories",
    "p",
    "reel",
    "tv",
    "search",
    "login",
    "signup",
    "help",
    "policies",
    "popular",
    "blog",
}

DENY_HOSTS = {"about.instagram.com", "help.instagram.com", "business.instagram.com"}


def normalize_url(url: str) -> str:
    parts = urlsplit(url)
    query = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if not key.startswith(TRACKING) and key in {"id", "v", "story_fbid", "fbid"}
    ]
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme, parts.netloc.lower().removeprefix("www."), path, urlencode(query), ""))


def classify(site: Site, url: str) -> str | None:
    parts = urlsplit(url)
    host = normalize_hostname(parts.hostname or "")
    if not host or host in DENY_HOSTS or not any(host == h or host.endswith("." + h) for h in site.hosts):
        return None
    path = parts.path or "/"
    if site.name == "facebook" and path.startswith("/profile.php"):
        return "profile" if parts.query else None
    if site.name == "discord" and host == "discord.gg":
        return "invite" if re.match(r"^/[A-Za-z0-9-]+/?$", path) else None
    for kind, pattern in site.kinds:
        match = re.match(pattern, path)
        if not match:
            continue
        if kind == "profile" and match.group(1).lower() in DENY_PROFILE:
            return None
        return kind
    return None


class Social(Provider):
    info = ProviderInfo(
        name="social",
        title="Social site search (headless Chromium)",
        capabilities=frozenset({"social"}),
        auth="none",
        cost="free",
        rate=0.5,
        burst=1,
        tos_url="https://www.instagram.com/legal/terms/",
        notes="Renders one search page per site; needs the [browser] extra and Chromium.",    )
    cache_ttl = 1800.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "keyword":
            raise ParseChanged("social search expects a keyword target")
        wanted = ctx.options.get("sites") or list(SITES)
        sites = [SITES[name] for name in wanted if name in SITES]
        if not sites:
            raise ParseChanged(f"unknown social sites: {', '.join(wanted)}")
        per_site = int(ctx.options.get("per_site") or 10)
        query = quote_plus(target.value)

        found: dict[str, Observation] = {}
        empty: list[str] = []
        try:
            with BrowserSession() as browser:
                for site in sites:
                    try:
                        final_url, body = browser.html(site.search.format(q=query))
                    except DependencyMissing:
                        raise
                    except Exception:
                        empty.append(site.name)
                        continue
                    source = Source(provider=self.info.name, url=final_url)
                    hits = 0
                    for anchor in extract_anchors(body, final_url):
                        kind = classify(site, anchor.url)
                        if kind is None:
                            continue
                        url = normalize_url(anchor.url)
                        if url in found:
                            continue
                        found[url] = Observation(
                            type="url",
                            value=url,
                            confidence=0.45,
                            sources=[source],
                            attrs={"site": site.name, "kind": kind, "title": clip(anchor.text, 120)},
                        )
                        hits += 1
                        if hits >= per_site or len(found) >= ctx.max_items:
                            break
                    if hits == 0:
                        empty.append(site.name)
                    if len(found) >= ctx.max_items:
                        break
        except DependencyMissing:
            raise
        if not found and len(empty) == len(sites):
            raise Blocked("every social site returned no parseable results (login wall or CAPTCHA)")
        return list(found.values())
