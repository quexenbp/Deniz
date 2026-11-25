# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Headless Chromium session for JS-rendered sources.

Playwright is an optional extra (``deniz[browser]``). Import stays lazy so
the core install keeps working without it; a missing browser raises
``DependencyMissing`` with the install commands instead of a traceback.
"""

from __future__ import annotations

import contextlib
import html as html_lib
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .errors import DependencyMissing

ANCHOR = re.compile(r'<a\b[^>]*\bhref=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.I | re.S)
TAG = re.compile(r"<[^>]+>")
SPACE = re.compile(r"\s+")

HINT = (
    "browser provider needs Playwright: pip install 'deniz[browser]' "
    "&& python -m playwright install chromium"
)
STATE_ENV = "DENIZ_BROWSER_STATE"

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)


def _require_playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise DependencyMissing(HINT, provider="social") from exc
    return sync_playwright


@dataclass(frozen=True)
class Anchor:
    url: str
    text: str


def extract_anchors(body: str, base: str) -> list[Anchor]:
    """Parse ``<a href>`` pairs without a full HTML parser."""
    out: list[Anchor] = []
    for raw, inner in ANCHOR.findall(body):
        href = html_lib.unescape(raw).strip()
        if not href or href.startswith(("#", "javascript:", "data:", "mailto:", "tel:")):
            continue
        if href.startswith("/"):
            parts = urlsplit(base)
            href = f"{parts.scheme}://{parts.netloc}{href}"
        if not href.startswith("http"):
            continue
        text = SPACE.sub(" ", TAG.sub(" ", inner)).strip()
        out.append(Anchor(href, text))
    return out


class BrowserSession:
    """One Chromium instance shared by every URL of a run."""

    def __init__(self, *, timeout: float = 25.0, settle_ms: int = 2200, max_bytes: int = 1_500_000) -> None:
        self.timeout = timeout
        self.settle_ms = settle_ms
        self.max_bytes = max_bytes
        self.pages_fetched = 0
        self.state_path = os.environ.get(STATE_ENV) or ""
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None

    def __enter__(self) -> BrowserSession:
        factory = _require_playwright()
        try:
            self._playwright = factory().start()
            self._browser = self._playwright.chromium.launch(headless=True)
        except Exception as exc:  # missing chromium, sandbox problems
            self.close()
            raise DependencyMissing(f"cannot launch Chromium: {exc}. {HINT}") from exc
        self._context = self._browser.new_context(
            user_agent=DEFAULT_UA,
            locale="en-US",
            viewport={"width": 1366, "height": 900},
            java_script_enabled=True,
            ignore_https_errors=os.environ.get("DENIZ_BROWSER_STRICT_TLS") != "1",
            storage_state=self.state_path if self.state_path and Path(self.state_path).exists() else None,
        )
        self._context.set_default_timeout(int(self.timeout * 1000))
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def html(self, url: str) -> tuple[str, str]:
        """Navigate, let the SPA settle, return ``(final_url, html)``."""
        if self._context is None:
            raise RuntimeError("BrowserSession used outside its context manager")
        page = self._context.new_page()
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=int(self.timeout * 1000))
            page.wait_for_timeout(self.settle_ms)
            self.pages_fetched += 1
            return page.url, page.content()[: self.max_bytes]
        finally:
            page.close()

    def texts(self, urls: Iterable[str]) -> list[tuple[str, str]]:
        return [self.html(url) for url in urls]

    def close(self) -> None:
        for closer in (
            getattr(self._context, "close", None),
            getattr(self._browser, "close", None),
            getattr(self._playwright, "stop", None),
        ):
            if closer is not None:
                with contextlib.suppress(Exception):
                    closer()
        self._context = self._browser = self._playwright = None
