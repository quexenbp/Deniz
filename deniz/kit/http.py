# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""HTTP client with retries, per-host rate limiting and HTTP cache."""

from __future__ import annotations

import json as jsonlib
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .cache import Cache, cache_key
from .errors import Blocked, BudgetExceeded, CacheMiss, NetworkError, RateLimited, TimeoutError_
from .ratelimit import Limiter

RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}
DEFAULT_UA = "Deniz/0.1 (+https://github.com/quexenbp/Deniz)"


@dataclass
class HttpStats:
    requests: int = 0
    cache_hits: int = 0
    retries: int = 0


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    content: bytes
    url: str
    from_cache: bool = False
    elapsed_ms: float = 0.0
    sha256: str | None = None

    @property
    def text(self) -> str:
        return self.text_limited(None)

    def text_limited(self, limit: int | None = 300_000) -> str:
        content = self.content if limit is None else self.content[:limit]
        encoding = "utf-8"
        content_type = self.headers.get("content-type", "")
        if "charset=" in content_type:
            encoding = content_type.split("charset=", 1)[1].split(";")[0].strip() or "utf-8"
        try:
            return content.decode(encoding, "replace")
        except LookupError:
            return content.decode("utf-8", "replace")

    def json(self) -> Any:
        import json

        return json.loads(self.text)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


@dataclass
class HttpConfig:
    timeout: float = 20.0
    retries: int = 2
    backoff: float = 0.6
    max_redirects: int = 5
    user_agent: str = DEFAULT_UA
    verify: bool = True
    offline: bool = False
    proxy: str | None = None
    max_bytes: int | None = None


class HttpClient:
    def __init__(
        self,
        cache: Cache,
        limiter: Limiter,
        config: HttpConfig | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.cache = cache
        self.limiter = limiter
        self.config = config or HttpConfig()
        self.stats = HttpStats()
        proxy = self.config.proxy or os.environ.get("DENIZ_PROXY") or None
        self._client = httpx.Client(
            timeout=httpx.Timeout(self.config.timeout),
            follow_redirects=True,
            max_redirects=self.config.max_redirects,
            verify=self.config.verify,
            transport=transport,
            proxy=proxy if transport is None else None,
            headers={"user-agent": self.config.user_agent},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        provider: str = "",
        rate: float = 2.0,
        burst: int = 2,
        cache_ttl: float = 900.0,
        retries: int | None = None,
        timeout: float | None = None,
        max_bytes: int | None = None,
    ) -> Response:
        return self.request(
            "GET",
            url,
            params=params,
            headers=headers,
            provider=provider,
            rate=rate,
            burst=burst,
            cache_ttl=cache_ttl,
            retries=retries,
            timeout=timeout,
            max_bytes=max_bytes,
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        provider: str = "",
        rate: float = 2.0,
        burst: int = 2,
        cache_ttl: float = 0.0,
        retries: int | None = None,
        content: bytes | None = None,
        timeout: float | None = None,
        max_bytes: int | None = None,
    ) -> Response:
        params_str = {str(k): str(v) for k, v in (params or {}).items()}
        limit = max_bytes if max_bytes is not None else self.config.max_bytes
        key_url = f"{url}#mb={limit}" if limit else url
        key = cache_key(method, key_url, params_str, content)
        if method.upper() == "GET" and cache_ttl > 0:
            cached = self.cache.get(key)
            if cached is not None:
                self.stats.cache_hits += 1
                return Response(
                    status=cached.status,
                    headers=cached.headers,
                    content=cached.body,
                    url=url,
                    from_cache=True,
                    sha256=cached.sha256,
                )
        if self.config.offline:
            raise CacheMiss(f"offline and not cached: {method} {url}")

        host = httpx.URL(url).host or ""
        self.limiter.bucket(host, rate, burst).acquire()
        attempts = self.config.retries if retries is None else retries
        last_exc: Exception | None = None

        for attempt in range(attempts + 1):
            started = time.perf_counter()
            self.stats.requests += 1
            retry_after: str | None = None
            try:
                status, resp_headers, body, final_url = self._send(
                    method, url, params_str, headers, content, timeout, limit
                )
            except httpx.TimeoutException as exc:
                last_exc = TimeoutError_(str(exc), provider=provider)
            except httpx.HTTPError as exc:
                last_exc = NetworkError(str(exc), provider=provider)
            else:
                elapsed = (time.perf_counter() - started) * 1000
                retry_after = resp_headers.get("retry-after")
                if status in RETRY_STATUS and attempt < attempts:
                    last_exc = RateLimited(f"{status} from {url}", provider=provider)
                elif status == 429:
                    raise RateLimited(f"429 from {url}", provider=provider)
                elif status in (401, 407):
                    raise Blocked(f"{status} from {url}", provider=provider)
                else:
                    if method.upper() == "GET" and cache_ttl > 0:
                        if status == 200:
                            self.cache.set(key, status, resp_headers, body, cache_ttl)
                        elif status >= 500:
                            # short negative cache so a dead source does not cost retries on every run
                            self.cache.set(key, status, resp_headers, body, min(60.0, cache_ttl))
                    return Response(
                        status=status,
                        headers=resp_headers,
                        content=body,
                        url=final_url,
                        elapsed_ms=elapsed,
                    )
                if attempt >= attempts:
                    break
            delay = self.config.backoff * (2**attempt) + random.uniform(0, 0.2)
            if retry_after and retry_after.isdigit():
                delay = max(delay, float(retry_after))
            self.stats.retries += 1
            time.sleep(delay)

        assert last_exc is not None
        raise last_exc

    def get_json(self, url: str, **kwargs: Any) -> Any:
        return self.get(url, **kwargs).json()

    def _send(
        self,
        method: str,
        url: str,
        params: dict[str, str],
        headers: dict[str, str] | None,
        content: bytes | None,
        timeout: float | None,
        max_bytes: int | None,
    ) -> tuple[int, dict[str, str], bytes, str]:
        timeout_obj = httpx.Timeout(timeout) if timeout else None
        if not max_bytes:
            raw = self._client.request(
                method,
                url,
                params=params or None,
                headers=headers,
                content=content,
                timeout=timeout_obj,
            )
            resp_headers = {k.lower(): v for k, v in raw.headers.items()}
            return raw.status_code, resp_headers, raw.content, str(raw.url)
        with self._client.stream(
            method,
            url,
            params=params or None,
            headers=headers,
            content=content,
            timeout=timeout_obj,
        ) as raw:
            chunks: list[bytes] = []
            total = 0
            for chunk in raw.iter_bytes():
                chunks.append(chunk)
                total += len(chunk)
                if total >= max_bytes:
                    break
            resp_headers = {k.lower(): v for k, v in raw.headers.items()}
            return raw.status_code, resp_headers, b"".join(chunks)[:max_bytes], str(raw.url)


@dataclass
class ProviderHttp:
    """Per-provider view so adapters cannot forget their budget."""

    client: HttpClient
    provider: str
    rate: float = 2.0
    burst: int = 2
    budget: int | None = None
    defaults: dict[str, Any] = field(default_factory=dict)
    used_bytes: int = 0

    def get(self, url: str, **kwargs: Any) -> Response:
        return self._call("GET", url, **kwargs)

    def post(self, url: str, *, json: Any = None, **kwargs: Any) -> Response:
        if json is not None:
            kwargs["content"] = jsonlib.dumps(json, ensure_ascii=False).encode("utf-8")
            headers = dict(kwargs.pop("headers", {}) or {})
            headers.setdefault("content-type", "application/json")
            kwargs["headers"] = headers
        return self._call("POST", url, **kwargs)

    def _call(self, method: str, url: str, **kwargs: Any) -> Response:
        if self.budget is not None and self.used_bytes >= self.budget:
            raise BudgetExceeded(
                f"{self.provider} byte budget exhausted ({self.used_bytes}/{self.budget})",
                provider=self.provider,
            )
        kwargs.setdefault("provider", self.provider)
        kwargs.setdefault("rate", self.rate)
        kwargs.setdefault("burst", self.burst)
        if self.defaults.get("max_bytes") and "max_bytes" not in kwargs:
            kwargs["max_bytes"] = self.defaults["max_bytes"]
        kwargs.update({k: v for k, v in self.defaults.items() if k != "max_bytes"})
        response = self.client.request(method, url, **kwargs)
        self.used_bytes += len(response.content)
        return response

