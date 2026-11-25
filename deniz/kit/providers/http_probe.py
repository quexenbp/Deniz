# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""HTTP(S) liveness probe with TLS metadata."""

from __future__ import annotations

import contextlib
import socket
import ssl
import time
from typing import Any, cast

import httpx

from ..errors import DenizError, TimeoutError_
from ..http import Response
from ..models import Observation, Source, Target
from ..util import clip, extract_title
from .base import Context, Provider, ProviderInfo


class HttpProbe(Provider):
    info = ProviderInfo(
        name="http",
        title="HTTP(S) probe",
        capabilities=frozenset({"http"}),
        auth="none",
        cost="free",
        rate=10.0,
        burst=5,
        notes="One GET per host, HTTPS first, HTTP fallback.",
    )
    cache_ttl = 600.0

    def __init__(self, http) -> None:
        super().__init__(http)
        # Same transport so tests stay offline; TLS verification off only here.
        self._insecure = httpx.Client(
            timeout=httpx.Timeout(15),
            follow_redirects=True,
            verify=False,
            transport=http._client._transport,
            headers={"user-agent": http.config.user_agent},
        )

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        host = target.value
        if not ctx.allow_out_of_scope and not ctx.scope.allows(host):
            return []
        started = time.perf_counter()
        response: Response | None = None
        scheme = "https"
        tls_error = None

        with contextlib.suppress(httpx.HTTPError, DenizError):
            response = self.client.get(
                f"https://{host}/",
                rate=self.info.rate,
                burst=self.info.burst,
                cache_ttl=self.cache_ttl,
                max_bytes=600_000,
            )

        if response is None:
            # Certificate failures and TLS handshake problems: retry unverified.
            try:
                raw = self._insecure.get(f"https://{host}/")
                response = Response(
                    status=raw.status_code,
                    headers={k.lower(): v for k, v in raw.headers.items()},
                    content=raw.content,
                    url=str(raw.url),
                )
                tls_error = "unverified"
            except httpx.HTTPError:
                pass

        if response is None:
            try:
                scheme = "http"
                response = self.client.get(
                    f"http://{host}/",
                    rate=self.info.rate,
                    burst=self.info.burst,
                    cache_ttl=self.cache_ttl,
                    max_bytes=600_000,
                )
            except (httpx.HTTPError, DenizError) as exc:
                raise TimeoutError_(f"no HTTP(S) answer for {host}: {exc}", provider=self.info.name) from exc

        body = response.text_limited(300_000)
        elapsed = int((time.perf_counter() - started) * 1000)
        title = extract_title(body)
        source = Source(provider=self.info.name, url=f"{scheme}://{host}/")
        attrs = {
            "host": host,
            "status": response.status,
            "final_url": str(response.url),
            "server": clip(response.headers.get("server", ""), 120),
            "content_type": clip(response.headers.get("content-type", ""), 120),
            "elapsed_ms": elapsed,
            "tls": scheme == "https",
            "tls_error": tls_error,
        }
        cert = self._cert(host) if scheme == "https" else None
        if cert:
            attrs["tls"] = cert

        items = [
            Observation(
                type="url",
                value=f"{scheme}://{host}/",
                confidence=0.95,
                sources=[source],
                attrs=attrs,
            )
        ]
        if title:
            items.append(
                Observation(
                    type="title",
                    value=title,
                    confidence=0.8,
                    sources=[source],
                    attrs={"url": f"{scheme}://{host}/"},
                )
            )
        return items

    @staticmethod
    def _cert(host: str) -> dict[str, str] | None:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, 443), timeout=5) as sock, context.wrap_socket(sock, server_hostname=host) as tls:
                cert = cast(dict[str, Any], tls.getpeercert() or {})
        except OSError:
            return None
        if not cert:
            return None
        subject = {k: v for pair in cast(tuple, cert.get("subject", ())) for k, v in pair}
        issuer = {k: v for pair in cast(tuple, cert.get("issuer", ())) for k, v in pair}
        return {
            "subject_cn": clip(str(subject.get("commonName", "")), 200),
            "issuer_cn": clip(str(issuer.get("commonName", "")), 200),
            "issuer_org": clip(str(issuer.get("organizationName", "")), 200),
            "not_after": clip(str(cert.get("notAfter", "")), 60),
            "san": clip(", ".join(str(x[1]) for x in cast(tuple, cert.get("subjectAltName", ()))), 500),
        }


