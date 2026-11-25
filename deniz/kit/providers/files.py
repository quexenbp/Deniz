"""Common sensitive-path probing."""

from __future__ import annotations

from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo

PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.git/HEAD",
    "/.env",
    "/.svn/entries",
    "/.DS_Store",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/dump.sql",
    "/composer.json",
    "/package.json",
    "/swagger.json",
    "/openapi.json",
    "/api/swagger.json",
    "/server-status",
    "/phpinfo.php",
    "/info.php",
    "/admin/",
    "/login/",
    "/.well-known/openid-configuration",
    "/crossdomain.xml",
    "/favicon.ico",
)
INTERESTING = {200, 206, 301, 302, 401, 403}


class Files(Provider):
    info = ProviderInfo(
        name="files",
        title="Common path probe",
        capabilities=frozenset({"surface"}),
        auth="none",
        cost="free",
        rate=8.0,
        burst=4,
        max_bytes=300_000,
        budget=2_000_000,
        notes="GET with small wordlist; status 200/30x/401/403 only.",
    )
    cache_ttl = 3600.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        host = target.value
        origin = f"https://{host}"
        out: list[Observation] = []
        for path in PATHS:
            url = f"{origin}{path}"
            try:
                resp = self.client.get(url, rate=self.info.rate, burst=self.info.burst, timeout=12)
            except Exception:
                continue
            if resp.status not in INTERESTING:
                continue
            out.append(
                Observation(
                    type="url",
                    value=url,
                    confidence=0.6,
                    sources=[Source(provider=self.info.name, url=url)],
                    attrs={
                        "kind": "path",
                        "path": path,
                        "status": resp.status,
                        "size": len(resp.content),
                        "content_type": resp.headers.get("content-type", "")[:120],
                    },
                )
            )
        return out
