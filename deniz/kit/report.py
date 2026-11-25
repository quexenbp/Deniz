# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Report renderers: self-contained HTML and STIX 2.1.

HTML is static and escaped; no template engine, no JS. STIX uses deterministic
UUIDv5 ids so the same observation always maps to the same SCO.
"""

from __future__ import annotations

import html
import ipaddress
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from .models import Observation, Result
from .privacy import redact_result

NS = uuid.UUID("6f6d6172-7961-6d00-8000-000000000001")  # deniz namespace
IDENTITY = "identity--" + str(uuid.uuid5(NS, "deniz"))

LABELS = {
    "en": {
        "report": "Deniz report",
        "module": "module",
        "run": "run",
        "observed": "observed",
        "providers": "providers",
        "requests": "requests",
        "cache_hits": "cache hits",
        "errors": "Errors",
        "kind": "kind",
        "provider": "provider",
        "message": "message",
        "observations": "Observations",
        "type": "type",
        "value": "value",
        "confidence": "confidence",
        "sources": "sources",
        "attrs": "attrs",
        "none": "none",
        "case": "case",
        "updated": "updated",
        "scope": "scope",
        "tags": "tags",
        "findings": "Findings",
        "severity": "severity",
        "finding": "finding",
        "note": "note",
        "acked": "acked",
        "timeline": "Timeline",
        "runs": "Runs",
        "target": "target",
        "counts": "counts",
        "yes": "yes",
        "no": "no",
        "footer": "Generated {at} by Deniz. Passive sources only; verify before action.",
    },
    "tr": {
        "report": "Deniz raporu",
        "module": "modül",
        "run": "çalıştırma",
        "observed": "gözlem",
        "providers": "sağlayıcılar",
        "requests": "istek",
        "cache_hits": "önbellek isabeti",
        "errors": "Hatalar",
        "kind": "tür",
        "provider": "sağlayıcı",
        "message": "mesaj",
        "observations": "Gözlemler",
        "type": "tür",
        "value": "değer",
        "confidence": "güven",
        "sources": "kaynaklar",
        "attrs": "nitelikler",
        "none": "yok",
        "case": "vaka",
        "updated": "güncellendi",
        "scope": "kapsam",
        "tags": "etiketler",
        "findings": "Bulgular",
        "severity": "önem",
        "finding": "bulgu",
        "note": "not",
        "acked": "onaylandı",
        "timeline": "Zaman çizelgesi",
        "runs": "Çalıştırmalar",
        "target": "hedef",
        "counts": "sayımlar",
        "yes": "evet",
        "no": "hayır",
        "footer": "{at} tarihinde Deniz ile üretildi. Yalnızca pasif kaynaklar; işlem öncesi doğrulayın.",
    },
}


def _labels(lang: str) -> dict[str, str]:
    return LABELS.get(lang, LABELS["en"])


def _stable(kind: str, value: str) -> str:
    return f"{kind}--{uuid.uuid5(NS, kind + '|' + value.lower())}"


def _stix_object(item: Observation, created: str) -> dict:
    base = {"spec_version": "2.1", "created": created, "modified": created, "confidence": int(item.confidence * 100)}
    if item.type == "hostname":
        return {**base, "type": "domain-name", "id": _stable("domain-name", item.value), "value": item.value}
    if item.type == "ip":
        kind = "ipv4-addr" if isinstance(ipaddress.ip_address(item.value), ipaddress.IPv4Address) else "ipv6-addr"
        return {**base, "type": kind, "id": _stable(kind, item.value), "value": item.value}
    if item.type == "url":
        return {**base, "type": "url", "id": _stable("url", item.value), "value": item.value}
    if item.type == "email":
        return {**base, "type": "email-addr", "id": _stable("email-addr", item.value), "value": item.value}
    if item.type == "username":
        return {**base, "type": "user-account", "id": _stable("user-account", item.value), "account_login": item.value}
    if item.type == "cve":
        return {**base, "type": "vulnerability", "id": _stable("vulnerability", item.value), "name": item.value}
    if item.type == "certificate":
        return {
            **base,
            "type": "x509-certificate",
            "id": _stable("x509-certificate", item.value),
            "hashes": {"SHA-256": item.value} if len(item.value) == 64 else {},
        }
    return {
        **base,
        "type": "x-deniz-observation",
        "id": _stable("x-deniz-observation", item.type + "|" + item.value),
        "x_type_name": item.type,
        "x_value": item.value,
        "x_attrs": item.attrs,
    }


def _target_object(result: Result, created: str) -> dict:
    target = result.target
    if target.type == "hostname":
        target = target.model_copy(update={"type": "domain"})
    kind = {
        "domain": "domain-name",
        "ip": "ipv4-addr",
        "url": "url",
        "email": "email-addr",
        "username": "user-account",
        "org": "identity",
    }.get(target.type, "x-deniz-observation")
    if kind == "ip":
        kind = "ipv4-addr" if isinstance(ipaddress.ip_address(target.value), ipaddress.IPv4Address) else "ipv6-addr"
    base = {"type": kind, "spec_version": "2.1", "id": _stable(kind, target.value), "created": created, "modified": created}
    if kind in ("domain-name", "ipv4-addr", "ipv6-addr", "url", "email-addr"):
        return {**base, "value": target.value}
    if kind == "user-account":
        return {**base, "account_login": target.value}
    if kind == "identity":
        return {**base, "name": target.value, "identity_class": "organization"}
    return {**base, "x_type_name": target.type, "x_value": target.value, "x_attrs": {}}


def render_stix(result: Result) -> dict:
    created = result.observed_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
    target_obj = _target_object(result, created)
    target_id = target_obj["id"]
    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": IDENTITY,
            "created": created,
            "modified": created,
            "name": "Deniz",
            "identity_class": "system",
        },
        {
            "type": "x-deniz-run",
            "spec_version": "2.1",
            "id": _stable("x-deniz-run", result.run_id),
            "created": created,
            "modified": created,
            "x_run_id": result.run_id,
            "x_module": result.module,
            "x_target": f"{result.target.type}:{result.target.value}",
            "x_providers": result.stats.providers_used,
        },
        target_obj,
    ]
    seen: set[str] = set()
    for item in result.items:
        obj = _stix_object(item, created)
        if obj["id"] not in seen:
            seen.add(obj["id"])
            objects.append(obj)
        rel_id = _stable("relationship", target_id + "|" + obj["id"])
        if rel_id in seen:
            continue
        seen.add(rel_id)
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": created,
                "modified": created,
                "relationship_type": "related-to",
                "source_ref": target_id,
                "target_ref": obj["id"],
                "description": f"observed by {item.sources[0].provider}",
            }
        )
    return {
        "type": "bundle",
        "id": "bundle--" + str(uuid.uuid5(NS, result.run_id)),
        "objects": objects,
    }


def _link(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme in ("http", "https"):
        safe = html.escape(url, quote=True)
        return f'<a href="{safe}" rel="noopener noreferrer">{safe}</a>'
    return html.escape(url)


def render_html(result: Result, lang: str = "en") -> str:
    labels = _labels(lang)
    counts = result.summary()
    chips = "".join(f"<span class='chip'>{html.escape(k)}: {v}</span>" for k, v in sorted(counts.items()))
    rows = []
    for item in result.items:
        attrs = html.escape(json.dumps(item.attrs, ensure_ascii=False, indent=2))
        sources = "<br>".join(_link(s.url) for s in item.sources)
        rows.append(
            "<tr>"
            f"<td>{html.escape(item.type)}</td>"
            f"<td><code>{html.escape(item.value)}</code></td>"
            f"<td>{item.confidence:.2f}</td>"
            f"<td>{sources}</td>"
            f"<td><details><summary>{labels['attrs']}</summary><pre>{attrs}</pre></details></td>"
            "</tr>"
        )
    errors = "".join(
        f"<tr><td>{html.escape(e.kind)}</td><td>{html.escape(e.provider or '')}</td><td>{html.escape(e.message)}</td></tr>"
        for e in result.errors
    )
    return f"""<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{labels['report']} — {html.escape(result.target.value)}</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:1100px;padding:0 1rem;color:#111}}
 h1{{font-size:1.4rem;margin:0 0 .5rem}} code{{font-size:.85em}}
 table{{border-collapse:collapse;width:100%;margin:1rem 0}} th,td{{border-bottom:1px solid #ddd;padding:.45rem;text-align:left;vertical-align:top}}
 th{{background:#f6f6f6}} .meta{{color:#555}} .chip{{display:inline-block;background:#eef;padding:.15rem .5rem;border-radius:4px;margin:.15rem;font-size:.8rem}}
 pre{{white-space:pre-wrap;max-height:14rem;overflow:auto;background:#fafafa;padding:.5rem;font-size:.8rem}}
 footer{{margin-top:2rem;color:#666;font-size:.8rem}}
</style>
</head>
<body>
<h1>{labels['report']}: {html.escape(result.target.value)}</h1>
<p class="meta">{labels['module']} {html.escape(result.module)} · {labels['run']} {html.escape(result.run_id)} · {labels['observed']} {result.observed_at.isoformat()}</p>
<p>{chips}</p>
<p class="meta">{labels['providers']}: {html.escape(', '.join(result.stats.providers_used) or '-')} · {labels['requests']}: {result.stats.requests} · {labels['cache_hits']}: {result.stats.cache_hits} · {result.stats.duration_ms} ms</p>
<h2>{labels['errors']} ({len(result.errors)})</h2>
<table><thead><tr><th>{labels['kind']}</th><th>{labels['provider']}</th><th>{labels['message']}</th></tr></thead><tbody>{errors or f'<tr><td colspan="3">{labels["none"]}</td></tr>'}</tbody></table>
<h2>{labels['observations']} ({len(result.items)})</h2>
<table><thead><tr><th>{labels['type']}</th><th>{labels['value']}</th><th>{labels['confidence']}</th><th>{labels['sources']}</th><th>{labels['attrs']}</th></tr></thead><tbody>{''.join(rows) or f'<tr><td colspan="5">{labels["none"]}</td></tr>'}</tbody></table>
<footer>{labels['footer'].format(at=datetime.now(UTC).isoformat())}</footer>
</body>
</html>
"""


def render_pdf(result: Result, path: Path, lang: str = "en") -> Path:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - optional extra
        raise RuntimeError("PDF needs: pip install 'deniz[browser]' && playwright install chromium") from exc

    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as handle:
        handle.write(render_html(result, lang))
        html_path = Path(handle.name)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(html_path.as_uri())
            page.pdf(path=str(path), format="A4", print_background=True, margin={"top": "14mm", "bottom": "14mm", "left": "12mm", "right": "12mm"})
            browser.close()
    finally:
        html_path.unlink(missing_ok=True)
    return path


def write_report(result: Result, fmt: str, out_dir: Path, redact: bool = False, lang: str = "en") -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    if redact:
        result = redact_result(result)
    if fmt == "html":
        path = out_dir / "report.html"
        path.write_text(render_html(result, lang), encoding="utf-8")
    elif fmt == "pdf":
        path = out_dir / "report.pdf"
        render_pdf(result, path, lang)
    elif fmt == "stix":
        path = out_dir / "report.stix.json"
        path.write_text(json.dumps(render_stix(result), indent=2, ensure_ascii=False), encoding="utf-8")
    elif fmt == "jsonl":
        path = out_dir / "report.items.jsonl"
        with path.open("w", encoding="utf-8") as handle:
            for item in result.items:
                handle.write(json.dumps(item.model_dump(mode="json"), ensure_ascii=False) + "\n")
    else:
        raise ValueError(f"unknown format: {fmt}")
    return path

