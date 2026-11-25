"""Extract forms, inputs and query parameters from a page."""

from __future__ import annotations

import html as html_lib
import re

from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo

FORM = re.compile(r"(<form\b[^>]*>)(.*?)</form>", re.I | re.S)
ACTION = re.compile(r'action=["\']([^"\']*)', re.I)
METHOD = re.compile(r'method=["\']([^"\']+)', re.I)
INPUT = re.compile(r'<input\b[^>]*>', re.I)
NAME = re.compile(r'name=["\']([^"\']+)', re.I)
TYPE = re.compile(r'type=["\']([^"\']+)', re.I)
HREF = re.compile(r'href=["\']([^"\']+)', re.I)


class EntryPoints(Provider):
    info = ProviderInfo(
        name="entrypoints",
        title="Forms and query parameters",
        capabilities=frozenset({"surface"}),
        auth="none",
        cost="free",
        rate=6.0,
        burst=3,
        max_bytes=500_000,
        budget=2_000_000,
        notes="Homepage only; no submission.",
    )
    cache_ttl = 1800.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        host = target.value
        try:
            resp = self.client.get(f"https://{host}/", rate=self.info.rate, burst=self.info.burst)
        except Exception:
            return []
        if resp.status != 200:
            return []
        body = resp.text_limited(500_000)
        source = [Source(provider=self.info.name, url=f"https://{host}/")]
        out: list[Observation] = []

        for index, (open_tag, form) in enumerate(FORM.findall(body)[:20]):
            header = open_tag
            action_match = ACTION.search(header)
            action = action_match.group(1) if action_match else "/"
            if not action:
                action = "/"
            if action.startswith(("http://", "https://")):
                action_url = action
            else:
                action_url = f"https://{host}{action if action.startswith('/') else '/' + action}"
            method_match = METHOD.search(header)
            method = method_match.group(1).lower() if method_match else "get"
            inputs = []
            for tag in INPUT.findall(form)[:30]:
                name = NAME.search(tag)
                if name:
                    kind = TYPE.search(tag)
                    inputs.append({"name": clip(name.group(1), 80), "type": kind.group(1) if kind else "text"})
            out.append(
                Observation(
                    type="url",
                    value=action_url,                    confidence=0.7,
                    sources=source,
                    attrs={"kind": "form", "method": method, "inputs": inputs, "index": index},
                )
            )

        params: set[str] = set()
        for href in HREF.findall(body)[:500]:
            if "?" not in href:
                continue
            query = html_lib.unescape(href.split("?", 1)[1])
            for pair in query.split("&"):
                param_name = pair.split("=", 1)[0]
                if param_name and len(param_name) < 60:
                    params.add(param_name)
        if params:
            out.append(
                Observation(
                    type="note",
                    value="params: " + ", ".join(sorted(params)[:30]),
                    confidence=0.6,
                    sources=source,
                    attrs={"record": "PARAMS", "params": sorted(params)[:30], "host": host},
                )
            )
        return out
