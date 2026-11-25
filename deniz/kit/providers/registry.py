# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Provider registry with plugin loading.

Plugins come from two places:

* installed packages exposing the ``deniz.providers`` entry point;
* ``*.py`` files in ``$DENIZ_PLUGIN_PATH`` exposing a module-level
  ``PROVIDER`` class.

Plugins run in-process. Treat the directory as trusted code.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from importlib.metadata import entry_points
from pathlib import Path

from .base import CONTRACT_VERSION, Provider, ProviderInfo

BUILTIN = {
    "crtsh": "deniz.kit.providers.crtsh:Crtsh",
    "certspotter": "deniz.kit.providers.certspotter:Certspotter",
    "hackertarget": "deniz.kit.providers.hackertarget:Hackertarget",
    "rapiddns": "deniz.kit.providers.rapiddns:RapidDns",
    "anubis": "deniz.kit.providers.anubis:Anubis",
    "searxng": "deniz.kit.providers.searxng:Searx",
    "typosquat": "deniz.kit.providers.typosquat:Typosquat",
    "nvd": "deniz.kit.providers.nvd:Nvd",
    "username": "deniz.kit.providers.username:Username",
    "hibp": "deniz.kit.providers.hibp:Hibp",
    "buckets": "deniz.kit.providers.buckets:Bucket",
    "emailauth": "deniz.kit.providers.emailauth:EmailAuth",
    "ports": "deniz.kit.providers.ports:Ports",
    "takeover": "deniz.kit.providers.takeover:Takeover",
    "github": "deniz.kit.providers.github:Github",
    "github_leaks": "deniz.kit.providers.github_leaks:GithubLeaks",
    "fingerprint": "deniz.kit.providers.fingerprint:Fingerprint",
    "rdap": "deniz.kit.providers.rdap:Rdap",
    "asn": "deniz.kit.providers.asn:Asn",
    "discovery": "deniz.kit.providers.discovery:Discovery",
    "wikipedia": "deniz.kit.providers.wikipedia:Wikipedia",
    "arxiv": "deniz.kit.providers.arxiv:Arxiv",
    "reddit": "deniz.kit.providers.reddit:Reddit",
    "urlscan": "deniz.kit.providers.urlscan:Urlscan",
    "internetdb": "deniz.kit.providers.internetdb:InternetDb",
    "stackoverflow": "deniz.kit.providers.stackoverflow:StackOverflow",
    "openalex": "deniz.kit.providers.openalex:OpenAlex",
    "kap": "deniz.kit.providers.kap:Kap",
    "uyap": "deniz.kit.providers.uyap:Uyap",
    "photon": "deniz.kit.providers.photon:Photon",
    "suggest": "deniz.kit.providers.suggest:Suggest",
    "dnsbl": "deniz.kit.providers.dnsbl:Dnsbl",
    "ahmia": "deniz.kit.providers.ahmia:Ahmia",
    "openverse": "deniz.kit.providers.openverse:Openverse",
    "tldbrute": "deniz.kit.providers.tldbrute:TldBrute",
    "entrypoints": "deniz.kit.providers.entrypoints:EntryPoints",
    "crawl": "deniz.kit.providers.crawl:Crawl",
    "files": "deniz.kit.providers.files:Files",
    "email": "deniz.kit.providers.email:Email",
    "phone": "deniz.kit.providers.phone:Phone",
    "x": "deniz.kit.providers.xsearch:XSearch",
    "dnsbrute": "deniz.kit.providers.dnsbrute:DnsBrute",
    "pubmed": "deniz.kit.providers.pubmed:PubMed",
    "person": "deniz.kit.providers.person:Person",
    "pastebin": "deniz.kit.providers.pastebin:Pastebin",
    "dictionary": "deniz.kit.providers.dictionary:Dictionary",
    "sepiasearch": "deniz.kit.providers.sepiasearch:SepiaSearch",
    "piratebay": "deniz.kit.providers.piratebay:PirateBay",
    "crtsearch": "deniz.kit.providers.crtsearch:CrtSearch",
    "youtube": "deniz.kit.providers.youtube:YouTube",
    "telegram": "deniz.kit.providers.telegram:Telegram",
    "wikileaks": "deniz.kit.providers.wikileaks:WikiLeaks",
    "sentiment": "deniz.kit.providers.sentiment:Sentiment",
    "spotify": "deniz.kit.providers.spotify:Spotify",
    "hackernews": "deniz.kit.providers.hackernews:HackerNews",
    "lemmy": "deniz.kit.providers.lemmy:Lemmy",
    "mastodon": "deniz.kit.providers.mastodon:Mastodon",
    "cluster": "deniz.kit.providers.cluster:Cluster",
    "topicmodeling": "deniz.kit.providers.topicmodeling:TopicModeling",
    "darkweb": "deniz.kit.providers.darkweb:DarkWeb",
    "goodreads": "deniz.kit.providers.goodreads:Goodreads",
    "social": "deniz.kit.providers.social:Social",
    "gitlab": "deniz.kit.providers.gitlab:Gitlab",
    "axfr": "deniz.kit.providers.axfr:Axfr",
    "wayback": "deniz.kit.providers.wayback:Wayback",
    "dns": "deniz.kit.providers.dns_resolve:DnsResolve",
    "http": "deniz.kit.providers.http_probe:HttpProbe",
}

GROUP = "deniz.providers"


@dataclass(frozen=True)
class PluginError:
    source: str
    error: str


class Registry:
    def __init__(self, load_plugins: bool = True) -> None:
        self._builtin = dict(BUILTIN)
        self._plugins: dict[str, type[Provider]] = {}
        self.errors: list[PluginError] = []
        if load_plugins:
            self._load_entry_points()
            self._load_directory()

    def _validate(self, name: str, cls: object, source: str) -> None:
        if not isinstance(cls, type) or not issubclass(cls, Provider):
            self.errors.append(PluginError(source, "PROVIDER/entry point is not a Provider subclass"))
            return
        if cls.info.name != name:
            self.errors.append(PluginError(source, f"info.name '{cls.info.name}' != '{name}'"))
            return
        declared = getattr(cls, "API_VERSION", CONTRACT_VERSION)
        if declared != CONTRACT_VERSION:
            self.errors.append(PluginError(source, f"provider API {declared} != core {CONTRACT_VERSION}"))
            return
        if name in self._builtin:
            self.errors.append(PluginError(source, f"shadows builtin provider '{name}'"))
            return
        self._plugins[name] = cls

    def _load_entry_points(self) -> None:
        for ep in entry_points(group=GROUP):
            try:
                self._validate(ep.name, ep.load(), f"entry:{ep.value}")
            except Exception as exc:
                self.errors.append(PluginError(f"entry:{ep.name}", str(exc)))

    def _load_directory(self) -> None:
        raw = os.environ.get("DENIZ_PLUGIN_PATH")
        if not raw:
            return
        for path in sorted(Path(raw).expanduser().glob("*.py")):
            name = f"deniz_plugin_{path.stem}"
            try:
                spec = importlib.util.spec_from_file_location(name, path)
                if spec is None or spec.loader is None:
                    raise ImportError("cannot build module spec")
                module = importlib.util.module_from_spec(spec)
                sys.modules[name] = module
                spec.loader.exec_module(module)
                cls = getattr(module, "PROVIDER", None)
                if cls is None:
                    raise AttributeError("no PROVIDER attribute")
                self._validate(getattr(cls.info, "name", path.stem), cls, str(path))
            except Exception as exc:
                self.errors.append(PluginError(str(path), str(exc)))

    def names(self) -> list[str]:
        return sorted([*self._builtin, *self._plugins])

    def get(self, name: str) -> type[Provider]:
        if name in self._plugins:
            return self._plugins[name]
        if name not in self._builtin:
            raise KeyError(f"unknown provider: {name}")
        module_name, _, attr = self._builtin[name].partition(":")
        module = importlib.import_module(module_name)
        return getattr(module, attr)

    def infos(self) -> Iterable[ProviderInfo]:
        for name in self.names():
            yield self.get(name).info

    def select(self, capabilities: Iterable[str]) -> list[type[Provider]]:
        wanted = set(capabilities)
        return [self.get(n) for n in self.names() if wanted.issubset(self.get(n).info.capabilities)]

    def is_plugin(self, name: str) -> bool:
        return name in self._plugins

    def plugin_dir(self) -> Path:
        return Path(os.environ.get("DENIZ_PLUGIN_PATH", "~/.deniz/plugins")).expanduser()

