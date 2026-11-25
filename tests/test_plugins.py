# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from pathlib import Path

from deniz.kit.providers.registry import Registry

PLUGIN = '''
from deniz.kit.providers.base import Provider, ProviderInfo

class Demo(Provider):
    info = ProviderInfo(name="demo", title="demo", capabilities=frozenset({"demo"}))

    def run(self, target, ctx):
        return []

PROVIDER = Demo
'''

SHADOW = PLUGIN.replace('name="demo"', 'name="crtsh"')
BROKEN = "VALUE = 1\n"
OLD_API = PLUGIN.replace('name="demo"', 'name="oldapi"').replace("class Demo(Provider):", "class Demo(Provider):\n    API_VERSION = 0")


def test_directory_plugin(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "demo.py").write_text(PLUGIN, encoding="utf-8")
    monkeypatch.setenv("DENIZ_PLUGIN_PATH", str(tmp_path))
    registry = Registry()
    assert "demo" in registry.names()
    assert registry.is_plugin("demo")
    assert registry.get("demo").info.name == "demo"
    assert registry.errors == []


def test_broken_and_shadow(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "broken.py").write_text(BROKEN, encoding="utf-8")
    (tmp_path / "shadow.py").write_text(SHADOW, encoding="utf-8")
    (tmp_path / "oldapi.py").write_text(OLD_API, encoding="utf-8")
    monkeypatch.setenv("DENIZ_PLUGIN_PATH", str(tmp_path))
    registry = Registry()
    sources = {e.source for e in registry.errors}
    assert any("broken.py" in s for s in sources)
    assert any("shadow.py" in s for s in sources)
    assert any("oldapi.py" in s for s in sources)
    assert not registry.is_plugin("crtsh")
    assert not registry.is_plugin("oldapi")

