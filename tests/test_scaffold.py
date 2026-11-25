from __future__ import annotations

from pathlib import Path

import pytest

from deniz.kit.scaffold import new_provider


def root(tmp_path: Path) -> Path:
    providers = tmp_path / "deniz" / "kit" / "providers"
    providers.mkdir(parents=True)
    (providers / "registry.py").write_text('BUILTIN = {\n    "one": "x",\n}\n', encoding="utf-8")
    (tmp_path / "tests").mkdir()
    return tmp_path


def test_provider_generator(tmp_path: Path) -> None:
    base = root(tmp_path)
    paths = new_provider(base, "my-source", "My source")
    provider, test = paths
    assert provider == base / "deniz" / "kit" / "providers" / "my_source.py"
    assert "class MySource(Provider)" in provider.read_text(encoding="utf-8")
    assert "API_VERSION = CONTRACT_VERSION" in provider.read_text(encoding="utf-8")
    compile(provider.read_text(encoding="utf-8"), str(provider), "exec")
    compile(test.read_text(encoding="utf-8"), str(test), "exec")
    registry = (base / "deniz" / "kit" / "providers" / "registry.py").read_text(encoding="utf-8")
    assert '"my_source": "deniz.kit.providers.my_source:MySource"' in registry


def test_provider_refuses_overwrite(tmp_path: Path) -> None:
    base = root(tmp_path)
    new_provider(base, "dup")
    with pytest.raises(FileExistsError):
        new_provider(base, "dup")
    new_provider(base, "dup", force=True)


def test_provider_rejects_bad_names(tmp_path: Path) -> None:
    base = root(tmp_path)
    for name in ("1bad", "has space", "x"):
        with pytest.raises(ValueError):
            new_provider(base, name)
