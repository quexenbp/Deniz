from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

textual = pytest.importorskip("textual")


def test_tui_mounts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DENIZ_HOME", str(tmp_path))
    from deniz.kit.tui import DenizApp

    async def run() -> None:
        app = DenizApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.query_one("#cases-table") is not None

    asyncio.run(run())
