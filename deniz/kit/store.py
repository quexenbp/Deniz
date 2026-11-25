# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Run storage: one directory per run, JSONL items, JSON summary."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .models import Result


@dataclass(frozen=True)
class RunRef:
    run_id: str
    path: Path


def write_run_files(path: Path, result: Result) -> None:
    """Write the result envelope and JSONL views into an existing directory."""

    payload = result.model_dump(mode="json", by_alias=True)
    (path / "result.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    with (path / "items.jsonl").open("w", encoding="utf-8") as handle:
        for item in result.items:
            handle.write(json.dumps(item.model_dump(mode="json"), ensure_ascii=False) + "\n")
    with (path / "errors.jsonl").open("w", encoding="utf-8") as handle:
        for error in result.errors:
            handle.write(json.dumps(error.model_dump(mode="json"), ensure_ascii=False) + "\n")
    (path / "summary.json").write_text(
        json.dumps(
            {
                "run_id": result.run_id,
                "module": result.module,
                "target": result.target.model_dump(mode="json"),
                "counts": result.summary(),
                "errors": len(result.errors),
                "duration_ms": result.stats.duration_ms,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


class RunStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def begin(self, module: str) -> RunRef:
        run_id = __import__("uuid").uuid4().hex
        path = self.root / f"{run_id}-{module.replace('.', '-')}"
        path.mkdir(parents=True, exist_ok=False)
        return RunRef(run_id=run_id, path=path)

    def write(self, run: RunRef, result: Result) -> None:
        write_run_files(run.path, result)
        (self.root / "latest").write_text(result.run_id, encoding="utf-8")

    def list(self, limit: int = 20) -> list[Path]:
        dirs = sorted((p for p in self.root.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime, reverse=True)
        return dirs[:limit]

    def resolve(self, run_id: str) -> Path:
        matches = [p for p in self.root.iterdir() if p.is_dir() and p.name.startswith(run_id)]
        if not matches:
            raise FileNotFoundError(run_id)
        return matches[0]

