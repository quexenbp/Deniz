from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

from deniz.kit.cases import CaseStore
from deniz.kit.cli import cmd_runs
from deniz.kit.graph import GraphStore
from deniz.kit.models import Observation, Result, Source, Target
from deniz.kit.store import RunStore


def old(path: Path, days: int = 60) -> None:
    stamp = time.time() - days * 86400
    os.utime(path, (stamp, stamp))


def record(graph: GraphStore, run_id: str, value: str) -> None:
    result = Result(run_id=run_id, module="test", target=Target(type="domain", value=value))
    result.add(Observation(type="hostname", value=value, sources=[Source(provider="t", url="u")]))
    graph.record(result)


def test_prune_skips_case_runs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DENIZ_HOME", str(tmp_path))
    runs = RunStore(tmp_path / "runs")
    keep = runs.begin("keep")
    drop = runs.begin("drop")
    old(keep.path)
    old(drop.path)
    cases = CaseStore(tmp_path / "cases.sqlite3")
    case = cases.create("acme")
    cases.add_run(case.id, keep.run_id)
    graph = GraphStore(tmp_path / "graph.sqlite3")
    record(graph, keep.run_id, "keep.example.com")
    record(graph, drop.run_id, "drop.example.com")

    args = argparse.Namespace(action="prune", prune_days=30, include_case_runs=False, show=None, diff=None, limit=20)
    assert cmd_runs(args) == 0
    assert keep.path.exists()
    assert not drop.path.exists()
    remaining = {row["value"] for row in graph.entities()}
    assert "keep.example.com" in remaining
    assert "drop.example.com" not in remaining
