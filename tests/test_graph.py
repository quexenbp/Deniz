# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from pathlib import Path

from deniz.kit.graph import GraphStore
from deniz.kit.models import Observation, Result, Source, Target


def sample(run_id: str, host: str) -> Result:
    result = Result(run_id=run_id, module="test", target=Target(type="domain", value="example.com"))
    result.add(
        Observation(
            type="hostname",
            value=host,
            sources=[Source(provider="test", url="https://t")],
            attrs={},
        )
    )
    result.add(
        Observation(
            type="ip",
            value="192.0.2.1",
            sources=[Source(provider="test", url="https://t")],
            attrs={"host": host},
        )
    )
    return result


def test_record_and_show(tmp_path: Path) -> None:
    graph = GraphStore(tmp_path / "g.sqlite3")
    graph.record(sample("a", "a.example.com"))
    assert graph.stats()["entities"] >= 3
    data = graph.show("a.example.com")
    assert data["entity"]["type"] == "hostname"
    assert any(edge["relation"] == "resolves_to" for edge in data["outgoing"])


def test_diff(tmp_path: Path) -> None:
    graph = GraphStore(tmp_path / "g.sqlite3")
    graph.record(sample("a", "a.example.com"))
    graph.record(sample("b", "b.example.com"))
    delta = graph.diff("a", "b")
    assert "b.example.com" in delta["added"]
    assert "a.example.com" in delta["removed"]


def test_prune_removes_old(tmp_path: Path) -> None:
    graph = GraphStore(tmp_path / "g.sqlite3")
    graph.record(sample("a", "a.example.com"))
    assert graph.prune(days=-1)["observations"] >= 1
    assert graph.stats()["entities"] == 0


def test_case_filter(tmp_path: Path) -> None:
    graph = GraphStore(tmp_path / "g.sqlite3")
    graph.record(sample("a", "a.example.com"))
    graph.record(sample("b", "b.example.com"))
    values = {row["value"] for row in graph.entities(run_ids=["a"])}
    assert "a.example.com" in values
    assert "b.example.com" not in values
    data = graph.show("a.example.com", run_ids=["b"])
    assert data["observations"] == []
    assert data["entity"]["value"] == "a.example.com"


def test_export_graph(tmp_path: Path) -> None:
    graph = GraphStore(tmp_path / "g.sqlite3")
    graph.record(sample("a", "a.example.com"))
    data = graph.export_graph(["a"])
    assert any(n["value"] == "a.example.com" for n in data["nodes"])
    assert data["edges"]


def test_search(tmp_path: Path) -> None:
    graph = GraphStore(tmp_path / "g.sqlite3")
    graph.record(sample("a", "a.example.com"))
    rows = graph.search(["a"], "example", 10)
    assert any(row["value"] == "a.example.com" for row in rows)
    assert graph.search(["a"], "nothing", 10) == []


def test_timeline_new_counts(tmp_path: Path) -> None:
    graph = GraphStore(tmp_path / "g.sqlite3")
    graph.record(sample("a", "a.example.com"))
    graph.record(sample("b", "b.example.com"))
    rows = graph.timeline(["a", "b"])
    assert rows[0]["new"] == 0
    assert rows[1]["new"] >= 1

