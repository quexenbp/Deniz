from __future__ import annotations

from pathlib import Path

from deniz.kit.pipeline.domain import order_chain
from deniz.kit.providers.health import FAIL, OK, HealthStore


class Stub:
    def __init__(self, scores: dict[str, float | None]) -> None:
        self.scores = scores

    def score(self, name: str) -> float | None:
        return self.scores.get(name)


def test_healthy_first_and_dead_last() -> None:
    stub = Stub({"a": 0.2, "b": None, "c": 1.0, "d": 0.0})
    assert order_chain(["a", "b", "c", "d"], stub) == ["c", "b", "a", "d"]


def test_real_health_store_orders(tmp_path: Path) -> None:
    health = HealthStore(tmp_path / "h.sqlite3")
    for _ in range(5):
        health.record("good", OK)
        health.record("bad", FAIL)
    ordered = order_chain(["bad", "good", "unknown"], health)
    assert ordered[0] == "good"
    assert ordered[-1] == "bad"


def test_hidden_needs_samples(tmp_path: Path) -> None:
    health = HealthStore(tmp_path / "h.sqlite3")
    assert health.hidden("x") is False
    for _ in range(4):
        health.record("x", FAIL)
    assert health.hidden("x") is False
    health.record("x", FAIL)
    assert health.hidden("x") is True
    for _ in range(5):
        health.record("x", OK)
    assert health.hidden("x") is False


def test_provider_list_hides_quarantined(tmp_path: Path, monkeypatch, capsys) -> None:
    from deniz.cli import main

    monkeypatch.setenv("DENIZ_HOME", str(tmp_path))
    health = HealthStore(Path(tmp_path) / "state.sqlite3")
    for _ in range(5):
        health.record("wikipedia", FAIL)
    assert main(["providers", "list"]) == 0
    assert "wikipedia" not in capsys.readouterr().out
    assert main(["providers", "list", "--all"]) == 0
    assert "wikipedia (hidden)" in capsys.readouterr().out
