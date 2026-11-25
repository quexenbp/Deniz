from __future__ import annotations

import os

import pytest

from deniz.kit.cases import CaseStore
from deniz.kit.findings import FindingStore
from deniz.kit.graph import GraphStore
from deniz.kit.models import Observation, Result, Source, Target
from deniz.kit.monitors import MonitorStore

DSN = os.environ.get("DENIZ_TEST_PG")
pytestmark = pytest.mark.skipif(not DSN, reason="set DENIZ_TEST_PG to a disposable database")
TABLES = "edges, observations, entities, runs, alerts, monitors, findings, case_runs, cases"


def clean(dsn: str) -> None:
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as con:
        con.execute(f"DROP TABLE IF EXISTS {TABLES} CASCADE")


def test_postgres_stores() -> None:
    assert DSN
    clean(DSN)
    cases = CaseStore(DSN)
    graph = GraphStore(DSN)
    monitors = MonitorStore(DSN)
    findings = FindingStore(DSN)

    case = cases.create("pg", allow=["example.com"])
    result = Result(module="test", target=Target(type="domain", value="example.com"))
    result.add(
        Observation(
            type="takeover",
            value="a.example.com -> github.io",
            confidence=0.9,
            sources=[Source(provider="t", url="u")],
        )
    )
    graph.record(result)
    cases.add_run(case.id, result.run_id)
    monitor = monitors.add(case.id, "domain", "example.com", 30)
    monitors.add_alert(monitor, "delta", "1", {})
    rows = findings.refresh(case.id, [result.run_id], graph)

    assert cases.get("pg").runs == [result.run_id]
    assert graph.stats()["entities"] == 2
    assert rows[0].kind == "takeover"
    assert len(monitors.alerts()) == 1
    for store in (cases, graph, monitors, findings):
        store.db.close()
    clean(DSN)
