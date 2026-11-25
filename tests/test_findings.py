from __future__ import annotations

import json
from pathlib import Path

import pytest

from deniz.kit.cases import CaseStore
from deniz.kit.findings import FindingStore, derive
from deniz.kit.graph import GraphStore
from deniz.kit.models import Observation, Result, Source, Target
from deniz.kit.store import RunStore


def build(tmp_path: Path):
    graph = GraphStore(tmp_path / "g.sqlite3")
    result = Result(run_id="run-1", module="test", target=Target(type="domain", value="example.com"))
    src = [Source(provider="test", url="https://t")]
    result.add(Observation(type="takeover", value="x.example.com -> github.io", sources=src, confidence=0.9))
    result.add(Observation(type="bucket", value="s3://example", sources=src, attrs={"public_listing": True}))
    result.add(Observation(type="cve", value="CVE-2021-1", sources=src, attrs={"cvss": 9.8}))
    result.add(Observation(type="breach", value="BigBreach", sources=src, attrs={"data_classes": ["Passwords"]}))
    result.add(Observation(type="note", value="SPF: missing", sources=src, attrs={"record": "SPF", "all": "missing"}))
    result.add(Observation(type="note", value="DMARC: missing", sources=src, attrs={"record": "DMARC", "policy": "missing"}))
    result.add(Observation(type="note", value="RDAP: client hold", sources=src, attrs={"record": "RDAP", "risky_status": ["client hold"]}))
    result.add(Observation(type="note", value="Domain expires in 5 days", sources=src, attrs={"record": "RDAP_EXPIRY", "days": 5}))
    graph.record(result)
    return graph


def test_derive_severities(tmp_path: Path) -> None:
    rows = derive("case-1", ["run-1"], build(tmp_path))
    kinds = {r[0]: r[1] for r in rows}
    assert kinds["takeover"] == "high"
    assert kinds["bucket_public"] == "high"
    assert kinds["breach"] == "high"
    assert kinds["spf_weak"] == "medium"
    assert kinds["dmarc_weak"] == "medium"
    assert kinds["cve"] == "critical"
    assert kinds["domain_status"] == "high"
    assert kinds["domain_expiry"] == "high"


def test_store_dedupe_and_ack(tmp_path: Path) -> None:
    graph = build(tmp_path)
    store = FindingStore(tmp_path / "f.sqlite3")
    first = store.refresh("case-1", ["run-1"], graph)
    second = store.refresh("case-1", ["run-1"], graph)
    assert len(first) == len(second)
    assert len({(f.kind, f.value) for f in second}) == len(second)
    assert store.stats("case-1")["high"] >= 1
    assert store.ack_all("case-1") == len(second)
    assert store.list("case-1", include_acked=False) == []


def test_override_and_note(tmp_path: Path) -> None:
    store = FindingStore(tmp_path / "f.sqlite3")
    store.refresh("c", ["run-1"], build(tmp_path))
    finding = store.list("c")[0]
    store.set(finding.id, "critical", "confirmed in prod")
    updated = next(f for f in store.list("c") if f.id == finding.id)
    assert updated.severity_override == "critical"
    assert updated.note == "confirmed in prod"
    with pytest.raises(ValueError):
        store.set(finding.id, "urgent")


def test_export_contains_findings(tmp_path: Path) -> None:
    graph = build(tmp_path)
    store = FindingStore(tmp_path / "f.sqlite3")
    cases = CaseStore(tmp_path / "cases.sqlite3")
    case = cases.create("acme")
    store.refresh(case.id, ["run-1"], graph)
    runs = RunStore(tmp_path / "runs")
    run = runs.begin("test")
    result = Result(run_id=run.run_id, module="test", target=Target(type="domain", value="example.com"))
    result.add(Observation(type="takeover", value="x", sources=[Source(provider="t", url="u")], confidence=0.9))
    runs.write(run, result)
    cases.add_run(case.id, run.run_id)
    # finding rows point at "run-1"; export still writes the file for the case
    out = cases.export(case.id, runs, tmp_path / "export", store)
    assert (out / "findings.json").exists()
    assert "findings" in (out / "case.json").read_text(encoding="utf-8")
    stix = json.loads((out / "case.stix.json").read_text(encoding="utf-8"))
    assert any(obj["type"] == "note" and "high" in obj["labels"] for obj in stix["objects"])
