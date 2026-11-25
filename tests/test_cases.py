# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

import json
from pathlib import Path

import pytest

from deniz.kit.cases import CaseStore
from deniz.kit.models import Observation, Result, Source, Target
from deniz.kit.store import RunStore


def test_crud_and_scope(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite3")
    case = store.create("acme", allow=["acme.test"], deny=["dev.acme.test"])
    assert store.get("acme").id == case.id
    assert store.get(case.id[:8]).id == case.id
    assert store.get("acme").scope().allows("acme.test")
    assert not store.get("acme").scope().allows("dev.acme.test")
    with pytest.raises(ValueError):
        store.create("acme")


def test_notes_and_runs(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite3")
    case = store.create("acme")
    store.add_note(case.id, "kickoff")
    store.add_run(case.id, "run-1")
    got = store.get("acme")
    assert got.notes[0]["text"] == "kickoff"
    assert got.runs == ["run-1"]


def test_archive_and_delete(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite3")
    case = store.create("acme", tags=["client", "external"])
    assert store.get(case.id).tags == ["client", "external"]
    store.add_tag(case.id, "urgent")
    assert "urgent" in store.get(case.id).tags
    store.remove_tag(case.id, "client")
    assert "client" not in store.get(case.id).tags
    store.archive(case.id)
    assert store.get(case.id).archived is True
    assert store.list_cases() == []
    assert len(store.list_cases(include_archived=True)) == 1
    store.unarchive(case.id)
    assert store.list_cases()[0].id == case.id
    store.delete(case.id)
    with pytest.raises(KeyError):
        store.get(case.id)


def test_export(tmp_path: Path) -> None:
    cases = CaseStore(tmp_path / "cases.sqlite3")
    runs = RunStore(tmp_path / "runs")
    case = cases.create("acme", allow=["acme.test"])
    run = runs.begin("domain.quick")
    result = Result(run_id=run.run_id, module="domain.quick", target=Target(type="domain", value="acme.test"))
    result.add(
        Observation(
            type="hostname",
            value="www.acme.test",
            sources=[Source(provider="crtsh", url="https://crt.sh")],
        )
    )
    runs.write(run, result)
    cases.add_run(case.id, run.run_id)

    out = cases.export(case.id, runs, tmp_path / "export", findings=None, graph=None, as_zip=True)
    assert out.suffix == ".zip"
    import zipfile

    names = zipfile.ZipFile(out).namelist()
    assert "case.json" in names and "case.html" in names
    plain = cases.export(case.id, runs, tmp_path / "export-plain")
    assert (plain / "case.json").exists()
    assert (plain / "case.stix.json").exists()
    assert (plain / "runs" / run.path.name / "report.html").exists()
    data = json.loads((plain / "case.stix.json").read_text(encoding="utf-8"))
    ids = {o["id"] for o in data["objects"]}
    for obj in data["objects"]:
        if obj["type"] == "relationship":
            assert obj["source_ref"] in ids and obj["target_ref"] in ids

