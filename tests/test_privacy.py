from __future__ import annotations

import json
from pathlib import Path

from deniz.kit.cases import CaseStore
from deniz.kit.models import Observation, Result, Source, Target
from deniz.kit.privacy import mask_email_local, mask_phones, redact_result
from deniz.kit.report import write_report
from deniz.kit.store import RunStore


def sample() -> Result:
    source = Source(provider="test", url="https://example.test/?email=ali.veli@example.com")
    result = Result(module="identity.email", target=Target(type="email", value="ali.veli@example.com"))
    result.add(
        Observation(
            type="email",
            value="ali.veli@example.com",
            sources=[source],
            attrs={"phone": "+90 532 123 45 67", "note": "reach ali.veli@example.com"},
        )
    )
    result.error("blocked", "ask ali.veli@example.com", provider="test")
    return result


def test_mask_email_keeps_domain() -> None:
    assert mask_email_local("ali.veli@example.com") == "a***@example.com"
    assert mask_email_local("no-email-here") == "no-email-here"


def test_mask_phone_keeps_last_two_digits() -> None:
    masked = mask_phones("call +90 532 123 45 67 now")
    assert "67" in masked
    assert "532" not in masked
    assert "call" in masked and "now" in masked


def test_redact_result_covers_values_attrs_sources_and_errors() -> None:
    redacted = redact_result(sample())
    dumped = json.dumps(redacted.model_dump(mode="json"), ensure_ascii=False)
    assert "ali.veli@example.com" not in dumped
    assert "a***@example.com" in dumped
    assert "532" not in redacted.items[0].attrs["phone"]
    assert redacted.target.value == "a***@example.com"
    assert len(redacted.items) == 1


def test_report_redaction(tmp_path: Path) -> None:
    for fmt in ("html", "stix", "jsonl"):
        path = write_report(sample(), fmt, tmp_path, redact=True)
        text = path.read_text(encoding="utf-8")
        assert "ali.veli@example.com" not in text
        assert "a***@example.com" in text


def test_case_export_redaction(tmp_path: Path) -> None:
    cases = CaseStore(tmp_path / "cases.sqlite3")
    runs = RunStore(tmp_path / "runs")
    case = cases.create("pii")
    run = runs.begin("identity.email")
    result = sample()
    result.run_id = run.run_id
    runs.write(run, result)
    cases.add_run(case.id, run.run_id)
    cases.add_note(case.id, "owner ali.veli@example.com")

    out = cases.export(case.id, runs, tmp_path / "export", redact=True)
    for name in ("case.json", "case.stix.json", "case.html", "findings.json"):
        path = out / name
        if path.exists():
            assert "ali.veli@example.com" not in path.read_text(encoding="utf-8")
    run_dir = out / "runs" / run.path.name
    for name in ("result.json", "items.jsonl", "errors.jsonl", "summary.json"):
        assert "ali.veli@example.com" not in (run_dir / name).read_text(encoding="utf-8")
    assert "a***@example.com" in (run_dir / "result.json").read_text(encoding="utf-8")
