# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from pathlib import Path

import pytest

from deniz.kit.models import Observation, Result, Source, Target
from deniz.kit.report import render_html, render_stix, write_report


def sample() -> Result:
    src = Source(provider="crtsh", url="https://crt.sh/?q=x")
    result = Result(run_id="fixed", module="domain.quick", target=Target(type="domain", value="example.com"))
    result.add(Observation(type="hostname", value="a.example.com", sources=[src], confidence=0.75))
    result.add(Observation(type="ip", value="192.0.2.1", sources=[src], attrs={"host": "a.example.com"}))
    result.add(Observation(type="ip", value="2001:db8::1", sources=[src], attrs={"host": "a.example.com"}))
    result.add(
        Observation(type="title", value="<script>alert(1)</script>", sources=[src], attrs={"url": "https://a.example.com/"})
    )
    return result


def test_html_escapes(tmp_path: Path) -> None:
    body = render_html(sample())
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "<script>alert(1)</script>" not in body
    assert "https://a.example.com/" in body


def test_turkish_report_labels() -> None:
    body = render_html(sample(), "tr")
    assert 'lang="tr"' in body
    assert "Gözlemler" in body and "Hatalar" in body
    assert "Observations" not in body


def test_stix_is_deterministic_and_linked() -> None:
    first = render_stix(sample())
    second = render_stix(sample())
    assert first["id"] == second["id"]
    ids = {obj["id"] for obj in first["objects"]}
    for obj in first["objects"]:
        if obj["type"] == "relationship":
            assert obj["source_ref"] in ids
            assert obj["target_ref"] in ids
    types = {obj["type"] for obj in first["objects"]}
    assert "ipv4-addr" in types and "ipv6-addr" in types and "x-deniz-observation" in types


def test_write_report(tmp_path: Path) -> None:
    assert write_report(sample(), "html", tmp_path).exists()
    assert write_report(sample(), "stix", tmp_path).exists()
    assert write_report(sample(), "jsonl", tmp_path).exists()


def test_pdf_if_browser_available(tmp_path: Path) -> None:
    pytest.importorskip("playwright")
    try:
        path = write_report(sample(), "pdf", tmp_path)
    except RuntimeError as exc:
        pytest.skip(str(exc))
    assert path.read_bytes().startswith(b"%PDF-")

