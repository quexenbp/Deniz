# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

import pytest
from pydantic import ValidationError

from deniz.kit.models import Observation, Result, Source, Target


def test_target_validation() -> None:
    assert Target(type="domain", value="Example.COM.").value == "example.com"
    with pytest.raises(ValidationError):
        Target(type="domain", value="nodot")
    with pytest.raises(ValidationError):
        Target(type="ip", value="999.1.1.1")


def test_observation_requires_source() -> None:
    with pytest.raises(ValidationError):
        Observation(type="hostname", value="a.example.com")
    obs = Observation(
        type="hostname",
        value="a.example.com",
        sources=[Source(provider="test", url="https://example.test")],
    )
    assert obs.confidence == 0.5


def test_result_alias_and_dedupe() -> None:
    src = Source(provider="p", url="u")
    result = Result(module="m", target=Target(type="domain", value="e.com"))
    result.add(Observation(type="hostname", value="A.e.com", confidence=0.2, sources=[src]))
    result.add(Observation(type="hostname", value="a.e.com", confidence=0.9, sources=[src]))
    result.dedupe()
    assert len(result.items) == 1
    assert result.items[0].confidence == 0.9
    assert result.model_dump(by_alias=True)["schema"] == "deniz.result/1"


def test_dedupe_keeps_ip_per_host() -> None:
    src = Source(provider="p", url="u")
    result = Result(module="m", target=Target(type="domain", value="e.com"))
    result.add(Observation(type="ip", value="192.0.2.1", sources=[src], attrs={"host": "a.e.com"}))
    result.add(Observation(type="ip", value="192.0.2.1", sources=[src], attrs={"host": "b.e.com"}))
    result.dedupe()
    assert len(result.items) == 2

