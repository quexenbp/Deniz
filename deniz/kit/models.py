# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Result envelope and observation models (`deniz.result/1`)."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ObservationType = Literal[
    "hostname",
    "ip",
    "url",
    "certificate",
    "header",
    "title",
    "service",
    "asn",
    "technology",
    "email",
    "username",
    "bucket",
    "cve",
    "breach",
    "bucket",
    "takeover",
    "note",
]
TargetType = Literal["domain", "hostname", "ip", "email", "username", "url", "org", "keyword", "phone", "text"]
Schema = Literal["deniz.result/1"]


def utcnow() -> datetime:
    return datetime.now(UTC)


class Source(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    url: str
    fetched_at: datetime = Field(default_factory=utcnow)
    sha256: str | None = None


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: TargetType
    value: str

    @field_validator("value")
    @classmethod
    def _normalise(cls, value: str, info: Any) -> str:
        value = value.strip().lower().rstrip(".")
        if not value:
            raise ValueError("target value is empty")
        kind = info.data.get("type")
        if kind == "ip":
            ipaddress.ip_address(value)
        elif kind in ("domain", "hostname"):
            if len(value) > 253 or "." not in value:
                raise ValueError(f"invalid domain: {value}")
            if value.startswith("."):
                raise ValueError(f"invalid domain: {value}")
        elif kind == "email" and "@" not in value:
            raise ValueError(f"invalid email: {value}")
        elif kind == "keyword" and len(value) < 2:
            raise ValueError("keyword too short")
        elif kind == "phone" and (not value.startswith("+") or len(value) < 7):
            raise ValueError(f"invalid phone: {value}")
        elif kind == "text" and len(value) < 3:
            raise ValueError("text too short")
        return value


class Observation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: ObservationType
    value: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    sources: list[Source] = Field(min_length=1)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    attrs: dict[str, Any] = Field(default_factory=dict)

    @field_validator("sources")
    @classmethod
    def _needs_source(cls, value: list[Source]) -> list[Source]:
        if not value:
            raise ValueError("observation needs at least one source")
        return value


class ErrorInfo(BaseModel):
    kind: str
    provider: str | None = None
    message: str
    retryable: bool = False


class Stats(BaseModel):
    requests: int = 0
    cache_hits: int = 0
    duration_ms: int = 0
    providers_used: list[str] = Field(default_factory=list)


class Result(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    schema_: Schema = Field("deniz.result/1", alias="schema")
    run_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    module: str
    provider: str | None = None
    target: Target
    observed_at: datetime = Field(default_factory=utcnow)
    items: list[Observation] = Field(default_factory=list)
    errors: list[ErrorInfo] = Field(default_factory=list)
    stats: Stats = Field(default_factory=Stats)

    def add(self, observation: Observation) -> None:
        self.items.append(observation)

    def error(self, kind: str, message: str, *, provider: str | None = None, retryable: bool = False) -> None:
        self.errors.append(ErrorInfo(kind=kind, provider=provider, message=message, retryable=retryable))

    def dedupe(self) -> None:
        seen: dict[tuple[str, str, str], Observation] = {}
        for item in self.items:
            host = str(item.attrs.get("host") or item.attrs.get("url") or "")
            key = (item.type, item.value.lower(), host)
            current = seen.get(key)
            if current is None:
                seen[key] = item
                continue
            current.sources.extend(s for s in item.sources if s.url not in {x.url for x in current.sources})
            current.confidence = max(current.confidence, item.confidence)
            if item.first_seen and (current.first_seen is None or item.first_seen < current.first_seen):
                current.first_seen = item.first_seen
            if item.last_seen and (current.last_seen is None or item.last_seen > current.last_seen):
                current.last_seen = item.last_seen
            current.attrs.update({k: v for k, v in item.attrs.items() if k not in current.attrs})
        self.items = list(seen.values())

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.items:
            counts[item.type] = counts.get(item.type, 0) + 1
        return counts

