# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Provider contract.

A provider is a typed data source with declared cost, auth and budget. It
must not print; it returns observations or raises a typed error.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from ..auth import AuthStore
from ..http import HttpClient, ProviderHttp
from ..models import Observation, Target
from ..scope import Scope

CONTRACT_VERSION = 1


@dataclass(frozen=True)
class ProviderInfo:
    name: str
    title: str
    capabilities: frozenset[str]
    auth: str = "none"  # none | key | oauth
    cost: str = "free"  # free | quota | paid
    rate: float = 1.0
    burst: int = 2
    max_bytes: int | None = None
    budget: int | None = None
    tos_url: str = ""
    homepage: str = ""
    notes: str = ""


@dataclass
class Context:
    http: HttpClient
    scope: Scope
    auth: AuthStore
    max_items: int = 5000
    max_workers: int = 16
    user_agent: str = ""
    allow_out_of_scope: bool = False
    providers_used: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)


class Provider(ABC):
    info: ClassVar[ProviderInfo]
    cache_ttl: ClassVar[float] = 900.0

    def __init__(self, http: HttpClient) -> None:
        self.http = http
        self.client = ProviderHttp(
            client=http,
            provider=self.info.name,
            rate=self.info.rate,
            burst=self.info.burst,
            budget=self.info.budget,
            defaults={"cache_ttl": self.cache_ttl},
        )

    @abstractmethod
    def run(self, target: Target, ctx: Context) -> list[Observation]:
        """Collect observations for the target."""

    def supports(self, capability: str) -> bool:
        return capability in self.info.capabilities

