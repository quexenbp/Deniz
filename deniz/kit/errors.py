# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Typed provider and transport errors.

Every provider failure maps to one of these kinds so the orchestrator can
decide whether to fall back, retry, or quarantine the provider.
"""

from __future__ import annotations

from enum import StrEnum


class ErrorKind(StrEnum):
    NETWORK = "network"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    BLOCKED = "blocked"
    AUTH_REQUIRED = "auth_required"
    NOT_FOUND = "not_found"
    PARSE_CHANGED = "parse_changed"
    DEAD = "dead"
    INVALID_INPUT = "invalid_input"
    OUT_OF_SCOPE = "out_of_scope"
    INTERNAL = "internal"
    CACHE_MISS = "cache_miss"
    DEPENDENCY_MISSING = "dependency_missing"
    BUDGET_EXCEEDED = "budget_exceeded"


class DenizError(Exception):
    kind: ErrorKind = ErrorKind.INTERNAL
    retryable = False

    def __init__(self, message: str, *, provider: str | None = None) -> None:
        super().__init__(message)
        self.provider = provider

    def __str__(self) -> str:
        base = super().__str__()
        return f"[{self.kind.value}] {base}"


class NetworkError(DenizError):
    kind = ErrorKind.NETWORK
    retryable = True


class TimeoutError_(DenizError):
    kind = ErrorKind.TIMEOUT
    retryable = True


class RateLimited(DenizError):
    kind = ErrorKind.RATE_LIMITED
    retryable = True


class Blocked(DenizError):
    kind = ErrorKind.BLOCKED
    retryable = False


class AuthRequired(DenizError):
    kind = ErrorKind.AUTH_REQUIRED
    retryable = False


class ParseChanged(DenizError):
    kind = ErrorKind.PARSE_CHANGED
    retryable = False


class ProviderDead(DenizError):
    kind = ErrorKind.DEAD
    retryable = False


class InvalidInput(DenizError):
    kind = ErrorKind.INVALID_INPUT
    retryable = False


class OutOfScope(DenizError):
    kind = ErrorKind.OUT_OF_SCOPE
    retryable = False


class CacheMiss(DenizError):
    kind = ErrorKind.CACHE_MISS
    retryable = False


class DependencyMissing(DenizError):
    kind = ErrorKind.DEPENDENCY_MISSING
    retryable = False


class BudgetExceeded(DenizError):
    kind = ErrorKind.BUDGET_EXCEEDED
    retryable = False

