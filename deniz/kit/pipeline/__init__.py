# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

"""Pipelines."""

from __future__ import annotations

from ..errors import ErrorKind
from ..providers.health import FAIL


def health_kind(kind: ErrorKind) -> str:
    return FAIL

