# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from pathlib import Path

import pytest

from deniz.kit.config import Config


@pytest.fixture()
def config(tmp_path: Path) -> Config:
    return Config(home=tmp_path).ensure()

