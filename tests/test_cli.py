# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

import pytest

from deniz.cli import main


def test_version(capsys) -> None:
    assert main(["version"]) == 0
    assert "0.1.0" in capsys.readouterr().out


def test_schema(capsys) -> None:
    import json

    assert main(["schema"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["title"] == "Result"


def test_no_args_prints_help(capsys) -> None:
    assert main([]) == 0
    assert "usage: deniz" in capsys.readouterr().out


def test_unknown_command_exits(capsys) -> None:
    with pytest.raises(SystemExit) as info:
        main(["definitely-not-a-command"])
    assert info.value.code == 2

