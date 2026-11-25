#!/usr/bin/env bash
set -euo pipefail

# SPDX-License-Identifier: GPL-3.0-or-later
# Pre-release gate. Run from the repository root.

python -m ruff check deniz/kit deniz/cli.py deniz/mcp.py tests
python -m mypy deniz/kit --follow-imports=skip
python -m pytest -q
python -m pip wheel . --no-deps -w dist
python -m twine check dist/*
python -m pip_audit

echo "release checks passed"
