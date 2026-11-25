#!/usr/bin/env bash
# Build and verify an installable artifact without uploading.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PY=".venv/bin/python"
[ -x "$PY" ] || PY="python"
rm -rf dist build
"$PY" -m build
"$PY" -m twine check dist/*
TMP="$(mktemp -d)"
"$PY" -m venv "$TMP"
"$TMP/bin/pip" install --quiet dist/*.whl
"$TMP/bin/deniz" version
"$TMP/bin/python" -c "import deniz.kit, deniz.mcp; print('import ok')"
rm -rf "$TMP"
echo "artifact ok; upload to TestPyPI first"
