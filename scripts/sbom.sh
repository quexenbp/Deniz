#!/usr/bin/env bash
set -euo pipefail

# SPDX-License-Identifier: GPL-3.0-or-later
# Generate an SPDX JSON SBOM for the source tree and installed environment.
# Requires https://github.com/anchore/syft

out="${1:-sbom.spdx.json}"
syft dir:. -o "spdx-json=$out" --exclude './.venv' --exclude './dist' --exclude './.git'
echo "wrote $out"
