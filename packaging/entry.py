# SPDX-License-Identifier: GPL-3.0-or-later
"""PyInstaller entry point; mirrors the console script."""

from deniz.kit.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
