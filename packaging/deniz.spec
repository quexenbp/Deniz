# SPDX-License-Identifier: GPL-3.0-or-later
# ruff: noqa: F821
"""One-file PyInstaller build. Run from the repository root:

    pyinstaller --clean --noconfirm packaging/deniz.spec
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent

hidden = collect_submodules("deniz.kit")

a = Analysis(
    ["entry.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[(str(ROOT / "deniz" / "data"), "deniz/data")],
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="deniz",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
)
