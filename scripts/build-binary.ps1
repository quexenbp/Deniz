# Build a one-file binary on Windows.
$ErrorActionPreference = "Stop"

python -m pip install -e ".[dev]" pyinstaller
pyinstaller --clean --noconfirm packaging/deniz.spec
.\dist\deniz.exe version
