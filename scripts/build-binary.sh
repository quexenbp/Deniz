# Build a one-file binary on Linux/macOS.
set -euo pipefail

python -m pip install -e ".[dev]" pyinstaller
pyinstaller --clean --noconfirm packaging/deniz.spec
./dist/deniz version
