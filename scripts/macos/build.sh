#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
ROOT="$SCRIPT_DIR/../.."

cd "$ROOT"
[[ -x .venv/bin/python ]] || python3 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check -r requirements-build.txt
.venv/bin/python -m PyInstaller --noconfirm --clean --onefile --windowed \
  --name KiroIPGuard --icon "assets/kiro-ip-guard.icns" --add-data "assets:assets" \
  --collect-all pystray run_guard.py
echo "Build completed in: $ROOT/dist"
