#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
ROOT="$SCRIPT_DIR/../.."
RUN_MODE="${1:-background}"
ACTION="${2:-monitor}"
APP_ARG=""

case "$ACTION" in
  monitor) ;;
  settings) APP_ARG="--settings" ;;
  install) APP_ARG="--install-autostart" ;;
  remove) APP_ARG="--remove-autostart" ;;
  *) echo "Unknown action: $ACTION" >&2; exit 2 ;;
esac

APP="${KIRO_IP_GUARD_EXE:-}"
if [[ -z "$APP" && -x "$ROOT/dist/KiroIPGuard.app/Contents/MacOS/KiroIPGuard" ]]; then
  APP="$ROOT/dist/KiroIPGuard.app/Contents/MacOS/KiroIPGuard"
elif [[ -z "$APP" && -x "$ROOT/dist/KiroIPGuard" && ! -d "$ROOT/dist/KiroIPGuard" ]]; then
  APP="$ROOT/dist/KiroIPGuard"
elif [[ -z "$APP" && -x "$ROOT/dist/KiroIPGuard/KiroIPGuard" ]]; then
  APP="$ROOT/dist/KiroIPGuard/KiroIPGuard"
fi

if [[ -n "$APP" ]]; then
  [[ -x "$APP" ]] || { echo "Executable not found or not executable: $APP" >&2; exit 2; }
  set -- "$APP"
else
  PYTHON="$ROOT/.venv/bin/python"
  [[ -x "$PYTHON" ]] || {
    echo "Virtual environment not found. Run: python3 -m venv .venv" >&2
    echo "Then run: .venv/bin/python -m pip install -r requirements.txt" >&2
    exit 2
  }
  set -- "$PYTHON" -m ip_guard
fi
[[ -n "$APP_ARG" ]] && set -- "$@" "$APP_ARG"

cd "$ROOT"
if [[ "$RUN_MODE" == "background" ]]; then
  nohup "$@" >/dev/null 2>&1 &
  echo "Kiro IP Guard started in background (PID $!)."
else
  "$@"
fi
