#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR"
VERSION="${1:-}"

if [[ $# -gt 1 ]]; then
  echo "Usage: $0 [version]" >&2
  exit 2
fi
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "release.sh must run on macOS because macOS application bundles cannot be cross-built." >&2
  exit 2
fi
if [[ -z "$VERSION" ]]; then
  VERSION="$(sed -nE 's/^__version__[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
    "$ROOT/ip_guard/__init__.py" | head -n 1)"
fi
if [[ ! "$VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]]; then
  echo "Invalid or missing version: $VERSION" >&2
  exit 2
fi

case "$(uname -m)" in
  x86_64) ARCH="x64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) ARCH="$(uname -m)" ;;
esac

RELEASE_DIR="$ROOT/release"
PACKAGE_DIR="$RELEASE_DIR/KiroIPGuard-macOS-${ARCH}-onefile-v${VERSION}"
ZIP_PATH="$PACKAGE_DIR.zip"
APP="$ROOT/dist/KiroIPGuard.app"
mkdir -p "$RELEASE_DIR"

echo "Building macOS onefile package..."
"$ROOT/scripts/macos/build.sh"
if [[ ! -d "$APP" ]]; then
  echo "Expected application bundle not found: $APP" >&2
  exit 1
fi

rm -rf -- "$PACKAGE_DIR" "$ZIP_PATH"
mkdir -p "$PACKAGE_DIR"
cp -R "$APP" "$PACKAGE_DIR/"
cp "$ROOT/README.md" "$ROOT/README_zh.md" "$ROOT/assets/kiro-ip-guard.png" "$PACKAGE_DIR/"
cat > "$PACKAGE_DIR/Quick-Start.txt" <<EOF
Kiro IP Guard v$VERSION

1. Open KiroIPGuard.app to start monitoring in the menu bar.
2. Use the tray menu to open settings and manage user login startup.
3. Configuration is stored in ~/Library/Application Support/KiroIPGuard/config.json.
4. See README.md for English documentation or README_zh.md for Chinese documentation.
EOF

/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$PACKAGE_DIR" "$ZIP_PATH"
echo "Created: $ZIP_PATH"
