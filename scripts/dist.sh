#!/usr/bin/env bash
# Wraps electron-builder to prevent it from stripping package.json.
# electron-builder sometimes writes a minimal app package.json back
# to the working directory; this script saves and restores it.
set -euo pipefail

PKG="$(cd "$(dirname "$0")/.." && pwd)/package.json"
BAK="${PKG}.dist-bak"

cp "$PKG" "$BAK"
trap 'cp "$BAK" "$PKG"; rm -f "$BAK"; echo "package.json restored."' EXIT

npx electron-builder "$@"
