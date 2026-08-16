#!/usr/bin/env bash
# Builds a standalone AppImage for the Lynis Findings Dashboard.
#
# Steps:
#   1. Create an isolated build venv and install flask + pyinstaller into it
#      (this venv is only used to run PyInstaller; the resulting backend
#      binary is fully self-contained and does not depend on it at runtime).
#   2. Bundle app.py + templates/ + static/ + lynis_knowledge.json into a
#      single onefile executable.
#   3. Assemble an AppDir with that executable, AppRun, a .desktop file, and
#      an icon.
#   4. Download/cache appimagetool and pack the AppDir into a .AppImage.
#
# Output: dist/Lynis-Findings-Dashboard-<arch>.AppImage

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BUILD_DIR="$SCRIPT_DIR/build"
DIST_DIR="$SCRIPT_DIR/dist"
APPDIR="$BUILD_DIR/AppDir"
ARCH="$(uname -m)"
BACKEND_NAME="lynis-webui-backend"
APPIMAGE_NAME="Lynis-Findings-Dashboard-${ARCH}.AppImage"

echo "==> Cleaning previous build output"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$DIST_DIR"

echo "==> Setting up isolated build venv"
VENV_DIR="$BUILD_DIR/venv"
if ! python3 -m venv "$VENV_DIR" 2>/tmp/venv-create-error.$$; then
  cat /tmp/venv-create-error.$$ >&2
  rm -f /tmp/venv-create-error.$$
  echo "venv creation failed (likely missing ensurepip) — installing python3-venv via apt..."
  sudo apt-get update -qq
  sudo apt-get install -y python3-venv
  rm -rf "$VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi
rm -f /tmp/venv-create-error.$$
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet flask pyinstaller

echo "==> Running PyInstaller"
pyinstaller \
  --onefile \
  --name "$BACKEND_NAME" \
  --distpath "$BUILD_DIR/pyinstaller-dist" \
  --workpath "$BUILD_DIR/pyinstaller-work" \
  --specpath "$BUILD_DIR" \
  --add-data "$SCRIPT_DIR/templates:templates" \
  --add-data "$SCRIPT_DIR/static:static" \
  --add-data "$SCRIPT_DIR/lynis_knowledge.json:." \
  "$SCRIPT_DIR/app.py"

deactivate

echo "==> Assembling AppDir"
mkdir -p "$APPDIR/usr/bin"
cp "$BUILD_DIR/pyinstaller-dist/$BACKEND_NAME" "$APPDIR/usr/bin/$BACKEND_NAME"
cp "$SCRIPT_DIR/packaging/AppRun" "$APPDIR/AppRun"
cp "$SCRIPT_DIR/packaging/lynis-webui.desktop" "$APPDIR/lynis-webui.desktop"
cp "$SCRIPT_DIR/packaging/lynis-webui.png" "$APPDIR/lynis-webui.png"
chmod +x "$APPDIR/AppRun" "$APPDIR/usr/bin/$BACKEND_NAME"

APPIMAGETOOL="$BUILD_DIR/appimagetool"
if [ ! -x "$APPIMAGETOOL" ]; then
  echo "==> Downloading appimagetool"
  curl -L \
    "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-${ARCH}.AppImage" \
    -o "$APPIMAGETOOL"
  chmod +x "$APPIMAGETOOL"
fi

echo "==> Packing AppImage"
if ! ARCH="$ARCH" "$APPIMAGETOOL" "$APPDIR" "$DIST_DIR/$APPIMAGE_NAME"; then
  echo "Direct execution of appimagetool failed (often a missing-FUSE issue in" >&2
  echo "sandboxed/CI environments). Retrying with --appimage-extract-and-run..." >&2
  ARCH="$ARCH" "$APPIMAGETOOL" --appimage-extract-and-run "$APPDIR" "$DIST_DIR/$APPIMAGE_NAME"
fi

chmod +x "$DIST_DIR/$APPIMAGE_NAME"
echo "==> Done: $DIST_DIR/$APPIMAGE_NAME"
