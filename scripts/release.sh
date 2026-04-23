#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
TARGET_DEB_DIR="$ROOT_DIR/target/deb"
FLATPAK_BUILD_DIR="$ROOT_DIR/build-flatpak"
FLATPAK_REPO_DIR="$ROOT_DIR/target/flatpak-repo"
FLATPAK_BUNDLE_NAME="io.github.wireguard_gui.flatpak"

DO_DEB=1
DO_FLATPAK=1

usage() {
  cat <<'EOF'
Usage: ./scripts/release.sh [--deb-only|--flatpak-only]

Builds release artifacts and writes them to ./dist:
  - wireguard-gui_<version>_<arch>.deb
  - io.github.wireguard_gui.flatpak
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deb-only)
      DO_DEB=1
      DO_FLATPAK=0
      shift
      ;;
    --flatpak-only)
      DO_DEB=0
      DO_FLATPAK=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

mkdir -p "$DIST_DIR"

if [[ "$DO_DEB" -eq 1 ]]; then
  echo "==> Building Debian package"
  "$ROOT_DIR/scripts/build-deb.sh"
  latest_deb="$(ls -1t "$TARGET_DEB_DIR"/wireguard-gui_*.deb | head -n 1)"
  cp -f "$latest_deb" "$DIST_DIR/"
  echo "done: $DIST_DIR/$(basename "$latest_deb")"
fi

if [[ "$DO_FLATPAK" -eq 1 ]]; then
  echo "==> Building Flatpak bundle"
  if ! command -v flatpak-builder >/dev/null 2>&1; then
    echo "error: flatpak-builder not found. Install flatpak-builder."
    exit 1
  fi
  if ! flatpak info org.gnome.Sdk//47 >/dev/null 2>&1 || \
     ! flatpak info org.gnome.Platform//47 >/dev/null 2>&1 || \
     ! flatpak info org.freedesktop.Sdk.Extension.rust-stable//24.08 >/dev/null 2>&1; then
    echo "error: required Flatpak runtimes/SDK extensions are missing."
    echo "Install them with:"
    echo "  flatpak install -y flathub org.gnome.Platform//47 org.gnome.Sdk//47 org.freedesktop.Sdk.Extension.rust-stable//24.08"
    exit 1
  fi
  rm -rf "$FLATPAK_BUILD_DIR" "$FLATPAK_REPO_DIR"
  flatpak-builder --force-clean --repo="$FLATPAK_REPO_DIR" "$FLATPAK_BUILD_DIR" "$ROOT_DIR/io.github.wireguard_gui.json"
  flatpak build-bundle "$FLATPAK_REPO_DIR" "$DIST_DIR/$FLATPAK_BUNDLE_NAME" io.github.wireguard_gui
  echo "done: $DIST_DIR/$FLATPAK_BUNDLE_NAME"
fi

echo "==> Artifacts in $DIST_DIR"
ls -lh "$DIST_DIR"
