#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "error: dpkg-deb not found. Install dpkg-dev."
  exit 1
fi

VERSION="$(python3 - <<'PY'
import pathlib, re
text = pathlib.Path("Cargo.toml").read_text(encoding="utf-8")
m = re.search(r"^version\s*=\s*\"([^\"]+)\"", text, re.MULTILINE)
if not m:
    raise SystemExit("could not parse version from Cargo.toml")
print(m.group(1))
PY
)"
ARCH="$(dpkg --print-architecture)"
PKG_NAME="wireguard-gui"
BUILD_ROOT="$ROOT_DIR/target/deb/${PKG_NAME}_${VERSION}_${ARCH}"
PKG_PATH="$ROOT_DIR/target/deb/${PKG_NAME}_${VERSION}_${ARCH}.deb"

echo "==> Building release binaries"
cargo build --release -p wireguard-gui -p wireguard-gui-helper

echo "==> Preparing package tree"
rm -rf "$BUILD_ROOT"
mkdir -p \
  "$BUILD_ROOT/DEBIAN" \
  "$BUILD_ROOT/usr/local/bin" \
  "$BUILD_ROOT/usr/libexec" \
  "$BUILD_ROOT/usr/share/applications" \
  "$BUILD_ROOT/usr/share/icons/hicolor/scalable/apps" \
  "$BUILD_ROOT/usr/share/metainfo" \
  "$BUILD_ROOT/etc/polkit-1/rules.d"

install -Dm755 "target/release/wireguard-gui" "$BUILD_ROOT/usr/local/bin/wireguard-gui"
install -Dm755 "target/release/wireguard-gui-helper" "$BUILD_ROOT/usr/libexec/wireguard-gui-helper"
install -Dm644 "data/io.github.wireguard_gui.desktop" "$BUILD_ROOT/usr/share/applications/io.github.wireguard_gui.desktop"
install -Dm644 "data/icons/hicolor/scalable/apps/io.github.wireguard_gui.svg" "$BUILD_ROOT/usr/share/icons/hicolor/scalable/apps/io.github.wireguard_gui.svg"
install -Dm644 "data/io.github.wireguard_gui.metainfo.xml" "$BUILD_ROOT/usr/share/metainfo/io.github.wireguard_gui.metainfo.xml"
install -Dm644 "data/polkit/30-wireguard-gui.rules" "$BUILD_ROOT/etc/polkit-1/rules.d/30-wireguard-gui.rules"

cat > "$BUILD_ROOT/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: WireGuard GUI Maintainers <maintainers@example.com>
Depends: libc6, libgtk-4-1, libadwaita-1-0, wireguard-tools, policykit-1
Description: GTK WireGuard tunnel manager using wg-quick
 A desktop app to create, import, edit, connect, and disconnect file-based
 WireGuard tunnels under /etc/wireguard via a Polkit-gated helper.
EOF

echo "==> Building .deb"
dpkg-deb --build --root-owner-group "$BUILD_ROOT" "$PKG_PATH"

echo "done: $PKG_PATH"
