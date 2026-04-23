# WireGuard GUI

A GTK 4 / libadwaita desktop application for **Linux Mint 22.x** (and other modern distributions) that manages **file-based** WireGuard tunnels under `/etc/wireguard` using `wg-quick`. Privileged work is done by a small helper invoked through **`pkexec`** (Polkit).

## Features

- List tunnels from `/etc/wireguard/*.conf` and live `wg` / `ip` state  
- Connect / disconnect (`wg-quick up` / `down`)  
- Create new tunnels (keys generated on the helper)  
- Import existing `.conf` files  
- Delete tunnels (brings interface down, then removes the config)  
- Peer handshake time and transfer counters when an interface is up  

## Build (Rust)

Install build dependencies on **Linux Mint 22.3** (Ubuntu 24.04 base):

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libgtk-4-dev libadwaita-1-dev wireguard wireguard-tools
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

From the repository root:

```bash
cargo build --release
```

Binaries are written to `target/release/wireguard-gui` and `target/release/wireguard-gui-helper`.

## Install (system-wide)

```bash
sudo install -Dm755 target/release/wireguard-gui-helper /usr/libexec/wireguard-gui-helper
sudo install -Dm755 target/release/wireguard-gui /usr/local/bin/wireguard-gui
sudo install -Dm644 data/io.github.wireguard_gui.desktop /usr/share/applications/io.github.wireguard_gui.desktop
sudo install -Dm644 data/icons/hicolor/scalable/apps/io.github.wireguard_gui.svg /usr/share/icons/hicolor/scalable/apps/io.github.wireguard_gui.svg
sudo install -Dm644 data/io.github.wireguard_gui.metainfo.xml /usr/share/metainfo/io.github.wireguard_gui.metainfo.xml
sudo install -Dm644 data/polkit/30-wireguard-gui.rules /etc/polkit-1/rules.d/30-wireguard-gui.rules
```

## Debian package (.deb)

Build a local `.deb` package:

```bash
chmod +x scripts/build-deb.sh
./scripts/build-deb.sh
```

The package is written to `target/deb/wireguard-gui_<version>_<arch>.deb`.

Install it:

```bash
sudo apt install ./target/deb/wireguard-gui_*.deb
```

## Unified release artifacts

Build both `.deb` and Flatpak bundle into `dist/`:

```bash
chmod +x scripts/build-deb.sh scripts/release.sh
./scripts/release.sh
```

Optional:

```bash
./scripts/release.sh --deb-only
./scripts/release.sh --flatpak-only
```

Generated build output is intentionally ignored by git (`dist/`, `.flatpak-builder/`, `scripts/.flatpak-builder/`, and `build-flatpak/`) and should not be committed.

The GUI looks for the helper in this order:

1. Environment variable `WIREGUARD_GUI_HELPER` (full path)  
2. `wireguard-gui-helper` next to the `wireguard-gui` executable  
3. `/usr/libexec/wireguard-gui-helper`  

## Polkit / `pkexec`

Each privileged operation uses `pkexec`. This repository includes a scoped Polkit rule (`data/polkit/30-wireguard-gui.rules`) that uses `AUTH_ADMIN_KEEP` for `/usr/libexec/wireguard-gui-helper`, so users authenticate once and get fewer repeated prompts. Details: [data/polkit/README.md](data/polkit/README.md).

## Flatpak

Build and install from the included manifest:

```bash
sudo apt install -y flatpak flatpak-builder
flatpak install -y flathub org.gnome.Platform//47 org.gnome.Sdk//47 org.freedesktop.Sdk.Extension.rust-stable//24.08
flatpak-builder --user --force-clean build-flatpak io.github.wireguard_gui.json
flatpak-builder --user --install --force-clean build-flatpak io.github.wireguard_gui.json
```

Run:

```bash
flatpak run io.github.wireguard_gui
```

Notes:
- The manifest installs `wireguard-gui-helper` next to the app binary inside Flatpak so helper discovery works.
- Managing host `wg-quick` from a Flatpak sandbox can still vary by distro policy; on Mint, native install is usually the smoothest path.

## Development

Run the helper as root to test JSON output without the GUI:

```bash
sudo ./target/debug/wireguard-gui-helper status
```

## License

GPL-3.0-or-later (see `Cargo.toml`).
