#!/usr/bin/env bash
# install-karst.sh — build and install the KARST messenger (the CLI `karst` and the
# desktop client `karst-desktop`) into your user bin directory. Re-run any time after
# a `git pull` to update to the latest build.
#
#   scripts/install-karst.sh              # install the CLI + the Tauri desktop
#   KARST_BIN_DIR=/some/dir scripts/install-karst.sh
#   scripts/install-karst.sh --egui       # install the legacy egui client instead
#   scripts/install-karst.sh --no-gui     # CLI only (headless machine)
#
# Reference build, LINUX DESKTOP, and NOT for production: the cryptography is an
# unaudited reference implementation (see docs/STATUS.md). This installs YOUR
# client; to run a relay node, use scripts/install-node.sh instead.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

BINDIR="${KARST_BIN_DIR:-$HOME/.local/bin}"
WANT_GUI=1
GUI_KIND=desktop   # the Tauri desktop is the shipping client; `--egui` picks the legacy one
for a in "$@"; do
  case "$a" in
    --no-gui) WANT_GUI=0 ;;
    --egui) GUI_KIND=egui ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done

echo "== KARST messenger installer =="
echo "   Reference build, unaudited crypto — see docs/STATUS.md. Not for production."
echo
karst_require_toolchain

# Both GUIs need a graphical session at RUN time; warn if clearly headless.
if [ "$WANT_GUI" = 1 ] && [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
  echo "note: no DISPLAY/WAYLAND_DISPLAY detected — the GUI needs a graphical session"
  echo "      to RUN (it still builds fine here). Use --no-gui on a pure server."
fi

# The Tauri desktop needs WebKitGTK + GTK dev libraries to BUILD. Fail early with a
# clear hint rather than deep in a cargo error — or point at the egui client.
if [ "$WANT_GUI" = 1 ] && [ "$GUI_KIND" = desktop ] && ! pkg-config --exists webkit2gtk-4.1 2>/dev/null; then
  echo "error: the Tauri desktop needs WebKitGTK + GTK dev libraries to build." >&2
  echo "  Debian/Ubuntu: sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev \\" >&2
  echo "                 libsoup-3.0-dev libjavascriptcoregtk-4.1-dev librsvg2-dev" >&2
  echo "  Or install the legacy egui client instead: scripts/install-karst.sh --egui" >&2
  exit 1
fi

echo "Building release binaries (this can take several minutes the first time)…"
if [ "$WANT_GUI" = 0 ]; then
  karst_build_release -p client --bin karst
elif [ "$GUI_KIND" = egui ]; then
  karst_build_release -p client --bin karst -p gui --bin karst-gui
else
  karst_build_release -p client --bin karst -p desktop --bin karst-desktop
fi

mkdir -p "$BINDIR"
karst_install_bin "$(karst_bin_release karst)" "$BINDIR/karst"
echo "installed: $BINDIR/karst"

if [ "$WANT_GUI" = 1 ]; then
  if [ "$GUI_KIND" = egui ]; then
    GUI_BIN=karst-gui
  else
    GUI_BIN=karst-desktop
  fi
  karst_install_bin "$(karst_bin_release "$GUI_BIN")" "$BINDIR/$GUI_BIN"
  echo "installed: $BINDIR/$GUI_BIN"

  # A desktop launcher, best-effort (only where a desktop applications dir applies).
  APPS="$HOME/.local/share/applications"
  if mkdir -p "$APPS" 2>/dev/null; then
    cat >"$APPS/karst.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=KARST
Comment=Experimental private messenger with post-quantum encryption (reference build)
Exec=$BINDIR/$GUI_BIN
Terminal=false
Categories=Network;InstantMessaging;
DESKTOP
    echo "installed: $APPS/karst.desktop (app menu launcher)"
  fi
fi

karst_warn_if_not_on_path "$BINDIR"

cat <<NEXT

Done.

  GUI:  run '${GUI_BIN:-karst-desktop}' (or launch "KARST" from your app menu). First
        run creates an account — write down the 12-word recovery phrase. The network
        fields (relay address + relay-id) are prefilled from KARST_RELAY /
        KARST_RELAY_ID if set. Optional carriers: KARST_SOCKS5 (Tor/obfs4), KARST_WSS
        (look like HTTPS). Backup relays for multi-homing are configured in-app
        (Settings → Network & relays). See the README env table for the full list.
  CLI:  run 'karst' — 'karst init' prints your recovery phrase + address.
        'karst files' / 'karst export-file <id>' list and decrypt received files.

You still need a relay to reach anyone: run your own (scripts/install-node.sh) or
use someone else's address + relay-id.
NEXT
