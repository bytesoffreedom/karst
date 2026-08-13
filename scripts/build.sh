#!/usr/bin/env bash
# build.sh — build everything KARST ships, from a fresh checkout, in one command.
#
#   scripts/build.sh              # relay + CLI + desktop client (release)
#   scripts/build.sh --no-gui     # relay + CLI only (headless machine / server)
#   scripts/build.sh --check      # also run the test suite and clippy
#
# This BUILDS; it does not install and does not run anything. To install into your
# user bin directory use scripts/install-karst.sh (client) or scripts/install-node.sh
# (relay); to see the whole system working locally use scripts/karst-demo.sh.
#
# Reference build, LINUX, and NOT for production: the cryptography is an unaudited
# reference implementation. See docs/STATUS.md.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

GUI=1
CHECK=0
for a in "$@"; do
  case "$a" in
    --no-gui) GUI=0 ;;
    --check)  CHECK=1 ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a (try --help)" >&2; exit 2 ;;
  esac
done

command -v cargo >/dev/null || {
  echo "error: cargo not found. Install Rust: https://rustup.rs" >&2
  exit 1
}

# The desktop client links WebKitGTK and GTK. Say so HERE rather than letting the user
# read three hundred lines of linker output and guess which -dev package is missing.
if [ "$GUI" = 1 ] && ! pkg-config --exists webkit2gtk-4.1 2>/dev/null; then
  cat >&2 <<'MSG'
error: the desktop client needs WebKitGTK + GTK development libraries.

  Debian / Ubuntu:
    sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev \
                     libjavascriptcoregtk-4.1-dev librsvg2-dev build-essential pkg-config
  Fedora:
    sudo dnf install webkit2gtk4.1-devel gtk3-devel libsoup3-devel librsvg2-devel

Or build without it:  scripts/build.sh --no-gui
MSG
  exit 1
fi

echo "== building relay + CLI =="
karst_build_release -p relay --bin karst-relay -p client --bin karst

if [ "$GUI" = 1 ]; then
  echo "== building desktop client =="
  karst_build_release -p desktop --bin karst-desktop
fi

if [ "$CHECK" = 1 ]; then
  echo "== clippy =="
  cargo clippy --manifest-path "$KARST_IMPL/Cargo.toml" --all-targets -- -D warnings
  echo "== tests =="
  cargo test --manifest-path "$KARST_IMPL/Cargo.toml"
fi

OUT="$(karst_target_dir)/release"
echo
echo "built:"
for b in karst-relay karst $( [ "$GUI" = 1 ] && echo karst-desktop ); do
  # Report what is actually on disk rather than what was asked for — a build that
  # silently produced nothing should not print a success list.
  if [ -x "$OUT/$b" ]; then
    printf '  %-14s %s\n' "$b" "$OUT/$b"
  else
    echo "  MISSING: $b — the build reported success but the binary is not there" >&2
    exit 1
  fi
done
echo
echo "next:  scripts/karst-demo.sh      run the whole system locally, end to end"
echo "       scripts/install-karst.sh   install the client into your PATH"
echo "       scripts/install-node.sh    install a relay (interactive)"
