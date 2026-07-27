#!/usr/bin/env bash
# Shared functions for the KARST run scripts. Source of truth for binary
# locations and for waiting until the relay is ready.
#
# NOT for production — brings up a SKELETON relay (a dev capability with a public
# secret).

set -euo pipefail

# Repository root (this file lives in scripts/).
KARST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KARST_IMPL="$KARST_ROOT/impl"

# Build the needed binaries (relay + CLI + GUI). Idempotent, fast incremental.
karst_build() {
  cargo build --manifest-path "$KARST_IMPL/Cargo.toml" \
    -p node --bin karst-relay \
    -p client --bin karst \
    -p gui --bin karst-gui
}

karst_bin() { echo "$KARST_IMPL/target/debug/$1"; }

# Release build (for the installers). `$@` = extra cargo args (which -p/--bin).
karst_build_release() {
  cargo build --release --manifest-path "$KARST_IMPL/Cargo.toml" "$@"
}

karst_bin_release() { echo "$KARST_IMPL/target/release/$1"; }

# Install $1 → $2 ATOMICALLY. Safe to run while $2 is currently executing (the
# update-while-running case): write a sibling temp then rename in place, so a
# running process keeps the old inode instead of hitting ETXTBSY / "Text file busy".
karst_install_bin() {
  local src="$1" dest="$2"
  install -m 0755 "$src" "$dest.new"
  mv -f "$dest.new" "$dest"
}

# Best-effort check that a build toolchain is present; exits with guidance if not.
karst_require_toolchain() {
  if ! command -v cargo >/dev/null 2>&1; then
    echo "error: 'cargo' not found. Install Rust (stable) via https://rustup.rs:" >&2
    echo "       curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" >&2
    exit 1
  fi
  if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
    echo "error: no C compiler (cc/gcc) found — a few native deps need one." >&2
    echo "       Debian/Ubuntu: sudo apt install build-essential" >&2
    exit 1
  fi
}

# Warn (don't fail) if $1 is not on the user's PATH.
karst_warn_if_not_on_path() {
  case ":$PATH:" in
    *":$1:"*) : ;;
    *) echo "note: $1 is not on your PATH. Add it, e.g.:"
       echo "      echo 'export PATH=\"$1:\$PATH\"' >> ~/.profile && . ~/.profile" ;;
  esac
}

# Wait until HOST:PORT starts accepting connections (bind complete).
# Returns 0 on success, 1 on timeout (~200 attempts, no sleep).
karst_wait_port() {
  local addr="$1" host port
  host="${addr%:*}"; port="${addr##*:}"
  local i
  for i in $(seq 1 200); do
    if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
      exec 3>&- || true
      return 0
    fi
  done
  return 1
}

# Extract the relay-id from the relay log (printed as the line "relay-id <hex>").
karst_relay_id_from_log() {
  grep -oE 'relay-id [0-9a-f]+' "$1" | awk '{print $2}' | tail -1
}
