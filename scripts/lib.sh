#!/usr/bin/env bash
# Shared functions for the KARST run scripts. Source of truth for binary
# locations and for waiting until the relay is ready.
#
# NOT for production — brings up a REFERENCE relay (a dev capability with a public
# secret).

set -euo pipefail

# Repository root (this file lives in scripts/).
KARST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KARST_IMPL="$KARST_ROOT/impl"

# Build the needed binaries (relay + CLI). Idempotent, fast incremental.
# The desktop GUI is the Tauri client (`impl/desktop`) and is built separately.
# The relay binary lives in the `relay` crate, NOT in `node`: `node` is the wire protocol both
# sides speak, `relay` is the server that must not be linked by a client (#143). Naming the wrong
# crate here does not fail at review, it fails at `cargo build` for whoever runs a demo script.
karst_build() {
  cargo build --manifest-path "$KARST_IMPL/Cargo.toml" \
    -p relay --bin karst-relay \
    -p client --bin karst
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
# Wait for `host:port` to accept a connection, up to ~20 s.
#
# The loop used to run 200 attempts with NO delay between them, which finishes in a few
# milliseconds — long before any relay can bind — so every script that waits on a fresh relay
# failed on a cold start and looked like the relay was broken. A retry loop without a sleep is
# not a wait, it is a very fast way to give up.
karst_wait_port() {
  local addr="$1" host port
  host="${addr%:*}"; port="${addr##*:}"
  local i
  for i in $(seq 1 200); do
    if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
      exec 3>&- || true
      return 0
    fi
    sleep 0.1
  done
  return 1
}

# Extract the relay-id from the relay log (printed as the line "relay-id <hex>").
# Pull the relay-id out of a relay's startup log.
#
# The relay prints it inside an aligned box (`│  relay-id        <hex>`), so the separator is
# RUN of spaces, not one. The old pattern required exactly one and therefore matched nothing —
# and because the caller assigns through a pipeline under `set -e -o pipefail`, the empty grep
# killed the script before the "could not read relay-id" guard could say so. Every demo script
# died silently right after starting a relay that was working perfectly.
#
# `|| true` so a miss returns empty and the CALLER's guard is what reports it, in words.
karst_relay_id_from_log() {
  grep -oE 'relay-id[[:space:]]+[0-9a-f]{16,}' "$1" | awk '{print $2}' | tail -1 || true
}

# Wait until the relay-id has actually been PRINTED, and return it.
#
# `karst_wait_port` is not a substitute, and CI proved it: the relay binds its listener before it
# writes the startup banner, and the relay-id sits in the connect box that is deliberately printed
# LAST. So the port answers while the log is still half-written, and a caller that reads the log the
# moment the port opens gets an empty id — then dies several steps later with "relay-id должен быть
# 64 байта, дано 0", which points at the client rather than at the race that caused it.
#
# This lost on a loaded runner while passing on every developer machine, which is the signature of a
# race being decided by timing rather than by correctness.
karst_wait_relay_id() {
  local log="$1" i rid=""
  for i in $(seq 1 200); do          # 200 × 0.1s = 20s, the same budget as karst_wait_port
    rid="$(karst_relay_id_from_log "$log")"
    if [ -n "$rid" ]; then printf '%s' "$rid"; return 0; fi
    sleep 0.1
  done
  return 1
}
