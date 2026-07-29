#!/usr/bin/env bash
# Reproducible build of the CLI (`karst`) + relay (`karst-relay`) binaries. Anyone who runs
# this on the pinned toolchain (rust-toolchain.toml) with the committed Cargo.lock gets
# byte-identical binaries regardless of WHERE they checked the repo out — the two absolute
# paths that would otherwise leak into the binary (this checkout, the cargo registry) are
# remapped to fixed strings. Verify a published release by diffing these hashes.
set -euo pipefail
cd "$(dirname "$0")/.."   # the impl/ workspace root
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=$CARGO_HOME=/cargo"
cargo build --release --locked -p client -p relay
sha256sum target/release/karst target/release/karst-relay
