# Reproducible builds

Groundwork toward bit-for-bit reproducible binaries, so a third party can rebuild
a KARST release from source and confirm it matches the published artifact — no
trust in the build machine required. README Principle 7 already names this as a
real, honest tradeoff; this is the concrete progress and its current limits.

## What is pinned now

- **Toolchain** — `impl/rust-toolchain.toml` pins `channel = "1.97.0"`. A floating
  `stable` would silently change the compiler between builds; the pin means local,
  CI, and a verifier all use the same rustc. CI installs the same version
  (`dtolnay/rust-toolchain@1.97.0`).
- **Dependencies** — `impl/Cargo.lock` is committed, so the exact dependency graph
  is fixed (not resolved fresh per build).
- **Codegen determinism** — `[profile.release] codegen-units = 1`. Parallel
  codegen units can reorder emitted code run-to-run; one unit removes that source.

## Remaining sources of nondeterminism (and how to close them)

1. **Build paths.** rustc embeds absolute source paths (panic messages, debug
   info), so a verifier building under a different checkout dir would otherwise get
   different bytes. Closed by `scripts/build-reproducible.sh`, which sets
   `RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=$CARGO_HOME=/cargo"`
   — mapping BOTH the checkout dir and the cargo registry to fixed strings, so every
   builder embeds the same `/build` and `/cargo` paths regardless of where they are.
   (Not `.cargo/config.toml`: the `from` sides are `$PWD`/`$CARGO_HOME`, which config
   values can't expand — so it lives in the script, which is the thing to run.)
   `trim-paths` would be cleaner but is still nightly-only on the pinned 1.97.0.
   The std sysroot path (`/rustc/<hash>/…`) is already fixed by the pinned toolchain.
2. **The Tauri desktop bundle — NOT reproducible yet, stated plainly.** The `.deb`/
   `.AppImage`/`.dmg` packaging embeds timestamps and packer metadata, and bundles a
   webview build; achieving bit-for-bit there is materially harder than for a plain
   Rust binary. For now, reproducibility targets the **CLI and relay** binaries
   (`karst`, `karst-relay`); the desktop bundle is a known gap, not a silent one.

## Verification procedure (CLI / relay binaries)

```sh
git checkout <release-tag>
impl/scripts/build-reproducible.sh
# prints the sha256 of target/release/{karst,karst-relay} — compare to the published checksums.
```

The script uses `--locked`, which fails if `Cargo.lock` would change — proof the
dependency graph is the one that was published.

**This is verified, not asserted.** Running `scripts/build-reproducible.sh` in two
DIFFERENT absolute paths (`/home/…/impl` and `/tmp/…/impl`) produced **byte-
identical** binaries — confirmed 2026-07-19:

```
1b88016dd72efdb0ec5fa93012a293e19921998d162c10cb6b41081a91655a1f  karst
7c6abd01043bc1d7be2e4eba75c78888681ccf365e6eac2b7a544f81fe0943cb  karst-relay
```

(Those exact hashes are the current `main` at that commit; they move with the
source. The point is that TWO independent builds agreed.) Re-check any time by
running the script in two paths and diffing the hashes. A per-PR CI job that
builds twice was considered and deliberately skipped: it would double the (already
codegen-units=1-slow) release build on every push for marginal regression cover,
since the mechanism is deterministic and the script makes re-verification a
one-liner. Run it before cutting a release, and publish the hashes with it.

## Relationship to signed releases

Reproducibility and signing are complementary: a signature proves *who* built it,
reproducibility proves the binary matches the *public source*. Signed releases are
tracked separately (backlog #7); this note is the "matches the source" half.
