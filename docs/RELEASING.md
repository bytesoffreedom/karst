# Releasing

How a KARST release is cut, signed, and verified. Two layers, in order of strength:

1. **Reproducibility** (the strong one) — anyone can rebuild the binaries from the
   tagged source and confirm they match, trusting no build machine and no
   signature. See `docs/design/reproducible-builds.md`.
2. **A minisign signature** (for people who download the prebuilt binaries instead
   of rebuilding) — proves the artifact came from the maintainer's key.

The signature is the weaker layer and it does NOT cover a backdoored build (a
signed-but-malicious binary is still validly signed); only reproducibility +
independent rebuilders catch that. So the signature serves non-builders and anchors
"binary transparency"; the real assurance is rebuild-and-compare.

## One-time key setup (maintainer)

The release workflow (`.github/workflows/release.yml`) signs the checksums with a
minisign key stored as a repo secret.

```sh
# Generate a PASSWORDLESS minisign key (see the note below on why passwordless).
minisign -W -G -p minisign.pub -s minisign.key

# 1. Put the SECRET key's contents into a repo secret named MINISIGN_SECRET_KEY:
#    GitHub → repo → Settings → Secrets and variables → Actions → New secret.
cat minisign.key   # paste the whole file (both lines) as the secret value

# 2. Publish the PUBLIC key so users can verify. Put its one line in the README
#    (the "Verify a release" section) AND, redundantly, on karstmessenger.net and
#    the Telegram channel — a single publication point is a single thing to swap.
cat minisign.pub

# 3. Keep minisign.key OFFLINE (a hardware token / password manager). It is now
#    also in a GitHub secret; if you ever suspect the repo or CI is compromised,
#    rotate it: generate a new pair, update the secret + README, and re-sign.
```

**Why passwordless?** A password would have to live in a second repo secret, so it
leaks together with the key on a GitHub compromise — it adds no security in this
storage model, only friction. The key's protection here IS the repo's secret +
access controls. The stronger-but-manual alternative (sign LOCALLY with an
offline/hardware key, never putting it in GitHub) is noted in
`docs/design/reproducible-builds.md`; the maintainer chose the GitHub-secret model
for automation. Either way, reproducibility is the layer that does not depend on
the key.

## Pre-release checklist

Run through this before tagging. Green means the tag is safe to push.

- [ ] `cd impl && cargo test` passes (default) **and** `cargo test --features unaudited-crypto`; `cargo clippy --all-targets` is clean.
- [ ] **Live smoke:** `scripts/karst-demo.sh` prints the both-directions exchange + file transfer; a `public` relay starts and `karst-relay pow status` answers; the desktop UI launches (`karst-desktop`). See [RUNNING.md](RUNNING.md).
- [ ] **[STATUS.md](STATUS.md) reconciled with the code** — test counts, feature maturity, and any "not yet built / walled" notes match reality (the code is the source of truth; fix STATUS, not the reverse).
- [ ] **Reproducibility verified:** run `impl/scripts/build-reproducible.sh` in **two** different absolute paths and confirm the two `karst`/`karst-relay` sha256s are **identical** (see [design/reproducible-builds.md](design/reproducible-builds.md)).
- [ ] `Cargo.lock` committed; version bumped where applicable.
- [ ] **minisign key ready** (one-time, see above): the `MINISIGN_SECRET_KEY` repo secret is set and the **public** key is pasted into the README's "Verify a release" placeholder. Without this the release workflow fails closed.
- [ ] The `--features unaudited-crypto` primitives are still **off by default** and labelled as unaudited in STATUS.

## Cutting a release

```sh
# On main, with a clean tree and Cargo.lock committed:
git tag v0.1.0
git push origin v0.1.0
```

The `release` workflow then: runs `scripts/build-reproducible.sh` (pinned
toolchain, `--locked`, path-remapped → byte-identical for anyone), writes
`SHA256SUMS`, signs it with minisign, and publishes a GitHub Release with the two
binaries, `SHA256SUMS`, and `SHA256SUMS.minisig`.

The release binaries are the SAME bytes a verifier gets from the script, so the
published `SHA256SUMS` doubles as the reproducibility reference.

## Verifying a release (users)

```sh
# 1. The checksums are signed by the KARST key (public key from the README):
minisign -Vm SHA256SUMS -P <KARST_MINISIGN_PUBLIC_KEY>
# 2. The binaries match the checksums:
sha256sum -c SHA256SUMS
```

Or — the strongest — rebuild and compare, trusting neither this release nor the
signature:

```sh
git checkout v0.1.0
impl/scripts/build-reproducible.sh   # prints the same sha256s as SHA256SUMS
```
