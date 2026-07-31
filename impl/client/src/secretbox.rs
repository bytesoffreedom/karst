//! At-rest encryption of the client's secrets.
//!
//! `Argon2id(passphrase, salt)` gives a master key (derived ONCE per process), and
//! `XChaCha20-Poly1305` uses a FRESH random 24-byte nonce on EVERY write.
//! A 192-bit nonce makes random freshness safe without a counter — which is critical, since
//! `sessions.dat` is rewritten on every send and receive under a FIXED key (a repeated nonce is a
//! keystream-reuse catastrophe).
//!
//! # What this protects — and what it does NOT (honestly):
//! It protects a **COLD disk**: a stolen laptop, a backup, a synced `~/.config`. It does NOT
//! protect a running process: a password in the environment is readable from `/proc/<pid>/environ`
//! on a live host, so the "a live receiving chain is on disk" hole is NOT closed under a HOT
//! compromise. The claim is cold-disk only.
//!
//! # Format v2: context, not one key for everything
//!
//! The blob is `MAGIC(4) ‖ state_version(2 LE) ‖ nonce(24) ‖ AEAD ciphertext`, where the key is NOT
//! the master key but `HKDF(master, label)`, and `label` (the logical file name inside the account)
//! plus the version go into the AAD.
//!
//! Previously every file of every account was encrypted with ONE key and no AAD (CRYPTO-05): an
//! adversary with disk access could swap one account's `contacts.dat` for another's, or
//! `sessions.dat` in place of `net.dat` — everything decrypted normally, because the ciphertext was
//! bound to nothing about where it lay. Now it is bound: different `label`s give different keys (a
//! foreign file simply does not open), and the AAD catches the case where two key derivations ever
//! coincide.
//!
//! `state_version` is the version of the state SCHEMA, not a magic value (A6-5). The magic catches
//! an envelope-format change once; the version must rise on every change to the structures
//! serialised into it, so that an old binary meeting a higher version fails LOUDLY instead of
//! "reading it with defaults" and writing it back.

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// The version prefix: bump it when the ENVELOPE format changes (not the state schema).
pub(crate) const MAGIC: &[u8; 4] = b"KRS2";

/// The version of the state SCHEMA. Raise it on ANY change to the structures serialised under this
/// envelope (`Prefs`, `ContactRecord`, `SessionSnapshot`, `PendingUpload`, …).
///
/// Why it is separate from the magic: postcard is positional, and `serde(default)` on a trailing
/// field makes an old binary ACCEPT a new file, substitute defaults and write it back, so the new
/// fields silently disappear (A6-5). Such a file is now unreadable instead: "not KARST". The
/// downside is deliberate: raising the version BREAKS existing local data. There are no users and
/// no migrations (see docs/POSITIONING.md), so breaking it now is free.
/// v5: the one-time prekey secrets moved INSIDE the session state file so the pair commits in
/// one durable write (CRYPTO-26) — `sessions.dat` now holds `(generation, state, opks)` and
/// `opks.dat` is gone. v6: the recovery phrase widened to 24 words, so the seed file is 32 bytes
/// (CRYPTO-32). v7: `PeerState` carries the drop-box epoch high-water mark (A6-8). v8: a one-time
/// prekey is one UNIT — the X25519 secret plus its ML-KEM seed (CRYPTO-33) — so the `opks` entries
/// inside `sessions.dat` went from 32 to 96 bytes, and `capabilities.dat` keys per (relay, channel)
/// rather than per relay (A8-4). v9: `PeerState` carries the drop-box sweep cursor (#147).
///
/// The v7→v8 case is exactly what this version exists for. Postcard is not self-describing: an old
/// `opks` vector is `varint(N) ‖ 32N` and the new decoder reads `N` then demands `96N`, so without
/// the version the file surfaces as "secrets unreadable" — which this store deliberately treats as
/// a loud, wedging error telling the user to delete and re-provision. With it, the failure names
/// itself: written by an older KARST.
pub const STATE_VERSION: u16 = 11;

/// The pinned Argon2id cost parameters (see [`MasterKey::derive`]). Owned by KARST, not by the
/// `argon2` crate's defaults, so a dependency bump cannot silently change key derivation.
///
/// Raised in format v2 from 19 MiB / t=2 (CRYPTO-34). That was OWASP's *floor*, published as the
/// minimum for a memory-constrained environment — and this is a desktop application deriving ONE
/// key per unlock, which is the opposite of memory-constrained. Against an offline attacker
/// grinding the passphrase, the cost per guess is what buys time, and 19 MiB buys little from a
/// GPU. 128 MiB / t=3 is ~10x the memory-time product; measured ~0.2 s per derive in release on
/// this machine, i.e. still well inside "press unlock, see the app".
///
/// Deliberately NOT pushed to 256 MiB+: peak RSS during unlock is real, and a profile that a
/// low-RAM machine cannot run is a profile someone will quietly lower later.
///
/// HONEST LIMIT, since `STATE_VERSION` might imply otherwise: a KDF change cannot produce the
/// loud "written by an older/newer KARST" error. That message lives INSIDE the sealed blob, and
/// reading it needs the right key — which is exactly what a changed profile no longer derives. So
/// raising this constant makes existing local data fail as "wrong password", the misleading
/// shape we remove everywhere else. It is unavoidable here: the deniable container has no
/// plaintext header to carry a profile id, and adding one would be a tell. Version bumps of the
/// KDF are therefore release-note events, not self-describing ones.
pub const KDF_M_COST: u32 = 131_072; // KiB (128 MiB)
pub const KDF_T_COST: u32 = 3;
pub const KDF_P_COST: u32 = 1;

/// TEST-ONLY escape hatch, compiled out of release builds entirely.
///
/// A conservative KDF is expensive by construction, and the suite derives keys ~150 times in
/// tests that are not about the KDF at all — at the production profile that is minutes of CI per
/// run, which is how profiles end up quietly lowered "just for now". So `debug` builds honour
/// `KARST_INSECURE_FAST_KDF=1` and derive with Argon2's minimum cost instead.
///
/// The guarantee is structural, and deliberately NOT expressed as a test: a test would have to
/// mutate the process environment, which in a parallel test binary changes the KDF under every
/// other thread. `cfg(debug_assertions)` is checked by the compiler on every release build,
/// which is stronger than an assertion anyway. The branch sits behind it,
/// so a release binary does not contain it and no environment variable can reach it. When it IS
/// taken it says so on stderr every time, so a vault created under it can never be mistaken for
/// a real one. The production profile itself is still exercised — see
/// `the_production_kdf_profile_is_what_we_think_it_is`.
#[cfg(debug_assertions)]
const FAST_KDF_ENV: &str = "KARST_INSECURE_FAST_KDF";
const NONCE_LEN: usize = 24;
/// `MAGIC(4) ‖ state_version(2) ‖ nonce(24)`.
const HEADER_LEN: usize = 4 + 2 + NONCE_LEN;

/// A fresh 16-byte salt (not a secret; unique per installation, written in plaintext).
pub fn random_salt() -> [u8; 16] {
    use chacha20poly1305::aead::rand_core::RngCore;
    let mut s = [0u8; 16];
    OsRng.fill_bytes(&mut s);
    s
}

/// The password-derived master key. Keep ONE per process (Argon2id is expensive) and reuse it for
/// every sealed file. `Clone` is cheap (32 bytes) — one vault key is handed to every account
/// (`Vault::account`), so switching costs nothing.
///
/// `ZeroizeOnDrop` (CRYPTO-09): the bytes are overwritten when the last copy goes away, so a key
/// does not outlive its owner in freed heap, a core dump, or a swapped-out page.
///
/// HONEST LIMIT, because zeroization is easy to overclaim: this covers the memory THIS value
/// owns at the moment it is dropped. Rust may have copied the key while moving it (a move is a
/// memcpy and the source is not scrubbed), the allocator may have handed the page on, and the OS
/// may have paged it out before any of this ran. Clones are still explicit and few on purpose —
/// the real bound is how many copies exist, and `Drop` is the floor under that, not a substitute.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    /// `Argon2id(passphrase, salt)` under the PINNED KARST profile. `salt` is NOT a secret (it lies
    /// beside the data in plaintext) but must be unique per installation (≥ 8 bytes). Expensive.
    ///
    /// The parameters are ours, not the library's. `Argon2::default()` used to decide them, which
    /// means a dependency bump that changes those defaults would silently derive a DIFFERENT key
    /// and make every existing vault and container unopenable with the correct password — a
    /// security-critical constant owned by someone else's changelog (CRYPTO-16). The values below
    /// are byte-for-byte what `Argon2::default()` produced at the time of pinning, proven by
    /// `the_pinned_kdf_profile_is_byte_identical_to_the_old_default`, so pinning changed nothing
    /// on disk. Changing them in future is a deliberate, versioned migration — not a side effect.
    pub fn derive(passphrase: &[u8], salt: &[u8]) -> Result<Self, String> {
        let mut key = [0u8; 32];
        Self::kdf()?
            .hash_password_into(passphrase, salt, &mut key)
            .map_err(|e| format!("argon2: {e}"))?;
        Ok(MasterKey(key))
    }

    /// The pinned KARST KDF profile: Argon2**id**, version 0x13, m=131072 KiB, t=3, p=1, 32-byte
    /// output. The container has no plaintext header to carry a profile id (that would be a tell
    /// for deniability), so the profile is normative per format version rather than stored.
    fn kdf() -> Result<Argon2<'static>, String> {
        #[cfg(debug_assertions)]
        if std::env::var_os(FAST_KDF_ENV).is_some() {
            eprintln!(
                "KARST: {FAST_KDF_ENV} is set — deriving keys with Argon2's MINIMUM cost. \
                 This is for the test suite. Anything created now is not protected at rest."
            );
            let params = argon2::Params::new(argon2::Params::MIN_M_COST, 1, 1, Some(32))
                .map_err(|e| format!("argon2 params: {e}"))?;
            return Ok(Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params));
        }
        let params = argon2::Params::new(KDF_M_COST, KDF_T_COST, KDF_P_COST, Some(32))
            .map_err(|e| format!("argon2 params: {e}"))?;
        Ok(Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params))
    }

    /// The PRODUCTION Argon2 instance, ignoring the debug fast-KDF hatch. Exists so one test can
    /// verify the shipped profile even when the suite runs with the hatch on.
    #[cfg(test)]
    fn kdf_production_only_for_tests() -> Argon2<'static> {
        let params = argon2::Params::new(KDF_M_COST, KDF_T_COST, KDF_P_COST, Some(32)).unwrap();
        Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
    }

    /// Wrap raw 32 bytes as a key (for keys carried INSIDE a sealed slot, e.g. the Tier-2
    /// container's per-region keys). Not derived from a password — the bytes are the key.
    pub(crate) fn from_bytes(k: [u8; 32]) -> Self {
        MasterKey(k)
    }

    /// The raw 32 key bytes (only for sealing a region key into a slot; never persisted plaintext).
    pub(crate) fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// The key for THIS `label` specifically — not the master key. A foreign file dropped in its
    /// place derives a different key and does not open (CRYPTO-05). `label` is a logical path
    /// inside the account (`acct:<id>/net/sessions.dat`), NOT a path on disk: moving the directory
    /// must break nothing.
    fn subkey(&self, label: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut info = Vec::with_capacity(20 + label.len());
        info.extend_from_slice(b"KARST-at-rest-v2");
        info.extend_from_slice(&(label.len() as u32).to_be_bytes());
        info.extend_from_slice(label.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(&info, &mut key).expect("32 within HKDF output limit");
        key
    }

    /// The envelope's AAD: a length-prefixed `label` plus the versions. A second belt on top of
    /// the key separation, and exactly what makes `state_version` unforgeable.
    fn context_aad(label: &str, version: u16) -> Vec<u8> {
        let mut a = Vec::with_capacity(10 + label.len());
        a.extend_from_slice(MAGIC);
        a.extend_from_slice(&version.to_le_bytes());
        a.extend_from_slice(&(label.len() as u32).to_be_bytes());
        a.extend_from_slice(label.as_bytes());
        a
    }

    /// Encrypt a secret FOR A SPECIFIC PLACE (`label`). A FRESH random 24-byte nonce on every call
    /// (192 bits — random freshness is enough without a counter).
    pub fn seal(&self, label: &str, plaintext: &[u8]) -> Vec<u8> {
        let key = self.subkey(label);
        let cipher = XChaCha20Poly1305::new((&key).into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); // 192-bit, fresh
        let aad = Self::context_aad(label, STATE_VERSION);
        let ct = cipher
            .encrypt(&nonce, chacha20poly1305::aead::Payload { msg: plaintext, aad: &aad })
            .expect("XChaCha20-Poly1305 encryption");
        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&STATE_VERSION.to_le_bytes());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        out
    }

    /// RAW seal for an OPAQUE fixed-size region (the Tier-2 hidden volume): `nonce(24) ‖ ct`, with NO
    /// magic prefix — so the whole blob is indistinguishable from random (a random nonce + an AEAD
    /// ciphertext is computationally random). The caller pads the plaintext to a FIXED length so the
    /// output size never varies, and treats an `open_raw` failure as "no such volume".
    pub(crate) fn seal_raw(&self, label: &str, plaintext: &[u8]) -> Vec<u8> {
        let key = self.subkey(label);
        let cipher = XChaCha20Poly1305::new((&key).into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let aad = Self::context_aad(label, STATE_VERSION);
        let ct = cipher
            .encrypt(&nonce, chacha20poly1305::aead::Payload { msg: plaintext, aad: &aad })
            .expect("XChaCha20-Poly1305 encryption");
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        out
    }

    /// Open a `seal_raw` blob. `Err` = wrong key OR this region holds no hidden volume (just random) —
    /// the two are indistinguishable, which is the whole point.
    pub(crate) fn open_raw(&self, label: &str, blob: &[u8]) -> Result<Vec<u8>, String> {
        if blob.len() < NONCE_LEN + 16 {
            return Err("no hidden volume".into());
        }
        let key = self.subkey(label);
        let nonce = XNonce::from_slice(&blob[..NONCE_LEN]);
        let cipher = XChaCha20Poly1305::new((&key).into());
        let aad = Self::context_aad(label, STATE_VERSION);
        cipher
            .decrypt(nonce, chacha20poly1305::aead::Payload { msg: &blob[NONCE_LEN..], aad: &aad })
            .map_err(|_| "no hidden volume / wrong key".to_string())
    }

    /// Decrypt the contents of `label`. Three DISTINGUISHABLE failures: not our format (re-init
    /// needed); the file was written by a different schema version (a newer binary is needed, not
    /// "read it with defaults"); wrong password, corruption, or a foreign file.
    pub fn open(&self, label: &str, blob: &[u8]) -> Result<Vec<u8>, String> {
        if blob.len() < HEADER_LEN || &blob[..4] != MAGIC {
            return Err("not a KARST at-rest ciphertext (incompatible format — re-init needed?)".into());
        }
        let version = u16::from_le_bytes([blob[4], blob[5]]);
        if version != STATE_VERSION {
            // Both directions are loud DELIBERATELY. Higher means the file is newer than us
            // (silently dropping fields on write-back, A6-5); lower means an old format, and there
            // are no migrations.
            let side = if version > STATE_VERSION { "newer" } else { "older" };
            return Err(format!(
                "state file written by a {side} KARST (format v{version}, this build speaks \
                 v{STATE_VERSION}) — upgrade the client instead of reading it with defaults"
            ));
        }
        let key = self.subkey(label);
        let nonce = XNonce::from_slice(&blob[6..HEADER_LEN]);
        let cipher = XChaCha20Poly1305::new((&key).into());
        let aad = Self::context_aad(label, version);
        cipher
            .decrypt(nonce, chacha20poly1305::aead::Payload { msg: &blob[HEADER_LEN..], aad: &aad })
            .map_err(|_| "wrong password, corrupt file, or a file from another location".to_string())
    }
}

#[cfg(test)]
mod tests {
    /// CRYPTO-16/34 — the KDF profile must be OURS and must be the one we think it is.
    ///
    /// This used to assert equality with `Argon2::default()`, which was right while the pinned
    /// values WERE the old default: it proved pinning moved nobody's key. Format v2 raised the
    /// profile deliberately, so that assertion is gone by design (and the raise is exactly what
    /// makes existing local vaults unopenable — stated in the commit, not discovered here).
    ///
    /// What it pins now: a derive under the PRODUCTION profile equals a derive under the literal
    /// constants. So an `argon2` bump that changes how those constants are interpreted still goes
    /// red here — the library can never move key derivation under us silently. This is also the
    /// one test that pays the real KDF cost, so the production path stays covered even when the
    /// rest of the suite runs with the fast-KDF escape hatch.
    #[test]
    fn the_production_kdf_profile_is_what_we_think_it_is() {
        use argon2::Argon2;
        let (pw, salt) = (b"correct horse battery staple".as_slice(), b"0123456789abcdef".as_slice());

        let params = argon2::Params::new(super::KDF_M_COST, super::KDF_T_COST, super::KDF_P_COST, Some(32))
            .unwrap();
        let mut expected = [0u8; 32];
        Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(pw, salt, &mut expected)
            .unwrap();

        // Bypasses `MasterKey::derive` on purpose: that one honours the debug fast-KDF hatch, and
        // this test must measure the profile the shipped binary actually uses.
        let profiled = super::MasterKey::kdf_production_only_for_tests();
        let mut got = [0u8; 32];
        profiled.hash_password_into(pw, salt, &mut got).unwrap();

        assert_eq!(
            got, expected,
            "the derived key no longer matches the pinned Argon2id profile (m={}, t={}, p={}) — \
             if the argon2 crate moved, decide the migration deliberately instead of adjusting \
             this test",
            super::KDF_M_COST, super::KDF_T_COST, super::KDF_P_COST
        );
    }


    use super::*;

    const SALT: &[u8] = b"unique-install-salt";
    /// A representative at-rest label; the context binding itself is tested separately.
    const L: &str = "acct:test/contacts.dat";

    #[test]
    fn roundtrip_with_correct_passphrase() {
        let k = MasterKey::derive(b"correct horse", SALT).unwrap();
        let blob = k.seal(L, b"secret key material");
        assert_eq!(k.open(L, &blob).unwrap(), b"secret key material");
    }

    /// Load-bearing: a wrong password gives an AEAD FAILURE, not silent garbage.
    #[test]
    fn wrong_passphrase_fails_not_garbage() {
        let good = MasterKey::derive(b"correct horse", SALT).unwrap();
        let bad = MasterKey::derive(b"wrong horse", SALT).unwrap();
        let blob = good.seal(L, b"secret key material");
        assert!(bad.open(L, &blob).is_err(), "a wrong password must FAIL rather than return garbage");
    }

    /// Load-bearing (not a no-op): there are no plaintext bytes of the secret on disk. The same
    /// shape as wire_bytes_are_ciphertext for Noise — it catches "we accidentally wrote plaintext".
    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let k = MasterKey::derive(b"pw", SALT).unwrap();
        let secret = b"BOBS-PRIVATE-RATCHET-KEY-32bytes";
        let blob = k.seal(L, secret);
        assert!(
            !blob.windows(secret.len()).any(|w| w == secret),
            "the plaintext secret must not appear in the blob"
        );
    }

    /// The not-our-format branch (no magic) gives a "re-init" error, distinct from an AEAD
    /// failure. It pins the behaviour of the versioned magic (migration from pre-at-rest).
    #[test]
    fn missing_magic_is_reinit_error_not_aead() {
        let k = MasterKey::derive(b"pw", SALT).unwrap();
        let plaintext_era = b"raw pre-at-rest secret bytes with no MSC1 header";
        let err = k.open(L, plaintext_era).unwrap_err();
        assert!(err.contains("re-init"), "a foreign format must name re-init explicitly, got: {err}");
    }

    /// Load-bearing: two seals of the SAME text give DIFFERENT nonces and ciphertexts. It pins
    /// fresh-nonce-per-write (a fixed key plus a repeated nonce is keystream reuse).
    #[test]
    fn identical_plaintext_yields_fresh_nonce() {
        let k = MasterKey::derive(b"pw", SALT).unwrap();
        let a = k.seal(L, b"same session state");
        let b = k.seal(L, b"same session state");
        assert_ne!(&a[4..HEADER_LEN], &b[4..HEADER_LEN], "the nonce must be fresh on every write");
        assert_ne!(a, b, "ciphertext must not repeat for identical plaintext");
    }
}

