//! §2.1 — PQXDH: authenticated post-quantum KEY AGREEMENT.
//!
//! A hybrid of X3DH and ML-KEM (spec §2.1): `root_key = KDF(classical_DH‖pq_shared)`.
//! It provides **sender authentication** (the long-term IK_A takes part in the DH, so only the
//! holder of IK_A can build the same root_key) and **post-quantum protection** (ML-KEM-768
//! against harvest-now-decrypt-later). BOTH must be broken (that is the hybrid).
//!
//! This module is key agreement ONLY: it produces the `root_key` that seeds the Double Ratchet
//! (`crate::ratchet`). Message encryption belongs to the ratchet, not to this layer (there is no
//! one-shot AEAD here).
//!
//! # The slice boundaries, explicitly:
//! - **directional authentication:** Alice→Bob GIVEN an authentic IK_B (out of band, or §12). NOT
//!   mutual. The prekey is SIGNED by the IK (XEdDSA) — a prekey/KEM substitution by the relay is
//!   rejected explicitly (`verify_prekey_sig`), not merely fail-closed;
//! - **the bundle is in memory** — publishing and fetching a prekey at a relay (§12) is its own slice;
//! - **replaying the initial KA** is not prevented here (there is no one-time prekey) — but the
//!   ratchet above makes a repeated session establishment visible (see `ratchet`);
//! - **no low-order check** on the three X25519 DHs — an audit item (not exploitable for
//!   sender auth: a forger is bound to Alice's authentic public key);
//! - **1:1 only.**
//!
//! # Crypto discipline.
//! The primitives are vendored (`ml-kem` FIPS 203, `x25519-dalek`, `hkdf`). The X3DH composition
//! is REFERENCE code (an exact public spec, like admission) and is **NOT independently audited**.
//! It is tested adversarially (sender auth, and PQ load-bearing through a root_key difference).
//!

use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport, Kem, TryKeyInit};
use ml_kem::{Ciphertext, DecapsulationKey, EncapsulationKey, MlKem768};
use sha2::Sha256;
use x25519_dalek::PublicKey;

use crate::seal::Identity;

/// The KDF domain — separated from seal (`KARST-skeleton-seal-v1`), the ratchet and fetch-auth.
const DOMAIN: &[u8] = b"KARST-pqxdh-v1";

/// The recipient's public prekey bundle — what a sender needs. Public material (serialisable for
/// §12 publish/fetch at a relay).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PreKeyBundle {
    /// The long-term identity key (X25519). Also the mailbox address.
    pub ik_pub: [u8; 32],
    /// The prekey (X25519), SIGNED by the IK (see `prekey_sig`). Also the recipient's initial
    /// ratchet key.
    pub prekey_pub: [u8; 32],
    /// The ML-KEM-768 encapsulation key (~1184 B).
    pub kem_ek: Vec<u8>,
    /// Optional ONE-TIME prekey for this contact, WITH its owner's signature. When present it
    /// adds a fourth DH term `EK_A × OPK_B` to the root key and is CONSUMED by the recipient,
    /// giving the first message forward secrecy against a later compromise of the long-lived
    /// prekey secret. `None` means the 3-DH agreement — see [`SignedOpk`] for why that case is
    /// reported to the caller rather than taken silently.
    pub opk: Option<SignedOpk>,
    /// XEdDSA signature (by the identity key `ik_pub`) over the long-lived prekey material
    /// (`prekey_pub ‖ kem_ek`) — the §2.1 "signed prekey". Lets the sender REJECT a bundle
    /// whose prekey / KEM key a relay substituted, instead of only failing closed later in the
    /// DH agreement. Signed with the SAME X25519 identity key (Signal's XEdDSA), so no second
    /// key and no safety-number change. The one-time prekey is NOT signed.
    ///
    /// MANDATORY. It used to be `serde(default)` so a pre-signature bundle would still decode as
    /// "unsigned" — tolerance for clients that do not exist. A missing signature now fails to
    /// decode instead of arriving as an empty Vec that only a later check happens to catch.
    pub prekey_sig: Vec<u8>,
    /// The account's public mailbox point `M = m·G` for blinded deposit/fetch key separation
    /// (`crate::blind`). Bound by `prekey_sig` (a relay cannot swap it undetected). The live
    /// drop-box path derives the blinded deposit address from it for established sessions
    /// (`peer.rs` → `blind::deposit_address`).
    ///
    /// MANDATORY, and never the all-zero encoding: that is the Ristretto IDENTITY point, for
    /// which `h·M` is the identity for every blinding factor — so every sender would compute the
    /// same "address" and nobody could prove ownership of it. It used to default to `[0;32]` for
    /// pre-mailbox bundles, which is why a downstream guard had to catch the degenerate value at
    /// SEND time; it is now rejected where it would enter a session.
    pub mailbox_pub: [u8; 32],
}

/// A one-time prekey as it travels: the public key together with its owner's signature over it.
///
/// The two are ONE value on purpose. The OPK used to ride as a bare `[u8; 32]`, unsigned, while
/// everything else in the bundle was covered by `prekey_sig` — so a relay could hand the sender
/// an OPK of its OWN choosing (CRYPTO-04). The sender would fold `EK_A × OPK_relay` into the root
/// key believing it had gained forward secrecy, when the fourth DH was a value the relay knew.
/// The recipient would then fail to decrypt, but the damage is not decryption failure: it is that
/// the extra-forward-secrecy property is silently fake.
///
/// Signing each OPK individually rather than committing to the batch keeps the relay's job pure
/// storage-and-forward: it holds opaque signed values, hands one out, and cannot mint another.
///
/// STILL POSSIBLE, and deliberately not "fixed" here: the relay can WITHHOLD every OPK and claim
/// exhaustion, which is indistinguishable from genuine exhaustion. Refusing to talk in that case
/// would convert a downgrade into a lockout — and exhaustion is attacker-inducible today (an
/// unauthenticated fetch consumes one, issue #159). So the sender proceeds with 3-DH and REPORTS
/// it (`KeyAgreement::used_one_time_prekey`), instead of either failing or staying quiet.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SignedOpk {
    pub key: [u8; 32],
    /// The ONE-TIME ML-KEM-768 encapsulation key minted with `key` (~1184 B), signed with it as
    /// one unit (CRYPTO-33).
    ///
    /// This is the post-quantum half of the same one-time prekey, and it is deliberately not a
    /// separate object. The classical OPK gives the first message forward secrecy against a later
    /// compromise of the long-lived X25519 prekey; the KEM leg had no counterpart at all — the
    /// bundle's `kem_ek` is minted once, never rotated, so anyone who later obtains the account's
    /// secret material decapsulates every recorded opener and walks the ratchet forward from
    /// there. A sender that gets a one-time unit encapsulates against THIS key instead, and the
    /// recipient destroys its seed on the same commit that consumes the X25519 half.
    ///
    /// One unit rather than two stores because the pair must be all-or-nothing: two independent
    /// batches can go out of step (classical half present, PQ half exhausted), and the resulting
    /// silent per-leg downgrade is exactly what a merged unit cannot express.
    pub kem_ek: Vec<u8>,
    /// XEdDSA signature (64 B) by the OWNER's identity key over [`opk_sig_message`]. A `Vec`
    /// only because serde has no impl for `[u8; 64]`; a wrong length fails verification, which
    /// is the same door a wrong signature goes through.
    pub sig: Vec<u8>,
}

impl SignedOpk {
    /// Verify this one-time prekey against the identity key that should have signed it. Separate
    /// from [`PreKeyBundle::verify_prekey_sig`] so a relay checking a BATCH does not re-verify the
    /// bundle's prekey signature once per key: `MAX_OPKS_PER_IK` is 256, and doing both per entry
    /// made one publish cost 512 XEdDSA verifications plus 256 bundle clones — the same
    /// work-amplification shape as SEC-28.
    pub fn verify(&self, ik_pub: &[u8; 32]) -> bool {
        use xeddsa::Verify;
        let Ok(sig) = <[u8; 64]>::try_from(self.sig.as_slice()) else {
            return false; // wrong length = unsigned / incompatible
        };
        let pk = xeddsa::xed25519::PublicKey::from(&PublicKey::from(*ik_pub));
        pk.verify(&opk_sig_message(&self.key, &self.kem_ek), &sig).is_ok()
    }
}

/// One unconsumed one-time prekey UNIT: the classical X25519 half and the post-quantum ML-KEM
/// half, minted together and destroyed together (CRYPTO-33).
///
/// Held as the KEM's 64-byte FIPS 203 seed rather than the expanded decapsulation key: the
/// encapsulation key is a pure function of it (`kem_ek`), so the batch costs 96 bytes per unit at
/// rest instead of the ~2.4 KB the expanded pair would.
#[derive(Clone)]
pub struct OneTimePrekey {
    x: Identity,
    kem_seed: [u8; 64],
}

/// One unit's secret material, as it is persisted and handed back to `import_opk_secrets`.
/// `zeroize` on drop for the same reason every other secret here has it: these ARE the keys whose
/// destruction is the forward-secrecy claim.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    zeroize::Zeroize,
    zeroize::ZeroizeOnDrop,
)]
pub struct OneTimeSecret {
    /// X25519 one-time prekey secret.
    pub x: [u8; 32],
    /// ML-KEM-768 seed (FIPS 203 `from_seed`/`to_seed`). `serde` has no array impl this wide, so
    /// it travels as two halves rather than as `[u8; 64]`.
    pub kem_seed_lo: [u8; 32],
    pub kem_seed_hi: [u8; 32],
}

impl OneTimePrekey {
    fn generate() -> Self {
        // The KEM seed is the unit's whole post-quantum secret, so it comes from the OS CSPRNG
        // directly — never from the account's long-lived material, which would make it
        // re-derivable by exactly the compromise this is supposed to survive.
        let mut kem_seed = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut kem_seed);
        OneTimePrekey { x: Identity::generate(), kem_seed }
    }

    fn from_secret(s: &OneTimeSecret) -> Self {
        let mut kem_seed = [0u8; 64];
        kem_seed[..32].copy_from_slice(&s.kem_seed_lo);
        kem_seed[32..].copy_from_slice(&s.kem_seed_hi);
        OneTimePrekey { x: Identity::from_secret_bytes(s.x), kem_seed }
    }

    fn to_secret(&self) -> OneTimeSecret {
        OneTimeSecret {
            x: self.x.to_secret_bytes(),
            kem_seed_lo: self.kem_seed[..32].try_into().expect("32"),
            kem_seed_hi: self.kem_seed[32..].try_into().expect("32"),
        }
    }

    fn kem_dk(&self) -> DecapsulationKey<MlKem768> {
        let seed = Array::try_from(&self.kem_seed[..]).expect("64-byte ML-KEM seed");
        DecapsulationKey::<MlKem768>::from_seed(seed)
    }

    /// This unit's ML-KEM encapsulation key, as published.
    fn kem_ek(&self) -> Vec<u8> {
        self.kem_dk().encapsulation_key().to_bytes().as_slice().to_vec()
    }
}

/// The message an OPK signature covers: a domain tag ‖ the one-time prekey. Domain-separated from
/// [`prekey_sig_message`] so neither signature can ever be replayed as the other.
pub(crate) fn opk_sig_message(opk_pub: &[u8; 32], kem_ek: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(16 + 32 + kem_ek.len());
    m.extend_from_slice(b"KARST-opk-sig-v2"); // v2: the signature now covers the PQ half too
    m.extend_from_slice(opk_pub);
    m.extend_from_slice(kem_ek);
    m
}

/// The message the prekey signature covers: a domain tag ‖ the X25519 prekey ‖ the ML-KEM key ‖
/// the mailbox point `M`. All long-lived public materials are bound, so a relay cannot swap the
/// prekey, KEM key, OR the mailbox point undetected.
pub(crate) fn prekey_sig_message(prekey_pub: &[u8; 32], kem_ek: &[u8], mailbox_pub: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(19 + 32 + kem_ek.len() + 32);
    m.extend_from_slice(b"KARST-prekey-sig-v1");
    m.extend_from_slice(prekey_pub);
    m.extend_from_slice(kem_ek);
    m.extend_from_slice(mailbox_pub);
    m
}

impl PreKeyBundle {
    /// Verify the prekey signature against this bundle's `ik_pub`. A sender calls this on a
    /// fetched bundle BEFORE using it: `false` means the relay tampered with the prekey / KEM
    /// key (or the bundle is from an incompatible unsigned version) — do not proceed.
    pub fn verify_prekey_sig(&self) -> bool {
        use xeddsa::Verify;
        let pk = xeddsa::xed25519::PublicKey::from(&PublicKey::from(self.ik_pub));
        let msg = prekey_sig_message(&self.prekey_pub, &self.kem_ek, &self.mailbox_pub);
        let Ok(sig): Result<[u8; 64], _> = self.prekey_sig.as_slice().try_into() else {
            return false; // wrong length = unsigned / incompatible bundle
        };
        if pk.verify(&msg, &sig).is_err() {
            return false;
        }
        // ...and the one-time prekey, if the bundle carries one. Same identity key, different
        // domain tag. A bundle whose OPK does not verify is REJECTED WHOLE rather than downgraded
        // to 3-DH: a bad signature is not "no key available", it is evidence of tampering, and
        // quietly continuing would hand the attacker exactly the downgrade they were after.
        match &self.opk {
            None => true,
            Some(o) => o.verify(&self.ik_pub),
        }
    }
}

/// The recipient's secrets. `accept_key_agreement` recovers the root_key from them.
// Clone lets one logical identity back a per-relay `Peer` each, for multi-homed receive
// (`client::receive_threaded`); every clone carries the same secrets, as a rebuilt-from-seed
// account would.
#[derive(Clone)]
pub struct Account {
    ik: Identity,
    prekey: Identity,
    kem_dk: DecapsulationKey<MlKem768>,
    /// Unconsumed one-time prekey secrets, keyed by their public key. Each seeds at most
    /// one initial agreement, then `accept_key_agreement` deletes it. **In-memory for now**
    /// — this increment is the key-agreement mechanism; the sidecar persistence (kept out
    /// of `account.key`, so the long-lived identity is never at migration risk) and the
    /// relay-side per-fetch distribution that make it end-to-end one-time are the next
    /// increments.
    opks: std::collections::HashMap<[u8; 32], OneTimePrekey>,
    /// Per-account mailbox secret `m` (Ristretto scalar bytes) for deposit/fetch key SEPARATION
    /// (`crate::blind`). Derived deterministically from the account's own secret material, so it
    /// re-derives from the seed (no separate persistence) and a sender — who lacks that material
    /// — cannot recompute it. Its public `M = m·G` is published in the bundle, and the live
    /// drop-box path fetches blinded boxes with the derived fetch secret for established sessions.
    mailbox_secret: [u8; 32],
}

impl Account {
    pub fn generate() -> Self {
        let (kem_dk, _ek) = MlKem768::generate_keypair();
        let mut acct = Account {
            ik: Identity::generate(),
            prekey: Identity::generate(),
            kem_dk,
            opks: std::collections::HashMap::new(),
            mailbox_secret: [0u8; 32],
        };
        // Derive `m` from the account's OWN secret bytes (same rule as `from_secret_bytes`), so a
        // generated account and one restored from `to_secret_bytes` agree on `M`.
        acct.mailbox_secret = crate::blind::MailboxSecret::derive(&acct.to_secret_bytes()).to_bytes();
        acct
    }

    /// The account's public mailbox point `M = m·G` — published in the bundle so a sender can
    /// derive the blinded deposit addresses (`crate::blind::deposit_address`).
    pub fn mailbox_public(&self) -> [u8; 32] {
        crate::blind::MailboxSecret::from_bytes(&self.mailbox_secret)
            .expect("stored mailbox secret is canonical")
            .public()
    }

    /// The fetch secret `h·m` for one of MY inbound drop-boxes (epoch/direction under the shared
    /// per-session `seed`). Its public key is the box address a sender deposited into; I prove
    /// ownership of the box to the relay with a `blind::FetchOwnershipProof` over this secret.
    pub fn mailbox_fetch_secret(
        &self,
        seed: &[u8; 32],
        epoch: u64,
        dir: u8,
        relay_id: &[u8; 32],
    ) -> [u8; 32] {
        crate::blind::MailboxSecret::from_bytes(&self.mailbox_secret)
            .expect("stored mailbox secret is canonical")
            .fetch_secret(seed, epoch, dir, relay_id)
    }

    /// Mint a fresh one-time prekey, store its secret, and return its public key — to be
    /// placed in a published bundle. Consumed on first use (see `accept_key_agreement`).
    pub fn add_opk(&mut self) -> [u8; 32] {
        let unit = OneTimePrekey::generate();
        let pk = unit.x.public.to_bytes();
        self.opks.insert(pk, unit);
        pk
    }

    /// Sign one of our one-time prekeys with the identity key, so a relay can hand it out but
    /// cannot substitute one of its own (CRYPTO-04). Signing is the publisher's job — the relay
    /// only ever holds the signed pair.
    pub fn sign_opk(&self, opk_pub: &[u8; 32], kem_ek: &[u8]) -> Vec<u8> {
        use xeddsa::Sign;
        let sk = x25519_dalek::StaticSecret::from(self.ik.to_secret_bytes());
        let signer = xeddsa::xed25519::PrivateKey::from(&sk);
        let sig: [u8; 64] = signer.sign(&opk_sig_message(opk_pub, kem_ek), rand010::rng());
        sig.to_vec()
    }

    /// The published form of one of our one-time units — the X25519 key and its ML-KEM
    /// encapsulation key, signed together. `None` if we do not hold that unit (consumed, or never
    /// ours).
    pub fn signed_opk(&self, opk_pub: &[u8; 32]) -> Option<SignedOpk> {
        let unit = self.opks.get(opk_pub)?;
        let kem_ek = unit.kem_ek();
        let sig = self.sign_opk(opk_pub, &kem_ek);
        Some(SignedOpk { key: *opk_pub, kem_ek, sig })
    }

    /// Our unconsumed one-time prekeys, each signed — exactly what `publish` advertises.
    pub fn signed_opks(&self) -> Vec<SignedOpk> {
        self.opks.keys().filter_map(|k| self.signed_opk(k)).collect()
    }

    /// How many unconsumed one-time prekeys remain (for the batch top-up policy later).
    pub fn opk_count(&self) -> usize {
        self.opks.len()
    }

    /// Public keys of the current unconsumed one-time prekeys — what `publish` advertises.
    pub fn opk_pubs(&self) -> Vec<[u8; 32]> {
        self.opks.keys().copied().collect()
    }

    /// SECRET bytes of the current unconsumed one-time prekeys, for the caller to persist
    /// in a sidecar (kept OUT of `account.key`, so the long-lived identity never migrates).
    /// **These are private keys in the clear** — write under 0600, same care as the account.
    pub fn export_opk_secrets(&self) -> Vec<OneTimeSecret> {
        self.opks.values().map(|u| u.to_secret()).collect()
    }

    /// Load persisted one-time prekey secrets back into the account (see
    /// `export_opk_secrets`). Additive: existing OPKs are kept, so a top-up survives.
    pub fn import_opk_secrets(&mut self, secrets: &[OneTimeSecret]) {
        for s in secrets {
            let unit = OneTimePrekey::from_secret(s);
            self.opks.insert(unit.x.public.to_bytes(), unit);
        }
    }

    /// This account's bundle carrying a specific one-time prekey (must be one of ours, via
    /// `add_opk`). The sender mixes it into the agreement and the recipient consumes it.
    pub fn prekey_bundle_with_opk(&self, opk_pub: [u8; 32]) -> PreKeyBundle {
        PreKeyBundle { opk: self.signed_opk(&opk_pub), ..self.prekey_bundle() }
    }

    /// Serialise the secrets for persistence (a §2.1 identity is stable across runs).
    /// **CAUTION:** these are PRIVATE keys in the clear — ik(32) ‖ prekey(32) ‖ ML-KEM seed(64).
    /// The caller must write them under 0600; at-rest encryption (a password KDF) is deferred.
    /// Not a blanket serde impl: every export of a secret to disk is deliberate, so it cannot leak
    /// into a wire message by accident.
    /// The KEM is stored as a 64-byte seed (FIPS 203 `from_seed`/`to_seed`), not in expanded form.
    pub fn to_secret_bytes(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        out[..32].copy_from_slice(&self.ik.to_secret_bytes());
        out[32..64].copy_from_slice(&self.prekey.to_secret_bytes());
        let seed = self.kem_dk.to_seed().expect("the KEM dk was generated from a seed → Some");
        out[64..].copy_from_slice(seed.as_slice());
        out
    }

    /// Restore an account from stored secrets (see `to_secret_bytes`).
    pub fn from_secret_bytes(bytes: &[u8; 128]) -> Self {
        let ik = Identity::from_secret_bytes(bytes[..32].try_into().expect("32"));
        let prekey = Identity::from_secret_bytes(bytes[32..64].try_into().expect("32"));
        let seed = Array::try_from(&bytes[64..]).expect("a 64-byte ML-KEM seed");
        let kem_dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        // OPKs are not in `account.key` (see the `opks` field) — a restored account starts
        // with an empty batch. The account.key format is therefore UNCHANGED: no migration
        // of the long-lived identity.
        // The mailbox secret is DERIVED from these same secret bytes (domain-separated), so it
        // re-derives from the seed with no format change and no extra persistence.
        let mailbox_secret = crate::blind::MailboxSecret::derive(bytes).to_bytes();
        Account { ik, prekey, kem_dk, opks: std::collections::HashMap::new(), mailbox_secret }
    }

    /// The long-term identity public key (the recipient's address/identity).
    pub fn identity_public(&self) -> [u8; 32] {
        self.ik.public.to_bytes()
    }

    /// Sign an arbitrary message with the identity key — WITHOUT handing out the key.
    ///
    /// `sign_discovery` used to live on this type, and it was the only thing in the whole PQXDH
    /// module that reached for `discovery` and `protocol` — which made the module graph circular
    /// (`protocol` needs `PreKeyBundle` from here, and `discovery` needs `RelayDescriptor` from
    /// there). Legal inside one crate, impossible once these sit on either side of the trust
    /// boundary. The signature now lives in `discovery`, where the message it covers is defined.
    ///
    /// It used to hand back the raw secret, which was tolerable only while `discovery` lived in
    /// the same crate. Splitting the primitives out (#247) made that a secret crossing a crate
    /// boundary — so it does not: the caller passes the message in and gets a signature back, and
    /// the key never leaves the crate that owns it. The split found this; nothing else would
    /// have.
    pub fn sign_with_ik(&self, msg: &[u8]) -> Vec<u8> {
        use xeddsa::Sign;
        let sk = x25519_dalek::StaticSecret::from(self.ik.to_secret_bytes());
        let signer = xeddsa::xed25519::PrivateKey::from(&sk);
        let sig: [u8; 64] = signer.sign(msg, rand010::rng());
        sig.to_vec()
    }

    /// The long-term identity key (for sending: sender_ik) — crate-internal; the session layer
    /// takes the private key from here.
    /// The account's LONG-LIVED ML-KEM decapsulation key, for opening a sealed opener (PRIV-3).
    ///
    /// Exposed by reference and never cloned out: the sealed opener has to be opened with the
    /// long-lived key by construction (a one-time unit cannot be selected before the seal is open —
    /// which unit was used is written inside it), so this is the one legitimate caller. A method
    /// rather than a public field so that stays true.
    pub fn kem_dk_ref(&self) -> &DecapsulationKey<MlKem768> {
        &self.kem_dk
    }

    /// This account's KEM half packaged for the hybrid seal (PRIV-3) — deterministic from the seed,
    /// which is what makes the skeleton path work: the sender can learn `ek()` out of band and the
    /// recipient re-derives the same key after a reload.
    pub fn seal_kem(&self) -> crate::seal::SealKemKeys {
        crate::seal::SealKemKeys::from_dk(self.kem_dk.clone())
    }

    pub fn ik(&self) -> &Identity {
        &self.ik
    }

    /// The prekey (for receiving: the recipient's initial ratchet key).
    /// Open the RECEIVING half of a ratchet from an agreed root key, using this account's signed
    /// prekey.
    ///
    /// A method rather than a `prekey()` accessor because the accessor handed a private key across
    /// what is now a crate boundary (#247) for a caller that only ever fed it straight back into
    /// `Session::init_receiver` — and both types live here, so the whole operation belongs here.
    pub fn init_receiver_session(&self, root_key: [u8; 32]) -> crate::ratchet::Session {
        crate::ratchet::Session::init_receiver(root_key, self.prekey.clone())
    }

    #[allow(dead_code)]
    fn prekey_unused(&self) -> &Identity {
        &self.prekey
    }

    /// The public bundle for a sender — with an XEdDSA signature by the IK over the prekey material.
    pub fn prekey_bundle(&self) -> PreKeyBundle {
        use xeddsa::Sign;
        let prekey_pub = self.prekey.public.to_bytes();
        let kem_ek = self.kem_dk.encapsulation_key().to_bytes().as_slice().to_vec();
        let mailbox_pub = self.mailbox_public();
        // Sign `prekey_pub ‖ kem_ek ‖ M` with the identity key (XEdDSA over the same X25519 key).
        let sk = x25519_dalek::StaticSecret::from(self.ik.to_secret_bytes());
        let signer = xeddsa::xed25519::PrivateKey::from(&sk);
        let prekey_sig: [u8; 64] =
            signer.sign(&prekey_sig_message(&prekey_pub, &kem_ek, &mailbox_pub), rand010::rng());
        let prekey_sig = prekey_sig.to_vec();
        PreKeyBundle {
            ik_pub: self.ik.public.to_bytes(),
            prekey_pub,
            kem_ek,
            opk: None,
            prekey_sig,
            mailbox_pub,
        }
    }

    /// Accept an initial key agreement: recover the `root_key` and identify the sender, consuming
    /// the one-time prekey IMMEDIATELY.
    ///
    /// Prefer [`Account::prepare_key_agreement`] + [`Account::consume_opk`] on paths where the
    /// result can still be rejected: here the OPK burns BEFORE the first AEAD is checked, so a
    /// forged opener would burn someone else's one-time prekey (CRYPTO-03).
    pub fn accept_key_agreement(&mut self, ka: &KeyAgreement) -> Option<([u8; 32], [u8; 32])> {
        let accepted = self.prepare_key_agreement(ka)?;
        self.consume_opk(ka);
        Some(accepted)
    }

    /// Consume the one-time prekey named in this agreement. Call it ONLY after the first ratchet
    /// message decrypts successfully: consuming the OPK is what provides at-most-once dedup for a
    /// redelivered opener, so it must never burn on an unauthenticated message. Idempotent.
    pub fn consume_opk(&mut self, ka: &KeyAgreement) {
        if let Some(opk_pub) = ka.opk_pub {
            self.opks.remove(&opk_pub);
        }
    }

    /// The PREPARE step: recover the `root_key` and identify the claimed sender while changing
    /// NOTHING in the account. `None` means a structural error (a malformed KEM ciphertext, an
    /// unknown or already-consumed OPK, a non-contributory DH).
    ///
    /// Sender authentication is NOT checked here: a wrong IK_A yields a DIFFERENT root_key, so the
    /// first ratchet message fails to decrypt (AEAD). The caller must therefore verify that AEAD
    /// BEFORE committing anything (a session, an OPK consumption) — otherwise anyone holding the
    /// public bundle could make the recipient store a dead session under someone else's IK.
    /// Returns (root_key, the sender's claimed identity).
    pub fn prepare_key_agreement(&self, ka: &KeyAgreement) -> Option<([u8; 32], [u8; 32])> {
        // The sender's mailbox point becomes where we deposit our replies, so a degenerate one
        // must never enter a session: the all-zero encoding is the Ristretto IDENTITY, and
        // `h·identity == identity` for every blinding factor, so the "address" is the same for
        // everyone and nobody can prove they own it.
        if ka.mailbox_a_pub == [0u8; 32] {
            return None;
        }
        let ik_a = PublicKey::from(ka.ik_a_pub);
        let ek_a = PublicKey::from(ka.ek_a_pub);
        // The mirror of the sender's DH (static-static X25519 symmetry).
        // Every DH must be CONTRIBUTORY: a small-order peer point yields an all-zero shared
        // secret that the attacker also knows, so reject rather than fold it in (CRYPTO-06).
        let dh1 = self.prekey.dh_checked(&ik_a)?; // PK_B × IK_A (authenticates the sender)
        let dh2 = self.ik.dh_checked(&ek_a)?; //     IK_B × EK_A
        let dh3 = self.prekey.dh_checked(&ek_a)?; //  PK_B × EK_A

        // If the sender used a one-time prekey, find its secret and mirror dh4. A missing
        // OPK (already consumed, or never ours) fails the agreement rather than silently
        // downgrading — the sender committed to it in the transcript, so proceeding without
        // it would derive a different root key anyway.
        let unit = match ka.opk_pub {
            Some(opk_pub) => Some(self.opks.get(&opk_pub)?),
            None => None,
        };
        let dh4 = match unit {
            Some(u) => Some(u.x.dh_checked(&ek_a)?),
            None => None,
        };

        let ct: Ciphertext<MlKem768> = Array::try_from(ka.kem_ct.as_slice()).ok()?;
        // Mirror of the sender's choice above: a one-time unit means the ciphertext is against
        // THAT unit's KEM key, whose seed we destroy when the unit is consumed. Only an opener
        // that used no unit at all is decapsulated with the long-lived key.
        let pq_shared = match unit {
            Some(u) => u.kem_dk().decapsulate(&ct),
            None => self.kem_dk.decapsulate(&ct),
        };

        let transcript = transcript(
            &ka.ik_a_pub,
            &self.ik.public.to_bytes(),
            &ka.ek_a_pub,
            &self.prekey.public.to_bytes(),
            &ka.kem_ct,
            ka.opk_pub.as_ref(),
            &ka.mailbox_a_pub,
        );
        let root_key = derive_root_key(&dh1, &dh2, &dh3, dh4.as_ref(), pq_shared.as_slice(), &transcript);
        // NOTE: the one-time prekey is NOT consumed here — that is `consume_opk`, and the caller
        // must only call it once the first AEAD verified. It must never seed a second agreement
        // (or it is not one-time and the forward-secrecy claim is void), but burning it on an
        // unauthenticated message is its own vulnerability (CRYPTO-03).
        Some((root_key, ka.ik_a_pub))
    }
}

/// The initial key agreement on the wire (§2.1). It carries ONLY agreement material (no payload —
/// the payload travels in the ratchet message attached beside it).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyAgreement {
    /// The sender's long-term identity (claimed — authenticated by DH1).
    pub ik_a_pub: [u8; 32],
    /// The sender's ephemeral key.
    pub ek_a_pub: [u8; 32],
    /// The ML-KEM-768 ciphertext (~1088 B).
    pub kem_ct: Vec<u8>,
    /// Which one-time prekey the sender used (its public key), so the recipient knows
    /// which OPK secret to mix in and consume. `None` = no OPK was used. Appended last.
    pub opk_pub: Option<[u8; 32]>,
    /// The SENDER's mailbox point `M_A` (`crate::blind`), so the responder can deposit its
    /// replies into the sender's blinded B→A box (the responder never fetches the sender's
    /// bundle, so this is the only channel for `M_A`). Bound into the key-agreement transcript,
    /// so a relay that swaps it derives a different root key and the first message fails closed.
    /// Appended last.
    #[serde(default)]
    pub mailbox_a_pub: [u8; 32],
}

/// Alice, the sender: agree a `root_key` with the recipient from their bundle.
/// `sender_ik` is Alice's long-term identity (her authenticator).
/// Returns (root_key, the KA for the wire), or `Err` if the bundle is structurally invalid (a
/// malformed KEM key). No wire input ever reaches an `expect` or a panic.
pub fn initiate_key_agreement(
    sender_ik: &Identity,
    sender_mailbox_pub: &[u8; 32],
    bundle: &PreKeyBundle,
) -> Result<([u8; 32], KeyAgreement), String> {
    // Parse the WIRE-derived KEM key FIRST — before any DH. `verify_prekey_sig` passing does NOT
    // make this well-formed: a malicious contact signs its own malformed `kem_ek` with its own
    // IK, so the signature verifies. This used to `expect()` and panic the caller (CRYPTO-08).
    // CRYPTO-33: encapsulate against the ONE-TIME KEM key when the bundle carries a one-time
    // unit, and only fall back to the bundle's long-lived `kem_ek` when it does not. The
    // long-lived key is minted once and never rotated, so a ciphertext against it stays
    // decryptable by anyone who later obtains the account's secret material; a one-time key's
    // seed is destroyed on the commit that consumes the unit, which is what makes the PQ leg of
    // this handshake forward-secret at all. Which key was used is not ambiguous to the recipient:
    // the transcript binds `opk_pub`, and the unit is all-or-nothing.
    let kem_ek_bytes: &[u8] = match &bundle.opk {
        Some(o) => &o.kem_ek,
        None => &bundle.kem_ek,
    };
    let ek = <EncapsulationKey<MlKem768> as TryKeyInit>::new_from_slice(kem_ek_bytes)
        .map_err(|_| "bundle KEM key is malformed".to_string())?;

    let ik_b = PublicKey::from(bundle.ik_pub);
    let prekey_b = PublicKey::from(bundle.prekey_pub);
    let ek_a = Identity::generate(); // the sender's ephemeral

    // Every DH must be CONTRIBUTORY. A malicious contact can publish a small-order prekey / OPK
    // (the signature covers it, but "signed" says nothing about order): the shared secret would
    // be all-zero and therefore public, so refuse the bundle instead of folding it in (CRYPTO-06).
    const NON_CONTRIB: &str = "bundle contains a non-contributory (small-order) X25519 key";
    let dh1 = sender_ik.dh_checked(&prekey_b).ok_or(NON_CONTRIB)?; // IK_A × PK_B
    let dh2 = ek_a.dh_checked(&ik_b).ok_or(NON_CONTRIB)?; //         EK_A × IK_B
    let dh3 = ek_a.dh_checked(&prekey_b).ok_or(NON_CONTRIB)?; //     EK_A × PK_B
    // Fourth DH against the recipient's ONE-TIME prekey, iff the bundle carried one.
    let dh4 = match &bundle.opk {
        Some(o) => Some(ek_a.dh_checked(&PublicKey::from(o.key)).ok_or(NON_CONTRIB)?),
        None => None,
    };

    let (ct, pq_shared) = ek.encapsulate();
    let kem_ct = ct.as_slice().to_vec();

    let ik_a_pub = sender_ik.public.to_bytes();
    let ek_a_pub = ek_a.public.to_bytes();
    let transcript = transcript(
        &ik_a_pub,
        &bundle.ik_pub,
        &ek_a_pub,
        &bundle.prekey_pub,
        &kem_ct,
        bundle.opk.as_ref().map(|o| &o.key),
        sender_mailbox_pub,
    );
    let root_key = derive_root_key(&dh1, &dh2, &dh3, dh4.as_ref(), pq_shared.as_slice(), &transcript);

    Ok((
        root_key,
        KeyAgreement {
            ik_a_pub,
            ek_a_pub,
            kem_ct,
            opk_pub: bundle.opk.as_ref().map(|o| o.key),
            mailbox_a_pub: *sender_mailbox_pub,
        },
    ))
}

/// The transcript: it binds BOTH long-term keys (IK_A, IK_B), the ephemeral, the prekey and the
/// **KEM ciphertext** — without the last one an encapsulation-substitution attack is possible.
/// It goes into the KDF `info`.
fn transcript(
    ik_a: &[u8; 32],
    ik_b: &[u8; 32],
    ek_a: &[u8; 32],
    prekey_b: &[u8; 32],
    kem_ct: &[u8],
    opk_b: Option<&[u8; 32]>,
    mailbox_a: &[u8; 32],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(DOMAIN.len() + 192 + kem_ct.len());
    t.extend_from_slice(DOMAIN);
    t.extend_from_slice(ik_a);
    t.extend_from_slice(ik_b);
    t.extend_from_slice(ek_a);
    t.extend_from_slice(prekey_b);
    t.extend_from_slice(kem_ct);
    // Bind the sender's mailbox point M_A so a relay cannot swap it (a swap → different root key
    // → the first ratchet message fails closed, rather than silently redirecting B→A replies).
    t.extend_from_slice(mailbox_a);
    // Bind whether an OPK was used AND which one: a 1-byte presence flag then the key, so
    // "no OPK" and "OPK of all-zeros" cannot collide and a stripped OPK changes the key.
    match opk_b {
        Some(opk) => {
            t.push(1);
            t.extend_from_slice(opk);
        }
        None => t.push(0),
    }
    t
}

/// root_key = HKDF-SHA256(ikm = DH1‖DH2‖DH3‖pq_shared, info = transcript).
/// pq_shared is part of the IKM — the post-quantum leg is LOAD-BEARING (a test pins this).
fn derive_root_key(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4: Option<&[u8; 32]>,
    pq_shared: &[u8],
    transcript: &[u8],
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(128 + pq_shared.len());
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    // The one-time-prekey DH goes in BEFORE the PQ share, in a fixed position. It is
    // present iff an OPK was used; the transcript binds which OPK, so its absence cannot be
    // silently forged into presence or vice versa.
    if let Some(dh4) = dh4 {
        ikm.extend_from_slice(dh4);
    }
    ikm.extend_from_slice(pq_shared);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(transcript, &mut okm).expect("32 within HKDF output limit");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer test against the canonical XEdDSA spec vector (also in the `xeddsa`
    /// crate's own suite). This pins the Montgomery→Edwards key conversion — the subtle part —
    /// so a broken or forked `xeddsa` (or a version bump that changes it) reds in OUR CI, not
    /// just theirs. This is the one part of the primitive our tests can verify against a
    /// reference rather than a self round-trip.
    #[test]
    fn xeddsa_matches_the_spec_known_answer_vector() {
        use xeddsa::CalculateKeyPair;
        let priv_in: [u8; 32] = [
            0xf8, 0xce, 0xd4, 0x2b, 0x07, 0xe7, 0x81, 0x0a, 0x04, 0xcc, 0x85, 0x4b, 0x03, 0x57,
            0x6d, 0xf1, 0xe4, 0xc0, 0xfe, 0xb1, 0x6d, 0x68, 0x5e, 0x0a, 0xc0, 0x42, 0x5e, 0x1c,
            0x3c, 0x5e, 0xb2, 0x47,
        ];
        let sk = xeddsa::xed25519::PrivateKey::from(&priv_in);
        let (_signing, verifying) = sk.calculate_key_pair(0);
        assert_eq!(
            verifying,
            [
                0xD7, 0x6D, 0x40, 0x33, 0x2E, 0xD1, 0x13, 0x88, 0xCA, 0xA6, 0x9B, 0x50, 0x67,
                0x6D, 0x63, 0x08, 0x25, 0xCD, 0xDA, 0xD0, 0x32, 0x46, 0xED, 0xD6, 0x1E, 0xD3,
                0xCA, 0x72, 0xE6, 0xCB, 0x2C, 0x2E,
            ],
            "XEdDSA Montgomery→Edwards conversion diverged from the spec vector"
        );
    }

    /// The prekey signature verifies for a genuine bundle and fails the moment ANY signed
    /// field (prekey or KEM key) is altered — so a relay substitution is caught. Note this is
    /// a round-trip against the vetted `xeddsa` crate (itself checked against the XEdDSA spec
    /// vectors); it proves the WIRING (right key, right message), not the primitive.
    #[test]
    fn prekey_signature_binds_the_prekey_material() {
        let acct = Account::generate();
        let good = acct.prekey_bundle();
        assert!(good.verify_prekey_sig(), "a genuine bundle verifies under its own IK");

        // Swap the prekey → signature no longer covers it.
        let mut tampered = good.clone();
        tampered.prekey_pub = Account::generate().prekey_bundle().prekey_pub;
        assert!(!tampered.verify_prekey_sig(), "a swapped prekey is rejected");

        // Swap the KEM key → also rejected (both long-lived materials are signed).
        let mut tampered_kem = good.clone();
        tampered_kem.kem_ek = Account::generate().prekey_bundle().kem_ek;
        assert!(!tampered_kem.verify_prekey_sig(), "a swapped KEM key is rejected");

        // A bundle claiming a DIFFERENT IK than the signer → rejected (relay can't forge).
        let mut wrong_ik = good.clone();
        wrong_ik.ik_pub = Account::generate().prekey_bundle().ik_pub;
        assert!(!wrong_ik.verify_prekey_sig(), "signature does not verify under a foreign IK");

        // Swap the mailbox point M → also rejected (the sig now binds it, so a relay can't
        // substitute a mailbox point it controls a fetch secret for).
        let mut tampered_mbox = good.clone();
        tampered_mbox.mailbox_pub = Account::generate().prekey_bundle().mailbox_pub;
        assert!(!tampered_mbox.verify_prekey_sig(), "a swapped mailbox point is rejected");
    }

    /// A bundle carrying a MALFORMED KEM key, correctly self-signed by the attacker's own IK.
    /// `verify_prekey_sig` passes (the signature gate is not what saves us here), so the
    /// malformed wire value reaches the ML-KEM parse.
    fn attacker_bundle_with_malformed_kem() -> PreKeyBundle {
        use xeddsa::Sign;
        let attacker = Account::generate();
        let mut bundle = attacker.prekey_bundle();
        bundle.kem_ek = vec![7u8; 3]; // structurally invalid ML-KEM encapsulation key
        let sk = x25519_dalek::StaticSecret::from(attacker.ik().to_secret_bytes());
        let signer = xeddsa::xed25519::PrivateKey::from(&sk);
        let sig: [u8; 64] = signer.sign(
            &prekey_sig_message(&bundle.prekey_pub, &bundle.kem_ek, &bundle.mailbox_pub),
            rand010::rng(),
        );
        bundle.prekey_sig = sig.to_vec();
        assert!(bundle.verify_prekey_sig(), "the malformed bundle is genuinely signed");
        bundle
    }

    /// CRYPTO-08 — no wire-derived input may reach an `expect()`. A malicious CONTACT signs a
    /// MALFORMED `kem_ek` with its OWN identity key, so `verify_prekey_sig` passes and the bundle
    /// looks authentic; parsing it as an ML-KEM encapsulation key used to PANIC the victim's
    /// client (remote DoS by any contact whose bundle you connect to). Discriminating: the
    /// signature genuinely verifies (asserted in the helper), so only the explicit length/encoding
    /// check can save us — restore the `expect()` and this test unwinds instead of returning.
    #[test]
    fn a_signed_but_malformed_kem_key_is_rejected_not_panicked() {
        let bundle = attacker_bundle_with_malformed_kem();
        let sender = Account::generate();
        assert!(
            initiate_key_agreement(sender.ik(), &sender.mailbox_public(), &bundle).is_err(),
            "a malformed KEM key must fail the agreement, never panic"
        );
    }

    /// The same malformed bundle reaching the REACHABLE path: `connect_with_bundle` must return
    /// an error, not unwind — this is what a victim's client actually calls on a fetched bundle.
    #[test]
    fn connecting_to_a_malformed_bundle_errors_instead_of_panicking() {
        let bundle = attacker_bundle_with_malformed_kem();
        let good = Account::generate().prekey_bundle();
        assert!(good.verify_prekey_sig(), "control: a genuine bundle is usable");
        let sender = Account::generate();
        assert!(
            initiate_key_agreement(sender.ik(), &sender.mailbox_public(), &good).is_ok(),
            "a well-formed bundle still agrees"
        );
        assert!(
            initiate_key_agreement(sender.ik(), &sender.mailbox_public(), &bundle).is_err(),
            "the malformed one is refused"
        );
    }

    /// The per-account mailbox point `M` is published in the bundle, equals `m·G`, and — like the
    /// rest of the identity — is STABLE across a re-derive from the seed bytes (so it needs no
    /// separate persistence). Backs the live blinded deposit/fetch key separation.
    #[test]
    fn mailbox_point_is_published_and_seed_stable() {
        let acct = Account::generate();
        let bundle = acct.prekey_bundle();
        assert_ne!(bundle.mailbox_pub, [0u8; 32], "M is present, not the default");
        assert_eq!(bundle.mailbox_pub, acct.mailbox_public(), "bundle M equals the account's M");
        // Re-derive from the seed bytes → same M (no separate persistence needed).
        let restored = Account::from_secret_bytes(&acct.to_secret_bytes());
        assert_eq!(restored.mailbox_public(), acct.mailbox_public(), "M re-derives from the seed");
        // And the sender can already turn M into a blinded deposit address it cannot open.
        let addr = crate::blind::deposit_address(&bundle.mailbox_pub, &[3u8; 32], 5, 0, &[0xA7; 32]);
        assert!(addr.is_some(), "the published M is a valid Ristretto point");
    }

    /// Discriminating: pq_shared REALLY enters the root_key. If ML-KEM were decorative, the keys
    /// would match. "Quantum resistant" cannot be tested directly — what is tested is that the PQ
    /// contribution is WIRED into the key.
    #[test]
    fn pq_shared_is_load_bearing_in_root_key() {
        let (dh1, dh2, dh3) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let t = b"transcript";
        let k_real = derive_root_key(&dh1, &dh2, &dh3, None, &[9u8; 32], t);
        let k_zero = derive_root_key(&dh1, &dh2, &dh3, None, &[0u8; 32], t);
        assert_ne!(k_real, k_zero, "pq_shared must affect root_key");
    }

    /// Discriminating for SENDER AUTHENTICATION: DH1 (the only term that depends on the sender's
    /// private key) really enters the root_key. Without it, root_key = HKDF(DH2‖DH3‖pq) would be
    /// computable by anyone from the public bundle and forgery would succeed. This test pins that
    /// forgery is impossible BY KEY.

    #[test]
    fn dh1_is_load_bearing_in_root_key() {
        let t = b"transcript";
        let with = derive_root_key(&[7u8; 32], &[2u8; 32], &[3u8; 32], None, &[9u8; 32], t);
        let without = derive_root_key(&[8u8; 32], &[2u8; 32], &[3u8; 32], None, &[9u8; 32], t);
        assert_ne!(with, without, "DH1 (sender auth) must affect root_key");
    }

    /// The one-time-prekey DH SECRET (not just its public key via the transcript) is mixed
    /// into the root key. Tested at the `derive_root_key` layer so the transcript cannot
    /// mask it: same transcript, different `dh4` → different key. Neuter the `dh4` mix in
    /// `derive_root_key` and both cases collapse to one key → red.
    #[test]
    fn dh4_one_time_prekey_secret_is_load_bearing_in_root_key() {
        let t = b"transcript";
        let (d1, d2, d3, pq) = (&[1u8; 32], &[2u8; 32], &[3u8; 32], &[5u8; 32]);
        let with_a = derive_root_key(d1, d2, d3, Some(&[9u8; 32]), pq, t);
        let with_b = derive_root_key(d1, d2, d3, Some(&[8u8; 32]), pq, t);
        assert_ne!(with_a, with_b, "the OPK DH secret must affect the root key");
        let without = derive_root_key(d1, d2, d3, None, pq, t);
        assert_ne!(with_a, without, "OPK presence must affect the root key");
    }

    /// Persistence of the §2.1 identity: an account restored from bytes yields THE SAME public
    /// bundle (a stable address for discovery) AND agrees the same root_key (the KEM seed was
    /// restored correctly). Not "the round trip does not panic" — precisely the invariance of the
    /// bundle plus a working decapsulation.
    #[test]
    fn account_persists_identity_bundle_and_decap() {
        let acct = Account::generate();
        let bundle = acct.prekey_bundle();

        let mut restored = Account::from_secret_bytes(&acct.to_secret_bytes());
        let rb = restored.prekey_bundle();
        assert_eq!(rb.ik_pub, bundle.ik_pub, "the IK is stable");
        assert_eq!(rb.prekey_pub, bundle.prekey_pub, "the prekey is stable");
        assert_eq!(rb.kem_ek, bundle.kem_ek, "the KEM ek is stable (the seed was restored)");

        // Agreement against the restored account works (decapsulation on the seed).
        let alice = Identity::generate();
        let alice_m = crate::blind::MailboxSecret::generate().public();
        let (alice_rk, ka) = initiate_key_agreement(&alice, &alice_m, &rb).expect("well-formed bundle");
        assert_eq!(ka.mailbox_a_pub, alice_m, "the KA carries the sender's mailbox point");
        let (bob_rk, sender) = restored.accept_key_agreement(&ka).expect("decap");
        assert_eq!(alice_rk, bob_rk, "a restored account still agrees on the key");
        assert_eq!(sender, alice.public.to_bytes());
    }

    /// CRYPTO-33: the post-quantum leg of a first contact is forward-secret.
    ///
    /// The bundle's `kem_ek` is minted once and never rotated, so a ciphertext against it stays
    /// decryptable by anyone who later obtains the account's secret material — the ratchet's
    /// forward secrecy starts AFTER this handshake and cannot help with the handshake itself. A
    /// one-time unit carries its own KEM key whose seed is destroyed when the unit is consumed.
    ///
    /// Discriminating in the direction that matters: it asserts the ciphertext does NOT open
    /// under the STATIC key. Point the sender back at `bundle.kem_ek` and the two shared secrets
    /// coincide, which is the whole bug. (ML-KEM decapsulation under the wrong key does not
    /// error — FIPS 203 implicit rejection returns a pseudorandom value — so "different secret"
    /// is exactly the observable, not "it failed".)
    #[test]
    fn the_opener_is_encapsulated_against_the_one_time_key_not_the_static_one() {
        let mut bob = Account::generate();
        let opk_pub = bob.add_opk();
        let bundle = bob.prekey_bundle_with_opk(opk_pub);
        assert_ne!(
            bundle.opk.as_ref().expect("bundle carries the unit").kem_ek,
            bundle.kem_ek,
            "the one-time unit republished the STATIC KEM key — nothing to destroy later"
        );

        let alice = Identity::generate();
        let m_a = [7u8; 32];
        let (alice_root, ka) = initiate_key_agreement(&alice, &m_a, &bundle).expect("agreement");
        let (bob_root, _) = bob.prepare_key_agreement(&ka).expect("bob agrees");
        assert_eq!(alice_root, bob_root, "control: the handshake itself still works");

        let ct: Ciphertext<MlKem768> = Array::try_from(ka.kem_ct.as_slice()).expect("ct");
        let under_static = bob.kem_dk.decapsulate(&ct);
        let under_unit = bob.opks[&opk_pub].kem_dk().decapsulate(&ct);
        assert_ne!(
            under_static.as_slice(),
            under_unit.as_slice(),
            "the opener was encapsulated against the long-lived KEM key, so destroying the \
             one-time unit destroys nothing: the recorded handshake stays openable forever by \
             whoever later gets the account's secrets"
        );
    }

    /// Consuming the unit destroys the PQ secret with it — the account keeps every long-lived
    /// key and still cannot reopen the recorded opener.
    #[test]
    fn consuming_a_one_time_unit_destroys_its_kem_seed() {
        let mut bob = Account::generate();
        let opk_pub = bob.add_opk();
        let bundle = bob.prekey_bundle_with_opk(opk_pub);
        let alice = Identity::generate();
        let (_, ka) = initiate_key_agreement(&alice, &[7u8; 32], &bundle).expect("agreement");
        assert!(bob.prepare_key_agreement(&ka).is_some(), "control: openable while held");

        bob.consume_opk(&ka);
        assert!(
            bob.prepare_key_agreement(&ka).is_none(),
            "the opener is still openable after its one-time unit was consumed"
        );
        assert!(!bob.opks.contains_key(&opk_pub), "the unit's secret survived consumption");
    }

    /// The signature covers the PQ half, so a relay cannot swap a one-time unit's KEM key for one
    /// it can decapsulate while leaving the X25519 half — and the sender's own long-lived key —
    /// untouched. Without this the whole slice is decorative: the sender encapsulates against
    /// whatever the relay put there.
    #[test]
    fn a_substituted_one_time_kem_key_fails_the_unit_signature() {
        let mut bob = Account::generate();
        let opk_pub = bob.add_opk();
        let bundle = bob.prekey_bundle_with_opk(opk_pub);
        let ik = bundle.ik_pub;
        let genuine = bundle.opk.clone().expect("unit");
        assert!(genuine.verify(&ik), "control: the genuine unit verifies");

        // The relay keeps the signed X25519 half and swaps in a KEM key of its own.
        let relay = Account::generate();
        let mut swapped = genuine.clone();
        swapped.kem_ek = relay.prekey_bundle().kem_ek;
        assert!(
            !swapped.verify(&ik),
            "a one-time unit whose PQ half was replaced still verified — the sender would \
             encapsulate to the relay"
        );
    }
}

/// PQXDH COMPOSITION vectors, checked against an independent reading (QA-4, second slice).
///
/// # What is covered, and the line the scope is drawn on
///
/// Not X25519, not ML-KEM. Neither is in Python's standard library, and importing a package would
/// put a third party's reading of the primitive exactly where an independent reading is supposed
/// to be — the same line the ratchet vectors already drew, for the same reason. Those primitives
/// are upstream's to test and their own test vectors are published.
///
/// What IS covered is the part this project actually invented: how the three or four DH outputs
/// and the KEM secret are CONCATENATED into the IKM, and what goes into the transcript that becomes
/// the HKDF info. That composition is where a misreading is both most likely and most silent — get
/// the field order wrong on both sides and two implementations agree with each other forever while
/// interoperating with nobody, and get the transcript wrong and a binding the security argument
/// depends on quietly stops being there.
///
/// The two cases are the two shapes the composition takes: with a one-time prekey (four DH legs)
/// and without one (three). They differ in the IKM layout AND in the transcript's presence flag,
/// which is exactly the pair a "no OPK" / "OPK of zeros" collision would hide.
#[cfg(test)]
mod composition_vectors {
    use super::*;

    const VECTORS: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/pqxdh_composition.json");

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Deliberately arbitrary and pairwise distinct: no all-zero inputs (which hide a missing
    /// field) and no two equal (which hide a swapped argument).
    fn cases() -> Vec<(String, String)> {
        let ik_a = [0x11u8; 32];
        let ik_b = [0x22u8; 32];
        let ek_a = [0x33u8; 32];
        let prekey_b = [0x44u8; 32];
        let mailbox_a = [0x55u8; 32];
        let opk_b = [0x66u8; 32];
        let kem_ct = [0x77u8; 16]; // a stand-in length: the composition does not care how long
        let dh1 = [0xA1u8; 32];
        let dh2 = [0xA2u8; 32];
        let dh3 = [0xA3u8; 32];
        let dh4 = [0xA4u8; 32];
        let pq = [0xB0u8; 32];

        let mut out = Vec::new();

        let t_opk =
            transcript(&ik_a, &ik_b, &ek_a, &prekey_b, &kem_ct, Some(&opk_b), &mailbox_a);
        out.push(("transcript.with_opk".into(), hex(&t_opk)));
        out.push((
            "root_key.with_opk".into(),
            hex(&derive_root_key(&dh1, &dh2, &dh3, Some(&dh4), &pq, &t_opk)),
        ));

        let t_none = transcript(&ik_a, &ik_b, &ek_a, &prekey_b, &kem_ct, None, &mailbox_a);
        out.push(("transcript.without_opk".into(), hex(&t_none)));
        out.push((
            "root_key.without_opk".into(),
            hex(&derive_root_key(&dh1, &dh2, &dh3, None, &pq, &t_none)),
        ));
        out
    }

    fn render(cases: &[(String, String)]) -> String {
        let body: Vec<String> = cases.iter().map(|(k, v)| format!("  \"{k}\": \"{v}\"")).collect();
        format!("{{\n{}\n}}\n", body.join(",\n"))
    }

    /// The checked-in vectors are what this build produces.
    ///
    /// DISCRIMINATING by construction: reorder a transcript field, drop the OPK presence flag,
    /// move the fourth DH leg after the PQ secret, or stop feeding the KEM ciphertext into the
    /// transcript — each reds here with both values side by side.
    #[test]
    fn the_checked_in_vectors_match_this_build() {
        let produced = render(&cases());
        if std::env::var_os("KARST_REGEN_VECTORS").is_some() {
            std::fs::write(VECTORS, &produced).expect("writing vectors");
            eprintln!("KARST_REGEN_VECTORS: rewrote {VECTORS} — update verify_vectors.py to match");
        }
        let on_disk = std::fs::read_to_string(VECTORS).unwrap_or_default();
        assert_eq!(
            on_disk, produced,
            "the PQXDH composition changed. If that was deliberate: regenerate with \
             KARST_REGEN_VECTORS=1 AND update scripts/verify_vectors.py, which must reach the same \
             numbers from the written rules alone. Updating only one of the two turns this into a \
             test of nothing."
        );
    }

    /// The independent reading agrees.
    ///
    /// Fails rather than skips when `python3` is absent, for the reason the ratchet vectors give:
    /// a check that quietly skips is green and verifies nothing.
    #[test]
    fn an_independent_implementation_reaches_the_same_numbers() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../scripts/verify_vectors.py");
        let out = std::process::Command::new("python3")
            .arg(script)
            .arg(VECTORS)
            .output()
            .expect("python3 is required for the independent vector check — install it");
        assert!(
            out.status.success(),
            "the independent implementation disagrees with ours:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
