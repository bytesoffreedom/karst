//! A hybrid (X25519 + ML-KEM-768) sealed box for the SKELETON.
//!
//! # THIS IS NOT §2.1. Explicitly and loudly:
//!
//! `SkeletonSeal` is a sealed box (ephemeral X25519 to the recipient's static key, HKDF-SHA256,
//! ChaCha20-Poly1305). It does **NOT** have:
//! - **sender authentication.** A sealed box gives Bob confidentiality but says nothing about the
//!   message being from Alice — anyone who can reach the relay can seal to Bob. Real §2.1
//!   (X3DH/PQXDH) authenticates the sender by her long-term key; here sender auth is zero.
//!   Consequence: admission (§7) authenticates Alice TO THE RELAY, not to Bob — different
//!   parties; only an E2E layer can give the recipient assurance, and there is none here (yet);
//!
//!
//! - forward secrecy and a Double Ratchet (the key is derived from the recipient's STATIC keys —
//!   compromising those secrets reveals every past message).
//!
//!
//!
//! # Post-quantum protection IS present (PRIV-3), and the boundary must be stated precisely
//!
//! The AEAD key is derived from TWO secrets: an ephemeral X25519 against the recipient's static
//! `ik`, AND ML-KEM-768 against their long-lived `kem_ek`. The `pq_shared` slot in `derive_key`
//! `ik`, AND ML-KEM-768 against their long-lived `kem_ek`. The `pq_shared` slot in `derive_key`
//! was left for exactly this — adding it turned out to be filling a slot rather than a rewrite.
//!
//! What it CLOSED: harvest-now-decrypt-later against the social graph. An adversary who recorded
//! an opener today can no longer reconstruct "who wrote to whom first" by breaking one X25519 with
//! a quantum computer — both secrets are needed at once, and ML-KEM-768 does not yield to quantum
//! search.
//!
//! What it did NOT close, and this is not a small caveat: **there is still no forward secrecy
//! here.** Both of the recipient's keys are long-lived (a one-time KEM key cannot be used — which
//! unit was taken is recorded INSIDE the sealed envelope, see the `kem_ct` field), so whoever
//! later obtains the account's secret material can decrypt recorded openers. It did not get
//! worse: the classical half always had this property. What changed is that a quantum computer
//! alone, without a compromise, is no longer enough.
//!
//!
//! Sender auth is still zero, and that is NOT a defect: it is precisely the absence of a sender
//! signature that makes the envelope anonymous to the relay. Who actually wrote it is stated only
//! by the PQXDH inside.
//!
//! The purpose of the rest is to prove that the message path (admission §7 ↔ E2E) composes. The
//! real E2E layer is PQXDH plus the Double Ratchet.

use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport, Kem, TryKeyInit};
use ml_kem::{Ciphertext, DecapsulationKey, EncapsulationKey, MlKem768};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// The recipient's static identifier (for the skeleton, a long-lived X25519 key).
/// Real §2.1 replaces it with a prekey bundle.
#[derive(Clone)]
pub struct Identity {
    secret: StaticSecret,
    pub public: PublicKey,
}

impl Identity {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Identity { secret, public }
    }

    /// Serialise the secret for storage. **CAUTION:** this is a private key IN THE CLEAR. The
    /// caller must write it under 0600; at-rest encryption (a password KDF) is deferred and not
    /// implemented here.
    pub fn to_secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Restore an identity from a stored secret.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Identity { secret, public }
    }

    /// Static-static Diffie–Hellman with a foreign public key. The basis of fetch-auth (§7 mailbox
    /// ownership): `X25519(id_sec, peer)` is symmetric with `X25519(peer_sec, id_pub)`, so both
    /// sides obtain the same shared secret. It does NOT reveal the secret — only the shared DH.
    /// This is the identity key's second use in a DH (the first being the ephemeral-static seal);
    /// the domains are separated at the KDF level (`fetch_auth` vs `seal`).

    pub fn dh(&self, peer: &PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(peer).to_bytes()
    }

    /// Static-static DH that REJECTS a non-contributory result — i.e. a peer point of small
    /// order, for which the shared secret is all-zero and therefore KNOWN to everyone. This is
    /// the guard `node::mailbox_owner_ok` already applies to the fetch proof, lifted into one
    /// place so every PROTOCOL DH can use it (CRYPTO-06).
    ///
    /// Why it matters most in the ratchet: an active adversary who knows the current state can
    /// offer a small-order ratchet key so the DH step contributes NOTHING, stripping the fresh
    /// entropy that gives post-compromise security (healing). In PQXDH the ML-KEM leg and the
    /// other DH legs blunt a single zero leg, but a zero leg is never legitimate — reject it.
    ///
    /// `None` = non-contributory (constant-time check via `was_contributory`).
    pub fn dh_checked(&self, peer: &PublicKey) -> Option<[u8; 32]> {
        let shared = self.secret.diffie_hellman(peer);
        shared.was_contributory().then(|| shared.to_bytes())
    }

    /// Key for issuing STATELESS PoW capabilities (slice 4a, the Public door). A
    /// domain-separated hash of the node's static secret, so it is PERSISTENT with the node
    /// key (a PoW cap survives a relay restart) yet never exposes the raw secret. Third use
    /// of the identity key, domain-separated from `seal`/`fetch_auth` by the label.
    pub fn issuer_key(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"KARST-cap-issuer-v1");
        h.update(self.secret.to_bytes());
        h.finalize().into()
    }
}

/// A sealed message on the wire.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SkeletonSeal {
    /// The sender's ephemeral public key.
    pub ephemeral_pub: [u8; 32],
    /// **ML-KEM-768 ciphertext to the recipient's LONG-LIVED encapsulation key** (PRIV-3).
    ///
    /// Long-lived and not the one-time KEM key, and that is forced rather than chosen: which
    /// one-time unit a sender used is recorded in `opk_pub` INSIDE the sealed key agreement, so a
    /// recipient cannot know which one-time secret to decapsulate with until it has already opened
    /// the seal. The inner handshake has no such problem (it reads the transcript after opening) and
    /// does use the one-time key — see `pqxdh::initiate_key_agreement`, CRYPTO-33.
    ///
    /// The honest consequence, stated where the field is: this layer is NOT forward-secret. Someone
    /// who later obtains the account's long-lived KEM secret can decapsulate recorded openers and
    /// recover who first wrote to whom. That is the same exposure the classical half already had
    /// (an ephemeral X25519 against a STATIC identity key), so nothing got weaker — what changed is
    /// that a quantum adversary with no secret at all no longer suffices, which is precisely the
    /// harvest-now-decrypt-later threat this envelope hides the social graph from.
    pub kem_ct: Vec<u8>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Derive the AEAD key from the shared secret — a hybrid of X25519 and ML-KEM-768.
///
/// `pq_shared` is no longer empty: the slot left for ML-KEM is filled (PRIV-3). The order is fixed
/// (classical, then PQ) and is part of the format: swapping it silently breaks compatibility, so
/// it must be a version break rather than an edit.
///
/// Both public keys (the recipient's and the sender's ephemeral) are bound in — the same "bind the
/// whole transcript" lesson as in Fiat–Shamir.
fn derive_key(
    classical_dh: &[u8; 32],
    pq_shared: &[u8],
    recipient_pub: &[u8; 32],
    ephemeral_pub: &[u8; 32],
) -> Key {
    let mut ikm = Vec::with_capacity(32 + pq_shared.len());
    ikm.extend_from_slice(classical_dh);
    ikm.extend_from_slice(pq_shared); // empty for now; the slot reserved for ML-KEM
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut info = Vec::new();
    info.extend_from_slice(b"KARST-skeleton-seal-v1");
    info.extend_from_slice(recipient_pub);
    info.extend_from_slice(ephemeral_pub);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("32 within HKDF output limit");
    *Key::from_slice(&okm)
}

/// Additional authenticated data — binding the keys AND the PQ ciphertext.
///
/// `kem_ct` is included deliberately: without it, it stays unauthenticated. A substituted `kem_ct`
/// would give a different `pq_shared`, hence a different AEAD key, and the envelope would not
/// open — but "did not open" and "rejected as forged" are different things to whoever reads the
/// log afterwards. Binding it leaves exactly one reason for the refusal.
fn aad(recipient_pub: &[u8; 32], ephemeral_pub: &[u8; 32], kem_ct: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(64 + kem_ct.len());
    a.extend_from_slice(recipient_pub);
    a.extend_from_slice(ephemeral_pub);
    a.extend_from_slice(kem_ct);
    a
}

/// A recipient's ML-KEM half for the hybrid seal, kept OPAQUE (PRIV-3).
///
/// Exists so callers outside this crate never have to name an `ml_kem` type. That is not tidiness:
/// the moment `DecapsulationKey<MlKem768>` appears in another crate's struct field, that crate needs
/// its own `ml-kem` dependency pinned to a matching version, and a KEM upgrade turns into a
/// multi-crate change instead of a change here. The real account path uses `pqxdh::Account`'s own
/// key; this is for the skeleton path, which has no bundle to publish one in.
pub struct SealKemKeys {
    dk: DecapsulationKey<MlKem768>,
    ek: Vec<u8>,
}

impl SealKemKeys {
    /// Wrap an EXISTING decapsulation key — for a recipient whose KEM key is derived, not minted.
    ///
    /// The skeleton path needs this: its recipient identity comes from the recovery phrase, so its
    /// KEM key has to come from the same seed. A freshly generated one cannot work at all — the
    /// sender would have no way to learn it, and the envelope would authenticate and never open.
    pub fn from_dk(dk: DecapsulationKey<MlKem768>) -> Self {
        let ek = dk.encapsulation_key().to_bytes().as_slice().to_vec();
        SealKemKeys { dk, ek }
    }

    pub fn generate() -> Self {
        let (dk, _ek) = <MlKem768 as Kem>::generate_keypair();
        let ek = dk.encapsulation_key().to_bytes().as_slice().to_vec();
        SealKemKeys { dk, ek }
    }

    /// The encapsulation key a sender needs — the public half.
    pub fn ek(&self) -> &[u8] {
        &self.ek
    }

    /// Open a seal addressed to `identity` and these KEM keys.
    pub fn open(&self, seal: &SkeletonSeal, identity: &Identity) -> Option<Vec<u8>> {
        seal.open(identity, &self.dk)
    }
}

impl SkeletonSeal {
    /// Seal `plaintext` for the recipient: X25519 `recipient_pub` plus ML-KEM `recipient_kem_ek`.
    ///
    /// `recipient_kem_ek` is the long-lived `kem_ek` from the recipient's bundle (see the `kem_ct`
    /// field for why long-lived rather than one-time). It returns `Err` rather than panicking:
    /// this key comes FROM THE WIRE — the bundle signature covers it, but a signature says nothing
    /// about the bytes parsing as an ML-KEM key. The same lesson as CRYPTO-08.
    pub fn seal(
        recipient_pub: &PublicKey,
        recipient_kem_ek: &[u8],
        plaintext: &[u8],
    ) -> Result<SkeletonSeal, String> {
        let ek = <EncapsulationKey<MlKem768> as TryKeyInit>::new_from_slice(recipient_kem_ek)
            .map_err(|_| "recipient KEM key is malformed".to_string())?;
        let (kem_ct_arr, pq_shared) = ek.encapsulate();
        let kem_ct = kem_ct_arr.as_slice().to_vec();

        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_pub = PublicKey::from(&ephemeral);
        let classical_dh = ephemeral.diffie_hellman(recipient_pub);

        let rp = recipient_pub.to_bytes();
        let ep = ephemeral_pub.to_bytes();
        let key = derive_key(classical_dh.as_bytes(), pq_shared.as_slice(), &rp, &ep);
        let cipher = ChaCha20Poly1305::new(&key);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload { msg: plaintext, aad: &aad(&rp, &ep, &kem_ct) },
            )
            .expect("AEAD encryption");

        Ok(SkeletonSeal { ephemeral_pub: ep, kem_ct, nonce: nonce_bytes, ciphertext: ct })
    }

    /// Decrypt with our own static secret. `None` when the AEAD does not verify (substitution or
    /// corruption — exactly what the layer-separation test catches).
    pub fn open(
        &self,
        recipient: &Identity,
        kem_dk: &DecapsulationKey<MlKem768>,
    ) -> Option<Vec<u8>> {
        let eph = PublicKey::from(self.ephemeral_pub);
        let classical_dh = recipient.secret.diffie_hellman(&eph);
        // A wire-supplied ciphertext of the wrong length is a `None`, not a panic — same rule as
        // the encapsulation key above, from the other direction.
        let ct: Ciphertext<MlKem768> = Array::try_from(self.kem_ct.as_slice()).ok()?;
        let pq_shared = kem_dk.decapsulate(&ct);
        let rp = recipient.public.to_bytes();
        let key = derive_key(classical_dh.as_bytes(), pq_shared.as_slice(), &rp, &self.ephemeral_pub);
        let cipher = ChaCha20Poly1305::new(&key);
        cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad(&rp, &self.ephemeral_pub, &self.kem_ct),
                },
            )
            .ok()
    }
}

/// **The seal is hybrid, and both halves are load-bearing** (PRIV-3).
///
/// The point of adding ML-KEM here is a specific adversary: one who records an opener today and
/// breaks X25519 with a quantum computer later, recovering who first wrote to whom. That claim is
/// only true if the PQ half genuinely gates decryption — if the classical secret alone still opened
/// the envelope, the field would be decoration and the claim would be false while looking true.
#[cfg(test)]
mod the_seal_needs_both_halves {
    use super::*;

    fn recipient() -> (Identity, SealKemKeys) {
        (Identity::generate(), SealKemKeys::generate())
    }

    #[test]
    fn a_round_trip_works_with_both_keys() {
        let (id, kem) = recipient();
        let sealed = SkeletonSeal::seal(&id.public, kem.ek(), b"who wrote to whom").expect("seals");
        assert_eq!(kem.open(&sealed, &id).expect("opens"), b"who wrote to whom");
    }

    /// **The PQ half gates decryption.** Holding the X25519 identity and NOT the KEM secret must not
    /// be enough — that is the whole claim.
    ///
    /// Discriminating: pass an empty `pq_shared` in `derive_key` (the pre-PRIV-3 behaviour) and this
    /// goes green again, because the classical secret would once more be sufficient.
    #[test]
    fn the_x25519_secret_alone_does_not_open_it() {
        let (id, kem) = recipient();
        let sealed = SkeletonSeal::seal(&id.public, kem.ek(), b"social graph").expect("seals");
        let wrong_kem = SealKemKeys::generate();
        assert!(
            wrong_kem.open(&sealed, &id).is_none(),
            "the envelope opened with the right X25519 identity and the WRONG ML-KEM secret. The \
             post-quantum half is then decoration: an adversary who breaks X25519 alone still \
             recovers who first wrote to whom, which is exactly the harvest-now-decrypt-later \
             threat this layer exists to stop."
        );
    }

    /// And the classical half still gates it too — a hybrid that quietly stopped using X25519 would
    /// be a downgrade wearing an upgrade's name.
    #[test]
    fn the_kem_secret_alone_does_not_open_it() {
        let (id, kem) = recipient();
        let sealed = SkeletonSeal::seal(&id.public, kem.ek(), b"social graph").expect("seals");
        let other = Identity::generate();
        assert!(kem.open(&sealed, &other).is_none(), "the wrong X25519 identity opened the seal");
    }

    /// `kem_ct` is authenticated, not merely used. Swapping it must be a clean AEAD failure.
    #[test]
    fn a_substituted_kem_ciphertext_is_refused() {
        let (id, kem) = recipient();
        let mut sealed = SkeletonSeal::seal(&id.public, kem.ek(), b"x").expect("seals");
        let other = SkeletonSeal::seal(&id.public, kem.ek(), b"y").expect("seals");
        sealed.kem_ct = other.kem_ct;
        assert!(kem.open(&sealed, &id).is_none(), "a swapped KEM ciphertext was accepted");
    }

    /// A malformed KEM key off the wire is an error, never a panic (the CRYPTO-08 lesson, applied
    /// to the new field): a contact signs its own bundle, so a signature says nothing about whether
    /// these bytes parse.
    #[test]
    fn a_malformed_recipient_kem_key_is_refused_not_panicked() {
        let id = Identity::generate();
        assert!(SkeletonSeal::seal(&id.public, &[7u8; 3], b"x").is_err());
        assert!(SkeletonSeal::seal(&id.public, &[], b"x").is_err());
    }

    /// A malformed ciphertext ON the way in is likewise a `None`.
    #[test]
    fn a_malformed_kem_ciphertext_is_refused_not_panicked() {
        let (id, kem) = recipient();
        let mut sealed = SkeletonSeal::seal(&id.public, kem.ek(), b"x").expect("seals");
        sealed.kem_ct = vec![1u8; 5];
        assert!(kem.open(&sealed, &id).is_none());
    }
}
