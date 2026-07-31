//! §2.1 — the Double Ratchet (classical X25519) on top of the PQXDH `root_key`.
//!
//! Per-message **forward secrecy** (a message key is deleted after use, the chain is one-way) plus
//! **post-compromise security** (a DH step on a fresh ephemeral heals a compromise). The PQ part
//! comes from the initial PQXDH (§2.1: the ratchet is classical, the hybrid lives in the
//! handshake). It follows the Signal Double Ratchet spec, as reference code over the primitives
//! (like PQXDH), and is NOT audited.
//!
//! # THIS SLICE and no more:
//! - **out-of-order is tolerated** (skipped message keys, per the Signal spec): missed keys are
//!   derived and stored, so out-of-order arrivals (a mailbox batch, DTN store-and-forward) still
//!   decrypt. Anti-DoS has two bounds: `MAX_SKIP` per receive step (against an unbounded KDF) and
//!   `MAX_STORE` in total with FIFO eviction (against memory and disk growth). It used to be
//!   strictly in-order, so a single drop killed the session — and crash consistency (advancing
//!   unconditionally on encrypt) produces drops by itself;
//! - no header encryption, no PQ ratchet, no weaving into the node path (a session is seeded with
//!   a raw `root_key`); no time-based expiry of skipped keys.
//!
//! # Transactionality (without it one corrupt packet breaks the session — and worse):
//! `decrypt` mutates a COPY and **verifies the AEAD BEFORE** committing. Beyond "a corrupt packet
//! does not break the session", this buys a property BEYOND the Signal spec: a forged message with
//! a large `n` does NOT fill the skipped store and does NOT advance `nr` (in literal Signal,
//! `SkipMessageKeys` mutates before DECRYPT) — an adversary without a valid AEAD tag cannot make
//! us store keys. The rollback is safe: the chain state rolls back together with the store, and a
//! retransmission derives the keys again.
//!
//! # The FS trade-off, named: skipped keys DO land at rest (in the snapshot — otherwise they are
//! lost between the client's recv calls, load→process→save, and the fix is useless). This weakens
//! FS non-retention for exactly those pending messages, over the window "until received or
//! evicted". It is the standard Signal trade for out-of-order tolerance; time-based expiry
//! (`wall_clock` exists) would bound the window directly — the next step.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Mac, SimpleHmac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::PublicKey;

use crate::seal::Identity;

const AAD_DOMAIN: &[u8] = b"KARST-ratchet-v2";

/// The maximum number of keys derived in ONE receive step (in each of up to two chains).
/// Anti-DoS: a forged `header.n`/`header.pn` cannot force an unbounded KDF.
const MAX_SKIP: u32 = 1000;
/// The maximum number of stored skipped keys IN TOTAL (FIFO eviction of the oldest). It must be
/// ≥ 2·MAX_SKIP: one decrypt across a chain boundary can add up to MAX_SKIP (the old chain, `pn`)
/// plus MAX_SKIP (the new one, `n`) — otherwise eviction would fire IN THE MIDDLE of a decrypt and
/// throw away exactly the gap fillers being inserted.
const MAX_STORE: usize = 2048;

/// How many DH-ratchet generations a skipped key may outlive. Out-of-order delivery spans at most
/// a chain boundary or two; anything older is not late mail, it is retention.
const MAX_SKIPPED_GENERATIONS: u64 = 4;

/// A stored skipped message key, identified by (the chain's ratchet public key, the number). `mk`
/// is the message key; it lands at rest (see the FS trade-off in the module docs).
#[derive(Clone, serde::Serialize, serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct SkippedKey {
    dh: [u8; 32],
    n: u32,
    mk: [u8; 32],
    /// Which DH-ratchet generation stored this key. Skipped keys were bounded in NUMBER but never
    /// expired, so one could sit at rest long past any plausible reordering window, widening the
    /// interval in which a device compromise yields plaintext for messages that may never even
    /// arrive (A6-9). Age is counted in RATCHET STEPS rather than wall-clock on purpose: the local
    /// clock is an unauthenticated input, and a chain that is several DH steps behind is stale by
    /// the protocol's own measure.
    gen: u64,
}

/// The message header: the sender's current ratchet public key, the length of the previous chain
/// (`pn`), the number within the current chain (`n`), and a per-message salt.
/// It is bound in full as AEAD associated data.
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct Header {
    pub dh: [u8; 32],
    pub pn: u32,
    pub n: u32,
    /// Fresh random per message; the AEAD key and nonce are derived from `(mk, salt)` rather
    /// than being `mk` with a zero nonce (CRYPTO-01 residual). See [`message_aead`] — this is
    /// what makes a ratchet-state ROLLBACK non-catastrophic instead of merely unlikely.
    pub salt: [u8; SALT_LEN],
}

/// Per-message salt width. 128 bits: a repeat needs ~2^64 messages in ONE chain, while the
/// cost is 16 bytes per message, which stays inside the current padding bucket (pinned by
/// `a_full_size_chunk_still_fits_its_padding_bucket`) so the change is invisible on the wire.
pub const SALT_LEN: usize = 16;

/// A message on the wire.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RatchetMessage {
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RatchetError {
    /// A jump of more than `MAX_SKIP` in a single receive step (the anti-DoS bound). Not merely
    /// "out of order" — moderate out-of-order arrival is tolerated now.
    OutOfOrder,
    /// There is no receiving chain (no first message has arrived).
    NoReceivingChain,
    /// The AEAD did not verify (substitution or a foreign key).
    Decrypt,
    /// The header carried a small-order ratchet key: the DH step would NOT be contributory (the
    /// shared secret would be zeros, known to the attacker), which would kill the PCS healing.
    /// The state is NOT advanced (`decrypt` is transactional) — CRYPTO-06.
    NonContributoryDh,
}

/// Double-Ratchet session state. `Clone` exists for the transactional decrypt (mutate a copy,
/// commit only once the AEAD verifies).
///
/// `ZeroizeOnDrop` (CRYPTO-09): the root key, both chain keys and every stored skipped message
/// key are overwritten when the session — including each transient decrypt CLONE — is dropped.
/// The clone matters most: a failed decrypt throws its copy away, and that copy held the same
/// chain keys as the original.
///
/// HONEST LIMIT: this scrubs what the value owns at drop time. A move is a memcpy and does not
/// scrub the source, the allocator may have reused the page, and the OS may have paged it out
/// first. It shortens the window; it does not close it.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Session {
    // `x25519_dalek::StaticSecret` inside `Identity` is already `ZeroizeOnDrop`, so scrubbing it
    // again here would be a second pass over bytes dalek has cleared — skipped, not forgotten.
    #[zeroize(skip)]
    dhs: Identity,           // our ratchet pair
    dhr: Option<[u8; 32]>,   // the peer's ratchet public key
    rk: [u8; 32],            // root key
    cks: Option<[u8; 32]>,   // sending chain key
    ckr: Option<[u8; 32]>,   // receiving chain key
    ns: u32,                 // send counter
    nr: u32,                 // receive counter
    pn: u32,                 // length of the previous sending chain
    skipped: Vec<SkippedKey>, // skipped (out-of-order) keys, FIFO-bounded
    /// Counts DH-ratchet steps, so a skipped key can be aged out by protocol progress rather than
    /// by an unauthenticated wall clock (A6-9).
    dh_gen: u64,
    /// **Routing contribution produced by the last DH step**, waiting to be taken by the session
    /// layer (PRIV-2). NOT key material for messages — a domain-separated derivative of the step's
    /// FIRST DH output, which is the one value the peer provably already holds (it computed the
    /// same number as its own second output, one leg earlier). That asymmetry is the whole reason
    /// routing can heal at all: a contribution taken from the step's SECOND output would need a
    /// key the peer has not received yet, so the recipient could never derive the address it is
    /// supposed to poll.
    ///
    /// Deliberately not the raw DH: nothing outside this module should ever hold that.
    routing_contribs: Vec<[u8; 32]>,
}

/// The persistent form of a session (to resume the ratchet across CLI process invocations). Chain
/// and root keys, the private ratchet key, and ONLY the skipped (out-of-order) `mk`s. Per-message
/// keys of messages received IN ORDER never reach the disk (they are local to encrypt/decrypt), so
/// FS non-retention holds for them; skipped keys are persisted DELIBERATELY (without that the fix
/// does not survive a reload — see the FS trade-off in the module docs). `dhs_secret` is a private
/// key in the clear: the caller must write it under 0600 (here at rest, through `client::Store`).
/// Handled by the caller writing it under 0600 (here at rest, through `client::Store`).
/// Zeroized on drop for the same reason as `Session` (CRYPTO-09): a snapshot is the SAME key
/// material in a serializable shape, and it exists exactly in the window where it is copied
/// around — taken, encoded, sealed, dropped.
#[derive(serde::Serialize, serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SessionSnapshot {
    dhs_secret: [u8; 32],
    dhr: Option<[u8; 32]>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    /// Skipped keys — persisted DELIBERATELY (the FS trade-off, see the module docs): without them
    /// the out-of-order fix does not survive the client's `load→process→save`.
    skipped: Vec<SkippedKey>,
    dh_gen: u64,
    /// Persisted because it is produced on decrypt and consumed by the session layer AFTER the
    /// durable save: dropping it on restart would silently skip one routing generation, and the
    /// two sides would then disagree about the address with no error anywhere.
    routing_contribs: Vec<[u8; 32]>,
}

impl Session {
    /// Take a snapshot for persistence (see `SessionSnapshot`).
    pub fn snapshot(&self) -> SessionSnapshot {
        SessionSnapshot {
            dhs_secret: self.dhs.to_secret_bytes(),
            dhr: self.dhr,
            rk: self.rk,
            cks: self.cks,
            ckr: self.ckr,
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            skipped: self.skipped.clone(),
            dh_gen: self.dh_gen,
            routing_contribs: self.routing_contribs.clone(),
        }
    }

    /// Restore a session from a snapshot.
    pub fn restore(mut s: SessionSnapshot) -> Self {
        Session {
            dhs: Identity::from_secret_bytes(s.dhs_secret),
            dhr: s.dhr,
            rk: s.rk,
            cks: s.cks,
            ckr: s.ckr,
            ns: s.ns,
            nr: s.nr,
            pn: s.pn,
            // `SessionSnapshot` zeroizes on drop, which makes it non-`Copy` and unmovable field
            // by field — take the vector out and leave an empty one behind for the drop to scrub.
            skipped: std::mem::take(&mut s.skipped),
            dh_gen: s.dh_gen,
            routing_contribs: s.routing_contribs.clone(),
        }
    }

    /// The initiator (Alice): knows the recipient's ratchet public key (their PQXDH prekey).
    pub fn init_sender(root_key: [u8; 32], their_ratchet_pub: [u8; 32]) -> Self {
        let dhs = Identity::generate();
        let dh_out = dhs.dh(&PublicKey::from(their_ratchet_pub));
        let (rk, cks) = kdf_rk(&root_key, &dh_out);
        // The FIRST element of the shared sequence. The responder computes the same number as the
        // first DH of its own first step, so both sides start the routing chain from it — without
        // this the two sequences would be offset by one element forever and never agree.
        let first_contrib = vec![routing_contrib(&dh_out)];
        Session {
            dhs,
            dhr: Some(their_ratchet_pub),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: Vec::new(),
            dh_gen: 0,
            routing_contribs: first_contrib,
        }
    }

    /// The recipient (Bob): their ratchet pair is the prekey from the PQXDH bundle. The first
    /// sending chain arrives with the DH step on the first incoming message.
    pub fn init_receiver(root_key: [u8; 32], our_ratchet_key: Identity) -> Self {
        Session {
            dhs: our_ratchet_key,
            dhr: None,
            rk: root_key,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: Vec::new(),
            dh_gen: 0,
            routing_contribs: Vec::new(),
        }
    }

    /// The ratchet public key of our current pair (for the peer's init_sender).
    pub fn ratchet_public(&self) -> [u8; 32] {
        self.dhs.public.to_bytes()
    }

    /// Encrypt a message. Requires a sending chain (Alice has one from init; Bob after the first
    /// decrypt).
    ///
    /// The AEAD key/nonce come from `(mk, fresh salt)`, not from `mk` with a zero nonce. A fresh
    /// message key per message made the zero nonce *safe*, but only for as long as the chain
    /// never goes backwards — and a chain CAN go backwards: restore a backup, clone the disk,
    /// roll back the VM. `cks` then re-derives the same `mk` and, with a fixed nonce, encrypts a
    /// DIFFERENT plaintext under the identical key+nonce: keystream reuse (XOR of the two
    /// plaintexts) plus a reused Poly1305 key. Rollback cannot be *prevented* by a program that
    /// keeps its state in files the attacker can restore, so it is made harmless instead.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> RatchetMessage {
        let ck = self.cks.expect("sending chain (the recipient must receive before we send)");
        let (ck_next, mk) = kdf_ck(&ck);
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let header = Header { dh: self.dhs.public.to_bytes(), pn: self.pn, n: self.ns, salt };
        self.cks = Some(ck_next);
        self.ns += 1;
        let ciphertext = aead_encrypt(&mk, plaintext, &aad(&header), &header.salt);
        RatchetMessage { header, ciphertext }
    }

    /// Take the routing contributions produced since the last call, in the order computed (PRIV-2).
    ///
    /// A step produces TWO, and the sender's init produces one. That is not an implementation
    /// detail — it is the reason the two sides agree at all. The DH outputs form ONE sequence
    /// `v0, v1, v2, …` that both sides walk in the same order, each computing two of them per step
    /// with a one-element overlap. Folding only ONE output per step was tried first and is wrong in
    /// a way no amount of reasoning caught: each side then takes only the even or only the odd
    /// elements, the sequences are DISJOINT, and the recipient can never derive the sender's
    /// address. A test in this module pins the agreement precisely because that mistake looks
    /// correct on paper.
    ///
    /// Take, not read: exactly one caller may fold it into the routing chain, and folding the same
    /// contribution twice would advance one side's generation past the other's with nothing to say
    /// so — the two would then derive different addresses and mail would stop arriving with no
    /// error anywhere. Consuming it makes the double-fold impossible instead of discouraged.
    pub fn take_routing_contributions(&mut self) -> Vec<[u8; 32]> {
        std::mem::take(&mut self.routing_contribs)
    }

    /// Decrypt. TRANSACTIONAL: mutate a copy, verify the AEAD, commit only on success — a corrupt
    /// packet neither advances nor breaks the session.
    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>, RatchetError> {
        let mut staged = self.clone();
        let mk = staged.advance_for_decrypt(&msg.header)?;
        let pt = aead_decrypt(&mk, &msg.ciphertext, &aad(&msg.header), &msg.header.salt)
            .map_err(|_| RatchetError::Decrypt)?;
        *self = staged; // commit only after the AEAD verified
        Ok(pt)
    }

    /// Advance the STAGED state for this header and return the message key.
    /// Mutates `self` (a copy made by `decrypt`) and does NOT touch the AEAD. The algorithm is
    /// Signal's `RatchetDecrypt`: (1) a stored skipped key; (2) a DH step on a new ratchet key,
    /// filling the tail of the previous chain; (3) skips within the current chain up to `header.n`;
    /// (4) the key at exactly `header.n`.
    fn advance_for_decrypt(&mut self, header: &Header) -> Result<[u8; 32], RatchetError> {
        // (1) Out of order from this or the PREVIOUS chain — the key is already derived and stored.
        if let Some(mk) = self.take_skipped(header.dh, header.n) {
            return Ok(mk);
        }
        // (2) A new ratchet key from the peer → store the tail of the previous receiving chain
        // (nr..header.pn) and take a DH step (the PCS healing).
        if self.dhr != Some(header.dh) {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(header)?;
        }
        // (3) Skips within the current chain up to header.n (stored).
        self.skip_message_keys(header.n)?;
        // (4) The key at exactly header.n (here nr == header.n, in order or after the skips).
        let ck = self.ckr.ok_or(RatchetError::NoReceivingChain)?;
        let (ck_next, mk) = kdf_ck(&ck);
        self.ckr = Some(ck_next);
        self.nr += 1;
        Ok(mk)
    }

    /// Take a skipped key by (the chain's ratchet public key, the number), if it is stored.
    /// The removal is only fixed when `decrypt` commits (staged), so a replay or forgery without a
    /// valid AEAD cannot delete a key.
    fn take_skipped(&mut self, dh: [u8; 32], n: u32) -> Option<[u8; 32]> {
        let i = self.skipped.iter().position(|s| s.dh == dh && s.n == n)?;
        Some(self.skipped.remove(i).mk)
    }

    /// Store a skipped key; on overflow, FIFO-evict the oldest.
    fn store_skipped(&mut self, dh: [u8; 32], n: u32, mk: [u8; 32]) {
        if self.skipped.len() >= MAX_STORE {
            self.skipped.remove(0);
        }
        self.skipped.push(SkippedKey { dh, n, mk, gen: self.dh_gen });
    }

    /// Drop skipped keys older than `MAX_SKIPPED_GENERATIONS` DH steps — run on every ratchet
    /// step, so stale message keys stop living at rest indefinitely (A6-9).
    fn expire_skipped(&mut self) {
        let cutoff = self.dh_gen.saturating_sub(MAX_SKIPPED_GENERATIONS);
        self.skipped.retain(|s| s.gen >= cutoff);
    }

    /// Advance the receiving chain to `until`, STORING the skipped keys under the current `dhr`.
    /// Anti-DoS: a jump larger than `MAX_SKIP` at once is refused (with no keys derived).
    /// `until <= nr` is a no-op. Overflow-safe.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), RatchetError> {
        if until > self.nr && until - self.nr > MAX_SKIP {
            return Err(RatchetError::OutOfOrder);
        }
        if until <= self.nr {
            return Ok(());
        }
        let dh = self.dhr.ok_or(RatchetError::NoReceivingChain)?;
        while self.nr < until {
            let ck = self.ckr.ok_or(RatchetError::NoReceivingChain)?;
            let (ck_next, mk) = kdf_ck(&ck);
            self.store_skipped(dh, self.nr, mk);
            self.ckr = Some(ck_next);
            self.nr += 1;
        }
        Ok(())
    }

    /// The DH ratchet step: new receiving and sending chains on the peer's ratchet key.
    fn dh_ratchet(&mut self, header: &Header) -> Result<(), RatchetError> {
        // Reject a small-order ratchet key BEFORE touching state: its DH is all-zero, i.e. known
        // to the attacker, so the step would inject no fresh entropy and silently defeat the
        // healing (PCS) property this ratchet exists to provide (CRYPTO-06). `decrypt` stages a
        // clone and commits only on success, so returning Err here leaves the session untouched.
        let their = PublicKey::from(header.dh);
        let dh1 = self.dhs.dh_checked(&their).ok_or(RatchetError::NonContributoryDh)?;
        let dhs_new = Identity::generate();
        let dh2 = dhs_new.dh_checked(&their).ok_or(RatchetError::NonContributoryDh)?;
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        let (rk1, ckr) = kdf_rk(&self.rk, &dh1);
        let (rk2, cks) = kdf_rk(&rk1, &dh2);
        self.rk = rk2;
        self.dhr = Some(header.dh);
        self.dhs = dhs_new;
        self.ckr = Some(ckr);
        self.cks = Some(cks);
        // PRIV-2: hand the session layer a routing contribution derived from `dh1` — the output
        // the PEER already computed as its own `dh2` one leg earlier. Domain-separated so it can
        // never collide with a chain or root key, and set here rather than returned so the value
        // rides the same transactional commit as the step itself: `decrypt` stages a clone, so a
        // forged message cannot advance routing any more than it can advance the ratchet.
        self.routing_contribs.push(routing_contrib(&dh1));
        self.routing_contribs.push(routing_contrib(&dh2));
        self.dh_gen = self.dh_gen.saturating_add(1);
        self.expire_skipped();
        Ok(())
    }
}

/// Domain-separated routing contribution from ONE DH output (PRIV-2).
///
/// Separate from `kdf_rk` so routing material can never be confused with a chain or root key, and
/// so the raw DH never leaves this module.
fn routing_contrib(dh_out: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, dh_out);
    let mut out = [0u8; 32];
    hk.expand(b"karst-routing-contrib-v1", &mut out).expect("32 is a valid HKDF length");
    out
}

/// `KDF_RK`: HKDF-SHA256(salt=rk, ikm=dh) → 64 bytes → (new_rk, chain_key).
fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(rk), dh_out);
    let mut okm = [0u8; 64];
    hk.expand(b"KARST-ratchet-rk-v1", &mut okm).expect("64 within HKDF output limit");
    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    new_rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    (new_rk, ck)
}

/// `KDF_CK`: (next_chain_key, message_key) through separate HMAC constants.
/// One-way: `mk` cannot be recovered from `next_ck` (the basis of forward secrecy).
fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mk = hmac(ck, &[0x01]);
    let next_ck = hmac(ck, &[0x02]);
    (next_ck, mk)
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <SimpleHmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key len");
    m.update(data);
    let out = m.finalize().into_bytes();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

fn aad(header: &Header) -> Vec<u8> {
    let mut a = Vec::with_capacity(AAD_DOMAIN.len() + 40 + SALT_LEN);
    a.extend_from_slice(AAD_DOMAIN);
    a.extend_from_slice(&header.dh);
    a.extend_from_slice(&header.pn.to_le_bytes());
    a.extend_from_slice(&header.n.to_le_bytes());
    a.extend_from_slice(&header.salt);
    a
}

/// `(AEAD key, nonce)` for ONE message: HKDF-SHA256 over the message key, salted with the
/// header's per-message salt. Two encryptions under the same `mk` — which is exactly what a
/// state rollback produces — land on different keys, so neither the keystream nor the Poly1305
/// key is ever reused. The salt is attacker-VISIBLE (it rides in the header) but not
/// attacker-CHOSEN on our side, and it is covered by the AAD, so flipping it in transit only
/// breaks the tag.
fn message_aead(mk: &[u8; 32], salt: &[u8; SALT_LEN]) -> ([u8; 32], [u8; 12]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), mk);
    let mut okm = [0u8; 44];
    hk.expand(b"KARST-ratchet-msg-v2", &mut okm).expect("44 within HKDF output limit");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    (key, nonce)
}

fn aead_encrypt(mk: &[u8; 32], pt: &[u8], aad: &[u8], salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let (key, nonce) = message_aead(mk, salt);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: pt, aad }).expect("AEAD encryption")
}

fn aead_decrypt(
    mk: &[u8; 32],
    ct: &[u8],
    aad: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<Vec<u8>, ()> {
    let (key, nonce) = message_aead(mk, salt);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: ct, aad }).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PCS (healing), discriminating — like dh1/pq_shared: a fresh DH genuinely enters the new
    /// root_key. An adversary holding the OLD rk but not the new ephemeral (hence a different DH)
    /// cannot derive the new root_key.
    #[test]
    fn fresh_dh_is_load_bearing_in_new_root_key() {
        let rk = [5u8; 32];
        let (rk_a, _) = kdf_rk(&rk, &[1u8; 32]);
        let (rk_b, _) = kdf_rk(&rk, &[2u8; 32]);
        assert_ne!(rk_a, rk_b, "a new root_key must depend on a fresh DH (PCS)");
    }

    /// Forward secrecy as NON-RETENTION: after decrypting, the session does NOT keep the key of the
    /// consumed message. Not "the keys differ" and not "a replay fails" (that is replay
    /// protection) — precisely the absence of that key material from the state.
    #[test]
    fn message_key_not_retained_in_session_state() {
        let root = [7u8; 32];
        let bob_prekey = Identity::generate();
        let mut alice = Session::init_sender(root, bob_prekey.public.to_bytes());
        let mut bob = Session::init_receiver(root, bob_prekey);

        let m = alice.encrypt(b"hello");
        // The key Bob will decrypt this message with (from his current state after the DH step).
        // Compute it the same way decrypt would, but before it runs.
        let mut probe = bob.clone();
        let mk = probe.advance_for_decrypt(&m.header).unwrap();

        assert_eq!(bob.decrypt(&m).unwrap(), b"hello");

        // Dump ALL of Bob's session key material (including the skipped store) — the key of the
        // message received IN ORDER is not in it.
        let dump = dump_key_material(&bob);
        assert!(
            !dump.windows(32).any(|w| w == mk),
            "a consumed message key must not stay in the state (FS)"
        );
    }

    /// CRYPTO-01 residual, THE carrying test. A ratchet state that goes BACKWARDS — restored
    /// backup, cloned disk, rolled-back VM — re-derives the same message key and encrypts a
    /// different plaintext with it. Under the old scheme (key = `mk`, nonce = zero) that is a
    /// two-time pad: `ct1 XOR ct2 == pt1 XOR pt2` recovers the XOR of both plaintexts with no
    /// key at all, and the Poly1305 key is reused on top.
    ///
    /// Rollback cannot be PREVENTED locally — an attacker who can restore one file can restore
    /// them all — so it is made harmless instead: the per-message salt lands the two encryptions
    /// on different keys AND different nonces.
    ///
    /// Discriminating on purpose: it asserts the XOR relation is BROKEN, so it goes red the
    /// moment the derivation stops depending on the salt. Asserting merely `ct1 != ct2` would
    /// have passed under the old scheme too (different plaintexts → different ciphertexts).
    #[test]
    fn a_rolled_back_sending_chain_does_not_reuse_the_keystream() {
        let (alice, _bob) = pair();

        // The SAME pre-send state used twice = exactly what restoring a backup does.
        let mut original = alice.clone();
        let mut rolled_back = alice;

        let pt1 = b"transfer 10 to alice............";
        let pt2 = b"transfer 99 to mallory..........";
        let m1 = original.encrypt(pt1);
        let m2 = rolled_back.encrypt(pt2);

        assert_eq!(m1.header.n, m2.header.n, "the rollback must really replay the same message number");
        assert_ne!(m1.header.salt, m2.header.salt, "each message must carry a FRESH salt");

        let xor_ct: Vec<u8> =
            m1.ciphertext.iter().zip(&m2.ciphertext).map(|(a, b)| a ^ b).collect();
        let xor_pt: Vec<u8> = pt1.iter().zip(pt2.iter()).map(|(a, b)| a ^ b).collect();
        assert_ne!(
            &xor_ct[..xor_pt.len()],
            &xor_pt[..],
            "keystream reuse: XOR of the two ciphertexts leaked the XOR of the two plaintexts — \
             the AEAD key/nonce must depend on the per-message salt, not on the message key alone"
        );
    }

    /// The salt is authenticated, not just carried: flipping it in transit must fail the tag
    /// rather than silently decrypting under a different key. Guards against someone deriving
    /// the key from the salt but forgetting to bind the salt into the AAD.
    #[test]
    fn a_tampered_salt_fails_the_tag() {
        let (mut alice, mut bob) = pair();
        let mut msg = alice.encrypt(b"hello");
        msg.header.salt[0] ^= 1;
        assert_eq!(bob.decrypt(&msg), Err(RatchetError::Decrypt));
    }

    /// The 16-byte salt must not push a full-size message into a bigger padding bucket: the
    /// on-wire SIZE CLASS is the observable, and a changed size class is itself a tell. Pins
    /// that a maximum inline chunk (1024 B payload + framing + AEAD tag) still lands in the
    /// same bucket it did before the salt existed.
    #[test]
    fn a_full_size_chunk_still_fits_its_padding_bucket() {
        let (mut alice, _bob) = pair();
        // 1024 = client::content::MAX_CHUNK_PAYLOAD (that crate depends on this one, not the
        // other way round), plus generous room for the Content framing around the chunk.
        let msg = alice.encrypt(&vec![0u8; 1024 + 64]);
        let on_wire = postcard::to_stdvec(&msg).expect("serialize");

        let with_salt = crate::session::bucket_for(4 + on_wire.len());
        let without_salt = crate::session::bucket_for(4 + on_wire.len() - SALT_LEN);
        assert_eq!(
            with_salt, without_salt,
            "the per-message salt moved a full-size message into a different padding bucket \
             ({without_salt} -> {with_salt}): the change became visible on the wire"
        );
    }

    /// A fresh session pair on a shared root (Alice sends, Bob receives).
    fn pair() -> (Session, Session) {
        let root = [7u8; 32];
        let bob_prekey = Identity::generate();
        let alice = Session::init_sender(root, bob_prekey.public.to_bytes());
        let bob = Session::init_receiver(root, bob_prekey);
        (alice, bob)
    }

    /// All session key material, including the skipped mks.
    fn dump_key_material(s: &Session) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&s.rk);
        if let Some(c) = s.cks {
            d.extend_from_slice(&c);
        }
        if let Some(c) = s.ckr {
            d.extend_from_slice(&c);
        }
        for sk in &s.skipped {
            d.extend_from_slice(&sk.mk);
        }
        d
    }

    /// Out of order WITHIN one chain: m0 arrives, then m2 (m1 is stored), then m1 catches up — all
    /// three decrypt. Previously m2 after m0 gave OutOfOrder.
    #[test]
    fn out_of_order_within_chain_decrypts_via_skipped() {
        let (mut alice, mut bob) = pair();
        let m0 = alice.encrypt(b"zero");
        let m1 = alice.encrypt(b"one");
        let m2 = alice.encrypt(b"two");

        assert_eq!(bob.decrypt(&m0).unwrap(), b"zero");
        assert_eq!(bob.decrypt(&m2).unwrap(), b"two", "skipping m1 stores the m1 key");
        assert_eq!(bob.skipped.len(), 1, "exactly one skipped key (m1)");
        assert_eq!(bob.decrypt(&m1).unwrap(), b"one", "the late m1 is opened from the store");
        assert!(bob.skipped.is_empty(), "a consumed skipped key is deleted (FS)");
    }

    /// Out of order ACROSS a chain boundary: the tail of the old chain (m1) is stored during the DH
    /// step and decrypts after a message from the new chain.
    #[test]
    fn out_of_order_across_ratchet_boundary() {
        let (mut alice, mut bob) = pair();
        let a0 = alice.encrypt(b"a0"); // chain A, n0
        let a1 = alice.encrypt(b"a1"); // chain A, n1 (will be delayed)
        assert_eq!(bob.decrypt(&a0).unwrap(), b"a0");

        // Bob replies → Alice takes a DH step → a new chain from Alice.
        let r0 = bob.encrypt(b"r0");
        assert_eq!(alice.decrypt(&r0).unwrap(), b"r0");
        let b0 = alice.encrypt(b"b0"); // a NEW chain from Alice, pn=2

        // Bob receives b0 (the new chain): the tail of the old one (a1) is stored, DH step taken.
        assert_eq!(bob.decrypt(&b0).unwrap(), b"b0");
        assert_eq!(bob.skipped.len(), 1, "the tail of the old chain (a1) is stored");
        // The late a1 from the OLD chain — served from the store.
        assert_eq!(bob.decrypt(&a1).unwrap(), b"a1");
        assert!(bob.skipped.is_empty());
    }

    /// Load-bearing (the reason for the fix): a skipped key survives snapshot→restore (mirroring
    /// the client's `load→process→save`), and the late gap filler then decrypts from the RESTORED
    /// store.
    #[test]
    fn skipped_key_survives_snapshot_restore() {
        let (mut alice, mut bob) = pair();
        let m0 = alice.encrypt(b"zero");
        let m1 = alice.encrypt(b"one");
        let m2 = alice.encrypt(b"two");
        assert_eq!(bob.decrypt(&m0).unwrap(), b"zero");
        assert_eq!(bob.decrypt(&m2).unwrap(), b"two"); // m1 is stored

        // A round trip through the persistent form.
        let mut bob2 = Session::restore(bob.snapshot());
        assert_eq!(bob2.decrypt(&m1).unwrap(), b"one", "the gap filler comes from the RESTORED store");
    }

    /// Anti-DoS BEYOND the spec: a forged message with a large `n` (valid header, broken AEAD) does
    /// NOT fill the skipped store and does NOT advance `nr` — the staged copy is discarded.
    /// Discriminating: committing before the AEAD would grow the store and jump nr.
    #[test]
    fn forged_high_n_does_not_populate_skipped_store() {
        let (mut alice, mut bob) = pair();
        let m0 = alice.encrypt(b"zero");
        assert_eq!(bob.decrypt(&m0).unwrap(), b"zero");
        let dhr = bob.dhr.unwrap();

        // A valid header (the same chain), n=50, but garbage ciphertext.
        let forged = RatchetMessage {
            header: Header { dh: dhr, pn: 0, n: 50, salt: [7u8; 16] },
            ciphertext: vec![0u8; 48],
        };
        assert_eq!(bob.decrypt(&forged), Err(RatchetError::Decrypt));
        assert!(bob.skipped.is_empty(), "a forged message did not fill the store (staged changes rolled back)");
        assert_eq!(bob.nr, 1, "a forged message did not advance nr");

        // The session is intact: the next legitimate in-order message goes through.
        let m1 = alice.encrypt(b"one");
        assert_eq!(bob.decrypt(&m1).unwrap(), b"one");
    }

    /// `MAX_SKIP`: a jump beyond the limit in one step is refused and the session is NOT touched
    /// (the staged copy is dropped). This is the anti-unbounded-KDF bound.
    #[test]
    fn gap_larger_than_max_skip_is_rejected_session_intact() {
        let (mut alice, mut bob) = pair();
        let m0 = alice.encrypt(b"zero");
        assert_eq!(bob.decrypt(&m0).unwrap(), b"zero");
        let dhr = bob.dhr.unwrap();

        let too_far = RatchetMessage {
            header: Header { dh: dhr, pn: 0, n: MAX_SKIP + 5, salt: [7u8; 16] },
            ciphertext: vec![0u8; 48],
        };
        assert_eq!(bob.decrypt(&too_far), Err(RatchetError::OutOfOrder));
        assert!(bob.skipped.is_empty(), "no keys were derived");
        assert_eq!(bob.nr, 1, "nr untouched");
        // And the session keeps working within the allowed range.
        let m1 = alice.encrypt(b"one");
        assert_eq!(bob.decrypt(&m1).unwrap(), b"one");
    }

    /// CRYPTO-09 (#157): the session's key material is scrubbed when the value is dropped.
    ///
    /// Discriminating on the BYTES, not on the trait: `zeroize()` is called on a session whose
    /// keys are known, and the root key, both chain keys and every stored skipped key must come
    /// back all-zero. Removing `ZeroizeOnDrop` (or a `#[zeroize(skip)]` slapped on `rk` to quiet
    /// a compiler complaint) fails this — an "assert the type implements the trait" test would
    /// not, because the derive can be present and still skip the field that matters.
    ///
    /// What this does NOT prove, stated so nobody reads more into it: that no COPY survives
    /// elsewhere. A move is a memcpy and leaves the source untouched, and reading freed memory to
    /// check would be undefined behaviour. This pins the one thing that is actually checkable —
    /// the owned bytes are cleared — and the type doc carries the rest of the limit.
    #[test]
    fn dropping_a_session_scrubs_its_key_material() {
        use zeroize::Zeroize;
        let (mut alice, mut bob) = pair();
        let m0 = alice.encrypt(b"zero");
        assert_eq!(bob.decrypt(&m0).unwrap(), b"zero");
        // Leave a skipped key behind too, so the vector is not empty when we scrub.
        let _m1 = alice.encrypt(b"one");
        let m2 = alice.encrypt(b"two");
        assert_eq!(bob.decrypt(&m2).unwrap(), b"two");
        assert!(!bob.skipped.is_empty(), "precondition: a skipped key is stored");
        assert_ne!(bob.rk, [0u8; 32], "precondition: the root key is real");
        assert!(bob.ckr.is_some_and(|c| c != [0u8; 32]), "precondition: a receiving chain exists");

        bob.zeroize();

        assert_eq!(bob.rk, [0u8; 32], "the root key must be scrubbed");
        assert_eq!(bob.cks, None, "the sending chain key is gone, not merely blanked");
        assert_eq!(bob.ckr, None, "the receiving chain key is gone, not merely blanked");
        assert!(bob.skipped.is_empty(), "stored skipped message keys must not survive");
    }
}

/// **The claim PRIV-2's whole design rests on**, checked rather than argued.
///
/// The routing chain can only heal if the recipient can derive the next generation BEFORE receiving
/// anything in it. That is possible for exactly one reason: a step's FIRST DH output is numerically
/// the same value the peer computed as its own SECOND output one leg earlier. If that ever stops
/// being true — someone reorders the two `kdf_rk` calls, or takes the contribution from `dh2` —
/// the recipient starts polling an address it cannot compute yet, mail stops arriving, and nothing
/// in the code says why. So it is pinned here, next to the arithmetic that makes it true.
#[cfg(test)]
mod routing_contribution_is_derivable_by_both_sides {
    use super::*;

    /// Both sides produce the SAME contribution sequence, and the recipient produces each element
    /// no later than the sender needs it.
    #[test]
    fn each_step_yields_the_contribution_the_peer_already_produced_one_leg_earlier() {
        // A real two-sided conversation: only `decrypt` advances a DH step, so the legs alternate.
        let root = [5u8; 32];
        let bob_dh = Identity::generate();
        let mut alice = Session::init_sender(root, bob_dh.public.to_bytes());
        let mut bob = Session::init_receiver(root, bob_dh);

        let mut alice_contribs = Vec::new();
        let mut bob_contribs = Vec::new();

        // Six legs, alternating. Each side folds whatever its own step produced.
        for leg in 0..6 {
            if leg % 2 == 0 {
                let m = alice.encrypt(b"from alice");
                bob.decrypt(&m).expect("delivers");
                bob_contribs.extend(bob.take_routing_contributions());
            } else {
                let m = bob.encrypt(b"from bob");
                alice.decrypt(&m).expect("delivers");
                alice_contribs.extend(alice.take_routing_contributions());
            }
        }

        assert!(
            !alice_contribs.is_empty() && !bob_contribs.is_empty(),
            "no contributions were produced at all — the hook is not firing, so the routing chain \
             would silently never advance"
        );

        // THE property, in two halves.
        //
        // (1) SAME SEQUENCE, SAME ORDER. The DH outputs form one sequence both sides walk; each
        //     computes two per step with a one-element overlap, and the sender's init supplies the
        //     first. Compared as PREFIXES, not with an offset: an offset was the first guess and it
        //     was wrong — folding one output per step gives each side only the even or only the odd
        //     elements, so the sequences are disjoint and the recipient can never derive the
        //     sender's address. That mistake reads as correct on paper, which is why this is a test.
        let shared = alice_contribs.len().min(bob_contribs.len());
        assert!(shared >= 4, "not enough legs to compare sequences: {shared}");
        assert_eq!(
            alice_contribs[..shared],
            bob_contribs[..shared],
            "the two sides are walking DIFFERENT contribution sequences. If they do not agree \
             element for element, the recipient cannot derive the box the sender writes to and \
             delivery stops with no error anywhere."
        );

        // (2) DIVERGENCE OF AT MOST ONE. This is what makes a two-wide polling window a BOUND
        //     rather than a guess: a DH step happens only inside `advance_for_decrypt`, so neither
        //     side advances without a successful delivery from the other. If this ever exceeds one,
        //     `drop::ROUTING_WINDOW` is too narrow and mail goes missing intermittently — the
        //     worst possible way for this to break.
        let gap = alice_contribs.len().abs_diff(bob_contribs.len());
        assert!(
            gap <= 1,
            "the two sides drifted {gap} generations apart, not the one leg the design bounds. \
             drop::ROUTING_WINDOW is sized from this bound."
        );
    }

    /// A contribution can be folded once and only once.
    #[test]
    fn a_contribution_is_consumed_not_merely_read() {
        let root = [6u8; 32];
        let bob_dh = Identity::generate();
        let mut alice = Session::init_sender(root, bob_dh.public.to_bytes());
        let mut bob = Session::init_receiver(root, bob_dh);
        let m = alice.encrypt(b"one");
        bob.decrypt(&m).expect("delivers");
        // The first step of a receiver session may or may not ratchet; take twice either way and
        // require the second take to be empty, because a double fold desynchronises the sides.
        let first = bob.take_routing_contributions();
        assert!(
            bob.take_routing_contributions().is_empty(),
            "taking twice returned values twice ({} then more) — folding one step's contributions \
             into two generations puts this side permanently ahead of its peer",
            first.len()
        );
    }

    /// A forged message must not advance routing, for the same reason it must not advance the
    /// ratchet: `decrypt` stages a clone and commits only on a verified AEAD.
    #[test]
    fn a_message_that_fails_to_decrypt_produces_no_contribution() {
        let root = [7u8; 32];
        let bob_dh = Identity::generate();
        let mut alice = Session::init_sender(root, bob_dh.public.to_bytes());
        let mut bob = Session::init_receiver(root, bob_dh);
        let mut m = alice.encrypt(b"one");
        *m.ciphertext.last_mut().expect("non-empty") ^= 0xFF;
        assert!(bob.decrypt(&m).is_err(), "a tampered message must not decrypt");
        assert!(
            bob.take_routing_contributions().is_empty(),
            "a forged message advanced the routing chain — an attacker could push a recipient's \
             routing generation past its peer's and cut delivery without holding any key"
        );
    }
}

/// **Public protocol vectors, and a SECOND implementation that must agree with them** (QA-4).
///
/// Our own tests are written by whoever wrote the code and inherit its misunderstandings. A test
/// that says "`kdf_rk` returns what `kdf_rk` returned last time" catches a typo and nothing else;
/// it cannot catch a misread specification, because both sides of the comparison come from the
/// same reading. So the vectors below are checked twice: once here against the live code, and once
/// by `scripts/verify_vectors.py`, which reimplements the key schedule from the written rules
/// using only Python's standard library — no shared code, no shared crate, no shared reading.
///
/// **Why the key schedule and not the ciphertext.** ChaCha20-Poly1305 is not in Python's standard
/// library, and pulling in a dependency would put a third party's reading of RFC 8439 in the place
/// where an INDEPENDENT reading is supposed to be. HKDF-SHA256 and HMAC-SHA256 are stdlib, so the
/// derivation chain — where a misread spec actually bites, and where a mistake silently produces
/// keys that agree with themselves forever — is fully covered without importing anyone's opinion.
///
/// Pre-alpha means these may be regenerated deliberately (`KARST_REGEN_VECTORS=1`), but BOTH
/// implementations must then be updated and agree again, or the exercise is theatre.
#[cfg(test)]
mod protocol_vectors {
    use super::*;

    const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/ratchet_kdf.json");

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Deterministic inputs, chosen to be obviously arbitrary rather than accidentally special:
    /// no all-zero keys (which hide a missing salt), no equal inputs (which hide a swapped
    /// argument).
    fn cases() -> Vec<(String, String)> {
        let mut out = Vec::new();
        let rk = [0x11u8; 32];
        let dh = [0x22u8; 32];
        let ck = [0x33u8; 32];
        let mk = [0x44u8; 32];
        let salt = [0x55u8; SALT_LEN];

        out.push(("routing_contrib".into(), hex(&routing_contrib(&dh))));
        let (new_rk, chain) = kdf_rk(&rk, &dh);
        out.push(("kdf_rk.new_rk".into(), hex(&new_rk)));
        out.push(("kdf_rk.ck".into(), hex(&chain)));
        let (next_ck, msg_key) = kdf_ck(&ck);
        out.push(("kdf_ck.next_ck".into(), hex(&next_ck)));
        out.push(("kdf_ck.mk".into(), hex(&msg_key)));
        let (key, nonce) = message_aead(&mk, &salt);
        out.push(("message_aead.key".into(), hex(&key)));
        out.push(("message_aead.nonce".into(), hex(&nonce)));

        // The AAD byte layout is part of the wire contract: a reordering here breaks every peer
        // while every local test still passes, because both sides would reorder together.
        let header = Header { dh: [0x66u8; 32], pn: 0x0102_0304, n: 0x0506_0708, salt };
        out.push(("aad".into(), hex(&aad(&header))));
        out
    }

    fn render(cases: &[(String, String)]) -> String {
        let body: Vec<String> =
            cases.iter().map(|(k, v)| format!("  \"{k}\": \"{v}\"")).collect();
        format!("{{\n{}\n}}\n", body.join(",\n"))
    }

    /// The checked-in vectors are what this build produces.
    ///
    /// DISCRIMINATING by construction: change any constant in the key schedule — an info string, a
    /// salt argument, the 0x01/0x02 HMAC tags, the AAD field order — and this reds with the two
    /// values side by side.
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
            "the key schedule changed. If that was deliberate: regenerate with \
             KARST_REGEN_VECTORS=1 AND update scripts/verify_vectors.py, which must reach the \
             same numbers from the written rules alone. Updating only one of the two turns this \
             into a test of nothing."
        );
    }

    /// The INDEPENDENT implementation agrees.
    ///
    /// Fails rather than skips when `python3` is missing. A vector check that quietly skips is the
    /// exact failure this file exists to prevent: green, and verifying nothing.
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
