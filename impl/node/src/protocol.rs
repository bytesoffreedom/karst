//! The shared PROTOCOL VOCABULARY: the request/response types, the envelopes, the descriptors
//! and the small proof helpers that BOTH sides of the wire have to agree on.
//!
//! Split out of `node` because that module was two things at once — the relay implementation and
//! the words the relay and the client use to talk to each other. Everything else in this crate
//! pointed at `node` for the second reason while `node` pointed back for the first, which is a
//! cycle: legal inside one crate, a hard error the moment these become separate crates on either
//! side of the trust boundary (#143). Nothing here knows what a `RelayNode` is.
//!
//! What does NOT belong here: relay state (mailboxes, bundle slots, quota trackers), relay
//! policy ENFORCEMENT, and the in-memory test transport that wraps a live relay. Those are the
//! relay's business, and a client has no reason to be able to name them.

use admission::capability::{CapabilityProof, Quota};
use admission::cookie::Cookie;
use hkdf::Hkdf;
use hmac::{Mac, SimpleHmac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::PublicKey;

use crate::pqxdh::PreKeyBundle;
use crate::ratchet::RatchetMessage;
use crate::seal::{Identity, SkeletonSeal};

/// Node-list (discovery plane) bounds. `known_relays` holds SIGNED descriptors — a bounded set
/// keeps memory capped and lets the served page stay inside one response frame. Entries only ever
/// arrive verified (signature, window, and these bounds), so "bounded" is enforced by refusing an
/// oversized descriptor, never by trimming one: see `descriptor_within_bounds`.
pub const MAX_KNOWN_RELAYS: usize = 128;
/// Cap on dial hints per relay descriptor (avoid a junk descriptor bloating the list).
pub const MAX_ADDRS_PER_RELAY: usize = 4;
/// Cap on a single dial-hint string (a real host:port / .onion / .b32.i2p is well under this).
/// `addrs` is attacker-controlled, unsigned free-form (excluded from the binding signature),
/// so it must be bounded in BOTH length and count before it is stored, or 4 hints × ~16 KB
/// across the discovery map (~100 000 slots) is a multi-GB memory-growth DoS.
pub const MAX_ADDR_LEN: usize = 256;
/// Cap on ids in ONE `AckRequest`. A recipient cannot have received more than a mailbox holds, so
/// a larger list is not a legitimate ack — it is work being bought cheaply (SEC-28).
/// Mailbox STORAGE ceiling (backpressure at insert, `MailboxFull`). Independent of
/// how many seals leave per fetch — a full mailbox now drains `FETCH_CAP` at a time
/// over several polls.
pub const MAX_FETCH_SEALS: usize = 256;

pub const MAX_ACK_IDS: usize = MAX_FETCH_SEALS;
/// Cap on stored one-time prekeys per IK (bounded relay state; see `PublishRequest::opks`).
///
/// Was 256, when a one-time prekey was 32 bytes of X25519 plus a signature. A unit now carries its
/// own ML-KEM-768 encapsulation key (~1184 B) so the post-quantum leg of a first contact is
/// forward-secret too (CRYPTO-33), which makes the unit ~12× larger and `MAX_OPKS_PER_IK * unit`
/// the thing that sets `wire::MAX_PUBLISH_FRAME`. That frame must stay under `MAX_BLOB_FRAME` —
/// a compile-time assert in `wire.rs` enforces it — so this is a batch that fits one publish with
/// headroom (the ceiling admits ~47). Raising it far is not a matter of taste: it fails the build.
///
/// **What the smaller batch costs, plainly:** a batch serves that many FIRST CONTACTS before it
/// runs out, and a sender who arrives after it does gets a bundle with no one-time unit — 3-DH
/// instead of 4-DH, and the static last-resort KEM key instead of a one-time one. That is
/// reported, not silent (`ForwardSecrecy::NoOneTimePrekey`). The mitigation is republishing more
/// often rather than a deeper batch, which the client already does on every unlock and poll.
pub const MAX_OPKS_PER_IK: usize = 40;
/// How long an undelivered sealed message lives in a mailbox before the TTL sweep
/// drops it (7 days). A recipient who never comes back otherwise pins memory
/// forever. Generous enough for ordinary offline delivery; swept lazily when the
/// epoch advances (`advance_epoch` → `sweep_mailboxes`), never on a background thread.
pub const MAILBOX_TTL_SECS: u64 = 7 * 24 * 3600;
/// Stable per-message id for lease/ACK: a domain-separated hash of the sealed payload.
/// Every sealed payload carries a fresh ephemeral key + nonce (ratchet message key or
/// skeleton ephemeral), so distinct deposits never collide; the recipient recomputes
/// the same id from the bytes it fetched, so an ACK names exactly the messages it holds
/// without the relay having to assign and ship ids inside the fixed-size fetch page.
pub fn payload_id(payload: &Payload) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(b"KARST-mailbox-msgid-v1");
    h.update(postcard::to_stdvec(payload).expect("Payload serializes"));
    h.finalize().into()
}
/// Proof of mailbox ownership for a fetch (§7): bound to the sender-recipient static-static DH
/// with the relay AND to `cookie.mac` (30-second freshness). The KDF domain `KARST-fetch-auth-v1`
/// is separated from seal — the same domain-separation principle as `KARST-skeleton-seal-v1`. Only
/// the holder of the `mailbox` private key can compute the DH, hence the proof.
pub fn fetch_proof(shared_dh: &[u8; 32], cookie_mac: &[u8; 16], mailbox: &[u8; 32]) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::new(None, shared_dh);
    let mut key = [0u8; 32];
    hk.expand(b"KARST-fetch-auth-v1", &mut key).expect("32 within HKDF output limit");
    let mut mac = <SimpleHmac<Sha256> as Mac>::new_from_slice(&key).expect("HMAC accepts any key len");
    mac.update(cookie_mac);
    mac.update(mailbox);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}
/// Verify a mailbox ownership proof, shared by `handle_fetch` and `handle_ack`. A BLINDED drop-box
/// (`own_proof` non-empty) proves knowledge of its fetch secret via a Schnorr proof bound to the
/// cookie MAC; the IDENTITY mailbox (an X25519 key) proves via the DH `dh_proof`. `false` on any
/// malformed input or a failed check.
pub fn mailbox_owner_ok(
    relay_identity: &Identity,
    mailbox: [u8; 32],
    cookie_mac: &[u8; 16],
    dh_proof: [u8; 16],
    own_proof: &[u8],
) -> bool {
    if !own_proof.is_empty() {
        // Blinded drop-box: an in-group Schnorr proof against the address + the cookie MAC.
        return <[u8; 64]>::try_from(own_proof)
            .ok()
            .map(|b| crate::blind::FetchOwnershipProof::from_bytes(&b).verify(&mailbox, cookie_mac))
            .unwrap_or(false);
    }
    // Identity mailbox: DH ownership. Reject a low-order/non-contributory point (zero shared),
    // whose known shared would let an attacker forge the proof.
    let shared = relay_identity.dh(&PublicKey::from(mailbox));
    if shared.ct_eq(&[0u8; 32]).unwrap_u8() == 1 {
        return false;
    }
    fetch_proof(&shared, cookie_mac, &mailbox).ct_eq(&dh_proof).unwrap_u8() == 1
}
/// The session §2.1 envelope (PQXDH + Double Ratchet). The first message carries the key agreement
/// (`Initial`); later ones carry only ratchet payload (`Ratchet`). The relay stores it opaquely —
/// it holds no key and cannot tell the contents apart.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum SessionEnvelope {
    /// The continuation of an established session.
    ///
    /// The unsealed `Initial` opener that used to sit here is GONE (#232/A3-14). It carried
    /// `KeyAgreement.ik_a_pub` — the sender's long-term identity — in the clear, so any relay
    /// that wanted the social graph could read every edge straight off the openers.
    /// `InitialSealed` replaced it, and `Peer::process` already refused the legacy form; keeping
    /// the variant meant the shape stayed EXPRESSIBLE, and a runtime refusal is a weaker thing
    /// than a form that cannot be constructed. Removing it renumbers the postcard variants,
    /// which is a wire break — free at zero users, and taken deliberately.
    Ratchet(RatchetMessage),
    /// **Sealed opener**: the same PQXDH `KeyAgreement`, wrapped in a sealed box
    /// addressed to the RECIPIENT's identity key (ephemeral X25519 → their `ik_pub`,
    /// HKDF → ChaCha20-Poly1305 — `seal::SkeletonSeal`).
    ///
    /// The relay sees a fresh ephemeral public key and ciphertext: no sender identity.
    /// The recipient opens it with their own IK — which they can do without knowing who
    /// sent it — and then runs PQXDH exactly as before, so sender AUTHENTICATION is
    /// unchanged (it was never the relay's business, and it still comes from the inner
    /// key agreement).
    ///
    /// The outer box deliberately has **no sender authentication** — that is what makes
    /// it anonymous to the relay. Anyone can seal to you; only the inner PQXDH says who
    /// it really was. That is the same property that made `SkeletonSeal` unfit as an E2E
    /// layer, used here for exactly what it is good for.
    ///
    /// APPENDED LAST: postcard numbers variants positionally.
    InitialSealed { sealed_ka: crate::seal::SkeletonSeal, msg: RatchetMessage },
    /// **A `Ratchet` envelope re-randomised for ONE relay** (PRIV-4, `crate::veil`).
    ///
    /// Adds no security: the bytes inside are already a ratchet ciphertext. It exists so that the
    /// same queued message, when multi-homing retransmits it to a second relay, does not arrive
    /// there BYTE-IDENTICAL — two operators comparing logs would otherwise match on equality and
    /// learn it is one message, with no analysis at all. PRIV-12 removed that join on the box
    /// address; this removes it on the payload.
    ///
    /// `nonce` is DERIVED from `(relay, inner)` rather than random, so a retransmit to the SAME
    /// relay reproduces the same bytes and this relay's own `payload_id` deduplication keeps
    /// working. See `crate::veil` for why that is correct here and would not be in an AEAD.
    ///
    /// APPENDED LAST: postcard numbers variants positionally.
    Veiled { nonce: [u8; crate::veil::NONCE_LEN], inner: Vec<u8> },
}
/// The payload in a mailbox. **A staged migration** (not dead code): the session §2.1 path
/// (`Session`) is the new in-process E2E; the skeleton (`Skeleton`) still carries the socket and
/// CLI path until session persistence is added there. The relay stores either variant opaquely.

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum Payload {
    Skeleton(SkeletonSeal),
    Session(SessionEnvelope),
}
impl Payload {
    /// The approximate payload size, for the pipeline's stage-0 size gate.
    pub fn approx_len(&self) -> usize {
        match self {
            Payload::Skeleton(s) => s.ciphertext.len(),
            Payload::Session(SessionEnvelope::InitialSealed { sealed_ka, msg }) => {
                // `kem_ct` counts (PRIV-3). It is ~1088 bytes — by far the largest single field in
                // the envelope — so omitting it would make the stage-0 size gate under-count by
                // more than a third of the packet: an oversize opener would pass the gate that
                // exists to reject it, and the ceiling in `admission::params` would be enforcing a
                // number that has nothing to do with what is on the wire.
                sealed_ka.ciphertext.len() + sealed_ka.kem_ct.len() + msg.ciphertext.len() + 64
            }
            // The veil is a byte-for-byte re-encoding of a `Ratchet` envelope plus a nonce, so its
            // size gate cost is the veiled length itself.
            Payload::Session(SessionEnvelope::Veiled { nonce, inner }) => nonce.len() + inner.len(),
            Payload::Session(SessionEnvelope::Ratchet(msg)) => msg.ciphertext.len(),
        }
    }
}
/// Proof of IK OWNERSHIP for a §12 bundle publication (the write-side mirror of `fetch_proof`):
/// only the holder of the private IK can compute `DH(IK, relay)`. It binds cookie.mac (freshness)
/// AND the bundle CONTENTS (ik‖prekey‖kem_ek) — otherwise an intercepted proof could be reused to
/// substitute a bundle with different contents. It stops OTHER clients from overwriting someone's
/// bundle; against a MALICIOUS RELAY it does not help (that one substitutes the IK — the external
/// wall, an out-of-band IK check).
pub fn publish_proof(
    shared_dh: &[u8; 32],
    cookie_mac: &[u8; 16],
    bundle: &PreKeyBundle,
) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::new(None, shared_dh);
    let mut key = [0u8; 32];
    hk.expand(b"KARST-publish-auth-v1", &mut key).expect("32 within HKDF output limit");
    let mut mac = <SimpleHmac<Sha256> as Mac>::new_from_slice(&key).expect("HMAC accepts any key len");
    mac.update(cookie_mac);
    mac.update(&bundle.ik_pub);
    mac.update(&bundle.prekey_pub);
    mac.update(&bundle.kem_ek);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}
/// A message on the wire: the admission part (§7), the route, and the sealed payload. An owning
/// type — the transport passes it whole.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct WireMessage {
    pub client_addr: Vec<u8>,
    pub carrier_id: Vec<u8>,
    pub cookie: Option<Cookie>,
    pub request_nonce: Vec<u8>,
    pub capability_proof: CapabilityProof,
    /// The recipient's public key = their mailbox address (skeleton: a static X25519 key;
    /// session: the recipient's long-term IK).
    pub recipient: [u8; 32],
    pub payload: Payload,
}
/// The relay's reply to a client.
#[derive(Debug)]
pub enum Response {
    /// First contact: the relay issued a cookie, and the client retries with it.
    NeedCookie(Cookie),
    /// Admitted, and the sealed payload is sitting in the recipient's mailbox. **How much that
    /// is worth depends on the relay** (R2-5, #161): on a `Volatile` relay the message lives only
    /// in this process's memory, so a crash or restart before the recipient's fetch loses it with
    /// NO resend signal to the sender; on a `Durable` one (`enable_durable_mail`) the deposit was
    /// fsynced to the mail log BEFORE this reply, so a restart redelivers it. `Accepted` itself
    /// deliberately does not carry which — a per-message flag would invite a sender to decide
    /// retention message-by-message on a value the relay can simply lie about. The posture is a
    /// property of the RELAY, fetched once via `GetPolicy`
    /// (`RelayPolicy::mailbox_durability`) and used to CHOOSE the relay, which is where the
    /// decision actually belongs.
    Accepted,
    /// Rejected by the admission pipeline (the outcome text).
    Rejected(String),
}
/// Operator's choice for the §15 blob store's restart behaviour. `Durable` keeps parked blobs
/// across a restart (reliability for large transfers); `Ephemeral` wipes them on start (the
/// lower-residue posture). Blobs are E2E ciphertext + capped + TTL-swept in EITHER mode, so this
/// changes only how long opaque ciphertext lingers, not what the relay can read (nothing).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlobPersistence {
    Durable,
    Ephemeral,
}
/// Whether a message sitting in a mailbox survives this relay restarting (R2-5, #161).
///
/// An operator CHOICE, like `BlobPersistence`: `Volatile` remains the default (nothing is written
/// to disk), `Durable` is enabled with `RelayNode::enable_durable_mail`. `bundles`/`opk_batches`
/// stay in RAM in both modes on purpose — a live client republishes its bundle on every launch,
/// so those self-heal, while a queued message has no such second source.
///
/// **What `Durable` is worth, exactly.** It turns "guaranteed loss on an ordinary restart" into
/// "loss if that relay's disk or the relay itself goes away". It is NOT delivery reliability:
/// that needs replication across relays (#149) or an end-to-end receipt from the recipient,
/// neither of which exists. The mode is *provable* by a client (send to yourself, restart is the
/// operator's business — but a fetched message coming back after downtime self-verifies), while
/// `Volatile` is, like `BlobPersistence::Ephemeral`, an unverifiable claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MailboxDurability {
    /// In-memory only. A crash or restart between `Accepted` and the recipient's fetch loses the
    /// message, and the sender is never told — its outbox already retired the entry on
    /// `Accepted` (see that variant's doc comment). Advertised so a client can, at minimum, know
    /// not to trust the guarantee `Accepted` does not make.
    Volatile,
    /// Deposits are fsynced to a mail log before `Accepted` is answered, and replayed on start.
    /// At-least-once: deletions are not fsynced, so a crash can redeliver an already-delivered
    /// message (the client dedups by `payload_id`) — see `crate::mailstore` for why that side of
    /// the trade is deliberate. The relay holds only E2E ciphertext in either mode; what changes
    /// is how long opaque bytes linger on the operator's disk.
    Durable,
}
/// A relay's advertised policy — the operator-configured knobs a client can inspect (`GetPolicy`)
/// to understand what it's connecting to and to prefer relays matching its preferences. Every
/// field is **operator-declared**; they differ in how far a client can check them:
///   * `pow_bits` — VERIFIABLE (the client solves the PoW to join).
///   * `max_blob_size` — VERIFIABLE (an over-cap upload is rejected).
///   * `blob_persistence` — `Durable` is PROVABLE (fetch a parked chunk back — it self-verifies),
///     but `Ephemeral` is a CLAIM no one can check remotely (you cannot prove a server deleted /
///     did not copy data). Trust ephemeral only as far as the operator; accountability for the
///     unverifiable claims will come from the future reputation layer, not from crypto.
///   * `mailbox_durability` — not operator-configurable at all yet (see `MailboxDurability`); this
///     relay always reports `Volatile` because that is the only thing it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RelayPolicy {
    /// Blob-store restart posture (`None` = large-file blobs disabled on this relay).
    pub blob_persistence: Option<BlobPersistence>,
    /// How long a parked blob lives before the TTL sweep (0 when blobs are disabled).
    pub blob_ttl_secs: u64,
    /// Per-blob size ceiling in bytes (0 when blobs are disabled).
    pub max_blob_size: u64,
    /// Door policy: `None` = not issuing (Private/Dev), `Some(0)` = open (no PoW),
    /// `Some(n)` = n-bit PoW required to earn a capability.
    pub pow_bits: Option<u32>,
    /// Whether an `Accepted` message survives this relay restarting (R2-5, #161). Always
    /// `Volatile` today — see `MailboxDurability`.
    pub mailbox_durability: MailboxDurability,
}
/// Required shape of `BlobPutRequest::request_nonce` — NOT freeform client-chosen bytes, unlike
/// the live-message path's `request_nonce`. Two problems this closes at once (CRYPTO-15/#169):
///
/// 1. **Cross-class replay.** `Capability::prove`'s MAC is `HMAC(secret, request_nonce ||
///    epoch_id)` — the capability's `scope` is checked separately (equality against
///    `requested_scope`) but is NOT folded into the MAC for a stored/dev capability, so a proof
///    minted for an ordinary message send (`Scope::MessageDelivery`, some arbitrary `"req-N"`
///    nonce) verifies just as well if replayed onto the blob path with the SAME nonce and the
///    same requested scope. Deriving the nonce from `(blob_id, index)` means a message-path
///    proof's nonce essentially never has this shape, so it is rejected before the capability
///    HMAC even runs — presenting a capability for blob storage requires a proof MINTED for
///    that specific chunk, not a sniffed/reused one from elsewhere.
/// 2. **Retry = same charge.** A genuine resend of the same chunk (session died mid-upload,
///    §15) recomputes the SAME nonce and therefore the same proof, rather than minting a fresh
///    one — so it lands as the identical (harmless, blobstore-deduped) request rather than a new
///    quota charge with a random nonce every attempt.
///
/// Public and deterministic, not secret: the client must be ABLE to compute it, the relay only
/// needs to REJECT a mismatch.
pub fn blob_put_nonce(blob_id: &[u8; 32], index: u32) -> Vec<u8> {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(b"KARST-blob-put-nonce-v1");
    h.update(blob_id);
    h.update(index.to_be_bytes());
    h.finalize().to_vec()
}
/// Slot counts a bundled deposit may have. See `docs/design/bundling.md`.
///
/// A class, not a count: a bundle of exactly the messages you happened to write IS the count of
/// messages you happened to write, and padding to a rung is what makes five sends and eight sends
/// look the same.
///
/// **The rungs are NOT measured.** `[1, 4, 16]` is a first guess and a three-rung ladder makes a
/// two-message burst cost four envelopes. #256 is the precedent for taking that seriously — four
/// size classes were considered there and one was chosen, because the sizes did not fit the wire.
/// They must come from measuring real send bursts against the bandwidth they cost.
pub const BUNDLE_CLASSES: [usize; 3] = [1, 4, 16];

/// The largest bundle this build will accept.
pub const MAX_BUNDLE_SLOTS: usize = 16;

/// Whether `n` is a legal slot count.
pub fn is_bundle_class(n: usize) -> bool {
    BUNDLE_CLASSES.contains(&n)
}

/// One slot of a bundle: a ratchet envelope **already veiled for this relay** (PRIV-4).
///
/// Veiled and nothing else, and the type is the enforcement. Two things fall out of that:
///
/// - **An opener cannot be expressed.** The veil key is a session's `drop_seed`, which a first
///   contact does not have, so an `InitialSealed` envelope has no veiled form at all. That is the
///   same exclusion the old `RatchetMessage` slot type bought — a bundle stays exactly
///   `slot_count × envelope` — arrived at through the property that matters rather than by
///   naming a variant.
/// - **The veil cannot be silently dropped.** The first version of this format carried bare
///   `RatchetMessage`s, and nothing would have failed: the recipient accepts both veiled and
///   unveiled envelopes, so bundled mail would have decrypted perfectly while losing PRIV-4 on
///   every message a bundle carried. Two relays holding the same envelope — the ordinary case on
///   send-side failover — would have seen byte-identical ciphertext again.
///
/// The relay reconstructs [`SessionEnvelope::Veiled`] from these two fields when it deposits, so
/// the whole receive side is unchanged.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BundleSlot {
    /// The veil's own nonce (`karst_crypto::veil`), NOT the request nonce.
    pub veil_nonce: [u8; crate::veil::NONCE_LEN],
    /// The veiled envelope bytes.
    pub veiled: Vec<u8>,
}

impl BundleSlot {
    /// The payload the relay deposits for this slot.
    pub fn into_envelope(self) -> SessionEnvelope {
        SessionEnvelope::Veiled { nonce: self.veil_nonce, inner: self.veiled }
    }
}

/// Length of the random salt that opens a bundle's `request_nonce`.
pub const BUNDLE_SALT_LEN: usize = 32;

/// The `request_nonce` for a bundle: a fresh random salt, then a hash binding the recipient and
/// every slot **under that salt**.
///
/// Binding the slots stops a capability proof minted for one bundle from being replayed with
/// envelopes swapped in or out — the same discipline `blob_put_nonce` applies per chunk, and for
/// the same reason: the cheap structural check runs before the capability HMAC, so a proof minted
/// elsewhere is rejected at zero crypto cost.
///
/// **The salt is what makes a retransmit possible at all**, and it is not decoration. The relay's
/// replay filter keys on the request nonce, so a nonce that were a pure function of the bundle's
/// contents would make every retry of that bundle byte-identical — and rejected as a replay. The
/// entries would stay queued, retry identically, and be rejected again: a livelock, on the exact
/// path that exists to survive a lost response. The ordinary deposit path does not have this
/// problem because `transmit` draws a random nonce per attempt; the salt gives a bundle the same
/// freshness without giving up the binding.
pub fn bundle_nonce(recipient: &[u8; 32], slots: &[BundleSlot], salt: &[u8; BUNDLE_SALT_LEN]) -> Vec<u8> {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(b"KARST-bundle-nonce-v2");
    h.update(salt);
    h.update(recipient);
    h.update((slots.len() as u32).to_be_bytes());
    for s in slots {
        h.update(s.veil_nonce);
        h.update((s.veiled.len() as u32).to_be_bytes());
        h.update(&s.veiled);
    }
    let mut out = salt.to_vec();
    out.extend_from_slice(&h.finalize());
    out
}

/// Whether `nonce` is a well-formed [`bundle_nonce`] for this recipient and these slots — the
/// relay's side of the check, which reads the salt off the front rather than choosing it.
pub fn bundle_nonce_binds(recipient: &[u8; 32], slots: &[BundleSlot], nonce: &[u8]) -> bool {
    if nonce.len() != BUNDLE_SALT_LEN + 32 {
        return false;
    }
    let mut salt = [0u8; BUNDLE_SALT_LEN];
    salt.copy_from_slice(&nonce[..BUNDLE_SALT_LEN]);
    // Not constant-time on purpose: both sides are public, and an attacker who wants a matching
    // nonce can simply compute one — the check is structural, not a secret comparison.
    bundle_nonce(recipient, slots, &salt) == nonce
}

/// §15 bundled deposit: several ratchet envelopes to ONE recipient, admitted once.
///
/// Per-recipient rather than cross-recipient, and that is the whole design decision — see
/// `docs/design/bundling.md`. Packing several contacts' mail into one deposit is the bigger
/// speedup and it hands the relay a link between those mailboxes for free, in the request
/// structure itself.
///
/// Slots are [`BundleSlot`] — veiled ratchet envelopes — not `Payload`: an opener is a larger
/// fixed class of its own, so a bundle mixing one in would have two possible sizes and "a bundle
/// is slot_count x envelope" would stop being true. The type enforces it rather than a comment
/// asking implementers to remember. A first contact deposits alone, which costs nothing — a first
/// contact is one message by definition.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BundleRequest {
    pub client_addr: Vec<u8>,
    pub carrier_id: Vec<u8>,
    pub cookie: Option<Cookie>,
    /// Must satisfy [`bundle_nonce_binds`] for `recipient` and `slots`.
    pub request_nonce: Vec<u8>,
    pub capability_proof: CapabilityProof,
    pub recipient: [u8; 32],
    /// Exactly one of [`BUNDLE_CLASSES`] entries. Unused slots carry padding envelopes addressed
    /// to the same recipient — see the design note for why those are not the existing cover loop.
    pub slots: Vec<BundleSlot>,
}

/// The result of offering a bundle to a transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleOutcome {
    /// The relay answered per slot.
    Stored(Vec<SlotOutcome>),
    NeedCookie(Cookie),
    Rejected(String),
    /// This transport cannot bundle. NOT an error and NOT a silent fallback — see
    /// [`Transport::bundle`].
    Unsupported,
}

/// What one slot of a bundle did. Carried per slot inside the encrypted response: an on-path
/// observer cannot read it, and the sender needs it to know what to re-send.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SlotOutcome {
    Stored,
    /// The mailbox was full or the message was a duplicate. Named separately from a refusal of
    /// the whole bundle so a partially stored bundle is never reported as stored.
    NotStored(String),
}

/// §7.2 admission quota for blob-upload chunks (CRYPTO-15/#169). A SEPARATE window from
/// `POW_CAP_QUOTA` (the live-message quota): that budget is priced for a chat message — 4 MiB /
/// 600 s buys roughly 68 requests at the blob chunk size (`blobstore::MAX_BLOB_CHUNK`, ~60 KiB
/// ciphertext) — so a 2 GiB upload (~35_000 chunks, see `blobstore::MAX_BLOB_CHUNKS`) would need
/// on the order of 500 windows, ~85 HOURS, to clear the message quota. Charging blob bytes
/// against the message budget would not bound abuse, it would just make every honest large
/// upload time out — the wrong fix for a bypass. This budget is sized to the blob store's OWN
/// scale instead, with headroom so a full `MAX_BLOB_SIZE` transfer plus retries never trips it
/// mid-transfer: `max_bytes`/`max_requests` are DOUBLE `blobstore::MAX_BLOB_SIZE` /
/// `blobstore::MAX_BLOB_CHUNKS` (see `blob_cap_quota_has_headroom_over_the_blob_store_caps`,
/// which pins this against a later change to either side). Net effect: "refill your whole
/// storage allotment, twice over, per hour" per capability — sustaining more needs another
/// capability (another PoW solve), the same economics `POW_CAP_QUOTA` documents.
///
/// **Unlinkability trade, stated plainly:** every chunk of one upload carries the SAME
/// `capability_id` (that is what lets it be metered as one budget), so up to ~35_000 chunks of a
/// large file are linkable to each other by whoever holds the relay — and if the same capability
/// is also used for messaging, blob traffic links to message traffic under that capability. The
/// blob path's `client_addr` is deliberately fresh per DOWNLOAD for exactly the opposite reason
/// (`blob_get_addr`, client/src/lib.rs) — charging a capability is in tension
/// with that, not a free win. Accepted here because the alternative (no capability at all) is the
/// bug this closes; a client that wants blob traffic unlinked from its messaging must hold a
/// SEPARATE capability for uploads (mint one PoW solve per upload session) rather than reusing
/// its messaging capability — a client-side policy choice, not something this relay enforces.
pub const BLOB_CAP_QUOTA: Quota = Quota {
    max_requests: 2 * crate::blobstore::MAX_BLOB_CHUNKS,
    max_bytes: 2 * crate::blobstore::MAX_BLOB_SIZE,
    window_secs: 3600,
};
/// §12 fetch that ALSO consumes a one-time prekey — admission-gated exactly like a send.
///
/// The plain `FetchBundle` is a public read and stays one: discovery must never require a
/// credential, or an unprovisioned client cannot reach anyone. But handing out a one-time prekey
/// is not a read — it DESTROYS a scarce resource the recipient minted, and the recipient cannot
/// replace it until they next publish. A public read with an irreversible side effect is how
/// sixteen anonymous requests silently pushed every future first contact down to 3-DH (R2-3).
///
/// So the side effect moved behind the credential that already meters scarce relay resources.
/// A legitimate sender pays nothing new: it needs a capability to send the very next message
/// anyway. A drainer needs one capability per drain — proof-of-work on a public relay — and burns
/// its own quota doing it.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BundleOpkRequest {
    pub ik: [u8; 32],
    pub client_addr: Vec<u8>,
    pub carrier_id: Vec<u8>,
    pub cookie: Option<Cookie>,
    pub request_nonce: Vec<u8>,
    pub capability_proof: CapabilityProof,
}
/// Answer to [`BundleOpkRequest`]. `Bundle(None)` = that IK has published nothing; a bundle with
/// `opk: None` = published, but no one-time prekey left (genuine exhaustion).
pub enum BundleOpkResponse {
    NeedCookie(Cookie),
    Bundle(Option<PreKeyBundle>),
    Rejected(String),
}
/// A §12 bundle publication request. `proof` binds ownership of the private IK (`bundle.ik_pub`)
/// to cookie.mac and to the bundle contents.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PublishRequest {
    pub bundle: PreKeyBundle,
    /// A batch of ONE-TIME prekeys, each SIGNED by the publisher's identity key (see
    /// `pqxdh::SignedOpk`). The relay hands out one per bundle fetch and never twice, so each
    /// contact gets a DISTINCT prekey.
    ///
    /// They used to be bare public keys, and the note here said an OPK swap was "the same DoS
    /// bucket as a prekey swap, never a confidentiality loss". That was wrong in the way that
    /// matters: a swapped OPK does break the agreement, but only AFTER the sender has already
    /// derived a root key believing the fourth DH gave it forward secrecy against a later
    /// compromise of the long-lived prekey — a property the relay had quietly removed
    /// (CRYPTO-04). Signed now, and the relay verifies at publish so it cannot even store junk
    /// that would waste a fetcher's first contact.
    pub opks: Vec<crate::pqxdh::SignedOpk>,
    /// Drop whatever one-time prekeys the relay still holds for this IK before storing `opks`.
    /// Set when the client's own secrets are gone (restored backup / unreadable sidecar), so the
    /// relay stops serving public keys nobody can answer for (R2-4).
    pub replace_opks: bool,
    pub client_addr: Vec<u8>,
    pub carrier_id: Vec<u8>,
    pub cookie: Option<Cookie>,
    /// Replay/quota nonce for the admission pipeline. Only consulted when this publish CREATES a
    /// slot — a refresh never reaches the pipeline, so a republishing client neither spends quota
    /// nor fills the replay filter.
    pub request_nonce: Vec<u8>,
    /// Capability proof, checked when this publish creates a NEW slot (CRYPTO-18).
    pub capability_proof: CapabilityProof,
    pub proof: [u8; 16],
}
/// The reply to a §12 publication.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PublishResponse {
    /// A (fresh) cookie is needed — the client re-obtains one and retries.
    NeedCookie(Cookie),
    /// Published (the bundle was stored or overwritten).
    Published,
    /// Rejected (auth failure, or storage full).
    Rejected(String),
}
/// A mailbox fetch request. `mailbox` is the recipient's public key (their address); `proof` binds
/// ownership of the private key to `cookie.mac`.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct FetchRequest {
    pub mailbox: [u8; 32],
    pub client_addr: Vec<u8>,
    pub carrier_id: Vec<u8>,
    pub cookie: Option<Cookie>,
    /// DH ownership proof (`fetch_proof`), used for the IDENTITY mailbox (an X25519 key). Empty/
    /// ignored when `own_proof` is set.
    pub proof: [u8; 16],
    /// Schnorr ownership proof (`blind::FetchOwnershipProof`, 64 bytes) for a BLINDED drop-box —
    /// a Ristretto address has no DH with the relay's X25519 key, so it proves knowledge of the
    /// fetch secret (the discrete log of the address) instead. Empty = use the DH `proof` (the
    /// identity mailbox). Bound to the cookie MAC as its context (anti-replay).
    pub own_proof: Vec<u8>,
}
/// Delete leased messages after the recipient has durably persisted them. Carries the
/// SAME ownership proof as `FetchRequest` (see `handle_ack`): the right to delete a
/// mailbox's mail is the same right as to read it, never weaker.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct AckRequest {
    pub mailbox: [u8; 32],
    pub client_addr: Vec<u8>,
    pub carrier_id: Vec<u8>,
    pub cookie: Option<Cookie>,
    pub proof: [u8; 16],
    /// `payload_id` of each message the recipient has persisted and wants deleted.
    pub ids: Vec<[u8; 32]>,
    /// Schnorr ownership proof for a blinded drop-box (see `FetchRequest::own_proof`). Empty =
    /// use the DH `proof`. The right to delete is the same right as to read, proven the same way.
    pub own_proof: Vec<u8>,
}
/// The reply to an ACK.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum AckResponse {
    /// A (fresh) cookie is needed — the client re-obtains one and retries (as with fetch).
    NeedCookie(Cookie),
    /// Named messages deleted (or already gone — ACK is idempotent).
    Acked,
    /// Rejected (including a failed ownership proof) — the mailbox is untouched.
    Rejected(String),
}
/// The reply to a fetch.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum FetchResponse {
    /// A (fresh) cookie is needed — the client re-obtains one and retries.
    NeedCookie(Cookie),
    /// Authenticated: sealed objects for this poll — at most one fixed-size page
    /// worth (`FETCH_CAP`); any remainder stays queued for the next poll.
    Fetched(Vec<Payload>),
    /// Rejected (including a failed fetch-auth) — the mailbox is untouched.
    Rejected(String),
}
/// §7 slice 4a — a PoW redemption for the PUBLIC door. The client mines a solution for the
/// relay-declared `bucket` + difficulty (see `admission::pow`) and sends it to EARN a
/// capability. No cookie: PoW is the anti-abuse gate here, and the response (a small
/// capability) is no amplification vector. Rides the established Noise session like every
/// request, so the capability secret in the response never crosses the wire in the clear.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct JoinRequest {
    /// Time bucket the solution was mined for (the relay declares the current one via
    /// `WireResponse::PowRequired`); redeemable only while it is fresh (± skew).
    pub bucket: u32,
    /// Fresh random per attempt, so two joins are unlinkable and yield independent caps.
    pub client_seed: [u8; 32],
    /// The hashcash nonce (see `admission::pow::solve`).
    pub nonce: u64,
}
/// A relay's public descriptor for node-list discovery (the DISCOVERY plane — "which relays
/// exist", NOT the sensitive user directory). The relay-id `noise_pub ‖ fetch_pub` uniquely
/// identifies it; `addrs` are dial hints (may be several carriers: direct, `.onion`, …). This
/// is public infrastructure info: a client dialing a descriptor authenticates the relay by
/// `noise_pub` in the Noise handshake, so a wrong-key descriptor fails closed on dial.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RelayDescriptor {
    pub noise_pub: [u8; 32],
    pub fetch_pub: [u8; 32],
    pub addrs: Vec<String>,
    /// UDP endpoints where this relay also answers QUIC, if any (QUIC-1, see
    /// `docs/design/quic-transport.md`). Empty = this relay offers TCP/WSS only, which is the
    /// answer for anything reached through Tor regardless, since Tor carries no UDP.
    ///
    /// A HINT with exactly the standing of `addrs`, and bounded the same way: these are operator
    /// claims, not proofs (CRYPTO-23), and an unbounded list is an SSRF and a memory-growth vector
    /// (A3-12, A3-13). Relay identity is not established by an address — it is `Noise_NK` against
    /// the pinned relay-id, over whichever carrier the bytes arrived on.
    ///
    /// **Deliberately NOT accompanied by an ALPN string, a certificate fingerprint, or a
    /// supported-transport bitfield**, all three of which the sketch for this work proposed:
    ///
    /// - The ALPN is a protocol CONSTANT (`karst-relay/1`), not per-relay data. Advertising it
    ///   per relay would let a relay name a different one, which is a negotiation nobody asked
    ///   for.
    /// - A certificate fingerprint would be unverifiable today. The descriptor's signature covers
    ///   the relay-id and nothing else (see `discovery::location_id`), so a fingerprint would sit
    ///   in the unsigned part where a relay in the middle substitutes it — a field that invites
    ///   trust it cannot carry. It becomes meaningful only if QUIC's TLS ever REPLACES Noise as
    ///   the way relay identity is established, which is audit-gated and its own decision.
    /// - `supported_transports` would restate "is `quic_addrs` non-empty" — a second place saying
    ///   the same thing, and therefore a second place that can disagree with the first.
    pub quic_addrs: Vec<String>,
}
impl RelayDescriptor {
    /// The relay-id bytes (`noise_pub ‖ fetch_pub`) — the dedup key.
    pub fn id(&self) -> [u8; 64] {
        let mut id = [0u8; 64];
        id[..32].copy_from_slice(&self.noise_pub);
        id[32..].copy_from_slice(&self.fetch_pub);
        id
    }

    /// The 128-hex relay-id clients pin (`noise_pub ‖ fetch_pub`).
    pub fn relay_id_hex(&self) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(128);
        for b in self.noise_pub.iter().chain(self.fetch_pub.iter()) {
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

/// How long a signed descriptor stays valid. Short enough that a retired relay, or a policy a
/// relay has since changed, ages out of everyone's copy on its own; long enough that an offline
/// relay is not evicted for a restart.
pub const DESCRIPTOR_TTL_SECS: u64 = 6 * 3600;

/// How often a relay re-signs. Well under [`DESCRIPTOR_TTL_SECS`] so a descriptor fetched at the
/// worst moment still has hours of validity left, and so a configuration change reaches whoever
/// asks within an hour rather than at the next TTL boundary.
pub const DESCRIPTOR_REFRESH_SECS: u64 = 3600;

/// Clock-skew allowance, matching the discovery plane's (`DISCOVERY_CLOCK_SKEW_SECS`). Two honest
/// machines disagree by minutes; refusing a descriptor over that would make discovery depend on NTP.
pub const DESCRIPTOR_SKEW_SECS: u64 = 5 * 60;

/// **Everything a relay says about itself, in one statement it signs** (NODE-1).
///
/// # What this changes
///
/// The same facts were already advertised, in two places with different standing: `GetNodeList`
/// served addresses that nothing bound to the relay they described, and `GetPolicy` served the
/// policy over a session with that relay and nowhere else. So a client could not learn a relay's
/// policy without first connecting to it, and an intermediary passing a descriptor along could
/// rewrite anything in it.
///
/// A `NodeDescriptor` is signed by the relay's OWN Noise key, so it carries its own proof of
/// authorship wherever it travels: whoever relays it can drop it or delay it, but cannot edit it.
///
/// # What the signature does NOT establish
///
/// **Liveness.** A signature says "this relay said this", never "this relay is up, and is still
/// reachable at these addresses". A hostile peer can hand out genuinely-signed descriptors for
/// relays that retired an hour ago, and `expires_at` bounds only how stale that can get, never how
/// MANY it can send. So this does not replace the dial in `gossip::verified_self_descriptor` — that
/// dial is what keeps a dead-but-authentic entry out of the node list, and any future auto-dial path
/// must keep reusing the same gate.
///
/// **Truth.** The policy inside is still operator-DECLARED, exactly as `RelayPolicy` documents:
/// signing an unverifiable claim makes it attributable, not true. What it buys is accountability —
/// a relay that signs "ephemeral blobs" and keeps them has put its name on the statement.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodeDescriptor {
    /// The keys and dial hints — unchanged in meaning from a bare [`RelayDescriptor`].
    pub relay: RelayDescriptor,
    /// The operator-declared posture, now readable BEFORE connecting to this relay.
    pub policy: RelayPolicy,
    /// When this statement was made (relay's wall clock).
    pub issued_at: u64,
    /// When it stops being usable. See [`DESCRIPTOR_TTL_SECS`].
    pub expires_at: u64,
}

/// A [`NodeDescriptor`] with the relay's signature over it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedDescriptor {
    pub desc: NodeDescriptor,
    /// XEdDSA over [`descriptor_msg`], by the X25519 secret behind `desc.relay.noise_pub` — the
    /// same construction the prekey bundle uses, so this needs no second key, no new configuration
    /// and no change to the install scripts.
    pub sig: Vec<u8>,
}

/// The exact bytes a descriptor's signature covers: a domain tag and the postcard encoding.
///
/// postcard is positional and self-description-free, so re-encoding the decoded struct reproduces
/// the signed bytes exactly — there is no canonicalisation question to get wrong, and
/// `a_reencoded_descriptor_still_verifies` pins that property against a future field reordering.
/// Does this descriptor sit inside the node-list bounds?
///
/// A predicate rather than a sanitiser, and that is the whole point once descriptors are signed:
/// trimming an over-long address list produces a document whose signature no longer verifies, so
/// a relay that stored the trimmed version would be re-serving something nobody signed. An
/// oversized descriptor is refused instead, and stays refused until its own signer fixes it.
///
/// A descriptor with no dial hint at all fails too — it cannot be dialed, so storing it only
/// consumes a slot and teaches a client nothing.
pub fn descriptor_within_bounds(d: &RelayDescriptor) -> bool {
    let ok = |v: &Vec<String>| {
        v.len() <= MAX_ADDRS_PER_RELAY && v.iter().all(|a| !a.is_empty() && a.len() <= MAX_ADDR_LEN)
    };
    !d.addrs.is_empty() && ok(&d.addrs) && ok(&d.quic_addrs)
}

pub fn descriptor_msg(desc: &NodeDescriptor) -> Vec<u8> {
    let mut m = Vec::with_capacity(256);
    m.extend_from_slice(b"KARST-node-descriptor-v1");
    m.extend_from_slice(&postcard::to_stdvec(desc).expect("NodeDescriptor serializes"));
    m
}

impl NodeDescriptor {
    /// Build and sign this relay's current statement about itself. `noise_secret` is the X25519
    /// secret behind `relay.noise_pub`; signing with any other key yields a descriptor that
    /// verifies nowhere, which [`SignedDescriptor::verified`] treats exactly like a forgery.
    pub fn signed(
        relay: RelayDescriptor,
        policy: RelayPolicy,
        now: u64,
        noise_secret: &[u8; 32],
    ) -> SignedDescriptor {
        let desc = NodeDescriptor {
            relay,
            policy,
            issued_at: now,
            expires_at: now.saturating_add(DESCRIPTOR_TTL_SECS),
        };
        let sig = crate::discovery::sign(noise_secret, &descriptor_msg(&desc));
        SignedDescriptor { desc, sig }
    }
}

impl SignedDescriptor {
    /// The descriptor, if the signature is the relay's own AND the validity window contains `now`.
    /// `None` on any fault — nothing partially-trusted comes out of here.
    ///
    /// Both ends of the window are checked, for different reasons. The lower bound stops a
    /// still-perfectly-signed record from being replayed forever, which is the failure the discovery
    /// plane already had to close. The upper bound stops a relay from minting a descriptor that
    /// never lapses: without it, `expires_at` is a promise the signer makes to itself, and one line
    /// of a hostile fork removes it.
    pub fn verified(&self, now: u64) -> Option<&NodeDescriptor> {
        if !self.window_contains(now) {
            return None;
        }
        let ok = crate::discovery::verify(
            &self.desc.relay.noise_pub,
            &descriptor_msg(&self.desc),
            &self.sig,
        );
        ok.then_some(&self.desc)
    }

    /// The validity-window half of [`verified`], WITHOUT the signature check — arithmetic on three
    /// `u64`s and nothing else.
    ///
    /// This exists because re-verifying is not free and, on a stored descriptor, not needed. A
    /// descriptor only enters `known_relays` through `add_relay`, which refuses anything whose
    /// signature does not verify; bytes in memory do not stop being signed. What DOES change with
    /// time is the window, so that is what a re-check has to look at.
    ///
    /// Getting this wrong made `GetNodeList` — a PUBLIC read, with no admission gate — do up to
    /// `MAX_KNOWN_RELAYS` XEdDSA verifications under the relay lock, once per request, on behalf of
    /// anyone who asked. That is a work amplifier handed to strangers, and it was introduced by the
    /// commit that made the list signed in the first place.
    pub fn window_contains(&self, now: u64) -> bool {
        if self.desc.expires_at.saturating_add(DESCRIPTOR_SKEW_SECS) <= now {
            return false; // lapsed
        }
        if self.desc.expires_at
            > self.desc.issued_at.saturating_add(DESCRIPTOR_TTL_SECS + DESCRIPTOR_SKEW_SECS)
        {
            return false; // a validity window longer than the protocol allows
        }
        if self.desc.issued_at > now.saturating_add(DESCRIPTOR_SKEW_SECS) {
            return false; // signed in the future
        }
        true
    }
}
/// §15 large-file upload: one ciphertext chunk of an E2E-encrypted blob. Cookie-gated
/// (DoS/freshness, like fetch) AND capability-gated (CRYPTO-15/#169) — `capability_proof` must
/// verify (§7.2) and `request_nonce` must equal `blob_put_nonce(blob_id, index)`, so this chunk
/// is charged against `BLOB_CAP_QUOTA` under `capability_proof.capability_id`, the same way
/// every other write the relay stores costs a capability's quota; see `RelayNode::
/// handle_blob_put`. `client_addr` is still the self-declared sender used for blob ownership +
/// the blobstore's own best-effort per-sender byte caps — NOT strongly authenticated (a fresh
/// address is free to mint), which is exactly why those caps alone were never the fix; the
/// capability above is.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BlobPutRequest {
    pub client_addr: Vec<u8>,
    pub carrier_id: Vec<u8>,
    pub cookie: Option<Cookie>,
    /// Must equal `blob_put_nonce(&blob_id, index)` — see that function's doc comment.
    pub request_nonce: Vec<u8>,
    pub capability_proof: CapabilityProof,
    pub blob_id: [u8; 32],
    pub index: u32,
    pub count: u32,
    /// The blob's READ key, public half, derived by the uploader from the content key that
    /// already travels E2E inside the `FileRef` (PRIV-7a). Registered on the first chunk and
    /// immutable after; the relay keeps only this half and verifies a download proof against it.
    pub read_pub: [u8; 32],
    pub data: Vec<u8>,
}
/// §15 upload-progress query. Same class as [`BlobGetRequest`] — bearer-by-id, answered out of the
/// blob store — so it carries the same cookie stage.
///
/// It used to be `BlobStat([u8; 32])`: no address, no cookie, no admission. That made it the one
/// blob endpoint a stranger could hit for free, and the serve loop's own comment already noted a
/// stranger could "buy the full deadline with one `BlobStat`". The progress it returns was never the
/// interesting part — knowing the id already grants chunk downloads — so this is about the
/// unauthenticated endpoint, not about hiding a number (PRIV-7).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BlobStatRequest {
    pub client_addr: Vec<u8>,
    pub carrier_id: Vec<u8>,
    pub cookie: Option<Cookie>,
    pub blob_id: [u8; 32],
    /// The read key the requester CLAIMS, and the proof they hold its secret (PRIV-7a), bound to
    /// `blob_read_context(cookie.mac, blob_id, BLOB_STAT_INDEX)`.
    ///
    /// The claimed half is carried — rather than only checked against a stored one — because an
    /// uploader must be able to ask "how far did I get?" for a blob the relay has never seen, and
    /// there is nothing stored to check against yet. The relay verifies the proof against the
    /// CLAIMED key, then answers truthfully only if the stored key matches it; a mismatch is
    /// answered exactly like an unknown blob, so this cannot be turned into "does this id exist?".
    pub read_pub: [u8; 32],
    pub read_proof: Vec<u8>,
}

/// The index a STAT read-proof is bound to. A stat is not a chunk, so it needs an index of its
/// own that no real chunk can ever take: `MAX_BLOB_CHUNKS` bounds every legitimate index, so
/// `u32::MAX` is out of reach by construction. Without a distinct index, a proof captured for a
/// stat would be replayable as a chunk download and the other way round.
pub const BLOB_STAT_INDEX: u32 = u32::MAX;

/// The one refusal a blob read gives when the read token does not admit the request — an unknown
/// id and a bad proof BOTH produce exactly this, so the endpoint never answers "does this id
/// exist?" (PRIV-7a).
///
/// It is a shared constant rather than two matching literals because both sides must agree on it:
/// the relay produces it, and the client distinguishes it from every other refusal. A download
/// refused for this reason can never succeed by retrying — the key is wrong or the blob is gone —
/// whereas "blobs disabled" or a transport-level refusal is a different situation entirely.
pub const BLOB_READ_REFUSED: &str = "read proof rejected";

/// §15 large-file download: fetch one ciphertext chunk. Cookie-gated for DoS **and** read-token
/// gated (PRIV-7a): the id alone no longer buys the bytes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlobGetRequest {
    pub client_addr: Vec<u8>,
    pub carrier_id: Vec<u8>,
    pub cookie: Option<Cookie>,
    pub blob_id: [u8; 32],
    pub index: u32,
    /// Proof of the read right (PRIV-7a), bound to `blob_read_context(cookie.mac, blob_id,
    /// index)`. Downloads stop being bearer-by-id: knowing the 256-bit id is no longer enough,
    /// the requester must show they hold the content key the recipient was given.
    pub read_proof: Vec<u8>,
}
/// Response to a blob upload/download.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum BlobResponse {
    NeedCookie(Cookie),
    /// Upload: chunk stored (more expected).
    Stored,
    /// Upload: final chunk stored, blob complete + frozen.
    Complete,
    /// Download: the requested ciphertext chunk (`None` = not available / unknown id).
    Chunk(Option<Vec<u8>>),
    Rejected(String),
}
/// The transport between a client and a relay. The in-memory implementation is below; the socket
/// version is the next slice, against the same contract.
pub trait Transport {
    fn send(&self, msg: &WireMessage, now: u64) -> Response;
    fn fetch(&self, req: &FetchRequest, now: u64) -> FetchResponse;

    /// `send`/`fetch`, but carrying a per-request **isolation scope**: two requests with
    /// different scopes must not share a circuit.
    ///
    /// The default ignores the scope, which is honest for in-memory and test transports —
    /// they have no circuits to separate, and pretending otherwise would let a test assert
    /// isolation that production does not have. `SocketTransport` overrides it and passes
    /// the scope down to the adapter.
    ///
    /// Separate from `send`/`fetch` rather than replacing them so the six existing
    /// implementations keep working: a transport that cannot isolate should say so by
    /// inheriting the default, not by threading a parameter it will discard.
    fn send_isolated(&self, msg: &WireMessage, now: u64, _scope: Option<&str>) -> Response {
        self.send(msg, now)
    }

    fn fetch_isolated(&self, req: &FetchRequest, now: u64, _scope: Option<&str>) -> FetchResponse {
        self.fetch(req, now)
    }

    /// Deposit several envelopes to one recipient in one admitted request
    /// (`docs/design/bundling.md`).
    ///
    /// The default REFUSES rather than falling back to a loop of `send`s. A silent fallback would
    /// be the worst of both: the caller believes it sent a bundle, so it stops padding and stops
    /// batching, while the wire shows exactly the per-message deposits bundling exists to hide.
    /// A transport that cannot bundle says so, and the caller decides.
    /// `scope` is the same per-request isolation scope `send_isolated` carries, and it is a
    /// PARAMETER rather than an omission: a bundle that rode the default circuit while every
    /// ordinary deposit rode a per-handle one would undo path isolation exactly for the requests
    /// that carry the most messages — and `docs/design/bundling.md` leans on that isolation when
    /// it argues against cross-recipient bundles.
    fn bundle(&self, _req: &BundleRequest, _now: u64, _scope: Option<&str>) -> BundleOutcome {
        BundleOutcome::Unsupported
    }

    /// Delete leased (fetched-with-`ack`) messages after durable persistence. The default
    /// is unsupported: a transport that cannot ACK simply never sets `FetchRequest::ack`,
    /// so it stays on legacy delete-on-fetch and this is never called.
    fn ack(&self, _req: &AckRequest, _now: u64) -> AckResponse {
        AckResponse::Rejected("ack unsupported".into())
    }

    /// `ack`, but carrying a per-request isolation scope (see `fetch_isolated`). The
    /// default ignores the scope, honest for in-memory/test transports.
    fn ack_isolated(&self, req: &AckRequest, now: u64, _scope: Option<&str>) -> AckResponse {
        self.ack(req, now)
    }

    /// §12 bundle publication. Unsupported by default (test transports have no discovery); real
    /// transports override it.
    fn publish_bundle(&self, _req: &PublishRequest, _now: u64) -> PublishResponse {
        PublishResponse::Rejected("bundle publish unsupported".into())
    }

    /// §12 bundle fetch (public). `Ok(None)` means it was never published; `Err` is a transport
    /// failure. Unsupported by default.
    fn fetch_bundle(&self, _ik: &[u8; 32], _now: u64) -> Result<Option<PreKeyBundle>, String> {
        Err("bundle fetch unsupported".into())
    }

    /// §12 fetch WITH a one-time prekey (admission-gated — see [`BundleOpkRequest`]). Default is
    /// unsupported rather than "fall back to the public read": a transport that cannot present a
    /// capability must not silently obtain a weaker agreement, it must say it cannot do this.
    fn fetch_bundle_opk(
        &self,
        _req: &BundleOpkRequest,
        _now: u64,
    ) -> Result<BundleOpkResponse, String> {
        Err("one-time-prekey bundle fetch unsupported".into())
    }
}

#[cfg(test)]
mod bundle_rules {
    use super::*;

    fn msg(n: u8) -> BundleSlot {
        BundleSlot { veil_nonce: [n; crate::veil::NONCE_LEN], veiled: vec![n; 32] }
    }

    const SALT: [u8; BUNDLE_SALT_LEN] = [3u8; BUNDLE_SALT_LEN];

    /// Only the ladder's rungs are legal. A bundle of exactly what the sender happened to write
    /// IS the count of what they happened to write, which is the thing padding removes.
    #[test]
    fn only_a_class_is_a_legal_slot_count() {
        for n in [1usize, 4, 16] {
            assert!(is_bundle_class(n), "{n} is a rung and must be legal");
        }
        for n in [0usize, 2, 3, 5, 15, 17, 100] {
            assert!(!is_bundle_class(n), "{n} is not a rung and must be refused");
        }
    }

    /// The nonce binds the slots, so a proof minted for one bundle cannot be replayed with an
    /// envelope swapped in, dropped, or reordered.
    #[test]
    fn the_nonce_changes_when_any_slot_changes() {
        let r = [9u8; 32];
        let base = bundle_nonce(&r, &[msg(1), msg(2)], &SALT);

        assert_ne!(base, bundle_nonce(&r, &[msg(1), msg(3)], &SALT), "a swapped slot kept the nonce");
        assert_ne!(base, bundle_nonce(&r, &[msg(2), msg(1)], &SALT), "reordering kept the nonce");
        assert_ne!(base, bundle_nonce(&r, &[msg(1)], &SALT), "a dropped slot kept the nonce");
        assert_ne!(
            base,
            bundle_nonce(&r, &[msg(1), msg(2), msg(3)], &SALT),
            "an added slot kept the nonce"
        );
    }

    /// And to the recipient, so a bundle cannot be redirected to another mailbox.
    #[test]
    fn the_nonce_changes_with_the_recipient() {
        let slots = [msg(1), msg(2)];
        assert_ne!(
            bundle_nonce(&[1u8; 32], &slots, &SALT),
            bundle_nonce(&[2u8; 32], &slots, &SALT)
        );
    }

    /// Length is part of the binding, not just content: two slots whose bodies concatenate to the
    /// same bytes must not collide. Without the per-field length prefix they would.
    #[test]
    fn slots_cannot_be_re_split_into_the_same_nonce() {
        let r = [5u8; 32];
        let nz = [1u8; crate::veil::NONCE_LEN];
        let a = BundleSlot { veil_nonce: nz, veiled: vec![0xAA, 0xBB, 0xCC, 0xDD] };
        let b = BundleSlot { veil_nonce: nz, veiled: vec![0xAA, 0xBB] };
        let c = BundleSlot { veil_nonce: nz, veiled: vec![0xCC, 0xDD] };
        assert_ne!(
            bundle_nonce(&r, &[a], &SALT),
            bundle_nonce(&r, &[b, c], &SALT),
            "a re-split of the same bytes produced the same nonce"
        );
    }

    /// The salt is on the wire and the binding is checked against it, so the relay never has to
    /// guess which salt a sender used.
    #[test]
    fn the_relay_verifies_the_binding_from_the_nonce_alone() {
        let r = [7u8; 32];
        let slots = [msg(1), msg(2)];
        let nonce = bundle_nonce(&r, &slots, &SALT);
        assert!(bundle_nonce_binds(&r, &slots, &nonce));
        assert!(!bundle_nonce_binds(&r, &[msg(1), msg(3)], &nonce), "a swapped slot still bound");
        assert!(!bundle_nonce_binds(&[8u8; 32], &slots, &nonce), "another recipient still bound");
        assert!(!bundle_nonce_binds(&r, &slots, &nonce[..nonce.len() - 1]), "a short nonce bound");
        let mut forged = nonce.clone();
        forged[0] ^= 1; // a different salt, same tail
        assert!(!bundle_nonce_binds(&r, &slots, &forged), "the tail was not checked against the salt");
    }

    /// TWO bundles of the SAME slots must get DIFFERENT nonces, or a retransmit after a lost
    /// response is a verbatim replay — rejected by the relay's replay filter, forever, on the one
    /// path that exists to survive a lost response.
    #[test]
    fn the_same_bundle_twice_is_two_different_requests() {
        let r = [4u8; 32];
        let slots = [msg(1), msg(2), msg(3), msg(4)];
        let first = bundle_nonce(&r, &slots, &[1u8; BUNDLE_SALT_LEN]);
        let second = bundle_nonce(&r, &slots, &[2u8; BUNDLE_SALT_LEN]);
        assert_ne!(first, second, "an identical retransmit produced an identical nonce");
        assert!(bundle_nonce_binds(&r, &slots, &first));
        assert!(bundle_nonce_binds(&r, &slots, &second), "the second attempt lost the binding");
    }

    /// The ceiling matches the ladder's top rung, so a bundle that passes the class check can
    /// never exceed what the relay will accept.
    #[test]
    fn the_ceiling_and_the_ladder_agree() {
        assert_eq!(*BUNDLE_CLASSES.iter().max().expect("non-empty"), MAX_BUNDLE_SLOTS);
    }
}
