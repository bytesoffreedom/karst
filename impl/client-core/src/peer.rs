//! The §2.1 session peer: PQXDH agreement plus a Double Ratchet over the real message path
//! (admission §7 → mailbox → fetch-auth). This is where §2.1 stops being an island and becomes
//! in-process E2E over the path.
//!
//! A Peer is SENDER and RECIPIENT at once (a ratchet session is bidirectional): `connect`
//! establishes a session to a recipient from their bundle; `send` sends over it; `receive`
//! collects its own mailbox and advances the sessions. One session per peer pair (keyed by the
//! peer's long-term IK), serving both directions.
//!
//! # The slice boundaries, named rather than silent:
//! - **the socket and the CLI do NOT use this path** — there it is a process per invocation, and
//!   the ratchet needs `Session` to persist across runs (serde + Store), which is its own slice.
//!   Here a session lives in memory between calls;
//! - **§12 bundle publish/fetch** is implemented (`publish`/`connect`): the relay stores and
//!   serves bundles. But the relay is NOT an identity anchor: the authenticity of `peer_ik` is
//!   checked out of band (OOB/TOFU) — an external wall. `connect` verifies that the bundle handed
//!   over claims the requested IK; substituting only the prekey/KEM fails closed; substituting the
//!   IK itself, when `peer_ik` was never verified out of band, is a MITM;
//! - **first-delivery reliability is assumed**: the chain advances unconditionally (see `send` —
//!   otherwise keystream reuse), so an undelivered message leaves a gap. Only an `Initial` with
//!   n=0 can establish a session; if that one did not land, the session is dead until `connect`
//!   runs again (first-delivery-must-succeed). Gap-free retransmission (resending the same bytes)
//!   and the Signal prologue repeat are a separate reliability slice;
//!
//! - **a repeated `Initial`** from an already-known peer does NOT re-establish a live session
//!   (protection against state reset) — decryption continues on the existing one;
//! - **routing a `Ratchet` is trial decryption** across all sessions (safe: `decrypt` is
//!   transactional, so a miss does not advance anyone else's session). Sealed sender or a session
//!   id for explicit addressing without leaking metadata is a separate slice;
//! - **1:1 only.**

use std::collections::HashMap;
use std::time::{Duration, Instant};

use admission::capability::Capability;
use admission::cookie::Cookie;
use x25519_dalek::PublicKey;

use node::protocol::{fetch_proof, payload_id, publish_proof, AckRequest, AckResponse, BundleOpkRequest, BundleOpkResponse, FetchRequest, FetchResponse, Payload, PublishRequest, PublishResponse, Response, SessionEnvelope, Transport, WireMessage};
use karst_crypto::pqxdh::{initiate_key_agreement, Account, KeyAgreement, PreKeyBundle};

/// How much forward secrecy the FIRST message of a new session actually got.
///
/// A relay can no longer SUBSTITUTE a one-time prekey — each is signed by its owner
/// (`pqxdh::SignedOpk`). But it can still hand out none and claim exhaustion, which is
/// indistinguishable from genuine exhaustion. Refusing to talk in that case would turn a
/// downgrade into a lockout, and exhaustion is attacker-inducible today (an unauthenticated
/// bundle fetch consumes one, #159).
///
/// So the agreement proceeds and SAYS SO. Returning this from `connect` forces the caller to
/// acknowledge the difference instead of inheriting it silently — the project's "no silent
/// fallback" rule, applied to cryptographic strength rather than to transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardSecrecy {
    /// 4-DH AND a one-time ML-KEM key: a one-time unit was used, so the first message stays
    /// secret even if the peer's long-lived secrets are compromised later — on BOTH legs. The
    /// unit is one object precisely so this can be one answer (CRYPTO-33).
    Full,
    /// 3-DH and the STATIC KEM key: the bundle carried no one-time unit. The session is still
    /// end-to-end encrypted and heals on the first DH ratchet step; what is lost is forward
    /// secrecy for the FIRST message against a later compromise of the long-lived material —
    /// the signed prekey on the classical leg, and the never-rotated `kem_ek` on the
    /// post-quantum one. This is the case a caller must surface rather than swallow: it is the
    /// only signal that the PQ leg of this particular handshake is recorded-now-decrypt-later.
    NoOneTimePrekey,
}
use karst_crypto::ratchet::{RatchetMessage, Session, SessionSnapshot};
use karst_crypto::seal::Identity;

/// 32 fresh random bytes from the OS CSPRNG (pseudonyms, request nonces).
fn random32() -> [u8; 32] {
    use chacha20poly1305::aead::rand_core::RngCore;
    let mut b = [0u8; 32];
    chacha20poly1305::aead::OsRng.fill_bytes(&mut b);
    b
}

/// A decrypted incoming message WITH sender attribution. `sender` is their long-term IK
/// (PQXDH-authenticated: only the holder of the matching private key could have agreed this
/// session's root_key). It lets the UI or CLI sort incoming messages into chats — this is not new
/// crypto but an exposure of what the session already knows.
#[derive(Clone)]
pub struct Received {
    pub sender: [u8; 32],
    pub plaintext: Vec<u8>,
    /// `payload_id` of the sealed envelope this was decrypted from — a stable, collision-free
    /// id for the exact ciphertext. Lets the caller dedup a redelivered message when
    /// persisting plaintext-first (the crash-before-ratchet-save window): the same envelope
    /// redelivers with the same `msg_id`, so an already-persisted one is skipped. Set at the
    /// `receive` call site from the OUTER payload (what the relay stored and redelivers), not
    /// the inner unsealed opener.
    pub msg_id: [u8; 32],
}

/// The state of a session to one peer. `pending_initial` is `Some` until the first `Initial`
/// envelope is delivered (on the initiating side); then `None`, and we send `Ratchet`s.
struct SessionState {
    session: Session,
    pending_initial: Option<KeyAgreement>,
    /// Stable per-session secret the rotating drop-box addresses derive from (see
    /// `crate::drop`). Taken from the root key at key agreement, so both sides hold it
    /// and neither has to send it.
    drop_seed: [u8; 32],
    /// The PEER's mailbox point `M` (`karst_crypto::blind`) — where I compute my OUTBOUND blinded
    /// deposit box. The initiator takes it from the peer's signed bundle; the responder from the
    /// key-agreement. My own inbound box uses my own account mailbox secret, not this.
    peer_mailbox_pub: [u8; 32],
    /// The peer's LONG-LIVED ML-KEM encapsulation key, kept so the opener can be sealed
    /// post-quantum (PRIV-3). Only the initiator has one — it comes from the bundle this session
    /// was opened against — and it is only used while `pending_initial` is `Some`, which is why an
    /// empty vector is a legitimate state rather than a missing value: the responding side never
    /// seals an opener.
    peer_kem_ek: Vec<u8>,
}

/// Max messages held awaiting delivery to the relay. A permanently-unreachable relay must
/// not grow the state file without bound; beyond this the oldest queued message is dropped
/// (it is the least likely to still be decryptable — see the DH-step bound on `flush_outbox`).
const MAX_OUTBOX: usize = 512;

/// Ceiling on DISTINCT peer identity keys held in `sessions` — checked only where a BRAND-NEW
/// stranger's first-contact opener would otherwise insert a new entry (see `process_opener`).
///
/// Without this, `sessions` grows without bound from unauthenticated strangers: anyone who
/// fetches our published bundle can complete a valid PQXDH agreement against it with NO
/// one-time prekey of ours at all (`pqxdh::prepare_key_agreement`'s `opk_pub: None` branch
/// agrees fine against our reusable signed prekey — see CRYPTO-03/the 3-DH fallback), so the
/// attacker's cost per accepted session is just their own key generation, not a resource of
/// ours. Each accepted stranger becomes a PERMANENT `SessionState` (unbounded RAM) and, before
/// `process_for_peer` routed ordinary per-session traffic straight to its own box, an
/// unbounded per-message trial-decryption cost too — a small amount of attacker traffic buying
/// a large, and growing, amount of victim CPU (SEC-33).
///
/// Set to match the client layer's own `MAX_CONTACTS` (`client::store`, 10_000, SEC-44): a real
/// account's live session count tracks its contact count (one session per correspondent), plus
/// incidental churn from strangers who message once and are never added as a contact — the same
/// headroom the client already accepts for its own contact-flood cap. `inbound_sessions` can
/// hold at most one entry per `peer_ik` ALREADY counted here (the `inbound implies outbound`
/// invariant enforced below), so total `SessionState` entries across both maps top out at 2×
/// this, never more.
///
/// Honest residual, same shape as `MAX_MAILBOXES`'s: once `sessions` is completely full, a
/// GENUINE new correspondent's first contact is refused exactly like a hostile flood's — this
/// cap cannot tell them apart. `Peer::take_refused_sessions` makes that refusal loud (a counter
/// the caller can surface) rather than a message silently vanishing with no trace at all.
const MAX_SESSIONS: usize = 10_000;

/// Wall-clock ceiling on ONE `Peer::receive` pass (R2-12).
///
/// A receive pass fetches the identity mailbox and then EVERY session's inbound drop-box, one
/// epoch at a time — `sessions + inbound_sessions` boxes on an ordinary cycle (`poll_epochs`, 3
/// epochs), ten epochs' worth on a sweep cycle. Each of those is its own connect + Noise handshake
/// + request, because a request per handle is what keeps the relay from linking them.
///
/// That loop had no time bound at all. A relay that ACCEPTS connections and then stalls costs
/// `READ_TIMEOUT` (15 s) per box rather than failing fast the way a blackholed one does (the
/// identity fetch's `?` aborts that case in one `CONNECT_TIMEOUT`), and box errors are collected
/// rather than propagated — deliberately, so one bad box cannot discard mail already drained. Put
/// together: a few dozen sessions on a sweep cycle against a stalling relay is hours inside one
/// call, with the caller's poll thread wedged behind it. Multi-homed, the relays are polled
/// sequentially (the ratchet is one conversation, so state has to thread through them in order),
/// so a single such relay stalls every OTHER relay's mail behind it — the head-of-line half of
/// R2-12.
///
/// Stopping early is safe in the direction that matters: an unfetched box is not a drained one.
/// Its mail is still on the relay and the next cycle collects it, which is exactly what already
/// happens for a box whose fetch errors. What is NOT safe is the reverse — dropping mail already
/// in hand — so the pass returns what it collected and reports the truncation as a box error.
///
/// This bounds ONE relay's pass, not the total work. Shrinking the work itself (fewer round trips
/// per poll) is a different problem, tracked separately as the polling-cost item.
const RECEIVE_BUDGET: Duration = Duration::from_secs(20);

/// Ceiling on receipts held for a later ACK. One receipt per (relay, box) page fetched in a
/// receive cycle, so a legitimate multi-homed poll produces a handful; anything approaching this
/// means the caller is fetching without ever acking, and the oldest receipts are the ones whose
/// leases lapse first anyway.
const MAX_PENDING_ACKS: usize = 1_024;

/// Drop an undelivered queued message after this long (wall-clock, from queue time). The
/// recipient's mailbox TTL bounds how long a deposit could survive anyway, and a ratchet
/// step likely made the exact ciphertext undeliverable well before — so retrying past this
/// wastes effort on mail no one can read.
const OUTBOX_TTL_SECS: u64 = node::protocol::MAILBOX_TTL_SECS;

/// One message encrypted and durably queued, awaiting delivery to the relay. Holds the
/// EXACT ciphertext (`envelope`) so a failed transmit retries the identical bytes rather
/// than re-encrypting position N under a new plaintext (which would reuse the message key).
///
/// `drop_seed`/`peer_mailbox_pub` are a ROUTING SNAPSHOT taken at `queue` time (A6-1). Routing
/// a `Ratchet` envelope used to re-derive its deposit address from `sessions[peer_ik]`'s
/// CURRENT state at flush time — harmless as long as that state cannot change between queue
/// and flush, which held right up until `converge_split_session` started SWAPPING a peer's
/// `sessions[peer_ik]` entry out from under it (simultaneous-first-contact convergence, see
/// `Peer::converge_split_session`). Without this snapshot, a message queued under the LOSING
/// session and flushed AFTER its own convergence swap would be deposited at the WINNER's box —
/// an address the recipient's copy of the losing session never watches — and vanish silently.
/// Baking the routing in at queue time makes delivery of an already-encrypted envelope
/// independent of whatever `sessions[peer_ik]` holds by the time it is actually sent.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct OutboxEntry {
    id: u64,
    peer_ik: [u8; 32],
    envelope: SessionEnvelope,
    queued_at: u64,
    drop_seed: [u8; 32],
    peer_mailbox_pub: [u8; 32],
}

/// The peer's persistent state (for the CLI: a process per invocation resumes sessions from disk).
/// It holds ratchet snapshots, cookies and the nonce counter. **Secret material** (the ratchet
/// keys inside the snapshots) must be written under 0600, atomically and under flock (otherwise a
/// race between processes leads to keystream reuse). The Account is NOT here — it persists
/// separately (`account.key`).
/// **Format note.** postcard encodes fields positionally, so this struct's layout IS its format,
/// and there is no compatibility path: a state file from any other layout fails to decode. The
/// version that governs that is `client::secretbox::STATE_VERSION`, which must be bumped whenever
/// this struct changes — see `docs/design/format-versioning.md`.
///
/// **Why handles and cookies persist.** A caller like the CLI/GUI runs a fresh `Peer`
/// per poll, so anything not persisted is re-minted every cycle — and a re-minted handle
/// has no cookie, so every mailbox pays a `NeedCookie` round trip before it can be read.
/// That doubles the round trips per poll and delays delivery by a full cookie exchange
/// per box, which is enough to make mail land visibly late.
///
/// (It does NOT exhaust the capability quota: `RelayNode::handle_fetch` charges no quota
/// — it checks the cookie and the ownership proof and nothing else. Only deposits go
/// through the admission pipeline. An earlier version of this comment claimed otherwise;
/// it was wrong, and the code says so.)
///
/// Persisting costs nothing in privacy: `Box` handles are keyed BY epoch, so they still
/// rotate on schedule, and `Identity`/`Opener` handles address mailboxes that are
/// permanent anyway. Cookies are bearer tokens — same 0600 care as the ratchet snapshots
/// beside them.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PeerState {
    sessions: Vec<PersistedSession>,
    nonce_ctr: u64,
    /// Handles and cookies are keyed by the RELAY they belong to (its fetch-auth pubkey),
    /// because they are relay-scoped: a cookie issued by R1 is invalid at R2, and — the
    /// security invariant of multi-homing — a handle presented to R1 must never be reused
    /// at R2, or two relays that compare logs join you by a shared `client_addr` however
    /// many mailbox addresses rotate above it. Sessions are NOT keyed this way: the ratchet
    /// with a peer is the same conversation whichever relay carries it.
    handles: Vec<([u8; 32], Handle, [u8; 32])>,
    cookies: Vec<([u8; 32], Vec<u8>, Cookie)>,
    /// When the complete drop-box window was last swept. Persisted because the CLI/GUI
    /// runs a fresh `Peer` per poll: in memory it would reset every cycle, turning the
    /// slow sweep into an every-cycle one and multiplying fetch cost by `TTL_EPOCHS`.
    /// The highest drop-box epoch that has been fully swept AND can no longer receive anything —
    /// the sweep's durable cursor (#147).
    ///
    /// Without it, every sweep re-fetched ten epochs' worth of boxes for every session, forever.
    /// Most of those cannot receive: a sender deposits into ITS OWN epoch, which is at most
    /// `FUTURE_SLACK_EPOCHS` ahead of ours, so once our epoch has moved past `E + slack` nothing
    /// can ever land in epoch `E` again. Re-fetching it is a round trip that is guaranteed to come
    /// back empty — and the sweep is `sessions × epochs` of them.
    ///
    /// Only advanced when a sweep pass completed with NO box error and was not truncated by the
    /// receive budget: a cursor moved past a box that was never actually read would lose that
    /// box's mail permanently, which is the one failure this must not have. A session created
    /// after the cursor is safe by construction — it had no boxes in those epochs to miss.
    swept_through: u64,
    last_sweep: u64,
    /// The highest drop-box epoch this client has ever acted on (A6-8, #224).
    ///
    /// Epochs come from the LOCAL wall clock, which nothing authenticates. A clock that jumps
    /// BACKWARDS — a bad NTP step, a restored snapshot, a user fixing a timezone — would
    /// otherwise make us deposit into a box we already moved past and poll boxes we have already
    /// drained, quietly splitting a conversation across addresses. Keeping the high-water mark
    /// makes our own epoch monotonic, which is the half of the problem a client CAN fix about
    /// itself. Persisted for the same reason `last_sweep` is: a fresh `Peer` per poll would reset
    /// it every cycle and the guarantee would be worth nothing.
    epoch_hwm: u64,
    /// Messages encrypted (ratchet advanced) but not yet accepted by a relay, so the exact
    /// ciphertext can be retransmitted after a transport failure instead of being lost with
    /// the advanced ratchet. Persisted IN this state so it commits atomically with the
    /// ratchet snapshots — the invariant "envelope N queued ⟺ session ratchet is at ≥ N+1"
    /// depends on both landing in one write.
    outbox: Vec<OutboxEntry>,
    /// Monotonic id source for outbox entries, so a caller can ask whether a specific queued
    /// message was delivered.
    outbox_next_id: u64,
    /// Responder sessions from simultaneous first contact (see `Peer::inbound_sessions`). A
    /// separate top-level Vec — NOT a field on `PersistedSession`, so the responder map stays
    /// readable on its own. Reuses the `PersistedSession` shape unchanged (it already carries
    /// `peer_ik`).
    inbound_sessions: Vec<PersistedSession>,
}

/// (peer_ik, drop_seed) — a session's peer and the seed its drop-boxes derive from. For diagnostics.
pub type PeerSeed = ([u8; 32], [u8; 32]);

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedSession {
    peer_ik: [u8; 32],
    snapshot: SessionSnapshot,
    pending_initial: Option<KeyAgreement>,
    /// The peer's long-lived ML-KEM encapsulation key (PRIV-3), persisted for the same reason as
    /// `pending_initial`: an opener queued before a restart still has to be sealed post-quantum
    /// when it is finally sent, and this key is not recoverable from anything else on disk — the
    /// bundle it came from is not kept.
    #[serde(default)]
    peer_kem_ek: Vec<u8>,
    /// Persisted because it cannot be recovered: the root key it came from is consumed
    /// at key agreement and the ratchet has already moved past it. Lose this and the
    /// session's mail becomes unreachable — it is secret material, same care as the
    /// ratchet snapshot.
    drop_seed: [u8; 32],
    /// The peer's mailbox point (where I deposit outbound). Public, but persisted alongside the
    /// session because the responder only ever received it in the (consumed) key-agreement.
    peer_mailbox_pub: [u8; 32],
}

impl PeerState {
    /// The empty starting state (first run — no sessions).
    pub fn empty() -> Self {
        PeerState {
            sessions: Vec::new(),
            nonce_ctr: 0,
            handles: Vec::new(),
            cookies: Vec::new(),
            // Zero means "never swept", so the first poll sweeps. A client returning from
            // a long absence collects its backlog immediately rather than after the first
            // interval.
            swept_through: 0,
            last_sweep: 0,
            epoch_hwm: 0,
            outbox: Vec::new(),
            outbox_next_id: 0,
            inbound_sessions: Vec::new(),
        }
    }

    /// Deserialize a persisted state. ONE layout, strictly — see the body.
    pub fn from_bytes(bytes: &[u8]) -> Result<PeerState, postcard::Error> {
        // Strict decode. This used to be a CHAIN that walked back one trailing-field addition at
        // a time (PeerStatePreInbound → PeerStatePreOutbox), so state written by an older build
        // still loaded. There are no older builds with state, and the chain had a real hazard:
        // postcard ignores trailing bytes, so a mis-ordered attempt could silently drop fields
        // that were actually present. One layout, one decode, loud failure (no-users sweep).
        postcard::from_bytes::<PeerState>(bytes)
    }

    /// How many messages are queued in the outbox awaiting delivery to a relay (for a UI
    /// "pending sends" indicator — read without building a `Peer`).
    pub fn outbox_len(&self) -> usize {
        self.outbox.len()
    }

    /// Forget ALL session state with one peer — the outbound ratchet, the responder
    /// (`inbound_sessions`) half, and any queued outbox ciphertext addressed to them — so the NEXT
    /// send re-runs the PQXDH handshake from scratch. This is the recovery primitive for a SPLIT
    /// session: two peers who each initiated before either received (a pre-fix build dropped the
    /// other's opener, leaving each on a session the other never learned). Both sides call this,
    /// then a fresh message re-establishes ONE coherent session — sequentially it becomes a normal
    /// session, simultaneously the two-session hold handles it. Returns whether anything was
    /// removed. Ratchet continuity with that peer is intentionally broken; history is untouched.
    /// (peer_ik, drop_seed) for every held session — outbound first, then the responder
    /// (`inbound_sessions`) half. For diagnostics: a healthy pair shares ONE drop_seed per
    /// direction; a split shows each side on a different one with no matching inbound.
    pub fn debug_peers(&self) -> (Vec<PeerSeed>, Vec<PeerSeed>) {
        let f = |v: &Vec<PersistedSession>| v.iter().map(|s| (s.peer_ik, s.drop_seed)).collect();
        (f(&self.sessions), f(&self.inbound_sessions))
    }

    pub fn forget_peer(&mut self, peer_ik: &[u8; 32]) -> bool {
        let before = self.sessions.len()
            + self.inbound_sessions.len()
            + self.outbox.len()
            + self.handles.len()
            + self.cookies.len();
        self.sessions.retain(|s| &s.peer_ik != peer_ik);
        self.inbound_sessions.retain(|s| &s.peer_ik != peer_ik);
        self.outbox.retain(|o| &o.peer_ik != peer_ik);

        // ...and the TRANSPORT identifiers that name this peer, which used to survive being
        // "forgotten" (A5-9). `Handle::Opener` and `Handle::Box` embed the peer's identity key
        // directly, so a forgotten contact's IK stayed sitting in `sessions.dat` in plaintext —
        // and `Opener` is not epoch-keyed, so ordinary rotation never aged it out either. The
        // cookies keyed by those handles' addresses are the same trace one layer down: they bind
        // the relay's view of "this address knocked on Bob" to state we claimed to have deleted.
        //
        // Forgetting a contact is a user-facing promise. It has to cascade, or the promise is
        // only about what the UI stops showing.
        let mut orphaned: Vec<([u8; 32], Vec<u8>)> = Vec::new();
        self.handles.retain(|(relay, handle, addr)| {
            let names_peer = match handle {
                Handle::Opener(ik) | Handle::Box(ik, _) => ik == peer_ik,
                Handle::Identity | Handle::LoopSend(_) | Handle::LoopRecv(_) => false,
            };
            if names_peer {
                orphaned.push((*relay, addr.to_vec()));
            }
            !names_peer
        });
        self.cookies.retain(|(relay, addr, _)| !orphaned.contains(&(*relay, addr.clone())));

        before
            != self.sessions.len()
                + self.inbound_sessions.len()
                + self.outbox.len()
                + self.handles.len()
                + self.cookies.len()
    }

    /// The distinct relay ids that own a handle in this state — for tests asserting that a
    /// round-trip through one relay's `Peer` does not drop another relay's handles.
    pub fn relay_ids_for_test(&self) -> Vec<[u8; 32]> {
        let mut ids: Vec<[u8; 32]> = self.handles.iter().map(|(r, _, _)| *r).collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}

/// What a `client_addr` handle is FOR. The relay sees a handle on every request, so two
/// requests sharing one handle are linked by definition — which makes this enum the
/// real privacy boundary, not the mailbox address. Each variant gets its own unlinkable
/// random handle:
///
/// - `Identity` — polling our own identity mailbox for openers, and publishing our
///   bundle. Both already name us via the mailbox/bundle, so they may share.
/// - `Opener` — knocking on a stranger's identity mailbox. Kept apart from `Box` so the
///   relay cannot join "knocked on Bob" with "deposits into box X" and learn whose box
///   X is.
/// - `Box` — one session's drop-box in one epoch. Rotating with the epoch is what makes
///   the address rotation mean anything.
///
/// postcard encodes variants positionally — append new ones LAST.
#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
enum Handle {
    Identity,
    Opener([u8; 32]),
    Box([u8; 32], u64),
    /// Our own loop box for one epoch — cover traffic. Distinct from `Box` so a loop is
    /// never deposited under a handle a real session also uses.
    ///
    /// SPLIT by leg, and that split is the mechanism, not tidiness. A real message's box
    /// is deposited into by the sender and fetched from by the RECIPIENT — two parties,
    /// two handles, and (with per-handle isolation) two circuits, so the relay sees two
    /// source addresses. A loop is both parties. If its two legs shared a handle they
    /// would share a circuit, the relay would see one address on both, and it could tell
    /// loops from real mail at a glance — which is exactly what lets it filter cover out
    /// and fake a working drop detector. Two handles make the loop wear a real message's
    /// shape.
    LoopSend(u64),
    LoopRecv(u64),
}

/// A session peer over a transport. Holds the long-term `Account` (identity + prekey + KEM), the
/// admission capability, and the per-peer sessions.
pub struct Peer<T: Transport> {
    account: Account,
    transport: T,
    capability: Capability,
    relay_pub: PublicKey,
    carrier_id: Vec<u8>,
    nonce_ctr: u64,
    /// **Per-purpose pseudonyms** used as `client_addr` — the value the relay binds a
    /// cookie to. Fresh random bytes per `Handle`, NEVER derived from the identity key.
    ///
    /// They ARE persisted, and deliberately so — the "never persisted" this comment used to
    /// claim contradicted both `PeerState::handles` and the reasoning at the top of this file
    /// (A5-8). A caller runs a fresh `Peer` per poll, so an in-memory-only handle would be
    /// re-minted every cycle, and a new pseudonym on every poll is itself a pattern the relay can
    /// watch. Persisting costs nothing here because `Box` handles are keyed BY EPOCH, so they
    /// still rotate on the schedule the drop-boxes do.
    ///
    /// `client_addr` was once the IK, which handed the relay a plaintext social graph:
    /// on a deposit the sender's IK sat right next to `recipient`. Nothing needs it —
    /// `client_addr` is used ONLY for cookie issue/verify (the quota rides the
    /// capability, the replay filter rides the nonce) — so any unlinkable value works.
    ///
    /// One pseudonym per process was the first fix, and it was not enough. It is stable
    /// across epochs, so a relay watching fetches relinks every rotating drop-box back
    /// to the identity mailbox polled beside them, and address rotation buys nothing.
    /// Hence one handle per `Handle`: random (a derived one would just be a stable
    /// per-IK value the relay reverses by correlation) and not persisted, so a restart
    /// costs a `NeedCookie` round trip and the relay sees unrelated handles.
    ///
    /// Keyed by `(relay, Handle)`: this `Peer` talks to ONE relay (`relay_pub`), but the
    /// persisted state it loads/saves holds every relay's handles, and a handle minted for
    /// one relay must never be presented to another (see `PeerState::handles`).
    handles: HashMap<([u8; 32], Handle), [u8; 32]>,
    /// Wall-clock ceiling on one `receive` pass — see `RECEIVE_BUDGET`. A runtime knob, not
    /// persisted state: it describes how long THIS process is willing to wait, not anything about
    /// the conversation. Tests shrink it to prove the loop actually stops.
    receive_budget: Duration,
    /// Messages from a peer we DO have a session with that our chain could not open, this pass.
    ///
    /// In-memory and per-pass, deliberately not persisted: it describes what THIS run observed,
    /// not a property of the conversation. See `process_for_peer` for what it means (R2-11).
    out_of_step: u64,
    /// See `PeerState::swept_through` (#147).
    swept_through: u64,
    /// See `PeerState::last_sweep`.
    last_sweep: u64,
    /// See `PeerState::epoch_hwm` (A6-8, #224).
    epoch_hwm: u64,
    /// One cookie per handle, keyed by `(relay, client_addr)` — cookies are MAC-bound to
    /// `client_addr` AND issued by a specific relay, so R1's cookie is meaningless at R2.
    cookies: HashMap<([u8; 32], Vec<u8>), Cookie>,
    sessions: HashMap<[u8; 32], SessionState>,
    /// The RESPONDER side of a peer-initiated session, kept ALONGSIDE our own outbound one in
    /// `sessions` for the same peer. Populated ONLY when a `Session::Initial` arrives from a peer
    /// we already hold an outbound session to (simultaneous first contact — both sides PQXDH-
    /// initiated before either received). Two independent one-way ratchet chains result: we SEND
    /// on our outbound `sessions[ik]` and RECEIVE the peer's stream on `inbound_sessions[ik]`,
    /// each on its own drop-box. Invariant: `inbound implies outbound` — a pure first-contact
    /// responder still lands in `sessions`, so `send`/`has_session`/`connect` are untouched.
    inbound_sessions: HashMap<[u8; 32], SessionState>,
    /// Messages fetched-under-lease this receive, awaiting an ACK once the caller has
    /// saved the ratchet. Drained by [`Peer::ack_all`] / [`Peer::take_pending_acks`].
    /// In-memory only.
    pending_ack: Vec<AckReceipt>,
    /// Persisted send queue (mirrors `PeerState::outbox`): messages encrypted but not yet
    /// accepted by a relay, retransmitted verbatim by [`Peer::flush_outbox`].
    outbox: Vec<OutboxEntry>,
    outbox_next_id: u64,
    /// Count of brand-new strangers' first-contact attempts refused since the last
    /// [`Peer::take_refused_sessions`] because `sessions` was already at `MAX_SESSIONS`. Never
    /// persisted (like `lease`/`pending_ack`) — this is a live "something is flooding you"
    /// signal for the caller, not session state that has to survive a restart. Existing
    /// signalling paths hand back only `None` for a payload that could not be delivered
    /// (the same shape as a padded miss); this is what makes a capacity
    /// refusal LOUD instead.
    sessions_refused: u64,
    /// Count of real `Session::decrypt` attempts made while routing an inbound `Ratchet`
    /// payload. Test-only bookkeeping (never read or reset by production code): it is what
    /// lets a test prove, by COUNTING rather than timing, that `process_for_peer`'s per-session
    /// routing costs O(1) regardless of how many sessions are held, unlike the generic
    /// `process_ratchet` sweep it replaces on the real per-session-box path (SEC-33).
    decrypt_attempts_for_test: u64,
}

/// A self-contained instruction to delete one mailbox's leased messages: the address, the
/// pseudonym the cookie is bound to, the carrier, the DH shared with the relay (to rebuild
/// the ownership proof on a cookie refresh), the cookie that authorised the fetch, the
/// isolation scope, and the ids to delete. Opaque to callers — everything [`send_ack`]
/// needs is inside, so a receipt can be carried OUT of a `Peer` (multi-homed receive
/// drops the per-relay `Peer` before the single save) and acked afterwards through the
/// right relay's transport.
pub struct AckReceipt {
    mailbox: [u8; 32],
    client_addr: Vec<u8>,
    carrier_id: Vec<u8>,
    shared: [u8; 32],
    cookie: Option<Cookie>,
    scope: Option<String>,
    ids: Vec<[u8; 32]>,
    /// For a BLINDED drop-box: the fetch secret to re-prove ownership on the ACK (Schnorr). `None`
    /// for the identity mailbox, which uses the DH `shared` above.
    own_fetch_secret: Option<[u8; 32]>,
}

/// What proves ownership of the mailbox being fetched/acked: the IDENTITY mailbox is an X25519 key
/// (DH proof); a rotating drop-box is a blinded Ristretto address (Schnorr proof over its fetch
/// secret — `karst_crypto::blind`).
enum BoxAuth {
    Identity(Identity),
    DropBox { address: [u8; 32], fetch_secret: [u8; 32] },
}

impl BoxAuth {
    fn mailbox(&self) -> [u8; 32] {
        match self {
            BoxAuth::Identity(id) => id.public.to_bytes(),
            BoxAuth::DropBox { address, .. } => *address,
        }
    }
}

/// One fetch, built and authorised but not yet sent.
///
/// The split exists so the network phase needs nothing mutable: building this MINTS a handle and
/// reads a cookie (both `&mut self`), sending it needs only `&self.transport`. Everything the
/// response handler will need is carried here rather than re-derived, because re-deriving
/// `client_addr` after the fact would mint a DIFFERENT handle and file the ACK receipt under an
/// address the relay never saw.
#[derive(Clone)]
pub struct PreparedFetch {
    req: FetchRequest,
    client_addr: Vec<u8>,
    scope: Option<String>,
    /// The cookie the request was signed with — the ACK must re-present this exact one, and by the
    /// time the response is absorbed the cookie map may already hold a newer one.
    cookie: Option<Cookie>,
}

/// Evidence that this relay is reached over the DIRECT carrier, with no proxy in the path.
///
/// It exists so the fan-out below cannot be enabled by accident. Fetching many boxes CONCURRENTLY
/// is the same shape as batching them, and #280 settled that question for batching: under a proxy
/// it must never happen. Sequential fetches are spread out in time, which is most of what keeps a
/// relay from reading one client's boxes as one set; N simultaneous circuit opens collapse exactly
/// that spread, and under Tor they also multiply circuits for a single poll.
///
/// The type is the prohibition. There is no `pub` constructor that takes a bare `true` — the only
/// way to obtain one is [`DirectCarrier::inspect`], which is handed the actual proxy and route
/// configuration and answers `None` for anything that is not a plain direct connection.
pub struct DirectCarrier(());

impl DirectCarrier {
    /// `Some` only when nothing sits between us and the relay: no SOCKS5 proxy, and no route that
    /// is anything other than a direct dial. Anything unrecognised answers `None` — a new carrier
    /// added later is refused until someone decides deliberately that it may fan out.
    pub fn inspect(proxy: Option<&str>, routes: &[String]) -> Option<Self> {
        if proxy.is_some_and(|p| !p.trim().is_empty()) {
            return None;
        }
        if routes.iter().any(|r| !r.trim().is_empty() && !r.eq_ignore_ascii_case("direct")) {
            return None;
        }
        Some(DirectCarrier(()))
    }
}

/// How the box-fetch phase is executed. The phases themselves (`prepare_fetch` → transport →
/// `absorb_fetch`) do not change; only who runs the middle one, and how many at a time.
///
/// It is a trait rather than a flag because the parallel implementation needs `T: Sync`, which
/// cannot be added to `receive` itself: the in-memory test transports are `Rc`-based and would stop
/// compiling. With a trait, the bound sits on the implementation, so a caller holding a non-`Sync`
/// transport simply cannot name the parallel executor.
pub trait BoxFetcher<T: Transport> {
    /// Run every prepared request against the transport, returning one response per request **in
    /// the same order**. Order is not cosmetic: the caller absorbs them in box order, and
    /// `pending_ack` evicts its oldest entry at the cap.
    fn run(&self, transport: &T, reqs: &[PreparedFetch], now: u64) -> Vec<FetchResponse>;
}

/// One box at a time — the behaviour every caller had before the fan-out existed.
pub struct Sequential;

impl<T: Transport> BoxFetcher<T> for Sequential {
    fn run(&self, transport: &T, reqs: &[PreparedFetch], now: u64) -> Vec<FetchResponse> {
        reqs.iter().map(|p| transport.fetch_isolated(&p.req, now, p.scope.as_deref())).collect()
    }
}

/// Several boxes at once, on the direct carrier only.
///
/// `width` bounds how many requests are in flight; it is not "one thread per box" — a client with a
/// large session table would otherwise open hundreds of sockets in one poll, which is a burst the
/// relay sees as one client and the OS may refuse outright.
pub struct Parallel {
    _direct: DirectCarrier,
    width: usize,
}

impl Parallel {
    /// Requires the [`DirectCarrier`] witness by value, so the prohibition cannot be satisfied by
    /// a stale check somewhere else in the caller.
    pub fn new(direct: DirectCarrier, width: usize) -> Self {
        Parallel { _direct: direct, width: width.clamp(1, MAX_FETCH_WIDTH) }
    }
}

impl<T: Transport + Sync> BoxFetcher<T> for Parallel {
    fn run(&self, transport: &T, reqs: &[PreparedFetch], now: u64) -> Vec<FetchResponse> {
        if reqs.len() <= 1 {
            return Sequential.run(transport, reqs, now);
        }
        let next = std::sync::atomic::AtomicUsize::new(0);
        let slots: Vec<std::sync::Mutex<Option<FetchResponse>>> =
            (0..reqs.len()).map(|_| std::sync::Mutex::new(None)).collect();
        let workers = self.width.min(reqs.len());
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(p) = reqs.get(i) else { return };
                    let resp = transport.fetch_isolated(&p.req, now, p.scope.as_deref());
                    // Written into ITS OWN slot, so the result order is the request order however
                    // the threads interleave.
                    *slots[i].lock().expect("slot lock") = Some(resp);
                });
            }
        });
        slots
            .into_iter()
            .map(|s| {
                s.into_inner()
                    .expect("slot lock")
                    .unwrap_or_else(|| FetchResponse::Rejected("fetch worker produced no answer".into()))
            })
            .collect()
    }
}

/// The ceiling on concurrent box fetches. Small deliberately: the win is removing serial latency,
/// not saturating a link, and a burst that looks like a scan is worse than a slow poll.
pub const MAX_FETCH_WIDTH: usize = 8;

/// What a fetch response means to the caller, once the `&mut self` bookkeeping is done.
enum Absorbed {
    Fetched(Vec<Payload>),
    /// The relay issued a fresh cookie; it is banked, and the same box should be asked again. The
    /// caller bounds how many times — one retry, exactly as before the split.
    Retry,
    Rejected(String),
}

/// Send one ACK, best-effort, refreshing the cookie once on a `NeedCookie`. Free (not a
/// method) so single- and multi-homed receive share exactly one copy of the retry: the
/// single path acks through the `Peer`'s own transport, the multi path acks a carried-out
/// receipt through the relay's transport after the single save. A failure just leaves the
/// message leased to redeliver — never an error the caller must handle.
pub fn send_ack<T: Transport>(transport: &T, receipt: &AckReceipt, now: u64) {
    let mut cookie = receipt.cookie;
    for _ in 0..2 {
        // Same ownership proof as the fetch that leased these: Schnorr for a drop-box, DH for the
        // identity mailbox.
        let (proof, own_proof) = match (receipt.own_fetch_secret, cookie) {
            (Some(fs), Some(c)) => {
                let own = karst_crypto::blind::FetchOwnershipProof::prove(&fs, &receipt.mailbox, &c.mac)
                    .map(|p| p.to_bytes().to_vec())
                    .unwrap_or_default();
                ([0u8; 16], own)
            }
            (None, Some(c)) => (fetch_proof(&receipt.shared, &c.mac, &receipt.mailbox), Vec::new()),
            (_, None) => ([0u8; 16], Vec::new()),
        };
        let req = AckRequest {
            mailbox: receipt.mailbox,
            client_addr: receipt.client_addr.clone(),
            carrier_id: receipt.carrier_id.clone(),
            cookie,
            proof,
            ids: receipt.ids.clone(),
            own_proof,
        };
        match transport.ack_isolated(&req, now, receipt.scope.as_deref()) {
            AckResponse::NeedCookie(c) => {
                cookie = Some(c);
                continue;
            }
            // Acked or Rejected: nothing more to do.
            _ => break,
        }
    }
}

impl<T: Transport> Peer<T> {
    pub fn new(transport: T, account: Account, capability: Capability, relay_pub: PublicKey) -> Self {
        Peer {
            account,
            transport,
            capability,
            relay_pub,
            carrier_id: b"mem".to_vec(),
            nonce_ctr: 0,
            handles: HashMap::new(),
            cookies: HashMap::new(),
            receive_budget: RECEIVE_BUDGET,
            out_of_step: 0,
            swept_through: 0,
            last_sweep: 0,
            epoch_hwm: 0,
            sessions: HashMap::new(),
            inbound_sessions: HashMap::new(),
            pending_ack: Vec::new(),
            outbox: Vec::new(),
            outbox_next_id: 0,
            sessions_refused: 0,
            decrypt_attempts_for_test: 0,
        }
    }

    /// How many messages this pass arrived from a peer we hold a session with and could NOT be
    /// opened — the local, detectable symptom of another device using this identity (R2-11).
    ///
    /// Take it after `receive` and surface it. Zero is the normal answer; anything else means the
    /// ratchet with that contact has been advanced by something this vault did not do, and the
    /// mail is not going to start arriving on its own. Reading it RESETS it, so a caller polling
    /// in a loop reports per pass rather than a growing total.
    pub fn take_out_of_step(&mut self) -> u64 {
        std::mem::take(&mut self.out_of_step)
    }

    /// Shorten (or lengthen) the wall-clock ceiling on one `receive` pass — see `RECEIVE_BUDGET`
    /// for what it bounds and why stopping early is safe. A caller that polls on a tight schedule
    /// can hand it a budget smaller than the interval so a stalling relay can never make one poll
    /// overlap the next.
    pub fn set_receive_budget(&mut self, budget: Duration) {
        self.receive_budget = budget;
    }

    /// This client's drop-box epoch, forced monotonic (A6-8, #224).
    ///
    /// `drop::epoch_of(now)` is a pure function of the local wall clock, and nothing authenticates
    /// that clock. Going FORWARD is normal (time passes, and a long offline stretch is a big
    /// legitimate jump). Going BACKWARDS is not: it makes us deposit into a box we have already
    /// moved past and poll boxes we already drained, so one conversation ends up split across
    /// addresses with no error anywhere. The high-water mark refuses the backwards half.
    ///
    /// It does NOT fix the other half — a clock wrong in the FORWARD direction still puts our
    /// deposits into a box the peer may not look in. Nothing local can catch that without an
    /// authenticated time source; the receiving side's `drop::FUTURE_SLACK_EPOCHS` is what
    /// tolerates it, and only up to a point.
    fn local_epoch(&mut self, now: u64) -> u64 {
        let e = crate::drop::epoch_of(now);
        if e > self.epoch_hwm {
            self.epoch_hwm = e;
        }
        self.epoch_hwm
    }

    /// The relay this `Peer` talks to, as the namespace key for handles and cookies.
    fn relay_id(&self) -> [u8; 32] {
        self.relay_pub.to_bytes()
    }

    /// The `client_addr` for one purpose ON THIS RELAY, minted on first use and kept.
    /// Scoped by relay so the same purpose gets a DIFFERENT handle on a different relay —
    /// otherwise two relays comparing logs would see one `client_addr` and link you.
    fn handle(&mut self, key: Handle) -> Vec<u8> {
        let rid = self.relay_id();
        self.handles.entry((rid, key)).or_insert_with(random32).to_vec()
    }

    /// The transport isolation scope for a handle: requests under different handles must
    /// not share a circuit.
    ///
    /// Without this the whole handle scheme is undone one layer down. Handles make two
    /// requests unlinkable to the relay by construction — and then they arrive over one
    /// connection from one source address, and the relay relinks them for free. Rotating
    /// an identifier above the IP means nothing while the IP is shared.
    ///
    /// Derived from the handle by a hash rather than being the handle: the relay reads the
    /// handle in the clear as `client_addr`, and the proxy sees the scope, so passing it
    /// verbatim would let a proxy operator and a relay operator join their logs on an
    /// exact match rather than on timing. (The adapter hashes again with its compartment
    /// token — belt and braces, and the two live at different layers.)
    fn scope_for(&self, handle: &Handle) -> Option<String> {
        let bytes = self.handles.get(&(self.relay_id(), handle.clone()))?;
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"karst-handle-scope-v1");
        h.update(bytes);
        Some(h.finalize().iter().take(16).map(|x| format!("{x:02x}")).collect())
    }

    /// Forget handles for epochs no longer in flight, and the cookies bound to them.
    ///
    /// Without this, `Box` handles accumulate one per session per epoch forever — an
    /// unbounded state file, and a growing on-disk record of exactly which epochs a
    /// conversation was active in. Retiring a handle the moment its epoch leaves the
    /// poll window keeps the file bounded and the history short.
    fn prune_handles(&mut self, now: u64) {
        let live = crate::drop::poll_epochs(now);
        // (relay, client_addr) of each pruned handle, so its relay-scoped cookie goes too.
        let mut dropped: Vec<([u8; 32], [u8; 32])> = Vec::new();
        self.handles.retain(|(relay, h), v| match h {
            Handle::Box(_, epoch) | Handle::LoopSend(epoch) | Handle::LoopRecv(epoch)
                if !live.contains(epoch) =>
            {
                dropped.push((*relay, *v));
                false
            }
            _ => true,
        });
        self.cookies
            .retain(|(relay, addr), _| !dropped.iter().any(|(dr, da)| dr == relay && da.as_slice() == addr.as_slice()));
    }

    /// Take the persistent state (sessions + cookies + nonce), to save to disk between CLI process
    /// invocations.
    pub fn export_state(&self) -> PeerState {
        let persist = |map: &HashMap<[u8; 32], SessionState>| -> Vec<PersistedSession> {
            map.iter()
                .map(|(ik, st)| PersistedSession {
                    peer_ik: *ik,
                    snapshot: st.session.snapshot(),
                    pending_initial: st.pending_initial.clone(),
                    drop_seed: st.drop_seed,
                    peer_mailbox_pub: st.peer_mailbox_pub,
                    peer_kem_ek: st.peer_kem_ek.clone(),
                })
                .collect()
        };
        let sessions = persist(&self.sessions);
        let inbound_sessions = persist(&self.inbound_sessions);
        PeerState {
            sessions,
            inbound_sessions,
            nonce_ctr: self.nonce_ctr,
            // Round-trip the FULL multi-relay map: this Peer only used its own relay's
            // entries, but the persisted state carries every relay's, so other relays'
            // handles/cookies are not lost when one relay's Peer saves back.
            handles: self.handles.iter().map(|((r, k), v)| (*r, k.clone(), *v)).collect(),
            cookies: self.cookies.iter().map(|((r, k), v)| (*r, k.clone(), *v)).collect(),
            swept_through: self.swept_through,
            last_sweep: self.last_sweep,
            epoch_hwm: self.epoch_hwm,
            outbox: self.outbox.clone(),
            outbox_next_id: self.outbox_next_id,
        }
    }

    /// Load persistent state (overwrites the current in-memory state).
    pub fn import_state(&mut self, state: PeerState) {
        self.nonce_ctr = state.nonce_ctr;
        self.handles = state.handles.into_iter().map(|(r, k, v)| ((r, k), v)).collect();
        self.cookies = state.cookies.into_iter().map(|(r, k, v)| ((r, k), v)).collect();
        self.swept_through = state.swept_through;
        self.last_sweep = state.last_sweep;
        self.epoch_hwm = state.epoch_hwm;
        self.outbox = state.outbox;
        self.outbox_next_id = state.outbox_next_id;
        let restore = |v: Vec<PersistedSession>| -> HashMap<[u8; 32], SessionState> {
            v.into_iter()
                .map(|p| {
                    (
                        p.peer_ik,
                        SessionState {
                            session: Session::restore(p.snapshot),
                            pending_initial: p.pending_initial,
                            drop_seed: p.drop_seed,
                            peer_mailbox_pub: p.peer_mailbox_pub,
                            peer_kem_ek: p.peer_kem_ek,
                        },
                    )
                })
                .collect()
        };
        self.sessions = restore(state.sessions);
        self.inbound_sessions = restore(state.inbound_sessions);
    }

    /// This peer's long-term IK — its mailbox address, and the session key its peers use.
    pub fn identity(&self) -> [u8; 32] {
        self.account.identity_public()
    }

    /// Mint `n` fresh one-time prekeys and return THEIR public keys — the only ones a publish
    /// should advertise (re-advertising already-published keys stockpiles duplicates on the
    /// relay; see [`Peer::publish`], Bug C). The secrets are held in the account for the caller
    /// to persist; each is consumed on `receive`.
    pub fn add_opks(&mut self, n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|_| self.account.add_opk()).collect()
    }

    /// Load persisted one-time prekey secrets into this peer's account (before receiving,
    /// so openers that used an OPK can be accepted; before publishing, to advertise them).
    pub fn load_opks(&mut self, secrets: &[karst_crypto::pqxdh::OneTimeSecret]) {
        self.account.import_opk_secrets(secrets);
    }

    /// The account's current unconsumed one-time prekey secrets, to persist after a
    /// `receive` (which consumes some) or a top-up.
    pub fn export_opks(&self) -> Vec<karst_crypto::pqxdh::OneTimeSecret> {
        self.account.export_opk_secrets()
    }

    /// How many unconsumed one-time prekeys the account currently holds.
    pub fn opk_count(&self) -> usize {
        self.account.opk_count()
    }

    /// Whether a session to the peer exists (so `connect` is not called twice).
    pub fn has_session(&self, peer_ik: &[u8; 32]) -> bool {
        self.sessions.contains_key(peer_ik)
    }

    /// This peer's public prekey bundle.
    pub fn bundle(&self) -> PreKeyBundle {
        self.account.prekey_bundle()
    }

    /// This peer's bundle carrying one of ITS OWN one-time prekeys, signed. The only way to build
    /// such a bundle from outside `pqxdh`: an OPK cannot be attached without the identity key that
    /// signs it, so nothing can accidentally produce the unsigned form the relay used to serve.
    pub fn bundle_with_opk(&self, opk_pub: [u8; 32]) -> PreKeyBundle {
        self.account.prekey_bundle_with_opk(opk_pub)
    }

    /// §12: publish OUR bundle at the relay so others can initiate towards us.
    /// Cookie refresh plus an ownership proof (possession of the private IK).
    pub fn publish(&mut self, now: u64) -> PublishResponse {
        // Advertise the account's currently-held one-time prekeys. Fine for a ONE-SHOT publish
        // (a fresh account with no OPKs publishes an empty batch). For a PERSISTENT batch that is
        // re-published over time, use [`Peer::publish_advertising`] with only freshly minted keys:
        // the relay appends a publish's OPKs with no dedup, so re-advertising the whole held set
        // stockpiles duplicates and later hands the SAME key to two first-contacts (Bug C — see
        // the client `publish_with_opks`).
        let opks = self.account.opk_pubs();
        self.publish_advertising(&opks, now)
    }

    /// Publish the bundle advertising EXACTLY `opks`. The caller passes only FRESHLY minted
    /// one-time prekeys (`add_opks`), never the whole held set — see [`Peer::publish`] for why
    /// re-advertising already-published keys stockpiles duplicates and drops first-contacts.
    /// Minting/persisting the batch is the caller's job (tops up and saves before publishing).
    pub fn publish_advertising(&mut self, opks: &[[u8; 32]], now: u64) -> PublishResponse {
        self.publish_advertising_replacing(opks, false, now)
    }

    /// As [`Peer::publish_advertising`], but first tells the relay to DROP the one-time prekeys it
    /// still holds for this identity. Use when our own secrets are gone (restored backup, damaged
    /// sidecar): otherwise the relay keeps serving keys nobody can answer for (R2-4).
    pub fn publish_advertising_replacing(
        &mut self,
        opks: &[[u8; 32]],
        replace: bool,
        now: u64,
    ) -> PublishResponse {
        let bundle = self.account.prekey_bundle();
        let signed_opks: Vec<karst_crypto::pqxdh::SignedOpk> = opks
            .iter()
            .filter_map(|k| self.account.signed_opk(k))
            .collect();
        let shared = self.account.ik().dh(&self.relay_pub);
        // Publishing announces the bundle — and the IK inside it — so it shares the
        // handle with the identity-mailbox poll, which names us just as loudly. It must
        // NOT share with a drop-box handle.
        let client_addr = self.handle(Handle::Identity);
        let rid = self.relay_id();
        for _ in 0..2 {
            let cookie = self.cookies.get(&(rid, client_addr.clone())).copied();
            let proof = match cookie {
                Some(c) => publish_proof(&shared, &c.mac, &bundle),
                None => [0u8; 16],
            };
            // The nonce/proof are only consulted when this publish CREATES the slot; a refresh
            // never reaches the admission pipeline. Minted per attempt so a cookie retry is not a
            // replay.
            let nonce = random32().to_vec();
            let req = PublishRequest {
                bundle: bundle.clone(),
                request_nonce: nonce.clone(),
                capability_proof: self.capability.prove(&nonce, 0),
                // Sign each one-time prekey here, at the only place that holds the identity
                // secret. The relay stores opaque signed pairs and can hand one out, but cannot
                // mint a substitute (CRYPTO-04).
                opks: signed_opks.clone(),
                replace_opks: replace,
                client_addr: client_addr.clone(),
                carrier_id: self.carrier_id.clone(),
                cookie,
                proof,
            };
            match self.transport.publish_bundle(&req, now) {
                PublishResponse::NeedCookie(c) => {
                    self.cookies.insert((rid, client_addr.clone()), c);
                    continue;
                }
                other => return other,
            }
        }
        PublishResponse::Rejected("persistent cookie challenge".into())
    }

    /// §12: establish a session to `peer_ik` by FETCHING their bundle from the relay.
    /// Verifies that the bundle handed over claims the REQUESTED IK — the relay cannot slip in a
    /// bundle under a different IK unnoticed (substituting the IK itself is the external wall: the
    /// authenticity of `peer_ik` is checked out of band, see STATUS).
    pub fn connect(&mut self, peer_ik: &[u8; 32], now: u64) -> Result<ForwardSecrecy, String> {
        let bundle = self.fetch_bundle_with_opk(peer_ik, now)?;
        if bundle.ik_pub != *peer_ik {
            return Err("relay returned bundle for wrong IK".into());
        }
        self.connect_with_bundle(&bundle)
    }

    /// Fetch `peer_ik`'s bundle over the ADMISSION-GATED path, so it may carry a one-time prekey.
    ///
    /// Deliberately no fallback to the public `fetch_bundle` when this is rejected: the public
    /// read never carries an OPK, so falling back would turn "my capability was refused" into a
    /// silently weaker 4-DH→3-DH agreement — the exact class of silent downgrade this whole
    /// slice exists to remove. A rejection is an error the caller sees.
    fn fetch_bundle_with_opk(&mut self, peer_ik: &[u8; 32], now: u64) -> Result<PreKeyBundle, String> {
        // A fresh per-request handle, like any other admission-gated request: the relay learns
        // "somebody wants IK X" either way, but not that it is the same somebody as last time.
        let client_addr = self.handle(Handle::Identity);
        let rid = self.relay_id();
        let nonce = random32().to_vec();
        let proof = self.capability.prove(&nonce, 0);
        let mut req = BundleOpkRequest {
            ik: *peer_ik,
            client_addr: client_addr.clone(),
            carrier_id: self.carrier_id.clone(),
            cookie: self.cookies.get(&(rid, client_addr.clone())).copied(),
            request_nonce: nonce,
            capability_proof: proof,
        };
        for _ in 0..2 {
            match self.transport.fetch_bundle_opk(&req, now)? {
                BundleOpkResponse::NeedCookie(c) => {
                    self.cookies.insert((rid, client_addr.clone()), c);
                    req.cookie = Some(c);
                }
                BundleOpkResponse::Bundle(Some(b)) => return Ok(b),
                BundleOpkResponse::Bundle(None) => return Err("bundle not published".into()),
                BundleOpkResponse::Rejected(e) => return Err(format!("bundle fetch rejected: {e}")),
            }
        }
        Err("persistent cookie challenge on bundle fetch".into())
    }

    /// Establish an outgoing session from a bundle already in hand (OOB delivery, or tests).
    /// **The authenticity of `bundle.ik_pub` is the caller's responsibility** (the relay is not a
    /// trusted identity anchor). It does NOT overwrite a live session: a repeated `connect` to a
    /// known peer returns `Err` (otherwise a new root_key would silently kill a working session in
    /// both directions — the same class of silent loss).
    pub fn connect_with_bundle(&mut self, bundle: &PreKeyBundle) -> Result<ForwardSecrecy, String> {
        if self.sessions.contains_key(&bundle.ik_pub) {
            return Err("session already established with this peer".into());
        }
        // Reject a bundle whose signed prekey material (prekey ‖ KEM key) does not verify under
        // its own IK — a relay that substituted a prekey is caught HERE, explicitly, instead of
        // only failing closed later when the ratchet can't decrypt. (The IK itself is anchored
        // out of band / by the safety number; this closes the prekey-substitution gap.)
        if !bundle.verify_prekey_sig() {
            return Err("bundle prekey signature invalid — relay tampered or unsigned bundle".into());
        }
        // A degenerate mailbox point is signed by its owner but still unusable: the all-zero
        // encoding is the Ristretto identity, so `h·M` is the identity for every epoch — every
        // sender derives the same box and nobody can prove ownership of it. Refuse it here rather
        // than storing it and failing at the first send.
        if bundle.mailbox_pub == [0u8; 32] {
            return Err("bundle carries a degenerate mailbox point — refusing".into());
        }
        // A malformed KEM key in a (validly signed) bundle fails HERE with an error instead of
        // panicking the client — a malicious contact can sign its own garbage (CRYPTO-08).
        let (root_key, ka) =
            initiate_key_agreement(self.account.ik(), &self.account.mailbox_public(), bundle)?;
        // Take the drop-box seed BEFORE the ratchet starts moving: this is the one
        // moment both sides hold the same root key.
        let drop_seed = crate::drop::drop_seed(&root_key);
        let session = Session::init_sender(root_key, bundle.prekey_pub);
        // The PEER's mailbox point (from its signed bundle) — where I deposit my outbound box.
        let peer_mailbox_pub = bundle.mailbox_pub;
        let fs = match ka.opk_pub {
            Some(_) => ForwardSecrecy::Full,
            None => ForwardSecrecy::NoOneTimePrekey,
        };
        self.sessions.insert(
            bundle.ik_pub,
            SessionState {
                session,
                pending_initial: Some(ka),
                drop_seed,
                peer_mailbox_pub,
                peer_kem_ek: bundle.kem_ek.clone(),
            },
        );
        Ok(fs)
    }

    /// Send `plaintext` to `peer_ik` over an established session.
    ///
    /// **The chain advances UNCONDITIONALLY** on `encrypt`: each `mk` encrypts exactly one
    /// plaintext, which is what makes the zero nonce safe (the `ratchet` precondition). A
    /// non-delivery (`Rejected`) leaves a **gap** — the recipient rejects it on in-order/`pn`
    /// grounds until the session is re-established. That is a liveness cost, NOT key reuse: NEVER
    /// trade nonce uniqueness for liveness at the crypto layer. (If the advance were committed only
    /// on `Accepted`, the next DIFFERENT plaintext would take the same chain position → the same
    /// `mk` with a zero nonce → keystream reuse, while the relay is untrusted and the first
    /// ciphertext has already left.) Gap-free retransmission means resending the same envelope
    /// BYTES verbatim (never re-encrypting) — a separate reliability slice.
    pub fn send(&mut self, peer_ik: &[u8; 32], plaintext: &[u8], now: u64) -> Response {
        let envelope = match self.encrypt_next(peer_ik, plaintext) {
            Ok(e) => e,
            Err(e) => return Response::Rejected(e),
        };
        self.transmit_envelope(peer_ik, envelope, now)
    }

    /// Encrypt the next message (advancing the chain UNCONDITIONALLY) and return the envelope
    /// WITHOUT transmitting it. For crash-consistent sending: the caller must PERSIST the state
    /// BEFORE transmitting. Otherwise a crash between transmit and save means the next send
    /// re-encrypts the same chain position with different text → the same `mk` plus a zero nonce =
    /// keystream reuse (ciphertext N is already at the relay). The durable record "position N is
    /// spent" must land before ct_N appears on the wire.
    pub fn encrypt_next(&mut self, peer_ik: &[u8; 32], plaintext: &[u8]) -> Result<SessionEnvelope, String> {
        let st = self.sessions.get_mut(peer_ik).ok_or("no session (call connect first)")?;
        // THE one place a ratchet plaintext is produced, and therefore the one place it is padded
        // to a fixed block (`crate::pad`). Padding here rather than at each caller is the whole
        // design: the relay reads `msg.ciphertext.len()` after terminating Noise, so a single
        // unpadded send site would restore the size signal for that message class alone — and it
        // would be the class nobody thought about.
        let padded = crate::pad::pad(plaintext)?;
        let rmsg = st.session.encrypt(&padded); // advances the stored session
        Ok(match &st.pending_initial {
            // Seal the opener to the RECIPIENT's identity key. The KeyAgreement carries
            // our long-term IK, and an unsealed opener hands the relay the social-graph
            // edge in the clear — it treats the payload as opaque, but the format is
            // public and parseable. Sealed, the relay sees a fresh ephemeral + ciphertext
            // and cannot tell who opened the conversation.
            Some(ka) => {
                let plain = postcard::to_stdvec(ka).map_err(|e| format!("encode ka: {e}"))?;
                // Sealed to BOTH of the recipient's long-lived public keys (PRIV-3): X25519 for the
                // classical half, ML-KEM for the half a quantum adversary cannot break. Without the
                // second one, an opener recorded today still names who first wrote to whom later.
                let sealed_ka = karst_crypto::seal::SkeletonSeal::seal(
                    &PublicKey::from(*peer_ik),
                    &st.peer_kem_ek,
                    &plain,
                )?;
                SessionEnvelope::InitialSealed { sealed_ka, msg: rmsg }
            }
            None => SessionEnvelope::Ratchet(rmsg),
        })
    }

    /// Transmit an already-encrypted envelope (with cookie retry). On `Accepted` it clears
    /// `pending_initial` (only Ratchets from then on). Kept separate from `encrypt_next` so the
    /// caller can put a durable save between them (see `encrypt_next`).
    ///
    /// Routes with LIVE session state (`sessions[peer_ik]` as it is right now) — correct here
    /// because this is the immediate `send()` path: `encrypt_next` and this call are
    /// synchronous and back-to-back, so nothing can have swapped the session in between. A
    /// QUEUED envelope flushed later needs the routing it was encrypted under instead — see
    /// [`Peer::transmit_envelope_routed`], which this delegates to with no override.
    pub fn transmit_envelope(&mut self, peer_ik: &[u8; 32], envelope: SessionEnvelope, now: u64) -> Response {
        self.transmit_envelope_routed(peer_ik, envelope, None, now)
    }

    /// As [`Peer::transmit_envelope`], but for a QUEUED (already-encrypted) envelope: `routing`
    /// carries the `(drop_seed, peer_mailbox_pub)` snapshot taken at `queue` time. Without it,
    /// a `Ratchet` envelope flushed after its own peer's `sessions[peer_ik]` entry was SWAPPED
    /// by `converge_split_session` would be routed by the NEW (winning) session's box address
    /// instead of the one it was actually encrypted for — silently stranding it (A6-1). `None`
    /// falls back to whatever `sessions[peer_ik]` holds right now, for the immediate-send path.
    /// Wrap a `Ratchet` envelope in this relay's veil (PRIV-4). Openers and already-veiled
    /// envelopes pass through unchanged.
    ///
    /// **Openers are NOT veiled, and this is a named limit rather than an oversight.** The veil key
    /// is the session's `drop_seed`; a recipient meeting a stranger has no session yet, so it could
    /// not derive one. An opener that reaches two relays is therefore still byte-identical there.
    /// Closing it would mean re-sealing the key agreement per relay — the `SkeletonSeal` has fresh
    /// randomness, so that would work — but `pending_initial` is cleared as soon as the envelope is
    /// queued (PRIV-3, so a batch carries ONE opener rather than N), so the material is gone by
    /// flush time. Retaining it to un-do that would trade a certain waste for a narrow gain.
    fn veiled_for_this_relay(
        &self,
        peer_ik: &[u8; 32],
        envelope: SessionEnvelope,
        routing: Option<([u8; 32], [u8; 32])>,
    ) -> Result<SessionEnvelope, String> {
        let msg = match envelope {
            SessionEnvelope::Ratchet(m) => m,
            // An opener carries no session the recipient could derive a key from; a `Veiled` here
            // would mean this ran twice.
            other => return Ok(other),
        };
        let drop_seed = match routing {
            Some((seed, _)) => seed,
            None => self
                .sessions
                .get(peer_ik)
                .map(|st| st.drop_seed)
                .ok_or("no session (call connect first)")?,
        };
        let inner = postcard::to_stdvec(&SessionEnvelope::Ratchet(msg))
            .map_err(|e| format!("encode envelope: {e}"))?;
        let (nonce, veiled) =
            karst_crypto::veil::veil(&drop_seed, &self.relay_id(), &inner).ok_or_else(|| {
                "envelope too long to veil — this is a bug, not a wire condition".to_string()
            })?;
        Ok(SessionEnvelope::Veiled { nonce, inner: veiled })
    }

    fn transmit_envelope_routed(
        &mut self,
        peer_ik: &[u8; 32],
        envelope: SessionEnvelope,
        routing: Option<([u8; 32], [u8; 32])>,
        now: u64,
    ) -> Response {
        let (recipient, handle) = match self.route_for(peer_ik, &envelope, routing, now) {
            Ok(r) => r,
            Err(e) => return Response::Rejected(e),
        };
        // PRIV-4: re-randomise for THIS relay, here rather than at encrypt time — the whole point is
        // that a queued envelope retransmitted to a second relay does not arrive byte-identical, and
        // "this relay" is only known at transmit. The routing snapshot's `drop_seed` is the key, so
        // the veil follows the same session the address does (A6-1), including after a convergence
        // swap.
        let envelope = match self.veiled_for_this_relay(peer_ik, envelope, routing) {
            Ok(e) => e,
            Err(e) => return Response::Rejected(e),
        };
        let resp = self.transmit(recipient, handle, envelope, now);
        if matches!(resp, Response::Accepted) {
            if let Some(st) = self.sessions.get_mut(peer_ik) {
                st.pending_initial = None;
            }
        }
        resp
    }

    /// Encrypt the next message (advances the ratchet UNCONDITIONALLY) and durably QUEUE its
    /// exact ciphertext for delivery, returning its outbox id. The caller MUST persist the
    /// state (`export_state`) before the message can reach the wire: the ratchet advance and
    /// the queued ciphertext then commit in one write, so a crash cannot leave position N
    /// consumed with its ciphertext lost — the retransmit gap this closes. Delivery (and
    /// retry after a transport failure) is [`Peer::flush_outbox`].
    pub fn queue(&mut self, peer_ik: &[u8; 32], plaintext: &[u8], now: u64) -> Result<u64, String> {
        // Snapshot THIS session's routing BEFORE encrypting — see `OutboxEntry`'s doc for why
        // flush must not re-derive this from `sessions[peer_ik]` later (a convergence swap may
        // have relocated it by then). Looked up first, not after `encrypt_next`, so a missing
        // session surfaces as the SAME ordinary `Err` `encrypt_next` would give — never a
        // panic on our own dispatch (a session cannot legitimately disappear between these two
        // lines: nothing else runs in between).
        let (drop_seed, peer_mailbox_pub) = self
            .sessions
            .get(peer_ik)
            .map(|st| (st.drop_seed, st.peer_mailbox_pub))
            .ok_or("no session (call connect first)")?;
        let envelope = self.encrypt_next(peer_ik, plaintext)?;
        // **ONE opener per batch, not one per payload.** `pending_initial` normally clears when a
        // transmit is ACCEPTED — right for the immediate-send path, where encrypt and transmit are
        // back to back. A batch (`send_session_batch`) encrypts EVERY payload first and flushes
        // afterwards, so nothing was accepted yet and every envelope in the batch came out as an
        // opener, each carrying its own full copy of the key agreement. For a six-part avatar that
        // is five redundant copies — and after PRIV-3 added the outer ML-KEM ciphertext it is
        // ~3.4 KB of waste apiece, enough to overflow the fixed fetch page and split a transfer
        // that used to arrive in one poll. It fit before by about 96 bytes, which is not a margin,
        // it is a coincidence.
        //
        // Clearing it HERE is safe precisely because the envelope above is already built: this only
        // affects what LATER payloads encrypt to, never what is already queued. The opener sits at
        // the front of a FIFO outbox that retransmits exactly, so the recipient still sees it
        // first, and a flush that fails leaves the remainder queued behind it.
        if let Some(st) = self.sessions.get_mut(peer_ik) {
            st.pending_initial = None;
        }
        let id = self.outbox_next_id;
        self.outbox_next_id = self.outbox_next_id.wrapping_add(1);
        self.outbox.push(OutboxEntry {
            id,
            peer_ik: *peer_ik,
            envelope,
            queued_at: now,
            drop_seed,
            peer_mailbox_pub,
        });
        // Bound the queue against a permanently-unreachable relay: drop the oldest beyond the
        // cap (least likely still decryptable, see the DH-step bound below).
        while self.outbox.len() > MAX_OUTBOX {
            self.outbox.remove(0);
        }
        Ok(id)
    }

    /// Attempt to deliver every queued message to a relay, in FIFO (position) order, removing
    /// each the relay ACCEPTS (deposited) and each expired past `OUTBOX_TTL_SECS`. An entry
    /// the relay could not accept (unreachable / rejected) stays queued for the next flush —
    /// this is the EXACT retransmit of the same ciphertext, never a re-encrypt of position N.
    /// Best-effort; returns the ids delivered this pass. The caller persists afterwards so the
    /// removals are durable.
    ///
    /// **Deliverability bound.** The relay accepting a deposit is not the recipient decrypting
    /// it — the relay never reads the payload. A retransmit is decryptable only within the
    /// recipient's skipped-key window; once the recipient DH-ratchets past the queued position
    /// (and the message key is evicted, `MAX_STORE`), the deposit still "succeeds" at the relay
    /// but the recipient drops it (the transactional decrypt fails closed). The sender cannot
    /// detect that, so a too-delayed retransmit is bounded by TTL, not by proof of delivery.
    /// The opener is the robust sub-case: it is position 0 of the first sending chain and the
    /// recipient cannot have stepped before receiving it, so it is always in-window until they
    /// first reply.
    pub fn flush_outbox(&mut self, now: u64) -> Vec<u64> {
        let mut delivered = Vec::new();
        for entry in std::mem::take(&mut self.outbox) {
            if now.saturating_sub(entry.queued_at) > OUTBOX_TTL_SECS {
                continue; // expired: drop (the recipient's mailbox would be gone anyway)
            }
            // Route with the SNAPSHOT taken at queue time, not whatever `sessions[peer_ik]`
            // holds now — see `OutboxEntry`'s doc (A6-1 convergence can have swapped it since).
            let routing = Some((entry.drop_seed, entry.peer_mailbox_pub));
            match self.transmit_envelope_routed(&entry.peer_ik, entry.envelope.clone(), routing, now) {
                Response::Accepted => delivered.push(entry.id),
                _ => self.outbox.push(entry), // keep for retry — identical bytes next time
            }
        }
        delivered
    }

    /// Whether a queued message (by the id `queue` returned) is still awaiting delivery.
    /// After a `flush_outbox`, `false` means the relay accepted it (or it expired).
    pub fn is_queued(&self, id: u64) -> bool {
        self.outbox.iter().any(|e| e.id == id)
    }

    /// How many messages are queued awaiting delivery (for tests / a UI "pending" count).
    pub fn outbox_len(&self) -> usize {
        self.outbox.len()
    }

    /// The queued envelopes, for asserting their SHAPE (test-only).
    ///
    /// Exists for one property: a batch must not repeat the key agreement. Counting openers is the
    /// only way to see that from outside, and the alternative — inferring it from delivered byte
    /// counts — is what let the waste go unnoticed until it crossed a page boundary.
    #[doc(hidden)]
    pub fn outbox_envelopes_for_test(&self) -> Vec<SessionEnvelope> {
        self.outbox.iter().map(|e| e.envelope.clone()).collect()
    }

    /// Assemble the WireMessage and take it through admission with a cookie refresh. The same
    /// envelope is reused on the retry (a cookie challenge does NOT re-encrypt).
    /// This peer's own loop box for `epoch` — where cover traffic is deposited and read
    /// back. Derived from the identity SECRET, so only we can compute it.
    fn loop_box(&self, epoch: u64) -> Identity {
        let seed = crate::drop::loop_seed(&self.account.ik().to_secret_bytes());
        // A loop is to SELF, so both legs share one box on purpose — a fixed direction.
        crate::drop::drop_identity(&seed, epoch, 0)
    }

    /// Send one loop: a cover message to ourselves (§2.2 / Loopix).
    ///
    /// The relay is asked "is this user writing to anyone right now?" on every deposit,
    /// and silence is an answer. A client that deposits only when its user types has a
    /// shape; one that also deposits on its own schedule does not. The loop comes back to
    /// us, so nobody's mailbox is spent but ours, and a loop that never returns is
    /// evidence the relay is dropping mail — the one integrity signal a store-and-forward
    /// design gets for free.
    ///
    /// The payload is a well-formed `Ratchet` envelope of random bytes. It has to be
    /// well-formed because the relay parses far enough to size it; it decrypts for nobody,
    /// including us — trial-decryption fails and yields `None`, disturbing no session,
    /// because `decrypt` is transactional.
    ///
    /// **Scope, and it is narrower than it looks.** See `receive_loops` for the residual:
    /// against the relay itself this is only cover when the two legs ride independent
    /// paths.
    pub fn send_loop(&mut self, now: u64) -> Response {
        let epoch = self.local_epoch(now);
        let recipient = self.loop_box(epoch).public.to_bytes();
        // EXACTLY the length a real padded message has (`crate::pad`), because "the same size
        // class" is now a literal statement rather than an approximation. It used to be a fixed 96
        // bytes chosen to resemble a short text, and the honest note here said the E2E layer does
        // not pad, so real messages vary and a relay comparing size DISTRIBUTIONS separates the
        // populations anyway. Padding real traffic fixed that — and made this line the last
        // remaining size tell: a 96-byte envelope among uniformly-sized ones would have labelled
        // every loop for the relay, which is worse than sending none. Cover only works while it is
        // arithmetically indistinguishable, so this length is derived from the same constant rather
        // than written down beside it.
        let msg = karst_crypto::ratchet::RatchetMessage {
            header: karst_crypto::ratchet::Header { dh: random32(), pn: 0, n: 0, salt: [7u8; 16] },
            ciphertext: {
                let mut c = vec![0u8; crate::pad::PADDED_LEN + 16];
                use chacha20poly1305::aead::rand_core::RngCore;
                chacha20poly1305::aead::OsRng.fill_bytes(&mut c);
                c
            },
        };
        self.transmit(recipient, Handle::LoopSend(epoch), SessionEnvelope::Ratchet(msg), now)
    }

    /// Drain our loop boxes, returning how many loops came back.
    ///
    /// **What this does NOT buy, and it is most of it.** The relay terminates our TCP, so
    /// it reads the source IP on both legs. A real message's box sees a deposit from us
    /// and a fetch from our CONTACT — two addresses. A loop's box sees both legs from
    /// ours. That distinguisher survives the per-epoch handles entirely, and it breaks
    /// both things loops are for: the relay can subtract loops from our volume, and —
    /// worse — a relay that can tell loops from real mail can drop the real mail while
    /// faithfully returning the loops, so the drop detector reports all-clear while
    /// messages vanish. A detector that lies on demand is worse than none.
    ///
    /// Both benefits are therefore CONDITIONAL on the two legs riding independent paths
    /// (§15 isolation — a distinct circuit per handle) so the addresses differ. Against an
    /// external observer that cannot map boxes to legs, loops work as advertised today.
    pub fn receive_loops(&mut self, now: u64) -> usize {
        let mut got = 0;
        for epoch in crate::drop::poll_epochs(now) {
            // The loop box is a SELF-box (an X25519 identity from `loop_seed`), so it keeps the DH
            // ownership proof — I hold its secret directly, no session blinding involved.
            let id = self.loop_box(epoch);
            if let Ok(payloads) = self.fetch_mailbox(BoxAuth::Identity(id), Handle::LoopRecv(epoch), now) {
                got += payloads.len();
            }
        }
        got
    }

    /// Where an envelope goes, and under which handle.
    ///
    /// An opener has nowhere to go but the recipient's identity mailbox: the recipient
    /// has no session yet, so it cannot derive a drop-box, and a stranger's first knock
    /// needs one stable address to arrive at. That is the honest residual of this slice
    /// — everything AFTER the first message rotates.
    /// `routing`, if given, OVERRIDES the live `sessions[peer_ik]` lookup for a `Ratchet`
    /// envelope — the snapshot a queued entry was encrypted under (see
    /// [`Peer::transmit_envelope_routed`]). `None` uses the CURRENT session, correct only when
    /// nothing could have mutated it since encryption (the immediate-send path).
    fn route_for(
        &mut self,
        peer_ik: &[u8; 32],
        envelope: &SessionEnvelope,
        routing: Option<([u8; 32], [u8; 32])>,
        now: u64,
    ) -> Result<([u8; 32], Handle), String> {
        match envelope {
            SessionEnvelope::InitialSealed { .. } => {
                Ok((*peer_ik, Handle::Opener(*peer_ik)))
            }
            // Cannot happen by construction: the veil is applied AFTER routing, because it needs to
            // know which relay this transmit is for. Loud rather than routed on a guess — a veiled
            // envelope here means the ordering was changed, and guessing a route would strand mail.
            SessionEnvelope::Veiled { .. } => {
                Err("internal: a veiled envelope reached routing; the veil is applied after it".into())
            }
            SessionEnvelope::Ratchet(_) => {
                let (drop_seed, peer_mailbox_pub) = match routing {
                    Some(r) => r,
                    None => {
                        let st = self.sessions.get(peer_ik).ok_or("no session (call connect first)")?;
                        (st.drop_seed, st.peer_mailbox_pub)
                    }
                };
                let epoch = self.local_epoch(now);
                // Deposit into the OUTBOUND box (me → peer): the peer's mailbox point blinded for
                // this session/epoch. The peer fetches the same address with its own fetch secret;
                // I never hold that secret, so depositing does not let me read the box.
                let dir = crate::drop::direction(&self.identity(), peer_ik);
                // Fail LOUD on a session that predates blinded mailboxes: its `peer_mailbox_pub` is
                // the serde default `[0;32]`, which is the VALID Ristretto identity — so
                // `deposit_address` would return `Some(identity)` and silently deposit into a box
                // no one fetches (a real `M = m·G` is a hash-derived scalar times the basepoint,
                // never the identity, so this never false-rejects a live session).
                if peer_mailbox_pub == [0u8; 32] {
                    return Err("session predates blinded mailboxes — re-establish it (connect anew)".into());
                }
                // The relay-id is THIS peer's relay (PRIV-12), which is exactly right on failover:
                // a `Peer` is built per relay, so a queued envelope flushed through a secondary
                // derives that secondary's address rather than the primary's — and the recipient,
                // whose own `Peer` per relay does the same, still finds it.
                let address = karst_crypto::blind::deposit_address(
                    &peer_mailbox_pub,
                    &drop_seed,
                    epoch,
                    dir,
                    &self.relay_id(),
                )
                    .ok_or("peer mailbox point is not a valid curve point")?;
                Ok((address, Handle::Box(*peer_ik, epoch)))
            }
        }
    }

    fn transmit(
        &mut self,
        recipient: [u8; 32],
        handle: Handle,
        envelope: SessionEnvelope,
        now: u64,
    ) -> Response {
        // Random nonce: it must be globally unique across peers sharing the dev-cap
        // (else two peers' req-N would collide in the replay filter). It used to be
        // `IK ‖ counter`, which bought that uniqueness by putting the sender's identity
        // — and a per-identity message count — on the wire for the relay to read. 32
        // random bytes give the same uniqueness and name nobody. Nothing parses the
        // nonce (the capability MAC hashes it whole; the replay filter stores it whole).
        let nonce = random32().to_vec();
        self.nonce_ctr += 1;
        let proof = self.capability.prove(&nonce, 0);
        let client_addr = self.handle(handle.clone());
        let scope = self.scope_for(&handle);
        let rid = self.relay_id();

        let mut msg = WireMessage {
            // A per-purpose handle, NOT the IK: this field sits next to `recipient`, so
            // the IK here is exactly what let the relay read the social graph off the
            // wire — and a handle stable across epochs would relink the drop-boxes.
            client_addr: client_addr.clone(),
            carrier_id: self.carrier_id.clone(),
            cookie: self.cookies.get(&(rid, client_addr.clone())).copied(),
            request_nonce: nonce,
            capability_proof: proof,
            recipient,
            payload: Payload::Session(envelope),
        };

        for _ in 0..2 {
            match self.transport.send_isolated(&msg, now, scope.as_deref()) {
                Response::NeedCookie(c) => {
                    self.cookies.insert((rid, client_addr.clone()), c);
                    msg.cookie = Some(c);
                    continue;
                }
                other => return other,
            }
        }
        Response::Rejected("persistent cookie challenge".into())
    }

    /// Collect incoming mail: fetch-auth plus session advancement. `Ok(vec)` has one element per
    /// envelope (`None` = did not decrypt / not ours; `Some(Received)` carries the sender);
    /// `Err` is a transport or auth failure.
    /// Collect incoming mail: fetch-auth + session advance.
    ///
    /// Polls the identity mailbox (where a stranger's opener lands) plus every live
    /// session's drop-boxes for the epochs still in flight — each under its own handle,
    /// so the relay cannot join them.
    ///
    /// **Cost.** A cycle costs one fetch per box, i.e. `3 × sessions + 1` round trips.
    /// This is bandwidth and latency, NOT quota: `RelayNode::handle_fetch` charges no
    /// capability quota (cookie + ownership proof only — deposits are the metered path).
    /// Correctness is not negotiable here regardless: dropping the neighbouring epochs to
    /// save round trips would silently strand mail across a rollover. If the count ever
    /// binds, the fix is a batched multi-mailbox fetch — but note that batching every box
    /// under ONE `client_addr` would relink them and undo the slice.
    pub fn receive(&mut self, now: u64) -> Result<Vec<Option<Received>>, String> {
        self.receive_with(now, &Sequential)
    }

    /// `receive`, with the box-fetch phase run by `fetcher`.
    ///
    /// [`Sequential`] is what `receive` uses. [`Parallel`] fans the boxes out, and can only be
    /// constructed from a [`DirectCarrier`] witness — see its documentation for why concurrency is
    /// a proxy-relevant decision rather than a pure performance knob.
    pub fn receive_with<F: BoxFetcher<T>>(
        &mut self,
        now: u64,
        fetcher: &F,
    ) -> Result<Vec<Option<Received>>, String> {
        // Monotonic, and deliberately not `now`: the budget measures how long WE have been in this
        // call, which a wall clock that jumps (or a caller passing a fixed test clock) cannot say.
        let started = Instant::now();
        self.prune_handles(now);
        // A6-1: converge any split held from BEFORE this cycle — state `import_state`d from an
        // older build, or from a peer this side hasn't polled since the other half landed.
        // `process_opener` already converges a split the MOMENT it forms; this sweep is the
        // same idempotent check for one that formed some OTHER way (only `inbound_sessions`
        // can ever hold a split half — `inbound implies outbound`, see its field doc — so this
        // is bounded by the number of peers actually split, not by session count generally).
        let split_peers: Vec<[u8; 32]> = self.inbound_sessions.keys().copied().collect();
        for peer_ik in split_peers {
            self.converge_split_session(&peer_ik);
        }
        let mut out = Vec::new();

        // The identity mailbox: openers from strangers. It names us — the DH ownership
        // proof is against our own IK — which is exactly why it gets a handle of its
        // own and never shares one with a drop-box.
        let ik = self.account.ik().clone();
        let payloads = self.fetch_mailbox(BoxAuth::Identity(ik), Handle::Identity, now)?;
        for p in &payloads {
            // SEC-33: a `Ratchet` envelope is NEVER legitimately deposited here — `route_for`
            // sends `Ratchet` only to the recipient's OWN blinded per-session box
            // (`Handle::Box`), never to the identity mailbox. So a `Ratchet`-shaped payload
            // landing on this PUBLIC, session-less address is always either garbage or an
            // attacker probe; skip it WITHOUT touching a single session, rather than paying
            // `process_ratchet`'s full sweep (bounded by `MAX_SESSIONS`, but still real DH-
            // ratchet-step cost per session — measured at seconds of CPU for one message) for a
            // payload that could never be legitimate.
            if matches!(p, Payload::Session(SessionEnvelope::Ratchet(_))) {
                out.push(None);
                continue;
            }
            out.push(self.process(p).map(|mut r| { r.msg_id = payload_id(p); r }));
        }

        // The hot window every cycle; the complete one on a slow schedule. Sweeping every
        // cycle would multiply fetch cost by TTL_EPOCHS for mail that is old by
        // definition; never sweeping loses that mail outright.
        let sweep_due = now.saturating_sub(self.last_sweep) >= crate::drop::SWEEP_INTERVAL_SECS;
        // Read BEFORE `last_sweep` is stamped below, or the deep-sweep test compares now with now.
        let previous_sweep = self.last_sweep;
        let window: Vec<u64> = if sweep_due {
            self.last_sweep = now;
            crate::drop::sweep_epochs(now)
        } else {
            crate::drop::poll_epochs(now).to_vec()
        };
        // #147: drop the epochs the cursor has already closed. A sender deposits into ITS OWN
        // epoch, and a sender whose clock agrees with ours to within `FUTURE_SLACK_EPOCHS` cannot
        // reach a box below the cursor — fetching it is a round trip guaranteed to come back
        // empty, multiplied by every session in the table.
        //
        // **The assumption that buys this, and the DEEP SWEEP that covers it.** The cursor is only
        // sound while sender clocks are close to ours. A sender whose clock is several days SLOW
        // deposits into a past epoch, and would land below the cursor — mail that then rots at an
        // address nobody asks for again, which is precisely the silent loss `sweep_epochs` was
        // built to prevent. (The offline-recipient case is safe by construction: no sweep runs
        // while offline, so the cursor does not move past the epochs the mail arrived in.)
        //
        // So the cursor is IGNORED once per epoch — the first sweep of each new day walks the full
        // window regardless. That keeps the full `TTL_EPOCHS` tolerance for a badly-skewed sender
        // while still removing ~99% of the repeated fetches: with a ten-minute sweep interval it is
        // one full walk per day instead of one every ten minutes.
        //
        // Derived from `last_sweep`, which is already persisted, rather than a second timestamp:
        // one more piece of at-rest state for a once-a-day decision is not worth the format churn.
        let deep = crate::drop::epoch_of(now) > crate::drop::epoch_of(previous_sweep);
        let epochs: Vec<u64> = if deep {
            window
        } else {
            window.into_iter().filter(|e| *e > self.swept_through).collect()
        };
        // What the cursor WOULD become if this pass completes cleanly. Computed before the fetches
        // so a clock that moves during the pass cannot advance it further than the window we
        // actually walked.
        let closable = crate::drop::epoch_of(now)
            .saturating_sub(crate::drop::FUTURE_SLACK_EPOCHS)
            .saturating_sub(1);
        let me = self.identity();

        // Every session's INBOUND box, as a BLINDED drop-box: its address is my own mailbox point
        // blinded for this session/epoch (`deposit_address(M_me, drop_seed, epoch, dir)`) — the
        // same address the peer deposited into — and I hold the matching fetch secret to prove
        // ownership. Collected first: `fetch_mailbox` borrows self mutably.
        let own_m = self.account.mailbox_public();
        let account = self.account.clone();
        // Captured for the closure below: every box address is now relay-specific (PRIV-12), and
        // this pass belongs to ONE relay.
        let relay_id = self.relay_id();
        // The `[u8; 32]` alongside each entry is the box's OWNING peer — carried explicitly
        // rather than re-derived from `Handle` after the fact (SEC-33's `process_for_peer`
        // needs it, and a `match` that assumes only `Handle::Box` ever reaches here would have
        // to panic on any other variant; carrying the value we already have here instead means
        // there is nothing to panic on, ever, even if `Handle` grows a new variant later — loud
        // failure belongs on attacker input, never on our own dispatch).
        let boxes: Vec<(BoxAuth, Handle, [u8; 32])> = self
            .sessions
            .iter()
            // Also collect the peer-INITIATED (responder) sessions' inbound boxes: on a
            // simultaneous first contact the peer's stream arrives on `inbound_sessions[ik]`,
            // whose drop_seed differs from our outbound one, so it is a DISTINCT box address.
            .chain(self.inbound_sessions.iter())
            .flat_map(|(peer_ik, st)| {
                // The INBOUND box (peer → me) — the opposite direction to what I deposit into, so
                // I collect the peer's mail, never my own outbound.
                let dir = crate::drop::direction(peer_ik, &me);
                epochs
                    .iter()
                    .filter_map(|e| {
                        let address = karst_crypto::blind::deposit_address(
                            &own_m, &st.drop_seed, *e, dir, &relay_id,
                        )?;
                        let fetch_secret =
                            account.mailbox_fetch_secret(&st.drop_seed, *e, dir, &relay_id);
                        Some((BoxAuth::DropBox { address, fetch_secret }, Handle::Box(*peer_ik, *e), *peer_ik))
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let mut box_err: Option<String> = None;
        let mut skipped = 0usize;
        let total_boxes = boxes.len();
        // Walked in chunks so the time budget still means something: with a fan-out the whole pass
        // would otherwise be dispatched before the first elapsed-check, and R2-12's bound would
        // apply to nothing. One chunk is at most `MAX_FETCH_WIDTH` boxes in flight.
        for chunk in boxes.chunks(MAX_FETCH_WIDTH) {
            // R2-12: stop once this pass has spent its budget (see `RECEIVE_BUDGET`). Checked
            // BEFORE dispatch, not after, so the budget bounds when the last request STARTS —
            // requests already in flight still run to their own timeout, which is the tightest
            // bound available without cancelling a socket mid-flight.
            if started.elapsed() >= self.receive_budget {
                skipped += chunk.len();
                continue;
            }
            // Phase 1 for the whole chunk (needs `&mut self`), then one transport phase, then
            // phase 3 in BOX ORDER — never completion order, because `pending_ack` evicts its
            // oldest entry at the cap and `out` is what the caller sees.
            let mut pending: Vec<(usize, PreparedFetch)> = chunk
                .iter()
                .enumerate()
                .map(|(i, (auth, handle, _))| (i, self.prepare_fetch(auth, handle)))
                .collect();
            let mut done: Vec<Option<Result<Vec<Payload>, String>>> = vec![None; chunk.len()];
            // At most two rounds, exactly as one sequential fetch had: a `NeedCookie` banks the
            // cookie and the SAME box is asked once more. Anything still unanswered after that is
            // the terminal "persistent cookie challenge".
            for round in 0..2 {
                if pending.is_empty() {
                    break;
                }
                let reqs: Vec<PreparedFetch> = pending.iter().map(|(_, p)| p.clone()).collect();
                let responses = fetcher.run(&self.transport, &reqs, now);
                let mut retry: Vec<(usize, PreparedFetch)> = Vec::new();
                for ((i, prepared), resp) in pending.into_iter().zip(responses) {
                    let (auth, handle, _) = &chunk[i];
                    match self.absorb_fetch(auth, &prepared, resp) {
                        Absorbed::Fetched(payloads) => done[i] = Some(Ok(payloads)),
                        Absorbed::Rejected(r) => done[i] = Some(Err(r)),
                        Absorbed::Retry => {
                            if round == 0 {
                                retry.push((i, self.prepare_fetch(auth, handle)));
                            } else {
                                done[i] = Some(Err("persistent cookie challenge".into()));
                            }
                        }
                    }
                }
                pending = retry;
            }
            for (i, (_, _, owner)) in chunk.iter().enumerate() {
                match done[i].take() {
                    Some(Ok(payloads)) => {
                        for p in &payloads {
                            out.push(self.process_for_peer(owner, p).map(|mut r| { r.msg_id = payload_id(p); r }));
                        }
                    }
                    Some(Err(e)) => box_err = Some(e),
                    // Not dispatched and not absorbed: count it as unread, so the cursor below
                    // cannot move past a box nobody looked at.
                    None => skipped += 1,
                }
            }
        }
        // Advance the cursor ONLY on a pass that actually walked every box it meant to. A cursor
        // moved past a box that was never read would lose that box's mail permanently — the one
        // failure mode this must not have — so a box error, a budget truncation, or a
        // non-sweep cycle all leave it where it was.
        if sweep_due && box_err.is_none() && skipped == 0 && closable > self.swept_through {
            self.swept_through = closable;
        }
        if skipped > 0 {
            // Reported through the same channel a failed box uses, and for the same reason: the
            // mail is still on the relay, so this is "not finished", never "nothing there". It
            // only becomes the returned error when this pass collected nothing at all (see the
            // match below) — a truncated pass that DID deliver hands the mail over first.
            box_err = Some(format!(
                "receive budget of {}s exhausted — {skipped} of {total_boxes} boxes not fetched \
                 this cycle; their mail stays on the relay and the next cycle collects it",
                self.receive_budget.as_secs()
            ));
        }

        // A failed box fetch must not discard mail we already drained. A SUCCESSFUL
        // fetch removes the payloads from the relay, so they exist nowhere else once we
        // hold them — returning `Err` now would destroy them. A failed fetch, by
        // contrast, drains nothing: that box's mail is still on the relay and the next
        // cycle collects it. So reporting the error is worth exactly one thing, and we
        // only pay for it when there is nothing to lose: if this cycle delivered
        // nothing, surface the fault; otherwise hand the mail over and let the fault
        // surface on the next empty cycle, which it will if it is real rather than
        // transient.
        match box_err {
            Some(e) if out.is_empty() => Err(e),
            _ => Ok(out),
        }
    }

    /// Fetch one mailbox under one handle. `mailbox` is whatever keypair addresses it —
    /// our identity key, or a derived drop-box — since the relay's ownership check is a
    /// DH against the address itself and does not care which.
    fn fetch_mailbox(
        &mut self,
        auth: BoxAuth,
        handle: Handle,
        now: u64,
    ) -> Result<Vec<Payload>, String> {
        // One box, one round trip at a time — the shape every caller had before the fetch was
        // split into phases. It is now written in terms of that split (`prepare_fetch` →
        // transport → `absorb_fetch`) rather than beside it, so there is exactly one description
        // of how a fetch is built, authorised and remembered. Two implementations of that would
        // drift, and the half that drifts is the one that records ACK receipts — mail nobody
        // deletes, or worse, mail deleted twice.
        for _ in 0..2 {
            let prepared = self.prepare_fetch(&auth, &handle);
            let resp = self.transport.fetch_isolated(&prepared.req, now, prepared.scope.as_deref());
            match self.absorb_fetch(&auth, &prepared, resp) {
                Absorbed::Fetched(payloads) => return Ok(payloads),
                Absorbed::Retry => continue,
                Absorbed::Rejected(r) => return Err(r),
            }
        }
        Err("persistent cookie challenge".into())
    }

    /// Phase 1 of a fetch: everything that needs `&mut self`, and nothing that touches the network.
    ///
    /// Minting the handle and reading the cookie both mutate, so this cannot happen while several
    /// requests are in flight. Doing it for ALL boxes first is what lets the transport phase take
    /// only `&self` — see `fetch_boxes` — and it is why this is a separate function rather than a
    /// block inside the loop.
    fn prepare_fetch(&mut self, auth: &BoxAuth, handle: &Handle) -> PreparedFetch {
        let mailbox = auth.mailbox();
        let client_addr = self.handle(handle.clone());
        let scope = self.scope_for(handle);
        let rid = self.relay_id();
        let cookie = self.cookies.get(&(rid, client_addr.clone())).copied();
        // Ownership proof for THIS cookie: DH for the identity mailbox, Schnorr (bound to the
        // cookie MAC) for a blinded drop-box.
        let (proof, own_proof) = match (&auth, cookie) {
            (BoxAuth::Identity(id), Some(c)) => {
                (fetch_proof(&id.dh(&self.relay_pub), &c.mac, &mailbox), Vec::new())
            }
            (BoxAuth::DropBox { fetch_secret, .. }, Some(c)) => {
                let own = karst_crypto::blind::FetchOwnershipProof::prove(fetch_secret, &mailbox, &c.mac)
                    .map(|p| p.to_bytes().to_vec())
                    .unwrap_or_default();
                ([0u8; 16], own)
            }
            (_, None) => ([0u8; 16], Vec::new()),
        };
        PreparedFetch {
            req: FetchRequest {
                mailbox,
                client_addr: client_addr.clone(),
                carrier_id: self.carrier_id.clone(),
                cookie,
                proof,
                own_proof,
            },
            client_addr,
            scope,
            cookie,
        }
    }

    /// Phase 3 of a fetch: everything that needs `&mut self` again — bank a fresh cookie, or
    /// record what this box leased so it can be acked once the ratchet is durable.
    ///
    /// Takes the response by value and returns what the caller should do next, so the SAME
    /// function serves one sequential fetch and a whole fanned-out batch. Payload decryption is
    /// deliberately NOT here: it belongs to the caller, which knows the box's owning peer.
    fn absorb_fetch(
        &mut self,
        auth: &BoxAuth,
        prepared: &PreparedFetch,
        resp: FetchResponse,
    ) -> Absorbed {
        let rid = self.relay_id();
        match resp {
            FetchResponse::NeedCookie(c) => {
                self.cookies.insert((rid, prepared.client_addr.clone()), c);
                Absorbed::Retry
            }
            FetchResponse::Fetched(payloads) => {
                // Under lease, remember what to delete: the messages stay on the relay
                // until the ACK runs (after the caller persists the ratchet). The
                // receipt captures the cookie that just authorised this fetch, so it can
                // be acked later without the Peer. Empty pages leave nothing to ACK.
                // ALWAYS record a receipt (#179 follow-up). This used to be gated on an
                // `enable_ack` flag, which made sense while the flag ALSO selected the
                // relay's behaviour: a non-lease fetch destroyed its messages, so there was
                // nothing to remember. Now every fetch leases, so a receive that records
                // nothing leaves mail sitting on the relay with no receipt anywhere — it
                // redelivers when the lease lapses, silently, and no caller can choose to
                // clean it up. Recording costs a Vec entry; the real control is `ack_all`,
                // which the caller still only runs once the ratchet is durable.
                if !payloads.is_empty() {
                    // The later ACK re-proves ownership: DH needs `shared`, a drop-box needs
                    // its fetch secret.
                    let (shared, own_fetch_secret) = match auth {
                        BoxAuth::Identity(id) => (id.dh(&self.relay_pub), None),
                        BoxAuth::DropBox { fetch_secret, .. } => ([0u8; 32], Some(*fetch_secret)),
                    };
                    // A caller that never runs `ack_all` (a probe, a test, an aborted
                    // receive) must not grow this without bound. Dropping the OLDEST
                    // receipt is the safe direction: that mail stays on the relay and
                    // redelivers when its lease lapses, exactly as if the ACK had failed.
                    if self.pending_ack.len() >= MAX_PENDING_ACKS {
                        self.pending_ack.remove(0);
                    }
                    self.pending_ack.push(AckReceipt {
                        mailbox: prepared.req.mailbox,
                        client_addr: prepared.client_addr.clone(),
                        carrier_id: self.carrier_id.clone(),
                        shared,
                        cookie: prepared.cookie,
                        scope: prepared.scope.clone(),
                        ids: payloads.iter().map(payload_id).collect(),
                        own_fetch_secret,
                    });
                }
                Absorbed::Fetched(payloads)
            }
            FetchResponse::Rejected(r) => Absorbed::Rejected(r),
        }
    }

    /// Delete every message leased during this receive. MUST be called only AFTER the
    /// advanced ratchet state is durably saved: an ACK tells the relay to forget the
    /// ciphertext, so acking before the ratchet is on disk would reopen the at-most-once
    /// window this whole path closes.
    ///
    /// Best-effort by design: a failed ACK is not an error the caller must handle. The
    /// message simply stays on the relay and redelivers when its lease expires; the
    /// ratchet then fails closed on the duplicate (already-consumed message key ⇒ AEAD
    /// fail, no state mutation), so at worst prompt deletion is delayed, never correctness.
    /// A `NeedCookie` refreshes the cookie and retries once (see [`send_ack`]).
    pub fn ack_all(&mut self, now: u64) {
        for receipt in std::mem::take(&mut self.pending_ack) {
            send_ack(&self.transport, &receipt, now);
        }
    }

    /// Take the leased-this-receive ACK receipts OUT of the peer, so a caller that saves
    /// once for a whole SET of relays (multi-homed receive) can ack them AFTER the save,
    /// each through its own relay's transport via [`send_ack`]. A receipt must only be
    /// acked if this peer's `receive` returned `Ok` — a failed relay's state advance is
    /// rolled back, so acking would delete a message that was never durably received.
    pub fn take_pending_acks(&mut self) -> Vec<AckReceipt> {
        std::mem::take(&mut self.pending_ack)
    }

    /// Take (reset to 0) the count of brand-new strangers' first-contact attempts refused
    /// since the last call because `sessions` was at `MAX_SESSIONS` capacity — SEC-33's LOUD
    /// counterpart to the silent `None` those attempts otherwise return from `receive`. A
    /// caller (CLI/GUI) can poll this after every receive and surface a warning ("N connection
    /// attempts refused: too many open conversations") instead of a flood of strangers vanishing
    /// with no trace whatsoever.
    pub fn take_refused_sessions(&mut self) -> u64 {
        std::mem::take(&mut self.sessions_refused)
    }

    /// SEC-33: handle a payload known to have arrived at ONE SPECIFIC peer's own inbound
    /// drop-box (`Handle::Box(peer_ik, _)`) — never the identity mailbox. `route_for` only
    /// ever deposits a `Ratchet` envelope at the recipient's blinded PER-SESSION box, whose
    /// address is MY mailbox point blinded by THAT peer's own `drop_seed` (see `receive`) —
    /// an independently-derived value nobody else's session shares. So anything landing in
    /// this specific box could only ever belong to `peer_ik`'s session(s); trying every OTHER
    /// session held (`process_ratchet`'s generic sweep) buys nothing legitimate and IS the
    /// per-message cost SEC-33 multiplies by session count. This path stays O(1) regardless
    /// of how many sessions are held — which is what ordinary, ongoing conversation traffic
    /// actually needs; `process`/`process_ratchet` remain the fallback for payloads whose
    /// owning session genuinely isn't known ahead of time (the identity mailbox).
    fn process_for_peer(&mut self, peer_ik: &[u8; 32], payload: &Payload) -> Option<Received> {
        // PRIV-4: unveil first, then handle the envelope exactly as before. The key is this peer's
        // `drop_seed` — the same value that produced the box this arrived in, so a message that
        // reached the right box always has the right key. Both maps are tried because a peer's
        // stream can ride `inbound_sessions` after a simultaneous first contact.
        if let Payload::Session(SessionEnvelope::Veiled { nonce, inner }) = payload {
            let seeds: Vec<[u8; 32]> = self
                .sessions
                .get(peer_ik)
                .map(|st| st.drop_seed)
                .into_iter()
                .chain(self.inbound_sessions.get(peer_ik).map(|st| st.drop_seed))
                .collect();
            for seed in seeds {
                let Some(bytes) = karst_crypto::veil::unveil(&seed, nonce, inner) else { continue };
                let Ok(env) = postcard::from_bytes::<SessionEnvelope>(&bytes) else { continue };
                // Only a `Ratchet` is ever veiled; anything else means a peer sent a shape our own
                // encoder cannot produce, which is a miss rather than something to reinterpret.
                if matches!(env, SessionEnvelope::Ratchet(_)) {
                    return self.process_for_peer(peer_ik, &Payload::Session(env));
                }
            }
            return None;
        }
        match payload {
            Payload::Session(SessionEnvelope::Ratchet(msg)) => {
                if let Some(st) = self.sessions.get_mut(peer_ik) {
                    self.decrypt_attempts_for_test += 1;
                    if let Some(pt) = Self::open_padded(&mut st.session, msg) {
                        return Some(Received { sender: *peer_ik, plaintext: pt, msg_id: [0u8; 32] });
                    }
                }
                if let Some(st) = self.inbound_sessions.get_mut(peer_ik) {
                    self.decrypt_attempts_for_test += 1;
                    if let Some(pt) = Self::open_padded(&mut st.session, msg) {
                        return Some(Received { sender: *peer_ik, plaintext: pt, msg_id: [0u8; 32] });
                    }
                }
                // R2-11, the loud half. This is NOT the "garbage from a stranger" case: the box
                // address is derived from a session's own `drop_seed`, so reaching it means the
                // sender holds that session — and we hold a session with them — and our chain
                // still cannot open the message. The ratchet has been advanced by SOMETHING ELSE
                // holding this identity: a second device on the same recovery phrase, or state
                // restored from a backup while the live copy kept moving.
                //
                // It used to be a silent `None`, which is the worst possible answer, because the
                // symptom the user gets is messages that simply do not arrive — with nothing,
                // anywhere, saying why. KARST cannot MERGE the two states (there is no device
                // identity in `PeerState` to merge along, which is the rest of R2-11), but it can
                // refuse to be quiet about it.
                //
                // Counted rather than logged per message: a diverged channel produces one of these
                // per message, and a log line each would bury the signal in the noise it is made
                // of. The caller surfaces the count.
                if self.sessions.contains_key(peer_ik) || self.inbound_sessions.contains_key(peer_ik)
                {
                    self.out_of_step = self.out_of_step.saturating_add(1);
                }
                None
            }
            // Openers/skeletons never legitimately arrive on a per-session box (`route_for`
            // never sends them there) — handled generically for defense-in-depth; unreachable
            // from the honest client, harmless if it ever isn't.
            _ => self.process(payload),
        }
    }

    /// Process one incoming payload, advancing the corresponding session. Sender attribution: an
    /// Initial carries `sender_ik` in the KA; for a Ratchet the sender is the key of the session
    /// that decrypted it (trial decryption).
    /// `process` for tests: can THIS peer open this payload? Used to assert that a
    /// stranger with real keys gets nothing from a raw slot.
    pub fn open_for_test(&mut self, payload: &Payload) -> Option<Received> {
        self.process(payload)
    }

    fn process(&mut self, payload: &Payload) -> Option<Received> {
        // PRIV-4, the generic path: no box told us whose this is, so every held session's
        // `drop_seed` is a candidate key. Bounded by `MAX_SESSIONS` and cheap (one HKDF each), and
        // it only runs for payloads that arrived WITHOUT a known box — `process_for_peer` handles
        // the ordinary case with one or two candidates.
        if let Payload::Session(SessionEnvelope::Veiled { nonce, inner }) = payload {
            let seeds: Vec<[u8; 32]> = self
                .sessions
                .values()
                .chain(self.inbound_sessions.values())
                .map(|st| st.drop_seed)
                .collect();
            for seed in seeds {
                let Some(bytes) = karst_crypto::veil::unveil(&seed, nonce, inner) else { continue };
                let Ok(env) = postcard::from_bytes::<SessionEnvelope>(&bytes) else { continue };
                if matches!(env, SessionEnvelope::Ratchet(_)) {
                    if let Some(r) = self.process(&Payload::Session(env)) {
                        return Some(r);
                    }
                }
            }
            return None;
        }
        match payload {
            // Handled by the block above; an arm is still required for exhaustiveness. `None`
            // rather than a panic: nothing about our own dispatch should be able to abort the
            // process, and a miss here is the same "not for us" the rest of this function returns.
            Payload::Session(SessionEnvelope::Veiled { .. }) => None,
            // This envelope is not addressed to this session peer.
            Payload::Skeleton(_) => None,
            // A sealed opener: unwrap it with our OWN identity key — which works without
            // knowing who sent it, and is exactly why the relay could not read it — then
            // handle the KeyAgreement as usual. Sender authentication is unchanged: it
            // comes from the inner PQXDH, never from the outer box.
            Payload::Session(SessionEnvelope::InitialSealed { sealed_ka, msg }) => {
                let plain = sealed_ka.open(self.account.ik(), self.account.kem_dk_ref())?;
                let ka: KeyAgreement = postcard::from_bytes(&plain).ok()?;
                self.process_opener(&ka, msg)
            }
            // An UNSEALED opener is REFUSED. It carries the sender's identity key in the clear,
            // so the relay can read the social-graph edge straight off it — the exact leak
            // `InitialSealed` exists to close. The variant was kept only so an in-flight capsule
            // from an older client would still open; there are no older clients, and accepting it
            // let any peer silently downgrade a conversation's metadata privacy by sending the
            // legacy form. We only ever SEND sealed, so nothing legitimate produces this.
            Payload::Session(SessionEnvelope::Ratchet(msg)) => self.process_ratchet(msg),
        }
    }

    /// Handle a first-contact opener (already unsealed). Split out of `process` so the sealed
    /// path does not have to round-trip through the legacy wire variant to reach it.
    fn process_opener(&mut self, ka: &KeyAgreement, msg: &RatchetMessage) -> Option<Received> {
        {
            {
                // accept_key_agreement FIRST — it CONSUMES the one-time prekey, and that
                // consumption IS the at-most-once dedup: a re-delivered Initial whose OPK we
                // already consumed (and durably saved) returns None here and is NOT re-processed
                // (see the lease_recv crash-dedup tests). A success here is therefore a GENUINELY
                // NEW agreement (fresh OPK ⇒ a root key no existing session holds), so there is no
                // "try the existing session" case to handle — an existing session could never
                // decrypt a message under a brand-new root key.
                // PREPARE only: derive the root key WITHOUT consuming the one-time prekey. Nothing
                // here is authenticated yet — anyone can fetch a public bundle and claim any
                // `ik_a_pub` — so no durable state may change until the first AEAD verifies below
                // (CRYPTO-03).
                let (root_key, sender_ik) = self.account.prepare_key_agreement(ka)?;
                let drop_seed = crate::drop::drop_seed(&root_key);
                // The `drop_seed` (derived from the agreed root key) is the identity of THIS
                // agreement. If a session we already hold for this peer has the SAME drop_seed, this
                // Initial is a RE-DELIVERY of that session's opener (a lost ACK), not a new session
                // — route it to that session so its ratchet handles it: a genuine lost-ACK re-play
                // decrypts, an already-consumed duplicate fails closed (at-most-once). Rebuilding a
                // fresh receiver would instead re-decrypt the duplicate and deliver it TWICE.
                for st in self.sessions.get_mut(&sender_ik).into_iter().chain(self.inbound_sessions.get_mut(&sender_ik)) {
                    if st.drop_seed == drop_seed {
                        return Self::open_padded(&mut st.session, msg)
                            .map(|pt| Received { sender: sender_ik, plaintext: pt, msg_id: [0u8; 32] });
                    }
                }
                let mut session = self.account.init_receiver_session(root_key);
                // THE authentication step: only a sender who actually holds the claimed identity
                // key derives this root key, so a forged opener fails here. Bail BEFORE touching
                // the session maps or the one-time prekey — otherwise a stranger could park a dead
                // session under any victim's IK (it would become the primary outbound session and
                // silently swallow the replies) and burn a one-time prekey per attempt.
                let pt = Self::open_padded(&mut session, msg)?;
                // SEC-33: refuse a BRAND-NEW stranger once `sessions` is at `MAX_SESSIONS`,
                // BEFORE `consume_opk` — a refused attempt must not burn a real one-time prekey
                // on a peer we are about to discard anyway (that would degrade forward secrecy
                // for the NEXT genuine contact, who'd fall back to 3-DH for no reason). Checked
                // AFTER authentication (so this never short-circuits before the AEAD proves the
                // sender holds the claimed IK) but only against a sender NOT already in
                // `sessions` — the re-delivery loop above and an already-known peer's
                // `inbound_sessions` entry (simultaneous first contact) are never refused by
                // this; only growth of the table itself is capped.
                if !self.sessions.contains_key(&sender_ik) && self.sessions.len() >= MAX_SESSIONS {
                    self.sessions_refused = self.sessions_refused.saturating_add(1);
                    return None;
                }
                // Authenticated ⇒ commit. Consuming the OPK here still gives at-most-once dedup on
                // re-delivery: a genuine duplicate finds the OPK already gone and stops earlier.
                self.account.consume_opk(ka);
                // The sender's mailbox point rode the (authenticated) key-agreement — store it as
                // where I deposit my B→A replies.
                let peer_mailbox_pub = ka.mailbox_a_pub;
                // `peer_kem_ek` stays EMPTY on the responding side, deliberately: `pending_initial`
                // is `None` here, so this session never seals an opener and has no use for the
                // peer's KEM key. Storing one would mean keeping a public key we would never read.
                let new_state = SessionState {
                    session,
                    pending_initial: None,
                    drop_seed,
                    peer_mailbox_pub,
                    peer_kem_ek: Vec::new(),
                };
                // INVARIANT `inbound implies outbound`: a responder session goes in the SECONDARY
                // map ONLY when we already hold our own OUTBOUND session to this peer — i.e. we
                // both PQXDH-initiated before either received (simultaneous first contact). Keeping
                // BOTH, on their separate drop-boxes, is what lets each side send on its own chain
                // and receive the peer's on the other, instead of one clobbering the other (a split
                // that loses every message after the first — the "invisible until you reply" bug).
                // A plain first-contact responder has no outbound session, so it lands in `sessions`
                // unchanged — send/has_session/connect never see the secondary map.
                // Not `entry`: the check ROUTES between two different maps (inbound vs primary),
                // it is not an insert-if-absent into one.
                #[allow(clippy::map_entry)]
                let just_split = if self.sessions.contains_key(&sender_ik) {
                    self.inbound_sessions.insert(sender_ik, new_state);
                    true
                } else {
                    self.sessions.insert(sender_ik, new_state);
                    false
                };
                // A6-1: the moment BOTH halves of a simultaneous first contact exist locally is
                // exactly the moment convergence becomes possible — no need to wait for anything
                // else to happen first (see `converge_split_session`).
                if just_split {
                    self.converge_split_session(&sender_ik);
                }
                Some(Received { sender: sender_ik, plaintext: pt, msg_id: [0u8; 32] })
            }
        }
    }

    /// A6-1: heal a simultaneous-first-contact split by converging its two one-way chains onto
    /// ONE bidirectional session, deterministically and with no wire message.
    ///
    /// **Why the split stops healing.** `sessions[peer_ik]` only ever ENCRYPTS (it is what
    /// `send`/`queue` use) and `inbound_sessions[peer_ik]` only ever DECRYPTS (nothing calls
    /// `encrypt` on it) — see their field docs. A reply from the peer therefore never reaches
    /// the chain we send on: it lands on the OTHER one-way chain instead, where nobody replies
    /// back. `Session::dh_ratchet` only fires when a NEW header key arrives on a chain that is
    /// ALSO used to answer — which never happens here — so post-compromise healing is
    /// permanently stalled on both halves, not just delayed.
    ///
    /// **Why no wire message is needed.** `drop_seed` is a pure function of a session's root
    /// key (`crate::drop::drop_seed`), and that root key was ALREADY agreed identically by both
    /// sides at PQXDH time — nothing about it depends on which side happened to send or
    /// receive first. So both peers hold the exact same two `drop_seed` values (their own
    /// outbound's and the other's, now sitting in `inbound_sessions`) and can compare them with
    /// a fixed, symmetric rule — smaller byte string wins — and land on the SAME winner with no
    /// negotiation. A rule beats a handshake here specifically because it cannot be
    /// interrupted half-done: there is no message to lose, so there is no half-converged state
    /// to fall into. (Equality is not a real case: it would mean two independent PQXDH
    /// agreements, run with fresh ephemerals on each side, produced the same root key.)
    ///
    /// **What actually converges.** If our OWN outbound already IS the winner, there is nothing
    /// to do — we were already sending on the surviving chain, and the peer converges toward us
    /// the next time THEY run this check. Otherwise the two entries are SWAPPED:
    /// `inbound_sessions[peer_ik]` (the peer's session, which — per `process_opener` — already
    /// forced a DH-ratchet step on its very first decrypt and so already holds a working
    /// sending chain) is promoted into `sessions[peer_ik]`, and our losing outbound is demoted
    /// into `inbound_sessions[peer_ik]`.
    ///
    /// **Why the swap loses nothing.** Nothing is deleted, only relocated — and both maps are
    /// treated identically everywhere that matters: `receive`'s box collection polls the
    /// INBOUND box of every session in EITHER map the same way (by that session's own
    /// `drop_seed`, regardless of which map holds it), and `process_for_peer`/`process_ratchet`
    /// try both maps to decrypt. So the demoted loser keeps being polled and keeps decrypting
    /// exactly as it did before the swap — any reply the peer already sent on it, or sends
    /// before THEY converge too, still arrives. The one thing that changes is which chain FUTURE
    /// `send`/`queue` calls encrypt on. Already-queued ciphertext under the old (now demoted)
    /// chain is unaffected by the swap for the same reason: `OutboxEntry` carries its OWN
    /// routing snapshot from `queue` time, not a live lookup — see its doc.
    fn converge_split_session(&mut self, peer_ik: &[u8; 32]) {
        let (Some(out_seed), Some(in_seed)) = (
            self.sessions.get(peer_ik).map(|st| st.drop_seed),
            self.inbound_sessions.get(peer_ik).map(|st| st.drop_seed),
        ) else {
            return; // no split held for this peer (yet) — nothing to converge
        };
        if in_seed < out_seed {
            // Swap, don't drop: see the doc above for why both halves stay fully usable either
            // way, just under the other map.
            let winner = self.inbound_sessions.remove(peer_ik).expect("checked Some above");
            let loser = self
                .sessions
                .insert(*peer_ik, winner)
                .expect("checked Some above");
            self.inbound_sessions.insert(*peer_ik, loser);
        }
    }

    /// An ongoing ratchet message: no sender hint, so trial-decrypt. Safe because `decrypt` is
    /// transactional — a miss does not move anyone else's session. Both maps: a peer's stream
    /// after a simultaneous first contact rides `inbound_sessions`.
    /// **The only place a ratchet message is opened.** Decrypt, then strip the fixed-size block.
    ///
    /// A free function, not a method, so it can be called while a session is borrowed out of either
    /// map — which is what every caller here is doing. There were six `session.decrypt(` sites
    /// before this existed, and six places to forget the second half of the operation;
    /// `pad_is_not_bypassed` now fails the build if a seventh appears.
    ///
    /// A block that authenticates but will not unpad is treated as a miss, deliberately. It means
    /// a peer holding a valid chain sent something our own encoder cannot produce — a bug or a
    /// version skew — and the caller's "not for us" path is the safe reading: it advances no state
    /// and burns no one-time prekey.
    fn open_padded(
        session: &mut karst_crypto::ratchet::Session,
        msg: &RatchetMessage,
    ) -> Option<Vec<u8>> {
        let block = session.decrypt(msg).ok()?;
        crate::pad::unpad(&block).ok()
    }

    fn process_ratchet(&mut self, msg: &RatchetMessage) -> Option<Received> {
        for (ik, st) in self.sessions.iter_mut() {
            self.decrypt_attempts_for_test += 1;
            if let Some(pt) = Self::open_padded(&mut st.session, msg) {
                return Some(Received { sender: *ik, plaintext: pt, msg_id: [0u8; 32] });
            }
        }
        for (ik, st) in self.inbound_sessions.iter_mut() {
            self.decrypt_attempts_for_test += 1;
            if let Some(pt) = Self::open_padded(&mut st.session, msg) {
                return Some(Received { sender: *ik, plaintext: pt, msg_id: [0u8; 32] });
            }
        }
        None
    }

    /// Test-only: how many real `Session::decrypt` attempts have run since the last
    /// [`Peer::reset_decrypt_attempts_for_test`] — see `session_cap_tests` for how this proves,
    /// by counting rather than timing, that `process_for_peer` costs O(1) where the generic
    /// `process_ratchet` sweep it replaces on the hot path costs O(sessions) (SEC-33).
    #[cfg(test)]
    pub fn decrypt_attempts_for_test(&self) -> u64 {
        self.decrypt_attempts_for_test
    }

    #[cfg(test)]
    pub fn reset_decrypt_attempts_for_test(&mut self) {
        self.decrypt_attempts_for_test = 0;
    }
}

#[cfg(test)]
mod outbox_state_tests {
    use super::{OutboxEntry, PeerState, PersistedSession};
    use node::protocol::SessionEnvelope;
    use karst_crypto::ratchet::{Header, RatchetMessage, Session};
    use admission::cookie::Cookie;

    fn a_ratchet_envelope() -> SessionEnvelope {
        SessionEnvelope::Ratchet(RatchetMessage {
            header: Header { dh: [1u8; 32], pn: 0, n: 0, salt: [7u8; 16] },
            ciphertext: vec![9u8; 16],
        })
    }

    /// A state file in an OLD layout must now fail LOUDLY.
    ///
    /// `from_bytes` used to walk back through PeerStatePreInbound → PeerStatePreOutbox so
    /// state written by an earlier build still loaded. With no such state in existence that chain
    /// was pure surface, and it carried a real hazard: postcard ignores trailing bytes, so a
    /// mis-ordered attempt could silently accept an old layout for NEW data and drop the fields
    /// that were actually there. One layout, one decode — and an unreadable file is an error the
    /// caller sees, not silent defaults substituted for a live ratchet's outbox.
    ///
    /// (This replaces two tests that pinned the removed fallback. They were deleted deliberately
    /// because the behaviour they described is gone, not to make a red run go green.)
    #[test]
    fn an_old_layout_state_file_is_rejected_rather_than_silently_defaulted() {
        let pre_outbox = postcard::to_stdvec(&(
            Vec::<super::PersistedSession>::new(),
            7u64, // nonce_ctr
            Vec::<([u8; 32], super::Handle, [u8; 32])>::new(),
            Vec::<([u8; 32], Vec<u8>, Cookie)>::new(),
            42u64, // last_sweep
        ))
        .unwrap();
        assert!(
            PeerState::from_bytes(&pre_outbox).is_err(),
            "an old layout must be reported, not loaded with invented defaults"
        );
    }

    /// The current layout round-trips a NON-empty outbox: try-new-first must win so the
    /// queued messages are never silently dropped by the fallback (postcard ignores trailing
    /// bytes, so old-first would lose them).
    #[test]
    fn outbox_round_trips_through_the_current_layout() {
        let state = PeerState {
            sessions: Vec::new(),
            nonce_ctr: 3,
            handles: Vec::new(),
            cookies: Vec::new(),
            swept_through: 0,
            last_sweep: 0,
            epoch_hwm: 0,
            outbox: vec![OutboxEntry {
                id: 5,
                peer_ik: [2u8; 32],
                envelope: a_ratchet_envelope(),
                queued_at: 100,
                drop_seed: [3u8; 32],
                peer_mailbox_pub: [4u8; 32],
            }],
            outbox_next_id: 6,
            inbound_sessions: Vec::new(),
        };
        let bytes = postcard::to_stdvec(&state).unwrap();
        let back = PeerState::from_bytes(&bytes).expect("current layout loads");
        assert_eq!(back.outbox.len(), 1, "queued message survived the round trip");
        assert_eq!(back.outbox[0].id, 5);
        assert_eq!(back.outbox_next_id, 6);
        assert_eq!(back.nonce_ctr, 3);
    }

    /// `forget_peer` clears BOTH session halves (outbound + inbound) and any queued outbox for one
    /// peer, and leaves other peers untouched — the split-session recovery primitive.
    #[test]
    fn forget_peer_clears_both_halves_and_spares_others() {
        let mk = |ik: u8| PersistedSession {
            peer_ik: [ik; 32],
            snapshot: Session::init_sender([1u8; 32], [2u8; 32]).snapshot(),
            pending_initial: None,
            drop_seed: [ik; 32],
            peer_mailbox_pub: [0u8; 32],
            peer_kem_ek: Vec::new(),
        };
        let mut st = PeerState::empty();
        st.sessions = vec![mk(1), mk(2)];
        st.inbound_sessions = vec![mk(1)];
        assert!(st.forget_peer(&[1u8; 32]), "removed peer 1's state");
        assert_eq!(st.sessions.len(), 1);
        assert_eq!(st.sessions[0].peer_ik, [2u8; 32], "peer 2 spared");
        assert!(st.inbound_sessions.is_empty(), "peer 1's inbound half cleared");
        assert!(!st.forget_peer(&[9u8; 32]), "unknown peer: nothing to clear");
    }

    /// A5-9. "Forget this contact" is a user-facing promise, and it used to be a promise about
    /// what the UI stops showing. `Handle::Opener` and `Handle::Box` embed the peer's identity key
    /// directly, so a forgotten contact's IK stayed in `sessions.dat` — and `Opener` is not
    /// epoch-keyed, so ordinary rotation never aged it out. The cookies keyed by those handles'
    /// addresses are the same trace one layer down.
    ///
    /// Discriminating on both axes: it asserts the forgotten peer's IK appears NOWHERE in the
    /// serialized state (so a handle that merely stopped being used but stayed on disk fails),
    /// and that ANOTHER peer's handle and cookie survive (so a cascade that wiped everything
    /// would fail too).
    #[test]
    fn forget_peer_erases_the_handles_and_cookies_that_name_them() {
        use super::Handle;
        let relay = [7u8; 32];
        let (gone, kept) = ([0xAB; 32], [0xCD; 32]);
        let mut st = PeerState::empty();
        st.handles = vec![
            (relay, Handle::Identity, [1u8; 32]),
            (relay, Handle::Opener(gone), [2u8; 32]),
            (relay, Handle::Box(gone, 9), [3u8; 32]),
            (relay, Handle::Opener(kept), [4u8; 32]),
        ];
        let cookie = |n: u8| Cookie {
            version: 1,
            epoch_id: 0,
            client_addr_hash: [n; 16],
            issued_at: 0,
            mac: [n; 16],
        };
        st.cookies = vec![
            (relay, vec![2u8; 32], cookie(2)),
            (relay, vec![3u8; 32], cookie(3)),
            (relay, vec![4u8; 32], cookie(4)),
        ];

        assert!(st.forget_peer(&gone), "handles/cookies alone are enough to count as state");

        let on_disk = postcard::to_stdvec(&st).unwrap();
        assert!(
            !on_disk.windows(32).any(|w| w == gone),
            "the forgotten contact's identity key is still in the persisted state — 'forget' has \
             to cascade to the transport identifiers that embed it, or it only means 'hidden'"
        );
        assert!(
            st.handles.iter().any(|(_, h, _)| matches!(h, Handle::Opener(ik) if *ik == kept)),
            "another contact's handle must survive"
        );
        assert!(
            st.cookies.iter().any(|(_, addr, _)| addr == &vec![4u8; 32]),
            "another contact's cookie must survive"
        );
        assert!(
            st.handles.iter().any(|(_, h, _)| matches!(h, Handle::Identity)),
            "our own identity handle is not a trace of THEM"
        );
    }

    /// Migration safety: a session restored from a state file written BEFORE blinded mailboxes has
    /// `peer_mailbox_pub == [0;32]` (the serde default) — which is the VALID Ristretto identity, so
    /// `deposit_address` would silently return a box no one fetches. A follow-up send must fail
    /// LOUD ("re-establish") instead of dropping mail into the void.
    #[test]
    fn a_stale_session_without_a_mailbox_point_fails_loud_on_send() {
        use node::protocol::{Response};
use super::LoopbackMail;
        use karst_crypto::pqxdh::Account;
        use karst_crypto::ratchet::Session;
        use admission::capability::{Capability, Quota, Scope};
        
        

        // A stand-in relay key: this test never reaches a relay (#143).
        let relay_pub = x25519_dalek::PublicKey::from([7u8; 32]);
        let cap = Capability {
            capability_id: [0xCA; 16],
            scope: Scope::MessageDelivery,
            quota: Quota { max_requests: 10_000, max_bytes: 1 << 30, window_secs: 600 },
            not_before: 0,
            not_after: u32::MAX,
            secret: [0x33; 32],
        };
        let mut peer = super::Peer::new(LoopbackMail::default(), Account::generate(), cap, relay_pub);

        let bob_ik = [9u8; 32];
        peer.sessions.insert(
            bob_ik,
            super::SessionState {
                session: Session::init_sender([1u8; 32], [2u8; 32]),
                pending_initial: None, // a follow-up Ratchet send → hits the blinded deposit path
                drop_seed: [3u8; 32],
                peer_mailbox_pub: [0u8; 32],
                peer_kem_ek: Vec::new(), // the serde default of a pre-change session
            },
        );

        match peer.send(&bob_ik, b"hi", 0) {
            Response::Rejected(e) => assert!(e.contains("re-establish"), "loud, actionable error: {e}"),
            other => panic!("a stale session must fail loud, not silently drop mail: {other:?}"),
        }
    }
}

/// SEC-33: unbounded session growth as a trial-decryption DoS amplifier.
#[cfg(test)]
mod session_cap_tests {
    use node::protocol::{Payload, Response, SessionEnvelope};
use super::LoopbackMail;
    use karst_crypto::pqxdh::Account;
    use karst_crypto::ratchet::{Header, RatchetMessage, Session};
    use admission::capability::{Capability, Quota, Scope};
    
    
    use x25519_dalek::PublicKey;

    fn dev_cap() -> Capability {
        Capability {
            capability_id: [0xCC; 16],
            scope: Scope::MessageDelivery,
            quota: Quota { max_requests: 100_000, max_bytes: 1 << 30, window_secs: 600 },
            not_before: 0,
            not_after: u32::MAX,
            secret: [0x35; 32],
        }
    }

    fn shared() -> (LoopbackMail, PublicKey) {
        // A stand-in relay key: nothing here talks to a relay, and the tests that do live in
        // `tests/` where a real one is available (#143).
        (LoopbackMail::default(), PublicKey::from([7u8; 32]))
    }

    fn mk_peer(transport: &LoopbackMail, relay_pub: PublicKey) -> super::Peer<LoopbackMail> {
        super::Peer::new(transport.clone(), Account::generate(), dev_cap(), relay_pub)
    }

    /// A cheap synthetic session under a distinct fabricated `peer_ik` — for filling `sessions`
    /// toward `MAX_SESSIONS` without paying for a real PQXDH agreement per entry (that would make
    /// the test itself pay the CPU cost SEC-33 is about). Only table MEMBERSHIP is under test
    /// here, never this session's cryptographic history.
    fn dummy_ik(i: u64) -> [u8; 32] {
        let mut ik = [0u8; 32];
        ik[..8].copy_from_slice(&i.to_le_bytes());
        ik
    }
    /// One real `Session::init_sender` (X25519 keygen + a DH), CLONED into every dummy entry
    /// instead of re-run per entry: `MAX_SESSIONS` real key generations would make filling the
    /// table itself slow enough to risk starving unrelated timing-sensitive tests running in
    /// parallel, for no benefit — a cheap struct clone proves table membership just as well.
    fn dummy_session_template() -> Session {
        Session::init_sender([1u8; 32], [2u8; 32])
    }

    fn insert_dummy(peer: &mut super::Peer<LoopbackMail>, ik: [u8; 32], template: &Session) {
        peer.sessions.insert(
            ik,
            super::SessionState {
                session: template.clone(),
                pending_initial: None,
                drop_seed: [3u8; 32],
                peer_mailbox_pub: [4u8; 32],
                peer_kem_ek: Vec::new(),
            },
        );
    }

    /// A flood of distinct strangers, each capable of a genuine PQXDH agreement against our
    /// published bundle with NO one-time prekey of ours required (3-DH always succeeds against
    /// our reusable signed prekey), must not grow `sessions` past `MAX_SESSIONS` — otherwise
    /// nothing bounds how much RAM (and, before `process_for_peer`, how much per-message
    /// trial-decryption CPU) a remote party can force us to hold. Drives the FINAL, over-the-cap
    /// stranger through the real `process_opener` path with a genuine PQXDH-derived opener; the
    /// rest of the table is filled with cheap synthetic entries (see `insert_dummy`) so the test
    /// doesn't itself pay for `MAX_SESSIONS` real handshakes.
    #[test]
    fn a_flood_of_first_contact_openers_cannot_grow_the_session_table_past_the_cap() {
        let (transport, relay_pub) = shared();
        let mut victim = mk_peer(&transport, relay_pub);
        victim.publish(0);
        let template = dummy_session_template();
        for i in 0..super::MAX_SESSIONS as u64 {
            insert_dummy(&mut victim, dummy_ik(i), &template);
        }
        assert_eq!(victim.sessions.len(), super::MAX_SESSIONS, "set up at exactly the cap");

        let mut mallory = mk_peer(&transport, relay_pub);
        let victim_ik = victim.identity();
        mallory.connect(&victim_ik, 0).expect("mallory can fetch the bundle and PQXDH-agree freely");
        let opener = mallory.encrypt_next(&victim_ik, b"let me in").expect("encrypt mallory's opener");

        assert!(
            victim.open_for_test(&Payload::Session(opener)).is_none(),
            "a stranger past the cap must not be admitted"
        );
        assert_eq!(
            victim.sessions.len(),
            super::MAX_SESSIONS,
            "the session table must not grow past the cap"
        );
        assert_eq!(victim.take_refused_sessions(), 1, "the refusal must be LOUD, not silent");
    }

    /// Control: an ALREADY-established contact must keep receiving even while `sessions` sits at
    /// the cap — the cap refuses only a BRAND-NEW stranger (`process_opener`); an existing
    /// session is never touched by it, and `process_for_peer` routes its traffic directly. This
    /// is what stops the fix from "passing" by refusing everything.
    #[test]
    fn an_established_contact_still_receives_after_the_session_cap_is_reached() {
        let (transport, relay_pub) = shared();
        let mut victim = mk_peer(&transport, relay_pub);
        let mut alice = mk_peer(&transport, relay_pub);
        victim.publish(0);
        let victim_ik = victim.identity();
        let alice_ik = alice.identity();

        // Alice's REAL first contact, accepted before the table fills.
        alice.connect(&victim_ik, 0).unwrap();
        let opener = alice.encrypt_next(&victim_ik, b"hi, it's alice").unwrap();
        let received = victim
            .open_for_test(&Payload::Session(opener))
            .expect("alice's genuine opener must be accepted");
        assert_eq!(received.plaintext.as_slice(), b"hi, it's alice");

        // Fill the REST of the table (alice already occupies one slot).
        let template = dummy_session_template();
        for i in 0..(super::MAX_SESSIONS as u64 - 1) {
            insert_dummy(&mut victim, dummy_ik(i), &template);
        }
        assert_eq!(victim.sessions.len(), super::MAX_SESSIONS, "at the cap, alice included");

        // Alice's NEXT message, continuing the SAME live session, must still decrypt.
        let next = alice.encrypt_next(&victim_ik, b"still here?").unwrap();
        let got = victim
            .process_for_peer(&alice_ik, &Payload::Session(next))
            .expect("an established contact must keep receiving once the table is at the cap");
        assert_eq!(got.plaintext.as_slice(), b"still here?");
    }

    /// SEC-33's core claim, made structural: on a garbage `Ratchet` message that matches NO
    /// held session, the generic `process_ratchet` sweep pays one `decrypt` attempt PER session
    /// held — attacker-controlled, since `sessions` holds one entry per accepted stranger.
    /// `process_for_peer` (the real per-session-box path, used for ordinary, ongoing traffic)
    /// pays exactly ONE, because the box the payload arrived on already identifies the owning
    /// peer. Counts real `decrypt` calls rather than timing anything, so this cannot flake on a
    /// loaded CI box.
    ///
    /// **`process_ratchet` itself has no production caller left.** `process()`'s `Ratchet` arm
    /// is the only thing that invokes it, and `receive()` filters every `Ratchet`-shaped payload
    /// out of the identity-mailbox loop BEFORE calling `process()` (see the `matches!` check
    /// right before that call), because `route_for` never deposits a `Ratchet` envelope there —
    /// only `Initial`/`InitialSealed`. `process_for_peer`'s own fallback to `process()` only
    /// fires on its `_` arm, which a `Ratchet` payload can never reach (it is matched, and
    /// handled directly, one arm up). So this test drives `process_ratchet` through
    /// `open_for_test`, a test-only entry point — the O(sessions) sweep is retained as a generic
    /// fallback with no live caller, not as an active cost on any current path. If a future
    /// change ever routes a `Ratchet` payload back through `process()` from a real fetch, this
    /// sweep would run again — which is exactly the regression `an_established_contact_...` and
    /// the test below exist to catch.
    ///
    /// Uses a REPRESENTATIVE session count, not the full `MAX_SESSIONS` — the cap tests above
    /// already prove the boundary itself at negligible cost; this test's `decrypt` calls are
    /// each a REAL DH-ratchet step (2 X25519 DHs + 2 HKDF expansions — see `ratchet::dh_ratchet`),
    /// so running it at `MAX_SESSIONS` would spend several real seconds proving a ratio that a
    /// few hundred sessions already demonstrate just as conclusively.
    const REPRESENTATIVE_SESSION_COUNT: u64 = 300;

    #[test]
    fn process_for_peer_pays_one_decrypt_attempt_where_the_generic_sweep_pays_one_per_session() {
        let (transport, relay_pub) = shared();
        let mut victim = mk_peer(&transport, relay_pub);
        let template = dummy_session_template();
        for i in 0..REPRESENTATIVE_SESSION_COUNT {
            insert_dummy(&mut victim, dummy_ik(i), &template);
        }
        assert_eq!(victim.sessions.len(), REPRESENTATIVE_SESSION_COUNT as usize);

        // A well-formed but GARBAGE `Ratchet` message: its `dh`/ciphertext match no session's
        // state, so every trial decrypt this drives is guaranteed to fail the AEAD.
        let garbage = RatchetMessage {
            header: Header { dh: [0x77; 32], pn: 0, n: 0, salt: [7u8; 16] },
            ciphertext: vec![0x11; 48],
        };

        victim.reset_decrypt_attempts_for_test();
        assert!(
            victim.open_for_test(&Payload::Session(SessionEnvelope::Ratchet(garbage.clone()))).is_none(),
            "garbage must not decrypt against anything"
        );
        assert_eq!(
            victim.decrypt_attempts_for_test(),
            REPRESENTATIVE_SESSION_COUNT,
            "the generic sweep must try every session held — this is the O(sessions) cost SEC-33 is about"
        );

        victim.reset_decrypt_attempts_for_test();
        assert!(
            victim
                .process_for_peer(&dummy_ik(0), &Payload::Session(SessionEnvelope::Ratchet(garbage)))
                .is_none(),
            "still garbage, still must not decrypt"
        );
        assert_eq!(
            victim.decrypt_attempts_for_test(),
            1,
            "routing by the box's own peer identifies the ONLY session that could ever match — O(1), not O(sessions)"
        );
    }

    /// SEC-33's other entry point: the identity mailbox is a PUBLIC address a stranger can
    /// deposit to with no session, no bundle fetch, nothing — it's how first contact works.
    /// `route_for` never sends a `Ratchet` envelope there (only `Initial`/`InitialSealed` — see
    /// its match arms), so a `Ratchet`-shaped payload landing on it is provably never
    /// legitimate. Drives an ACTUAL deposit through the real relay/transport (`Peer::transmit`,
    /// bypassing `route_for` the way a hostile client would) and the real `receive()`, and
    /// asserts it costs not one decrypt attempt, let alone one per session — the whole
    /// generic `process_ratchet` sweep must never run for this payload shape at this address.
    #[test]
    fn a_garbage_ratchet_message_at_the_identity_mailbox_touches_no_session() {
        let (transport, relay_pub) = shared();
        let mut victim = mk_peer(&transport, relay_pub);
        let template = dummy_session_template();
        // This test's assertion is `== 0`, not `== N` (that comparison is the OTHER two tests'
        // job) — a handful of sessions is enough to prove "touches none of them", and it keeps
        // this test off `receive()`'s own pre-existing, already-documented `3 × sessions + 1`
        // round-trip cost (see `receive`'s doc comment): that's a bandwidth/latency property,
        // unrelated to SEC-33, and paying it at `REPRESENTATIVE_SESSION_COUNT` here would only
        // slow the test down for no added proof.
        for i in 0..5u64 {
            insert_dummy(&mut victim, dummy_ik(i), &template);
        }
        let victim_ik = victim.identity();

        let mut mallory = mk_peer(&transport, relay_pub);
        let garbage = RatchetMessage {
            header: Header { dh: [0x66; 32], pn: 0, n: 0, salt: [7u8; 16] },
            ciphertext: vec![0x22; 48],
        };
        // Recipient = victim's identity key = victim's identity mailbox address. No PQXDH, no
        // established session, no bundle fetch — exactly what a stranger CAN do unauthenticated.
        assert!(
            matches!(
                mallory.transmit(victim_ik, super::Handle::Opener(victim_ik), SessionEnvelope::Ratchet(garbage), 0),
                Response::Accepted
            ),
            "the deposit itself must succeed — admission gates senders, not payload shape"
        );

        victim.reset_decrypt_attempts_for_test();
        let received = victim.receive(0).expect("receive succeeds even though the garbage is dropped");
        assert!(received.iter().all(Option::is_none), "garbage at the identity mailbox must not decrypt");
        assert_eq!(
            victim.decrypt_attempts_for_test(),
            0,
            "a Ratchet-shaped payload at the identity mailbox is NEVER legitimate — it must cost \
             ZERO decrypt attempts, not one per session held"
        );
    }
}

/// A6-1: simultaneous-first-contact convergence. `session_convergence.rs` (integration test,
/// full PQXDH + relay) proves both sides independently pick the same session and that a
/// straggler queued before an END-TO-END split still arrives. These are UNIT-level tests that
/// isolate two narrower claims the e2e path cannot cleanly isolate on its own:
///
/// - `route_for`'s SNAPSHOT actually changes where a queued envelope lands (the e2e path masks
///   a broken snapshot: `receive()` always drains the identity mailbox — creating the peer's
///   second session — before it polls drop-boxes IN THE SAME call, and `process_for_peer`
///   trial-decrypts a peer's traffic against BOTH of that peer's held sessions regardless of
///   which box it arrived on. Together these recover an address computed from the wrong
///   session in every ordering this test file's own harness can produce — so proving the
///   snapshot's effect requires inspecting the computed ADDRESS directly, not observing
///   receive() end to end);
/// - the DH ratchet actually RESUMES stepping once convergence makes a session bidirectional
///   again (the ticket's actual subject — "the DH ratchet stops healing" — which a plaintext
///   round-trip alone does not distinguish from the pre-fix split, since BOTH one-way chains
///   already deliver plaintext correctly; only the ratchet-pubkey changing on reply is
///   specific to healing).
#[cfg(test)]
mod convergence_route_tests {
    use super::{SessionEnvelope, SessionState};
    use node::protocol::{Response};
use super::LoopbackMail;
    use karst_crypto::pqxdh::Account;
    use karst_crypto::ratchet::{Header, RatchetMessage, Session};
    use admission::capability::{Capability, Quota, Scope};
    
    
    use x25519_dalek::PublicKey;

    const NOW: u64 = 1_000_000;

    fn dev_cap() -> Capability {
        Capability {
            capability_id: [0xCE; 16],
            scope: Scope::MessageDelivery,
            quota: Quota { max_requests: 100, max_bytes: 1 << 20, window_secs: 600 },
            not_before: 0,
            not_after: u32::MAX,
            secret: [0x36; 32],
        }
    }

    /// A relay + transport shared by TWO peers, so they can actually reach each other — the
    /// routing test below needs neither (it never touches the network), but the healing and
    /// disk-reload tests do.
    fn shared() -> (LoopbackMail, PublicKey) {
        // A stand-in relay key: nothing here talks to a relay, and the tests that do live in
        // `tests/` where a real one is available (#143).
        (LoopbackMail::default(), PublicKey::from([7u8; 32]))
    }

    fn mk_peer(transport: &LoopbackMail, relay_pub: PublicKey) -> super::Peer<LoopbackMail> {
        super::Peer::new(transport.clone(), Account::generate(), dev_cap(), relay_pub)
    }

    /// A standalone peer with its OWN relay — for the routing test, which never sends or
    /// receives anything over the network (it calls `route_for` directly).
    fn mk_lone_peer() -> super::Peer<LoopbackMail> {
        let (transport, relay_pub) = shared();
        mk_peer(&transport, relay_pub)
    }

    /// THE routing claim, isolated: a `Ratchet` envelope encrypted under one session
    /// (`pre_swap_seed`) must deposit at the address THAT session derives — even after
    /// `sessions[peer_ik]` has since been replaced (exactly what `converge_split_session`
    /// does) — when routed with the snapshot `queue` captured. Without the snapshot, routing
    /// drifts to whatever CURRENTLY occupies `sessions[peer_ik]`, landing at a DIFFERENT
    /// address than the one actually encrypted for.
    #[test]
    fn a_queued_envelope_routes_by_its_own_snapshot_not_by_whatever_session_is_current() {
        let mut peer = mk_lone_peer();
        let peer_ik = [9u8; 32];
        let mailbox_pub = karst_crypto::blind::MailboxSecret::generate().public();
        let pre_swap_seed = [1u8; 32];
        let post_swap_seed = [2u8; 32];
        let mk_state = |drop_seed: [u8; 32]| SessionState {
            session: Session::init_sender([7u8; 32], [8u8; 32]),
            pending_initial: None,
            drop_seed,
            peer_mailbox_pub: mailbox_pub,
                        peer_kem_ek: Vec::new(),
            };

        // The session this message is ACTUALLY encrypted under.
        peer.sessions.insert(peer_ik, mk_state(pre_swap_seed));
        let envelope = SessionEnvelope::Ratchet(RatchetMessage {
            header: Header { dh: [3u8; 32], pn: 0, n: 0, salt: [4u8; 16] },
            ciphertext: vec![5u8; 32],
        });
        let dir = crate::drop::direction(&peer.identity(), &peer_ik);
        let epoch = crate::drop::epoch_of(NOW);
        // Derived with THIS peer's relay, because the address is relay-specific now (PRIV-12).
        let correct_address = karst_crypto::blind::deposit_address(
            &mailbox_pub,
            &pre_swap_seed,
            epoch,
            dir,
            &peer.relay_id(),
        )
        .expect("valid curve point");

        // The convergence swap: some OTHER session now occupies `sessions[peer_ik]` — the
        // message above was already encrypted before this happened.
        peer.sessions.insert(peer_ik, mk_state(post_swap_seed));

        let (snapshot_addr, _) = peer
            .route_for(&peer_ik, &envelope, Some((pre_swap_seed, mailbox_pub)), NOW)
            .expect("routes with the snapshot");
        assert_eq!(
            snapshot_addr, correct_address,
            "routed WITH the queue-time snapshot: lands where it was actually encrypted for"
        );

        let (live_addr, _) =
            peer.route_for(&peer_ik, &envelope, None, NOW).expect("routes without an override");
        assert_ne!(
            live_addr, correct_address,
            "routed WITHOUT the snapshot: drifts to whatever `sessions[peer_ik]` holds NOW — \
             exactly the hazard `OutboxEntry`'s snapshot exists to close"
        );
    }

    /// A6-8 (#224): a clock that jumps BACKWARDS must not move our drop-box address.
    ///
    /// Epochs are a pure function of the local wall clock and nothing authenticates it. A bad NTP
    /// step, a restored VM snapshot or a user correcting a timezone can move the clock back —
    /// and if the address followed, we would deposit into a box we already moved past while the
    /// peer polls the newer one, splitting a conversation across addresses with no error
    /// anywhere. The high-water mark makes our own epoch monotonic.
    ///
    /// Discriminating on the ADDRESS, not on the counter: the message is routed at a late `now`,
    /// then again after the clock falls back three epochs, and both must land in the same box.
    /// Drop the high-water mark and the second address differs — RED.
    ///
    /// The forward direction is deliberately NOT asserted here: a clock that runs fast is a real
    /// hazard this cannot fix (see `local_epoch`), and the receiving side's
    /// `drop::FUTURE_SLACK_EPOCHS` is what tolerates it.
    #[test]
    fn a_backwards_clock_jump_does_not_move_our_drop_box() {
        let (transport, relay_pub) = shared();
        let mut peer = super::Peer::new(transport, Account::generate(), dev_cap(), relay_pub);
        let peer_ik = [9u8; 32];
        let seed = [4u8; 32];
        let mailbox_pub = karst_crypto::blind::MailboxSecret::generate().public();
        peer.sessions.insert(
            peer_ik,
            SessionState {
                session: Session::init_sender([7u8; 32], [8u8; 32]),
                pending_initial: None,
                drop_seed: seed,
                peer_mailbox_pub: mailbox_pub,
                            peer_kem_ek: Vec::new(),
            },
        );
        let envelope = SessionEnvelope::Ratchet(RatchetMessage {
            header: Header { dh: [3u8; 32], pn: 0, n: 0, salt: [4u8; 16] },
            ciphertext: vec![5u8; 32],
        });

        let late = 40 * crate::drop::DROP_EPOCH_SECS;
        let (addr_before, _) =
            peer.route_for(&peer_ik, &envelope, None, late).expect("routes at the later time");

        // The clock falls back three days.
        let rolled_back = late - 3 * crate::drop::DROP_EPOCH_SECS;
        assert_ne!(
            crate::drop::epoch_of(rolled_back),
            crate::drop::epoch_of(late),
            "the fixture must really cross epochs"
        );
        let (addr_after, _) = peer
            .route_for(&peer_ik, &envelope, None, rolled_back)
            .expect("routes after the clock moved back");

        assert_eq!(
            addr_before, addr_after,
            "a backwards clock must not change the box we deposit into"
        );
    }

    /// The ticket's actual subject: after convergence, BOTH sides' ratchet-pubkeys keep
    /// changing across several further rounds — not merely once.
    ///
    /// A single round is NOT discriminating on its own: `process_opener` already forces one
    /// free `dh_ratchet` step on the very FIRST decrypt of ANY new session, split or not (see
    /// its doc) — so whichever side happens to win the tie-break may see its NEXT one or two
    /// replies land on a chain whose peer-key hasn't moved YET (the winning side's own long-held
    /// session never decrypted anything before convergence, so it takes one full round to catch
    /// up). What a split can NEVER do, and convergence exists to restore, is CONTINUE
    /// ratcheting on message after message — a one-way chain gets its one first-contact freebie
    /// and then nothing, forever. So this drives several rounds and compares the FIRST key each
    /// side held against the LAST — proof of ongoing, not one-shot, healing.
    #[test]
    fn the_converged_session_keeps_dh_ratcheting_across_several_further_rounds() {
        let (transport, relay_pub) = shared();
        let mut alice = mk_peer(&transport, relay_pub);
        let mut bob = mk_peer(&transport, relay_pub);
        let (alice_ik, bob_ik) = (alice.identity(), bob.identity());

        alice.connect_with_bundle(&bob.bundle()).unwrap();
        bob.connect_with_bundle(&alice.bundle()).unwrap();
        assert!(matches!(alice.send(&bob_ik, b"a0", NOW), Response::Accepted));
        assert!(matches!(bob.send(&alice_ik, b"b0", NOW), Response::Accepted));
        bob.receive(NOW).unwrap();
        alice.receive(NOW).unwrap();

        // Precondition: converged (see `session_convergence.rs` for the dedicated test of this
        // property) — both now hold the SAME session for each other.
        let alice_seed = alice.sessions.get(&bob_ik).unwrap().drop_seed;
        let bob_seed = bob.sessions.get(&alice_ik).unwrap().drop_seed;
        assert_eq!(alice_seed, bob_seed, "precondition: converged before checking healing");

        let alice_key0 = alice.sessions.get(&bob_ik).unwrap().session.ratchet_public();
        let bob_key0 = bob.sessions.get(&alice_ik).unwrap().session.ratchet_public();

        for i in 0..3u8 {
            assert!(matches!(bob.send(&alice_ik, &[b'B', i], NOW), Response::Accepted));
            let got: Vec<_> = alice.receive(NOW).unwrap().into_iter().flatten().collect();
            assert_eq!(got.len(), 1, "round {i}: alice gets bob's message");

            assert!(matches!(alice.send(&bob_ik, &[b'A', i], NOW), Response::Accepted));
            let got: Vec<_> = bob.receive(NOW).unwrap().into_iter().flatten().collect();
            assert_eq!(got.len(), 1, "round {i}: bob gets alice's message");
        }

        let alice_key_last = alice.sessions.get(&bob_ik).unwrap().session.ratchet_public();
        let bob_key_last = bob.sessions.get(&alice_ik).unwrap().session.ratchet_public();
        assert_ne!(
            alice_key0, alice_key_last,
            "alice's ratchet key must have moved after several further rounds — a split \
             session gets ONE free DH-ratchet at first contact and then never another; \
             seeing it move AGAIN is what 'healing resumed' actually means"
        );
        assert_ne!(
            bob_key0, bob_key_last,
            "same for bob's side — BOTH directions must keep healing, not just one"
        );
    }

    /// A6-1's other entry point: a split that formed and was PERSISTED before this fix (or one
    /// this side hasn't touched since the peer's half landed) must also converge — via the
    /// sweep at the top of `receive()` — not just a split detected fresh inside
    /// `process_opener` in the SAME process. Builds the split BY HAND (the same shape
    /// `process_opener` would have produced on an OLDER build, before convergence existed —
    /// same technique `session_cap_tests::insert_dummy` uses to avoid paying for a real PQXDH
    /// agreement when only the MAP SHAPE is under test) and hands it to a fresh `Peer` purely
    /// via `import_state` — `process_opener` never runs in this process at all, so the ONLY
    /// thing that can converge it is the sweep.
    #[test]
    fn a_split_present_only_because_it_was_just_loaded_from_disk_converges_on_the_next_receive() {
        let mut peer = mk_lone_peer();
        let peer_ik = [9u8; 32];
        let mailbox_pub = karst_crypto::blind::MailboxSecret::generate().public();
        let mk_state = |drop_seed: [u8; 32]| SessionState {
            session: Session::init_sender([7u8; 32], [8u8; 32]),
            pending_initial: None,
            drop_seed,
            peer_mailbox_pub: mailbox_pub,
                        peer_kem_ek: Vec::new(),
            };
        // `sessions[peer]` (the outbound map — what `send`/`queue` use) starts with the LARGER
        // seed on purpose: convergence must actually SWAP for the assertion below to hold. If
        // it started with the smaller seed already, a completely inert (no-op) sweep would
        // pass this check by doing nothing — the exact "passes by deleting/skipping state"
        // trap the project's testing rule warns against.
        peer.sessions.insert(peer_ik, mk_state([2u8; 32]));
        peer.inbound_sessions.insert(peer_ik, mk_state([1u8; 32]));

        let state = peer.export_state();
        let mut reloaded = mk_lone_peer();
        reloaded.import_state(state);

        // No mailbox traffic to fetch — this exercises ONLY the sweep at the top of
        // `receive()`, never `process_opener` (nothing arrives for it to process).
        reloaded.receive(NOW).unwrap();

        let out_seed = reloaded.sessions.get(&peer_ik).unwrap().drop_seed;
        let in_seed = reloaded.inbound_sessions.get(&peer_ik).unwrap().drop_seed;
        assert!(
            out_seed < in_seed,
            "the sweep must converge onto the SMALLER seed just as `process_opener`'s own \
             check would — `sessions[peer]` (what `send`/`queue` actually use) must end up \
             holding it regardless of which map the winner started in, and regardless of \
             whether the split was detected fresh or reloaded from disk"
        );
    }
}

/// R2-12: one receive pass is bounded in wall-clock time.
#[cfg(test)]
mod receive_budget_tests {
    use node::protocol::{AckRequest, AckResponse, BundleOpkRequest, BundleOpkResponse, FetchRequest, FetchResponse, PublishRequest, PublishResponse, Response, Transport, WireMessage};
use super::LoopbackMail;
    use karst_crypto::pqxdh::PreKeyBundle;
    use karst_crypto::pqxdh::Account;
    use karst_crypto::ratchet::Session;
    use admission::capability::{Capability, Quota, Scope};
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Duration;

    /// A relay that answers correctly but SLOWLY — the shape that costs the client dearly. A
    /// blackholed relay fails fast (the identity fetch's `?` aborts the pass in one connect
    /// timeout); one that accepts the connection and then takes its time does not, because box
    /// errors are collected rather than propagated. Counting fetches is what makes the assertion
    /// independent of how fast the machine running it happens to be.
    #[derive(Clone)]
    struct SlowTransport {
        inner: LoopbackMail,
        per_request: Duration,
        /// Which mailbox ADDRESSES the pass actually reached. Counting requests instead would
        /// count each box's `NeedCookie` retry as well, which says nothing about how much of the
        /// box set was covered.
        seen: Rc<RefCell<std::collections::BTreeSet<[u8; 32]>>>,
    }

    impl Transport for SlowTransport {
        fn send(&self, msg: &WireMessage, now: u64) -> Response {
            self.inner.send(msg, now)
        }
        fn fetch(&self, req: &FetchRequest, now: u64) -> FetchResponse {
            self.seen.borrow_mut().insert(req.mailbox);
            std::thread::sleep(self.per_request);
            self.inner.fetch(req, now)
        }
        fn ack(&self, req: &AckRequest, now: u64) -> AckResponse {
            self.inner.ack(req, now)
        }
        fn publish_bundle(&self, req: &PublishRequest, now: u64) -> PublishResponse {
            self.inner.publish_bundle(req, now)
        }
        fn fetch_bundle(&self, ik: &[u8; 32], now: u64) -> Result<Option<PreKeyBundle>, String> {
            self.inner.fetch_bundle(ik, now)
        }
        fn fetch_bundle_opk(
            &self,
            req: &BundleOpkRequest,
            now: u64,
        ) -> Result<BundleOpkResponse, String> {
            self.inner.fetch_bundle_opk(req, now)
        }
    }

    fn dev_cap() -> Capability {
        Capability {
            capability_id: [0xCD; 16],
            scope: Scope::MessageDelivery,
            quota: Quota { max_requests: 1_000_000, max_bytes: 1 << 30, window_secs: 600 },
            not_before: 0,
            not_after: u32::MAX,
            secret: [0x37; 32],
        }
    }

    /// A time far enough from the epoch origin that `poll_epochs`'s window does not collapse
    /// (at `now = 0` the previous epoch saturates onto the current one), and a multiple of the
    /// epoch length so it does not sit on a boundary.
    const NOW: u64 = 40 * crate::drop::DROP_EPOCH_SECS;

    /// How many DISTINCT boxes one session contributes to an ordinary (non-sweep) pass. Derived
    /// from the same function the code under test uses, so the expectation cannot drift away from
    /// the polling window by being written down twice.
    fn distinct_poll_epochs(now: u64) -> usize {
        let e = crate::drop::poll_epochs(now);
        e.iter().collect::<std::collections::BTreeSet<_>>().len()
    }

    /// A synthetic session under a fabricated peer IK. The receive side addresses a box from OUR
    /// own mailbox point and the session's `drop_seed`, so a session with no cryptographic history
    /// still produces a real box address to fetch — which is all this test needs.
    fn dummy_ik(i: u64) -> [u8; 32] {
        let mut ik = [0u8; 32];
        ik[..8].copy_from_slice(&i.to_le_bytes());
        ik[31] = 1;
        ik
    }

    /// The pass stops when its budget is spent instead of walking every box.
    ///
    /// Without the budget this loop is unbounded in time: `sessions × epochs` boxes, each its own
    /// connect + handshake + request, and a stalling relay makes every one of them pay a read
    /// timeout. Multi-homed, the relays are polled in sequence, so that one relay holds up all the
    /// others' mail — the head-of-line half of R2-12.
    #[test]
    fn a_slow_relay_cannot_stretch_one_receive_pass_without_end() {
        let relay_pub = x25519_dalek::PublicKey::from([7u8; 32]);
        let seen = Rc::new(RefCell::new(std::collections::BTreeSet::new()));
        let transport = SlowTransport {
            inner: LoopbackMail::default(),
            per_request: Duration::from_millis(20),
            seen: seen.clone(),
        };

        let mut peer = super::Peer::new(transport, Account::generate(), dev_cap(), relay_pub);
        const SESSIONS: u64 = 40;
        for i in 0..SESSIONS {
            peer.sessions.insert(
                dummy_ik(i),
                super::SessionState {
                    session: Session::init_sender([1u8; 32], [2u8; 32]),
                    pending_initial: None,
                    drop_seed: [i as u8; 32],
                    peer_mailbox_pub: [0u8; 32],
                peer_kem_ek: Vec::new(),
                },
            );
        }
        // Ordinary cycle, not a sweep: a sweep would fetch ten epochs per session instead of the
        // polling window's, which makes the same point with a bigger number but ties the test to
        // whichever branch `sweep_due` happens to take.
        peer.last_sweep = NOW;
        let boxes = 1 + (SESSIONS as usize) * distinct_poll_epochs(NOW); // + the identity mailbox
        peer.set_receive_budget(Duration::from_millis(120));

        let got = peer.receive(NOW);
        let done = seen.borrow().len();
        assert!(
            done < boxes / 2,
            "the pass walked {done} of {boxes} boxes — the budget did not stop it"
        );
        // Nothing was waiting, so the truncation is what the pass has to report: an unfetched box
        // is not an empty one, and reporting it as "no mail" would be a lie the caller acts on.
        match got {
            Err(e) => assert!(
                e.contains("receive budget"),
                "the truncation must name itself, not surface as some other fault: {e}"
            ),
            Ok(msgs) => panic!("a truncated, empty pass reported success with {} messages", msgs.len()),
        }
    }

    /// The cursor is IGNORED on the first sweep of a new epoch, so a sender whose clock is days
    /// SLOW is still reached (#147, found by the #233 revision).
    ///
    /// The cursor's soundness rests on sender clocks being close to ours: a sender deposits into
    /// ITS OWN epoch, and one running several days behind lands in a box below the cursor. Without
    /// this, that mail would rot at an address nobody asks for again — exactly the silent loss the
    /// full sweep window exists to prevent, reintroduced by an optimisation.
    ///
    /// Discriminating on the SECOND sweep inside one epoch versus the first sweep of the next: the
    /// cheap path must skip closed epochs, and the deep path must not.
    #[test]
    fn the_first_sweep_of_a_new_epoch_ignores_the_cursor() {
        let relay_pub = x25519_dalek::PublicKey::from([7u8; 32]);
        let seen = Rc::new(RefCell::new(std::collections::BTreeSet::new()));
        let transport = SlowTransport {
            inner: LoopbackMail::default(),
            per_request: Duration::from_millis(0),
            seen: seen.clone(),
        };
        let mut peer = super::Peer::new(transport, Account::generate(), dev_cap(), relay_pub);
        peer.sessions.insert(
            dummy_ik(1),
            super::SessionState {
                session: Session::init_sender([1u8; 32], [2u8; 32]),
                pending_initial: None,
                drop_seed: [5u8; 32],
                peer_mailbox_pub: [0u8; 32],
                peer_kem_ek: Vec::new(),
            },
        );

        peer.receive(NOW).expect("first sweep walks everything and sets the cursor");

        // A second sweep in the SAME epoch takes the cheap path.
        seen.borrow_mut().clear();
        peer.receive(NOW + crate::drop::SWEEP_INTERVAL_SECS).expect("second sweep");
        let shallow = seen.borrow().len();

        // The first sweep of the NEXT epoch walks the whole window again.
        seen.borrow_mut().clear();
        peer.receive(NOW + crate::drop::DROP_EPOCH_SECS).expect("deep sweep");
        let deep = seen.borrow().len();

        assert!(
            deep > shallow,
            "the first sweep of a new epoch visited {deep} boxes and the mid-epoch one {shallow} — \
             the cursor was not ignored, so a sender with a slow clock stays unreachable"
        );
        assert_eq!(
            deep,
            1 + crate::drop::sweep_epochs(NOW + crate::drop::DROP_EPOCH_SECS).len(),
            "a deep sweep should walk the identity mailbox plus the full window for the session"
        );
    }

    /// A message from a peer we HOLD a session with that our chain cannot open is counted and
    /// surfaced, not silently dropped (R2-11).
    ///
    /// That is the locally-visible symptom of a second device on this identity: the box address is
    /// derived from the session's own seed, so reaching it proves the sender holds that session,
    /// and our failure to open it proves something else advanced the chain. This vault cannot
    /// merge the two — there is no device identity in `PeerState` to merge along — but the user
    /// must not be left with "messages stop arriving" and nothing anywhere saying why.
    ///
    /// Discriminating against the case it must NOT fire on: an undecryptable payload for a peer we
    /// have NO session with is an ordinary stranger's garbage and stays silent.
    #[test]
    fn a_message_a_known_contact_sent_that_we_cannot_open_is_reported() {
        let relay_pub = x25519_dalek::PublicKey::from([7u8; 32]);
        let mut peer = super::Peer::new(
            LoopbackMail::default(),
            Account::generate(),
            dev_cap(),
            relay_pub,
        );
        let known = dummy_ik(1);
        peer.sessions.insert(
            known,
            super::SessionState {
                session: Session::init_sender([1u8; 32], [2u8; 32]),
                pending_initial: None,
                drop_seed: [5u8; 32],
                peer_mailbox_pub: [0u8; 32],
                peer_kem_ek: Vec::new(),
            },
        );
        // A ratchet message this session cannot open — what a diverged chain produces.
        let garbage = karst_crypto::ratchet::RatchetMessage {
            header: karst_crypto::ratchet::Header { dh: [9u8; 32], pn: 0, n: 0, salt: [0u8; 16] },
            ciphertext: vec![0u8; 32],
        };
        let payload = node::protocol::Payload::Session(
            node::protocol::SessionEnvelope::Ratchet(garbage),
        );

        assert!(peer.process_for_peer(&known, &payload).is_none(), "it genuinely cannot be opened");
        assert_eq!(peer.take_out_of_step(), 1, "a known contact's unopenable message must be told");
        assert_eq!(peer.take_out_of_step(), 0, "reading the count resets it, so polls do not sum");

        // The control: the SAME payload attributed to a peer we have no session with is an
        // ordinary stranger's garbage and must stay quiet.
        let stranger = dummy_ik(2);
        assert!(peer.process_for_peer(&stranger, &payload).is_none());
        assert_eq!(peer.take_out_of_step(), 0, "a stranger's garbage must not raise this");
    }

    /// The sweep does not re-walk epochs nothing can deposit into any more (#147).
    ///
    /// A sender deposits into ITS OWN epoch, at most `FUTURE_SLACK_EPOCHS` ahead of ours, so once
    /// our epoch has moved past `E + slack` nothing can ever land in epoch `E` again. Before the
    /// cursor, every sweep re-fetched the full ten-epoch window for every session — round trips
    /// guaranteed to come back empty, multiplied by the session table.
    ///
    /// Discriminating on the SECOND sweep, not the first: the first legitimately walks the whole
    /// window (nothing is known closed yet), so a test that only looked at one pass would pass
    /// with the cursor removed.
    #[test]
    fn a_second_sweep_skips_the_epochs_that_can_no_longer_receive() {
        let relay_pub = x25519_dalek::PublicKey::from([7u8; 32]);
        let seen = Rc::new(RefCell::new(std::collections::BTreeSet::new()));
        let transport = SlowTransport {
            inner: LoopbackMail::default(),
            per_request: Duration::from_millis(0),
            seen: seen.clone(),
        };
        let mut peer = super::Peer::new(transport, Account::generate(), dev_cap(), relay_pub);
        const SESSIONS: u64 = 4;
        for i in 0..SESSIONS {
            peer.sessions.insert(
                dummy_ik(i),
                super::SessionState {
                    session: Session::init_sender([1u8; 32], [2u8; 32]),
                    pending_initial: None,
                    drop_seed: [i as u8; 32],
                    peer_mailbox_pub: [0u8; 32],
                peer_kem_ek: Vec::new(),
                },
            );
        }

        // First sweep: `last_sweep` is 0 and NOW is far from it, so the full window is walked.
        peer.receive(NOW).expect("first sweep");
        let first = seen.borrow().len();
        let window = crate::drop::sweep_epochs(NOW).len();
        assert!(
            first > 1 + (SESSIONS as usize) * 3,
            "precondition: the first sweep really did walk the wide window ({first} boxes, \
             {window} epochs)"
        );

        // Second sweep, one interval later and still inside the same epoch: everything the first
        // pass closed is now off the list.
        seen.borrow_mut().clear();
        let later = NOW + crate::drop::SWEEP_INTERVAL_SECS;
        peer.receive(later).expect("second sweep");
        let second = seen.borrow().len();
        assert!(
            second < first,
            "the second sweep walked {second} boxes, the first {first} — the cursor closed nothing"
        );
        // Concretely: only the epochs that are still open, plus the identity mailbox.
        let open = crate::drop::sweep_epochs(later)
            .into_iter()
            .filter(|e| *e > crate::drop::epoch_of(later) - crate::drop::FUTURE_SLACK_EPOCHS - 1)
            .count();
        assert_eq!(
            second,
            1 + (SESSIONS as usize) * open,
            "the second sweep should visit exactly the still-open epochs of each session"
        );
    }

    /// The control arm: with a budget it can meet, the SAME pass fetches every box. Without this,
    /// a bug that stopped after one box would pass the test above.
    #[test]
    fn an_unhurried_pass_still_visits_every_box() {
        let relay_pub = x25519_dalek::PublicKey::from([7u8; 32]);
        let seen = Rc::new(RefCell::new(std::collections::BTreeSet::new()));
        let transport = SlowTransport {
            inner: LoopbackMail::default(),
            per_request: Duration::from_millis(0),
            seen: seen.clone(),
        };

        let mut peer = super::Peer::new(transport, Account::generate(), dev_cap(), relay_pub);
        const SESSIONS: u64 = 8;
        for i in 0..SESSIONS {
            peer.sessions.insert(
                dummy_ik(i),
                super::SessionState {
                    session: Session::init_sender([1u8; 32], [2u8; 32]),
                    pending_initial: None,
                    drop_seed: [i as u8; 32],
                    peer_mailbox_pub: [0u8; 32],
                peer_kem_ek: Vec::new(),
                },
            );
        }
        peer.last_sweep = NOW;
        // Identity mailbox + one box per (session × poll epoch).
        let expected = 1 + (SESSIONS as usize) * distinct_poll_epochs(NOW);

        let got = peer.receive(NOW);
        assert_eq!(seen.borrow().len(), expected, "an unhurried pass skipped boxes");
        assert!(
            got.is_ok(),
            "an unhurried empty pass must not report a fault: {}",
            got.err().unwrap_or_default()
        );
    }
}

/// A LOOPBACK mailbox for unit tests: deposits go into a map, fetches drain it. No admission, no
/// quota, no relay (#143).
///
/// Two reasons this exists rather than the relay's in-memory transport. First, the relay is
/// another crate now, and a dev-dependency on it does NOT reach a unit test: Cargo builds this
/// crate twice — with and without `cfg(test)` — so a relay type implements the `Transport` trait
/// from the OTHER build. Same name, different type; no import fixes it.
///
/// Second, and more to the point: these tests are about the CLIENT's session logic — routing
/// arithmetic, the session-table cap, split-session convergence, the receive budget. What they
/// need from the far end is that a deposit comes back on a fetch. Admission, cookies and quota
/// were incidental scaffolding, and testing against a full relay meant a failure in the relay
/// could red a client test for reasons the test does not name. The relay's own behaviour is
/// covered by the integration tests in `tests/`, where a real one is available.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct LoopbackMail {
    boxes: std::rc::Rc<std::cell::RefCell<HashMap<[u8; 32], Vec<Payload>>>>,
    #[allow(clippy::type_complexity)]
    bundles: std::rc::Rc<
        std::cell::RefCell<HashMap<[u8; 32], (PreKeyBundle, Vec<karst_crypto::pqxdh::SignedOpk>)>>,
    >,
}

#[cfg(test)]
impl Transport for LoopbackMail {
    fn send(&self, msg: &WireMessage, _now: u64) -> Response {
        self.boxes.borrow_mut().entry(msg.recipient).or_default().push(msg.payload.clone());
        Response::Accepted
    }
    fn fetch(&self, req: &FetchRequest, _now: u64) -> FetchResponse {
        let drained = self.boxes.borrow_mut().remove(&req.mailbox).unwrap_or_default();
        FetchResponse::Fetched(drained)
    }
    fn publish_bundle(&self, req: &PublishRequest, _now: u64) -> PublishResponse {
        self.bundles
            .borrow_mut()
            .insert(req.bundle.ik_pub, (req.bundle.clone(), req.opks.clone()));
        PublishResponse::Published
    }
    fn fetch_bundle(&self, ik: &[u8; 32], _now: u64) -> Result<Option<PreKeyBundle>, String> {
        Ok(self.bundles.borrow().get(ik).map(|(b, _)| b.clone()))
    }
    /// One-time prekeys are handed out ONE per fetch and never twice — the property the client
    /// side depends on, and the only part of the relay's bundle handling these tests care about.
    fn fetch_bundle_opk(
        &self,
        req: &BundleOpkRequest,
        _now: u64,
    ) -> Result<BundleOpkResponse, String> {
        let mut all = self.bundles.borrow_mut();
        Ok(match all.get_mut(&req.ik) {
            None => BundleOpkResponse::Bundle(None),
            Some((bundle, opks)) => {
                let mut out = bundle.clone();
                out.opk = opks.pop();
                BundleOpkResponse::Bundle(Some(out))
            }
        })
    }
}

/// **The padding cannot be bypassed** — enforced by scanning this file, not by remembering.
///
/// PRIV-1 rests on an exhaustive claim: EVERY ratchet plaintext is a fixed-size block. Exhaustive
/// claims do not survive as conventions. Before `Peer::open_padded` existed there were six
/// `Session::decrypt` sites here, and adding a seventh is the natural thing to do while writing a
/// new receive path — it compiles, the tests pass, and the message even arrives, because the
/// padding is only a prefix and some zeros. What breaks is the property: that class of message
/// carries its true length again, and the relay reads it.
#[cfg(test)]
mod pad_is_not_bypassed {
    /// Exactly one decrypt site, and it is the one that unpads.
    ///
    /// Discriminating: call the ratchet's decrypt on a message anywhere else in this file — the
    /// exact call this counts — and it goes red. (Spelled out rather than quoted, because a quoted
    /// example would be a second match and this test would fail on its own documentation.)
    #[test]
    fn a_ratchet_message_is_opened_in_one_place_only() {
        let src = include_str!("peer.rs");
        // Split so this test does not match itself when the file is scanned.
        let needle = concat!(".decrypt", "(msg)");
        let sites = src.matches(needle).count();
        assert_eq!(
            sites, 1,
            "found {sites} ratchet-decrypt sites in peer.rs; there must be exactly ONE \
             (`Peer::open_padded`, which strips the fixed-size block afterwards). A second site \
             would deliver messages perfectly well while restoring the plaintext-length signal to \
             the relay for whatever class of message it handles — see `crate::pad`."
        );
    }

    /// The send side, mirrored: one encrypt site, and it pads.
    #[test]
    fn a_ratchet_plaintext_is_produced_in_one_place_only() {
        let src = include_str!("peer.rs");
        let encrypts = src.matches(concat!("session.encrypt", "(")).count();
        assert_eq!(
            encrypts, 1,
            "found {encrypts} ratchet-encrypt sites in peer.rs; there must be exactly ONE \
             (`Peer::encrypt_next`, which pads first). An unpadded send site is the same leak as \
             an unpadded receive site, arriving from the other direction."
        );
    }

    /// Cover traffic must be the length of a real padded message, derived from the same constant.
    ///
    /// A literal here would drift the first time `PADDED_LEN` moves, and the drift is silent: loops
    /// keep working, they just become identifiable — which is the failure mode where a relay drops
    /// real mail and returns the loops, so the drop detector reports all-clear.
    #[test]
    fn cover_traffic_is_sized_from_the_padding_constant_not_a_literal() {
        let src = include_str!("peer.rs");
        assert!(
            src.contains("crate::pad::PADDED_LEN + 16"),
            "`send_loop` no longer sizes its ciphertext from `pad::PADDED_LEN`. A cover message \
             whose length differs from a real one labels every loop for the relay."
        );
    }
}

/// **The property PRIV-1 actually claims**: what the relay reads is the same size either way.
///
/// The tests inside `crate::pad` prove the padding function is uniform. This proves the PRODUCT is
/// — that a one-byte reply and a maximum-length message leave `encrypt_next` as the same number of
/// bytes on the ciphertext the relay measures (`Payload::approx_len`). That is the only statement
/// worth making to a user, and it is the one that would go quietly false if a future send path
/// skipped the padding.
///
/// DISCRIMINATING: remove the `pad::pad` call in `encrypt_next` and this goes red immediately,
/// reporting both sizes.
#[cfg(test)]
mod the_relay_learns_nothing_from_size {
    use super::LoopbackMail;
    use admission::capability::{Capability, Quota, Scope};
    use karst_crypto::pqxdh::Account;
    use node::protocol::{Payload, SessionEnvelope};
    use x25519_dalek::PublicKey;

    fn dev_cap() -> Capability {
        Capability {
            capability_id: [0xCC; 16],
            scope: Scope::MessageDelivery,
            quota: Quota { max_requests: 100_000, max_bytes: 1 << 30, window_secs: 600 },
            not_before: 0,
            not_after: u32::MAX,
            secret: [0x35; 32],
        }
    }

    fn mk_peer(t: &LoopbackMail) -> super::Peer<LoopbackMail> {
        super::Peer::new(t.clone(), Account::generate(), dev_cap(), PublicKey::from([7u8; 32]))
    }

    /// The length the RELAY sees, taken from the relay's own function rather than reimplemented —
    /// so this test cannot disagree with the size gate about what a payload measures.
    fn seen_by_relay(env: SessionEnvelope) -> usize {
        Payload::Session(env).approx_len()
    }

    #[test]
    fn one_byte_and_a_full_length_message_are_the_same_size_on_the_wire() {
        let transport = LoopbackMail::default();
        let mut bob = mk_peer(&transport);
        bob.publish(0);
        let bob_ik = bob.identity();

        let mut alice = mk_peer(&transport);
        alice.connect(&bob_ik, 0).expect("PQXDH against a published bundle");

        // Leave the opener state before comparing ORDINARY messages — openers are their own class
        // by design, and `pending_initial` only clears once a transmit is accepted. Getting this
        // wrong is not hypothetical: the first draft of this test skipped the transmit, so all
        // three "ordinary" messages were still openers and the common `Ratchet` class — the one
        // almost every message belongs to — went untested while the test passed.
        let opener = alice.encrypt_next(&bob_ik, &[b'x'; 1]).expect("opener");
        alice.transmit_envelope(&bob_ik, opener, 0);

        let first = alice.encrypt_next(&bob_ik, b"k").expect("tiny");
        assert!(
            matches!(first, SessionEnvelope::Ratchet(_)),
            "this test is supposed to be measuring the ORDINARY class; it is still producing              openers, so it proves nothing about the messages users actually send"
        );
        let tiny = seen_by_relay(first);
        let large = seen_by_relay(
            alice
                .encrypt_next(&bob_ik, &vec![b'x'; crate::pad::MAX_PAYLOAD])
                .expect("a full-length message still fits one envelope"),
        );
        let empty = seen_by_relay(alice.encrypt_next(&bob_ik, b"").expect("empty"));

        assert_eq!(
            (tiny, large),
            (empty, empty),
            "the relay can still tell message sizes apart: 1 byte → {tiny}, \
             {} bytes → {large}, empty → {empty}. Every ratchet envelope must measure the same, \
             or the size channel PRIV-1 closed is open again.",
            crate::pad::MAX_PAYLOAD
        );
    }

    /// And the opener's class is flat too — a first contact carrying a long message must not be
    /// distinguishable from one carrying a short greeting.
    #[test]
    fn a_short_and_a_long_first_contact_are_the_same_size() {
        let transport = LoopbackMail::default();
        let mut bob = mk_peer(&transport);
        bob.publish(0);
        let bob_ik = bob.identity();

        let mut chatty = mk_peer(&transport);
        chatty.connect(&bob_ik, 0).expect("agree");
        let long = seen_by_relay(
            chatty
                .encrypt_next(&bob_ik, &vec![b'x'; crate::pad::MAX_PAYLOAD])
                .expect("full-length opener"),
        );

        let mut terse = mk_peer(&transport);
        terse.connect(&bob_ik, 0).expect("agree");
        let short = seen_by_relay(terse.encrypt_next(&bob_ik, b"hi").expect("short opener"));

        assert_eq!(
            long, short,
            "a first contact still leaks how much was written: {long} vs {short} bytes"
        );
    }
}

/// **A batch carries ONE opener, not one per payload.**
///
/// `pending_initial` clears on an ACCEPTED transmit, which is right for the immediate-send path but
/// wrong for a batch: `send_session_batch` encrypts every payload before flushing any of them, so
/// nothing has been accepted yet and every envelope came out as an opener with its own full copy of
/// the key agreement. Nobody noticed because it still WORKED — a six-part avatar's six openers came
/// to about 15.9 KB against a 16 KB fetch page, so it fit by ~96 bytes. That is not a margin, it is
/// a coincidence, and PRIV-3's outer ML-KEM ciphertext spent it: the transfer started arriving in
/// two polls instead of one, which surfaces as an avatar that silently never assembles.
///
/// Pinned here rather than left to the integration test that caught it, because the integration test
/// only fails once the waste is large enough to cross a page boundary. This fails as soon as the
/// waste exists.
#[cfg(test)]
mod a_batch_repeats_no_key_agreement {
    use super::LoopbackMail;
    use admission::capability::{Capability, Quota, Scope};
    use karst_crypto::pqxdh::Account;
    use node::protocol::SessionEnvelope;
    use x25519_dalek::PublicKey;

    fn dev_cap() -> Capability {
        Capability {
            capability_id: [0xCC; 16],
            scope: Scope::MessageDelivery,
            quota: Quota { max_requests: 100_000, max_bytes: 1 << 30, window_secs: 600 },
            not_before: 0,
            not_after: u32::MAX,
            secret: [0x35; 32],
        }
    }

    /// Queue six payloads the way a multi-part transfer does, and require exactly one opener.
    ///
    /// DISCRIMINATING: remove the `pending_initial = None` in `Peer::queue` and this reports six.
    #[test]
    fn only_the_first_queued_envelope_is_an_opener() {
        let transport = LoopbackMail::default();
        let mk = |t: &LoopbackMail| {
            super::Peer::new(t.clone(), Account::generate(), dev_cap(), PublicKey::from([7u8; 32]))
        };
        let mut bob = mk(&transport);
        bob.publish(0);
        let bob_ik = bob.identity();

        let mut alice = mk(&transport);
        alice.connect(&bob_ik, 0).expect("PQXDH against a published bundle");
        for i in 0..6u8 {
            alice.queue(&bob_ik, &[i; 32], 0).expect("queues");
        }

        let openers = alice
            .outbox_envelopes_for_test()
            .iter()
            .filter(|e| matches!(e, SessionEnvelope::InitialSealed { .. }))
            .count();
        assert_eq!(
            openers, 1,
            "a six-payload batch produced {openers} openers. Each carries a full key agreement — \
             after PRIV-3 that is ~3.4 KB apiece — so the redundant copies overflow the fixed fetch \
             page and split a transfer across polls, which reaches the user as a file or avatar \
             that never finishes assembling."
        );
    }
}

/// **The same queued message does not reach two relays byte-identical** (PRIV-4).
///
/// `crate::veil`'s own tests prove the primitive. This proves the PEER applies it per relay — the
/// link that actually matters, and the one that would silently vanish if the veil moved to encrypt
/// time (where "which relay" is not yet known) instead of transmit time.
#[cfg(test)]
mod a_message_looks_different_at_each_relay {
    use super::LoopbackMail;
    use admission::capability::{Capability, Quota, Scope};
    use karst_crypto::pqxdh::Account;
    use node::protocol::SessionEnvelope;
    use x25519_dalek::PublicKey;

    fn dev_cap() -> Capability {
        Capability {
            capability_id: [0xCC; 16],
            scope: Scope::MessageDelivery,
            quota: Quota { max_requests: 100_000, max_bytes: 1 << 30, window_secs: 600 },
            not_before: 0,
            not_after: u32::MAX,
            secret: [0x35; 32],
        }
    }

    fn veiled_bytes(env: SessionEnvelope) -> (Vec<u8>, Vec<u8>) {
        match env {
            SessionEnvelope::Veiled { nonce, inner } => (nonce.to_vec(), inner),
            _ => panic!("an ordinary message must ride the wire veiled"),
        }
    }

    /// DISCRIMINATING: have `veiled_for_this_relay` return the envelope untouched and this reports
    /// the panic above; veil with a relay-independent nonce and the two byte strings match.
    #[test]
    fn two_relays_receive_the_same_message_as_different_bytes() {
        let transport = LoopbackMail::default();
        let mut bob = super::Peer::new(
            transport.clone(),
            Account::generate(),
            dev_cap(),
            PublicKey::from([7u8; 32]),
        );
        bob.publish(0);
        let bob_ik = bob.identity();

        // One session, one message — then the SAME message offered to two different relays, which
        // is exactly what failover does with a queued envelope.
        let mut alice = super::Peer::new(
            transport.clone(),
            Account::generate(),
            dev_cap(),
            PublicKey::from([7u8; 32]),
        );
        alice.connect(&bob_ik, 0).expect("PQXDH against a published bundle");
        let opener = alice.encrypt_next(&bob_ik, b"hi").expect("opener");
        alice.transmit_envelope(&bob_ik, opener, 0);
        let env = alice.encrypt_next(&bob_ik, b"the same queued message").expect("ratchet");

        let routing = alice.sessions.get(&bob_ik).map(|st| (st.drop_seed, st.peer_mailbox_pub));
        let at_a = alice
            .veiled_for_this_relay(&bob_ik, env.clone(), routing)
            .expect("veils for relay A");
        // A second `Peer` differing ONLY in which relay it talks to.
        let mut alice_b = super::Peer::new(
            transport,
            Account::generate(),
            dev_cap(),
            PublicKey::from([0xB2u8; 32]),
        );
        alice_b.import_state(alice.export_state());
        let at_b = alice_b
            .veiled_for_this_relay(&bob_ik, env, routing)
            .expect("veils for relay B");

        let (na, va) = veiled_bytes(at_a);
        let (nb, vb) = veiled_bytes(at_b);
        assert_ne!(na, nb, "the nonce did not vary by relay");
        assert_ne!(
            va, vb,
            "one queued message reached two relays as IDENTICAL bytes. Two operators comparing logs \
             then match on equality and learn it is one message — the join PRIV-4 exists to remove, \
             and the one multi-homing hands them for free."
        );
    }

    /// An OPENER is deliberately not veiled — named here so the limit is a decision on the record
    /// rather than a gap someone discovers. A recipient meeting a stranger holds no session, so it
    /// could not derive the key.
    #[test]
    fn an_opener_is_left_alone_because_the_recipient_has_no_key_yet() {
        let transport = LoopbackMail::default();
        let mut bob = super::Peer::new(
            transport.clone(),
            Account::generate(),
            dev_cap(),
            PublicKey::from([7u8; 32]),
        );
        bob.publish(0);
        let bob_ik = bob.identity();
        let mut alice =
            super::Peer::new(transport, Account::generate(), dev_cap(), PublicKey::from([7u8; 32]));
        alice.connect(&bob_ik, 0).expect("agree");
        let opener = alice.encrypt_next(&bob_ik, b"first contact").expect("opener");
        let routing = alice.sessions.get(&bob_ik).map(|st| (st.drop_seed, st.peer_mailbox_pub));
        assert!(
            matches!(
                alice.veiled_for_this_relay(&bob_ik, opener, routing).expect("passes through"),
                SessionEnvelope::InitialSealed { .. }
            ),
            "an opener was veiled; the recipient has no session yet and could never unveil it"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// PERF-4b: the box fan-out. Tests for the executor itself, where the property lives.
// ---------------------------------------------------------------------------------------------
#[cfg(test)]
mod fan_out {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A transport that measures CONCURRENCY: it records the high-water mark of requests in flight
    /// at once. `Mutex`-based rather than `Rc`/`RefCell` on purpose — the parallel executor needs
    /// `T: Sync`, so the in-memory test transports used elsewhere in this file cannot exercise it.
    #[derive(Default)]
    struct ConcurrencyProbe {
        live: AtomicUsize,
        high_water: AtomicUsize,
        served: AtomicUsize,
    }

    impl Transport for ConcurrencyProbe {
        fn send(&self, _m: &WireMessage, _now: u64) -> Response {
            Response::Rejected("probe".into())
        }
        fn fetch(&self, req: &FetchRequest, _now: u64) -> FetchResponse {
            let now_live = self.live.fetch_add(1, Ordering::SeqCst) + 1;
            self.high_water.fetch_max(now_live, Ordering::SeqCst);
            // Long enough that genuinely concurrent workers overlap, short enough to keep the test
            // quick. Wall-clock is NOT what is asserted — only the high-water mark is.
            std::thread::sleep(std::time::Duration::from_millis(30));
            self.live.fetch_sub(1, Ordering::SeqCst);
            self.served.fetch_add(1, Ordering::SeqCst);
            // Echo the mailbox back so the caller can check the ORDER of the answers.
            FetchResponse::Fetched(vec![Payload::Skeleton(karst_crypto::seal::SkeletonSeal {
                ephemeral_pub: req.mailbox,
                kem_ct: Vec::new(),
                nonce: [0u8; 12],
                ciphertext: req.mailbox.to_vec(),
            })])
        }
    }

    fn prepared(n: usize) -> Vec<PreparedFetch> {
        (0..n)
            .map(|i| {
                let mut mailbox = [0u8; 32];
                mailbox[0] = i as u8;
                PreparedFetch {
                    req: FetchRequest {
                        mailbox,
                        client_addr: vec![i as u8],
                        carrier_id: Vec::new(),
                        cookie: None,
                        proof: [0u8; 16],
                        own_proof: Vec::new(),
                    },
                    client_addr: vec![i as u8],
                    scope: None,
                    cookie: None,
                }
            })
            .collect()
    }

    fn echoed_index(r: &FetchResponse) -> u8 {
        match r {
            FetchResponse::Fetched(ps) => match &ps[0] {
                Payload::Skeleton(s) => s.ciphertext[0],
                _ => panic!("probe returns a skeleton payload"),
            },
            _ => panic!("the probe always answers Fetched"),
        }
    }

    /// **The property this slice exists for.** With the fan-out, more than one box is in flight at
    /// once; sequentially, never more than one.
    ///
    /// Asserted on a high-water COUNTER, not on wall-clock time: a timing assertion would be flaky
    /// on a loaded machine and would pass for the wrong reason on a fast one.
    ///
    /// Verified discriminating by swapping `Parallel` for `Sequential` here — the high-water mark
    /// drops to 1 and the assertion reds, which is exactly the mistake being guarded against
    /// (a "parallel" path that quietly runs one at a time).
    #[test]
    fn the_fan_out_really_overlaps_and_the_sequential_path_never_does() {
        let reqs = prepared(8);

        let probe = ConcurrencyProbe::default();
        let par = Parallel::new(DirectCarrier::inspect(None, &[]).expect("direct"), 4);
        let out = par.run(&probe, &reqs, 0);
        assert_eq!(out.len(), reqs.len(), "one answer per request");
        assert_eq!(probe.served.load(Ordering::SeqCst), 8, "every box was actually fetched");
        assert!(
            probe.high_water.load(Ordering::SeqCst) > 1,
            "the fan-out never had two requests in flight — it is parallel in name only"
        );

        let probe2 = ConcurrencyProbe::default();
        let out2 = Sequential.run(&probe2, &reqs, 0);
        assert_eq!(out2.len(), reqs.len());
        assert_eq!(
            probe2.high_water.load(Ordering::SeqCst),
            1,
            "the sequential path must never overlap requests"
        );
    }

    /// Answers come back in REQUEST order, whatever order the workers finish in.
    ///
    /// Load-bearing rather than cosmetic: the caller absorbs responses in box order and
    /// `pending_ack` evicts its OLDEST entry at the cap, so completion-order results would change
    /// which receipt is dropped — that is mail nobody deletes, or mail deleted twice.
    #[test]
    fn answers_come_back_in_request_order() {
        let reqs = prepared(8);
        let probe = ConcurrencyProbe::default();
        let par = Parallel::new(DirectCarrier::inspect(None, &[]).expect("direct"), 8);
        let out = par.run(&probe, &reqs, 0);
        let order: Vec<u8> = out.iter().map(echoed_index).collect();
        assert_eq!(order, (0..8).collect::<Vec<u8>>(), "responses are not in request order");
    }

    /// The #280 prohibition, as a type: the witness cannot be obtained under a proxy or a
    /// non-direct route, so `Parallel` cannot be constructed there at all.
    #[test]
    fn the_witness_refuses_anything_that_is_not_a_plain_direct_dial() {
        assert!(DirectCarrier::inspect(None, &[]).is_some(), "a plain direct dial fans out");
        assert!(
            DirectCarrier::inspect(None, &["direct".into()]).is_some(),
            "an explicit direct route is still direct"
        );
        assert!(DirectCarrier::inspect(Some("127.0.0.1:9050"), &[]).is_none(), "a proxy refuses");
        assert!(
            DirectCarrier::inspect(None, &["wss".into()]).is_none(),
            "a non-direct carrier refuses"
        );
        assert!(
            DirectCarrier::inspect(None, &["mixnet".into(), "direct".into()]).is_none(),
            "one non-direct route among several is enough to refuse"
        );
    }

    /// A single box takes the sequential path even under `Parallel` — spawning a thread scope to
    /// run one request is pure overhead, and the common case (one session, one epoch) is one box.
    #[test]
    fn one_box_does_not_spawn_anything() {
        let reqs = prepared(1);
        let probe = ConcurrencyProbe::default();
        let par = Parallel::new(DirectCarrier::inspect(None, &[]).expect("direct"), 8);
        let out = par.run(&probe, &reqs, 0);
        assert_eq!(out.len(), 1);
        assert_eq!(probe.high_water.load(Ordering::SeqCst), 1);
    }
}

/// Routing-chain separation, pinned as a property rather than trusted to the taxonomy (PRIV-2).
///
/// The slice this comes from asked for one routing chain per session. What the code does is
/// FINER — a chain per box per epoch, and a further split by leg — so the requirement is met by
/// construction rather than by a rule someone follows. These tests exist because "met by
/// construction" is a claim about a `match` arm that anyone can widen in a hurry.
#[cfg(test)]
mod routing_separation {
    use super::*;

    /// A scope is derived from the handle, so two handles cannot share a circuit unless they are
    /// the same handle. The interesting pairs are the ones a reasonable person might have merged.
    fn distinct(a: &Handle, b: &Handle, what: &str) {
        assert!(a != b, "{what}: these two would share a routing chain");
    }

    /// Two boxes of the same peer in DIFFERENT epochs are different handles, so a chain does not
    /// span an epoch boundary. Without this, rotating the box means nothing: the relay watches one
    /// source address walk from the old box to the new one and stitches the rotation back together.
    #[test]
    fn a_chain_does_not_span_an_epoch_boundary() {
        distinct(&Handle::Box([7u8; 32], 1), &Handle::Box([7u8; 32], 2), "one box across two epochs");
    }

    /// Two different boxes in the same epoch are different handles. This is the per-session
    /// separation the slice asked for, and it holds at box granularity — finer than per-session,
    /// because a session's box rotates within its life.
    #[test]
    fn two_peers_never_share_a_chain_within_an_epoch() {
        distinct(&Handle::Box([1u8; 32], 5), &Handle::Box([2u8; 32], 5), "two peers in one epoch");
    }

    /// The deposit leg and the fetch leg of cover traffic are separate handles. Merging them is
    /// the specific mistake that makes cover detectable: a loop is both parties, so one shared
    /// chain would show the relay one source address on both legs while a real message shows two.
    /// A relay that can spot loops can drop real mail and return the loops, and the drop detector
    /// reports all-clear while messages vanish.
    #[test]
    fn a_loops_two_legs_never_share_a_chain() {
        distinct(&Handle::LoopSend(3), &Handle::LoopRecv(3), "a loop's two legs");
    }

    /// A loop and a real session never share a handle either, in any epoch — otherwise cover
    /// traffic would ride the chain it is supposed to be hiding among, and be identifiable by
    /// exactly the thing that was meant to hide it.
    #[test]
    fn cover_traffic_never_shares_a_chain_with_real_mail() {
        distinct(&Handle::LoopSend(4), &Handle::Box([9u8; 32], 4), "cover send vs real mail");
        distinct(&Handle::LoopRecv(4), &Handle::Box([9u8; 32], 4), "cover recv vs real mail");
    }

    /// The identity mailbox and an opener are separate from everything. The identity mailbox is
    /// the emergency channel and the one long-lived address a client has; sharing its chain with
    /// a rotating box would tie every rotation back to the stable name.
    #[test]
    fn the_long_lived_identity_channel_is_isolated_from_rotating_boxes() {
        distinct(&Handle::Identity, &Handle::Box([1u8; 32], 1), "identity vs a rotating box");
        distinct(&Handle::Identity, &Handle::Opener([1u8; 32]), "identity vs an opener");
        distinct(&Handle::Opener([1u8; 32]), &Handle::Box([1u8; 32], 1), "opener vs a box");
    }
}
