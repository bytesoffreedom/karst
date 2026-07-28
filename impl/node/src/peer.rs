//! §2.1 сессионный peer: PQXDH-согласование + Double Ratchet поверх реального
//! пути сообщения (admission §7 → mailbox → fetch-auth). Первое, когда §2.1
//! перестаёт быть островом и становится E2E in-process пути.
//!
//! Peer одновременно ОТПРАВИТЕЛЬ и ПОЛУЧАТЕЛЬ (ratchet-сессия двунаправленна):
//! `connect` устанавливает сессию к получателю по его bundle; `send` шлёт по ней;
//! `receive` забирает свой mailbox и продвигает сессии. Одна сессия на пир-пару
//! (ключ — долговременный IK пира), обслуживает оба направления.
//!
//! # Границы среза (названы, не тихие):
//! - **сокет/CLI НЕ используют этот путь** — там процесс-на-вызов, ratchet
//!   требует персистентности `Session` между запусками (serde + Store) — отдельный
//!   срез. Здесь сессия живёт в памяти между вызовами;
//! - **§12 bundle publish/fetch** реализован (`publish`/`connect`): relay хранит
//!   и отдаёт bundle. Но relay — НЕ якорь личности: подлинность `peer_ik`
//!   проверяется вне канала (OOB/TOFU) — внешняя стена. `connect` сверяет, что
//!   отданный bundle заявляет запрошенный IK; подмена только prekey/KEM →
//!   fail-closed; подмена самого IK при OOB-непроверенном `peer_ik` → MITM;
//! - **надёжность первой доставки предполагается**: цепочка продвигается
//!   безусловно (см. `send` — иначе keystream-reuse), поэтому недоставленное
//!   сообщение = gap. Установить сессию может лишь `Initial` c n=0; если он не
//!   прошёл, сессия мертва до `connect` заново (first-delivery-must-succeed).
//!   Retransmit-без-gap (дослать те же байты) и prologue-повтор (Signal) —
//!   отдельный reliability-срез;
//! - **повторный `Initial`** от уже известного пира НЕ переустанавливает живую
//!   сессию (защита от отбрасывания состояния) — расшифровка идёт на существующей;
//! - **маршрутизация `Ratchet` — trial-decryption** по всем сессиям (безопасно:
//!   `decrypt` транзакционен, промах не двигает чужую сессию). Sealed-sender/
//!   session-id для явной адресации без утечки метаданных — отдельный срез;
//! - **только 1:1.**

use std::collections::HashMap;

use admission::capability::Capability;
use admission::cookie::Cookie;
use x25519_dalek::PublicKey;

use crate::node::{
    fetch_proof, payload_id, publish_proof, AckRequest, AckResponse, BundleOpkRequest,
    BundleOpkResponse, FetchRequest, FetchResponse, Payload, PublishRequest, PublishResponse,
    Response, SessionEnvelope, Transport, WireMessage,
};
use crate::pqxdh::{initiate_key_agreement, Account, KeyAgreement, PreKeyBundle};

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
    /// 4-DH: a one-time prekey was used, so the first message stays secret even if the peer's
    /// long-lived signed prekey secret is compromised later.
    Full,
    /// 3-DH: the bundle carried no one-time prekey. The session is still end-to-end encrypted and
    /// heals on the first DH ratchet step; what is lost is forward secrecy for the FIRST message
    /// against a later compromise of the long-lived prekey.
    NoOneTimePrekey,
}
use crate::ratchet::{RatchetMessage, Session, SessionSnapshot};
use crate::seal::Identity;

/// 32 fresh random bytes from the OS CSPRNG (pseudonyms, request nonces).
fn random32() -> [u8; 32] {
    use chacha20poly1305::aead::rand_core::RngCore;
    let mut b = [0u8; 32];
    chacha20poly1305::aead::OsRng.fill_bytes(&mut b);
    b
}

/// Расшифрованное входящее сообщение с АТРИБУЦИЕЙ отправителя. `sender` = его
/// долговременный IK (PQXDH-аутентифицированный: только держатель приватного IK
/// согласовал бы root_key этой сессии). Позволяет UI/CLI разложить входящие по
/// чатам — это НЕ новая крипта, а проброс наружу того, что сессия уже знает.
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

/// Состояние сессии к одному пиру. `pending_initial` = `Some`, пока первый
/// `Initial`-конверт не доставлен (сторона-инициатор); затем `None` → шлём `Ratchet`.
struct SessionState {
    session: Session,
    pending_initial: Option<KeyAgreement>,
    /// Stable per-session secret the rotating drop-box addresses derive from (see
    /// `crate::drop`). Taken from the root key at key agreement, so both sides hold it
    /// and neither has to send it.
    drop_seed: [u8; 32],
    /// The PEER's mailbox point `M` (`crate::blind`) — where I compute my OUTBOUND blinded
    /// deposit box. The initiator takes it from the peer's signed bundle; the responder from the
    /// key-agreement. My own inbound box uses my own account mailbox secret, not this.
    peer_mailbox_pub: [u8; 32],
}

/// Max messages held awaiting delivery to the relay. A permanently-unreachable relay must
/// not grow the state file without bound; beyond this the oldest queued message is dropped
/// (it is the least likely to still be decryptable — see the DH-step bound on `flush_outbox`).
const MAX_OUTBOX: usize = 512;

/// Drop an undelivered queued message after this long (wall-clock, from queue time). The
/// recipient's mailbox TTL bounds how long a deposit could survive anyway, and a ratchet
/// step likely made the exact ciphertext undeliverable well before — so retrying past this
/// wastes effort on mail no one can read.
const OUTBOX_TTL_SECS: u64 = crate::node::MAILBOX_TTL_SECS;

/// One message encrypted and durably queued, awaiting delivery to the relay. Holds the
/// EXACT ciphertext (`envelope`) so a failed transmit retries the identical bytes rather
/// than re-encrypting position N under a new plaintext (which would reuse the message key).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct OutboxEntry {
    id: u64,
    peer_ik: [u8; 32],
    envelope: SessionEnvelope,
    queued_at: u64,
}

/// Персистентное состояние peer'а (для CLI: процесс-на-вызов возобновляет сессии
/// с диска). Содержит ratchet-снимки, cookie и счётчик nonce. **Секретный
/// материал** (ratchet-ключи в снимках) — писать под 0600, atomic + под flock
/// (иначе гонка процессов → keystream-reuse). Account НЕ здесь — он персистится
/// отдельно (`account.key`).
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
    last_sweep: u64,
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
    /// Пустое стартовое состояние (первый запуск — сессий нет).
    pub fn empty() -> Self {
        PeerState {
            sessions: Vec::new(),
            nonce_ctr: 0,
            handles: Vec::new(),
            cookies: Vec::new(),
            // Zero means "never swept", so the first poll sweeps. A client returning from
            // a long absence collects its backlog immediately rather than after the first
            // interval.
            last_sweep: 0,
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
        let before = self.sessions.len() + self.inbound_sessions.len() + self.outbox.len();
        self.sessions.retain(|s| &s.peer_ik != peer_ik);
        self.inbound_sessions.retain(|s| &s.peer_ik != peer_ik);
        self.outbox.retain(|o| &o.peer_ik != peer_ik);
        before != self.sessions.len() + self.inbound_sessions.len() + self.outbox.len()
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

/// Сессионный peer над транспортом. Держит долговременный `Account` (личность +
/// prekey + KEM), admission-capability и сессии по пирам.
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
    /// See `PeerState::last_sweep`.
    last_sweep: u64,
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
    /// `true` = fetch with `FetchRequest::ack` (lease-don't-delete) and remember what to
    /// ACK. Off by default: only a caller that will call [`Peer::ack_all`] AFTER durably
    /// persisting the advanced ratchet state (i.e. `recv_session`) turns it on. Never
    /// persisted — it is a per-receive mode, not session state.
    lease: bool,
    /// Messages fetched-under-lease this receive, awaiting an ACK once the caller has
    /// saved the ratchet. Drained by [`Peer::ack_all`] / [`Peer::take_pending_acks`].
    /// In-memory only.
    pending_ack: Vec<AckReceipt>,
    /// Persisted send queue (mirrors `PeerState::outbox`): messages encrypted but not yet
    /// accepted by a relay, retransmitted verbatim by [`Peer::flush_outbox`].
    outbox: Vec<OutboxEntry>,
    outbox_next_id: u64,
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
/// secret — `crate::blind`).
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
                let own = crate::blind::FetchOwnershipProof::prove(&fs, &receipt.mailbox, &c.mac)
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
            last_sweep: 0,
            sessions: HashMap::new(),
            inbound_sessions: HashMap::new(),
            lease: false,
            pending_ack: Vec::new(),
            outbox: Vec::new(),
            outbox_next_id: 0,
        }
    }

    /// Opt into lease/ACK receive: fetches keep their messages on the relay (leased) until
    /// [`Peer::ack_all`] deletes them. The caller MUST call `ack_all` only AFTER the
    /// advanced ratchet state is durable — that ordering is what turns at-most-once into
    /// effectively-once (a crash before the ACK redelivers the exact ciphertext, and the
    /// ratchet's transactional decrypt fails closed on the already-consumed duplicate).
    pub fn enable_ack(&mut self) {
        self.lease = true;
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

    /// Снять персистентное состояние (сессии + cookie + nonce). Для сохранения
    /// на диск между процесс-вызовами CLI.
    pub fn export_state(&self) -> PeerState {
        let persist = |map: &HashMap<[u8; 32], SessionState>| -> Vec<PersistedSession> {
            map.iter()
                .map(|(ik, st)| PersistedSession {
                    peer_ik: *ik,
                    snapshot: st.session.snapshot(),
                    pending_initial: st.pending_initial.clone(),
                    drop_seed: st.drop_seed,
                    peer_mailbox_pub: st.peer_mailbox_pub,
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
            last_sweep: self.last_sweep,
            outbox: self.outbox.clone(),
            outbox_next_id: self.outbox_next_id,
        }
    }

    /// Load persistent state (overwrites the current in-memory state).
    pub fn import_state(&mut self, state: PeerState) {
        self.nonce_ctr = state.nonce_ctr;
        self.handles = state.handles.into_iter().map(|(r, k, v)| ((r, k), v)).collect();
        self.cookies = state.cookies.into_iter().map(|(r, k, v)| ((r, k), v)).collect();
        self.last_sweep = state.last_sweep;
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
                        },
                    )
                })
                .collect()
        };
        self.sessions = restore(state.sessions);
        self.inbound_sessions = restore(state.inbound_sessions);
    }

    /// Долговременный IK этого peer = адрес его mailbox и ключ сессии у пиров.
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
    pub fn load_opks(&mut self, secrets: &[[u8; 32]]) {
        self.account.import_opk_secrets(secrets);
    }

    /// The account's current unconsumed one-time prekey secrets, to persist after a
    /// `receive` (which consumes some) or a top-up.
    pub fn export_opks(&self) -> Vec<[u8; 32]> {
        self.account.export_opk_secrets()
    }

    /// How many unconsumed one-time prekeys the account currently holds.
    pub fn opk_count(&self) -> usize {
        self.account.opk_count()
    }

    /// Установлена ли сессия к пиру (чтобы не вызывать `connect` повторно).
    pub fn has_session(&self, peer_ik: &[u8; 32]) -> bool {
        self.sessions.contains_key(peer_ik)
    }

    /// Публичный prekey-bundle этого peer.
    pub fn bundle(&self) -> PreKeyBundle {
        self.account.prekey_bundle()
    }

    /// This peer's bundle carrying one of ITS OWN one-time prekeys, signed. The only way to build
    /// such a bundle from outside `pqxdh`: an OPK cannot be attached without the identity key that
    /// signs it, so nothing can accidentally produce the unsigned form the relay used to serve.
    pub fn bundle_with_opk(&self, opk_pub: [u8; 32]) -> PreKeyBundle {
        self.account.prekey_bundle_with_opk(opk_pub)
    }

    /// §12: опубликовать СВОЙ bundle у relay, чтобы другие могли инициировать к
    /// нам. Cookie-refresh + ownership-proof (владение приватным IK).
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
        let signed_opks: Vec<crate::pqxdh::SignedOpk> = opks
            .iter()
            .map(|k| crate::pqxdh::SignedOpk { key: *k, sig: self.account.sign_opk(k) })
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
            let req = PublishRequest {
                bundle: bundle.clone(),
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

    /// §12: установить сессию к пиру `peer_ik`, ЗАБРАВ его bundle у relay.
    /// Проверяет, что отданный bundle заявляет ЗАПРОШЕННЫЙ IK — relay не может
    /// подсунуть bundle под другим IK незаметно (подмена самого IK — внешняя
    /// стена: подлинность `peer_ik` проверяется вне канала, см. STATUS).
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

    /// Установить исходящую сессию по УЖЕ имеющемуся bundle (OOB-доставка / тесты).
    /// **Подлинность `bundle.ik_pub` — ответственность вызывающего** (relay не
    /// доверенный якорь личности). НЕ перезатирает живую сессию: повторный
    /// `connect` к известному пиру → `Err` (иначе новый root_key молча убил бы
    /// работающую сессию в обе стороны — тот же класс silent-loss).
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
            SessionState { session, pending_initial: Some(ka), drop_seed, peer_mailbox_pub },
        );
        Ok(fs)
    }

    /// Отправить `plaintext` пиру `peer_ik` по установленной сессии.
    ///
    /// **Цепочка продвигается БЕЗУСЛОВНО** на `encrypt`: каждый `mk` шифрует ровно
    /// один plaintext → нулевой nonce безопасен (предусловие `ratchet`). Недоставка
    /// (`Rejected`) оставляет **gap** — получатель отвергнет по in-order/`pn` до
    /// переустановки. Это liveness-издержка, НЕ переиспользование ключа: НИКОГДА не
    /// менять nonce-уникальность на liveness на слое крипты. (Если бы коммитили
    /// продвижение лишь при `Accepted`, следующий ДРУГОЙ plaintext занял бы ту же
    /// позицию цепочки → тот же `mk` + нулевой nonce → keystream-reuse, а relay
    /// untrusted и первый шифртекст уже ушёл.) Retransmit-без-gap = дослать те же
    /// БАЙТЫ конверта дословно (не пере-шифровать) — отдельный reliability-срез.
    pub fn send(&mut self, peer_ik: &[u8; 32], plaintext: &[u8], now: u64) -> Response {
        let envelope = match self.encrypt_next(peer_ik, plaintext) {
            Ok(e) => e,
            Err(e) => return Response::Rejected(e),
        };
        self.transmit_envelope(peer_ik, envelope, now)
    }

    /// Зашифровать следующее сообщение (продвигает цепочку БЕЗУСЛОВНО), вернуть
    /// конверт — но НЕ передавать. Для crash-consistent отправки: вызывающий
    /// обязан ПЕРСИСТИТЬ состояние ДО передачи. Иначе краш между transmit и save
    /// → следующий send перешифрует ту же позицию цепочки другим текстом → тот же
    /// `mk`+нулевой nonce = keystream-reuse (шифртекст-N уже у relay). Durable-
    /// запись «позиция N израсходована» обязана лечь до появления ct_N на проводе.
    pub fn encrypt_next(&mut self, peer_ik: &[u8; 32], plaintext: &[u8]) -> Result<SessionEnvelope, String> {
        let st = self.sessions.get_mut(peer_ik).ok_or("no session (call connect first)")?;
        let rmsg = st.session.encrypt(plaintext); // продвигает сохранённую сессию
        Ok(match &st.pending_initial {
            // Seal the opener to the RECIPIENT's identity key. The KeyAgreement carries
            // our long-term IK, and an unsealed opener hands the relay the social-graph
            // edge in the clear — it treats the payload as opaque, but the format is
            // public and parseable. Sealed, the relay sees a fresh ephemeral + ciphertext
            // and cannot tell who opened the conversation.
            Some(ka) => {
                let plain = postcard::to_stdvec(ka).map_err(|e| format!("encode ka: {e}"))?;
                let sealed_ka =
                    crate::seal::SkeletonSeal::seal(&PublicKey::from(*peer_ik), &plain);
                SessionEnvelope::InitialSealed { sealed_ka, msg: rmsg }
            }
            None => SessionEnvelope::Ratchet(rmsg),
        })
    }

    /// Передать уже зашифрованный конверт (cookie-retry). На `Accepted` снимает
    /// `pending_initial` (дальше только Ratchet). Отдельно от `encrypt_next`,
    /// чтобы вызывающий вставил durable-save между ними (см. `encrypt_next`).
    pub fn transmit_envelope(&mut self, peer_ik: &[u8; 32], envelope: SessionEnvelope, now: u64) -> Response {
        let (recipient, handle) = match self.route_for(peer_ik, &envelope, now) {
            Ok(r) => r,
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
        let envelope = self.encrypt_next(peer_ik, plaintext)?;
        let id = self.outbox_next_id;
        self.outbox_next_id = self.outbox_next_id.wrapping_add(1);
        self.outbox.push(OutboxEntry { id, peer_ik: *peer_ik, envelope, queued_at: now });
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
            match self.transmit_envelope(&entry.peer_ik, entry.envelope.clone(), now) {
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

    /// Собрать WireMessage и провести через admission с cookie-refresh. Тот же
    /// конверт переиспользуется на повторе (cookie-challenge НЕ пере-шифрует).
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
        let epoch = crate::drop::epoch_of(now);
        let recipient = self.loop_box(epoch).public.to_bytes();
        // A short text's ciphertext, so a loop sits in the same size class as the traffic
        // it is hiding. Imperfect: the E2E layer does not pad, so real messages vary and a
        // relay comparing size DISTRIBUTIONS can still tell the populations apart. The
        // Noise layer's buckets hide this from an on-path observer but not from the relay,
        // which sees the payload after decryption. Named, not solved.
        let msg = crate::ratchet::RatchetMessage {
            header: crate::ratchet::Header { dh: random32(), pn: 0, n: 0, salt: [7u8; 16] },
            ciphertext: {
                let mut c = vec![0u8; 96];
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
    fn route_for(
        &self,
        peer_ik: &[u8; 32],
        envelope: &SessionEnvelope,
        now: u64,
    ) -> Result<([u8; 32], Handle), String> {
        match envelope {
            SessionEnvelope::Initial { .. } | SessionEnvelope::InitialSealed { .. } => {
                Ok((*peer_ik, Handle::Opener(*peer_ik)))
            }
            SessionEnvelope::Ratchet(_) => {
                let st = self.sessions.get(peer_ik).ok_or("no session (call connect first)")?;
                let epoch = crate::drop::epoch_of(now);
                // Deposit into the OUTBOUND box (me → peer): the peer's mailbox point blinded for
                // this session/epoch. The peer fetches the same address with its own fetch secret;
                // I never hold that secret, so depositing does not let me read the box.
                let dir = crate::drop::direction(&self.identity(), peer_ik);
                // Fail LOUD on a session that predates blinded mailboxes: its `peer_mailbox_pub` is
                // the serde default `[0;32]`, which is the VALID Ristretto identity — so
                // `deposit_address` would return `Some(identity)` and silently deposit into a box
                // no one fetches (a real `M = m·G` is a hash-derived scalar times the basepoint,
                // never the identity, so this never false-rejects a live session).
                if st.peer_mailbox_pub == [0u8; 32] {
                    return Err("session predates blinded mailboxes — re-establish it (connect anew)".into());
                }
                let address = crate::blind::deposit_address(&st.peer_mailbox_pub, &st.drop_seed, epoch, dir)
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

    /// Забрать входящие: fetch-auth + продвижение сессий. `Ok(vec)` — по элементу
    /// на конверт (`None` = не расшифровался / не наш; `Some(Received)` несёт
    /// отправителя); `Err` — сбой транспорта/auth.
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
        self.prune_handles(now);
        let mut out = Vec::new();

        // The identity mailbox: openers from strangers. It names us — the DH ownership
        // proof is against our own IK — which is exactly why it gets a handle of its
        // own and never shares one with a drop-box.
        let ik = self.account.ik().clone();
        let payloads = self.fetch_mailbox(BoxAuth::Identity(ik), Handle::Identity, now)?;
        for p in &payloads {
            out.push(self.process(p).map(|mut r| { r.msg_id = payload_id(p); r }));
        }

        // The hot window every cycle; the complete one on a slow schedule. Sweeping every
        // cycle would multiply fetch cost by TTL_EPOCHS for mail that is old by
        // definition; never sweeping loses that mail outright.
        let sweep_due = now.saturating_sub(self.last_sweep) >= crate::drop::SWEEP_INTERVAL_SECS;
        let epochs: Vec<u64> = if sweep_due {
            self.last_sweep = now;
            crate::drop::sweep_epochs(now)
        } else {
            crate::drop::poll_epochs(now).to_vec()
        };
        let me = self.identity();

        // Every session's INBOUND box, as a BLINDED drop-box: its address is my own mailbox point
        // blinded for this session/epoch (`deposit_address(M_me, drop_seed, epoch, dir)`) — the
        // same address the peer deposited into — and I hold the matching fetch secret to prove
        // ownership. Collected first: `fetch_mailbox` borrows self mutably.
        let own_m = self.account.mailbox_public();
        let account = self.account.clone();
        let boxes: Vec<(BoxAuth, Handle)> = self
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
                        let address = crate::blind::deposit_address(&own_m, &st.drop_seed, *e, dir)?;
                        let fetch_secret = account.mailbox_fetch_secret(&st.drop_seed, *e, dir);
                        Some((BoxAuth::DropBox { address, fetch_secret }, Handle::Box(*peer_ik, *e)))
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let mut box_err: Option<String> = None;
        for (auth, handle) in boxes {
            match self.fetch_mailbox(auth, handle, now) {
                Ok(payloads) => {
                    for p in &payloads {
                        out.push(self.process(p).map(|mut r| { r.msg_id = payload_id(p); r }));
                    }
                }
                Err(e) => box_err = Some(e),
            }
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
        let mailbox = auth.mailbox();
        let client_addr = self.handle(handle.clone());
        let scope = self.scope_for(&handle);
        let rid = self.relay_id();

        for _ in 0..2 {
            let cookie = self.cookies.get(&(rid, client_addr.clone())).copied();
            // Ownership proof for THIS cookie: DH for the identity mailbox, Schnorr (bound to the
            // cookie MAC) for a blinded drop-box.
            let (proof, own_proof) = match (&auth, cookie) {
                (BoxAuth::Identity(id), Some(c)) => {
                    (fetch_proof(&id.dh(&self.relay_pub), &c.mac, &mailbox), Vec::new())
                }
                (BoxAuth::DropBox { fetch_secret, .. }, Some(c)) => {
                    let own = crate::blind::FetchOwnershipProof::prove(fetch_secret, &mailbox, &c.mac)
                        .map(|p| p.to_bytes().to_vec())
                        .unwrap_or_default();
                    ([0u8; 16], own)
                }
                (_, None) => ([0u8; 16], Vec::new()),
            };
            let req = FetchRequest {
                mailbox,
                client_addr: client_addr.clone(),
                carrier_id: self.carrier_id.clone(),
                cookie,
                proof,
                ack: self.lease,
                own_proof,
            };
            match self.transport.fetch_isolated(&req, now, scope.as_deref()) {
                FetchResponse::NeedCookie(c) => {
                    self.cookies.insert((rid, client_addr.clone()), c);
                    continue;
                }
                FetchResponse::Fetched(payloads) => {
                    // Under lease, remember what to delete: the messages stay on the relay
                    // until the ACK runs (after the caller persists the ratchet). The
                    // receipt captures the cookie that just authorised this fetch, so it can
                    // be acked later without the Peer. Empty pages leave nothing to ACK.
                    if self.lease && !payloads.is_empty() {
                        // The later ACK re-proves ownership: DH needs `shared`, a drop-box needs
                        // its fetch secret.
                        let (shared, own_fetch_secret) = match &auth {
                            BoxAuth::Identity(id) => (id.dh(&self.relay_pub), None),
                            BoxAuth::DropBox { fetch_secret, .. } => ([0u8; 32], Some(*fetch_secret)),
                        };
                        self.pending_ack.push(AckReceipt {
                            mailbox,
                            client_addr: client_addr.clone(),
                            carrier_id: self.carrier_id.clone(),
                            shared,
                            cookie,
                            scope: scope.clone(),
                            ids: payloads.iter().map(payload_id).collect(),
                            own_fetch_secret,
                        });
                    }
                    return Ok(payloads);
                }
                FetchResponse::Rejected(r) => return Err(r),
            }
        }
        Err("persistent cookie challenge".into())
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

    /// Обработать один входящий груз, продвинув соответствующую сессию. Атрибутит
    /// отправителя: Initial несёт `sender_ik` в KA; для Ratchet отправитель = ключ
    /// сессии, которая расшифровала (trial-decryption).
    /// `process` for tests: can THIS peer open this payload? Used to assert that a
    /// stranger with real keys gets nothing from a raw slot.
    pub fn open_for_test(&mut self, payload: &Payload) -> Option<Received> {
        self.process(payload)
    }

    fn process(&mut self, payload: &Payload) -> Option<Received> {
        match payload {
            // Скелет-конверт этому session-peer не адресован.
            Payload::Skeleton(_) => None,
            // A sealed opener: unwrap it with our OWN identity key — which works without
            // knowing who sent it, and is exactly why the relay could not read it — then
            // handle the KeyAgreement as usual. Sender authentication is unchanged: it
            // comes from the inner PQXDH, never from the outer box.
            Payload::Session(SessionEnvelope::InitialSealed { sealed_ka, msg }) => {
                let plain = sealed_ka.open(self.account.ik())?;
                let ka: KeyAgreement = postcard::from_bytes(&plain).ok()?;
                self.process_opener(&ka, msg)
            }
            // An UNSEALED opener is REFUSED. It carries the sender's identity key in the clear,
            // so the relay can read the social-graph edge straight off it — the exact leak
            // `InitialSealed` exists to close. The variant was kept only so an in-flight capsule
            // from an older client would still open; there are no older clients, and accepting it
            // let any peer silently downgrade a conversation's metadata privacy by sending the
            // legacy form. We only ever SEND sealed, so nothing legitimate produces this.
            Payload::Session(SessionEnvelope::Initial { .. }) => None,
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
                        return st
                            .session
                            .decrypt(msg)
                            .ok()
                            .map(|pt| Received { sender: sender_ik, plaintext: pt, msg_id: [0u8; 32] });
                    }
                }
                let mut session = Session::init_receiver(root_key, self.account.prekey().clone());
                // THE authentication step: only a sender who actually holds the claimed identity
                // key derives this root key, so a forged opener fails here. Bail BEFORE touching
                // the session maps or the one-time prekey — otherwise a stranger could park a dead
                // session under any victim's IK (it would become the primary outbound session and
                // silently swallow the replies) and burn a one-time prekey per attempt.
                let pt = session.decrypt(msg).ok()?;
                // Authenticated ⇒ commit. Consuming the OPK here still gives at-most-once dedup on
                // re-delivery: a genuine duplicate finds the OPK already gone and stops earlier.
                self.account.consume_opk(ka);
                // The sender's mailbox point rode the (authenticated) key-agreement — store it as
                // where I deposit my B→A replies.
                let peer_mailbox_pub = ka.mailbox_a_pub;
                let new_state = SessionState { session, pending_initial: None, drop_seed, peer_mailbox_pub };
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
                if self.sessions.contains_key(&sender_ik) {
                    self.inbound_sessions.insert(sender_ik, new_state);
                } else {
                    self.sessions.insert(sender_ik, new_state);
                }
                Some(Received { sender: sender_ik, plaintext: pt, msg_id: [0u8; 32] })
            }
        }
    }

    /// An ongoing ratchet message: no sender hint, so trial-decrypt. Safe because `decrypt` is
    /// transactional — a miss does not move anyone else's session. Both maps: a peer's stream
    /// after a simultaneous first contact rides `inbound_sessions`.
    fn process_ratchet(&mut self, msg: &RatchetMessage) -> Option<Received> {
        for (ik, st) in self.sessions.iter_mut() {
            if let Ok(pt) = st.session.decrypt(msg) {
                return Some(Received { sender: *ik, plaintext: pt, msg_id: [0u8; 32] });
            }
        }
        for (ik, st) in self.inbound_sessions.iter_mut() {
            if let Ok(pt) = st.session.decrypt(msg) {
                return Some(Received { sender: *ik, plaintext: pt, msg_id: [0u8; 32] });
            }
        }
        None
    }
}

#[cfg(test)]
mod outbox_state_tests {
    use super::{OutboxEntry, PeerState, PersistedSession};
    use crate::node::SessionEnvelope;
    use crate::ratchet::{Header, RatchetMessage, Session};
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
            last_sweep: 0,
            outbox: vec![OutboxEntry {
                id: 5,
                peer_ik: [2u8; 32],
                envelope: a_ratchet_envelope(),
                queued_at: 100,
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

    /// Migration safety: a session restored from a state file written BEFORE blinded mailboxes has
    /// `peer_mailbox_pub == [0;32]` (the serde default) — which is the VALID Ristretto identity, so
    /// `deposit_address` would silently return a box no one fetches. A follow-up send must fail
    /// LOUD ("re-establish") instead of dropping mail into the void.
    #[test]
    fn a_stale_session_without_a_mailbox_point_fails_loud_on_send() {
        use crate::node::{InMemoryTransport, RelayNode, Response};
        use crate::pqxdh::Account;
        use crate::ratchet::Session;
        use admission::capability::{Capability, Quota, Scope};
        use std::cell::RefCell;
        use std::rc::Rc;

        let relay = Rc::new(RefCell::new(RelayNode::new(0)));
        let relay_pub = relay.borrow().relay_public();
        let cap = Capability {
            capability_id: [0xCA; 16],
            scope: Scope::MessageDelivery,
            quota: Quota { max_requests: 10_000, max_bytes: 1 << 30, window_secs: 600 },
            not_before: 0,
            not_after: u32::MAX,
            secret: [0x33; 32],
        };
        let mut peer = super::Peer::new(InMemoryTransport::new(relay), Account::generate(), cap, relay_pub);

        let bob_ik = [9u8; 32];
        peer.sessions.insert(
            bob_ik,
            super::SessionState {
                session: Session::init_sender([1u8; 32], [2u8; 32]),
                pending_initial: None, // a follow-up Ratchet send → hits the blinded deposit path
                drop_seed: [3u8; 32],
                peer_mailbox_pub: [0u8; 32], // the serde default of a pre-change session
            },
        );

        match peer.send(&bob_ik, b"hi", 0) {
            Response::Rejected(e) => assert!(e.contains("re-establish"), "loud, actionable error: {e}"),
            other => panic!("a stale session must fail loud, not silently drop mail: {other:?}"),
        }
    }
}
