//! Тонкие RelayNode и Client + транспорт. Ровно столько, чтобы провести одно
//! сообщение Alice → relay → Bob. Богатый API узла — задача следующих срезов.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

use admission::capability::{
    pow_cap_id, pow_cap_secret, Capability, CapabilityProof, CapabilityQuotaTracker,
    CapabilityTable, Quota, Scope, POW_CAP_QUOTA,
};
use admission::cookie::{Cookie, CookieKeyring};
use admission::params::{
    cookie_epoch_id, EPOCH_DURATION_SECS, ISSUED_CAP_TTL_SECS, POW_BUCKET_SKEW, POW_WINDOW_SECS,
};
use admission::pipeline::{AdmissionPipeline, Credential, Outcome, ReplayFilter, Request};
use admission::token::{IssuerRing, MockRingVerifier};
use hkdf::Hkdf;
use hmac::{Mac, SimpleHmac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::PublicKey;

use crate::discovery::{self, DiscoveryRecord};
use crate::pqxdh::{KeyAgreement, PreKeyBundle};
use crate::ratchet::RatchetMessage;
use crate::seal::{Identity, SkeletonSeal};

/// Потолок числа опубликованных bundle (§12): при полноте — отказ на публикацию
/// нового IK, НЕ тихий сброс (та же дисциплина, что `MAX_FETCH_SEALS`).
/// Перезапись СВОЕГО bundle всегда разрешена (не считается новым).
pub const MAX_BUNDLES: usize = 100_000;
/// Node-list (discovery plane) bounds. `known_relays` holds operator-curated descriptors
/// (self + configured peers) in this slice — a bounded set keeps the served list inside one
/// response frame and caps memory. Peer-to-peer gossip merge (with dial-verification) is a
/// separate slice; this set is never grown from untrusted input.
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
pub const MAX_ACK_IDS: usize = crate::wire::MAX_FETCH_SEALS;
/// Cap on stored one-time prekeys per IK (bounded relay state; see `PublishRequest::opks`).
pub const MAX_OPKS_PER_IK: usize = 256;

/// How long an undelivered sealed message lives in a mailbox before the TTL sweep
/// drops it (7 days). A recipient who never comes back otherwise pins memory
/// forever. Generous enough for ordinary offline delivery; swept lazily when the
/// epoch advances (`advance_epoch` → `sweep_mailboxes`), never on a background thread.
pub const MAILBOX_TTL_SECS: u64 = 7 * 24 * 3600;

/// How long a leased (fetched-but-unacked) message stays invisible to a subsequent
/// fetch before it becomes deliverable again. A client that fetches with
/// `FetchRequest::ack` promises to ACK once the message is durably persisted; if it
/// crashes first, the lease expires and the exact ciphertext redelivers on the next
/// poll (at-least-once + the ratchet's fail-closed dedup ⇒ effectively-once). Long
/// enough to cover a poll's decrypt + fsync, short enough that a crash redelivers
/// promptly. Measured from the fetch; the `MAILBOX_TTL_SECS` reap still runs from the
/// original deposit, so a client that never ACKs cannot mint an immortal message.
pub const LEASE_SECS: u64 = 60;

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

/// Свежий случайный ключ cookie-эпохи (для инициализации и ротации).
fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    k
}

/// Доказательство владения mailbox для fetch (§7): привязано к общему
/// static-static DH отправителя-получателя с relay И к `cookie.mac` (свежесть
/// 30 c). Домен KDF `KARST-fetch-auth-v1` отделён от seal — тот же принцип
/// разделения доменов, что `KARST-skeleton-seal-v1`. Только держатель приватного
/// ключа `mailbox` может вычислить DH → только он вычислит proof.
pub(crate) fn fetch_proof(shared_dh: &[u8; 32], cookie_mac: &[u8; 16], mailbox: &[u8; 32]) -> [u8; 16] {
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
fn mailbox_owner_ok(
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

/// Сессионный §2.1-конверт (PQXDH + Double Ratchet). Первое сообщение несёт
/// key-agreement (`Initial`), последующие — только ratchet-груз (`Ratchet`).
/// Relay хранит непрозрачно — ключа не имеет, различить содержимое не может.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum SessionEnvelope {
    /// Первый контакт: PQXDH-согласование + первое ratchet-сообщение.
    ///
    /// **LEGACY — names the sender to the relay.** `KeyAgreement.ik_a_pub` is the
    /// sender's long-term identity in the clear: the relay treats the payload as opaque,
    /// but the format is public, so a relay that wants the social graph reads every edge
    /// off the openers. Superseded by `InitialSealed`; kept so an in-flight capsule from
    /// an older peer still opens.
    Initial { ka: KeyAgreement, msg: RatchetMessage },
    /// Продолжение установленной сессии.
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
}

/// Полезный груз в mailbox. **Стадийная миграция** (не мёртвый код): сессионный
/// §2.1-путь (`Session`) — новый in-process E2E; скелет (`Skeleton`) ещё несёт
/// сокет/CLI-путь, пока тому не добавлена персистентность сессий. Relay хранит
/// любой вариант непрозрачно.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum Payload {
    Skeleton(SkeletonSeal),
    Session(SessionEnvelope),
}

impl Payload {
    /// Приблизительный размер груза для stage-0 size-gate конвейера допуска.
    fn approx_len(&self) -> usize {
        match self {
            Payload::Skeleton(s) => s.ciphertext.len(),
            Payload::Session(SessionEnvelope::Initial { ka, msg }) => {
                ka.kem_ct.len() + msg.ciphertext.len() + 64
            }
            Payload::Session(SessionEnvelope::InitialSealed { sealed_ka, msg }) => {
                sealed_ka.ciphertext.len() + msg.ciphertext.len() + 64
            }
            Payload::Session(SessionEnvelope::Ratchet(msg)) => msg.ciphertext.len(),
        }
    }
}

/// Доказательство ВЛАДЕНИЯ IK для §12-публикации bundle (write-side зеркало
/// `fetch_proof`): только держатель приватного IK вычислит `DH(IK, relay)`.
/// Связывает cookie.mac (свежесть) И СОДЕРЖИМОЕ bundle (ik‖prekey‖kem_ek) — иначе
/// перехваченный proof переиспользовали бы для подмены bundle другим содержимым.
/// Останавливает ДРУГИХ клиентов от перезаписи чужого bundle; против ЗЛОГО RELAY
/// не помогает (тот подменит IK — внешняя стена, OOB-проверка IK).
pub(crate) fn publish_proof(
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

/// Сообщение на проводе: admission-часть (§7) + маршрут + запечатанный полезный
/// груз. Владеющий тип — транспорт передаёт его целиком.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct WireMessage {
    pub client_addr: Vec<u8>,
    pub carrier_id: Vec<u8>,
    pub cookie: Option<Cookie>,
    pub request_nonce: Vec<u8>,
    pub capability_proof: CapabilityProof,
    /// Публичный ключ получателя = адрес его mailbox (skeleton: static X25519;
    /// session: долговременный IK получателя).
    pub recipient: [u8; 32],
    pub payload: Payload,
}

/// Ответ relay клиенту.
#[derive(Debug)]
pub enum Response {
    /// Первый контакт: relay выдал cookie, клиент повторяет с ним.
    NeedCookie(Cookie),
    /// Допущено, запечатанный груз положен в mailbox получателя.
    Accepted,
    /// Отклонено конвейером допуска (текст исхода).
    Rejected(String),
}

/// One queued sealed message. `enqueued_at` drives the deposit-time TTL sweep;
/// `leased_until` is the wall-clock time before which a leased-but-unacked message
/// stays invisible to a fetch (0 = not leased). Leasing never resets `enqueued_at`, so
/// a client that keeps crashing cannot outlive `MAILBOX_TTL_SECS`.
struct MailboxEntry {
    enqueued_at: u64,
    leased_until: u64,
    payload: Payload,
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

/// A relay's advertised policy — the operator-configured knobs a client can inspect (`GetPolicy`)
/// to understand what it's connecting to and to prefer relays matching its preferences. Every
/// field is **operator-declared**; they differ in how far a client can check them:
///   * `pow_bits` — VERIFIABLE (the client solves the PoW to join).
///   * `max_blob_size` — VERIFIABLE (an over-cap upload is rejected).
///   * `blob_persistence` — `Durable` is PROVABLE (fetch a parked chunk back — it self-verifies),
///     but `Ephemeral` is a CLAIM no one can check remotely (you cannot prove a server deleted /
///     did not copy data). Trust ephemeral only as far as the operator; accountability for the
///     unverifiable claims will come from the future reputation layer, not from crypto.
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
}

/// Relay-узел: гоняет admission-конвейер (§7) на входящих capsule и, при
/// Admit, кладёт ЗАПЕЧАТАННЫЙ (нечитаемый для узла) груз в mailbox получателя.
/// Узел никогда не видит открытый текст — ключа у него нет.
pub struct RelayNode {
    keyring: CookieKeyring,
    capabilities: CapabilityTable,
    verifier: MockRingVerifier,
    issuer_ring: IssuerRing,
    replay: ReplayFilter,
    cap_quota: CapabilityQuotaTracker,
    epoch: u32,
    /// Per-recipient queue of `(enqueued_at, sealed payload)`. The timestamp drives
    /// the TTL sweep (`sweep_mailboxes`) so undelivered mail for a recipient who never
    /// comes back doesn't accumulate forever.
    mailboxes: HashMap<[u8; 32], Vec<MailboxEntry>>,
    /// §12 discovery: опубликованные prekey-bundle по IK владельца. Публичный
    /// материал; запись гейтится ownership-proof, чтение открыто. Ограничен
    /// `MAX_BUNDLES` (отказ при полноте, не тихий сброс).
    bundles: HashMap<[u8; 32], PreKeyBundle>,
    /// One-time prekey batches per IK; a fetch pops one (see `PublishRequest::opks`).
    opk_batches: HashMap<[u8; 32], VecDeque<crate::pqxdh::SignedOpk>>,
    /// Rotating start offset for `node_list`, so advertisement is fair rather than always
    /// favouring whoever was learned first (A3-13). `Cell` because serving a list is a READ.
    gossip_cursor: std::cell::Cell<usize>,
    /// Статический ключ узла: основа fetch-auth (и §12 publish-auth). Задаётся
    /// извне (`with_identity`) для персистентности — `karst-relay` хранит его на
    /// диске, relay-id стабилен между перезапусками.
    relay_identity: Identity,
    /// §15 large-file blob store (disk-backed). `None` = blobs disabled (default; keeps
    /// the in-memory constructors/tests unchanged). Enabled via `enable_blobs`.
    blobs: Option<crate::blobstore::BlobStore>,
    /// The operator's blob-persistence posture, remembered so the relay can ADVERTISE it in its
    /// policy (`policy()`). `None` when blobs are disabled.
    blob_persistence: Option<BlobPersistence>,
    /// §7 slice 4a — the Public door. `Some(difficulty_bits)` = this relay issues STATELESS
    /// PoW capabilities (`handle_join`); `None` (default) = Private/Dev, no self-serve
    /// issuance. Set via `enable_pow_issue`, which also arms the capability table's stateless
    /// verifier. Off by default keeps every existing constructor/test a closed relay.
    pow_issue: Option<u32>,
    /// Operator quota policy (§7.2): a CEILING clamping every capability's effective quota at
    /// enforcement time, and the quota stamped on newly-issued PoW/invite capabilities. `None` =
    /// no ceiling (use the capability's own quota — the historical default, keeps every existing
    /// test open). Set live via `set_quota_policy` (admin channel) — changes bite immediately,
    /// existing capabilities included, because it is applied on each request, not just at issuance.
    quota_policy: Option<Quota>,
    /// Discovery plane: operator-curated relay descriptors (self + configured peers) served
    /// by `GetNodeList` so clients learn which relays exist. NEVER grown from untrusted gossip
    /// in this slice (see `add_relay`). Empty by default.
    known_relays: Vec<RelayDescriptor>,
    /// §12 4c — opt-in discovery directory: `discovery_pseudonym(discovery_pub) → DiscoveryRecord`.
    /// The pseudonym is the hash of a RANDOM, per-user discovery key that is decoupled from the IK
    /// — so it is unguessable (no dictionary attack), rotatable (a new keypair mints a new code and
    /// retires the old one) and revocable, WITHOUT touching the permanent identity. Written only on
    /// an explicit, self-authenticated `PublishDiscovery` (the user opting in), NEVER as a side
    /// effect of a bundle publish. Each record binds its code to the real IK via an IK signature,
    /// so a resolver trusts the code→IK mapping without the relay vouching; the write itself is
    /// authenticated by the discovery key, so only the code's owner can write/rotate/delete its
    /// slot. Bounded like `bundles`; expired records are dropped lazily on access.
    discovery: HashMap<[u8; 32], DiscoveryRecord>,
    /// This relay's own descriptor, advertised in the node-list. `Some` only if the relay
    /// advertises a routable address (else it has no reachable hint to offer — same rule as
    /// node-list self-advertisement).
    self_descriptor: Option<RelayDescriptor>,
}

impl RelayNode {
    pub fn new(now: u64) -> Self {
        Self::with_identity(now, Identity::generate())
    }

    /// Как `new`, но с ЗАДАННЫМ fetch-auth ключом узла — для персистентности
    /// ключа relay (стабильный relay-id между перезапусками). Cookie-ключи всё
    /// ещё эфемерны (ротируются по эпохам — это by design, не влияет на relay-id).
    pub fn with_identity(now: u64, relay_identity: Identity) -> Self {
        let epoch = cookie_epoch_id(now, EPOCH_DURATION_SECS);
        RelayNode {
            keyring: CookieKeyring::new(EPOCH_DURATION_SECS, now, random_key(), random_key()),
            capabilities: CapabilityTable::new(),
            verifier: MockRingVerifier,
            issuer_ring: IssuerRing { issuer_pubkeys: vec![[1u8; 32]], threshold_t: 1 },
            replay: ReplayFilter::new(epoch, 4096),
            cap_quota: CapabilityQuotaTracker::new(),
            epoch,
            mailboxes: HashMap::new(),
            bundles: HashMap::new(),
            opk_batches: HashMap::new(),
            gossip_cursor: std::cell::Cell::new(0),
            relay_identity,
            blobs: None,
            blob_persistence: None,
            pow_issue: None,
            quota_policy: None,
            known_relays: Vec::new(),
            discovery: HashMap::new(),
            self_descriptor: None,
        }
    }

    /// Enable the §15 disk-backed blob store at `dir`. `persist` is the operator's choice:
    /// `Durable` RECOVERS any parked blobs from a prior run (a big upload survives a restart);
    /// `Ephemeral` WIPES the store on start (blobs do not outlive the process — the lower-residue
    /// posture, an operator's call). `now` drives the recovery-time TTL sweep. Off by default.
    pub fn enable_blobs(&mut self, dir: std::path::PathBuf, now: u64, persist: BlobPersistence) -> std::io::Result<()> {
        self.blobs = Some(match persist {
            BlobPersistence::Durable => crate::blobstore::BlobStore::open(dir, now)?,
            BlobPersistence::Ephemeral => crate::blobstore::BlobStore::new(dir)?,
        });
        self.blob_persistence = Some(persist);
        Ok(())
    }

    /// This relay's advertised policy — what an operator's config exposes so a client can see (and
    /// prefer) relays matching its preferences. **Operator-declared:** some fields a client can
    /// verify by using the relay (PoW difficulty it solves, size caps it hits), the durable
    /// persistence claim it can PROVE (fetch a chunk back), but the ephemeral claim it CANNOT check
    /// remotely — see `RelayPolicy`.
    pub fn policy(&self) -> RelayPolicy {
        RelayPolicy {
            blob_persistence: self.blob_persistence,
            blob_ttl_secs: if self.blobs.is_some() { crate::blobstore::BLOB_TTL_SECS } else { 0 },
            max_blob_size: if self.blobs.is_some() { crate::blobstore::MAX_BLOB_SIZE } else { 0 },
            pow_bits: self.pow_issue,
        }
    }

    /// §15 upload: store one ciphertext chunk. Cookie-gated (DoS/freshness). The blob
    /// store enforces ownership, in-order, immutability, and the byte caps.
    pub fn handle_blob_put(&mut self, req: &BlobPutRequest, now: u64) -> BlobResponse {
        self.advance_epoch(now);
        match req.cookie {
            Some(c) if self.keyring.verify(&c, &req.client_addr, &req.carrier_id, now).is_ok() => {}
            _ => {
                let cookie = self.keyring.issue(&req.client_addr, &req.carrier_id, now as u32);
                return BlobResponse::NeedCookie(cookie);
            }
        }
        let sender: [u8; 32] = match req.client_addr.as_slice().try_into() {
            Ok(s) => s,
            Err(_) => return BlobResponse::Rejected("bad sender address".into()),
        };
        let Some(blobs) = &mut self.blobs else {
            return BlobResponse::Rejected("blobs disabled".into());
        };
        match blobs.put_chunk(sender, req.blob_id, req.index, req.count, &req.data, now) {
            crate::blobstore::BlobPut::Ok => BlobResponse::Stored,
            crate::blobstore::BlobPut::Complete => BlobResponse::Complete,
            crate::blobstore::BlobPut::Rejected(r) => BlobResponse::Rejected(r),
        }
    }

    /// §15 download: return one ciphertext chunk (bearer-by-id). Cookie-gated for DoS.
    pub fn handle_blob_get(&mut self, req: &BlobGetRequest, now: u64) -> BlobResponse {
        self.advance_epoch(now);
        match req.cookie {
            Some(c) if self.keyring.verify(&c, &req.client_addr, &req.carrier_id, now).is_ok() => {}
            _ => {
                let cookie = self.keyring.issue(&req.client_addr, &req.carrier_id, now as u32);
                return BlobResponse::NeedCookie(cookie);
            }
        }
        let Some(blobs) = &self.blobs else {
            return BlobResponse::Rejected("blobs disabled".into());
        };
        BlobResponse::Chunk(blobs.get_chunk(&req.blob_id, req.index))
    }

    /// §15 upload progress: `(next, count, complete)` for a blob — how many chunks are already
    /// stored, so a **resumable upload** continues from `next` instead of re-sending everything.
    /// `None` = the relay has never seen this blob (a fresh upload starts at 0) or blobs are off.
    /// Public read (bearer-by-id, like `FetchBundle`/`get_chunk`): no cookie, reveals only progress.
    pub fn blob_stat(&self, blob_id: &[u8; 32]) -> Option<(u32, u32, bool)> {
        self.blobs.as_ref()?.stat(blob_id)
    }

    /// Публичный ключ узла — клиент узнаёт его вне канала (как адрес) и
    /// использует для fetch-auth DH. Бинарь печатает его при старте.
    pub fn relay_public(&self) -> PublicKey {
        self.relay_identity.public
    }

    /// Every payload the relay is holding, ignoring which mailbox it sits in.
    ///
    /// This is deliberately the view PIR would grant: a reader who has NOT proved it owns
    /// any mailbox. Exposed so a test can assert that such a reader learns nothing — the
    /// composition the whole PIR slice rests on.
    pub fn all_slots_for_test(&self) -> Vec<Payload> {
        self.mailboxes.values().flat_map(|m| m.iter().map(|e| e.payload.clone())).collect()
    }

    /// Number of live capability-quota windows — exposed so a test can prove the periodic
    /// `reap` runs (a Public relay would otherwise leak one window per PoW solve). See the
    /// reap call in `advance_epoch`.
    pub fn cap_quota_windows_for_test(&self) -> usize {
        self.cap_quota.len()
    }

    /// Выдать capability клиенту (relay — сам issuer, §7.2). Возвращает копию,
    /// которую клиент хранит для построения proof'ов; секрет-запись остаётся и
    /// у relay для верификации.
    pub fn issue_capability(&mut self, cap: Capability) {
        self.capabilities.insert(cap);
    }

    /// Add (or update) a relay descriptor in the node list (discovery plane). **Operator-
    /// curated only** in this slice — self + `KARST_RELAY_PEERS`, never merged from untrusted
    /// gossip: re-serving a peer-heard address without dialing it first would let any relay
    /// aim every client at a victim IP (reflection). That merge, with dial-verification + rate
    /// limits, is a separate slice. Dedups by relay-id (unions addr hints), bounded.
    pub fn add_relay(&mut self, mut d: RelayDescriptor) {
        d.addrs.truncate(MAX_ADDRS_PER_RELAY);
        d.addrs.retain(|a| !a.is_empty() && a.len() <= MAX_ADDR_LEN);
        if d.addrs.is_empty() {
            return; // a descriptor with no dial hint is useless (and would poison the list)
        }
        let id = d.id();
        if let Some(existing) = self.known_relays.iter_mut().find(|e| e.id() == id) {
            for a in d.addrs {
                if existing.addrs.contains(&a) {
                    continue;
                }
                // Addresses used to be append-only up to the cap, so once four STALE addresses were
                // stored, a relay that changed address could never be reached again — its new,
                // working address was silently dropped (A3-13). Evict the oldest instead: entries
                // are kept newest-last, and only a freshly VERIFIED descriptor reaches this point.
                if existing.addrs.len() >= MAX_ADDRS_PER_RELAY {
                    existing.addrs.remove(0);
                }
                existing.addrs.push(a);
            }
        } else if self.known_relays.len() < MAX_KNOWN_RELAYS {
            self.known_relays.push(d);
        }
    }

    /// The full known-relay set (self + curated peers + verified-gossiped). For the gossip
    /// loop, which pulls each peer's list and merges new entries AFTER dial-verification.
    pub fn known_relays(&self) -> Vec<RelayDescriptor> {
        self.known_relays.clone()
    }

    /// §12 4c — set this relay's own descriptor (advertised in the node-list). Set by the binary
    /// only when the relay advertises a routable address.
    pub fn set_self_descriptor(&mut self, d: RelayDescriptor) {
        self.self_descriptor = Some(d);
    }

    /// §12 4c — publish (or rotate) an opt-in discovery record. Accepts iff (a) the slot matches
    /// `discovery_pseudonym(record.discovery_pub)`, (b) the write is authorised by the discovery
    /// key (`write_sig`), so only the code's owner writes its slot, and (c) the IK actually signed
    /// the code→IK binding (`ik_sig`), so the relay never stores a record pointing a code at a
    /// victim IK. `expiry` is clamped to `[now, now + MAX_TTL]`. Bounded like `bundles`
    /// (overwrite own slot freely; refuse a NEW slot once full).
    pub fn handle_publish_discovery(&mut self, record: &DiscoveryRecord, write_sig: &[u8], now: u64) -> bool {
        let pseudonym = discovery::discovery_pseudonym(&record.discovery_pub);
        if record.expiry <= now || record.expiry > now.saturating_add(discovery::MAX_TTL_SECS) {
            return false;
        }
        if !discovery::verify_binding(record) {
            return false;
        }
        let write_msg = discovery::write_msg(&record.discovery_pub, &record.ik, &record.location, record.expiry, record.single_use);
        if !discovery::verify(&record.discovery_pub, &write_msg, write_sig) {
            return false;
        }
        if !self.discovery.contains_key(&pseudonym) && self.discovery.len() >= MAX_BUNDLES {
            return false;
        }
        // Bound the attacker-controlled, unsigned `addrs` before storing (count + length) —
        // mirror `add_relay`. Without this a valid-but-bloated record is a memory-growth DoS.
        let mut record = record.clone();
        record.location.addrs.truncate(MAX_ADDRS_PER_RELAY);
        record.location.addrs.retain(|a| !a.is_empty() && a.len() <= MAX_ADDR_LEN);
        self.discovery.insert(pseudonym, record);
        true
    }

    /// §12 4c — delete a discovery record (turn discovery off). Authorised by a discovery-key
    /// signature over `delete_msg`, so only the owner can remove its own slot.
    pub fn handle_delete_discovery(&mut self, discovery_pub: &[u8; 32], delete_sig: &[u8]) -> bool {
        if !discovery::verify(discovery_pub, &discovery::delete_msg(discovery_pub), delete_sig) {
            return false;
        }
        self.discovery.remove(&discovery::discovery_pseudonym(discovery_pub)).is_some()
    }

    /// §12 4c — resolve a discovery pseudonym to its record. Public read (a resolver re-verifies
    /// the IK binding itself). Expired records are dropped lazily here and never returned.
    /// **Not private**: the relay sees which pseudonym was queried (mailbox-PIR would hide it, but
    /// that is walled — see STATUS). Honest residual: the relay could withhold or stale a record
    /// (an availability attack, not a MITM — identity stays anchored on the IK the resolver checks).
    pub fn handle_lookup_discovery(&mut self, pseudonym: &[u8; 32], now: u64) -> Option<DiscoveryRecord> {
        match self.discovery.get(pseudonym) {
            Some(rec) if rec.expiry > now => {
                let rec = rec.clone();
                // One-time invite: consume it — the next lookup finds nothing. Best-effort (an
                // honest relay; a hostile one could re-serve, but never forge the signed IK).
                if rec.single_use {
                    self.discovery.remove(pseudonym);
                }
                Some(rec)
            }
            Some(_) => {
                self.discovery.remove(pseudonym);
                None
            }
            None => None,
        }
    }

    /// The relay descriptors to serve for `GetNodeList`, trimmed to fit one response frame so
    /// the list never overflows the wire ceiling.
    pub fn node_list(&self) -> Vec<RelayDescriptor> {
        let budget = crate::wire::MAX_RESPONSE_FRAME - 512; // headroom for enum tag + framing
        let mut out = Vec::new();
        let mut used = 0usize;
        let n = self.known_relays.len();
        if n == 0 {
            return out;
        }
        // Start at a ROTATING offset, and keep walking past an entry that does not fit instead of
        // stopping at it. Always starting from index 0 and breaking on the first oversized
        // descriptor meant the relays at the front propagated on every single round while the tail
        // could never leave this node — a permanent centrality bias toward whoever was learned
        // first, and no recovery for a relay that changed address (A3-13). Self is seeded at index
        // 0 and must still be advertised, or a peer cannot verify us, so it is always included.
        let start = self.gossip_cursor.get() % n;
        self.gossip_cursor.set(start.wrapping_add(1));
        for k in 0..n {
            let i = if k == 0 { 0 } else { (start + k) % n };
            if k > 0 && i == 0 {
                continue; // self already emitted
            }
            let d = &self.known_relays[i];
            let sz = postcard::to_stdvec(d).map(|v| v.len()).unwrap_or(usize::MAX);
            if used + sz > budget {
                continue; // too big for what is left — try the next one, do not end the page
            }
            used += sz;
            out.push(d.clone());
        }
        out
    }

    /// §7 slice 4a — make this a PUBLIC relay: issue STATELESS PoW capabilities at
    /// `difficulty_bits`. Arms the capability table's stateless verifier with the persistent
    /// issuer key (derived from the node key, so PoW caps survive restarts). Off by default;
    /// a relay that never calls this is a closed (Private/Dev) door.
    pub fn enable_pow_issue(&mut self, difficulty_bits: u32) {
        self.set_pow_issue(Some(difficulty_bits));
    }

    /// Change the door policy at RUNTIME (owner control — see the relay binary's admin socket):
    /// `None` = issuance OFF (no new capabilities); `Some(0)` = OPEN (issue with no
    /// proof-of-work — the per-capability quota still bounds each, for early stages with no
    /// spam/Sybil pressure); `Some(bits)` = PoW-gated at `bits` difficulty.
    ///
    /// Turning issuance OFF does NOT invalidate already-earned capabilities: the stateless
    /// verifier stays armed once enabled, so outstanding caps keep working — only NEW
    /// issuance stops. Enabling issuance for the first time arms the verifier.
    pub fn set_pow_issue(&mut self, difficulty: Option<u32>) {
        if difficulty.is_some() {
            // Arm the stateless verifier once (idempotent). Kept armed even when issuance is
            // later turned off, so caps issued earlier still verify.
            self.capabilities.set_pow_issuer(self.relay_identity.issuer_key());
        }
        self.pow_issue = difficulty;
    }

    /// Current door policy: `None` = issuance off, `Some(0)` = open (no PoW), `Some(n)` = n-bit
    /// PoW. For the admin `pow status` command.
    pub fn pow_difficulty(&self) -> Option<u32> {
        self.pow_issue
    }

    /// Set the operator quota CEILING (`None` = off, no ceiling). Applied live on every request and
    /// stamped on newly-issued capabilities — an admin `quota` change bites immediately, existing
    /// capabilities included. See [`RelayNode::quota_policy`].
    pub fn set_quota_policy(&mut self, quota: Option<Quota>) {
        self.quota_policy = quota;
    }

    /// The current operator quota ceiling (`None` = off). For the admin `quota status` command.
    pub fn quota_policy(&self) -> Option<Quota> {
        self.quota_policy
    }

    /// The current PoW challenge, if this relay issues (Public). `(bucket, difficulty_bits)`.
    /// The relay declares the bucket so the client and relay agree on it without depending on
    /// the client's clock (`WireResponse::PowRequired`).
    pub fn pow_policy(&self, now: u64) -> Option<(u32, u32)> {
        self.pow_issue.map(|bits| ((now / POW_WINDOW_SECS) as u32, bits))
    }

    /// §7 slice 4a — redeem a PoW solution for a capability (the Public door). Verifies the
    /// solution is fresh (bucket within skew of now) and meets the difficulty, then DERIVES a
    /// stateless capability from the issuer key. Nothing is stored: replaying the same
    /// solution re-derives the identical capability (same id → same secret → same quota
    /// bucket), so redemption is idempotent and the door cannot be filled.
    pub fn handle_join(&mut self, req: &JoinRequest, now: u64) -> Result<Capability, String> {
        let Some(bits) = self.pow_issue else {
            return Err("issuance disabled (this relay is not public)".into());
        };
        // Bucket freshness: accept `now`'s bucket ± skew (clock drift + solve time). Saturating
        // arithmetic — `req.bucket` is attacker-controlled and must not overflow.
        let cur = (now / POW_WINDOW_SECS) as u32;
        let too_old = req.bucket.saturating_add(POW_BUCKET_SKEW) < cur;
        let too_new = cur.saturating_add(POW_BUCKET_SKEW) < req.bucket;
        if too_old || too_new {
            return Err("stale or future PoW bucket".into());
        }
        let relay_id = *self.relay_identity.public.as_bytes();
        if !admission::pow::verify(&relay_id, req.bucket, &req.client_seed, req.nonce, bits) {
            return Err("insufficient proof-of-work".into());
        }
        // Deterministic issuance. `not_after` is a function of the BUCKET (not `now`), so a
        // replayed redemption derives the identical secret → the identical capability.
        let issuer = self.relay_identity.issuer_key();
        let cap_id = pow_cap_id(&issuer, &relay_id, req.bucket, &req.client_seed, req.nonce);
        let not_after = ((req.bucket as u64 + 1) * POW_WINDOW_SECS + ISSUED_CAP_TTL_SECS)
            .min(u32::MAX as u64) as u32;
        let scope = Scope::MessageDelivery; // fetch is cookie+DH-gated, not capability-gated
        let secret = pow_cap_secret(&issuer, &cap_id, not_after, scope);
        Ok(Capability {
            capability_id: cap_id,
            scope,
            // Stamp the operator's policy quota on the issued cap (so a cap holder SEES its budget);
            // enforcement clamps to the live policy again anyway. `None` policy ⇒ the built-in default.
            quota: self.quota_policy.unwrap_or(POW_CAP_QUOTA),
            not_before: now as u32,
            not_after,
            secret,
        })
    }

    /// Продвинуть эпоху по часам сервера. МОНОТОННО (`e > self.epoch`): регресс
    /// стенных часов не откатит эпоху и не обнулит replay-фильтр через
    /// `roll_epoch`. Ключ генерим ЛЕНИВО — только при реальной смене эпохи.
    /// pipeline-epoch и ротация cookie-ключей оба выведены из
    /// `cookie_epoch_id(now)` → когерентны по построению. (Остаётся именованным:
    /// регресс часов ВНУТРИ эпохи всё ещё смещает 30-сек freshness cookie;
    /// настоящий фикс — монотонные часы, вне среза.)
    fn advance_epoch(&mut self, now: u64) {
        let e = cookie_epoch_id(now, EPOCH_DURATION_SECS);
        if e > self.epoch {
            self.keyring.rotate_if_needed(now, random_key());
            self.epoch = e;
            // Piggyback the periodic sweeps on the (once-per-epoch) advance — no background
            // thread, no extra lock surface.
            self.sweep_mailboxes(now);
            // Reap idle capability-quota windows. CRITICAL for a PUBLIC relay: every PoW
            // capability has a distinct `cap_id`, so without this the quota map would grow by
            // one permanent entry per solve — an unbounded-memory DoS on the very door slice
            // 4a hardens (the stateless cap removed the CAP table, but the QUOTA map is the
            // other place per-cap state lived). Safe for all cap types: an active window is
            // kept, an idle one is dropped and simply re-created on the next send.
            self.cap_quota.reap(now, EPOCH_DURATION_SECS);
            if let Some(blobs) = &mut self.blobs {
                blobs.sweep(now);
            }
        }
    }

    /// Drop undelivered mailbox entries older than `MAILBOX_TTL_SECS`, and forget any
    /// mailbox left empty. Monotonic-clock note: a `now` that regressed within an
    /// epoch can't trigger this (the `e > self.epoch` gate), and `saturating_sub`
    /// makes a regressed timestamp look FRESH (kept), never spuriously stale.
    fn sweep_mailboxes(&mut self, now: u64) {
        self.mailboxes.retain(|_, mbox| {
            mbox.retain(|e| now.saturating_sub(e.enqueued_at) <= MAILBOX_TTL_SECS);
            !mbox.is_empty()
        });
    }

    /// Обработать входящее сообщение. `now` — часы узла.
    pub fn handle(&mut self, msg: &WireMessage, now: u64) -> Response {
        self.advance_epoch(now);

        // raw_len ≈ размер груза + служебные поля (для Ступени 0).
        let raw_len = msg.payload.approx_len() + 128;
        let req = Request {
            raw_len,
            client_addr: &msg.client_addr,
            carrier_id: &msg.carrier_id,
            cookie: msg.cookie,
            request_nonce: &msg.request_nonce,
            requested_scope: Scope::MessageDelivery,
            credential: Credential::Capability(msg.capability_proof),
        };
        let pipe = AdmissionPipeline {
            keyring: &self.keyring,
            capabilities: &self.capabilities,
            token_verifier: &self.verifier,
            issuer_ring: &self.issuer_ring,
        };
        let policy = self.quota_policy;
        let outcome = pipe.process_with_policy(
            &req,
            now,
            self.epoch,
            [0u8; 64],
            &mut self.replay,
            &mut self.cap_quota,
            policy,
        );
        match outcome {
            Outcome::Challenge(_) => {
                // Первый контакт: выдать cookie, привязанный к адресу клиента.
                let cookie = self.keyring.issue(&msg.client_addr, &msg.carrier_id, now as u32);
                Response::NeedCookie(cookie)
            }
            Outcome::Admit => {
                // Cap на ВСТАВКЕ держит инвариант «mailbox всегда влезает в один
                // кадр ответа» по построению → fetch никогда не упрётся в
                // FrameTooLarge ПОСЛЕ drain'а (иначе — тихая потеря всей очереди
                // офлайн-получателя). Полный ящик = backpressure отправителю, не
                // молчаливый сброс. В духе admission-троттлинга.
                let mbox = self.mailboxes.entry(msg.recipient).or_default();
                if mbox.len() >= crate::wire::MAX_FETCH_SEALS {
                    Response::Rejected("MailboxFull".into())
                } else {
                    mbox.push(MailboxEntry { enqueued_at: now, leased_until: 0, payload: msg.payload.clone() });
                    Response::Accepted
                }
            }
            other => Response::Rejected(format!("{:?}", other)),
        }
    }

    /// Аутентифицированный fetch (§7-владение mailbox). Требует cookie
    /// (DoS-гейт + свежесть, как send) И доказательство владения приватным
    /// ключом `mailbox`. Без доказательства — `Reject`, **mailbox НЕ трогается**
    /// (иначе кто угодно, зная pubkey-адрес, сливал бы чужую очередь).
    pub fn handle_fetch(&mut self, req: &FetchRequest, now: u64) -> FetchResponse {
        self.advance_epoch(now);

        // Cookie: нет/невалиден → challenge (как на send).
        let cookie = match req.cookie {
            Some(c) if self.keyring.verify(&c, &req.client_addr, &req.carrier_id, now).is_ok() => c,
            _ => {
                let cookie = self.keyring.issue(&req.client_addr, &req.carrier_id, now as u32);
                return FetchResponse::NeedCookie(cookie);
            }
        };

        // Ownership proof. A BLINDED drop-box (a Ristretto address) has no DH with the relay's
        // X25519 key, so it proves knowledge of its fetch secret (Schnorr); the IDENTITY mailbox
        // (an X25519 key) proves via DH. Either failure rejects WITHOUT draining.
        if !mailbox_owner_ok(&self.relay_identity, req.mailbox, &cookie.mac, req.proof, &req.own_proof) {
            return FetchResponse::Rejected("fetch auth failed".into());
        }

        // Fixed-size fetch (§2.2): take at most one page worth of seals (`FETCH_CAP`
        // and within the page body budget); leave the rest queued for the next poll.
        // The response is later serialized into a constant-size page, so an on-path
        // observer cannot read the queue depth from the response length.
        //
        // Only VISIBLE entries are served: a message leased by an earlier `ack`-mode
        // fetch stays hidden until its lease expires (`leased_until <= now` again) or an
        // ACK deletes it. Indices are collected so lease/delete acts on the exact served
        // entries even when leased and visible entries are interleaved.
        let (seals, served): (Vec<Payload>, Vec<usize>) = match self.mailboxes.get(&req.mailbox) {
            Some(mbox) => {
                let (idx, payloads): (Vec<usize>, Vec<Payload>) = mbox
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| e.leased_until <= now)
                    .map(|(i, e)| (i, e.payload.clone()))
                    .unzip();
                let take = crate::wire::FetchPage::fit_prefix(&payloads);
                (
                    payloads.into_iter().take(take).collect(),
                    idx.into_iter().take(take).collect(),
                )
            }
            None => (Vec::new(), Vec::new()),
        };
        if let Some(mbox) = self.mailboxes.get_mut(&req.mailbox) {
            if req.ack {
                // Lease mode: keep the served messages, hide them until the lease expires
                // or an ACK deletes them. The client will ACK once it has durably
                // persisted the advanced ratchet state.
                for i in served {
                    mbox[i].leased_until = now + LEASE_SECS;
                }
            } else {
                // Legacy delete-on-fetch: remove the served entries now (descending index
                // keeps the earlier ones valid as we go).
                for i in served.into_iter().rev() {
                    mbox.remove(i);
                }
                if mbox.is_empty() {
                    self.mailboxes.remove(&req.mailbox);
                }
            }
        }
        FetchResponse::Fetched(seals)
    }

    /// Delete leased messages a recipient has durably persisted. Same ownership proof as
    /// `handle_fetch` (a delete-by-address weaker than the fetch gate would let anyone who
    /// knows the public mailbox address wipe someone's queue). Unknown / already-swept ids
    /// are silently ignored — an ACK is idempotent, so a redelivered-then-reacked message
    /// is not an error. A message not yet acked but whose lease expired is deletable too:
    /// the id still matches, and deleting it is exactly what a late ACK should do.
    pub fn handle_ack(&mut self, req: &AckRequest, now: u64) -> AckResponse {
        self.advance_epoch(now);

        let cookie = match req.cookie {
            Some(c) if self.keyring.verify(&c, &req.client_addr, &req.carrier_id, now).is_ok() => c,
            _ => {
                let cookie = self.keyring.issue(&req.client_addr, &req.carrier_id, now as u32);
                return AckResponse::NeedCookie(cookie);
            }
        };

        if !mailbox_owner_ok(&self.relay_identity, req.mailbox, &cookie.mac, req.proof, &req.own_proof) {
            return AckResponse::Rejected("ack auth failed".into());
        }

        // Bounded work, and each payload hashed ONCE.
        //
        // This ran `payload_id` — a full serialization plus SHA-256 — inside a nested loop, once
        // per (queued message, requested id) PAIR, with `ids` limited only by the request frame.
        // One authenticated ack could therefore make the relay perform hundreds of thousands of
        // hashes while holding the global mutex, stalling every other client, and could be
        // repeated for free (SEC-28). A recipient can never legitimately ack more than a mailbox
        // can hold, so anything beyond that is refused rather than served.
        if req.ids.len() > MAX_ACK_IDS {
            return AckResponse::Rejected("too many ids in one ack".into());
        }
        if let Some(mbox) = self.mailboxes.get_mut(&req.mailbox) {
            let wanted: std::collections::HashSet<[u8; 32]> = req.ids.iter().copied().collect();
            mbox.retain(|e| !wanted.contains(&payload_id(&e.payload)));
            if mbox.is_empty() {
                self.mailboxes.remove(&req.mailbox);
            }
        }
        AckResponse::Acked
    }

    /// §12 публикация bundle. Cookie-gate (DoS/свежесть, как fetch) + ownership-
    /// proof владения IK. `bundle.ik_pub` — ключ хранения. Перезапись своего —
    /// всегда; новый IK при полном хранилище → отказ (не тихий сброс).
    pub fn handle_publish(&mut self, req: &PublishRequest, now: u64) -> PublishResponse {
        self.advance_epoch(now);

        let cookie = match req.cookie {
            Some(c) if self.keyring.verify(&c, &req.client_addr, &req.carrier_id, now).is_ok() => c,
            _ => {
                let cookie = self.keyring.issue(&req.client_addr, &req.carrier_id, now as u32);
                return PublishResponse::NeedCookie(cookie);
            }
        };

        let ik = req.bundle.ik_pub;
        let shared = self.relay_identity.dh(&PublicKey::from(ik));
        // Low-order guard (как fetch-auth): нулевой общий секрет известен атакующему.
        if shared.ct_eq(&[0u8; 32]).unwrap_u8() == 1 {
            return PublishResponse::Rejected("publish auth failed".into());
        }
        let expected = publish_proof(&shared, &cookie.mac, &req.bundle);
        if expected.ct_eq(&req.proof).unwrap_u8() != 1 {
            return PublishResponse::Rejected("publish auth failed".into());
        }

        // Bounded: перезапись существующего IK — ок; новый при полноте — отказ.
        if !self.bundles.contains_key(&ik) && self.bundles.len() >= MAX_BUNDLES {
            return PublishResponse::Rejected("BundleStoreFull".into());
        }
        self.bundles.insert(ik, req.bundle.clone());
        // NOTE: publishing a bundle does NOT make you findable. Discovery is a separate, explicit
        // opt-in (`PublishDiscovery`) so that merely being reachable never leaks fact-of-partici-
        // pation into a lookup-able directory. See `handle_publish_discovery`.
        // Top up the one-time-prekey batch, capped so a client cannot make the relay hold
        // unbounded state. The relay does NOT dedup: it relies on the client advertising ONLY
        // freshly minted keys per publish (client `publish_with_opks` → `Peer::publish`), so each
        // key is appended at most once and a fetch hands out a distinct one. A client that
        // violates this only harms ITSELF — a re-advertised key can be handed to two of its own
        // first-contacts, and the second opener then fails closed (its OPK already consumed). Bug
        // C was exactly this: the client used to re-advertise the whole held set every publish.
        //
        // `replace_opks` is how a client says "forget what you are holding for me". Appending is
        // right for a top-up, but WRONG after the client lost its secrets (a restored backup, a
        // damaged sidecar): the relay would keep handing out public keys whose secrets no longer
        // exist, and every initiator that got one produced an opener the recipient could not
        // accept — until 256 stale entries filled the queue and new keys could not even be stored
        // (R2-4). The flag is authenticated exactly like the rest of the request: it rides inside
        // the publish proof, so only the IK's owner can clear that IK's queue.
        if req.replace_opks {
            self.opk_batches.remove(&ik);
        }
        let batch = self.opk_batches.entry(ik).or_default();
        for opk in &req.opks {
            if batch.len() >= MAX_OPKS_PER_IK {
                break;
            }
            // Verify the publisher's signature before storing. The relay gains nothing by
            // holding a key it could never hand out usefully, and a fetcher that received one
            // would burn a first contact on it — so junk is dropped at the door, not forwarded.
            // ONE verification per key: `SignedOpk::verify` checks only the OPK signature, where
            // building a probe bundle would have re-checked the prekey signature 256 times over.
            if !opk.verify(&ik) {
                continue;
            }
            batch.push_back(opk.clone());
        }
        PublishResponse::Published
    }

    /// §12 fetch bundle — ПУБЛИЧНЫЙ (bundle = публичный материал, без auth).
    /// `None` — не опубликован. Внимание: relay НЕ доверенный якорь личности —
    /// подлинность возвращённого IK проверяется вне канала (см. STATUS).
    pub fn get_bundle(&mut self, ik: &[u8; 32]) -> Option<PreKeyBundle> {
        let mut bundle = self.bundles.get(ik).cloned()?;
        // Hand out (and consume) ONE one-time prekey, if any remain. Exhaustion is not an
        // error: the fetcher falls back to the 3-DH agreement (`opk == None`) and is told so.
        bundle.opk = self.opk_batches.get_mut(ik).and_then(|b| b.pop_front());
        Some(bundle)
    }
}

/// Запрос §12-публикации bundle. `proof` привязывает владение приватным IK
/// (`bundle.ik_pub`) к cookie.mac и содержимому bundle.
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
    pub proof: [u8; 16],
}

/// Ответ на §12-публикацию.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PublishResponse {
    /// Нужен (свежий) cookie — клиент перевыдаёт и повторяет.
    NeedCookie(Cookie),
    /// Опубликовано (bundle сохранён/перезаписан).
    Published,
    /// Отклонено (провал auth / хранилище полно).
    Rejected(String),
}

/// Запрос на выборку mailbox. `mailbox` = pubkey получателя (его адрес);
/// `proof` привязывает владение приватным ключом к `cookie.mac`.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct FetchRequest {
    pub mailbox: [u8; 32],
    pub client_addr: Vec<u8>,
    pub carrier_id: Vec<u8>,
    pub cookie: Option<Cookie>,
    /// DH ownership proof (`fetch_proof`), used for the IDENTITY mailbox (an X25519 key). Empty/
    /// ignored when `own_proof` is set.
    pub proof: [u8; 16],
    /// Lease instead of delete: `true` means "I will ACK once persisted", so the relay
    /// keeps the served messages (hidden for `LEASE_SECS`) rather than deleting them on
    /// fetch. `false` is the legacy at-most-once delete-on-fetch — a path that fetches
    /// leased and never ACKs would redeliver until the lease/TTL expires, so only a
    /// caller that follows through with `AckRequest` sets this.
    #[serde(default)]
    pub ack: bool,
    /// Schnorr ownership proof (`blind::FetchOwnershipProof`, 64 bytes) for a BLINDED drop-box —
    /// a Ristretto address has no DH with the relay's X25519 key, so it proves knowledge of the
    /// fetch secret (the discrete log of the address) instead. Empty = use the DH `proof` (the
    /// identity mailbox). Bound to the cookie MAC as its context (anti-replay).
    #[serde(default)]
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
    #[serde(default)]
    pub own_proof: Vec<u8>,
}

/// Ответ на ACK.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum AckResponse {
    /// Нужен (свежий) cookie — клиент перевыдаёт и повторяет (как fetch).
    NeedCookie(Cookie),
    /// Named messages deleted (or already gone — ACK is idempotent).
    Acked,
    /// Отклонено (в т.ч. провал ownership-proof) — mailbox не тронут.
    Rejected(String),
}

/// Ответ на fetch.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum FetchResponse {
    /// Нужен (свежий) cookie — клиент перевыдаёт и повторяет.
    NeedCookie(Cookie),
    /// Authenticated: sealed objects for this poll — at most one fixed-size page
    /// worth (`FETCH_CAP`); any remainder stays queued for the next poll.
    Fetched(Vec<Payload>),
    /// Отклонено (в т.ч. провал fetch-auth) — mailbox не тронут.
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
}

impl RelayDescriptor {
    /// The relay-id bytes (`noise_pub ‖ fetch_pub`) — the dedup key.
    fn id(&self) -> [u8; 64] {
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

/// §15 large-file upload: one ciphertext chunk of an E2E-encrypted blob. Cookie-gated
/// (DoS/freshness, like fetch). `client_addr` is the self-declared sender used for blob
/// ownership + best-effort per-sender caps — NOT strongly authenticated in the skeleton
/// (see the blob-store DoS note); the per-blob / global caps + TTL are the hard bounds.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BlobPutRequest {
    pub client_addr: Vec<u8>,
    pub carrier_id: Vec<u8>,
    pub cookie: Option<Cookie>,
    pub blob_id: [u8; 32],
    pub index: u32,
    pub count: u32,
    pub data: Vec<u8>,
}

/// §15 large-file download: fetch one ciphertext chunk. Bearer-by-id (knowing the
/// 256-bit `blob_id` is the download right — the bytes are ciphertext regardless);
/// cookie-gated for DoS.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BlobGetRequest {
    pub client_addr: Vec<u8>,
    pub carrier_id: Vec<u8>,
    pub cookie: Option<Cookie>,
    pub blob_id: [u8; 32],
    pub index: u32,
}

/// Response to a blob upload/download.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
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

/// Транспорт между клиентом и relay. In-memory реализация ниже; сокет-версия —
/// следующий срез, тот же контракт.
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

    /// §12 публикация bundle. По умолчанию не поддержано (тест-транспорты без
    /// discovery); реальные транспорты переопределяют.
    fn publish_bundle(&self, _req: &PublishRequest, _now: u64) -> PublishResponse {
        PublishResponse::Rejected("bundle publish unsupported".into())
    }

    /// §12 fetch bundle (публичный). `Ok(None)` — не опубликован; `Err` — сбой
    /// транспорта. По умолчанию не поддержано.
    fn fetch_bundle(&self, _ik: &[u8; 32], _now: u64) -> Result<Option<PreKeyBundle>, String> {
        Err("bundle fetch unsupported".into())
    }
}

/// In-process транспорт: клиент и relay — разные объекты, общаются через этот
/// канал (не прямой вызов), чтобы loopback моделировал две реальные точки.
#[derive(Clone)]
pub struct InMemoryTransport {
    relay: Rc<RefCell<RelayNode>>,
}

impl InMemoryTransport {
    pub fn new(relay: Rc<RefCell<RelayNode>>) -> Self {
        InMemoryTransport { relay }
    }
}

impl Transport for InMemoryTransport {
    fn send(&self, msg: &WireMessage, now: u64) -> Response {
        self.relay.borrow_mut().handle(msg, now)
    }
    fn fetch(&self, req: &FetchRequest, now: u64) -> FetchResponse {
        self.relay.borrow_mut().handle_fetch(req, now)
    }
    fn ack(&self, req: &AckRequest, now: u64) -> AckResponse {
        self.relay.borrow_mut().handle_ack(req, now)
    }
    fn publish_bundle(&self, req: &PublishRequest, now: u64) -> PublishResponse {
        self.relay.borrow_mut().handle_publish(req, now)
    }
    fn fetch_bundle(&self, ik: &[u8; 32], now: u64) -> Result<Option<PreKeyBundle>, String> {
        let _ = now; // публичный read, время не нужно
        Ok(self.relay.borrow_mut().get_bundle(ik))
    }
}

/// Тонкий клиент: запечатывает сообщение (§2.1-скелет), проходит admission
/// (§7) с реальным cookie round-trip и шлёт через транспорт.
pub struct Client<T: Transport> {
    transport: T,
    capability: Capability, // выдана relay; клиент хранит для proof'ов
    client_addr: Vec<u8>,
    carrier_id: Vec<u8>,
    cookie: Option<Cookie>,
    nonce_ctr: u64,
}

impl<T: Transport> Client<T> {
    pub fn new(transport: T, capability: Capability, client_addr: &[u8]) -> Self {
        Client {
            transport,
            capability,
            client_addr: client_addr.to_vec(),
            carrier_id: b"mem".to_vec(),
            cookie: None,
            nonce_ctr: 0,
        }
    }

    /// Отправить `plaintext` получателю с публичным ключом `recipient_pub`.
    ///
    /// Cookie-refresh: сервер отвечает `NeedCookie` и на первый контакт (cookie
    /// нет), и на ПРОТУХШИЙ/сменивший эпоху cookie (§7.1, `COOKIE_TTL_SECS`=30 —
    /// долгоживущий клиент неизбежно упрётся). Поэтому обрабатываем `NeedCookie`
    /// на КАЖДОЙ отправке и повторяем РОВНО раз с новым cookie; всё остальное
    /// (`Accepted`, реальный `Rejected` по capability) возвращаем сразу —
    /// «протух cookie → повтор» строго отделено от «плохой credential → сдаться».
    ///
    /// Тот же nonce+proof на повторе безопасен: challenge отдаётся на Ступени 1
    /// (cookie) ДО Ступени 3 (replay) и Ступени 4 (quota), т.е. первая попытка
    /// НИЧЕГО не записала — ни в replay-фильтр, ни в учёт квоты.
    pub fn send(
        &mut self,
        recipient_pub: &x25519_dalek::PublicKey,
        plaintext: &[u8],
        now: u64,
    ) -> Response {
        let sealed = SkeletonSeal::seal(recipient_pub, plaintext);
        let nonce = format!("req-{}", self.nonce_ctr).into_bytes();
        self.nonce_ctr += 1;
        let proof = self.capability.prove(&nonce, 0);

        let mut msg = WireMessage {
            client_addr: self.client_addr.clone(),
            carrier_id: self.carrier_id.clone(),
            cookie: self.cookie,
            request_nonce: nonce,
            capability_proof: proof,
            recipient: recipient_pub.to_bytes(),
            payload: Payload::Skeleton(sealed),
        };

        // До двух попыток: один challenge → refresh → один повтор.
        for _ in 0..2 {
            match self.transport.send(&msg, now) {
                Response::NeedCookie(c) => {
                    self.cookie = Some(c);
                    msg.cookie = Some(c);
                    continue;
                }
                other => return other,
            }
        }
        // Два challenge подряд — свежий cookie сразу отвергнут (аномалия, не
        // штатный протух). Не зацикливаемся и не маскируем: честная ошибка.
        Response::Rejected("persistent cookie challenge".into())
    }
}

/// Получатель: своя identity + транспорт + публичный ключ relay (для fetch-auth
/// DH). Забирает ТОЛЬКО свой mailbox (`mailbox` = собственный pubkey).
pub struct Recipient<T: Transport> {
    transport: T,
    identity: Identity,
    relay_pub: PublicKey,
    client_addr: Vec<u8>,
    carrier_id: Vec<u8>,
    cookie: Option<Cookie>,
}

impl<T: Transport> Recipient<T> {
    pub fn new(transport: T, identity: Identity, relay_pub: PublicKey) -> Self {
        // client_addr = свой pubkey: стабильная привязка cookie.
        let client_addr = identity.public.to_bytes().to_vec();
        Recipient { transport, identity, relay_pub, client_addr, carrier_id: b"mem".to_vec(), cookie: None }
    }

    pub fn public(&self) -> PublicKey {
        self.identity.public
    }

    /// Забрать входящие: cookie-handshake (как send) + доказательство владения
    /// mailbox, затем расшифровать. `Ok(vec)` — выборка (может быть пустой,
    /// `None`-элементы = не расшифровались); `Err` — провал (недоступен/протокол/
    /// отказ auth), отделено от «пусто», чтобы `recv` не путал их.
    pub fn receive(&mut self, now: u64) -> Result<Vec<Option<Vec<u8>>>, String> {
        let mailbox = self.identity.public.to_bytes();
        let shared = self.identity.dh(&self.relay_pub);
        // До двух попыток: один challenge → refresh → повтор с proof.
        for _ in 0..2 {
            let proof = match self.cookie {
                Some(c) => fetch_proof(&shared, &c.mac, &mailbox),
                None => [0u8; 16], // cookie ещё нет → сервер сделает challenge
            };
            let req = FetchRequest {
                mailbox,
                client_addr: self.client_addr.clone(),
                carrier_id: self.carrier_id.clone(),
                cookie: self.cookie,
                proof,
                // Skeleton receiver stays on legacy delete-on-fetch: it opens strangers'
                // openers, not the ratchet path that gains the lease/ACK durability.
                ack: false,
                own_proof: Vec::new(), // identity mailbox → DH proof above
            };
            match self.transport.fetch(&req, now) {
                FetchResponse::NeedCookie(c) => {
                    self.cookie = Some(c);
                    continue;
                }
                FetchResponse::Fetched(payloads) => {
                    // Скелет-получатель открывает только `Skeleton`; сессионные
                    // §2.1-конверты ему не адресованы (их обрабатывает `Peer`) —
                    // `None`, а не паника.
                    return Ok(payloads
                        .iter()
                        .map(|p| match p {
                            Payload::Skeleton(s) => s.open(&self.identity),
                            Payload::Session(_) => None,
                        })
                        .collect());
                }
                FetchResponse::Rejected(r) => return Err(r),
            }
        }
        Err("persistent cookie challenge".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqxdh::Account;

    const NOW: u64 = 1_000_000;

    #[test]
    fn sweep_mailboxes_drops_only_entries_past_ttl() {
        // Deterministic with the fake clock (no thread, no timing): a fresh entry
        // survives, an entry past MAILBOX_TTL_SECS is dropped and its empty mailbox
        // forgotten. Neuter `sweep_mailboxes` to a no-op and the "swept" case reddens.
        let mut relay = RelayNode::new(NOW);
        let ik = [9u8; 32];
        let seal = Payload::Skeleton(SkeletonSeal {
            ephemeral_pub: [1u8; 32],
            nonce: [2u8; 12],
            ciphertext: vec![0u8; 8],
        });
        relay.mailboxes.insert(ik, vec![MailboxEntry { enqueued_at: NOW, leased_until: 0, payload: seal }]);

        relay.sweep_mailboxes(NOW + MAILBOX_TTL_SECS - 1);
        assert_eq!(relay.mailboxes.get(&ik).map(Vec::len), Some(1), "fresh entry kept");

        relay.sweep_mailboxes(NOW + MAILBOX_TTL_SECS + 1);
        assert!(!relay.mailboxes.contains_key(&ik), "stale entry swept, empty mailbox gone");
    }

    /// §12 write-side auth: опубликовать bundle под чужим IK нельзя. Владелец
    /// (proof своим IK) — ок; чужой (proof своим IK под IK жертвы) — отказ.
    /// Останавливает deliverability-DoS (перезапись чужого bundle).
    #[test]
    fn publish_requires_ik_ownership_proof() {
        let mut relay = RelayNode::new(NOW);
        let relay_pub = relay.relay_public();
        let bob = Account::generate();
        let bundle = bob.prekey_bundle();
        let addr = bob.identity_public().to_vec();
        let carrier = b"c".to_vec();
        let cookie = relay.keyring.issue(&addr, &carrier, NOW as u32);

        // Владелец: proof под приватным IK Bob против relay — публикуется.
        let good = publish_proof(&bob.ik().dh(&relay_pub), &cookie.mac, &bundle);
        let ok = PublishRequest {
            bundle: bundle.clone(),
            opks: Vec::new(),
            replace_opks: false,
            client_addr: addr.clone(),
            carrier_id: carrier.clone(),
            cookie: Some(cookie),
            proof: good,
        };
        assert!(matches!(relay.handle_publish(&ok, NOW), PublishResponse::Published));
        assert!(relay.get_bundle(&bundle.ik_pub).is_some());

        // Чужой: Mallory заявляет IK Bob, но подписать может лишь СВОИМ ключом —
        // relay сверяет через DH(relay, bob_ik) → не сойдётся → отказ.
        let mallory = Account::generate();
        let mut forged = mallory.prekey_bundle();
        forged.ik_pub = bundle.ik_pub; // притворяемся Bob
        let bad = publish_proof(&mallory.ik().dh(&relay_pub), &cookie.mac, &forged);
        let attack = PublishRequest {
            bundle: forged,
            opks: Vec::new(),
            replace_opks: false,
            client_addr: addr,
            carrier_id: carrier,
            cookie: Some(cookie),
            proof: bad,
        };
        assert!(
            matches!(relay.handle_publish(&attack, NOW), PublishResponse::Rejected(_)),
            "чужой не должен перезаписать bundle под IK Bob"
        );
        // bundle Bob не тронут (тот же prekey, что опубликовал он).
        assert_eq!(relay.get_bundle(&bundle.ik_pub).unwrap().prekey_pub, bundle.prekey_pub);
    }

    /// Публикация без cookie → challenge (DoS-gate, как fetch).
    #[test]
    fn publish_without_cookie_is_challenged() {
        let mut relay = RelayNode::new(NOW);
        let bob = Account::generate();
        let req = PublishRequest {
            bundle: bob.prekey_bundle(),
            opks: Vec::new(),
            replace_opks: false,
            client_addr: bob.identity_public().to_vec(),
            carrier_id: b"c".to_vec(),
            cookie: None,
            proof: [0u8; 16],
        };
        assert!(matches!(relay.handle_publish(&req, NOW), PublishResponse::NeedCookie(_)));
        assert!(relay.get_bundle(&bob.identity_public()).is_none(), "без cookie ничего не сохранено");
    }

    // ---- lease / ACK (at-most-once → effectively-once receive) ----

    fn test_seal(n: u8) -> Payload {
        Payload::Skeleton(SkeletonSeal { ephemeral_pub: [n; 32], nonce: [n; 12], ciphertext: vec![n; 8] })
    }

    /// Build a valid authenticated `FetchRequest` for `recip`'s own mailbox: a fresh cookie
    /// at `now` (COOKIE_TTL is 30 s, so re-issue per call) + the ownership proof.
    fn fetch_at(relay: &mut RelayNode, recip: &Identity, now: u64, ack: bool) -> FetchRequest {
        let mailbox = recip.public.to_bytes();
        let cookie = relay.keyring.issue(&mailbox, b"c", now as u32);
        let shared = recip.dh(&relay.relay_public());
        let proof = fetch_proof(&shared, &cookie.mac, &mailbox);
        FetchRequest { mailbox, client_addr: mailbox.to_vec(), carrier_id: b"c".to_vec(), cookie: Some(cookie), proof, ack, own_proof: Vec::new() }
    }

    fn ack_at(relay: &mut RelayNode, recip: &Identity, now: u64, ids: Vec<[u8; 32]>) -> AckRequest {
        let mailbox = recip.public.to_bytes();
        let cookie = relay.keyring.issue(&mailbox, b"c", now as u32);
        let shared = recip.dh(&relay.relay_public());
        let proof = fetch_proof(&shared, &cookie.mac, &mailbox);
        AckRequest { mailbox, client_addr: mailbox.to_vec(), carrier_id: b"c".to_vec(), cookie: Some(cookie), proof, ids, own_proof: Vec::new() }
    }

    /// #29 wired LIVE: the deposit/fetch SEPARATION at the relay's fetch gate. A blinded drop-box
    /// is fetchable ONLY by the holder of its fetch secret (the recipient), NOT by the depositor —
    /// who computes the address from the recipient's public mailbox point `M` but cannot derive the
    /// fetch secret. "Can deposit" no longer implies "can read".
    #[test]
    fn a_blinded_box_is_fetchable_only_by_its_fetch_secret_holder() {
        let mut relay = RelayNode::new(NOW);
        let recipient_m = crate::blind::MailboxSecret::generate();
        let (seed, epoch, dir) = ([5u8; 32], 3u64, 0u8);
        let address = crate::blind::deposit_address(&recipient_m.public(), &seed, epoch, dir).unwrap();
        let fetch_secret = recipient_m.fetch_secret(&seed, epoch, dir);
        let mk = |cookie: Cookie, own: Vec<u8>, dh: [u8; 16]| FetchRequest {
            mailbox: address,
            client_addr: address.to_vec(),
            carrier_id: b"c".to_vec(),
            cookie: Some(cookie),
            proof: dh,
            ack: false,
            own_proof: own,
        };

        // The RECIPIENT (fetch-secret holder) is authorized — an empty box returns Fetched, not Rejected.
        let c = relay.keyring.issue(&address, b"c", NOW as u32);
        let own = crate::blind::FetchOwnershipProof::prove(&fetch_secret, &address, &c.mac).unwrap();
        let ok = relay.handle_fetch(&mk(c, own.to_bytes().to_vec(), [0u8; 16]), NOW);
        assert!(!matches!(ok, FetchResponse::Rejected(_)), "the fetch-secret holder is authorized");

        // The DEPOSITOR holds only M; a proof from ANY other mailbox secret fails → cannot read.
        let depositor = crate::blind::MailboxSecret::generate();
        let wrong = depositor.fetch_secret(&seed, epoch, dir);
        let c2 = relay.keyring.issue(&address, b"c", NOW as u32);
        let forged = crate::blind::FetchOwnershipProof::prove(&wrong, &address, &c2.mac).unwrap();
        let bad = relay.handle_fetch(&mk(c2, forged.to_bytes().to_vec(), [0u8; 16]), NOW);
        assert!(matches!(bad, FetchResponse::Rejected(_)), "a non-owner (the depositor) cannot fetch the box");

        // A DH proof (the identity-mailbox path) does not open a blinded Ristretto box either.
        let c3 = relay.keyring.issue(&address, b"c", NOW as u32);
        let dh = relay.handle_fetch(&mk(c3, Vec::new(), [0xAB; 16]), NOW);
        assert!(matches!(dh, FetchResponse::Rejected(_)), "a DH proof cannot open a Ristretto box");
    }

    fn fetched(resp: FetchResponse) -> Vec<Payload> {
        match resp {
            FetchResponse::Fetched(p) => p,
            FetchResponse::NeedCookie(_) => panic!("expected Fetched, got NeedCookie"),
            FetchResponse::Rejected(r) => panic!("expected Fetched, got Rejected({r})"),
        }
    }

    fn deposit(relay: &mut RelayNode, recip: &Identity, at: u64, payload: Payload) {
        relay
            .mailboxes
            .entry(recip.public.to_bytes())
            .or_default()
            .push(MailboxEntry { enqueued_at: at, leased_until: 0, payload });
    }

    fn boxed(relay: &RelayNode, recip: &Identity) -> bool {
        relay.mailboxes.contains_key(&recip.public.to_bytes())
    }

    /// SEC-28 — an ack must not be a cheap way to buy relay work.
    ///
    /// `payload_id` (serialize + SHA-256) used to run once per (queued message, requested id)
    /// PAIR, with the id list bounded only by the request frame — so one authenticated ack could
    /// force hundreds of thousands of hashes while holding the global mutex, repeatable for free.
    /// A recipient can never legitimately ack more than a mailbox can hold, so a longer list is
    /// refused outright; within the cap, each payload is hashed once.
    #[test]
    fn an_oversized_ack_is_refused_rather_than_served() {
        let mut relay = RelayNode::new(NOW);
        let recip = Identity::generate();
        let address = recip.public.to_bytes();
        let cookie = relay.keyring.issue(&address, b"c", NOW as u32);
        let shared = recip.dh(&relay.relay_public());
        let proof = fetch_proof(&shared, &cookie.mac, &address);

        let over = MAX_ACK_IDS + 1;
        let req = AckRequest {
            mailbox: address,
            client_addr: address.to_vec(),
            carrier_id: b"c".to_vec(),
            cookie: Some(cookie),
            proof,
            ids: vec![[7u8; 32]; over],
            own_proof: Vec::new(),
        };
        assert!(
            matches!(relay.handle_ack(&req, NOW), AckResponse::Rejected(_)),
            "an ack larger than a mailbox can hold must be refused, not processed"
        );

        // The same ack within the cap is still served normally — the guard must bound work, not
        // break acking.
        let ok = AckRequest { ids: vec![[7u8; 32]; MAX_ACK_IDS], ..req };
        assert!(
            !matches!(relay.handle_ack(&ok, NOW), AckResponse::Rejected(_)),
            "a legitimate full-size ack must still work"
        );
    }

    /// Legacy `ack: false` fetch still DELETES on read — the un-updated path is untouched.
    #[test]
    fn legacy_fetch_deletes_on_read() {
        let mut relay = RelayNode::new(NOW);
        let bob = Identity::generate();
        deposit(&mut relay, &bob, NOW, test_seal(1));

        let req = fetch_at(&mut relay, &bob, NOW, false);
        assert_eq!(fetched(relay.handle_fetch(&req, NOW)).len(), 1);
        // Gone immediately: a second fetch is empty.
        let req2 = fetch_at(&mut relay, &bob, NOW, false);
        assert!(fetched(relay.handle_fetch(&req2, NOW)).is_empty(), "legacy fetch drained the box");
    }

    /// `ack: true` LEASES: the message is returned but stays on the relay, hidden from a
    /// second fetch, until an ACK deletes it. This is the crash-safety window — the message
    /// survives on the relay across the [fetch, save] gap.
    #[test]
    fn lease_fetch_keeps_until_ack() {
        let mut relay = RelayNode::new(NOW);
        let bob = Identity::generate();
        deposit(&mut relay, &bob, NOW, test_seal(2));

        let req = fetch_at(&mut relay, &bob, NOW, true);
        let got = fetched(relay.handle_fetch(&req, NOW));
        assert_eq!(got.len(), 1);
        // Leased → invisible to a second immediate fetch, but NOT deleted.
        let req2 = fetch_at(&mut relay, &bob, NOW, true);
        assert!(fetched(relay.handle_fetch(&req2, NOW)).is_empty(), "leased message hidden");
        assert!(boxed(&relay, &bob), "still on relay before ACK");

        // ACK the id we hold → deleted.
        let ids: Vec<[u8; 32]> = got.iter().map(payload_id).collect();
        let ack = ack_at(&mut relay, &bob, NOW, ids);
        assert!(matches!(relay.handle_ack(&ack, NOW), AckResponse::Acked));
        assert!(!boxed(&relay, &bob), "ACK deleted the message");
    }

    /// A client that fetches-under-lease and then CRASHES (never ACKs) gets the exact
    /// message redelivered once the lease expires — this is what makes redelivery possible.
    #[test]
    fn lease_expires_and_redelivers() {
        let mut relay = RelayNode::new(NOW);
        let bob = Identity::generate();
        let payload = test_seal(3);
        deposit(&mut relay, &bob, NOW, payload.clone());

        let req = fetch_at(&mut relay, &bob, NOW, true);
        assert_eq!(fetched(relay.handle_fetch(&req, NOW)).len(), 1);
        // Before expiry: hidden. After LEASE_SECS: visible again, same ciphertext.
        let mid = NOW + LEASE_SECS - 1;
        let req_mid = fetch_at(&mut relay, &bob, mid, true);
        assert!(fetched(relay.handle_fetch(&req_mid, mid)).is_empty(), "still leased");
        let later = NOW + LEASE_SECS + 1;
        let req_late = fetch_at(&mut relay, &bob, later, true);
        let re = fetched(relay.handle_fetch(&req_late, later));
        assert_eq!(re.len(), 1);
        assert_eq!(payload_id(&re[0]), payload_id(&payload), "exact ciphertext redelivered");
    }

    /// ACK carries the SAME ownership proof as fetch: a wrong proof cannot delete mail.
    #[test]
    fn ack_requires_ownership_proof() {
        let mut relay = RelayNode::new(NOW);
        let bob = Identity::generate();
        deposit(&mut relay, &bob, NOW, test_seal(4));

        let req = fetch_at(&mut relay, &bob, NOW, true);
        let got = fetched(relay.handle_fetch(&req, NOW));
        let ids: Vec<[u8; 32]> = got.iter().map(payload_id).collect();
        // Forge the proof: valid shape, wrong value.
        let mut bad = ack_at(&mut relay, &bob, NOW, ids);
        bad.proof = [0xAB; 16];
        assert!(matches!(relay.handle_ack(&bad, NOW), AckResponse::Rejected(_)));
        assert!(boxed(&relay, &bob), "forged ACK deleted nothing");
    }

    /// TTL is measured from DEPOSIT, not from the lease: a client that keeps leasing and
    /// never ACKs cannot mint an immortal message — the deposit-time sweep still reaps it.
    #[test]
    fn ttl_runs_from_deposit_not_lease() {
        let mut relay = RelayNode::new(NOW);
        let bob = Identity::generate();
        deposit(&mut relay, &bob, NOW, test_seal(5));

        // Lease it (leased_until = NOW + LEASE_SECS — a "fresh" lease)...
        let req = fetch_at(&mut relay, &bob, NOW, true);
        let _ = relay.handle_fetch(&req, NOW);
        // ...yet the sweep at deposit + TTL still removes it, lease notwithstanding.
        relay.sweep_mailboxes(NOW + MAILBOX_TTL_SECS + 1);
        assert!(!boxed(&relay, &bob), "deposit-time TTL reaps a never-acked lease");
    }
}
