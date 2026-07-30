//! Тонкие RelayNode и Client + транспорт. Ровно столько, чтобы провести одно
//! сообщение Alice → relay → Bob. Богатый API узла — задача следующих срезов.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use admission::capability::{
    pow_cap_id, pow_cap_secret, Capability, CapabilityQuotaTracker,
    CapabilityTable, Quota, Scope, POW_CAP_QUOTA,
};
use admission::cookie::{Cookie, CookieKeyring};
use admission::params::{
    cookie_epoch_id, EPOCH_DURATION_SECS, ISSUED_CAP_TTL_SECS, POW_BUCKET_SKEW, POW_WINDOW_SECS,
};
use admission::pipeline::{AdmissionPipeline, Credential, Outcome, ReplayFilter, Request};
use admission::token::{IssuerRing, NoTokenVerifier};
use rand::rngs::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;
use x25519_dalek::PublicKey;

// Re-exported so `node::` keeps naming the whole vocabulary for now. The extraction is a MOVE,
// not a rename: call sites across the workspace stay untouched in this slice, and the internal
// modules are pointed at `protocol` directly (which is what actually breaks the cycle).
pub use node::protocol::*;
use node::discovery::{self, DiscoveryRecord};
use node::pqxdh::PreKeyBundle;
use node::seal::Identity;

/// Потолок числа опубликованных bundle (§12): при полноте — отказ на публикацию
/// нового IK, НЕ тихий сброс (та же дисциплина, что `MAX_FETCH_SEALS`).
/// Перезапись СВОЕГО bundle всегда разрешена (не считается новым).
pub const MAX_BUNDLES: usize = 100_000;

/// What one signed one-time prekey costs the relay, for quota purposes: the 32-byte key, its
/// 64-byte signature, and the postcard framing around them. Deliberately the STORED size rather
/// than the wire size — the relay holds it until a fetcher takes it, and that is the resource
/// the byte budget exists to bound.
/// Admission cost charged for ONE published one-time prekey unit. Tracks the wire size in
/// `wire::SIGNED_OPK_WIRE`: the X25519 key, the one-time ML-KEM-768 encapsulation key and the
/// signature covering both. Undercharging here would make the PQ half free to publish, which is
/// most of the bytes the relay then stores and serves.
const SIGNED_OPK_COST: usize = 32 + 1184 + 64 + 24;

/// How long a published bundle survives without being republished. 30 days: a client republishes
/// on launch and on announce, so an account in ANY use stays live, while an abandoned or
/// Sybil-minted slot returns its capacity instead of holding it until the process restarts.
/// The one-time-prekey batch is swept with its bundle — the two are one resource.
pub const BUNDLE_TTL_SECS: u64 = 30 * 24 * 60 * 60;


/// Fixed wire size of an ML-KEM-768 encapsulation key (FIPS 203) — `PreKeyBundle::kem_ek`.
/// Mirrors the same literal `wire::PREKEY_BUNDLE_WIRE` already hardcodes for its frame-size
/// estimate (see its doc comment); enforced here as an actual check, not just an estimate.
const ML_KEM_768_EK_LEN: usize = 1184;
/// Fixed size of an XEdDSA signature (`PreKeyBundle::prekey_sig`, `SignedOpk::sig`).
const XEDDSA_SIG_LEN: usize = 64;


/// Ceiling on DISTINCT mailbox keys (recipients holding at least one queued message),
/// independent of `MAILBOX_TTL_SECS` and of the per-mailbox `MAX_FETCH_SEALS` cap. `recipient`
/// in `WireMessage` is any 32 bytes the SENDER picks — never checked against a published
/// bundle or any other proof the address belongs to someone — so an admitted sender can deposit
/// one message to a fresh fabricated address every send, and admission (capability + quota)
/// throttles the RATE new keys appear, never their total COUNT.
///
/// This is NOT a one-entry-per-identity table like `bundles` — do not size it that way.
/// `drop.rs`'s rotating drop-boxes mean one ACTIVE session alone can hold up to `2` (directions,
/// `drop::direction`) `× (TTL_EPOCHS + 2)` distinct live keys — `TTL_EPOCHS =
/// MAILBOX_TTL_SECS / DROP_EPOCH_SECS = 7`, so up to 18 keys for a single busy two-way
/// conversation, on top of one long-term identity-key mailbox per user (polled for a stranger's
/// first contact). Honest organic churn for a `MAX_BUNDLES`-sized population with even a modest
/// number of concurrently-active conversations per user reaches the high hundreds of thousands
/// to low millions — nowhere near `MAX_BUNDLES` itself. Set well above that (this is a rough
/// calibration pending real telemetry, not a derived exact bound; pre-alpha makes raising it
/// free).
///
/// Mitigating fact that makes a flat cap tenable at all: a mailbox drained by `handle_fetch`
/// (delete-on-fetch) or `handle_ack` is removed from the table IMMEDIATELY, not just at the TTL
/// sweep — so a key only occupies a table slot for mail that is genuinely UNDELIVERED, not for
/// every key a conversation has ever used.
///
/// Honest residual (same shape as `BundleSlot`'s CRYPTO-18 note): once the table is completely
/// full, first-contact delivery to a BRAND-NEW recipient is refused until TTL reclaims a slot —
/// this cap cannot distinguish a hostile flood from a legitimate surge of new correspondents. An
/// already-known recipient (already a key in the table) is never affected.
pub const MAX_MAILBOXES: usize = 2_000_000;

/// How long a leased (fetched-but-unacked) message stays invisible to a subsequent
/// fetch before it becomes deliverable again. A client that fetches with
/// `FetchRequest::ack` promises to ACK once the message is durably persisted; if it
/// crashes first, the lease expires and the exact ciphertext redelivers on the next
/// poll (at-least-once + the ratchet's fail-closed dedup ⇒ effectively-once). Long
/// enough to cover a poll's decrypt + fsync, short enough that a crash redelivers
/// promptly. Measured from the fetch; the `MAILBOX_TTL_SECS` reap still runs from the
/// original deposit, so a client that never ACKs cannot mint an immortal message.
pub const LEASE_SECS: u64 = 60;


/// A deposit that has PASSED admission and still has to be stored (#142). Holding this means the
/// relay lock can be — and is — released before the mail work begins.
pub struct AdmittedDeposit {
    store: Arc<Mutex<MailStore>>,
    recipient: [u8; 32],
}

impl AdmittedDeposit {
    /// Store the message. Takes only the MAIL lock, so a deposit's fsync blocks other mail work
    /// and nothing else — no admission, no discovery, no bundle lookup.
    pub fn deposit(&self, payload: &Payload, now: u64) -> Response {
        self.store.lock().expect("mail mutex").deposit(self.recipient, payload, now)
    }
}

/// A fetch that has passed the cookie + ownership gate and still has to be served.
pub struct AdmittedFetch {
    store: Arc<Mutex<MailStore>>,
    mailbox: [u8; 32],
}

impl AdmittedFetch {
    /// Serve one page and lease it.
    pub fn serve(&self, now: u64) -> Vec<Payload> {
        self.store.lock().expect("mail mutex").fetch_page(&self.mailbox, now)
    }
}

/// An ACK that has passed the cookie + ownership gate and still has to be applied.
pub struct AdmittedAck {
    store: Arc<Mutex<MailStore>>,
    mailbox: [u8; 32],
    ids: std::collections::HashSet<[u8; 32]>,
}

impl AdmittedAck {
    pub fn apply(&self) {
        self.store.lock().expect("mail mutex").ack(&self.mailbox, &self.ids);
    }
}

/// An upload that has PASSED admission and still has to be written (#142). Holding this means
/// the relay lock can be — and is — released before the file I/O begins.
pub struct AdmittedBlobPut {
    sender: [u8; 32],
    store: Arc<Mutex<node::blobstore::BlobStore>>,
}

impl AdmittedBlobPut {
    /// Do the write. Takes only the BLOB store's lock, so a slow chunk blocks other blob work
    /// and nothing else.
    pub fn put(&self, req: &BlobPutRequest, now: u64) -> BlobResponse {
        let mut store = self.store.lock().expect("blob store mutex");
        match store.put_chunk(self.sender, req.blob_id, req.index, req.count, &req.data, now) {
            node::blobstore::BlobPut::Ok => BlobResponse::Stored,
            node::blobstore::BlobPut::Complete => BlobResponse::Complete,
            node::blobstore::BlobPut::Rejected(r) => BlobResponse::Rejected(r),
        }
    }
}

/// Read one chunk out of an already-admitted store. Same split as `AdmittedBlobPut::put`.
pub fn blob_get_chunk(
    store: &Arc<Mutex<node::blobstore::BlobStore>>,
    req: &BlobGetRequest,
) -> BlobResponse {
    let store = store.lock().expect("blob store mutex");
    BlobResponse::Chunk(store.get_chunk(&req.blob_id, req.index))
}

/// Свежий случайный ключ cookie-эпохи (для инициализации и ротации).
fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    k
}









/// A published bundle plus when it was last (re)published. Bundles used to be immortal: nothing
/// removed one, ever, so a Sybil could mint identities until `MAX_BUNDLES` and lock every new
/// user out of publishing permanently — the store only emptied on relay restart (CRYPTO-18).
/// A live client republishes on every launch, so a TTL costs nothing real and turns "forever"
/// into "as long as somebody is actually using it".
struct BundleSlot {
    bundle: PreKeyBundle,
    refreshed_at: u64,
}

/// One queued sealed message. `enqueued_at` drives the deposit-time TTL sweep;
/// `leased_until` is the wall-clock time before which a leased-but-unacked message
/// stays invisible to a fetch (0 = not leased). Leasing never resets `enqueued_at`, so
/// a client that keeps crashing cannot outlive `MAILBOX_TTL_SECS`.
pub struct MailboxEntry {
    pub(crate) enqueued_at: u64,
    pub(crate) leased_until: u64,
    pub(crate) payload: Payload,
}






/// Node-local per-capability meter for blob-upload bytes/requests (§7.2, CRYPTO-15/#169) —
/// deliberately NOT `admission::capability::CapabilityQuotaTracker`. That tracker keeps a
/// sliding-window deque of every admitted proof TAG, sized to the caller's `max_requests`: fine
/// at message scale (`POW_CAP_QUOTA::max_requests` = 100 entries) but `BLOB_CAP_QUOTA` needs
/// `max_requests` in the tens of thousands, and at that size its per-`consume()` replay-scan +
/// byte-sum (both O(n) over the deque) become O(n²) across one upload — tens of thousands of
/// chunks times a deque that has grown to tens of thousands of entries is >10^9 deque visits,
/// and it is CHEAP to drive on purpose: resending the same already-stored index with a fresh
/// nonce each time costs the attacker ~0 stored bytes (blobstore nets the delta) while still
/// growing the deque. Charging blob bytes would otherwise hand back exactly the kind of
/// amplifier this fix exists to remove.
///
/// A tumbling window (reset wholesale at the window boundary, not pruned entry-by-entry) is
/// O(1) per request. The cost: it cannot single out a REPEATED exact proof for a `Replay`
/// verdict the way the message tracker does — a captured `(nonce, mac)` pair replayed by an
/// on-path attacker is counted as a fresh request against the SAME quota. `blob_put_nonce` keeps
/// this from being a bypass (the replayed request can only ever name the one already-stored
/// chunk it was minted for, so blobstore's own idempotent dedup keeps stored bytes at zero
/// delta) — what remains is a quota-burn nuisance against whoever's capability leaked onto the
/// wire, not a way to store bytes for free.
#[derive(Default)]
struct BlobQuotaTracker {
    /// `capability_id → (window_start, bytes_used, requests_used)`.
    windows: HashMap<[u8; 16], (u64, u64, u32)>,
}

impl BlobQuotaTracker {
    fn new() -> Self {
        Self::default()
    }

    /// `true` = admitted and counted; `false` = this request would exceed `quota` for the
    /// window `cap_id` is currently in (the window resets, rather than sliding, once
    /// `quota.window_secs` has elapsed since it started — simpler accounting than the message
    /// tracker's sliding window, acceptable here because `BLOB_CAP_QUOTA`'s headroom already
    /// means a window boundary mid-transfer costs at most one extra wait, never a failure).
    fn consume(&mut self, cap_id: [u8; 16], quota: &Quota, bytes: u64, now: u64) -> bool {
        let entry = self.windows.entry(cap_id).or_insert((now, 0, 0));
        if now.saturating_sub(entry.0) >= quota.window_secs as u64 {
            *entry = (now, 0, 0);
        }
        if entry.2 + 1 > quota.max_requests || entry.1 + bytes > quota.max_bytes {
            return false;
        }
        entry.1 += bytes;
        entry.2 += 1;
        true
    }

    /// Drop windows idle past `window_secs` — same hygiene as
    /// `CapabilityQuotaTracker::reap`, and for the same reason: a Public relay mints one
    /// `cap_id` per PoW solve, so without reaping this map grows by one permanent entry per
    /// solve.
    fn reap(&mut self, now: u64, window_secs: u64) {
        self.windows.retain(|_, (start, _, _)| now.saturating_sub(*start) < window_secs);
    }

    /// Live window count — exposed (via `RelayNode::blob_cap_quota_windows_for_test`) so a test
    /// can prove `reap` actually runs, same as `CapabilityQuotaTracker::len`.
    fn windows_len(&self) -> usize {
        self.windows.len()
    }
}

/// Relay-узел: гоняет admission-конвейер (§7) на входящих capsule и, при
/// Admit, кладёт ЗАПЕЧАТАННЫЙ (нечитаемый для узла) груз в mailbox получателя.
/// The mail plane: per-recipient queues plus their optional durable log (#142).
///
/// Split out of `RelayNode` so it can live behind its own lock. Everything that decides WHETHER a
/// message may be deposited (cookie, replay, capability, quota) stays on the relay; everything
/// that touches a queue or the disk is here. The caps are re-checked INSIDE this type rather than
/// trusted from the admission step: admission now runs under a different lock that has been
/// released by the time we get here, so two concurrently-admitted deposits must not both see room
/// for the same last slot. That invariant — a mailbox always fits in one response frame (#162) —
/// is not allowed to become racy just because the locking got finer.
pub struct MailStore {
    /// Per-recipient queue. `enqueued_at` drives the TTL sweep so undelivered mail for a
    /// recipient who never comes back doesn't accumulate forever.
    mailboxes: HashMap<[u8; 32], Vec<MailboxEntry>>,
    /// R2-5 (#161): the durable side. `None` = `Volatile` (the default — an accepted message
    /// lives in RAM only). `Some` = every deposit is fsynced before `Accepted` is answered, and
    /// the table above is rebuilt from the log on start.
    log: Option<crate::mailstore::MailLog>,
}

impl MailStore {
    fn new() -> Self {
        MailStore { mailboxes: HashMap::new(), log: None }
    }

    /// Store an ADMITTED message. Returns what the relay answers the sender.
    pub fn deposit(&mut self, recipient: [u8; 32], payload: &Payload, now: u64) -> Response {
        // Table-wide cap on NEW keys (see `MAX_MAILBOXES`): a fabricated recipient the relay has
        // never seen costs a whole HashMap entry that then sits until `MAILBOX_TTL_SECS` sweeps
        // it, and admission does not bound how many distinct addresses one capability can address
        // mail to — only how fast. Checked before `entry()` would itself allocate the new slot;
        // an EXISTING recipient is never blocked by this, only a brand-new one once full.
        if !self.mailboxes.contains_key(&recipient) && self.mailboxes.len() >= MAX_MAILBOXES {
            return Response::Rejected("MailboxTableFull".into());
        }
        // Cap на ВСТАВКЕ держит инвариант «mailbox всегда влезает в один кадр ответа» по
        // построению → fetch никогда не упрётся в FrameTooLarge ПОСЛЕ drain'а (иначе — тихая
        // потеря всей очереди офлайн-получателя). Полный ящик = backpressure отправителю, не
        // молчаливый сброс. В духе admission-троттлинга.
        let mbox = self.mailboxes.entry(recipient).or_default();
        // IDEMPOTENT deposit (R2-7). The transport deliberately does NOT retry a request once it
        // has been written to the connection: the relay may already have applied it, and a blind
        // retry would duplicate. But the sender's outbox retries later, retransmitting the EXACT
        // same ciphertext — with a fresh nonce and capability proof, so admission correctly sees a
        // new request. The deposit underneath is the same message, and storing it twice cost the
        // recipient a mailbox slot and the sender quota, and left every content type to implement
        // its own dedup.
        //
        // `payload_id` is already the stable identity of those bytes — it is what an ACK names —
        // so no new wire field is needed: re-depositing a message that is still in the mailbox is
        // accepted and ignored. The scan is bounded by the mailbox cap.
        //
        // Limit worth naming: this covers the window that actually produces duplicates (response
        // lost, sender retries), NOT a retry after the recipient has fetched and the entry is
        // gone. Catching that needs a delivered-ids record with its own retention — a different
        // trade, not this one. Note also that admission has ALREADY charged quota by the time we
        // get here, in this design as in the one before it: a retry pays for the request it made,
        // and only the storage is deduplicated.
        let deposit_id = payload_id(payload);
        if mbox.iter().any(|e| payload_id(&e.payload) == deposit_id) {
            return Response::Accepted;
        }
        if mbox.len() >= MAX_FETCH_SEALS {
            return Response::Rejected("MailboxFull".into());
        }
        if let Some(log) = self.log.as_mut() {
            // R2-5 (#161), FAIL-CLOSED. A relay that advertises `Durable` and then answers
            // `Accepted` for a message it could not write is worse than a volatile one: the
            // sender retires its outbox entry against a guarantee that silently stopped holding.
            // A full or broken disk therefore rejects, which the sender's outbox survives (it
            // retries). The fsync happens HERE, inside this lock — never while holding the
            // relay's, which is the whole point of the split.
            if log.deposit(recipient, now, payload).is_err() {
                return Response::Rejected("MailNotDurable".into());
            }
        }
        self.mailboxes
            .entry(recipient)
            .or_default()
            .push(MailboxEntry { enqueued_at: now, leased_until: 0, payload: payload.clone() });
        Response::Accepted
    }

    /// Serve one fixed-size page and LEASE what it served (#179 — a fetch is never a delete).
    pub fn fetch_page(&mut self, mailbox: &[u8; 32], now: u64) -> Vec<Payload> {
        // Fixed-size fetch (§2.2): take at most one page worth of seals (`FETCH_CAP` and within
        // the page body budget); leave the rest queued for the next poll. The response is later
        // serialized into a constant-size page, so an on-path observer cannot read the queue
        // depth from the response length.
        //
        // Only VISIBLE entries are served: a message leased by an earlier fetch stays hidden
        // until its lease expires (`leased_until <= now` again) or an ACK deletes it. Indices are
        // collected so the lease acts on the exact served entries even when leased and visible
        // entries are interleaved.
        let (seals, served): (Vec<Payload>, Vec<usize>) = match self.mailboxes.get(mailbox) {
            Some(mbox) => {
                let (idx, payloads): (Vec<usize>, Vec<Payload>) = mbox
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| e.leased_until <= now)
                    .map(|(i, e)| (i, e.payload.clone()))
                    .unzip();
                let take = node::wire::FetchPage::fit_prefix(&payloads);
                (payloads.into_iter().take(take).collect(), idx.into_iter().take(take).collect())
            }
            None => (Vec::new(), Vec::new()),
        };
        if let Some(mbox) = self.mailboxes.get_mut(mailbox) {
            for i in served {
                mbox[i].leased_until = now + LEASE_SECS;
            }
        }
        seals
    }

    /// Delete the named messages (an ACK the caller has already authenticated).
    pub fn ack(&mut self, mailbox: &[u8; 32], wanted: &std::collections::HashSet<[u8; 32]>) {
        let log = &mut self.log;
        if let Some(mbox) = self.mailboxes.get_mut(mailbox) {
            mbox.retain(|e| {
                let keep = !wanted.contains(&payload_id(&e.payload));
                if !keep {
                    if let Some(log) = log.as_mut() {
                        log.delete(*mailbox, &e.payload);
                    }
                }
                keep
            });
            if mbox.is_empty() {
                self.mailboxes.remove(mailbox);
            }
        }
    }

    /// Drop undelivered entries older than `MAILBOX_TTL_SECS`, and forget any mailbox left empty.
    /// Monotonic-clock note: `saturating_sub` makes a regressed timestamp look FRESH (kept),
    /// never spuriously stale.
    pub fn sweep(&mut self, now: u64) {
        let log = &mut self.log;
        self.mailboxes.retain(|mailbox, mbox| {
            mbox.retain(|e| {
                let keep = now.saturating_sub(e.enqueued_at) <= MAILBOX_TTL_SECS;
                if !keep {
                    if let Some(log) = log.as_mut() {
                        log.delete(*mailbox, &e.payload);
                    }
                }
                keep
            });
            !mbox.is_empty()
        });
        self.compact_if_needed();
    }

    /// Rewrite the mail log from the live table once it has accumulated enough dead records to be
    /// worth the rewrite. Called from the sweep — not per request, for the same reason the TTL
    /// scan is not: an O(n) rewrite on every insert is its own DoS.
    fn compact_if_needed(&mut self) {
        let Some(log) = &self.log else { return };
        let live_count: usize = self.mailboxes.values().map(Vec::len).sum();
        if !log.should_compact(live_count) {
            return;
        }
        let live: Vec<crate::mailstore::ReplayedEntry> = self
            .mailboxes
            .iter()
            .flat_map(|(mailbox, mbox)| {
                mbox.iter().map(move |e| crate::mailstore::ReplayedEntry {
                    mailbox: *mailbox,
                    enqueued_at: e.enqueued_at,
                    payload: e.payload.clone(),
                })
            })
            .collect();
        // A failed compaction is not silently ignored: `MailLog` marks its handle unusable if it
        // failed anywhere past the rename, so the next deposit fails loudly and the fail-closed
        // path answers `Rejected` instead of an `Accepted` nobody can honour. A failure BEFORE
        // the rename leaves the old log live and complete (compaction only ever drops records
        // already dead), so that case simply retries next epoch.
        if let Some(log) = &mut self.log {
            let _ = log.compact(&live);
        }
    }

    /// Is this relay writing queued mail to disk?
    pub fn is_durable(&self) -> bool {
        self.log.is_some()
    }

    /// How many messages are queued for one mailbox (diagnostics/tests).
    pub fn queued_for(&self, mailbox: &[u8; 32]) -> usize {
        self.mailboxes.get(mailbox).map_or(0, Vec::len)
    }

    /// Does this mailbox exist at all?
    pub fn holds(&self, mailbox: &[u8; 32]) -> bool {
        self.mailboxes.contains_key(mailbox)
    }

    /// Seed a queue directly — tests only, to build a state the live path would take too long to
    /// reach (a full table, an entry already past its TTL).
    pub fn insert_for_test(&mut self, mailbox: [u8; 32], entries: Vec<MailboxEntry>) {
        self.mailboxes.insert(mailbox, entries);
    }

    /// Append entries to a queue — tests only (see `insert_for_test`).
    pub fn append_for_test(&mut self, mailbox: [u8; 32], entries: Vec<MailboxEntry>) {
        self.mailboxes.entry(mailbox).or_default().extend(entries);
    }

    /// Make the durable log's next write fail — tests only, to exercise the fail-closed path.
    #[cfg(test)]
    pub fn poison_log_for_test(&mut self) {
        self.log.as_mut().expect("durable mail enabled").poison_for_test();
    }

    /// How many mailboxes exist (the table cap's view).
    pub fn table_len(&self) -> usize {
        self.mailboxes.len()
    }

    /// Every payload the relay is holding, ignoring which mailbox it sits in.
    pub fn all_payloads(&self) -> Vec<Payload> {
        self.mailboxes.values().flat_map(|m| m.iter().map(|e| e.payload.clone())).collect()
    }
}

/// Узел никогда не видит открытый текст — ключа у него нет.
pub struct RelayNode {
    keyring: CookieKeyring,
    capabilities: CapabilityTable,
    /// Token-credential verifier. `NoTokenVerifier` — it REFUSES every admission token (#145).
    ///
    /// Today no wire request can carry a `Credential::Token` at all (every relay path builds
    /// `Credential::Capability`), so this branch is unreachable — but "unreachable" is a property
    /// of the current wire, not of the relay, and the field used to hold `MockRingVerifier`, a
    /// structural-only stub that would ADMIT any well-shaped token the day some future request
    /// class carried one. Refusing by default makes that future a compile-time decision: swapping
    /// in an audited verifier is a type change here, visible in review, not a config flip.
    verifier: NoTokenVerifier,
    issuer_ring: IssuerRing,
    replay: ReplayFilter,
    cap_quota: CapabilityQuotaTracker,
    /// Blob-upload admission (CRYPTO-15/#169) — a SEPARATE budget from `cap_quota`, see
    /// `BLOB_CAP_QUOTA`'s doc comment for why message-scale and blob-scale quotas cannot share
    /// one tracker.
    blob_cap_quota: BlobQuotaTracker,
    epoch: u32,
    /// Where messages physically live: the per-recipient queues and their optional durable log.
    ///
    /// Behind its OWN lock, not the relay's (#142). Admission — cookie, replay, capability HMAC,
    /// quota — is in-memory arithmetic on relay state; a deposit or a fetch touches a queue and,
    /// on a durable relay, an fsync. Sharing one mutex meant every client's admission waited
    /// behind someone else's write barrier. The serve loop now takes the relay lock only to
    /// ADMIT, releases it, and does the mail work here. Lock ORDER is always relay → mail.
    mail: Arc<Mutex<MailStore>>,
    /// Mirrors `MailStore::is_durable`, cached here so `policy()` — which the serve loop answers
    /// while holding the relay lock — never has to take the mail lock (#142). It is set once, by
    /// `enable_durable_mail`, before the relay serves anything.
    mail_durable: bool,
    /// §12 discovery: опубликованные prekey-bundle по IK владельца. Публичный
    /// материал; запись гейтится ownership-proof, чтение открыто. Ограничен
    /// `MAX_BUNDLES` (отказ при полноте, не тихий сброс).
    bundles: HashMap<[u8; 32], BundleSlot>,
    /// One-time prekey batches per IK; a fetch pops one (see `PublishRequest::opks`).
    opk_batches: HashMap<[u8; 32], VecDeque<node::pqxdh::SignedOpk>>,
    /// Rotating start offset for `node_list`, so advertisement is fair rather than always
    /// favouring whoever was learned first (A3-13). `Cell` because serving a list is a READ.
    gossip_cursor: std::sync::atomic::AtomicUsize,
    /// Статический ключ узла: основа fetch-auth (и §12 publish-auth). Задаётся
    /// извне (`with_identity`) для персистентности — `karst-relay` хранит его на
    /// диске, relay-id стабилен между перезапусками.
    relay_identity: Identity,
    /// §15 large-file blob store (disk-backed). `None` = blobs disabled (default; keeps
    /// the in-memory constructors/tests unchanged). Enabled via `enable_blobs`.
    ///
    /// Behind its OWN lock, not the relay's (#142). Blob work is file I/O measured in tens of
    /// KiB per chunk; message delivery, fetch and ACK are small in-memory operations. Sharing one
    /// mutex meant a single chunk write head-of-line-blocked every other client's mail on the
    /// whole relay. The serve loop now takes the relay lock only long enough to ADMIT a blob
    /// request (cookie, nonce shape, capability, quota — all relay state) and does the I/O after
    /// releasing it, under this lock. Lock ORDER is always relay → blobs, never the reverse.
    blobs: Option<Arc<Mutex<node::blobstore::BlobStore>>>,
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
    /// The signed form of `self_descriptor` + `policy()`, cached and re-signed on a cadence
    /// (NODE-1). See `refresh_signed_descriptor` for why it is not minted per request.
    signed_self: Option<SignedDescriptor>,
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
            verifier: NoTokenVerifier,
            issuer_ring: IssuerRing { issuer_pubkeys: vec![[1u8; 32]], threshold_t: 1 },
            replay: ReplayFilter::new(epoch, 4096),
            cap_quota: CapabilityQuotaTracker::new(),
            blob_cap_quota: BlobQuotaTracker::new(),
            epoch,
            mail: Arc::new(Mutex::new(MailStore::new())),
            mail_durable: false,
            bundles: HashMap::new(),
            opk_batches: HashMap::new(),
            gossip_cursor: std::sync::atomic::AtomicUsize::new(0),
            relay_identity,
            blobs: None,
            blob_persistence: None,
            pow_issue: None,
            quota_policy: None,
            known_relays: Vec::new(),
            discovery: HashMap::new(),
            self_descriptor: None,
            signed_self: None,
        }
    }

    /// Enable the §15 disk-backed blob store at `dir`. `persist` is the operator's choice:
    /// `Durable` RECOVERS any parked blobs from a prior run (a big upload survives a restart);
    /// `Ephemeral` WIPES the store on start (blobs do not outlive the process — the lower-residue
    /// posture, an operator's call). `now` drives the recovery-time TTL sweep. Off by default.
    pub fn enable_blobs(&mut self, dir: std::path::PathBuf, now: u64, persist: BlobPersistence) -> std::io::Result<()> {
        self.blobs = Some(Arc::new(Mutex::new(match persist {
            BlobPersistence::Durable => node::blobstore::BlobStore::open(dir, now)?,
            BlobPersistence::Ephemeral => node::blobstore::BlobStore::new(dir)?,
        })));
        self.blob_persistence = Some(persist);
        Ok(())
    }

    /// R2-5 (#161): make this relay's mailboxes SURVIVE a restart, with the log in `dir`.
    ///
    /// Replays the log and installs what it holds, then advertises `MailboxDurability::Durable`.
    /// The replay re-applies the LIVE bounds rather than trusting the file: entries past
    /// `MAILBOX_TTL_SECS` are dropped, each mailbox is capped at `MAX_FETCH_SEALS` (the invariant
    /// "a mailbox always fits in one response frame", which a file written before that cap — or
    /// by anyone with disk access — must not be able to smuggle past), and the table itself at
    /// `MAX_MAILBOXES`. Anything the bounds reject is dropped from the log by the compaction that
    /// follows, so it is not re-litigated on every start.
    ///
    /// Errors are returned, not swallowed: a relay told to be durable that cannot open its log
    /// must fail to start rather than run as a silently volatile one.
    ///
    /// **Call before serving.** This REPLACES the mailbox table with what the log holds, so
    /// calling it on a relay already taking traffic would discard whatever is queued.
    pub fn enable_durable_mail(&mut self, dir: std::path::PathBuf, now: u64) -> std::io::Result<()> {
        let (mut log, entries) = crate::mailstore::MailLog::open(dir)?;
        let mut restored: HashMap<[u8; 32], Vec<MailboxEntry>> = HashMap::new();
        for e in entries {
            if now.saturating_sub(e.enqueued_at) > MAILBOX_TTL_SECS {
                continue; // TTL applies to a replayed entry exactly as to a live one
            }
            if !restored.contains_key(&e.mailbox) && restored.len() >= MAX_MAILBOXES {
                continue;
            }
            let mbox = restored.entry(e.mailbox).or_default();
            if mbox.len() >= MAX_FETCH_SEALS {
                continue;
            }
            // A lease is not persisted (see `mailstore`): everything replayed is visible, which
            // is what a lease timeout would have produced anyway.
            mbox.push(MailboxEntry { enqueued_at: e.enqueued_at, leased_until: 0, payload: e.payload });
        }
        let live: Vec<crate::mailstore::ReplayedEntry> = restored
            .iter()
            .flat_map(|(mailbox, mbox)| {
                mbox.iter().map(move |e| crate::mailstore::ReplayedEntry {
                    mailbox: *mailbox,
                    enqueued_at: e.enqueued_at,
                    payload: e.payload.clone(),
                })
            })
            .collect();
        log.compact(&live)?;
        let mut mail = self.mail.lock().expect("mail mutex");
        mail.mailboxes = restored;
        mail.log = Some(log);
        drop(mail);
        self.mail_durable = true;
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
            blob_ttl_secs: if self.blobs.is_some() { node::blobstore::BLOB_TTL_SECS } else { 0 },
            max_blob_size: if self.blobs.is_some() { node::blobstore::MAX_BLOB_SIZE } else { 0 },
            pow_bits: self.pow_issue,
            // R2-5 (#161): a real operator choice now — `Durable` only when a mail log is
            // actually open and being fsynced on deposit, never as a bare claim.
            mailbox_durability: if self.mail_durable {
                MailboxDurability::Durable
            } else {
                MailboxDurability::Volatile
            },
        }
    }

    /// §15 upload: store one ciphertext chunk. Cookie-gated (DoS/freshness) AND
    /// capability-gated (CRYPTO-15/#169): a cookie is a stateless HMAC round-trip the requester
    /// can mint for any address it names — a freshness proof, not a cost — so before this fix
    /// the path that stores the LARGEST bytes on the relay was the one write that never charged
    /// anyone's admission quota. The blob store's per-sender/global byte caps (`blobstore.rs`)
    /// are a SEPARATE, complementary mechanism keyed to the self-declared, freely-mintable
    /// `client_addr` — they still don't attribute cost to anything expensive to obtain. The
    /// capability check below does: `request_nonce` must have the shape `blob_put_nonce`
    /// requires (binds the proof to this exact chunk, see its doc comment) and
    /// `capability_proof` must verify, and only then is the chunk's byte size metered against
    /// `BLOB_CAP_QUOTA` — a budget sized for blob-store scale, not message scale (see that
    /// constant's doc comment for the arithmetic on why message-scale quota would just make
    /// every honest large upload time out instead of bounding abuse).
    pub fn handle_blob_put(&mut self, req: &BlobPutRequest, now: u64) -> BlobResponse {
        match self.admit_blob_put(req, now) {
            Ok(admitted) => admitted.put(req, now),
            Err(refusal) => refusal,
        }
    }

    /// The ADMISSION half of a blob upload — everything that reads relay state, and nothing that
    /// touches a file (#142). Returns the handle the caller then does the I/O through, AFTER it
    /// has released the relay lock. `handle_blob_put` above is the same thing done in one step,
    /// for callers that are not the serve loop (tests, in-process transports).
    pub fn admit_blob_put(
        &mut self,
        req: &BlobPutRequest,
        now: u64,
    ) -> Result<AdmittedBlobPut, BlobResponse> {
        self.advance_epoch(now);
        match req.cookie {
            Some(c) if self.keyring.verify(&c, &req.client_addr, &req.carrier_id, now).is_ok() => {}
            _ => {
                let cookie = self.keyring.issue(&req.client_addr, &req.carrier_id, now as u32);
                return Err(BlobResponse::NeedCookie(cookie));
            }
        }
        // Cheap, no-crypto check BEFORE the capability HMAC (stage-ordering discipline, same as
        // the live-message pipeline): rejects a proof minted elsewhere (wrong nonce shape) at
        // zero crypto cost, rather than paying an HMAC verify only to reject it anyway.
        if req.request_nonce != blob_put_nonce(&req.blob_id, req.index) {
            return Err(BlobResponse::Rejected("bad request nonce".into()));
        }
        let cap = match self.capabilities.verify(&req.capability_proof, &req.request_nonce, Scope::MessageDelivery, now as u32) {
            Ok(c) => c,
            Err(e) => return Err(BlobResponse::Rejected(format!("capability: {e:?}"))),
        };
        if !self.blob_cap_quota.consume(cap.capability_id, &BLOB_CAP_QUOTA, req.data.len() as u64, now) {
            return Err(BlobResponse::Rejected("blob quota exceeded".into()));
        }
        let sender: [u8; 32] = match req.client_addr.as_slice().try_into() {
            Ok(s) => s,
            Err(_) => return Err(BlobResponse::Rejected("bad sender address".into())),
        };
        let Some(store) = self.blobs.clone() else {
            return Err(BlobResponse::Rejected("blobs disabled".into()));
        };
        Ok(AdmittedBlobPut { sender, store })
    }

    /// The admission half of a blob DOWNLOAD: cookie only (see `handle_blob_get` for why this
    /// path is deliberately not capability-gated). Same split as `admit_blob_put`.
    pub fn admit_blob_get(
        &mut self,
        req: &BlobGetRequest,
        now: u64,
    ) -> Result<Arc<Mutex<node::blobstore::BlobStore>>, BlobResponse> {
        self.advance_epoch(now);
        match req.cookie {
            Some(c) if self.keyring.verify(&c, &req.client_addr, &req.carrier_id, now).is_ok() => {}
            _ => {
                let cookie = self.keyring.issue(&req.client_addr, &req.carrier_id, now as u32);
                return Err(BlobResponse::NeedCookie(cookie));
            }
        }
        self.blobs.clone().ok_or_else(|| BlobResponse::Rejected("blobs disabled".into()))
    }

    /// Admit a progress query. Same cookie stage as `admit_blob_get` — see `BlobStatRequest` on
    /// why this stopped being the one blob endpoint with no admission at all.
    pub fn admit_blob_stat(
        &mut self,
        req: &node::protocol::BlobStatRequest,
        now: u64,
    ) -> Result<Arc<Mutex<node::blobstore::BlobStore>>, BlobResponse> {
        self.advance_epoch(now);
        match req.cookie {
            Some(c) if self.keyring.verify(&c, &req.client_addr, &req.carrier_id, now).is_ok() => {}
            _ => {
                let cookie = self.keyring.issue(&req.client_addr, &req.carrier_id, now as u32);
                return Err(BlobResponse::NeedCookie(cookie));
            }
        }
        self.blobs.clone().ok_or_else(|| BlobResponse::Rejected("blobs disabled".into()))
    }

    /// The blob store's own handle, for the serve loop's public reads (`BlobStat`) — taken
    /// WITHOUT the relay lock held, so a stat cannot be stuck behind a chunk write while holding
    /// up everyone's mail. `None` = blobs disabled.
    pub fn blob_store(&self) -> Option<Arc<Mutex<node::blobstore::BlobStore>>> {
        self.blobs.clone()
    }

    /// §15 download: return one ciphertext chunk (bearer-by-id). Cookie-gated for DoS.
    /// Deliberately NOT capability-gated here (CRYPTO-15/#169 is scoped to the STORAGE cost of
    /// `handle_blob_put`, the path that stores the largest bytes): serving a chunk back is an
    /// EGRESS-bandwidth cost, a different resource with its own attribution question, left open
    /// as a separate, named gap rather than folded into this fix.
    pub fn handle_blob_get(&mut self, req: &BlobGetRequest, now: u64) -> BlobResponse {
        match self.admit_blob_get(req, now) {
            Ok(store) => blob_get_chunk(&store, req),
            Err(refusal) => refusal,
        }
    }

    /// §15 upload progress: `(next, count, complete)` for a blob — how many chunks are already
    /// stored, so a **resumable upload** continues from `next` instead of re-sending everything.
    /// `None` = the relay has never seen this blob (a fresh upload starts at 0) or blobs are off.
    /// Public read (bearer-by-id, like `FetchBundle`/`get_chunk`): no cookie, reveals only progress.
    pub fn blob_stat(&self, blob_id: &[u8; 32]) -> Option<(u32, u32, bool)> {
        self.blobs.as_ref()?.lock().expect("blob store mutex").stat(blob_id)
    }

    /// Публичный ключ узла — клиент узнаёт его вне канала (как адрес) и
    /// использует для fetch-auth DH. Бинарь печатает его при старте.
    pub fn relay_public(&self) -> PublicKey {
        self.relay_identity.public
    }

    /// The mail plane's own handle — for tests that need to inspect or seed queues directly, and
    /// for anything that wants mail work off the relay lock.
    ///
    /// (The doc block that used to sit here belonged to `MailStore::all_payloads` and had drifted
    /// onto its neighbour, describing a method this type does not have.)
    pub fn mail_store(&self) -> Arc<Mutex<MailStore>> {
        self.mail.clone()
    }

    pub fn all_slots_for_test(&self) -> Vec<Payload> {
        self.mail.lock().expect("mail mutex").all_payloads()
    }

    /// Number of live capability-quota windows — exposed so a test can prove the periodic
    /// `reap` runs (a Public relay would otherwise leak one window per PoW solve). See the
    /// reap call in `advance_epoch`.
    pub fn cap_quota_windows_for_test(&self) -> usize {
        self.cap_quota.len()
    }

    /// Number of live blob-quota windows (`BlobQuotaTracker`) — the same reap-proving purpose
    /// as `cap_quota_windows_for_test`, for the separate blob-upload tracker.
    pub fn blob_cap_quota_windows_for_test(&self) -> usize {
        self.blob_cap_quota.windows_len()
    }

    /// How many messages are queued for `recipient` — so a test can prove a re-deposit did not
    /// duplicate, without draining the mailbox (a fetch would remove the evidence).
    pub fn mailbox_len_for_test(&self, recipient: &[u8; 32]) -> usize {
        self.mail.lock().expect("mail mutex").queued_for(recipient)
    }

    /// Issue a cookie the way the request handlers do — so a test can build an admission-gated
    /// request by hand without reaching into the keyring.
    pub fn issue_cookie_for_test(&mut self, addr: &[u8], carrier: &[u8], now: u64) -> Cookie {
        self.keyring.issue(addr, carrier, now as u32)
    }

    /// Advance the relay's clock, running the periodic sweeps a real request would have run.
    pub fn tick_for_test(&mut self, now: u64) {
        self.advance_epoch(now);
    }

    /// Live published bundles and discovery records — so a test can prove the periodic sweep
    /// actually returns capacity, rather than inferring it from a lookup that would have
    /// removed the record itself.
    pub fn key_distribution_len_for_test(&self) -> (usize, usize) {
        (self.bundles.len(), self.discovery.len())
    }

    /// Выдать capability клиенту (relay — сам issuer, §7.2). Возвращает копию,
    /// которую клиент хранит для построения proof'ов; секрет-запись остаётся и
    /// у relay для верификации.
    pub fn issue_capability(&mut self, cap: Capability) {
        self.capabilities.insert(cap);
    }

    /// Withdraw a stored capability (CRYPTO-25). An invite is a bearer credential: the only way
    /// to take one back is to stop honouring its id, and that has to bite on the NEXT request,
    /// not at the next restart — an operator revoking an invite is usually reacting to something.
    /// Returns whether the id was known.
    pub fn revoke_capability(&mut self, capability_id: &[u8; 16]) -> bool {
        self.capabilities.remove(capability_id)
    }

    /// Stored capability ids (operator listing).
    pub fn capability_ids(&self) -> Vec<[u8; 16]> {
        self.capabilities.ids()
    }

    /// Add (or update) a relay descriptor in the node list (discovery plane). **Operator-
    /// curated only** in this slice — self + `KARST_RELAY_PEERS`, never merged from untrusted
    /// gossip: re-serving a peer-heard address without dialing it first would let any relay
    /// aim every client at a victim IP (reflection). That merge, with dial-verification + rate
    /// limits, is a separate slice. Dedups by relay-id (unions addr hints), bounded.
    pub fn add_relay(&mut self, mut d: RelayDescriptor) {
        d.addrs.truncate(MAX_ADDRS_PER_RELAY);
        d.addrs.retain(|a| !a.is_empty() && a.len() <= MAX_ADDR_LEN);
        // Same bounds for the QUIC hints, for the same reason: attacker-controlled, unsigned,
        // free-form (QUIC-1).
        d.quic_addrs.truncate(MAX_ADDRS_PER_RELAY);
        d.quic_addrs.retain(|a| !a.is_empty() && a.len() <= MAX_ADDR_LEN);
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
            // The QUIC hints were bounded above but never MERGED, so a relay already in the list
            // could never learn that it also speaks QUIC — the field would be sanitised and then
            // dropped, and a gossiped QUIC endpoint would silently go nowhere (QUIC-1 built the
            // shape; this is the half that carries it). Same eviction rule as `addrs`: newest-last,
            // oldest out at the cap.
            for a in d.quic_addrs {
                if existing.quic_addrs.contains(&a) {
                    continue;
                }
                if existing.quic_addrs.len() >= MAX_ADDRS_PER_RELAY {
                    existing.quic_addrs.remove(0);
                }
                existing.quic_addrs.push(a);
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

    /// This relay's own descriptor, if it advertises one.
    ///
    /// Needed so a listener that comes up AFTER the descriptor was built can amend it rather than
    /// rebuild it from scratch — the QUIC endpoint is only true once its bind succeeded, so the
    /// claim is added then and not before (QUIC-11).
    pub fn self_descriptor(&self) -> Option<RelayDescriptor> {
        self.self_descriptor.clone()
    }

    /// The cached signed descriptor, if one exists and is still fresh enough to serve (NODE-1).
    ///
    /// "Fresh enough" is `DESCRIPTOR_REFRESH_SECS`, not the TTL: serving a copy that is about to
    /// lapse would hand the holder something it must immediately re-fetch, and would make a
    /// configuration change take a full TTL to reach anyone.
    pub fn signed_descriptor(&self, now: u64) -> Option<SignedDescriptor> {
        let d = self.signed_self.as_ref()?;
        (now < d.desc.issued_at.saturating_add(DESCRIPTOR_REFRESH_SECS)
            && now.saturating_add(DESCRIPTOR_SKEW_SECS) >= d.desc.issued_at)
            .then(|| d.clone())
    }

    /// Re-sign this relay's statement about itself from CURRENT state, cache it and return it.
    /// `None` when this relay advertises no routable address — it is undiscoverable by its own
    /// choice, and there is nothing truthful to sign.
    ///
    /// Built fresh from `self_descriptor()` and `policy()` on every refresh, which is what makes an
    /// operator's configuration change propagate at all: nothing here remembers what was signed an
    /// hour ago.
    pub fn refresh_signed_descriptor(
        &mut self,
        now: u64,
        noise_secret: &[u8; 32],
    ) -> Option<SignedDescriptor> {
        let relay = self.self_descriptor.clone()?;
        let signed = NodeDescriptor::signed(relay, self.policy(), now, noise_secret);
        self.signed_self = Some(signed.clone());
        Some(signed)
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
        record.location.quic_addrs.truncate(MAX_ADDRS_PER_RELAY);
        record.location.quic_addrs.retain(|a| !a.is_empty() && a.len() <= MAX_ADDR_LEN);
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
        let budget = node::wire::MAX_RESPONSE_FRAME - 512; // headroom for enum tag + framing
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
        // Atomic, not `Cell` (#142): the relay now sits behind an `RwLock`, so a read-only
        // handler like this one may run on several threads at once — `Cell` is not `Sync` and
        // would make the whole `RelayNode` unshareable for reads. Fetch-and-add is the same
        // "rotate the starting point" behaviour with no lock of its own.
        let start = self.gossip_cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % n;
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
            // The quota the holder is TOLD it has must be the quota enforcement will actually
            // grant. This used to stamp `quota_policy.unwrap_or(POW_CAP_QUOTA)` while enforcement
            // computes `POW_CAP_QUOTA.clamped_by(policy)` — an element-wise MIN. The two agree
            // only while the policy is at or below the door's own bound; an operator who RAISES
            // the ceiling (the `unlimited` and `media-friendly` presets both do) handed clients a
            // capability advertising a budget the pipeline would then refuse, and the client saw
            // it as an unexplained rejection well inside its stated quota (A4-7).
            //
            // Same expression as enforcement, deliberately: `POW_CAP_QUOTA` is the Public door's
            // spam bound and a security parameter in its own right, so a policy may lower it,
            // never lift it.
            quota: match self.quota_policy {
                Some(p) => POW_CAP_QUOTA.clamped_by(&p),
                None => POW_CAP_QUOTA,
            },
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
            // TRY, don't wait (#142): this runs while the relay lock is held, so blocking here
            // on a deposit's fsync would put the stall right back. A skipped TTL sweep costs a
            // few minutes of lag, nothing else.
            if let Ok(mut mail) = self.mail.try_lock() {
                mail.sweep(now);
            }
            // Reap idle capability-quota windows. CRITICAL for a PUBLIC relay: every PoW
            // capability has a distinct `cap_id`, so without this the quota map would grow by
            // one permanent entry per solve — an unbounded-memory DoS on the very door slice
            // 4a hardens (the stateless cap removed the CAP table, but the QUOTA map is the
            // other place per-cap state lived). Safe for all cap types: an active window is
            // kept, an idle one is dropped and simply re-created on the next send.
            self.cap_quota.reap(now, EPOCH_DURATION_SECS);
            // Same reap, same reason, separate map (see `BlobQuotaTracker`'s doc comment) — a
            // fallback window of `BLOB_CAP_QUOTA.window_secs`, used only for a cap_id never
            // metered (mirrors `cap_quota`'s use of `EPOCH_DURATION_SECS` as ITS fallback).
            self.blob_cap_quota.reap(now, BLOB_CAP_QUOTA.window_secs as u64);
            self.sweep_key_distribution(now);
            if let Some(blobs) = &self.blobs {
                // TRY, don't wait: this runs while the relay lock is held, so blocking here on a
                // chunk write in progress would reintroduce exactly the head-of-line stall the
                // separate blob lock removes (#142). The TTL sweep is opportunistic housekeeping
                // — skipping it until the next epoch costs nothing but a few minutes of lag.
                if let Ok(mut blobs) = blobs.try_lock() {
                    blobs.sweep(now);
                }
            }
        }
    }

    /// Return the capacity held by abandoned key-distribution state: bundles nobody has
    /// republished within `BUNDLE_TTL_SECS` (with their one-time-prekey batches), and discovery
    /// records past their own signed expiry.
    ///
    /// Discovery records USED to be dropped only when somebody looked one up — so a record for a
    /// pseudonym nobody ever resolves sat in the map until restart, and since the pseudonym is a
    /// random per-user value an attacker could mint unlimited ones that would never be looked up
    /// by anyone (CRYPTO-19). Expiry is now enforced on the relay's own clock, not on the arrival
    /// of a reader.
    ///
    /// Runs on the epoch tick, not per request: an O(n) scan on every insert is its own DoS.
    fn sweep_key_distribution(&mut self, now: u64) {
        // `saturating_sub` makes a regressed clock look FRESH (kept), never spuriously stale —
        // same monotonicity note as `sweep_mailboxes`.
        self.bundles.retain(|_, slot| now.saturating_sub(slot.refreshed_at) <= BUNDLE_TTL_SECS);
        self.opk_batches.retain(|ik, _| self.bundles.contains_key(ik));
        self.discovery.retain(|_, rec| rec.expiry > now);
    }

    /// Обработать входящее сообщение. `now` — часы узла. One-step wrapper for callers that are
    /// not the serve loop (tests, the in-process transport): admits, then deposits immediately.
    /// The serve loop uses `admit_send` and does the deposit after releasing the relay lock.
    pub fn handle(&mut self, msg: &WireMessage, now: u64) -> Response {
        match self.admit_send(msg, now) {
            Ok(admitted) => admitted.deposit(&msg.payload, now),
            Err(refusal) => refusal,
        }
    }

    /// The ADMISSION half of a deposit (#142): everything that reads relay state — cookie,
    /// replay, capability HMAC, quota — and nothing that touches a queue or the disk. Returns the
    /// handle the caller deposits through once it has released the relay lock.
    pub fn admit_send(&mut self, msg: &WireMessage, now: u64) -> Result<AdmittedDeposit, Response> {
        self.advance_epoch(now);

        // raw_len ≈ размер груза + служебные поля (для Ступени 0).
        let raw_len = msg.payload.approx_len() + 128;
        let req = Request {
            raw_len,
            max_raw_len: admission::params::MAX_PACKET_SIZE,
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
                Err(Response::NeedCookie(cookie))
            }
            Outcome::Admit => Ok(AdmittedDeposit { store: self.mail.clone(), recipient: msg.recipient }),
            other => Err(Response::Rejected(format!("{:?}", other))),
        }
    }

    /// Аутентифицированный fetch (§7-владение mailbox). Требует cookie
    /// (DoS-гейт + свежесть, как send) И доказательство владения приватным
    /// ключом `mailbox`. Без доказательства — `Reject`, **mailbox НЕ трогается**
    /// (иначе кто угодно, зная pubkey-адрес, сливал бы чужую очередь).
    ///
    /// One-step wrapper; the serve loop uses `admit_fetch` and serves the page after releasing
    /// the relay lock (#142).
    pub fn handle_fetch(&mut self, req: &FetchRequest, now: u64) -> FetchResponse {
        match self.admit_fetch(req, now) {
            Ok(admitted) => FetchResponse::Fetched(admitted.serve(now)),
            Err(refusal) => refusal,
        }
    }

    /// The ADMISSION half of a fetch: cookie freshness plus the mailbox-ownership proof, both
    /// pure relay state. Nothing here touches a queue.
    pub fn admit_fetch(&mut self, req: &FetchRequest, now: u64) -> Result<AdmittedFetch, FetchResponse> {
        self.advance_epoch(now);

        // Cookie: нет/невалиден → challenge (как на send).
        let cookie = match req.cookie {
            Some(c) if self.keyring.verify(&c, &req.client_addr, &req.carrier_id, now).is_ok() => c,
            _ => {
                let cookie = self.keyring.issue(&req.client_addr, &req.carrier_id, now as u32);
                return Err(FetchResponse::NeedCookie(cookie));
            }
        };

        // Ownership proof. A BLINDED drop-box (a Ristretto address) has no DH with the relay's
        // X25519 key, so it proves knowledge of its fetch secret (Schnorr); the IDENTITY mailbox
        // (an X25519 key) proves via DH. Either failure rejects WITHOUT draining.
        if !mailbox_owner_ok(&self.relay_identity, req.mailbox, &cookie.mac, req.proof, &req.own_proof) {
            return Err(FetchResponse::Rejected("fetch auth failed".into()));
        }
        Ok(AdmittedFetch { store: self.mail.clone(), mailbox: req.mailbox })
    }

    /// Delete leased messages a recipient has durably persisted. Same ownership proof as
    /// `handle_fetch` (a delete-by-address weaker than the fetch gate would let anyone who knows
    /// the public mailbox address wipe someone's queue). Unknown / already-swept ids are silently
    /// ignored — an ACK is idempotent, so a redelivered-then-reacked message is not an error. A
    /// message not yet acked but whose lease expired is deletable too: the id still matches, and
    /// deleting it is exactly what a late ACK should do.
    ///
    /// One-step wrapper; the serve loop uses `admit_ack` and deletes after releasing the relay
    /// lock (#142).
    pub fn handle_ack(&mut self, req: &AckRequest, now: u64) -> AckResponse {
        match self.admit_ack(req, now) {
            Ok(admitted) => {
                admitted.apply();
                AckResponse::Acked
            }
            Err(refusal) => refusal,
        }
    }

    /// The ADMISSION half of an ACK: cookie, ownership proof, and the bound on how much work one
    /// ACK may ask for. Nothing here touches a queue.
    pub fn admit_ack(&mut self, req: &AckRequest, now: u64) -> Result<AdmittedAck, AckResponse> {
        self.advance_epoch(now);

        let cookie = match req.cookie {
            Some(c) if self.keyring.verify(&c, &req.client_addr, &req.carrier_id, now).is_ok() => c,
            _ => {
                let cookie = self.keyring.issue(&req.client_addr, &req.carrier_id, now as u32);
                return Err(AckResponse::NeedCookie(cookie));
            }
        };

        if !mailbox_owner_ok(&self.relay_identity, req.mailbox, &cookie.mac, req.proof, &req.own_proof) {
            return Err(AckResponse::Rejected("ack auth failed".into()));
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
            return Err(AckResponse::Rejected("too many ids in one ack".into()));
        }
        Ok(AdmittedAck {
            store: self.mail.clone(),
            mailbox: req.mailbox,
            ids: req.ids.iter().copied().collect(),
        })
    }

    /// §12 публикация bundle. Cookie-gate (DoS/свежесть, как fetch) + fixed-length check on
    /// `kem_ek`/`prekey_sig` (A10-1, #231 — both are stored verbatim, never parsed, here) +
    /// ownership-proof владения IK. `bundle.ik_pub` — ключ хранения. Перезапись своего —
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

        // A10-1 (#231): `kem_ek`/`prekey_sig` are never PARSED here — this relay only ever
        // stores-and-forwards them (a sender parses the KEM key in
        // `pqxdh::initiate_key_agreement`, not us) — so nothing else in this path would catch
        // either field being shaped to some other length. Unchecked, the flat `raw_len: 2048`
        // charged below (sized for "a bundle is ~1.3 KiB", see its comment) would be undercharging
        // an arbitrarily larger bundle by construction, not just in the untested worst case — and
        // because `get_bundle` serves the stored bundle back to ANY caller with no cookie and no
        // capability, a write metered once would then read out for free, at its real size, on
        // every future lookup. Rejected loudly, before the (cheap but non-zero) DH below.
        if req.bundle.kem_ek.len() != ML_KEM_768_EK_LEN || req.bundle.prekey_sig.len() != XEDDSA_SIG_LEN {
            return PublishResponse::Rejected("malformed bundle field length".into());
        }

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
        let is_new_slot = !self.bundles.contains_key(&ik);
        if is_new_slot && self.bundles.len() >= MAX_BUNDLES {
            return PublishResponse::Rejected("BundleStoreFull".into());
        }
        // CREATING a slot is metered; REFRESHING one you already own is not (CRYPTO-18).
        //
        // The ownership proof above stops you overwriting somebody ELSE's slot, but says nothing
        // about how many slots you may create: identities are free to mint locally, and the
        // cookie binds to a self-declared address, not to an identity. So a single client could
        // publish 100_000 fresh IKs and every later legitimate publish got `BundleStoreFull`,
        // permanently — the store had no TTL either.
        //
        // The asymmetry is deliberate. A live client republishes on every launch and announce;
        // charging that against its quota would make normal use look like an attack. Creating a
        // NEW slot is the operation that consumes a global, finite resource, so that is the one
        // that must present a capability and be charged for it.
        if is_new_slot {
            let areq = Request {
                // The REAL cost of this request, not a stand-in: the bundle AND the one-time
                // prekey batch riding with it. It used to be a flat 2048 covering the bundle
                // alone, so up to `MAX_OPKS_PER_IK` signed keys — tens of kilobytes the relay
                // then stores and serves — were free (A10-1). They were free for a structural
                // reason: stage 0 applied the live-path MTU to EVERY request class, so charging
                // the truth here would have rejected every honest full-batch publish. Each class
                // carries its own ceiling now, which is what makes the honest figure affordable.
                raw_len: 2048 + req.opks.len() * SIGNED_OPK_COST,
                max_raw_len: 2048 + MAX_OPKS_PER_IK * SIGNED_OPK_COST + 512,
                client_addr: &req.client_addr,
                carrier_id: &req.carrier_id,
                cookie: req.cookie,
                request_nonce: &req.request_nonce,
                requested_scope: Scope::MessageDelivery,
                credential: Credential::Capability(req.capability_proof),
            };
            let pipe = AdmissionPipeline {
                keyring: &self.keyring,
                capabilities: &self.capabilities,
                token_verifier: &self.verifier,
                issuer_ring: &self.issuer_ring,
            };
            let policy = self.quota_policy;
            let outcome = pipe.process_with_policy(
                &areq,
                now,
                self.epoch,
                [0u8; 64],
                &mut self.replay,
                &mut self.cap_quota,
                policy,
            );
            match outcome {
                Outcome::Admit => {}
                Outcome::Challenge(_) => {
                    let cookie =
                        self.keyring.issue(&req.client_addr, &req.carrier_id, now as u32);
                    return PublishResponse::NeedCookie(cookie);
                }
                other => return PublishResponse::Rejected(format!("{other:?}")),
            }
        }
        self.bundles.insert(ik, BundleSlot { bundle: req.bundle.clone(), refreshed_at: now });
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
    pub fn get_bundle(&self, ik: &[u8; 32]) -> Option<PreKeyBundle> {
        // NEVER carries a one-time prekey. This read is unauthenticated, and handing out an OPK
        // is destructive — that combination let anyone drain a victim's batch and push every
        // later first contact down to 3-DH (R2-3). The OPK-bearing form is
        // `handle_fetch_bundle_opk`, gated by the same capability a send needs.
        self.bundles.get(ik).map(|s| s.bundle.clone())
    }

    /// §12 fetch WITH a one-time prekey: full send-grade admission (cookie → capability → quota),
    /// then pop one key. See [`BundleOpkRequest`] for why the destructive half is gated and the
    /// public read is not.
    pub fn handle_fetch_bundle_opk(
        &mut self,
        req: &BundleOpkRequest,
        now: u64,
    ) -> BundleOpkResponse {
        self.advance_epoch(now);

        let areq = Request {
            // A fixed, small size: this request carries no payload, so charging it by a
            // caller-supplied length would let the caller choose its own quota cost.
            raw_len: 256,
            max_raw_len: admission::params::MAX_PACKET_SIZE,
            client_addr: &req.client_addr,
            carrier_id: &req.carrier_id,
            cookie: req.cookie,
            request_nonce: &req.request_nonce,
            requested_scope: Scope::MessageDelivery,
            credential: Credential::Capability(req.capability_proof),
        };
        let pipe = AdmissionPipeline {
            keyring: &self.keyring,
            capabilities: &self.capabilities,
            token_verifier: &self.verifier,
            issuer_ring: &self.issuer_ring,
        };
        let policy = self.quota_policy;
        let outcome = pipe.process_with_policy(
            &areq,
            now,
            self.epoch,
            [0u8; 64],
            &mut self.replay,
            &mut self.cap_quota,
            policy,
        );
        match outcome {
            Outcome::Challenge(_) => BundleOpkResponse::NeedCookie(self.keyring.issue(
                &req.client_addr,
                &req.carrier_id,
                now as u32,
            )),
            Outcome::Admit => {
                let Some(mut bundle) = self.bundles.get(&req.ik).map(|s| s.bundle.clone()) else {
                    return BundleOpkResponse::Bundle(None);
                };
                // Consume AFTER admission, so a rejected request never costs the victim a key.
                bundle.opk = self.opk_batches.get_mut(&req.ik).and_then(|b| b.pop_front());
                BundleOpkResponse::Bundle(Some(bundle))
            }
            other => BundleOpkResponse::Rejected(format!("{other:?}")),
        }
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

    /// The relay behind this transport, so an integration test can inspect or advance it.
    pub fn relay_for_test(&self) -> Rc<RefCell<RelayNode>> {
        self.relay.clone()
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
        Ok(self.relay.borrow().get_bundle(ik))
    }
    fn fetch_bundle_opk(
        &self,
        req: &BundleOpkRequest,
        now: u64,
    ) -> Result<BundleOpkResponse, String> {
        Ok(self.relay.borrow_mut().handle_fetch_bundle_opk(req, now))
    }
}

#[cfg(test)]
mod tests {
    use karst_client_core::demo::{Client, Recipient};
    use node::seal::SkeletonSeal;
    /// A capability the in-crate tests can present when a publish CREATES a slot (CRYPTO-18).
    /// A KEM key for a recipient that NOBODY opens (PRIV-3).
    ///
    /// These tests fabricate recipients to exercise admission, quota and mailbox behaviour; the seal
    /// is never opened, so any well-formed encapsulation key does. Named so the distinction is
    /// visible: where a test DOES open the seal, it must use that recipient's own key
    /// (`Recipient::kem_ek`), and passing this instead would make the envelope unopenable.
    fn throwaway_kem_ek() -> Vec<u8> {
        node::seal::SealKemKeys::generate().ek().to_vec()
    }

    fn publish_cap() -> Capability {
        Capability {
            capability_id: [0xBC; 16],
            scope: Scope::MessageDelivery,
            quota: Quota { max_requests: 1000, max_bytes: 1 << 24, window_secs: 600 },
            not_before: 0,
            not_after: u32::MAX,
            secret: [0x77; 32],
        }
    }

    use super::*;
    use node::pqxdh::Account;

    const NOW: u64 = 1_000_000;

    /// `BlobQuotaTracker::consume` (CRYPTO-15/#169) unit-tested directly with a tiny custom
    /// `Quota` — the real `BLOB_CAP_QUOTA` is sized in the tens-of-thousands/GiB range
    /// specifically so an honest large upload never trips it (see that constant's doc comment),
    /// which makes it impractical to drive to its own limit in a fast test. This exercises the
    /// SAME code the relay calls, just parameterized small enough to hit both boundaries (byte
    /// cap and request cap) directly.
    #[test]
    fn blob_quota_tracker_admits_within_budget_and_refuses_past_it() {
        let mut t = BlobQuotaTracker::new();

        // --- Byte cap binds independently of the request-count cap ---
        let by_bytes = [1u8; 16];
        let byte_quota = Quota { max_requests: 1000, max_bytes: 250, window_secs: 600 };
        assert!(t.consume(by_bytes, &byte_quota, 100, NOW), "1st request: 100/250 bytes used");
        assert!(t.consume(by_bytes, &byte_quota, 100, NOW), "2nd request: 200/250 bytes used");
        assert!(
            !t.consume(by_bytes, &byte_quota, 100, NOW),
            "3rd request would total 300 > max_bytes=250: must be refused on bytes alone"
        );
        // A rejected consume must not have mutated the running total — a smaller request that
        // still fits under the ORIGINAL 200-byte usage is still admitted afterwards.
        assert!(
            t.consume(by_bytes, &byte_quota, 40, NOW),
            "a rejected consume must not itself have spent budget (200 + 40 = 240 <= 250)"
        );

        // --- Request-count cap binds independently of the byte cap ---
        let by_count = [2u8; 16];
        let count_quota = Quota { max_requests: 3, max_bytes: 1 << 20, window_secs: 600 };
        assert!(t.consume(by_count, &count_quota, 1, NOW), "request 1/3");
        assert!(t.consume(by_count, &count_quota, 1, NOW), "request 2/3");
        assert!(t.consume(by_count, &count_quota, 1, NOW), "request 3/3");
        assert!(
            !t.consume(by_count, &count_quota, 1, NOW),
            "4th request must be refused: over max_requests=3, even though bytes are trivial"
        );

        // --- Per-capability isolation: a DIFFERENT capability_id has its own untouched budget —
        // a shared bucket would let one abusive capability starve every other uploader.
        let other = [3u8; 16];
        assert!(
            t.consume(other, &count_quota, 1, NOW),
            "a different capability_id must have a fresh budget, not share `by_count`'s"
        );

        // --- Tumbling window: past `window_secs`, the SAME capability_id gets a fresh budget.
        assert!(
            t.consume(by_count, &count_quota, 1, NOW + count_quota.window_secs as u64),
            "a new window resets the budget for the same capability_id"
        );
    }

    /// `reap` (idle-window hygiene, mirrors `CapabilityQuotaTracker::reap`'s reason for
    /// existing): a Public relay mints one fresh `cap_id` per PoW solve, so without reaping this
    /// map grows by one permanent entry per solve. Neuter `reap` to a no-op and this reddens.
    #[test]
    fn blob_quota_tracker_reap_drops_only_idle_windows() {
        let mut t = BlobQuotaTracker::new();
        let quota = Quota { max_requests: 10, max_bytes: 1000, window_secs: 100 };
        let active = [1u8; 16];
        let idle = [2u8; 16];
        assert!(t.consume(active, &quota, 1, NOW));
        assert!(t.consume(idle, &quota, 1, NOW));

        t.reap(NOW + 50, 100);
        assert_eq!(t.windows_len(), 2, "neither window is idle past 100s yet");

        // `active` is touched again once its window has actually rolled over (>= window_secs
        // since it started), which starts a FRESH window right at this instant; `idle` is never
        // touched again, so its window never rolls over and stays exactly as stale as it was.
        assert!(t.consume(active, &quota, 1, NOW + 150));

        t.reap(NOW + 150, 100);
        assert_eq!(t.windows_len(), 1, "idle's un-rolled-over window is reaped, active's fresh one is not");
    }

    #[test]
    fn sweep_mailboxes_drops_only_entries_past_ttl() {
        // Deterministic with the fake clock (no thread, no timing): a fresh entry
        // survives, an entry past MAILBOX_TTL_SECS is dropped and its empty mailbox
        // forgotten. Neuter `MailStore::sweep` to a no-op and the "swept" case reddens.
        let relay = RelayNode::new(NOW);
        let ik = [9u8; 32];
        let seal = Payload::Skeleton(SkeletonSeal { kem_ct: Vec::new(), ephemeral_pub: [1u8; 32],
            nonce: [2u8; 12],
            ciphertext: vec![0u8; 8],
        });
        let mail = relay.mail_store();
        let mut mail = mail.lock().unwrap();
        mail.insert_for_test(ik, vec![MailboxEntry { enqueued_at: NOW, leased_until: 0, payload: seal }]);

        mail.sweep(NOW + MAILBOX_TTL_SECS - 1);
        assert_eq!(mail.queued_for(&ik), 1, "fresh entry kept");

        mail.sweep(NOW + MAILBOX_TTL_SECS + 1);
        assert!(!mail.holds(&ik), "stale entry swept, empty mailbox gone");
    }

    /// Finding #2 (backlog #162, R2-8/9): `recipient` is any 32 bytes the SENDER picks — never
    /// checked against a published bundle or any other proof of ownership — so an admitted
    /// sender can deposit one message to a fresh fabricated address every send. Before
    /// `MAX_MAILBOXES`, nothing bounded how many distinct keys the table could hold short of
    /// `MAILBOX_TTL_SECS` (7 days) passing. The table is pre-filled directly (as
    /// `sweep_mailboxes_drops_only_entries_past_ttl` above does) so the test stays fast — only
    /// the mail store's cap check is under test here, not the admission pipeline.
    #[test]
    fn a_flood_of_fabricated_recipients_cannot_grow_the_mailbox_table_without_bound() {
        let relay = Rc::new(RefCell::new(RelayNode::new(NOW)));
        {
            let r = relay.borrow_mut();
            let mail = r.mail_store();
            let mut mail = mail.lock().unwrap();
            for n in 0..MAX_MAILBOXES as u64 {
                let mut recipient = [0u8; 32];
                recipient[..8].copy_from_slice(&n.to_le_bytes());
                mail.insert_for_test(
                    recipient,
                    vec![MailboxEntry { enqueued_at: NOW, leased_until: 0, payload: test_seal(1) }],
                );
            }
            assert_eq!(mail.table_len(), MAX_MAILBOXES, "table filled to the cap");
        }

        let cap = publish_cap();
        relay.borrow_mut().issue_capability(cap.clone());
        let transport = InMemoryTransport::new(relay.clone());
        let mut attacker = Client::new(transport, cap, b"attacker");

        // A FRESH fabricated recipient, once the table is already full, must be rejected loudly
        // — never a silent drop of the send.
        let fresh = PublicKey::from([0xFEu8; 32]);
        let resp = attacker.send(&fresh, &throwaway_kem_ek(), b"hello", NOW);
        assert!(
            matches!(resp, Response::Rejected(_)),
            "a brand-new recipient must be rejected once the mailbox table is at MAX_MAILBOXES, got {resp:?}"
        );
        assert_eq!(
            relay.borrow().mail_store().lock().unwrap().table_len(),
            MAX_MAILBOXES,
            "the table did not grow past the cap"
        );

        // Control: an ALREADY-PRESENT recipient (one of the pre-filled ones) still receives mail
        // — the cap throttles brand-new keys, never delivery to an existing correspondent.
        let mut known = [0u8; 32];
        known[..8].copy_from_slice(&0u64.to_le_bytes());
        let resp2 = attacker.send(&PublicKey::from(known), &throwaway_kem_ek(), b"hi", NOW);
        assert!(
            matches!(resp2, Response::Accepted),
            "legitimate delivery to an EXISTING mailbox must still work while the table is full, got {resp2:?}"
        );
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
        // Creating a slot is metered now, so the publisher presents a capability.
        let cap = publish_cap();
        relay.issue_capability(cap.clone());
        let nonce = b"publish-nonce-1".to_vec();

        // Владелец: proof под приватным IK Bob против relay — публикуется.
        let good = publish_proof(&bob.ik().dh(&relay_pub), &cookie.mac, &bundle);
        let ok = PublishRequest {
            bundle: bundle.clone(),
            opks: Vec::new(),
            replace_opks: false,
            client_addr: addr.clone(),
            carrier_id: carrier.clone(),
            cookie: Some(cookie),
            request_nonce: nonce.clone(),
            capability_proof: cap.prove(&nonce, 0),
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
        let n2 = b"publish-nonce-2".to_vec();
        let attack = PublishRequest {
            bundle: forged,
            opks: Vec::new(),
            replace_opks: false,
            client_addr: addr,
            carrier_id: carrier,
            cookie: Some(cookie),
            request_nonce: n2.clone(),
            capability_proof: cap.prove(&n2, 0),
            proof: bad,
        };
        assert!(
            matches!(relay.handle_publish(&attack, NOW), PublishResponse::Rejected(_)),
            "чужой не должен перезаписать bundle под IK Bob"
        );
        // bundle Bob не тронут (тот же prekey, что опубликовал он).
        assert_eq!(relay.get_bundle(&bundle.ik_pub).unwrap().prekey_pub, bundle.prekey_pub);
    }

    /// A10-1 (#231): `kem_ek`/`prekey_sig` are stored VERBATIM — this relay never parses either
    /// (a sender parses the KEM key, in `pqxdh::initiate_key_agreement`; this relay's job here is
    /// pure storage-and-forward) — so a wrong-length field would slip past every other check and
    /// make the flat `raw_len: 2048` charge below (sized for "a bundle is ~1.3 KiB") undercount an
    /// arbitrarily larger stored bundle, which `get_bundle` then serves back to ANY caller for
    /// free, repeatedly, at its real (inflated) size. Neuter the length check in `handle_publish`
    /// and the two malformed cases below flip from `Rejected` to `Published` — reddens.
    #[test]
    fn publish_rejects_a_bundle_whose_kem_ek_or_prekey_sig_is_the_wrong_length() {
        let mut relay = RelayNode::new(NOW);
        let relay_pub = relay.relay_public();
        let bob = Account::generate();
        let cap = publish_cap();
        relay.issue_capability(cap.clone());
        let addr = bob.identity_public().to_vec();
        let carrier = b"c".to_vec();

        let publish = |relay: &mut RelayNode, bundle: PreKeyBundle, nonce: &[u8]| -> PublishResponse {
            let cookie = relay.keyring.issue(&addr, &carrier, NOW as u32);
            let proof = publish_proof(&bob.ik().dh(&relay_pub), &cookie.mac, &bundle);
            let req = PublishRequest {
                bundle,
                opks: Vec::new(),
                replace_opks: false,
                client_addr: addr.clone(),
                carrier_id: carrier.clone(),
                cookie: Some(cookie),
                request_nonce: nonce.to_vec(),
                capability_proof: cap.prove(nonce, 0),
                proof,
            };
            relay.handle_publish(&req, NOW)
        };

        // Oversized kem_ek: within the wire frame's ceiling, but not the real ML-KEM-768 key size.
        let mut bad_kem = bob.prekey_bundle();
        bad_kem.kem_ek = vec![7u8; ML_KEM_768_EK_LEN + 1];
        assert!(
            matches!(publish(&mut relay, bad_kem, b"n-kem"), PublishResponse::Rejected(_)),
            "an oversized kem_ek must be rejected, not stored at the flat 2048-byte charge"
        );
        assert!(relay.get_bundle(&bob.identity_public()).is_none(), "malformed bundle not stored");

        // Undersized prekey_sig.
        let mut bad_sig = bob.prekey_bundle();
        bad_sig.prekey_sig = vec![7u8; XEDDSA_SIG_LEN - 1];
        assert!(
            matches!(publish(&mut relay, bad_sig, b"n-sig"), PublishResponse::Rejected(_)),
            "a wrong-length prekey_sig must be rejected"
        );
        assert!(relay.get_bundle(&bob.identity_public()).is_none(), "malformed bundle not stored");

        // Control: the SAME account's untouched bundle (real, correctly-sized fields) still
        // publishes — the check rejects a malformed LENGTH specifically, not publishing itself.
        assert!(
            matches!(publish(&mut relay, bob.prekey_bundle(), b"n-ok"), PublishResponse::Published),
            "a correctly-shaped bundle from the same account must still publish"
        );
        assert!(relay.get_bundle(&bob.identity_public()).is_some());
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
            request_nonce: b"n".to_vec(),
            capability_proof: publish_cap().prove(b"n", 0),
            proof: [0u8; 16],
        };
        assert!(matches!(relay.handle_publish(&req, NOW), PublishResponse::NeedCookie(_)));
        assert!(relay.get_bundle(&bob.identity_public()).is_none(), "без cookie ничего не сохранено");
    }

    // ---- lease / ACK (at-most-once → effectively-once receive) ----

    fn test_seal(n: u8) -> Payload {
        Payload::Skeleton(SkeletonSeal { kem_ct: Vec::new(), ephemeral_pub: [n; 32], nonce: [n; 12], ciphertext: vec![n; 8] })
    }

    /// Build a valid authenticated `FetchRequest` for `recip`'s own mailbox: a fresh cookie
    /// at `now` (COOKIE_TTL is 30 s, so re-issue per call) + the ownership proof.
    fn fetch_at(relay: &mut RelayNode, recip: &Identity, now: u64) -> FetchRequest {
        let mailbox = recip.public.to_bytes();
        let cookie = relay.keyring.issue(&mailbox, b"c", now as u32);
        let shared = recip.dh(&relay.relay_public());
        let proof = fetch_proof(&shared, &cookie.mac, &mailbox);
        FetchRequest { mailbox, client_addr: mailbox.to_vec(), carrier_id: b"c".to_vec(), cookie: Some(cookie), proof, own_proof: Vec::new() }
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
        let recipient_m = node::blind::MailboxSecret::generate();
        // A box address is relay-specific now (PRIV-12); this relay's identity names it.
        let (seed, epoch, dir, rid) = ([5u8; 32], 3u64, 0u8, [0xA7u8; 32]);
        let address =
            node::blind::deposit_address(&recipient_m.public(), &seed, epoch, dir, &rid).unwrap();
        let fetch_secret = recipient_m.fetch_secret(&seed, epoch, dir, &rid);
        let mk = |cookie: Cookie, own: Vec<u8>, dh: [u8; 16]| FetchRequest {
            mailbox: address,
            client_addr: address.to_vec(),
            carrier_id: b"c".to_vec(),
            cookie: Some(cookie),
            proof: dh,
            own_proof: own,
        };

        // The RECIPIENT (fetch-secret holder) is authorized — an empty box returns Fetched, not Rejected.
        let c = relay.keyring.issue(&address, b"c", NOW as u32);
        let own = node::blind::FetchOwnershipProof::prove(&fetch_secret, &address, &c.mac).unwrap();
        let ok = relay.handle_fetch(&mk(c, own.to_bytes().to_vec(), [0u8; 16]), NOW);
        assert!(!matches!(ok, FetchResponse::Rejected(_)), "the fetch-secret holder is authorized");

        // The DEPOSITOR holds only M; a proof from ANY other mailbox secret fails → cannot read.
        let depositor = node::blind::MailboxSecret::generate();
        let wrong = depositor.fetch_secret(&seed, epoch, dir, &rid);
        let c2 = relay.keyring.issue(&address, b"c", NOW as u32);
        let forged = node::blind::FetchOwnershipProof::prove(&wrong, &address, &c2.mac).unwrap();
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
        relay.mail_store().lock().unwrap().append_for_test(
            recip.public.to_bytes(),
            vec![MailboxEntry { enqueued_at: at, leased_until: 0, payload }],
        );
    }

    fn boxed(relay: &RelayNode, recip: &Identity) -> bool {
        relay.mail_store().lock().unwrap().holds(&recip.public.to_bytes())
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

    /// #179 follow-up: an ACK is "the relay may forget this", so a receiver must only say it
    /// about mail it could actually read.
    ///
    /// The skeleton `Recipient` acks on receipt (it holds nothing durable, so there is no later
    /// moment at which acking would be safer). But a mailbox can hold envelopes that are not
    /// its business — a `Payload::Session` belongs to `Peer` — and acking those would tell the
    /// relay to destroy someone else's mail. Before #179 the relay destroyed them anyway on a
    /// delete-on-read fetch; now that it does not, this receiver must not re-create that.
    ///
    /// Discriminating on WHAT SURVIVES, not on what came back: the unopenable envelope must
    /// still be on the relay afterwards. Ack the whole page instead and it reddens.
    #[test]
    fn the_reference_receiver_only_acks_what_it_could_open() {
        let identity = Identity::generate();
        let relay = Rc::new(RefCell::new(RelayNode::with_identity(NOW, identity.clone())));
        let cap = publish_cap();
        relay.borrow_mut().issue_capability(cap.clone());
        let bob = Identity::generate();

        // The receiver is built FIRST now: a hybrid seal needs the recipient's ML-KEM key
        // (PRIV-3), and `Recipient` mints its own, so there is nothing to seal to until it
        // exists. That mirrors the real path, where a sender must fetch the bundle first.
        let mut recip = Recipient::new(InMemoryTransport::new(relay.clone()), bob.clone(), identity.public);

        // One seal Bob can open...
        let mut alice = Client::new(InMemoryTransport::new(relay.clone()), cap, b"alice");
        assert!(matches!(
            alice.send(&bob.public, recip.kem_ek(), b"for bob", NOW),
            Response::Accepted
        ));
        // ...and one session envelope that is not his to read (it is `Peer`'s business).
        relay.borrow().mail_store().lock().unwrap().append_for_test(bob.public.to_bytes(), vec![MailboxEntry {
            enqueued_at: NOW,
            leased_until: 0,
            payload: Payload::Session(SessionEnvelope::Ratchet(node::ratchet::RatchetMessage {
                header: node::ratchet::Header {
                    dh: [9u8; 32],
                    pn: 0,
                    n: 0,
                    salt: [9u8; node::ratchet::SALT_LEN],
                },
                ciphertext: vec![9u8; 16],
            })),
        }]);
        assert_eq!(relay.borrow().mailbox_len_for_test(&bob.public.to_bytes()), 2);

        let got = recip.receive(NOW).expect("fetch succeeds");
        assert_eq!(got.len(), 2, "both entries were served");
        assert_eq!(got.iter().filter(|o| o.is_some()).count(), 1, "only one was openable");

        assert_eq!(
            relay.borrow().mailbox_len_for_test(&bob.public.to_bytes()),
            1,
            "the opened seal is ACKed away; the envelope this receiver could not read is NOT"
        );
    }

    /// #142: separating admission from the mail write must not make the mailbox cap racy.
    ///
    /// Admission and the deposit now run under DIFFERENT locks, with the relay lock released in
    /// between. Two senders can therefore both be admitted while the mailbox has exactly one slot
    /// left. If the cap lived only in the admission half — where it used to be, when both halves
    /// were one critical section — both would then write and the queue would exceed
    /// `MAX_FETCH_SEALS`, breaking the invariant #162 established: a mailbox always fits in one
    /// response frame, so a fetch can never hit `FrameTooLarge` AFTER draining and silently lose
    /// an offline recipient's whole queue.
    ///
    /// Two admissions are taken BEFORE either deposits, which is exactly the interleaving that
    /// concurrency produces, without threads or timing. Delete the cap check inside
    /// `MailStore::deposit` and this reddens.
    #[test]
    fn two_deposits_admitted_at_once_cannot_overfill_one_mailbox() {
        let mut relay = RelayNode::new(NOW);
        let cap = publish_cap();
        relay.issue_capability(cap.clone());
        let bob = Identity::generate();
        let mailbox = bob.public.to_bytes();

        // Fill to one slot short of the cap.
        let fill: Vec<MailboxEntry> = (0..MAX_FETCH_SEALS - 1)
            .map(|n| MailboxEntry { enqueued_at: NOW, leased_until: 0, payload: test_seal((n % 251) as u8) })
            .collect();
        relay.mail_store().lock().unwrap().append_for_test(mailbox, fill);

        // Both senders get past admission while that last slot is still free.
        let msg = |n: u8| WireMessage {
            client_addr: b"s".to_vec(),
            carrier_id: b"c".to_vec(),
            cookie: None,
            request_nonce: vec![n; 16],
            capability_proof: cap.prove(&[n; 16], 0),
            recipient: mailbox,
            // A payload that cannot collide with anything in the fill above — otherwise the
            // idempotent-deposit path would answer `Accepted` for a DUPLICATE and the test would
            // be measuring dedup, not the cap.
            payload: Payload::Skeleton(SkeletonSeal { kem_ct: Vec::new(), ephemeral_pub: [n; 32],
                nonce: [n; 12],
                ciphertext: vec![n; 9],
            }),
        };
        // One cookie round trip each, then a real admission.
        let cookie = relay.keyring.issue(b"s", b"c", NOW as u32);
        let admit = |relay: &mut RelayNode, n: u8| {
            let mut m = msg(n);
            m.cookie = Some(cookie);
            m.capability_proof = cap.prove(&m.request_nonce, 0);
            relay.admit_send(&m, NOW).map(|a| (a, m))
        };
        let first = admit(&mut relay, 1).expect("first sender admitted");
        let second = admit(&mut relay, 2).expect("second sender admitted while the slot was free");

        // Now they race for the same slot. Exactly one wins; the other is told the box is full.
        assert!(matches!(first.0.deposit(&first.1.payload, NOW), Response::Accepted));
        assert!(
            matches!(second.0.deposit(&second.1.payload, NOW), Response::Rejected(ref r) if r == "MailboxFull"),
            "the second admitted deposit must be refused by the cap, not squeezed in"
        );
        assert_eq!(
            relay.mail_store().lock().unwrap().queued_for(&mailbox),
            MAX_FETCH_SEALS,
            "the queue must sit exactly at the cap — the one-frame invariant is not negotiable"
        );

        // And the interaction the cap check now DEPENDS on being ordered after the dedup scan: a
        // retry of a message the relay already holds is `Accepted` even though the mailbox is
        // full. Moving the cap check above the dedup scan would look like a harmless
        // simplification and would instead tell a sender to keep retrying a message that is
        // already sitting in the recipient's queue.
        assert!(
            matches!(first.0.deposit(&first.1.payload, NOW), Response::Accepted),
            "an idempotent retry must still be Accepted at a full mailbox — it is already there"
        );
    }

    /// #179: a fetch can no longer ask the relay to DELETE on read.
    ///
    /// `FetchRequest` used to carry an `ack` flag, and with it clear the relay destroyed the
    /// served messages immediately — before the recipient had decrypted them, let alone written
    /// them down. This was the "legacy" mode kept for callers that had not moved to lease/ACK;
    /// the flag is gone, so there is no way to select it and no default to get wrong.
    ///
    /// Discriminating on the thing that actually matters — the message is STILL ON THE RELAY
    /// after being served — rather than on "a second fetch is empty", which is true under BOTH
    /// behaviours (deleted vs leased-and-hidden) and would therefore pin nothing.
    #[test]
    fn a_fetch_can_no_longer_ask_the_relay_to_delete_on_read() {
        let mut relay = RelayNode::new(NOW);
        let bob = Identity::generate();
        deposit(&mut relay, &bob, NOW, test_seal(1));

        let req = fetch_at(&mut relay, &bob, NOW);
        assert_eq!(fetched(relay.handle_fetch(&req, NOW)).len(), 1, "the message is served");
        assert!(boxed(&relay, &bob), "and is STILL on the relay: a fetch is a lease, never a delete");

        // Hidden while leased (that part is unchanged)...
        let req2 = fetch_at(&mut relay, &bob, NOW);
        assert!(fetched(relay.handle_fetch(&req2, NOW)).is_empty(), "leased message hidden");
        // ...and redelivered once the lease lapses, because nothing ACKed it. A receiver that
        // simply drops the message on the floor now costs a duplicate, not a loss.
        let later = NOW + LEASE_SECS + 1;
        let req3 = fetch_at(&mut relay, &bob, later);
        assert_eq!(
            fetched(relay.handle_fetch(&req3, later)).len(),
            1,
            "an unacked lease redelivers instead of the message being gone"
        );
    }

    /// `ack: true` LEASES: the message is returned but stays on the relay, hidden from a
    /// second fetch, until an ACK deletes it. This is the crash-safety window — the message
    /// survives on the relay across the [fetch, save] gap.
    #[test]
    fn lease_fetch_keeps_until_ack() {
        let mut relay = RelayNode::new(NOW);
        let bob = Identity::generate();
        deposit(&mut relay, &bob, NOW, test_seal(2));

        let req = fetch_at(&mut relay, &bob, NOW);
        let got = fetched(relay.handle_fetch(&req, NOW));
        assert_eq!(got.len(), 1);
        // Leased → invisible to a second immediate fetch, but NOT deleted.
        let req2 = fetch_at(&mut relay, &bob, NOW);
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

        let req = fetch_at(&mut relay, &bob, NOW);
        assert_eq!(fetched(relay.handle_fetch(&req, NOW)).len(), 1);
        // Before expiry: hidden. After LEASE_SECS: visible again, same ciphertext.
        let mid = NOW + LEASE_SECS - 1;
        let req_mid = fetch_at(&mut relay, &bob, mid);
        assert!(fetched(relay.handle_fetch(&req_mid, mid)).is_empty(), "still leased");
        let later = NOW + LEASE_SECS + 1;
        let req_late = fetch_at(&mut relay, &bob, later);
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

        let req = fetch_at(&mut relay, &bob, NOW);
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
        let req = fetch_at(&mut relay, &bob, NOW);
        let _ = relay.handle_fetch(&req, NOW);
        // ...yet the sweep at deposit + TTL still removes it, lease notwithstanding.
        relay.mail_store().lock().unwrap().sweep(NOW + MAILBOX_TTL_SECS + 1);
        assert!(!boxed(&relay, &bob), "deposit-time TTL reaps a never-acked lease");
    }

    /// R2-5 (#161): `RelayPolicy` must not let a client believe a queued message is any more
    /// durable than it is. `policy()` reports `Volatile` because nothing writes `mailboxes` to
    /// disk — see `MailboxDurability` for what changes this assertion (an additive variant, the
    /// day a durable mode actually exists).
    #[test]
    fn advertised_policy_reports_mailboxes_as_volatile() {
        let relay = RelayNode::new(NOW);
        assert_eq!(
            relay.policy().mailbox_durability,
            MailboxDurability::Volatile,
            "mailboxes have no disk path (see RelayNode::mailboxes) — the policy must say so"
        );
    }

    /// #145: the relay must not be able to admit a token credential on the strength of a
    /// structural stub.
    ///
    /// The finding as filed was "mock and production verifiers share one build/config path, so a
    /// feature-flag mistake could silently run a relay with no admission security". Reading the
    /// code sharpens it in both directions: no wire request can carry a `Credential::Token` at
    /// all today (every relay path builds `Credential::Capability`), so this was never live —
    /// but the relay did not merely DEFAULT to the mock, it hardcoded the type, so the day a
    /// request class carried a token, a stub that checks only the shape of the signature would
    /// have been the whole of admission.
    ///
    /// This pins the fix behaviourally, not by type name: a token the stub itself accepts must
    /// be REFUSED by whatever verifier the relay actually holds. Put `MockRingVerifier` back in
    /// that field and this reddens.
    #[test]
    fn the_relay_refuses_a_token_the_structural_stub_would_accept() {
        use admission::token::{AdmissionTokenVerifier, MockRingVerifier};
        let ring = IssuerRing { issuer_pubkeys: vec![[1u8; 32]; 5], threshold_t: 2 };
        let token = MockRingVerifier::mock_token([0x77; 32], 0, 2);
        // Control: the token is "valid" in the only sense the stub knows — 2 of 5, right epoch,
        // well-formed signature blob. Without this arm the test could pass on a malformed token.
        assert!(
            MockRingVerifier::for_tests_only().verify(&token, &ring, 0).is_ok(),
            "control: the structural stub accepts this token"
        );
        let relay = RelayNode::new(NOW);
        assert!(
            relay.verifier.verify(&token, &ring, 0).is_err(),
            "the relay's verifier must refuse a token no audited verifier has checked"
        );
    }

    /// R2-5 (#161): the fix. A relay running `Durable` must hand an accepted message back after
    /// a restart — same node identity, same log directory, a brand-new `RelayNode`.
    ///
    /// The negative control is the test below it, which is the SAME scenario on a `Volatile`
    /// relay and still asserts the message is gone: without that pair, this test would also pass
    /// if `with_identity` had somehow started sharing state, which is not what is being claimed.
    #[test]
    fn an_accepted_message_survives_a_relay_restart_when_the_operator_asked_for_durability() {
        let dir = mail_dir("survives");
        let identity = Identity::generate();
        let recipient = PublicKey::from([0x42u8; 32]);
        {
            let mut relay = RelayNode::with_identity(NOW, identity.clone());
            relay.enable_durable_mail(dir.clone(), NOW).expect("open the mail log");
            let cap = publish_cap();
            relay.issue_capability(cap.clone());
            let relay = Rc::new(RefCell::new(relay));
            let mut sender = Client::new(InMemoryTransport::new(relay.clone()), cap, b"sender");
            assert!(matches!(sender.send(&recipient, &throwaway_kem_ek(), b"hello", NOW), Response::Accepted));
            assert_eq!(relay.borrow().mailbox_len_for_test(&recipient.to_bytes()), 1);
        } // the relay process "exits" here

        let mut restarted = RelayNode::with_identity(NOW, identity);
        restarted.enable_durable_mail(dir.clone(), NOW).expect("reopen the mail log");
        assert_eq!(
            restarted.mailbox_len_for_test(&recipient.to_bytes()),
            1,
            "an accepted message must come back after a restart on a Durable relay"
        );
        assert_eq!(restarted.policy().mailbox_durability, MailboxDurability::Durable);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R2-5 (#161): what a restart does to messages a recipient has already SEEN. One leased but
    /// never ACKed comes back (it may be redelivered — the client dedups); one it ACKed does not,
    /// because the delete was recorded. This pins the lease/ACK boundary across a restart; the
    /// at-least-once trade itself — a delete lost to a crash — is pinned one layer down by
    /// `mailstore::tests::a_delete_lost_to_a_crash_redelivers_the_message`, which is the test an
    /// exactly-once implementation would fail.
    #[test]
    fn a_leased_message_returns_after_a_restart_but_an_acked_one_stays_gone() {
        let dir = mail_dir("atleastonce");
        let identity = Identity::generate();
        let bob = Identity::generate();
        {
            let mut relay = RelayNode::with_identity(NOW, identity.clone());
            relay.enable_durable_mail(dir.clone(), NOW).expect("open the mail log");
            let cap = publish_cap();
            relay.issue_capability(cap.clone());
            let mut relay = {
                // Two messages through the real client path (cookie + capability + admission):
                // one will be leased-and-forgotten, one leased-and-acked.
                let shared = Rc::new(RefCell::new(relay));
                let mut sender = Client::new(InMemoryTransport::new(shared.clone()), cap, b"sender");
                for body in [b"one".as_ref(), b"two".as_ref()] {
                    assert!(matches!(sender.send(&bob.public, &throwaway_kem_ek(), body, NOW), Response::Accepted));
                }
                drop(sender);
                Rc::try_unwrap(shared).ok().expect("sole owner").into_inner()
            };
                        // Lease both, then ACK only the first.
            let req = fetch_at(&mut relay, &bob, NOW);
            let got = fetched(relay.handle_fetch(&req, NOW));
            assert_eq!(got.len(), 2);
            let ack = ack_at(&mut relay, &bob, NOW, vec![payload_id(&got[0])]);
            assert!(matches!(relay.handle_ack(&ack, NOW), AckResponse::Acked));
        }

        let mut restarted = RelayNode::with_identity(NOW, identity);
        restarted.enable_durable_mail(dir.clone(), NOW).expect("reopen");
        assert_eq!(
            restarted.mailbox_len_for_test(&bob.public.to_bytes()),
            1,
            "the ACKed message is gone for good; the leased-but-unacked one is redelivered"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R2-5 (#161): the replay is not a trapdoor around the live bounds. A log holding an entry
    /// past `MAILBOX_TTL_SECS` — the shape a relay that was down for a week produces, and equally
    /// the shape someone with write access to the log would forge — must not reinstate it.
    #[test]
    fn a_replayed_log_is_re_bounded_not_trusted() {
        let dir = mail_dir("rebound");
        let bob = [0x55u8; 32];
        {
            let (mut log, _) = crate::mailstore::MailLog::open(dir.clone()).unwrap();
            log.deposit(bob, NOW, &test_seal(1)).unwrap(); // stale by the time we reopen
            log.deposit(bob, NOW + MAILBOX_TTL_SECS, &test_seal(2)).unwrap(); // still fresh
        }
        let mut relay = RelayNode::with_identity(NOW, Identity::generate());
        relay
            .enable_durable_mail(dir.clone(), NOW + MAILBOX_TTL_SECS + 1)
            .expect("open the mail log");
        assert_eq!(
            relay.mailbox_len_for_test(&bob),
            1,
            "the TTL applies to a replayed entry exactly as it does to a live one"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R2-5 (#161): FAIL-CLOSED. A relay that advertises `Durable` and cannot write must reject,
    /// not answer `Accepted` — the sender retires its outbox entry on `Accepted`, so a silent
    /// downgrade to volatile is exactly the loss this whole feature exists to close, except now
    /// the operator has also promised otherwise.
    #[test]
    fn a_durable_relay_that_cannot_write_rejects_instead_of_accepting() {
        let dir = mail_dir("failclosed");
        let mut relay = RelayNode::with_identity(NOW, Identity::generate());
        relay.enable_durable_mail(dir.clone(), NOW).expect("open the mail log");
        let cap = publish_cap();
        relay.issue_capability(cap.clone());
        relay.mail_store().lock().unwrap().poison_log_for_test(); // the disk goes away
        let relay = Rc::new(RefCell::new(relay));
        let mut sender = Client::new(InMemoryTransport::new(relay.clone()), cap, b"sender");
        let recipient = PublicKey::from([0x43u8; 32]);
        match sender.send(&recipient, &throwaway_kem_ek(), b"hello", NOW) {
            Response::Rejected(r) => assert_eq!(r, "MailNotDurable"),
            other => panic!("a durable relay that cannot write must reject, got {other:?}"),
        }
        assert_eq!(
            relay.borrow().mailbox_len_for_test(&recipient.to_bytes()),
            0,
            "nothing may be queued in RAM that is not on disk"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    fn mail_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "karst-relaymail-{name}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ))
    }

    /// #142/R2-5: the ADVERTISED durability and the real behaviour must be the same fact.
    ///
    /// `policy()` reads a cached flag rather than the mail store (so answering `GetPolicy` never
    /// queues behind an fsync), which creates exactly the failure this project has been caught by
    /// before: a reported value that nothing ties to what the code does. So this asserts both on
    /// ONE relay — it says `Durable`, and a message deposited through it really is on disk.
    #[test]
    fn a_relay_that_advertises_durable_mail_actually_writes_it() {
        let dir = mail_dir("advertised");
        let identity = Identity::generate();
        let recipient = PublicKey::from([0x51u8; 32]);
        {
            let mut relay = RelayNode::with_identity(NOW, identity.clone());
            relay.enable_durable_mail(dir.clone(), NOW).expect("open the mail log");
            assert_eq!(
                relay.policy().mailbox_durability,
                MailboxDurability::Durable,
                "the relay advertises durable mail"
            );
            let cap = publish_cap();
            relay.issue_capability(cap.clone());
            let relay = Rc::new(RefCell::new(relay));
            let mut sender = Client::new(InMemoryTransport::new(relay.clone()), cap, b"sender");
            assert!(matches!(sender.send(&recipient, &throwaway_kem_ek(), b"on disk?", NOW), Response::Accepted));
        }
        let mut restarted = RelayNode::with_identity(NOW, identity);
        restarted.enable_durable_mail(dir.clone(), NOW).expect("reopen");
        assert_eq!(
            restarted.mailbox_len_for_test(&recipient.to_bytes()),
            1,
            "...and the advertisement was true: the message survived the restart"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R2-5 (#161) — CHARACTERIZATION, not a fix. `mailboxes` lives only in `RelayNode`'s own
    /// memory (see its field doc), so there is nothing to "neuter" here to turn this red: it pins
    /// today's real behavior — an `Accepted` message is gone the moment the process holding it
    /// is gone — so a future persistence layer has a red test to turn green, instead of an
    /// unverified claim. `karst-relay` restarts with the SAME node identity (`load_or_create_keys`
    /// persists it to `relay.key`); `with_identity` + a cloned `Identity` reproduces exactly that
    /// continuity, so this is not a strawman "different relay" — same identity, empty mailboxes.
    #[test]
    fn an_accepted_message_does_not_survive_a_relay_restart() {
        let identity = Identity::generate();
        let relay = Rc::new(RefCell::new(RelayNode::with_identity(NOW, identity.clone())));
        let cap = publish_cap();
        relay.borrow_mut().issue_capability(cap.clone());
        let transport = InMemoryTransport::new(relay.clone());
        let mut sender = Client::new(transport, cap, b"sender");

        let recipient = PublicKey::from([0x42u8; 32]);
        let resp = sender.send(&recipient, &throwaway_kem_ek(), b"hello", NOW);
        assert!(matches!(resp, Response::Accepted), "precondition: the relay actually admitted it");
        assert_eq!(
            relay.borrow().mailbox_len_for_test(&recipient.to_bytes()),
            1,
            "precondition: it is really sitting in the mailbox before the 'restart'"
        );

        // The "restart": a fresh RelayNode, same persisted identity, nothing carried over.
        let restarted = RelayNode::with_identity(NOW, identity);
        assert_eq!(
            restarted.mailbox_len_for_test(&recipient.to_bytes()),
            0,
            "an Accepted message does not survive a restart, and the sender is never told (R2-5)"
        );
    }
}
