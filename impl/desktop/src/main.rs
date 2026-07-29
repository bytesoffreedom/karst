#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! KARST desktop (Tauri) — a thin command bridge over the `client` core. The UI is the web
//! frontend in `ui/`; every real operation is a `#[tauri::command]` that calls the SAME
//! `client`/`node` crates the CLI and egui app use.

use std::collections::HashMap;
use std::io::Cursor;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine};
use client::content::{decode, Assembled, Content, Reassembler};
use client::store::{
    AccountEntry, ContactRecord, ExtraPassword, HistoryRecord, NetSettings, Opened, ReceivedFile,
    Store, Vault,
};
use client::{Relay, RelayId};
use serde::Serialize;
use tauri::State;

/// Largest attachment we move over the Tauri IPC in ONE payload. The whole file crosses the
/// JS↔Rust bridge as a base64 JSON string, so this caps a single (de)serialization hitch. Files
/// above it are STREAMED in `MAX_ATTACH_BYTES`-sized chunks via `file_begin`/`file_push`/
/// `file_commit` instead (#35 / FT1).
const MAX_ATTACH_BYTES: usize = 8 * 1024 * 1024;

/// Ceiling on a single STREAMED attachment (accumulated across `file_push` chunks). A generous
/// bound that still stops a runaway/hostile frontend from growing the buffer without limit.
const MAX_STREAM_BYTES: usize = 512 * 1024 * 1024;

/// The vault directory. Precedence: `KARST_HOME` env (scripts/tests, unchanged) → the saved
/// `active-vault` pointer (set from the GUI's "Vault location" — survives a restart) → the
/// platform default. Read ONLY when opening a vault (boot `account_exists`, `create_account`,
/// `unlock`); after `enter()` the `Session` owns the store, so nothing re-derives this.
fn home() -> PathBuf {
    if let Ok(d) = std::env::var("KARST_HOME") {
        if !d.trim().is_empty() {
            return PathBuf::from(d);
        }
    }
    if let Ok(p) = std::fs::read_to_string(active_vault_pointer()) {
        let p = p.trim();
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    Store::default_dir()
}

/// The fixed config base that holds the `active-vault` pointer — deliberately NOT derived from
/// the vault dir, so the pointer never moves with the thing it selects.
fn config_base() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".config")
        })
        .join("karst")
}

fn active_vault_pointer() -> PathBuf {
    config_base().join("active-vault")
}

/// The vault folder to open for THIS window: an explicit per-window choice (the vault picker on the
/// unlock/create screen) wins over the global `home()`. Passing it per unlock is what lets two
/// windows open two DIFFERENT accounts on one machine, with no KARST_HOME and no shared pointer.
fn resolve_home(vault_dir: Option<String>) -> PathBuf {
    match vault_dir.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        Some(d) => PathBuf::from(d),
        None => home(),
    }
}

/// Whether `dir` already holds an account vault (pre-multipassword `accounts.dat`, or the
/// multipassword `slots.dat`). Lets the UI say "unlock this" vs "a new vault will be created".
fn dir_has_account(dir: &std::path::Path) -> bool {
    dir.join("accounts.dat").exists()
        || dir.join("slots.dat").exists()
        || dir.join("container.dat").exists() // a deniable container counts as an account to unlock
}
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
/// A story self-destructs 24h after it is posted.
const STORY_TTL_SECS: u64 = 24 * 60 * 60;
/// Most public posts we serve to a single live-pull visitor (bounds the reply to a profile view).
const POSTS_PULL_LIMIT: usize = 30;
/// Window the global live-pull reply budget refills over. Matched to the admission capability's own
/// quota window (`admission::capability`, 600 s), because the scarce thing being rationed is
/// ultimately that quota: a request unit spent answering a stranger's profile view is a request unit
/// this account cannot spend sending a message.
const POSTS_REPLY_WINDOW_SECS: u64 = 600;
/// Publication sends this client will spend answering `PostsRequest` per window — in TOTAL, across
/// every peer. A typical Public capability allows 100 requests per 600 s, so capping live-pull at 30
/// reserves the rest for chat: answering profile views can no longer deny the user their own sends.
const POSTS_REPLY_BUDGET: usize = 30;
/// Reply jobs allowed to run CONCURRENTLY. Each is one OS thread doing serialisation, sealing and
/// relay round trips, so this is the difference between a bounded responder and a thread flood.
const POSTS_REPLY_MAX_ACTIVE: usize = 2;

/// Global admission for `PostsRequest` replies (SEC-30). One inbound control message used to load
/// the whole feed, spawn an OS thread and fire up to `POSTS_PULL_LIMIT` separate sends, with no
/// cooldown, no dedup and no ceiling — a 1→30 amplifier any stranger could pull, repeatedly.
///
/// The bound is deliberately GLOBAL rather than per-peer. Per-peer cooldown is the obvious remedy
/// and it does not hold here: the requester is authenticated only as "some session", and a
/// `PostsRequest` needs no contact status, so an attacker mints a fresh identity key per request and
/// walks straight past any per-peer state. Worse, per-peer state keyed by an attacker-chosen IK is
/// itself unbounded memory. What survives fresh identities is a budget that does not care who is
/// asking.
///
/// The cost of that choice, stated plainly: a flood can exhaust the window's budget and make this
/// client stop answering live pulls until it refills — the feature is deniable. That is the right
/// trade, because the alternative it replaces is a flood exhausting the account's REQUEST QUOTA and
/// denying the user their own messages, plus unbounded threads. Losing "strangers can peek at my
/// public posts right now" is recoverable; losing "I can send" is not.
#[derive(Default)]
struct PostsReplyBudget {
    /// Start of the current window (0 until the first admission).
    window_start: u64,
    /// Sends reserved in this window.
    spent: usize,
    /// Reply jobs currently running.
    active: usize,
}

impl PostsReplyBudget {
    /// Reserve up to `want` sends for one reply job. Returns how many are granted (0 = refuse, and
    /// the caller must do NOTHING — not even read the feed, which is itself per-request work an
    /// attacker would otherwise get for free). On a non-zero grant the caller owns one active slot
    /// and must release it via `PostsReplySlot`.
    fn admit(&mut self, now: u64, want: usize) -> usize {
        if now.saturating_sub(self.window_start) >= POSTS_REPLY_WINDOW_SECS {
            self.window_start = now;
            self.spent = 0;
        }
        if self.active >= POSTS_REPLY_MAX_ACTIVE {
            return 0;
        }
        let granted = want.min(POSTS_REPLY_BUDGET.saturating_sub(self.spent));
        if granted == 0 {
            return 0;
        }
        self.spent += granted;
        self.active += 1;
        granted
    }

    /// Hand back sends that were reserved but not needed (we have fewer public posts than the
    /// grant). Without this a client with three public posts would burn a 30-send reservation per
    /// visitor and refuse honest visitors ten times too early.
    ///
    /// The caller must always leave at least ONE unit charged per admitted request — see the floor
    /// at the call site. Answering costs more than the sends: the feed and public-post sets are
    /// sealed files, so deciding there is nothing to reply with is already a full read and AEAD
    /// open per request. A client with no public posts at all — a new account, or one whose posts
    /// are all narrow-audience — is the common case, and refunding its whole reservation would
    /// leave the window permanently empty and the rate unbounded, with only the concurrency cap
    /// standing between a mailbox burst and one feed decrypt per message.
    fn refund(&mut self, n: usize) {
        self.spent = self.spent.saturating_sub(n);
    }
}

/// RAII release of an active reply slot — a `Drop` impl rather than a call at the end of the thread
/// body, so a panic in the reply loop cannot permanently consume one of the `POSTS_REPLY_MAX_ACTIVE`
/// slots and quietly kill live pull for the rest of the process's life.
struct PostsReplySlot(Arc<Mutex<PostsReplyBudget>>);

impl Drop for PostsReplySlot {
    fn drop(&mut self) {
        if let Ok(mut b) = self.0.lock() {
            b.active = b.active.saturating_sub(1);
        }
    }
}
/// Max fetch pages a single poll drains per proxy (≈ pages × page-size messages). Bounds one poll's
/// work so a flooded mailbox can't wedge it, while still emptying a normal image post in one pass.
const MAX_DRAIN_PAGES: usize = 80;

/// The unlocked device vault, the active account id, and the relays it multi-homes to.
struct Session {
    vault: Vault,
    id: String,
    relays: Vec<Relay>,
    /// This session opened a DECOY compartment (under a decoy password). The Security card is
    /// hidden and password/dead-man management is refused, so a coerced decoy login cannot see or
    /// disarm the real account's protections.
    decoy: bool,
}

/// One in-flight or just-finished large-file transfer (blob upload or download). Progress and
/// terminal state live here; the UI reads them via `transfer_progress` (a gated fast poll), and
/// `cancel_transfer` flips `cancel`. Threads update it in place.
struct TransferState {
    dir: &'static str, // "up" | "down"
    peer: [u8; 32],
    name: String,
    done: u64,
    total: u64,
    state: &'static str, // "active" | "done" | "cancelled" | "error"
    file_id: Option<String>,
    error: Option<String>,
    /// Set when the transfer reaches a terminal state — used to prune it after a grace period
    /// (so a missed fast-poll can't lose the terminal update).
    finished_at: Option<u64>,
    cancel: Arc<AtomicBool>,
}

type Transfers = Arc<Mutex<HashMap<u64, TransferState>>>;

#[derive(Default)]
struct App {
    session: Mutex<Option<Session>>,
    /// Per-sender inline-file reassembly state, threaded across `poll` calls (a small file's
    /// manifest + chunks may span batches). Its OWN lock, held only during the decode step —
    /// never across a network round trip. Cleared whenever the active account changes.
    reasm: Mutex<HashMap<[u8; 32], Reassembler>>,
    /// In-flight + recently-finished large-file transfers, keyed by transfer id. Shared with
    /// the upload/download threads via `Arc`.
    transfers: Transfers,
    next_tid: AtomicU64,
    /// Blob ids with a download thread currently running, so `poll` does not spawn a second
    /// thread for the same pending download while the first is still going. `Arc` so a download
    /// thread can clear its own entry when it finishes.
    in_flight: Arc<Mutex<std::collections::HashSet<[u8; 32]>>>,
    /// Files being STREAMED up from the webview, keyed by a per-send id. The frontend can only
    /// hand back one IPC payload at a time (base64 over JSON caps at a few MB), so a large file
    /// arrives as a run of `file_push` chunks accumulated here, then dispatched by `file_commit`.
    /// This is what lets an attachment exceed the old ~8 MB single-payload ceiling (#35 / FT1).
    pending_sends: Mutex<HashMap<String, Vec<u8>>>,
    /// The decrypted payload of an OPAQUE HIDDEN container, held only between an unlock that entered
    /// the hidden password and the UI fetching it once. Not a session — a bounded secret to display.
    hidden: Mutex<Option<Vec<u8>>>,
    /// Tier-2 REDESIGN (opt-in, not yet UI-exposed): when a container-backed account is open, this
    /// holds the `ContainerVault` so `container_flush` can snapshot the work dir back into the
    /// deniable container after changes. `None` for the normal file-tree vault path.
    container: Mutex<Option<client::container::ContainerVault>>,
    /// OFFLINE mode: when true, the session emits NOTHING to the network — no publish, no poll — so
    /// an observer sees no traffic for it at all. Default ON for a HIDDEN account (its whole network
    /// deniability is "silent unless you deliberately sync"); the user toggles it off to sync.
    /// `Arc<AtomicBool>` (not a plain `Mutex<bool>`) so a background thread that has no `State<App>`
    /// — the cover-traffic deposit, the `PostsRequest` reply loop — can still clone a live handle
    /// and re-check the flag mid-run instead of only at spawn time (SEC-45: a toggle read once
    /// before a thread starts doing I/O is stale for as long as that thread keeps running).
    offline: Arc<AtomicBool>,
    /// How many network-emitting calls with NO per-item cancel flag (a `poll`, a cover-traffic
    /// deposit, the `PostsRequest` reply loop) are currently between "read offline=false" and
    /// "done touching the wire." `stop_for_offline` waits for this to hit zero — together with
    /// every transfer's cancel flag landing — before it will claim nothing further is being
    /// emitted (SEC-45: without this, `set_net_offline(true)` could return success while one of
    /// these was still mid-flight on a relay handle captured before the flip).
    net_active: Arc<AtomicU64>,
    /// SEC-30 — the global ceiling on work an inbound `PostsRequest` may cause. `Arc` for the same
    /// reason `offline` is one: the reply job runs on its own thread and has to release its slot
    /// there, with no `State<App>` in hand.
    posts_reply: Arc<Mutex<PostsReplyBudget>>,
}

impl App {
    /// True when the active session is a HIDDEN container account. Its work dir is RAM/tmpfs and
    /// its zero-external-artifact rule means it must never write plaintext outside the container —
    /// so exporting a file to disk and accepting bulk media downloads are refused for it.
    fn is_hidden_session(&self) -> bool {
        self.container
            .lock()
            .unwrap()
            .as_ref()
            .map(|cv| cv.role == client::container::Role::Hidden)
            .unwrap_or(false)
    }

    /// The active account's store + relays (cheap clones), so a networked command doesn't
    /// hold the session lock across a blocking round trip. Errors if locked.
    fn snapshot(&self) -> Result<(Store, Vec<Relay>), String> {
        let g = self.session.lock().unwrap();
        let s = g.as_ref().ok_or("locked — unlock first")?;
        Ok((s.vault.account(&s.id), self.relays_or_empty(&s.relays)))
    }

    /// OFFLINE single-choke: every deposit command gets its relays from here (or `session_parts`),
    /// so returning an EMPTY set when offline makes all of them find "no relay" and emit nothing —
    /// airtight without gating each command. Read-only commands ignore the relays, so this is safe.
    fn relays_or_empty(&self, relays: &[Relay]) -> Vec<Relay> {
        if self.offline.load(Ordering::SeqCst) {
            Vec::new()
        } else {
            relays.to_vec()
        }
    }

    /// Like `snapshot`, but also hands back the vault + id so `poll` can hand a fresh `Store`
    /// to a background blob-download thread (the vault is cheap to clone).
    fn session_parts(&self) -> Result<(Vault, String, Vec<Relay>), String> {
        let g = self.session.lock().unwrap();
        let s = g.as_ref().ok_or("locked — unlock first")?;
        Ok((s.vault.clone(), s.id.clone(), self.relays_or_empty(&s.relays)))
    }

    /// Reset per-account transient state (called when the active account changes): drop
    /// half-received inline files, half-SENT streamed uploads, and CANCEL + drop any in-flight
    /// transfers so a new account never inherits another's threads or partial files.
    ///
    /// **A3-10 — `pending_sends` was the one thing this did not clear.** An upload id is minted by
    /// `file_begin` under the account that was unlocked then, but `file_commit` dispatches through
    /// whatever session is current when it runs — so a file a user started uploading as account A
    /// and committed after switching to account B went out from B, to B's contact, over B's relay.
    /// Clearing here gives the same guarantee an `upload_id → account` binding would (a commit can
    /// only ever reach the account that began it) at the one place that already exists to enforce
    /// exactly this, and it frees the buffered bytes on the switch as a side effect.
    fn reset_transient(&self) {
        self.reasm.lock().unwrap().clear();
        self.pending_sends.lock().unwrap().clear();
        let mut t = self.transfers.lock().unwrap();
        for st in t.values() {
            st.cancel.store(true, Ordering::Relaxed);
        }
        t.clear();
        self.in_flight.lock().unwrap().clear();
    }

    fn new_tid(&self) -> u64 {
        self.next_tid.fetch_add(1, Ordering::Relaxed)
    }
}

/// RAII marker for "a network-emitting call with no per-item cancel flag is between its offline
/// check and being done with the wire" — held by `poll`, `cover_tick`'s spawned deposit, and the
/// `PostsRequest` reply loop. `stop_for_offline` spins on `App::net_active` hitting zero, so
/// forgetting to drop this on an early return would hang the Offline toggle forever; tying it to
/// Drop means every return path (including `?`) releases it.
struct NetGuard(Arc<AtomicU64>);
impl NetGuard {
    /// Enter BEFORE checking `offline`, not after — otherwise a call that reads offline=false the
    /// instant before `stop_for_offline` observes `net_active == 0` can still start its round trip
    /// after Offline has already reported success (SEC-45's exact failure mode, just moved one
    /// layer down).
    fn enter(counter: &Arc<AtomicU64>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter.clone())
    }
}
impl Drop for NetGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Bound on how long `stop_for_offline` waits (in `STOP_WAIT_STEP`-sized polls) for cancellable
/// network work to actually quiesce before giving up and reporting the honest residual instead of
/// a false "done". A stuck relay call (dead socket that never times out at the transport layer)
/// must not hang the toggle forever.
const STOP_WAIT_STEPS: u32 = 250;
const STOP_WAIT_STEP: std::time::Duration = std::time::Duration::from_millis(20); // ~5s bound

/// Make going offline mean what it says: not "a bool flipped," but "verified nothing further is
/// being emitted" (SEC-45). Two kinds of network I/O outlive the `set_net_offline` call itself,
/// running on relay handles captured before the flip:
///
///   1. Chunked transfers (upload/download) — cancelled here via the SAME `AtomicBool` convention
///      `cancel_transfer` already uses; `client::blob_upload_with` / `client::download_blob` check
///      it at the next chunk boundary, not mid-chunk.
///   2. `poll`, `cover_tick`'s deposit, and the `PostsRequest` reply loop — no per-item transfer to
///      cancel, so each instead holds a `NetGuard` for as long as it might still touch the wire and
///      re-checks `App::offline` at its own loop boundaries once this has set it.
///
/// This flips every transfer's cancel flag EVERY TICK (not just once up front — see the loop
/// below for why), then WAITS for both (1) and (2) to actually reach quiet before returning `Ok`
/// — "success" is a fact this function has verified, not a promise made in advance and hoped for.
///
/// HONEST LIMIT: a single request already on the wire with no internal chunk boundary — a cover
/// deposit, a `download_post_attachment`/`download_gallery` fetch already started (they take no
/// cancel flag; see the report for why), or the one relay round trip a chunked transfer is
/// blocked on right now — cannot be torn down from this layer. It finishes on its own, normally
/// well under the wait bound below. If the bound is hit anyway (a wedged call that never returns),
/// this returns an error instead of falsely claiming silence; `offline` itself stays SET either
/// way (nothing NEW starts), so a caller that ignores the error has not been lied to about that.
fn stop_for_offline(app: &App) -> Result<(), String> {
    for _ in 0..STOP_WAIT_STEPS {
        // Re-flip EVERY tick, not just once before the loop: `drive_pending_downloads` can still
        // be between its own (racing) offline check and `transfers.insert(..., cancel: false)` —
        // a transfer that lands mid-wait would otherwise carry a cancel flag nobody ever set, and
        // this function would wait out the WHOLE download (many chunk round trips) before timing
        // out, instead of catching it within one tick. Scoped so the lock never spans the sleep.
        {
            let t = app.transfers.lock().unwrap();
            for st in t.values() {
                st.cancel.store(true, Ordering::SeqCst);
            }
        }
        let transfers_quiet = app.transfers.lock().unwrap().values().all(|t| t.state != "active");
        let net_quiet = app.net_active.load(Ordering::SeqCst) == 0;
        if transfers_quiet && net_quiet {
            return Ok(());
        }
        std::thread::sleep(STOP_WAIT_STEP);
    }
    Err("offline is set — nothing new will start — but a network call already in flight (a \
         transfer's current chunk, a poll's current round trip, or a cover deposit) hasn't \
         finished yet; it will complete on its own shortly and emit nothing further after that"
        .into())
}

/// Update a transfer's byte counters (called from the blob progress callback).
fn transfer_progress_step(transfers: &Transfers, tid: u64, done: u64, total: u64) {
    if let Ok(mut m) = transfers.lock() {
        if let Some(t) = m.get_mut(&tid) {
            t.done = done;
            t.total = total;
        }
    }
}

/// Move a transfer to its terminal state (idempotent-safe: sets `finished_at` for pruning).
fn transfer_finish(transfers: &Transfers, tid: u64, state: &'static str, file_id: Option<String>, error: Option<String>) {
    if let Ok(mut m) = transfers.lock() {
        if let Some(t) = m.get_mut(&tid) {
            t.state = state;
            t.file_id = file_id;
            t.error = error;
            t.finished_at = Some(now_secs());
        }
    }
}

#[derive(Serialize)]
struct Me {
    ik: String,
    name: String,
    bio: String,
    /// Own avatar as a `data:image/png;base64,…` URI, or `None` (the UI falls back to initials).
    #[serde(skip_serializing_if = "Option::is_none")]
    avatar: Option<String>,
}
#[derive(Serialize)]
struct Contact {
    ik: String,
    name: String,
    verified: bool,
    /// True when we know this contact is a public CHANNEL (learned from a JoinAccept) — the
    /// contact list shows a broadcast badge. A hint, not a trust anchor.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    channel: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    avatar: Option<String>,
    /// False = a conversation-only peer (you DM them but haven't added them): their self-declared
    /// name/avatar are hidden (shown as a short IK), and the UI offers an "Add to contacts" action.
    /// True = a confirmed contact. Defaults true so nothing regresses for existing contacts.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    conversation_only: bool,
}
/// A contact's self-declared (received) profile — advisory, not identity.
#[derive(Serialize)]
struct PeerProfile {
    name: String,
    bio: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    avatar: Option<String>,
    /// Extra gallery photos (data URIs), ordered — shown as a strip on the profile panel and swiped
    /// in the lightbox after the avatar. Empty unless the contact set a gallery.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    photos: Vec<String>,
}

/// Wrap raw image bytes as a self-contained `data:` URI for an `<img>` in the webview. Detects the
/// format from the magic bytes so both older PNG avatars and newer (larger) JPEG ones render right.
fn image_uri(b: &[u8]) -> String {
    let mime = if b.len() >= 2 && b[0] == 0xFF && b[1] == 0xD8 { "jpeg" } else { "png" };
    format!("data:image/{mime};base64,{}", STANDARD.encode(b))
}
fn avatar_uri(a: &Option<Vec<u8>>) -> Option<String> {
    a.as_ref().map(|b| image_uri(b))
}
/// Gallery photo bytes → data URIs, in order.
fn photos_uris(photos: &[Vec<u8>]) -> Vec<String> {
    photos.iter().map(|b| image_uri(b)).collect()
}
/// One publication for the feed UI — resolved for display (author name, mine flag).
#[derive(Serialize)]
struct Post {
    /// The publication id (hex) — the delete key for own posts.
    id: String,
    /// Author IK as hex, or "me" for our own posts (the UI keys avatars off this).
    author: String,
    /// Display name: the local contact label, "You" for own posts, or a short IK for unknowns.
    author_name: String,
    text: String,
    ts: u64,
    mine: bool,
    /// Whether the author has an avatar — the UI lazy-fetches the bytes ONCE via `peer_avatar` and
    /// caches them, instead of the feed re-encoding every avatar to base64 on every call.
    has_avatar: bool,
    /// Absolute unix-secs a STORY self-destructs at; `None` for a permanent publication. The UI
    /// shows a "disappears in Xh" badge and drops it once passed.
    #[serde(skip_serializing_if = "Option::is_none")]
    expire_at: Option<u64>,
    /// Whether an image is attached. The bytes are NOT inlined here — the UI lazy-fetches them ONCE
    /// via `post_image` and caches them, so the feed list stays tiny and fast to (re)render even
    /// with many image posts (re-encoding every image on every feed call was the freeze).
    has_image: bool,
    /// Metadata for MULTIPLE attachments (images + files), ordered by index — bytes lazy-loaded via
    /// `post_attachments`. Empty for a text-only / single-legacy-image post.
    attachments: Vec<AttMeta>,
}

/// One attachment's metadata for the feed list (no bytes — the UI lazy-loads them).
#[derive(Serialize)]
struct AttMeta {
    index: u32,
    kind: u8, // 0 image, 1 file
    name: String,
    /// Delivery state for the blob-transport path, so the UI shows a spinner / error tile instead of
    /// the media just being missing: "ok" = downloaded (bytes lazy-fetched via `post_attachments`);
    /// "loading" = still fetching its blob (a pending entry exists); "failed" = the fetch gave up.
    status: &'static str,
}
#[derive(Serialize)]
struct Msg {
    from_me: bool,
    text: String,
    ts: u64,
    /// Set on a RECEIVED file line when the sealed file is still on disk — lets a reloaded
    /// "📎 name" bubble offer a working Save. `None` for text and for sent files.
    #[serde(skip_serializing_if = "Option::is_none")]
    file_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    /// A sent message that did not reach the relay this call — durably queued, will
    /// retransmit. The UI shows a pending (clock) marker until a later poll drains the outbox.
    /// Omitted (false) for delivered messages and all received ones.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pending: bool,
    /// Absolute unix-secs at which a DISAPPEARING message self-destructs. Set only on ephemeral
    /// (never-persisted) bubbles; the UI removes the bubble once this passes. `None` for normal
    /// messages and everything loaded from history (history never holds an expiring message).
    #[serde(skip_serializing_if = "Option::is_none")]
    expire_at: Option<u64>,
}

/// One received file for the chat's "Received files" panel.
#[derive(Serialize)]
struct FileMeta {
    file_id: String,
    name: String,
    size: u64,
    ts: u64,
}
/// A received file plus WHO sent it — for the nav-rail "Files" view that spans every contact.
#[derive(Serialize)]
struct FileEntry {
    file_id: String,
    name: String,
    size: u64,
    ts: u64,
    sender: String,
    sender_name: String,
}
/// One item surfaced to the UI from a poll. `kind`: "text"; "file" (a small inline file, done);
/// or "transfer" (a large blob download that just STARTED — `tid` lets the UI track its progress
/// bar and finalize it when `transfer_progress` reports it done).
#[derive(Serialize, Clone)]
struct Incoming {
    kind: &'static str,
    sender: String,
    text: String,
    ts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tid: Option<u64>,
    /// Absolute unix-secs a DISAPPEARING incoming message self-destructs at; the UI removes the
    /// bubble once it passes. `None` for every normal message and non-text event.
    #[serde(skip_serializing_if = "Option::is_none")]
    expire_at: Option<u64>,
}
impl Incoming {
    fn text(sender: [u8; 32], text: String, ts: u64, expire_at: Option<u64>) -> Self {
        Incoming { kind: "text", sender: hex::encode(sender), text, ts, name: None, size: None, file_id: None, tid: None, expire_at }
    }
    fn file(sender: [u8; 32], name: String, size: u64, file_id: String, ts: u64) -> Self {
        Incoming {
            kind: "file",
            sender: hex::encode(sender),
            text: format!("📎 {name}"),
            ts,
            name: Some(name),
            size: Some(size),
            file_id: Some(file_id),
            tid: None,
            expire_at: None,
        }
    }
    fn transfer(sender: [u8; 32], tid: u64, name: String, size: u64, ts: u64) -> Self {
        Incoming {
            kind: "transfer",
            sender: hex::encode(sender),
            text: format!("📎 {name}"),
            ts,
            name: Some(name),
            size: Some(size),
            file_id: None,
            tid: Some(tid),
            expire_at: None,
        }
    }
    /// A §15 route offer from a contact: the `routes` they use to reach the relay you share.
    /// Surfaced for the user to SEE and decide — never applied automatically (trying an offered
    /// route reveals your IP to whoever runs it). `matches` is true when the offer names the
    /// relay you already use (the only case you could act on).
    fn route(sender: [u8; 32], routes: String, matches: bool, ts: u64) -> Self {
        Incoming {
            kind: if matches { "route" } else { "route_other" },
            sender: hex::encode(sender),
            text: routes,
            ts,
            name: None,
            size: None,
            file_id: None,
            tid: None,
            expire_at: None,
        }
    }
    /// A contact published a post. Surfaced live so an open feed can refresh / a badge appear;
    /// it is NOT a chat message (already stored in the feed, never in chat history).
    fn post(sender: [u8; 32], text: String, ts: u64) -> Self {
        Incoming { kind: "post", sender: hex::encode(sender), text, ts, name: None, size: None, file_id: None, tid: None, expire_at: None }
    }
    /// A subscription event: `what` = "joined" (auto-accepted into our channel), "pending" (a
    /// request to approve), or "accepted" (our own request was accepted). The UI toasts/refreshes.
    fn join(sender: [u8; 32], what: &'static str) -> Self {
        Incoming { kind: "join", sender: hex::encode(sender), text: what.to_string(), ts: now_secs(), name: None, size: None, file_id: None, tid: None, expire_at: None }
    }
    /// A contact-consent event: `what` = "request" (someone wants to add you) / "accepted" (they
    /// accepted your request). Drives the requests badge + a contact-list refresh.
    fn contactreq(sender: [u8; 32], what: &'static str) -> Self {
        Incoming { kind: "contactreq", sender: hex::encode(sender), text: what.to_string(), ts: now_secs(), name: None, size: None, file_id: None, tid: None, expire_at: None }
    }
    /// A contact migrated to a new channel: `sender` = their OLD address (already re-pointed),
    /// `text` = their NEW address hex. The UI toasts + prompts a re-verify of the safety number.
    fn migrate(old: [u8; 32], new: [u8; 32]) -> Self {
        Incoming { kind: "migrate", sender: hex::encode(old), text: hex::encode(new), ts: now_secs(), name: None, size: None, file_id: None, tid: None, expire_at: None }
    }
    /// A contact's avatar arrived + was cached; the UI must re-fetch to render it (the peer avatar
    /// is stored but the contact list / open chat header won't show it without a refresh).
    fn avatar(sender: [u8; 32]) -> Self {
        Incoming { kind: "avatar", sender: hex::encode(sender), text: String::new(), ts: now_secs(), name: None, size: None, file_id: None, tid: None, expire_at: None }
    }
    /// A contact's photo GALLERY arrived + was cached; the UI re-fetches to render it (same
    /// "data arrives but the open profile panel isn't told" refresh as `avatar`).
    fn gallery(sender: [u8; 32]) -> Self {
        Incoming { kind: "gallery", sender: hex::encode(sender), text: String::new(), ts: now_secs(), name: None, size: None, file_id: None, tid: None, expire_at: None }
    }
}

/// The immediate reply to `send_file`: a small inline file is `done` (render the final bubble);
/// a large blob upload returns `tid` and `done:false` (render a progress bubble to track).
#[derive(Serialize)]
struct FileSent {
    from_me: bool,
    name: String,
    size: u64,
    ts: u64,
    done: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tid: Option<u64>,
}

/// A snapshot of one transfer for the UI's fast progress poll.
#[derive(Serialize)]
struct TransferInfo {
    tid: u64,
    dir: &'static str,
    sender: String,
    name: String,
    done: u64,
    total: u64,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}
/// A decrypted received file, handed to the webview to trigger a browser download.
#[derive(Serialize)]
struct Exported {
    name: String,
    data: String, // base64
}
#[derive(Serialize)]
struct Net {
    relay_addr: String,
    relay_id: String,
    socks5: String,
    /// The SOCKS5 proxy is a mixnet (Nym) client.
    mixnet: bool,
    /// Live count of relays this account currently multi-homes to (0 = none configured).
    relay_count: usize,
}

/// Build a `Relay` from string config; `None` if the address/id don't parse.
fn parse_relay(addr: &str, relay_id: &str, socks5: &str, routes: &str, mixnet: bool) -> Option<Relay> {
    // A Dest, not a SocketAddr, so a `<b32>.b32.i2p:port` (or any hostname) relay is accepted —
    // it is resolved by the SOCKS bridge (i2pd), never by clearnet DNS here.
    let addr = node::transport::Dest::parse(addr.trim()).ok()?;
    let id = RelayId::parse(relay_id).ok()?;
    let proxy: Option<SocketAddr> = match socks5.trim() {
        "" => None,
        a => a.parse().ok(),
    };
    // An .onion / .i2p relay needs a SOCKS bridge (Tor / i2p router) to resolve it; a mixnet needs
    // its Nym SOCKS client. Without a proxy any of these can never connect — reject up front.
    if proxy.is_none() && (mixnet || client::is_i2p_host(&addr.host) || client::is_onion_host(&addr.host)) {
        return None;
    }
    Some(Relay::configured(addr, id, proxy, routes).with_mixnet(mixnet))
}

/// The account's relay set: its saved `NetSettings` (else the `KARST_RELAY`/`KARST_RELAY_ID`
/// env as a fallback) plus the `extra_relays` sidecar. Empty = offline (no relay configured).
fn build_relays(store: &Store) -> Vec<Relay> {
    let net = store.load_net().unwrap_or_default();
    let (addr, id, socks, routes, mixnet) = if !net.relay_id.trim().is_empty() {
        (net.relay_addr, net.relay_id, net.socks5, net.routes, net.mixnet)
    } else {
        (
            std::env::var("KARST_RELAY").unwrap_or_default(),
            std::env::var("KARST_RELAY_ID").unwrap_or_default(),
            String::new(),
            String::new(),
            false,
        )
    };
    let mut relays = Vec::new();
    if let Some(r) = parse_relay(&addr, &id, &socks, &routes, mixnet) {
        relays.push(r);
        for (a, i) in store.load_extra_relays().unwrap_or_default() {
            if let Some(r) = parse_relay(&a, &i, &socks, "", mixnet) {
                relays.push(r);
            }
        }
    }
    // Seeding lives HERE, in the one function that decides what this account's relay set IS,
    // rather than at each of the callers that change it (unlock, set-relay, add/remove backup) —
    // a new caller would otherwise leave its relay with no credential and no obvious symptom
    // beyond "publish silently skipped it".
    seed_dev_capabilities(store, &relays);
    relays
}

/// Announce our bundle to every relay (best-effort; a dead relay is not fatal).
/// Live proxy indices (channels currently offered), lowest first. Empty if none yet.
///
/// No `active` filter any more: burning a proxy now DELETES its entry and its secret (A6-4), so
/// presence in the registry IS liveness. A flag would have to be backed by keys that still exist,
/// which is exactly what "burned" must no longer mean.
fn active_proxies(store: &Store) -> Vec<u32> {
    let mut v: Vec<u32> = store.load_proxies().into_iter().map(|p| p.index).collect();
    v.sort_unstable();
    v
}

/// The default proxy (lowest active index), provisioning proxy 0 if the account has none. The
/// proxy-identity model NEVER puts the root on the wire, so there must always be ≥1 proxy — a new
/// or pre-proxy account gets one here at first publish/send.
fn default_proxy(store: &Store) -> Result<u32, String> {
    if let Some(i) = active_proxies(store).first().copied() {
        return Ok(i);
    }
    // Propagated, not defaulted. This used to `unwrap_or(0)`, which was harmless only while index
    // 0 was always derivable from the phrase: now a proxy's keys live in its registry entry, so
    // naming an index with no entry gives an identity that cannot be derived at all, and every
    // later call fails somewhere less obvious than here (A6-4).
    store.create_proxy("default", now_secs()).map(|e| e.index).map_err(|e| e.to_string())
}

/// The proxy that reaches a contact — their tag if set, else the default proxy.
fn proxy_for_contact(store: &Store, ik: &[u8; 32]) -> u32 {
    // A contact with no recorded channel falls back to the default one. If provisioning that
    // default fails there is no channel to send on at all, so index 0 is reported rather than
    // guessed: `as_proxy(0)` with no registry entry now fails loudly at the call site.
    match store.contact_proxy(ik) {
        Some(i) => i,
        None => default_proxy(store).unwrap_or(0),
    }
}

/// The relay to reach a contact through: the one their contact code named, when we hold it and a
/// credential for it, else the primary (`client::relays_for_contact`). The counterpart to
/// `proxy_for_contact` — that one picks WHICH identity of ours they see, this one picks WHERE they
/// are actually polling (A10-6). `None` only when no relay is configured at all.
fn relay_for_contact(store: &Store, relays: &[Relay], ik: &[u8; 32]) -> Option<Relay> {
    client::relays_for_contact(store, relays, ik).into_iter().next()
}

/// Write the DEV capability for every configured relay — only when `KARST_DEV_CAP=1` says this
/// is the local demo, and loudly.
///
/// A capability belongs to ONE relay (CRYPTO-24), so a fresh account holds none until it joins a
/// public door (PoW) or imports an invite. The reference DEV relay admits a capability whose
/// secret is published in this repository, and seeding that is what makes the one-machine demo
/// work — which is why this used to happen unconditionally, once per account.
///
/// Doing it per relay automatically would have been strictly worse than the account-wide slot it
/// replaced: `set_net` tries `earn_capability` first, and when that fails (a private, invite-only
/// relay has no open door) an automatic seed would hand that REAL relay a forgeable credential
/// and make `publish_all`'s "no credential → skip, and say so" branch unreachable. That is the
/// `unwrap_or(dev_capability())` shape A8-11 removed from the send path, reintroduced one layer
/// up. The client cannot tell a dev relay from a real one — the policy advertisement does not say
/// — so it must not guess: the operator states it, the same way `KARST_INSECURE_FAST_KDF` is
/// stated rather than inferred.
///
/// A real credential is never overwritten. With the flag on, our own dev id (0xCA..) IS
/// refreshed, so a demo account made on an older build picks up quota changes.
fn seed_dev_capabilities(store: &Store, relays: &[Relay]) {
    if std::env::var("KARST_DEV_CAP").unwrap_or_default() != "1" {
        return;
    }
    for r in relays {
        let held = store.load_capability_for(&r.id).ok();
        if held.map(|c| c.capability_id == [0xCA; 16]).unwrap_or(true) {
            eprintln!(
                "KARST: KARST_DEV_CAP=1 — writing the DEV admission capability for relay {}. \
                 Its secret is public: anyone can forge deposits under it. Local demo only.",
                &r.id.hex()[..16]
            );
            let _ = store.save_capability_for(&r.id, &client::dev_capability());
        }
    }
}

/// Announce presence. ROOT-NEVER-PUBLISHES INVARIANT: publish each ACTIVE PROXY's bundle via
/// `as_proxy`, never the root account — so the permanent identity never appears on a relay. A
/// proxy shares the device's per-relay capabilities (un-namespaced), and `publish_all` presents
/// each relay its own — a relay this account holds no credential for is skipped by that call
/// (creating a bundle slot is metered, so publishing there under another relay's credential would
/// only be rejected).
fn do_publish(store: &Store, relays: &[Relay], offline: bool) {
    // The ONE choke every publish goes through: OFFLINE emits nothing, so no caller can accidentally
    // leak a bundle (some read `s.relays` directly, bypassing `relays_or_empty`).
    if offline || relays.is_empty() {
        return;
    }
    let mut proxies = active_proxies(store);
    if proxies.is_empty() {
        // Nothing to publish under if provisioning fails — say so and return rather than
        // publishing under an index with no registry entry (A6-4).
        match default_proxy(store) {
            Ok(i) => proxies.push(i),
            Err(e) => {
                eprintln!("warning: no channel to publish under: {e}");
                return;
            }
        }
    }
    for pidx in proxies {
        let p = store.as_proxy(pidx);
        // The credential per relay is loaded inside `publish_all`, which skips (loudly) any relay
        // this account holds none for. Never a DEV fallback: its secret is public, so publishing
        // under it would advertise this identity with a forgeable credential (A8-11).
        let _ = client::publish_all(&p, relays, now_secs());
    }
}

fn me_of(store: &Store, id: &str) -> Me {
    let prof = store.load_profile().unwrap_or_default();
    // Proxy-identity model: "your address" is your DEFAULT PROXY's IK, never the root (which has
    // no address on the wire). This is the address others reach you at.
    let ik = default_proxy(store)
        .and_then(|i| store.as_proxy(i).load_account().map_err(|e| e.to_string()))
        .map(|a| hex::encode(a.identity_public()))
        .unwrap_or_else(|_| id.to_string());
    Me { ik, name: prof.name, bio: prof.bio, avatar: avatar_uri(&prof.avatar) }
}

fn parse_ik(hex_str: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(hex_str.trim()).map_err(|e| format!("bad ik hex: {e}"))?;
    b.as_slice().try_into().map_err(|_| "ik must be 32 bytes".to_string())
}

/// Enter an unlocked account: build its relays, announce, and set it active. `decoy` marks a
/// session opened under a decoy password (gates the Security card).
fn enter(app: &App, vault: Vault, id: String, decoy: bool, offline: bool) -> Me {
    // Clear any container from a previous session; the container-backed paths re-set it AFTER
    // calling `enter`, so a normal file-tree unlock correctly leaves it `None`.
    *app.container.lock().unwrap() = None;
    app.offline.store(offline, Ordering::SeqCst);
    let store = vault.account(&id);
    let relays = build_relays(&store);
    // Pick up any inline transfer that was mid-flight when the process last stopped. Its carrier
    // messages were already acked, so the relay will not resend them — without this the chunks
    // were simply gone (Bug E).
    *app.reasm.lock().unwrap() = client::load_reassemblers(&store);
    // Proxy-identity model: an account is reached only through proxies, so ensure one exists
    // (pre-proxy / fresh accounts get proxy 0 here). The root is never published.
    let _ = default_proxy(&store);
    // OFFLINE mode emits nothing — do_publish no-ops when offline (a hidden account defaults to
    // offline so it produces zero network traffic until the user deliberately syncs).
    do_publish(&store, &relays, offline);
    let me = me_of(&store, &id);
    app.reset_transient();
    // A crash mid-download leaves an orphaned partial (its index/history are written only on
    // success). Sweep them now, at unlock BEFORE any download starts, so an in-progress
    // partial is never touched. Any pending downloads left behind are re-driven by `poll`.
    let _ = store.sweep_orphan_files();
    *app.session.lock().unwrap() = Some(Session { vault, id, relays, decoy });
    me
}

/// Does a device vault with at least one account already exist on disk? (Checkable without
/// the password — only the file's PRESENCE, never its contents.) This is also the LAUNCH hook for
/// the dead-man switch: if it is overdue, everything is crypto-erased FIRST, so a lapsed device
/// correctly reports "no account" and lands on the create screen.
#[tauri::command]
fn account_exists() -> bool {
    // Fire the dead-man switch before reporting existence, before any password is entered.
    let _ = Vault::deadman_check(home(), now_secs());
    dir_has_account(&home())
}

/// The vault directory currently in effect (env / pointer / default) — for the UI to prefill the
/// "Vault location" field.
#[tauri::command]
fn vault_dir() -> String {
    home().display().to_string()
}

/// Whether `dir` already holds an account — a side-effect-free check (no pointer write, works
/// in-session) so the unlock/create screen can pick a per-window vault and route (unlock vs create)
/// without touching the global pointer. This is what lets two windows open two DIFFERENT accounts.
#[tauri::command]
fn folder_has_account(dir: String) -> bool {
    dir_has_account(std::path::Path::new(&dir))
}

/// Native folder picker (GTK directory dialog via zenity, present on this desktop). Returns the
/// chosen path, or `None` if cancelled. A real dialog — NOT `<input webkitdirectory>`, which
/// yields no files for an EMPTY folder, the common case when picking a spot for a fresh vault.
#[tauri::command]
fn pick_folder() -> Option<String> {
    let out = std::process::Command::new("zenity")
        .args(["--file-selection", "--directory", "--title=Choose the vault folder"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None; // cancelled or unavailable
    }
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!p.is_empty()).then_some(p)
}

/// Point future launches at `dir` as the vault location: writes the `active-vault` pointer, so the
/// choice STICKS across restarts (unlike an env var you have to re-set). Refuses while a session
/// is open — the vault is only switchable from the welcome/unlock screen, never mid-session.
/// Returns whether `dir` ALREADY holds an account, so the UI can route (unlock vs create) and say
/// which — the exact signal missing when an unexpected leftover vault caused a confusing error.
#[tauri::command]
fn set_vault_dir(app: State<App>, dir: String) -> Result<bool, String> {
    if app.session.lock().unwrap().is_some() {
        return Err("lock the device before changing the vault location".into());
    }
    if std::env::var("KARST_HOME").map(|d| !d.trim().is_empty()).unwrap_or(false) {
        return Err(
            "KARST_HOME is set in the environment and overrides this — unset it to choose a \
             folder here"
                .into(),
        );
    }
    let dir = dir.trim();
    if dir.is_empty() {
        return Err("enter a folder path".into());
    }
    std::fs::create_dir_all(config_base()).map_err(|e| format!("config dir: {e}"))?;
    std::fs::write(active_vault_pointer(), dir).map_err(|e| format!("saving the vault location: {e}"))?;
    Ok(dir_has_account(std::path::Path::new(dir)))
}

/// A fresh 12-word recovery phrase — generated in-memory, NOT yet persisted.
#[tauri::command]
fn generate_phrase() -> Vec<String> {
    client::seed::generate_mnemonic()
        .to_string()
        .split_whitespace()
        .map(String::from)
        .collect()
}

/// Open the vault under `password`, provision the account from `phrase`, enter it. Used for
/// both "create" (fresh phrase) and "restore" (an existing phrase).
#[tauri::command]
fn create_account(app: State<App>, phrase: String, password: String, vault_dir: Option<String>) -> Result<Me, String> {
    if password.is_empty() {
        return Err("set a password".into());
    }
    let m = client::seed::parse_mnemonic(&phrase)?;
    let entropy = client::seed::entropy_of(&m);
    let dir = resolve_home(vault_dir);
    let vault = Vault::unlock(&dir, password.as_bytes()).map_err(|e| {
        // One device = one encrypted vault; creating an account ADDS to it and so needs the
        // device's EXISTING password. A failed unlock when a vault is already present means the
        // typed password doesn't match it — say that plainly instead of a raw crypto error, and
        // point at the way out (pick a different, empty folder for a separate profile).
        if dir_has_account(&dir) {
            "this folder already has an account vault — enter its existing device password to add \
             an account here, or pick an empty folder for a separate profile"
                .to_string()
        } else {
            format!("opening the vault: {e}")
        }
    })?;
    let ik = client::seed::derive(&entropy).account.identity_public();
    let id = hex::encode(ik);
    let mut reg = vault.load_registry().map_err(|e| e.to_string())?;
    if !reg.iter().any(|e| e.id == id) {
        vault.create_account_dir(&id).map_err(|e| format!("creating the account: {e}"))?;
        vault.account(&id).save_seed(&entropy).map_err(|e| format!("writing the root seed: {e}"))?;
        reg.push(AccountEntry { id: id.clone(), label: format!("Account {}", reg.len() + 1), ik });
        vault.save_registry(&reg).map_err(|e| format!("registry: {e}"))?;
    }
    Ok(enter(&app, vault, id, false, false))
}

/// Unlock the existing device, ROUTING by the password's role: the real password opens the real
/// account (and refreshes the dead-man switch); a decoy password opens its decoy compartment; a
/// duress/wipe password crypto-erases everything (already done inside `open`) and reports `WIPED`
/// so the UI returns to the create screen. A wrong password fails closed.
#[tauri::command]
fn unlock(app: State<App>, password: String, vault_dir: Option<String>) -> Result<Me, String> {
    if password.is_empty() {
        return Err("enter your password".into());
    }
    // Fire the dead-man switch for THIS vault before opening it. `account_exists` only ever
    // checked the default `home()`, so a vault opened by an explicit `vault_dir` (a second
    // window, a chosen profile) skipped the switch entirely — it could lapse for months and
    // still open (A3-11). Checked here, every path that opens a vault is covered.
    let base = resolve_home(vault_dir);
    let _ = Vault::deadman_check(&base, now_secs());
    match Vault::open(&base, password.as_bytes()).map_err(|_| "wrong password".to_string())? {
        Opened::Real(vault) => {
            let reg = vault.load_registry().map_err(|e| e.to_string())?;
            let id = reg
                .first()
                .map(|e| e.id.clone())
                .ok_or("no account in this profile — create one")?;
            // The pre-password check reads a PLAINTEXT hint, which anyone with the directory can
            // edit or delete. Now that the vault is open we have the key: reconcile against the
            // SEALED state, which fires the wipe if it is overdue and repairs a tampered hint.
            if vault.deadman_reconcile(now_secs()).unwrap_or(false) {
                return Err("this vault's dead-man switch had lapsed — it has been erased".into());
            }
            let _ = vault.deadman_touch(now_secs()); // a real check-in restarts the countdown
            Ok(enter(&app, vault, id, false, false))
        }
        Opened::Decoy(vault) => {
            let reg = vault.load_registry().map_err(|e| e.to_string())?;
            let id = reg.first().map(|e| e.id.clone()).ok_or("empty decoy")?;
            Ok(enter(&app, vault, id, true, false))
        }
        // The wipe already happened inside `open`; signal the UI to show the fresh create screen.
        Opened::Wipe => Err("WIPED".to_string()),
        // An OPAQUE HIDDEN container: stash its bounded payload for the UI to fetch + show once, and
        // signal it (like WIPED) — this is not a login session, just a secret to display.
        Opened::Hidden(payload) => {
            *app.hidden.lock().unwrap() = Some(payload);
            Err("HIDDEN".to_string())
        }
    }
}

/// Tier-2 REDESIGN (opt-in, NOT yet UI-exposed). Create a deniable container of `size_mb` MB at
/// `dir/container.dat`, provision the real account inside it, and enter a container-backed session.
/// The container replaces the vault's keyslots; the account is sealed under a password-derived key
/// and the whole work dir is snapshotted into the container on `container_flush`.
#[tauri::command]
fn container_create(app: State<App>, phrase: String, password: String, vault_dir: Option<String>, size_mb: u64) -> Result<Me, String> {
    if password.is_empty() {
        return Err("set a password".into());
    }
    let m = client::seed::parse_mnemonic(&phrase)?;
    let entropy = client::seed::entropy_of(&m);
    let base = resolve_home(vault_dir);
    std::fs::create_dir_all(&base).map_err(|e| e.to_string())?;
    let cpath = base.join("container.dat");
    let n = size_mb.saturating_mul(1024 * 1024).max(256 * 1024);
    // Reserve ~1/4 for the (future) hidden tail. NOTE the halving: a region now holds TWO copy
    // slots so a torn save cannot brick it (CRYPTO-13), so the usable payload of a region is
    // about half its declared capacity. The declared figure below is the region size, not what
    // fits in it — a user asking for N MiB of container gets roughly 3N/8 of usable main account.
    let main_cap = n / 4 * 3;
    client::container::Container::create(&cpath, n, password.as_bytes(), main_cap).map_err(|e| e.to_string())?;
    let mut cv = client::container::ContainerVault::open(&cpath, password.as_bytes(), base.join("work"))
        .map_err(|e| e.to_string())?;
    let acct_key = cv.account_key();
    let vault = Vault::adopt(&cv.work_dir, acct_key);
    let ik = client::seed::derive(&entropy).account.identity_public();
    let id = hex::encode(ik);
    let mut reg = vault.load_registry().map_err(|e| e.to_string())?;
    if !reg.iter().any(|e| e.id == id) {
        vault.create_account_dir(&id).map_err(|e| e.to_string())?;
        vault.account(&id).save_seed(&entropy).map_err(|e| e.to_string())?;
        reg.push(AccountEntry { id: id.clone(), label: format!("Account {}", reg.len() + 1), ik });
        vault.save_registry(&reg).map_err(|e| e.to_string())?;
    }
    cv.save().map_err(|e| e.to_string())?; // persist the provisioned account into the container
    let me = enter(&app, vault, id, false, false);
    *app.container.lock().unwrap() = Some(cv);
    Ok(me)
}

/// Tier-2 REDESIGN (opt-in). Open a container-backed account for `password` and enter its session.
/// (Wipe/hidden role handling + a RAM/tmpfs work dir for the hidden account are a later slice.)
#[tauri::command]
fn container_unlock(app: State<App>, password: String, vault_dir: Option<String>) -> Result<Me, String> {
    if password.is_empty() {
        return Err("enter your password".into());
    }
    let base = resolve_home(vault_dir);
    // Route by the password's role: a Wipe password erases the container (reports WIPED); a HIDDEN
    // account is materialized into a RAM/tmpfs work dir so no plaintext files touch the real disk.
    let outcome = client::container::open_container(
        &base.join("container.dat"),
        password.as_bytes(),
        base.join("work"),
        hidden_work_dir(&base),
    )
    // An ordinary open failure collapses to ONE opaque string on purpose: "wrong password" and "no
    // such compartment" must be the same answer, or the error itself proves whether a compartment
    // exists. But two failures here are not about the password at all — the container is locked by
    // another session (A3-8), or it is over the size this build will hold in RAM (A3-9) — and
    // reporting either of those as "wrong password" leaves a user with a working password and no
    // way to find out what is actually wrong. They are surfaced by `ErrorKind`, which leaks
    // nothing: both are properties of the file, observable without any password.
    .map_err(|e| match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::OutOfMemory => e.to_string(),
        _ => "wrong password".to_string(),
    })?;
    let cv = match outcome {
        client::container::Unlocked::Wiped => return Err("WIPED".to_string()),
        client::container::Unlocked::Account(cv) => cv,
    };
    let acct_key = cv.account_key();
    let vault = Vault::adopt(&cv.work_dir, acct_key);
    let reg = vault.load_registry().map_err(|e| e.to_string())?;
    let id = reg.first().map(|e| e.id.clone()).ok_or("no account in this container")?;
    // A hidden account defaults to OFFLINE (emits nothing until deliberately synced).
    let offline = cv.role == client::container::Role::Hidden;
    let me = enter(&app, vault, id, false, offline);
    *app.container.lock().unwrap() = Some(cv);
    Ok(me)
}

/// RAM-backed (tmpfs) work dir for a HIDDEN account, so its plaintext files never touch the real
/// disk. Keyed by the vault base so parallel vaults don't collide.
///
/// `None` = this system cannot prove a RAM-backed store exists, and `open_container` then refuses
/// to open a hidden account. It used to fall back to `base/.hidden-work` — a predictable path on
/// the REAL disk — which silently voided the deniability the container exists for (CRYPTO-02).
fn hidden_work_dir(base: &std::path::Path) -> Option<std::path::PathBuf> {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    base.hash(&mut h);
    // The PID is part of the name on purpose. It used to be derived from the vault path ALONE, so
    // two windows on the same vault shared one directory — and the startup sweep, which deleted
    // every `karst-hid-*`, would wipe the LIVE plaintext work dir of an already-running process,
    // leaving it reading files that had vanished underneath it (A3-7). Per-process names make the
    // sweep able to tell "mine / dead owner" from "someone else's live session".
    client::container::ram_backed_hidden_dir(&format!("{:016x}-p{}", h.finish(), std::process::id()))
}

/// Snapshot the container-backed account's work dir back into the deniable container. Called after
/// mutations (the design's "save after each message"); a no-op when the session is file-tree-backed.
#[tauri::command]
fn container_flush(app: State<App>) -> Result<(), String> {
    let mut g = app.container.lock().unwrap();
    if let Some(cv) = g.as_mut() {
        cv.save().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// True when the current session is backed by a deniable container (so the UI can offer the
/// container-only controls, e.g. adding a hidden account).
#[tauri::command]
fn container_active(app: State<App>) -> bool {
    app.container.lock().unwrap().is_some()
}

/// True when the active session is the HIDDEN container account (so the UI can show the honest
/// "files aren't saved to disk / no bulk media" note).
#[tauri::command]
fn container_hidden(app: State<App>) -> bool {
    app.is_hidden_session()
}

/// Whether the active session is in OFFLINE mode (emits no network traffic).
#[tauri::command]
fn net_offline(app: State<App>) -> bool {
    app.offline.load(Ordering::SeqCst)
}

/// Toggle OFFLINE mode. Going ONLINE announces the account's bundle once (so it becomes reachable).
/// Going OFFLINE does not just flip the flag: it cancels every in-flight transfer and WAITS
/// (`stop_for_offline`) for that plus any guarded background call (`poll`, cover traffic, a
/// PostsRequest reply) to actually quiesce before returning — SEC-45 was this command reporting
/// success while a poll/upload/download already running on a captured relay handle kept emitting
/// after the toggle returned. `async` because the wait can (rarely, see `stop_for_offline`'s doc)
/// take real time; blocking this command's own thread is fine, same as `poll`'s fully-synchronous
/// body already does. For a hidden account this is the deliberate, user-controlled sync window —
/// the rest of the time it emits nothing.
#[tauri::command]
async fn set_net_offline(app: State<'_, App>, offline: bool) -> Result<(), String> {
    app.offline.store(offline, Ordering::SeqCst);
    if offline {
        stop_for_offline(&app)
    } else {
        // Coming online: publish the bundle so the account is reachable this session.
        let (store, relays) = app.snapshot()?;
        do_publish(&store, &relays, app.offline.load(Ordering::SeqCst));
        Ok(())
    }
}

/// Add a HIDDEN account to the open container: mints a FRESH identity + recovery phrase, provisions
/// an empty account for it entirely in RAM, folds it into the container's hidden region, and wipes
/// the RAM build. Returns the 12-word phrase for the user to save (the only way to recover it).
/// Requires an open MAIN container session (uses the ONE held instance — no two-writers hazard).
#[tauri::command]
fn container_add_hidden(app: State<App>, hidden_password: String) -> Result<Vec<String>, String> {
    if hidden_password.trim().is_empty() {
        return Err("choose a hidden password".into());
    }
    let m = client::seed::generate_mnemonic();
    let words: Vec<String> = m.to_string().split_whitespace().map(|s| s.to_string()).collect();
    let entropy = client::seed::entropy_of(&m);
    // The hidden account is BUILT in the clear before being sealed into the container, so this
    // directory holds the seed. It used to fall back to `std::env::temp_dir()` when /dev/shm was
    // missing — putting that seed on the real disk, the same hole already closed for the work dir
    // — and it was named `karst-hidbuild-*`, which the `karst-hid-` sweep never matched, so a
    // crash mid-creation left it behind (A3-5). Now: RAM-backed or refuse, and one naming scheme.
    let build = client::container::ram_backed_hidden_dir(&format!("build-p{}", std::process::id()))
        .ok_or("a hidden account needs a RAM-backed store (tmpfs); none is available on this system")?;
    let mut g = app.container.lock().unwrap();
    let cv = g.as_mut().ok_or("open a container account first")?;
    // Build the empty hidden account in RAM, sealed under the HIDDEN region's key (so its own
    // password opens it — NOT a password-derived key, which would break P3-style aliases), snapshot
    // it, then wipe the plaintext build. `add_hidden` gives us the region key inside the closure.
    let res = cv.add_hidden(hidden_password.as_bytes(), |region_key, max_payload| {
        let _ = std::fs::remove_dir_all(&build);
        std::fs::create_dir_all(&build)?;
        let out = (|| -> std::io::Result<Vec<u8>> {
            let hvault = Vault::adopt(&build, region_key.clone());
            let ik = client::seed::derive(&entropy).account.identity_public();
            let id = hex::encode(ik);
            hvault.create_account_dir(&id)?;
            hvault.account(&id).save_seed(&entropy)?;
            let mut reg = hvault.load_registry()?;
            reg.push(AccountEntry { id: id.clone(), label: "Hidden".into(), ik });
            hvault.save_registry(&reg)?;
            // The REAL usable capacity of the hidden region, threaded in from `add_hidden`.
            // Passing `usize::MAX` here would reopen SEC-35 on this exact path: the snapshot is
            // read into RAM before anything can refuse it, so the ceiling has to bind the READ.
            client::container::snapshot_dir(&build, max_payload)
        })();
        let _ = std::fs::remove_dir_all(&build); // wipe the RAM plaintext regardless of outcome
        out
    });
    res.map_err(|e| e.to_string())?;
    Ok(words)
}

/// Add the P3 "cover" password — a second password for the MAIN account that is SAFE TO REVEAL under
/// duress (its key can't read the slot directory, so it can't detect the hidden account). Reveal THIS,
/// never your main password, if forced to unlock.
#[tauri::command]
fn container_add_cover(app: State<App>, password: String) -> Result<(), String> {
    if password.trim().is_empty() {
        return Err("choose a cover password".into());
    }
    let mut g = app.container.lock().unwrap();
    let cv = g.as_mut().ok_or("open a container account first")?;
    cv.add_blind(password.as_bytes()).map_err(|e| e.to_string())
}

/// Add a wipe/duress password to the container: entering it crypto-erases the WHOLE container.
#[tauri::command]
fn container_add_wipe(app: State<App>, password: String) -> Result<(), String> {
    if password.trim().is_empty() {
        return Err("choose a wipe password".into());
    }
    let mut g = app.container.lock().unwrap();
    let cv = g.as_mut().ok_or("open a container account first")?;
    cv.add_wipe(password.as_bytes()).map_err(|e| e.to_string())
}

/// Fetch + CLEAR the opaque hidden container's payload after an unlock entered its password.
#[tauri::command]
fn hidden_payload(app: State<App>) -> Result<String, String> {
    let p = app.hidden.lock().unwrap().take().ok_or("no hidden container open")?;
    Ok(STANDARD.encode(&p))
}

/// Create/replace the OPAQUE HIDDEN container (a real-session action): store `text` under a separate
/// `hidden_password`. Its existence is undetectable to the outer (real/decoy) password. Bounded.
#[tauri::command]
fn set_hidden_container(app: State<App>, hidden_password: String, text: String) -> Result<(), String> {
    if hidden_password.trim().is_empty() {
        return Err("choose a hidden password".into());
    }
    let g = app.session.lock().unwrap();
    let s = g.as_ref().ok_or("locked")?;
    if s.decoy {
        return Err("not available in a decoy session".into());
    }
    s.vault
        .set_hidden(hidden_password.as_bytes(), text.as_bytes())
        .map_err(|e| e.to_string())
}

/// Configure the primary relay for the active account, persist it, re-announce.
#[tauri::command]
fn set_relay(app: State<App>, addr: String, relay_id: String, socks5: String, mixnet: bool) -> Result<(), String> {
    let relay = parse_relay(&addr, &relay_id, &socks5, "", mixnet).ok_or("invalid relay address, relay-id, or a .onion/.i2p/mixnet relay with no SOCKS bridge")?;
    let mut g = app.session.lock().unwrap();
    let s = g.as_mut().ok_or("locked")?;
    let store = s.vault.account(&s.id);
    store
        .save_net(&NetSettings {
            relay_addr: addr.trim().to_string(),
            relay_id: relay_id.trim().to_string(),
            socks5: socks5.trim().to_string(),
            routes: String::new(),
            mixnet,
        })
        .map_err(|e| e.to_string())?;
    // Best-effort: earn a send capability from a PUBLIC relay's open/PoW door (mirrors
    // `karst join`). A fresh account only carries a dev capability, which such a relay accepts
    // on publish but REJECTS on send; earning here is what makes "configure the relay in the UI"
    // actually unlock sending. A private, invite-only relay has no open door, so `join` fails —
    // that path is not fatal (the operator's invite is imported instead) and the dev/imported
    // capability is left untouched.
    // SEC-45: this hits the relay directly (a PoW admission round trip), NOT through
    // `relays_or_empty` — the ONE choke every other deposit relies on — so it must check `offline`
    // itself or Offline would still emit a request the moment a relay is configured.
    if !app.offline.load(Ordering::SeqCst) {
        if let Ok(cap) = client::earn_capability(&relay) {
            let _ = store.save_capability_for(&relay.id, &cap);
        }
    }
    s.relays = build_relays(&store);
    do_publish(&store, &s.relays, app.offline.load(Ordering::SeqCst));
    Ok(())
}

/// The account's configured BACKUP (secondary) relays — the multi-homing set beyond the
/// primary, as `(addr, relay_id)`. The core already receives across the whole set; this exposes
/// the list so the desktop can manage it.
#[tauri::command]
fn extra_relays(app: State<App>) -> Result<Vec<(String, String)>, String> {
    let (store, _) = app.snapshot()?;
    Ok(store.load_extra_relays().unwrap_or_default())
}

/// Add a backup relay: validate it, append to the sidecar (deduped by address), rebuild the live
/// relay set, and re-announce the bundle to the whole set so a contact can first-contact you via
/// the new relay too. A malformed entry is rejected up front (never persisted).
#[tauri::command]
fn add_extra_relay(app: State<App>, addr: String, relay_id: String) -> Result<(), String> {
    // Validate shape only; the real proxy/mixnet is inherited from the primary at build time.
    parse_relay(&addr, &relay_id, "127.0.0.1:1", "", false).ok_or("invalid relay address or relay-id")?;
    let mut g = app.session.lock().unwrap();
    let s = g.as_mut().ok_or("locked")?;
    let store = s.vault.account(&s.id);
    let (a, i) = (addr.trim().to_string(), relay_id.trim().to_string());
    let mut list = store.load_extra_relays().unwrap_or_default();
    if !list.iter().any(|(x, _)| x == &a) {
        list.push((a, i));
        store.save_extra_relays(&list).map_err(|e| e.to_string())?;
    }
    s.relays = build_relays(&store);
    do_publish(&store, &s.relays, app.offline.load(Ordering::SeqCst));
    Ok(())
}

/// Remove a backup relay by address, rebuild the live relay set. Sending/publishing stay on the
/// primary, so removing a backup only stops receiving through it.
#[tauri::command]
fn remove_extra_relay(app: State<App>, addr: String) -> Result<(), String> {
    let mut g = app.session.lock().unwrap();
    let s = g.as_mut().ok_or("locked")?;
    let store = s.vault.account(&s.id);
    let a = addr.trim();
    let list: Vec<(String, String)> = store
        .load_extra_relays()
        .unwrap_or_default()
        .into_iter()
        .filter(|(x, _)| x != a)
        .collect();
    store.save_extra_relays(&list).map_err(|e| e.to_string())?;
    s.relays = build_relays(&store);
    Ok(())
}

/// Import a relay invite (the `invite.json` a private, invite-only relay hands out — a
/// serialized capability) so this account may DEPOSIT there. A fresh account carries only a
/// dev capability, which such a relay accepts on publish but REJECTS on send; importing the
/// invite is what unlocks sending. Re-announces under the new capability. Mirrors the CLI's
/// `karst import-cap`.
#[tauri::command]
fn import_capability(app: State<App>, invite_json: String) -> Result<(), String> {
    // Type inferred from `save_capability_for` — no need to name the capability type here.
    let cap = serde_json::from_str(invite_json.trim()).map_err(|e| format!("parsing invite: {e}"))?;
    let (store, relays) = app.snapshot()?;
    // An invite is a bare capability: the relay writes exactly the serialized credential, with no
    // relay-id inside it (CRYPTO-25's file format), so the only thing that can say WHICH relay it
    // is for is the relay this account is currently configured against. It is stored against that
    // one and presented nowhere else (CRYPTO-24).
    let primary = relays.first().ok_or("configure this account's relay before importing its invite")?;
    store.save_capability_for(&primary.id, &cap).map_err(|e| format!("writing capability: {e}"))?;
    do_publish(&store, &relays, app.offline.load(Ordering::SeqCst));
    Ok(())
}

/// The active account's saved relay settings + the live relay count (for the settings form
/// and the chat Details "Network route" panel).
#[tauri::command]
fn net(app: State<App>) -> Result<Net, String> {
    let (store, relays) = app.snapshot()?;
    let n = store.load_net().unwrap_or_default();
    Ok(Net { relay_addr: n.relay_addr, relay_id: n.relay_id, socks5: n.socks5, mixnet: n.mixnet, relay_count: relays.len() })
}

/// One line for the Network panel: a relay's address, the carrier it actually rides (derived from
/// the live `Relay`, so a .onion reads "Tor", a mixnet relay reads "mixnet", etc.), and whether it
/// is the primary. Ordered like the live relay set, so it lines up with the reachability array.
#[derive(Serialize)]
struct RelayLine {
    addr: String,
    carrier: String,
    primary: bool,
}

#[tauri::command]
fn relay_lines(app: State<App>) -> Result<Vec<RelayLine>, String> {
    let g = app.session.lock().unwrap();
    let s = g.as_ref().ok_or("locked")?;
    Ok(s.relays
        .iter()
        .enumerate()
        .map(|(i, r)| RelayLine {
            addr: format!("{}:{}", r.addr.host, r.addr.port),
            carrier: r.carrier().label().to_string(),
            primary: i == 0,
        })
        .collect())
}

/// The 60-digit safety number for the conversation with `peer_ik` — the SHA-512 fingerprint of
/// the sorted pair {my IK, their IK}. Symmetric and identical across clients (CLI/egui/desktop),
/// so two people can read it aloud out of band to catch an IK swap. Uses the STORED contact IK
/// on purpose — that's exactly the key OOB verification is meant to check.
#[tauri::command]
fn safety_number(app: State<App>, peer_ik: String) -> Result<String, String> {
    let peer = parse_ik(&peer_ik)?;
    let (store, _) = app.snapshot()?;
    // The safety number verifies the identity the contact ACTUALLY talks to — our PROXY for them,
    // not the root — so both sides compute the same pair.
    let own = store
        .as_proxy(proxy_for_contact(&store, &peer))
        .load_account()
        .map_err(|e| format!("loading account: {e}"))?
        .identity_public();
    Ok(node::safety::safety_number(&own, &peer))
}

#[tauri::command]
fn lock(app: State<App>) -> Result<(), String> {
    // Persist a container-backed account before locking (no-op for the file-tree path), then drop
    // it. For a HIDDEN account the work dir is RAM/tmpfs plaintext and is deleted on lock — but
    // ONLY after the save actually succeeded. It used to discard the save error and delete
    // anyway, which threw away every message received since the last successful save (A3-6).
    // On failure we keep the session OPEN so the user still has their data and can retry.
    let mut guard = app.container.lock().unwrap();
    if let Some(cv) = guard.as_mut() {
        if let Err(e) = cv.save_and_release() {
            // Leave the vault and the session exactly as they were: still open, data still there.
            return Err(format!(
                "could not save this session into the container: {e}. NOT locking — the unsaved \
                 data exists only in this session. Fix the problem and lock again."
            ));
        }
    }
    *guard = None;
    drop(guard);
    app.reset_transient();
    *app.session.lock().unwrap() = None;
    Ok(())
}

/// One entry for the account switcher.
#[derive(Serialize)]
struct AccountInfo {
    id: String,
    label: String,
    ik: String,
    active: bool,
}

/// Every account in this device vault, with the active one flagged — for the switcher.
#[tauri::command]
fn accounts(app: State<App>) -> Result<Vec<AccountInfo>, String> {
    let (vault, id, _) = app.session_parts()?;
    let reg = vault.load_registry().map_err(|e| e.to_string())?;
    Ok(reg
        .into_iter()
        .map(|e| AccountInfo { active: e.id == id, ik: hex::encode(e.ik), id: e.id, label: e.label })
        .collect())
}

/// Switch the active account within the already-unlocked vault (no password needed — the vault
/// is open). Re-announces the new account's bundle and resets per-account transient state.
#[tauri::command]
fn switch_account(app: State<App>, id: String) -> Result<Me, String> {
    let (vault, cur, _) = app.session_parts()?;
    if id == cur {
        return Ok(me_of(&vault.account(&id), &id));
    }
    let reg = vault.load_registry().map_err(|e| e.to_string())?;
    if !reg.iter().any(|e| e.id == id) {
        return Err("no such account".into());
    }
    // Stay in the same compartment kind (a decoy session switches among decoy accounts only).
    let decoy = app.session.lock().unwrap().as_ref().map(|s| s.decoy).unwrap_or(false);
    Ok(enter(&app, vault, id, decoy, false))
}

/// The active account's 12-word recovery phrase, gated behind a fresh password check (the vault
/// is already open, but re-showing the SECRET must re-verify the human present). Derived from the
/// stored root entropy — nothing new is generated or written.
#[tauri::command]
fn show_phrase(app: State<App>, password: String) -> Result<String, String> {
    let (vault, id, _) = app.session_parts()?;
    // Re-verify against the CURRENT session's compartment WITHOUT routing or wiping: `rederive`
    // re-keys the same compartment from the entered password, so a wrong password just fails to
    // decrypt the seed below (and a wipe password can't erase anything from here).
    let v = vault.rederive(password.as_bytes()).map_err(|_| "wrong password".to_string())?;
    let entropy = v.account(&id).load_entropy().map_err(|_| "wrong password".to_string())?;
    Ok(client::seed::mnemonic_of_entropy(&entropy).to_string())
}

/// The real-session vault, or an error if the session is a DECOY (password/dead-man management is
/// refused there so a coerced decoy login can neither see nor disarm the real account's defenses).
fn real_session(app: &App) -> Result<Vault, String> {
    let g = app.session.lock().unwrap();
    let s = g.as_ref().ok_or("locked — unlock first")?;
    if s.decoy {
        return Err("not available in this session".into());
    }
    Ok(s.vault.clone())
}

/// Snapshot for the Security card: whether this is a decoy session (hide the card), which extra
/// passwords are set, and the dead-man state. Safe to call in any session.
#[derive(Serialize)]
struct SecurityState {
    decoy_session: bool,
    has_decoy: bool,
    has_wipe: bool,
    deadman_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    deadman_remaining: Option<u64>,
}

#[tauri::command]
fn security_state(app: State<App>) -> Result<SecurityState, String> {
    let g = app.session.lock().unwrap();
    let s = g.as_ref().ok_or("locked — unlock first")?;
    if s.decoy {
        return Ok(SecurityState {
            decoy_session: true,
            has_decoy: false,
            has_wipe: false,
            deadman_secs: 0,
            deadman_remaining: None,
        });
    }
    let extras = s.vault.extra_passwords().map_err(|e| e.to_string())?;
    let dm = s.vault.deadman();
    Ok(SecurityState {
        decoy_session: false,
        has_decoy: extras.contains(&ExtraPassword::Decoy),
        has_wipe: extras.contains(&ExtraPassword::Wipe),
        deadman_secs: dm.interval_secs,
        deadman_remaining: dm.remaining(now_secs()),
    })
}

/// Add a decoy password (opens a fresh empty account under coercion). Real session only.
#[tauri::command]
fn add_decoy_password(app: State<App>, password: String) -> Result<(), String> {
    real_session(&app)?.add_decoy(password.as_bytes()).map_err(|e| e.to_string())
}

/// Add a duress/wipe password (crypto-erases everything on entry). Real session only.
#[tauri::command]
fn add_wipe_password(app: State<App>, password: String) -> Result<(), String> {
    real_session(&app)?.add_wipe(password.as_bytes()).map_err(|e| e.to_string())
}

/// Remove a configured extra password (decoy or wipe) by entering it. Real session only.
#[tauri::command]
fn remove_extra_password(app: State<App>, password: String) -> Result<(), String> {
    real_session(&app)?.remove_extra(password.as_bytes()).map_err(|e| e.to_string())
}

/// Arm (secs > 0) or disarm (0) the dead-man switch. Real session only.
#[tauri::command]
fn set_deadman(app: State<App>, secs: u64) -> Result<(), String> {
    real_session(&app)?.set_deadman(secs, now_secs()).map_err(|e| e.to_string())
}

/// Channel state for the Settings toggle + contact badges.
#[derive(Serialize)]
struct ChannelState {
    enabled: bool,
    subscribers: usize,
    pending: usize,
}

/// The active account's channel state (mode + subscriber/pending counts).
#[tauri::command]
fn channel_state(app: State<App>) -> Result<ChannelState, String> {
    let (store, _) = app.snapshot()?;
    Ok(ChannelState {
        enabled: store.load_channel().enabled,
        subscribers: store.load_subscribers().len(),
        pending: store.load_pending_subs().len(),
    })
}

/// Turn channel mode ON/OFF. SECURITY-CRITICAL: real session only, and it RE-VERIFIES the device
/// password (channel mode auto-accepts subscribers and marks the account public, so it must be a
/// deliberate, authenticated act — never a stray click or anything the network can trigger). This
/// command is the SOLE writer of the channel flag (`store.save_channel`); no receive path calls it.
#[tauri::command]
fn set_channel_mode(app: State<App>, password: String, enable: bool) -> Result<ChannelState, String> {
    let vault = real_session(&app)?;
    // Re-derive from the entered password and require the REAL keyslot — a decoy/wipe/wrong
    // password must not flip the mode.
    match Vault::open(home(), password.as_bytes()).map_err(|_| "wrong password".to_string())? {
        Opened::Real(_) => {}
        _ => return Err("wrong password".into()),
    }
    let id = app.session.lock().unwrap().as_ref().map(|s| s.id.clone()).unwrap_or_default();
    let store = vault.account(&id);
    store
        .save_channel(&client::store::ChannelConfig { enabled: enable })
        .map_err(|e| format!("saving channel mode: {e}"))?;
    channel_state(app)
}

/// Ask to subscribe to a contact's posts (send a join request). A channel auto-accepts; a private
/// account queues it for the owner to approve.
#[tauri::command]
fn subscribe(app: State<App>, peer_ik: String) -> Result<(), String> {
    let peer = parse_ik(&peer_ik)?;
    let (store, relays) = app.snapshot()?;
    let relay = relay_for_contact(&store, &relays, &peer).ok_or("no relay configured")?;
    let ps = store.as_proxy(proxy_for_contact(&store, &peer));
    client::send_join_request(&ps, &relay, &peer, now_secs())
}

/// Pending join requests (IK + resolved name) awaiting manual approval on a private account.
#[tauri::command]
fn pending_subscribers(app: State<App>) -> Result<Vec<Contact>, String> {
    let (store, _) = app.snapshot()?;
    let contacts = store.load_contacts().unwrap_or_default();
    let profiles = store.load_peer_profiles().unwrap_or_default();
    Ok(store
        .load_pending_subs()
        .into_iter()
        .map(|ik| Contact {
            avatar: profiles.get(&ik).and_then(|p| avatar_uri(&p.avatar)),
            name: contact_display_name(
                &contacts.iter().find(|c| c.ik == ik).map(|c| c.name.clone()).unwrap_or_default(),
                &ik,
                &profiles,
            ),
            ik: hex::encode(ik),
            verified: contacts.iter().find(|c| c.ik == ik).map(|c| c.verified).unwrap_or(false),
            channel: false,
            conversation_only: false,
        })
        .collect())
}

/// Approve a pending subscriber: move them into subscribers + tell them (JoinAccept).
#[tauri::command]
fn approve_subscriber(app: State<App>, peer_ik: String) -> Result<(), String> {
    let peer = parse_ik(&peer_ik)?;
    let (store, relays) = app.snapshot()?;
    store.add_subscriber(peer, now_secs()).map_err(|e| e.to_string())?;
    store.remove_pending_sub(peer).map_err(|e| e.to_string())?;
    if let Some(relay) = relay_for_contact(&store, &relays, &peer) {
        let is_channel = store.load_channel().enabled;
        let ps = store.as_proxy(proxy_for_contact(&store, &peer));
        let _ = client::send_join_accept(&ps, &relay, &peer, is_channel, now_secs());
    }
    Ok(())
}

/// Reject a pending subscriber (silent — no message sent, to avoid confirming you to them).
#[tauri::command]
fn reject_subscriber(app: State<App>, peer_ik: String) -> Result<(), String> {
    let peer = parse_ik(&peer_ik)?;
    let (store, _) = app.snapshot()?;
    store.remove_pending_sub(peer).map_err(|e| e.to_string())
}

/// Reconnect with a contact: FORGET the session (across every proxy) so the next message re-runs
/// the handshake. Recovery for a SPLIT session — two people who each messaged/posted first, before
/// either received, on a build before the simultaneous-first-contact fix, end up unable to decrypt
/// each other. Both sides press Reconnect, then send anything, and a single coherent session
/// re-forms. Returns whether any stale session was cleared. History/feed are untouched.
#[tauri::command]
fn reconnect_peer(app: State<App>, peer_ik: String) -> Result<bool, String> {
    let peer = parse_ik(&peer_ik)?;
    let (root, relays) = app.snapshot()?;
    let mut cleared = false;
    for pidx in active_proxies(&root) {
        let ps = root.as_proxy(pidx);
        // Hold the sessions flock across load→forget→save. Without it a concurrent poll — which
        // loads sessions, receives, and re-saves under the SAME lock every few seconds — races us
        // and re-writes its stale in-memory copy on top of our clear, resurrecting the dead
        // session (exactly why the first Reconnect looked like a no-op). The lock serializes us
        // against the poll so the clear sticks.
        let _lock = ps.lock_sessions().map_err(|e| format!("locking sessions: {e}"))?;
        let mut st = ps.load_sessions().map_err(|e| format!("loading sessions: {e}"))?;
        if st.forget_peer(&peer) {
            ps.save_sessions(&st).map_err(|e| format!("saving sessions: {e}"))?;
            cleared = true;
        }
    }
    // Re-handshake immediately so the user need not send by hand: a fresh Profile opener re-runs
    // PQXDH (send_session connects when no session is held). The peer accepts it — a plain first
    // contact if they also reconnected, or into their inbound_sessions if they still hold their old
    // outbound (the simultaneous-first-contact path). Both sides pressing Reconnect thus heals both
    // directions with no manual message. Best-effort: a dead relay just defers it to the next send.
    if cleared {
        if let Some(relay) = relay_for_contact(&root, &relays, &peer) {
            let ps = root.as_proxy(proxy_for_contact(&root, &peer));
            // A conversation-only peer must NOT receive your profile — send an EMPTY opener (it still
            // re-runs PQXDH to heal the session). A confirmed contact gets your real profile.
            let (n, b) = if root.is_confirmed_contact(&peer).unwrap_or(false) {
                let prof = root.load_profile().unwrap_or_default();
                (prof.name, prof.bio)
            } else {
                (String::new(), String::new())
            };
            let _ = client::send_profile(&ps, &relay, &peer, &n, &b, now_secs());
        }
    }
    Ok(cleared)
}

// ----- Connection proxies (proxy-identity model): disposable channels -----

/// One proxy for the UI: its HD index, label, active flag, and its derived address (IK hex) — the
/// address a contact uses to reach you through this channel.
#[derive(Serialize)]
struct Proxy {
    index: u32,
    label: String,
    created_at: u64,
    /// The proxy's derived identity key, hex — the disposable address for this channel.
    ik: String,
}

fn proxy_of(store: &Store, e: &client::store::ProxyEntry) -> Proxy {
    let ik = store
        .proxy_identity(e.index)
        .map(|d| hex::encode(d.account.identity_public()))
        .unwrap_or_default();
    Proxy { index: e.index, label: e.label.clone(), created_at: e.created_at, ik }
}

/// Every connection proxy (active + burned), newest first.
#[tauri::command]
fn proxies(app: State<App>) -> Result<Vec<Proxy>, String> {
    let (store, _) = app.snapshot()?;
    let mut list: Vec<Proxy> = store.load_proxies().iter().map(|e| proxy_of(&store, e)).collect();
    list.sort_by_key(|p| std::cmp::Reverse(p.index));
    Ok(list)
}

/// Mint a new disposable proxy (a channel you hand out); returns it (with its derived address).
#[tauri::command]
fn create_proxy(app: State<App>, label: String) -> Result<Proxy, String> {
    let (store, relays) = app.snapshot()?;
    let e = store.create_proxy(label.trim(), now_secs()).map_err(|e| format!("creating proxy: {e}"))?;
    // Announce the new channel's bundle to the relay NOW, so a contact can open a session to it
    // immediately. Without this the channel is unreachable ("bundle not published") until the next
    // unlock re-runs do_publish — the exact "send failed: bundle not published" you hit.
    let np = store.as_proxy(e.index);
    let _ = client::publish_all(&np, &relays, now_secs());
    Ok(proxy_of(&store, &e))
}

/// Burn a proxy: stop offering it (its contacts can no longer be reached through it). NOT
/// reversible — the entry and its secret are deleted outright (#207, A6-4), so no in-flight mail
/// still addressed to it can ever be decrypted again once it's gone; see `Store::burn_proxy`.
#[tauri::command]
fn burn_proxy(app: State<App>, index: u32) -> Result<(), String> {
    let (store, _) = app.snapshot()?;
    // Refuse to burn the LAST active channel: an account must always have ≥1, and leaving zero made
    // the next `default_proxy()` silently mint a replacement — the surprise extra channel. Create
    // another channel first (and migrate contacts onto it), then burn this one.
    let active = active_proxies(&store);
    if active == [index] {
        return Err("this is your only active channel — create another one first, then burn this".into());
    }
    // Burn now DESTROYS: the entry, its secret, and the proxy's namespaced network state go, so
    // the identity cannot be reproduced by anyone — including the holder of the recovery phrase.
    // That is the whole point of A6-4, and it is why this is not undoable. `Store::burn_proxy`
    // also refuses outright (CRYPTO-27) while this proxy still has anything undelivered queued in
    // its outbox — that error surfaces to the user here verbatim, telling them to retry the send
    // (or wait for the relay) before burning.
    store.burn_proxy(index).map_err(|e| e.to_string())
}

/// Contacts currently reached through proxy `index` — the migration picker's default set.
#[tauri::command]
fn contacts_on_proxy(app: State<App>, index: u32) -> Result<Vec<Contact>, String> {
    let (store, _) = app.snapshot()?;
    let profiles = store.load_peer_profiles().unwrap_or_default();
    let channels = store.load_channel_peers();
    let dflt = default_proxy(&store).map_err(|e| e.to_string())?;
    Ok(store
        .load_contacts()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|c| store.contact_proxy(&c.ik).unwrap_or(dflt) == index)
        .map(|c| Contact {
            avatar: profiles.get(&c.ik).and_then(|p| avatar_uri(&p.avatar)),
            channel: channels.contains(&c.ik),
            ik: hex::encode(c.ik),
            name: c.name,
            verified: c.verified,
            conversation_only: false,
        })
        .collect())
}

/// Migrate CHOSEN contacts off proxy `old_index` onto a FRESH channel, keeping continuity: mint +
/// publish the new channel, tell each chosen contact over the OLD (authenticated) session to move
/// to it, and re-tag them locally. The unchosen (e.g. a spammer/attacker) stay on the old channel,
/// which you can then burn — they never learn the new address. Returns the new channel.
///
/// CRYPTO-27: a contact is re-tagged onto the new proxy ONLY when `send_channel_migrate` reports
/// `Ok(true)` (reached the relay this call). If it comes back `Ok(false)` (durably queued, relay
/// down) or `Err`, the contact is left on `old_index` — the migration message is still sitting in
/// the old proxy's outbox and a later flush/poll can still deliver it; re-tagging early would make
/// the UI show the contact as "migrated" while the one message that actually tells THEM to move
/// was never sent. `Store::burn_proxy` separately refuses to burn `old_index` while that outbox is
/// non-empty, so the un-migrated contact cannot be stranded by an immediate burn either — but
/// skipping the re-tag here is what keeps the contact LIST honest about who has actually moved.
#[tauri::command]
fn migrate_channel(app: State<App>, old_index: u32, contacts: Vec<String>, new_label: String) -> Result<Proxy, String> {
    let (store, relays) = app.snapshot()?;
    let relay = relays.first().cloned().ok_or("no relay configured")?;
    // Mint + publish the new channel so contacts can open a session to it.
    let new_e = store.create_proxy(new_label.trim(), now_secs()).map_err(|e| format!("creating channel: {e}"))?;
    let np = store.as_proxy(new_e.index);
    let _ = client::publish_all(&np, &relays, now_secs());
    let new_ik = np.load_account().map_err(|e| e.to_string())?.identity_public();
    // Over the OLD channel's authenticated session, tell each chosen contact to move; re-tag locally
    // ONLY once that message is confirmed to have reached the relay (see the doc comment above).
    let old = store.as_proxy(old_index);
    for hex_ik in &contacts {
        if let Ok(peer) = parse_ik(hex_ik) {
            match client::send_channel_migrate(&old, &relay, &peer, new_ik, now_secs()) {
                Ok(true) => {
                    let _ = store.set_contact_proxy(peer, new_e.index);
                }
                Ok(false) => eprintln!(
                    "warning: channel migration to {hex_ik} is queued, not yet delivered — \
                     not re-tagging until it reaches the relay"
                ),
                Err(e) => eprintln!("warning: channel migration to {hex_ik} failed: {e}"),
            }
        }
    }
    Ok(proxy_of(&store, &new_e))
}

// ----- §12 4c discovery: findable-by-code + add-by-code -----

/// Whether discovery is on + the current persistent contact code (local read, no relay).
#[derive(Serialize)]
struct DiscoveryStatus {
    on: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
}

#[tauri::command]
fn discovery_status(app: State<App>) -> Result<DiscoveryStatus, String> {
    let (store, _) = app.snapshot()?;
    // A contact code binds to a PROXY identity (never the root) — operate on the default proxy.
    let dp = store.as_proxy(default_proxy(&store).map_err(|e| e.to_string())?);
    let code = client::discovery_code(&dp)?;
    Ok(DiscoveryStatus { on: code.is_some(), code })
}

/// Turn discovery ON (mint + publish) and return the persistent contact code to share.
#[tauri::command]
fn discovery_on(app: State<App>) -> Result<String, String> {
    let (store, relays) = app.snapshot()?;
    let relay = relays.into_iter().next().ok_or("configure a relay first")?;
    client::discovery_publish(&store.as_proxy(default_proxy(&store)?), &relay, now_secs())
}

/// Rotate the persistent contact code (old one stops resolving); returns the fresh code.
#[tauri::command]
fn discovery_rotate(app: State<App>) -> Result<String, String> {
    let (store, relays) = app.snapshot()?;
    let relay = relays.into_iter().next().ok_or("configure a relay first")?;
    client::discovery_rotate(&store.as_proxy(default_proxy(&store)?), &relay, now_secs())
}

/// Turn discovery OFF: delete the relay record (best-effort) and clear the local key.
#[tauri::command]
fn discovery_off(app: State<App>) -> Result<(), String> {
    let (store, relays) = app.snapshot()?;
    let dp = store.as_proxy(default_proxy(&store).map_err(|e| e.to_string())?);
    match relays.into_iter().next() {
        Some(relay) => {
            client::discovery_off(&dp, &relay)?;
        }
        None => {
            // No relay to delete the record at — still clear the local key so we stop advertising.
            dp.delete_discovery().map_err(|e| format!("clearing discovery key: {e}"))?;
        }
    }
    Ok(())
}

/// Mint an INVITE code to hand to one person: a short-lived discovery row of its own, revocable
/// by you (`revoke_invite`) and lapsing on its own after `INVITE_TTL_SECS`.
#[tauri::command]
fn create_invite(app: State<App>) -> Result<String, String> {
    let (store, relays) = app.snapshot()?;
    let relay = relays.into_iter().next().ok_or("configure a relay first")?;
    client::discovery_one_time(&store.as_proxy(default_proxy(&store)?), &relay, now_secs())
}

/// One outstanding invite for the UI: the code plus when it lapses.
#[derive(Serialize)]
struct InviteView {
    code: String,
    expiry: u64,
}

/// The invites of yours that can still resolve. Local only — no relay is contacted.
#[tauri::command]
fn list_invites(app: State<App>) -> Result<Vec<InviteView>, String> {
    let (store, _) = app.snapshot()?;
    let ps = store.as_proxy(default_proxy(&store)?);
    Ok(client::invites(&ps, now_secs())?
        .into_iter()
        .map(|i| InviteView { code: i.code, expiry: i.expiry })
        .collect())
}

/// Retire an invite: delete its row at the relay, then forget it locally. Errors if the relay
/// could not be reached — the invite is still live in that case and the secret is kept so the
/// user can retry (silently forgetting it would strand a published row).
#[tauri::command]
fn revoke_invite(app: State<App>, code: String) -> Result<bool, String> {
    let (store, relays) = app.snapshot()?;
    let relay = relays.into_iter().next().ok_or("configure a relay first")?;
    let ps = store.as_proxy(default_proxy(&store)?);
    client::revoke_invite(&ps, &relay, code.trim(), now_secs())
}

/// Add a contact by a CONTACT CODE (persistent or invite): resolve it across the relay set (the
/// binding is self-verified — the relay never vouches), then commit the contact in one place
/// (`client::add_contact_by_code`, which also records the relay their code named). Returns the
/// resolved IK hex so the UI can open the chat.
#[tauri::command]
fn add_by_code(app: State<App>, code: String, name: String, via_proxy: Option<u32>) -> Result<String, String> {
    let (store, relays) = app.snapshot()?;
    if relays.is_empty() {
        return Err("configure a relay first".into());
    }
    // The channel of OURS they'll see us on — chosen, else default (never the root).
    let proxy = match via_proxy {
        Some(p) => p,
        None => default_proxy(&store).map_err(|e| e.to_string())?,
    };
    let ik = client::add_contact_by_code(&store, &relays, &code, &name, proxy, now_secs())?;
    Ok(hex::encode(ik))
}

#[tauri::command]
async fn me(app: State<'_, App>) -> Result<Me, String> {
    let (store, _) = app.snapshot()?;
    let id = app.session.lock().unwrap().as_ref().map(|s| s.id.clone()).unwrap_or_default();
    Ok(me_of(&store, &id))
}

/// Set your own display name + bio: save it locally (durable, unconditional — the edit is never
/// lost to a missing/slow relay), preserving any avatar, then broadcast it to your contacts
/// OFF-thread (best-effort — a slow/unreachable relay must never hang the Save or fail it).
#[tauri::command]
fn save_profile(app: State<App>, name: String, bio: String) -> Result<Me, String> {
    let (vault, id, relays) = app.session_parts()?;
    let store = vault.account(&id);
    let mut prof = store.load_profile().unwrap_or_default();
    prof.name = name; // clamped to MAX_PROFILE_NAME/BIO inside save_profile
    prof.bio = bio;
    store.save_profile(&prof).map_err(|e| format!("saving profile: {e}"))?;
    if let (false, Ok(contacts)) = (relays.is_empty(), store.load_contacts()) {
        // (the relay is chosen PER CONTACT below, so the whole set moves into the thread)
        // Only CONFIRMED contacts receive your profile — a conversation-only peer never does.
        let unconfirmed = store.load_unconfirmed().unwrap_or_default();
        let contacts: Vec<_> = contacts.into_iter().filter(|c| !unconfirmed.contains(&c.ik)).collect();
        let (v, aid) = (vault.clone(), id.clone());
        let (n, b) = (prof.name.clone(), prof.bio.clone());
        std::thread::spawn(move || {
            let store = v.account(&aid);
            let now = now_secs();
            for c in contacts {
                // Send each contact your profile AS the proxy they know (never the root identity),
                // THROUGH the relay their contact code named (else the primary).
                let ps = store.as_proxy(proxy_for_contact(&store, &c.ik));
                let Some(relay) = relay_for_contact(&store, &relays, &c.ik) else { continue };
                let _ = client::send_profile(&ps, &relay, &c.ik, &n, &b, now);
            }
        });
    }
    Ok(me_of(&store, &id))
}

/// A contact's SELF-DECLARED profile (name + bio) received over E2E. Advisory only — the trust
/// anchor for who a contact is stays the LOCAL ContactRecord name + verified + safety number, so
/// the UI shows the received bio but must not let this name override the contact's identity.
#[tauri::command]
fn peer_profile(app: State<App>, peer_ik: String) -> Result<PeerProfile, String> {
    let peer = parse_ik(&peer_ik)?;
    let (store, _) = app.snapshot()?;
    // A conversation-only peer's self-declared profile stays HIDDEN (name/bio/avatar) UNLESS they're
    // a confirmed contact OR they have a pending incoming request — the request is the deliberate
    // exception (you must see WHO is asking, and it surfaces on their chat, to decide).
    let show = store.is_confirmed_contact(&peer).unwrap_or(false)
        || store.load_contact_requests().contains(&peer);
    if !show {
        return Ok(PeerProfile { name: String::new(), bio: String::new(), avatar: None, photos: vec![] });
    }
    let p = store.load_peer_profiles().unwrap_or_default().get(&peer).cloned().unwrap_or_default();
    Ok(PeerProfile { name: p.name, bio: p.bio, avatar: avatar_uri(&p.avatar), photos: photos_uris(&p.photos) })
}

/// The name to SHOW for a peer: the user's own label wins (a rename/override); else the peer's
/// SELF-DECLARED profile name (what THEY call themselves, learned if they've reached you); else a
/// short IK. So adding a contact needs no name — you see their chosen name if it's known, an
/// address otherwise, and can always rename.
fn contact_display_name(
    local: &str,
    ik: &[u8; 32],
    profiles: &std::collections::BTreeMap<[u8; 32], client::store::Profile>,
) -> String {
    if !local.trim().is_empty() {
        return local.trim().to_string();
    }
    if let Some(name) = profiles.get(ik).map(|p| p.name.trim()).filter(|n| !n.is_empty()) {
        return name.to_string();
    }
    format!("{}…", hex::encode(&ik[..4]))
}

/// The accounts SUBSCRIBED to us (they receive our posts) — the audience the post picker narrows
/// over. A subscriber's display name uses our local label for them if any, else their profile name,
/// else a short IK.
#[tauri::command]
async fn subscribers(app: State<'_, App>) -> Result<Vec<Contact>, String> {
    let (store, _) = app.snapshot()?;
    let profiles = store.load_peer_profiles().unwrap_or_default();
    let contacts = store.load_contacts().unwrap_or_default();
    Ok(store
        .load_subscribers()
        .into_iter()
        .map(|s| {
            let local = contacts.iter().find(|c| c.ik == s.ik).map(|c| c.name.clone()).unwrap_or_default();
            Contact {
                name: contact_display_name(&local, &s.ik, &profiles),
                ik: hex::encode(s.ik),
                verified: false,
                channel: false,
                avatar: None,
                conversation_only: false,
            }
        })
        .collect())
}

#[tauri::command]
async fn contacts(app: State<'_, App>) -> Result<Vec<Contact>, String> {
    let (store, _) = app.snapshot()?;
    let profiles = store.load_peer_profiles().unwrap_or_default();
    let channels = store.load_channel_peers();
    let unconfirmed = store.load_unconfirmed().unwrap_or_default();
    Ok(store
        .load_contacts()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|c| {
            let convo_only = unconfirmed.contains(&c.ik);
            Contact {
                // A conversation-only peer's self-declared name/avatar stay hidden until you add
                // them — show a bare short IK (unless YOU gave them a local label). Confirmed
                // contacts resolve to their chosen name + avatar as before.
                avatar: if convo_only { None } else { profiles.get(&c.ik).and_then(|p| avatar_uri(&p.avatar)) },
                channel: channels.contains(&c.ik),
                name: if convo_only {
                    contact_display_name(&c.name, &c.ik, &Default::default())
                } else {
                    contact_display_name(&c.name, &c.ik, &profiles)
                },
                ik: hex::encode(c.ik),
                verified: c.verified,
                conversation_only: convo_only,
            }
        })
        .collect())
}

/// Set our avatar from a (frontend-produced, bounded PNG) image and broadcast it to contacts. The
/// webview canvas already re-encodes to a small ≤128px PNG (which also strips EXIF); the client
/// caps the size again on `set_own_avatar`. Fan-out is best-effort, off-thread.
#[tauri::command]
fn set_avatar(app: State<App>, data: String) -> Result<(), String> {
    let bytes = STANDARD.decode(data.trim()).map_err(|e| format!("bad image data: {e}"))?;
    let (store, relays) = app.snapshot()?;
    store.set_own_avatar(Some(bytes.clone())).map_err(|e| e.to_string())?;
    if let Some(relay) = relays.into_iter().next() {
        // Only CONFIRMED contacts get your avatar — a conversation-only peer never sees your profile.
        let unconfirmed = store.load_unconfirmed().unwrap_or_default();
        let contacts: Vec<_> = store
            .load_contacts()
            .unwrap_or_default()
            .into_iter()
            .filter(|c| !unconfirmed.contains(&c.ik))
            .collect();
        std::thread::spawn(move || {
            for c in contacts {
                let ps = store.as_proxy(proxy_for_contact(&store, &c.ik));
                let _ = client::send_avatar(&ps, &relay, &c.ik, &bytes, now_secs());
            }
        });
    }
    Ok(())
}

/// Our own gallery photos (beyond the avatar), as data URIs in order — for the profile UI.
#[tauri::command]
fn gallery(app: State<App>) -> Result<Vec<String>, String> {
    let (store, _) = app.snapshot()?;
    Ok(photos_uris(&store.load_profile().unwrap_or_default().photos))
}

/// Replace our whole gallery from a list of (frontend-produced, bounded JPEG/PNG) base64 images and
/// broadcast it to CONFIRMED contacts as one atomic transfer. Mirrors `set_avatar`: an empty list
/// clears the gallery (a valid transfer). NOT backfilled to a contact confirmed later — same as the
/// avatar. Fan-out is best-effort, off-thread.
#[tauri::command]
fn set_gallery(app: State<App>, data: Vec<String>) -> Result<(), String> {
    let mut photos: Vec<Vec<u8>> = Vec::with_capacity(data.len());
    for d in &data {
        photos.push(STANDARD.decode(d.trim()).map_err(|e| format!("bad image data: {e}"))?);
    }
    photos.truncate(client::content::MAX_GALLERY_PHOTOS);
    let (store, relays) = app.snapshot()?;
    store.set_own_photos(photos.clone()).map_err(|e| e.to_string())?;
    if let Some(relay) = relays.into_iter().next() {
        // Only CONFIRMED contacts get your gallery — a conversation-only peer never sees your profile.
        let unconfirmed = store.load_unconfirmed().unwrap_or_default();
        let contacts: Vec<_> = store
            .load_contacts()
            .unwrap_or_default()
            .into_iter()
            .filter(|c| !unconfirmed.contains(&c.ik))
            .collect();
        // A small gallery fits one mailbox → send it inline (no blob TTL); a larger one rides the
        // per-recipient blob path (same fork as post media). Decided ONCE from the packed size.
        let inline = client::content::gallery_fits_inline(client::content::pack_gallery(now_secs(), &photos).len());
        std::thread::spawn(move || {
            for c in contacts {
                let ps = store.as_proxy(proxy_for_contact(&store, &c.ik));
                let _ = if inline {
                    client::send_gallery(&ps, &relay, &c.ik, &photos, now_secs())
                } else {
                    client::send_gallery_blob(&ps, &relay, &c.ik, &photos, now_secs())
                };
            }
        });
    }
    Ok(())
}

/// Resolve a feed of `FeedRecord`s into display `Post`s (newest first). Own posts (author ==
/// our IK) get "You"/`mine`; contacts get their local label + cached avatar; unknown authors
/// get a short IK. Reads names from contacts.dat and avatars from the peer-profile cache.
/// (author, post_id) → post attachments still being fetched over the blob path: (index, kind, name).
type PendingAttMap = std::collections::HashMap<([u8; 32], [u8; 16]), Vec<(u32, u8, String)>>;

fn feed_to_posts(store: &Store, own: [u8; 32]) -> Vec<Post> {
    let contacts = store.load_contacts().unwrap_or_default();
    let profiles = store.load_peer_profiles().unwrap_or_default();
    let own_has_avatar = store.load_profile().map(|p| p.avatar.is_some()).unwrap_or(false);
    // Decrypt the image sidecar ONCE and keep only the keys: `has_image` is a set lookup, not a
    // per-post sidecar decrypt. (The old code called `feed_image` per post, decrypting the whole
    // sidecar every time — N posts ⇒ N full decrypts per feed load. That was the freeze.)
    let image_keys: std::collections::HashSet<([u8; 32], [u8; 16])> =
        store.load_feed_images().into_keys().collect();
    // Attachment METADATA from a single sidecar decrypt (bytes lazy-loaded per post by the UI).
    let mut atts_map = store.load_feed_attachments();
    // Blob-transport attachments still being fetched — grouped by (author, post_id) so each post can
    // show a "loading" tile (and a K/N counter) for media in flight, not just the media that landed.
    let mut pending_map: PendingAttMap = std::collections::HashMap::new();
    for p in store.list_pending_post_attachments().unwrap_or_default() {
        pending_map.entry((p.sender, p.post_id)).or_default().push((p.index, p.kind, p.name));
    }
    let now = now_secs();
    let mut feed = store.load_feed().unwrap_or_default();
    // Drop expired STORIES (ephemeral posts past their self-destruct time) — never shown.
    feed.retain(|f| f.expire_at.is_none_or(|e| e > now));
    feed.sort_by_key(|f| std::cmp::Reverse(f.ts)); // newest first
    feed.into_iter()
        .map(|r| {
            let mine = r.author == own;
            let (author_name, has_avatar) = if mine {
                ("You".to_string(), own_has_avatar)
            } else {
                let local = contacts.iter().find(|c| c.ik == r.author).map(|c| c.name.clone()).unwrap_or_default();
                let name = contact_display_name(&local, &r.author, &profiles);
                (name, profiles.get(&r.author).is_some_and(|p| p.avatar.is_some()))
            };
            Post {
                id: hex::encode(r.id),
                author: if mine { "me".into() } else { hex::encode(r.author) },
                author_name,
                text: r.text,
                ts: r.ts,
                mine,
                has_avatar,
                expire_at: r.expire_at,
                has_image: image_keys.contains(&(r.author, r.id)),
                attachments: {
                    // Merge landed attachments (ok/failed) with those still fetching (loading), so a
                    // 4-image post shows all four slots — image, spinner, or error — from the moment
                    // its refs arrive, and the UI can render "K of N loaded".
                    let mut v: Vec<AttMeta> = atts_map
                        .remove(&(r.author, r.id))
                        .unwrap_or_default()
                        .into_iter()
                        .map(|a| AttMeta {
                            index: a.index,
                            kind: a.kind,
                            name: a.name,
                            status: if a.failed { "failed" } else { "ok" },
                        })
                        .collect();
                    let have: std::collections::HashSet<u32> = v.iter().map(|a| a.index).collect();
                    for (index, kind, name) in pending_map.remove(&(r.author, r.id)).unwrap_or_default() {
                        if !have.contains(&index) {
                            v.push(AttMeta { index, kind, name, status: "loading" });
                        }
                    }
                    v.sort_by_key(|a| a.index);
                    v
                },
            }
        })
        .collect()
}

/// One attachment resolved for display: its bytes as a data URI (image inline / file download).
#[derive(Serialize)]
struct AttData {
    index: u32,
    kind: u8,
    name: String,
    uri: String,
}

/// A post's attachments (bytes), lazy-loaded + cached by the UI — a single sidecar decrypt per post,
/// only for the posts actually on screen. `author` is "me" for our own posts.
#[tauri::command]
async fn post_attachments(app: State<'_, App>, author: String, id: String) -> Result<Vec<AttData>, String> {
    let (store, _) = app.snapshot()?;
    let ik = if author == "me" {
        store.load_account().map_err(|e| e.to_string())?.identity_public()
    } else {
        parse_ik(&author)?
    };
    let raw = hex::decode(id.trim()).map_err(|e| format!("bad post id: {e}"))?;
    let pid: [u8; 16] = raw.try_into().map_err(|_| "post id must be 16 bytes".to_string())?;
    Ok(store
        .feed_attachments(ik, pid)
        .into_iter()
        // Skip failure markers / any empty entry — they carry no bytes; the UI renders their error
        // tile from the feed's `status`, not from a (would-be empty) data URI.
        .filter(|a| !a.failed && !a.bytes.is_empty())
        .map(|a| {
            let mime = if a.kind == 1 { "application/octet-stream" } else { "image/jpeg" };
            AttData { index: a.index, kind: a.kind, name: a.name, uri: format!("data:{mime};base64,{}", STANDARD.encode(a.bytes)) }
        })
        .collect())
}

/// Save a post FILE attachment to disk via a native save dialog. Returns the chosen path, or None if
/// cancelled. (Images are viewed inline; this is for the file cards.)
#[tauri::command]
fn save_post_attachment(app: State<App>, author: String, id: String, index: u32) -> Result<Option<String>, String> {
    let (store, _) = app.snapshot()?;
    let ik = if author == "me" {
        store.load_account().map_err(|e| e.to_string())?.identity_public()
    } else {
        parse_ik(&author)?
    };
    let raw = hex::decode(id.trim()).map_err(|e| format!("bad post id: {e}"))?;
    let pid: [u8; 16] = raw.try_into().map_err(|_| "post id must be 16 bytes".to_string())?;
    let att = store
        .feed_attachments(ik, pid)
        .into_iter()
        .find(|a| a.index == index)
        .ok_or("attachment not found")?;
    let out = std::process::Command::new("zenity")
        .args([
            "--file-selection",
            "--save",
            "--confirm-overwrite",
            &format!("--filename={}", sanitize_name(&att.name)),
            "--title=Save attachment",
        ])
        .output()
        .map_err(|e| format!("save dialog: {e}"))?;
    if !out.status.success() {
        return Ok(None); // cancelled
    }
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if path.is_empty() {
        return Ok(None);
    }
    std::fs::write(&path, &att.bytes).map_err(|e| format!("writing file: {e}"))?;
    Ok(Some(path))
}

/// Save a RECEIVED file (a chat file transfer) to disk via a NATIVE save dialog. The webview's
/// `<a download>` + blob trick is unreliable in WebKitGTK (Tauri) — it silently does nothing — which
/// is why "I can't save a received file" happened. Streams the decrypted bytes straight to the
/// chosen path (handles large blob files), so nothing large is buffered in the webview. Returns the
/// path, or None if cancelled.
#[tauri::command]
fn save_received_file(app: State<App>, file_id: String) -> Result<Option<String>, String> {
    if app.is_hidden_session() {
        return Err("the hidden account keeps everything inside the container — saving a file to disk would leave a trace".into());
    }
    let (store, _) = app.snapshot()?;
    let name = store.received_file_name(&file_id).map_err(|e| format!("reading file: {e}"))?;
    let out = std::process::Command::new("zenity")
        .args([
            "--file-selection",
            "--save",
            "--confirm-overwrite",
            &format!("--filename={}", sanitize_name(&name)),
            "--title=Save file",
        ])
        .output()
        .map_err(|e| format!("save dialog: {e}"))?;
    if !out.status.success() {
        return Ok(None); // cancelled
    }
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if path.is_empty() {
        return Ok(None);
    }
    store
        .export_received_file(&file_id, std::path::Path::new(&path))
        .map_err(|e| format!("saving file: {e}"))?;
    Ok(Some(path))
}

/// EVERY feed image as {post-id hex -> data URI}, from a SINGLE sidecar decrypt. The feed list
/// itself carries no image bytes (re-encoding every image on every feed load, and re-decrypting the
/// sidecar per post, was the freeze); the UI calls this once when the feed opens (and after new
/// image posts arrive), caches the result, and never re-encodes. Bounded by MAX_FEED_IMAGES.
#[tauri::command]
async fn post_images(app: State<'_, App>) -> Result<std::collections::HashMap<String, String>, String> {
    let (store, _) = app.snapshot()?;
    Ok(store
        .load_feed_images()
        .into_iter()
        .map(|((_author, id), bytes)| {
            (hex::encode(id), format!("data:image/jpeg;base64,{}", STANDARD.encode(bytes)))
        })
        .collect())
}

/// A feed author's avatar as a data URI — lazy-loaded and cached by the UI (same reason as
/// `post_image`). `author` is "me" for us, else a peer IK hex.
#[tauri::command]
async fn peer_avatar(app: State<'_, App>, author: String) -> Result<Option<String>, String> {
    let (store, _) = app.snapshot()?;
    let bytes = if author == "me" {
        store.load_profile().ok().and_then(|p| p.avatar)
    } else {
        let ik = parse_ik(&author)?;
        store.load_peer_profiles().ok().and_then(|m| m.get(&ik).and_then(|p| p.avatar.clone()))
    };
    Ok(avatar_uri(&bytes))
}

/// Publish a text post: store it in OUR feed immediately, then fan it out over the E2E channel
/// (best-effort, off-thread — a slow relay must never hang or fail the publish). `audience` limits
/// visibility: `None`/empty = every contact; otherwise only the listed contact IKs receive it (each
/// gets their own E2E copy, so no one learns the audience). Returns the full feed for the UI.
#[tauri::command]
fn create_post(
    app: State<App>,
    text: String,
    audience: Option<Vec<String>>,
    story: Option<bool>,
    image: Option<String>,
    attachments: Option<Vec<AttachmentIn>>,
) -> Result<Vec<Post>, String> {
    let text = text.trim().to_string();
    // Decode a legacy single image (kept for older callers). New callers pass `attachments`.
    let image_bytes = match image.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(b64) => {
            let bytes = STANDARD.decode(b64).map_err(|e| format!("bad image data: {e}"))?;
            if bytes.len() > client::content::MAX_POST_IMAGE_BYTES {
                return Err(format!("image too large (> {} KiB)", client::content::MAX_POST_IMAGE_BYTES / 1024));
            }
            Some(bytes)
        }
        None => None,
    };
    // Decode multi-attachments (images + files): kind 0/1, base64 bytes, gated at the door.
    let atts: Vec<(u8, String, Vec<u8>)> = attachments
        .unwrap_or_default()
        .into_iter()
        .map(|a| {
            let bytes = STANDARD.decode(a.b64.trim()).map_err(|e| format!("bad attachment data: {e}"))?;
            if bytes.is_empty() || bytes.len() > client::content::MAX_POST_IMAGE_BYTES {
                return Err(format!("attachment too large (> {} KiB)", client::content::MAX_POST_IMAGE_BYTES / 1024));
            }
            Ok((a.kind, sanitize_name(&a.name), bytes))
        })
        .collect::<Result<_, String>>()?;
    if text.is_empty() && image_bytes.is_none() && atts.is_empty() {
        return Err("empty post".into());
    }
    let (store, relays) = app.snapshot()?;
    let own = store.load_account().map_err(|e| format!("loading account: {e}"))?.identity_public();
    let id = client::store::random16();
    let ts = now_secs();
    // PUBLIC = to all subscribers (no narrow audience) — only these may be served to a live-pull
    // visitor; a narrow post (specific subscribers) stays private to them, never handed to a puller.
    let is_public = audience.as_ref().is_none_or(|a| a.is_empty());
    // A STORY is an ephemeral post that self-destructs 24h from now (reuses the disappearing sweep).
    let expire_at = if story.unwrap_or(false) { Some(ts + STORY_TTL_SECS) } else { None };
    store
        .append_feed(&client::store::FeedRecord { author: own, id, text: text.clone(), ts, expire_at })
        .map_err(|e| format!("saving post: {e}"))?;
    if is_public {
        let _ = store.mark_public_post(id);
    }
    // Store our own copies locally so our feed shows them immediately.
    if let Some(ref img) = image_bytes {
        let _ = store.set_feed_image(own, id, img.clone());
    }
    for (i, (kind, name, bytes)) in atts.iter().enumerate() {
        let _ = store.set_feed_attachment(
            own,
            id,
            client::store::StoredAttachment { index: i as u32, kind: *kind, name: name.clone(), bytes: bytes.clone(), failed: false },
        );
    }
    if let Some(relay) = relays.into_iter().next() {
        // Recipients: a chosen audience (narrow post — specific subscribers) OR — by default — every
        // SUBSCRIBER. Posts go to people who subscribed to you, NOT to your contacts: publishing is a
        // subscribe model, decoupled from your address book, so a contact never gets your posts just
        // for being a contact — they subscribe if they want them.
        let mut recipients: std::collections::HashSet<[u8; 32]> = match audience.filter(|a| !a.is_empty()) {
            Some(aud) => aud.iter().filter_map(|h| parse_ik(h).ok()).collect(),
            None => store.load_subscribers().into_iter().map(|s| s.ik).collect(),
        };
        let recipients: Vec<[u8; 32]> = recipients.drain().collect();
        std::thread::spawn(move || {
            let now = now_secs();
            for ik in recipients {
                let ps = store.as_proxy(proxy_for_contact(&store, &ik));
                let _ = match expire_at {
                    Some(exp) => client::send_story(&ps, &relay, &ik, id, &text, ts, exp, now),
                    None => client::send_publication(&ps, &relay, &ik, id, &text, ts, now),
                };
                // Attachments follow the text packet on the FIFO mailbox, each manifest-first + batched.
                if let Some(ref img) = image_bytes {
                    let _ = client::send_post_image(&ps, &relay, &ik, id, img, now);
                }
                // Multi-attachment media rides the relay's BLOB store (per-recipient blob + a tiny
                // ref) instead of ~90 inline chunks each — so a 4-image post lands 4 pointers, not
                // ~360 seals into a 256-cap mailbox (the MailboxFull that dropped later images). An
                // upload failure just means this recipient misses that attachment; the post shows.
                for (i, (kind, name, bytes)) in atts.iter().enumerate() {
                    if let Err(e) =
                        client::send_post_attachment_blob(&ps, &relay, &ik, id, i as u32, *kind, name, bytes, now)
                    {
                        eprintln!("[karst] post attachment {i} to a recipient failed: {e}");
                    }
                }
            }
        });
    }
    let (store, _) = app.snapshot()?;
    Ok(feed_to_posts(&store, own))
}

/// One attachment from the composer: kind 0 image / 1 file, a file name, base64 bytes.
#[derive(serde::Deserialize)]
struct AttachmentIn {
    kind: u8,
    name: String,
    b64: String,
}

/// Delete one of OUR OWN publications. Always removes it from our local feed. If `for_everyone`,
/// also broadcasts a RETRACTION to every contact so it drops from their feeds too (best-effort —
/// an offline contact past the relay TTL, or one who already saw it, may keep it). You can only
/// delete your own posts; a received post can only be removed from your own feed (`for_everyone`
/// is ignored for those). Returns the refreshed feed.
#[tauri::command]
fn delete_post(app: State<App>, id: String, for_everyone: bool) -> Result<Vec<Post>, String> {
    let id_b: [u8; 16] = hex::decode(&id).ok().and_then(|v| v.try_into().ok()).ok_or("bad post id")?;
    let (store, relays) = app.snapshot()?;
    let own = store.load_account().map_err(|e| format!("loading account: {e}"))?.identity_public();
    // Only own posts can be retracted for everyone; for a received post we just drop our own copy.
    let is_own = store.load_feed().unwrap_or_default().iter().any(|f| f.id == id_b && f.author == own);
    let author = if is_own { own } else {
        // Find the record's author so we remove exactly that (author, id) pair.
        store.load_feed().unwrap_or_default().into_iter().find(|f| f.id == id_b).map(|f| f.author).unwrap_or(own)
    };
    store.delete_feed_post(author, id_b).map_err(|e| format!("deleting post: {e}"))?;
    if for_everyone && is_own {
        if let Some(relay) = relays.into_iter().next() {
            let contacts = store.load_contacts().unwrap_or_default();
            std::thread::spawn(move || {
                let now = now_secs();
                for c in contacts {
                    let ps = store.as_proxy(proxy_for_contact(&store, &c.ik));
                    let _ = client::send_retraction(&ps, &relay, &c.ik, id_b, now);
                }
            });
        }
    }
    let (store, _) = app.snapshot()?;
    Ok(feed_to_posts(&store, own))
}

/// The whole feed (own + received publications), newest first — for the feed view.
#[tauri::command]
async fn feed(app: State<'_, App>) -> Result<Vec<Post>, String> {
    let (store, _) = app.snapshot()?;
    let own = store.load_account().map_err(|e| format!("loading account: {e}"))?.identity_public();
    Ok(feed_to_posts(&store, own))
}

/// Visit a profile (live pull): mark the author as pulled (so their reply posts are accepted into
/// the feed / their profile view) and ASK them for their recent public posts — answered only while
/// they're online. Returns whether we already subscribe to them (for the Subscribe button).
#[tauri::command]
fn view_profile(app: State<App>, peer_ik: String) -> Result<bool, String> {
    let peer = parse_ik(&peer_ik)?;
    let (store, relays) = app.snapshot()?;
    let _ = store.add_pulled(peer);
    if let Some(relay) = relay_for_contact(&store, &relays, &peer) {
        let ps = store.as_proxy(proxy_for_contact(&store, &peer));
        std::thread::spawn(move || {
            let _ = client::send_posts_request(&ps, &relay, &peer, now_secs());
        });
    }
    Ok(store.load_channel_peers().contains(&peer))
}

/// One contact's publications (author == `peer_ik`), newest first — for the contact panel's
/// "Publications" tab.
#[tauri::command]
async fn posts_of(app: State<'_, App>, peer_ik: String) -> Result<Vec<Post>, String> {
    let peer = parse_ik(&peer_ik)?;
    let (store, _) = app.snapshot()?;
    let own = store.load_account().map_err(|e| format!("loading account: {e}"))?.identity_public();
    Ok(feed_to_posts(&store, own).into_iter().filter(|p| p.author == hex::encode(peer)).collect())
}

/// Start (or open) a CONVERSATION with a raw 64-hex IK WITHOUT adding them as a contact: creates a
/// chat-only entry (flagged unconfirmed, so their name/avatar/posts stay hidden) and picks which of
/// our channels reaches them. Sends NOTHING — no profile, no contact request; the first message you
/// type is what reaches them. An already-known peer is opened as-is (never demoted).
#[tauri::command]
fn start_conversation(app: State<App>, ik: String, via_proxy: Option<u32>) -> Result<String, String> {
    let ik_b = parse_ik(&ik)?;
    let (store, _) = app.snapshot()?;
    let own = store.load_account().map_err(|e| e.to_string())?.identity_public();
    if ik_b == own {
        return Err("that is your own address".into());
    }
    ensure_conversation(&store, ik_b);
    // If they already reached us (a pinned receiving proxy), keep talking on THAT channel so we stay
    // one identity to them; else our default. Never silently re-point an existing conversation.
    let proxy = via_proxy.unwrap_or_else(|| proxy_for_contact(&store, &ik_b));
    let _ = store.set_contact_proxy(ik_b, proxy);
    Ok(hex::encode(ik_b))
}

/// Add someone as a CONTACT by name + 64-hex IK — the explicit "Add to contacts" action, also used to
/// promote an existing conversation. Confirms them on OUR side (unlocks their name/posts as they
/// arrive) and sends a mutual-consent CONTACT REQUEST carrying our profile, so they can add us back.
#[tauri::command]
fn add_contact(app: State<App>, name: String, ik: String, via_proxy: Option<u32>) -> Result<(), String> {
    let ik_b = parse_ik(&ik)?;
    let (store, relays) = app.snapshot()?;
    let mut cs = store.load_contacts().map_err(|e| e.to_string())?;
    if let Some(c) = cs.iter_mut().find(|c| c.ik == ik_b) {
        if !name.trim().is_empty() {
            c.name = name.trim().to_string(); // let an explicit label override on re-add
        }
    } else {
        cs.push(ContactRecord { name: name.trim().to_string(), ik: ik_b, verified: false });
    }
    store.save_contacts(&cs).map_err(|e| e.to_string())?;
    let _ = store.set_unconfirmed(ik_b, false); // explicit add → a confirmed contact on our side
    // Which of OUR channels reaches them: the chosen one, else the proxy they ALREADY reached us on
    // (so we stay one identity to them and the request goes back the right channel), else default.
    let proxy = via_proxy.unwrap_or_else(|| proxy_for_contact(&store, &ik_b));
    let _ = store.set_contact_proxy(ik_b, proxy);
    // Send a CONTACT REQUEST carrying our profile (mutual-consent add) — off-thread, best-effort, so
    // a slow relay never blocks the UI. Their accept brings back THEIR name+bio.
    if let Some(relay) = relays.into_iter().next() {
        let prof = store.load_profile().unwrap_or_default();
        let ps = store.as_proxy(proxy);
        std::thread::spawn(move || {
            let _ = client::send_contact_request(&ps, &relay, &ik_b, &prof.name, &prof.bio, now_secs());
        });
    }
    Ok(())
}

/// Incoming CONTACT requests (mutual-consent add): who asked, with their name/bio (from the profile
/// their request carried) so you can decide before accepting.
#[tauri::command]
async fn contact_requests(app: State<'_, App>) -> Result<Vec<Contact>, String> {
    let (store, _) = app.snapshot()?;
    let profiles = store.load_peer_profiles().unwrap_or_default();
    Ok(store
        .load_contact_requests()
        .into_iter()
        .map(|ik| Contact {
            avatar: profiles.get(&ik).and_then(|p| avatar_uri(&p.avatar)),
            channel: false,
            name: contact_display_name("", &ik, &profiles),
            ik: hex::encode(ik),
            verified: false,
            conversation_only: false,
        })
        .collect())
}

/// Accept a contact request: add them, drop the request, and send a ContactAccept carrying OUR
/// profile — so the person who asked now sees our name+bio. `via_proxy` = which of our channels
/// they'll see us on (else default).
#[tauri::command]
fn accept_contact_request(app: State<App>, peer_ik: String, via_proxy: Option<u32>) -> Result<(), String> {
    let ik = parse_ik(&peer_ik)?;
    let (store, relays) = app.snapshot()?;
    let mut cs = store.load_contacts().map_err(|e| e.to_string())?;
    if !cs.iter().any(|c| c.ik == ik) {
        cs.push(ContactRecord { name: String::new(), ik, verified: false });
        store.save_contacts(&cs).map_err(|e| e.to_string())?;
    }
    let _ = store.set_unconfirmed(ik, false); // accepting = they become a confirmed contact
    // Reply FROM the proxy their request reached us on (pinned on receive), NOT our default — else
    // our ContactAccept goes out under a DIFFERENT IK and they file us as a second, phantom contact
    // (the "contact isn't the IK that wrote" bug). proxy_for_contact returns that pinned proxy.
    let proxy = via_proxy.unwrap_or_else(|| proxy_for_contact(&store, &ik));
    let _ = store.set_contact_proxy(ik, proxy);
    let _ = store.remove_contact_request(ik);
    if let Some(relay) = relays.into_iter().next() {
        let prof = store.load_profile().unwrap_or_default();
        let ps = store.as_proxy(proxy);
        std::thread::spawn(move || {
            let _ = client::send_contact_accept(&ps, &relay, &ik, &prof.name, &prof.bio, now_secs());
        });
    }
    Ok(())
}

/// Decline a contact request — drop it SILENTLY (no message, so it never confirms to them that you
/// even saw it). They stay able to message you; they just don't become a mutual contact.
#[tauri::command]
fn decline_contact_request(app: State<App>, peer_ik: String) -> Result<(), String> {
    let ik = parse_ik(&peer_ik)?;
    let (store, _) = app.snapshot()?;
    store.remove_contact_request(ik).map_err(|e| e.to_string())
}

/// Mark a contact's safety number as verified (or un-verify). The trust anchor is the LOCAL
/// `verified` flag the user sets after comparing the safety number out-of-band — nothing the
/// network says can flip it.
#[tauri::command]
fn set_verified(app: State<App>, peer_ik: String, verified: bool) -> Result<(), String> {
    let ik_b = parse_ik(&peer_ik)?;
    let (store, _) = app.snapshot()?;
    let mut cs = store.load_contacts().map_err(|e| e.to_string())?;
    if let Some(c) = cs.iter_mut().find(|c| c.ik == ik_b) {
        c.verified = verified;
        store.save_contacts(&cs).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Rename a contact's LOCAL label — the name only you see. Never touches identity or the
/// safety-number trust anchor; a blank name is rejected so a contact never becomes nameless.
#[tauri::command]
fn rename_contact(app: State<App>, peer_ik: String, name: String) -> Result<(), String> {
    let ik_b = parse_ik(&peer_ik)?;
    let name = name.trim();
    if name.is_empty() {
        return Err("a contact needs a name".into());
    }
    let (store, _) = app.snapshot()?;
    let mut cs = store.load_contacts().map_err(|e| e.to_string())?;
    if let Some(c) = cs.iter_mut().find(|c| c.ik == ik_b) {
        c.name = name.to_string();
        store.save_contacts(&cs).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Remove a contact from the roster. Only the contact RECORD (name + verified flag) is
/// dropped; the sealed chat history stays on disk untouched, so re-adding the same address
/// restores the conversation. Purging history is a separate, destructive action on purpose.
#[tauri::command]
fn remove_contact(app: State<App>, peer_ik: String, ask_peer: Option<bool>) -> Result<(), String> {
    let ik_b = parse_ik(&peer_ik)?;
    let (store, relays) = app.snapshot()?;
    let mut cs = store.load_contacts().map_err(|e| e.to_string())?;
    cs.retain(|c| c.ik != ik_b);
    store.save_contacts(&cs).map_err(|e| e.to_string())?;
    // Clean slate: drop the CONVERSATION, their cached profile, any pending request, and the
    // session across every proxy — so re-adding the same IK later starts fresh instead of the old
    // thread resurrecting (the bug), and the ratchet doesn't linger.
    // Their route, resolved BEFORE it is forgotten just below — the optional "please delete your
    // copy too" still has to reach the relay they actually poll.
    let route = relay_for_contact(&store, &relays, &ik_b);
    let _ = store.delete_conversation(ik_b);
    let _ = store.remove_peer_profile(ik_b);
    let _ = store.remove_contact_request(ik_b);
    let _ = store.set_unconfirmed(ik_b, false); // clear the chat-only flag so no orphan lingers
    let _ = store.remove_contact_endpoint(&ik_b); // and where they said they were reachable
    for pidx in active_proxies(&store) {
        let ps = store.as_proxy(pidx);
        if let Ok(mut st) = ps.load_sessions() {
            if st.forget_peer(&ik_b) {
                let _ = ps.save_sessions(&st);
            }
        }
    }
    // Optionally ask them to delete their copy too (their choice; off-thread, best-effort).
    if ask_peer.unwrap_or(false) {
        if let Some(relay) = route {
            let ps = store.as_proxy(proxy_for_contact(&store, &ik_b));
            std::thread::spawn(move || {
                let _ = client::send_delete_conversation(&ps, &relay, &ik_b, now_secs());
            });
        }
    }
    Ok(())
}

/// Clear a CONVERSATION's history without removing the contact — for "they asked to delete", or a
/// plain "clear chat".
#[tauri::command]
fn clear_conversation(app: State<App>, peer_ik: String) -> Result<(), String> {
    let ik = parse_ik(&peer_ik)?;
    let (store, _) = app.snapshot()?;
    store.delete_conversation(ik).map_err(|e| e.to_string())
}

#[tauri::command]
async fn history(app: State<'_, App>, peer_ik: String) -> Result<Vec<Msg>, String> {
    let peer = parse_ik(&peer_ik)?;
    let (store, _) = app.snapshot()?;
    // Index of this peer's received files, keyed by (ts, name), so a reloaded "📎 name" bubble
    // can be rematched to its sealed file and offer a working Save.
    let mut idx: HashMap<(u64, String), (String, u64)> = HashMap::new();
    for f in store.list_received_files().unwrap_or_default() {
        if f.sender == peer {
            idx.insert((f.ts, f.name.clone()), (f.id, f.size));
        }
    }
    Ok(store
        .load_history()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|r| r.peer_ik == peer)
        .map(|r| {
            let text = String::from_utf8_lossy(&r.text).into_owned();
            let (mut file_id, mut size) = (None, None);
            if !r.from_me {
                if let Some(name) = text.strip_prefix("📎 ") {
                    if let Some((id, sz)) = idx.get(&(r.ts, name.to_string())) {
                        file_id = Some(id.clone());
                        size = Some(*sz);
                    }
                }
            }
            Msg { from_me: r.from_me, text, ts: r.ts, file_id, size, pending: false, expire_at: None }
        })
        .collect())
}

/// The files received from `peer_ik`, newest first — for the chat's "Received files" panel.
#[tauri::command]
async fn received_files(app: State<'_, App>, peer_ik: String) -> Result<Vec<FileMeta>, String> {
    let peer = parse_ik(&peer_ik)?;
    let (store, _) = app.snapshot()?;
    let mut v: Vec<FileMeta> = store
        .list_received_files()
        .unwrap_or_default()
        .into_iter()
        .filter(|f| f.sender == peer)
        .map(|f| FileMeta { file_id: f.id, name: f.name, size: f.size, ts: f.ts })
        .collect();
    v.sort_by_key(|f| std::cmp::Reverse(f.ts));
    Ok(v)
}

/// Every received file across ALL contacts, newest first, with the sender's local contact name
/// resolved — for the nav-rail "Files" view.
#[tauri::command]
fn all_received_files(app: State<App>) -> Result<Vec<FileEntry>, String> {
    let (store, _) = app.snapshot()?;
    let contacts = store.load_contacts().unwrap_or_default();
    let mut v: Vec<FileEntry> = store
        .list_received_files()
        .unwrap_or_default()
        .into_iter()
        .map(|f| {
            let sender_name = contacts
                .iter()
                .find(|c| c.ik == f.sender)
                .map(|c| c.name.clone())
                .unwrap_or_else(|| format!("{}…", hex::encode(&f.sender[..4])));
            FileEntry { file_id: f.id, name: f.name, size: f.size, ts: f.ts, sender: hex::encode(f.sender), sender_name }
        })
        .collect();
    v.sort_by_key(|f| std::cmp::Reverse(f.ts));
    Ok(v)
}

/// Send a text message to `peer_ik` over the primary relay. If the account has a disappearing
/// default set, the message goes out as a self-destructing `TextExpiring` and is NEVER written to
/// history (it must vanish from disk on both ends); otherwise it is a normal message, recorded to
/// history like before.
#[tauri::command]
fn send(app: State<App>, peer_ik: String, text: String) -> Result<Msg, String> {
    if app.offline.load(Ordering::SeqCst) {
        return Err("you're offline — turn off Offline mode in Settings to send".into());
    }
    let peer = parse_ik(&peer_ik)?;
    let (root, relays) = app.snapshot()?;
    // Proxy-identity model: talk to this contact AS the proxy they know (their tag, or the default
    // proxy). Network state rides the proxy; history/prefs it reads/writes are shared root data.
    let store = root.as_proxy(proxy_for_contact(&root, &peer));
    // …and THROUGH the relay their contact code named, when we hold it (A10-6): a contact whose
    // home relay is one of our backups has no bundle and no read mailbox at the primary.
    let relay = relay_for_contact(&root, &relays, &peer)
        .ok_or("no relay configured — set one in settings")?;
    let ts = now_secs();
    let ttl = store.load_prefs().map(|p| p.disappearing_secs).unwrap_or(0);
    if ttl > 0 {
        // Disappearing: send as TextExpiring, do NOT append to history. Both sides drop it at
        // `expire_at`; nothing durable is written on either end.
        client::send_text_expiring(&store, &relay, &peer, text.as_bytes(), ttl, ts)?;
        return Ok(Msg {
            from_me: true,
            text,
            ts,
            file_id: None,
            size: None,
            pending: false,
            expire_at: Some(ts.saturating_add(ttl as u64)),
        });
    }
    // `false` = the relay was down and the message is durably queued (pending); it will
    // retransmit on a later poll. Recorded to history either way — it is committed to send.
    let delivered = client::send_text(&store, &relay, &peer, text.as_bytes(), ts, ts)?;
    let _ = store.append_history(&HistoryRecord {
        from_me: true,
        peer_ik: peer,
        text: text.clone().into_bytes(),
        ts,
    });
    Ok(Msg { from_me: true, text, ts, file_id: None, size: None, pending: !delivered, expire_at: None })
}

/// This account's disappearing-message default (seconds; 0 = off).
#[tauri::command]
fn disappearing(app: State<App>) -> Result<u32, String> {
    let (store, _) = app.snapshot()?;
    Ok(store.load_prefs().map(|p| p.disappearing_secs).unwrap_or(0))
}

/// Set the disappearing-message default (seconds; 0 = off). Its own sealed blob, so a relay-screen
/// save cannot clobber it.
#[tauri::command]
fn set_disappearing(app: State<App>, secs: u32) -> Result<(), String> {
    let (store, _) = app.snapshot()?;
    let mut prefs = store.load_prefs().map_err(|e| e.to_string())?;
    prefs.disappearing_secs = secs;
    store.save_prefs(&prefs).map_err(|e| e.to_string())?;
    Ok(())
}

/// How many sent messages are still queued awaiting delivery (the relay was down). The UI
/// polls this to clear pending markers once the outbox drains — a send-side "delivered" cue.
#[tauri::command]
fn outbox_pending(app: State<App>) -> usize {
    let Ok((store, _)) = app.snapshot() else { return 0 };
    client::outbox_len(&store).unwrap_or(0)
}

/// Reduce a possibly-path-y filename to a safe basename (no directory components, bounded).
fn sanitize_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name).trim();
    let base: String = base.chars().filter(|c| !c.is_control()).take(200).collect();
    if base.is_empty() { "file".into() } else { base }
}

/// Send a file to `peer_ik`. Small files (≤ `MAX_FILE_SIZE`) ride the inline padded path
/// synchronously; larger ones stream up as an E2E blob OFF this thread (so the UI shows a
/// progress bar and can cancel), and only on success does the tiny `FileRef` go out + a
/// "📎 name" history line get written. Bytes arrive as base64 from the webview's file input.
#[tauri::command]
fn send_file(app: State<App>, peer_ik: String, name: String, data: String) -> Result<FileSent, String> {
    let peer = parse_ik(&peer_ik)?;
    let bytes = STANDARD.decode(data.trim()).map_err(|e| format!("bad file data: {e}"))?;
    if bytes.len() > MAX_ATTACH_BYTES {
        return Err(format!(
            "file too large for a single payload (max {} MB) — stream it instead",
            MAX_ATTACH_BYTES / (1024 * 1024)
        ));
    }
    dispatch_send(&app, peer, name, bytes)
}

/// Start a STREAMED attachment: returns an id the frontend threads through `file_push` and
/// `file_commit`. This is the large-file path — it sidesteps the single-payload base64 cap by
/// letting the file arrive in chunks (#35 / FT1).
#[tauri::command]
fn file_begin(app: State<App>) -> Result<String, String> {
    // Require an unlocked session up front so a locked client fails fast, not after uploading.
    let _ = app.session_parts()?;
    let id = hex::encode(client::blob::random32());
    app.pending_sends.lock().unwrap().insert(id.clone(), Vec::new());
    Ok(id)
}

/// Append one base64 chunk to a streamed attachment. Bounded by `MAX_STREAM_BYTES` so a
/// runaway/hostile frontend can't grow the buffer without limit.
#[tauri::command]
fn file_push(app: State<App>, id: String, data: String) -> Result<(), String> {
    let chunk = STANDARD.decode(data.trim()).map_err(|e| format!("bad file data: {e}"))?;
    let mut sends = app.pending_sends.lock().unwrap();
    append_chunk(&mut sends, &id, &chunk, MAX_STREAM_BYTES)
}

/// Append `chunk` to the buffer under `id`, failing (and dropping the buffer, so a rejected
/// stream frees its memory at once) if it would exceed `max`. Separated from the command so the
/// bound — the only DoS-relevant part — is unit-testable without a Tauri harness.
fn append_chunk(
    sends: &mut HashMap<String, Vec<u8>>,
    id: &str,
    chunk: &[u8],
    max: usize,
) -> Result<(), String> {
    let buf = sends.get_mut(id).ok_or("unknown upload id")?;
    if buf.len() + chunk.len() > max {
        sends.remove(id);
        return Err(format!("file exceeds the {} MB limit", max / (1024 * 1024)));
    }
    buf.extend_from_slice(chunk);
    Ok(())
}

/// Finish a streamed attachment: dispatch the accumulated bytes down the same inline/blob path
/// as a small `send_file`, then drop the buffer.
#[tauri::command]
fn file_commit(app: State<App>, id: String, peer_ik: String, name: String) -> Result<FileSent, String> {
    let peer = parse_ik(&peer_ik)?;
    let bytes = app.pending_sends.lock().unwrap().remove(&id).ok_or("unknown upload id")?;
    dispatch_send(&app, peer, name, bytes)
}

/// Discard a streamed attachment that was never committed (e.g. the user cancelled the picker).
#[tauri::command]
fn file_abort(app: State<App>, id: String) {
    app.pending_sends.lock().unwrap().remove(&id);
}

/// Send fully-buffered `bytes` to `peer`: small files ride the inline padded path synchronously;
/// larger ones stream up as an E2E blob OFF this thread (progress + cancel), and only on success
/// does the tiny `FileRef` + "📎 name" history line go out. Shared by `send_file` (small,
/// single-payload) and `file_commit` (streamed large).
fn dispatch_send(app: &App, peer: [u8; 32], name: String, bytes: Vec<u8>) -> Result<FileSent, String> {
    if bytes.is_empty() {
        return Err("empty file".into());
    }
    let name = sanitize_name(&name);
    let (vault, id, relays) = app.session_parts()?;
    // The relay the recipient's contact code named, when we hold it (A10-6) — both the session
    // packets and the blob upload have to land where they actually poll.
    let relay = relay_for_contact(&vault.account(&id), &relays, &peer)
        .ok_or("no relay configured — set one in settings")?;
    let ts = now_secs();
    let size = bytes.len() as u64;

    if size <= client::content::MAX_FILE_SIZE {
        let root = vault.account(&id);
        let store = root.as_proxy(proxy_for_contact(&root, &peer)); // send AS the contact's proxy
        client::send_file(&store, &relay, &peer, &name, &bytes, ts)?;
        let _ = store.append_history(&HistoryRecord {
            from_me: true,
            peer_ik: peer,
            text: format!("📎 {name}").into_bytes(),
            ts,
        });
        return Ok(FileSent { from_me: true, name, size, ts, done: true, tid: None });
    }

    // Blob upload off-thread with progress + cancel.
    let tid = app.new_tid();
    let cancel = Arc::new(AtomicBool::new(false));
    app.transfers.lock().unwrap().insert(
        tid,
        TransferState {
            dir: "up",
            peer,
            name: name.clone(),
            done: 0,
            total: size,
            state: "active",
            file_id: None,
            error: None,
            finished_at: None,
            cancel: cancel.clone(),
        },
    );
    let transfers = app.transfers.clone();
    let name2 = name.clone();
    let offline = app.offline.clone();
    std::thread::spawn(move || {
        let root = vault.account(&id);
        let store = root.as_proxy(proxy_for_contact(&root, &peer)); // the FileRef rides the contact's proxy
        let res = (|| -> Result<(), String> {
            // The upload presents a capability now (CRYPTO-15): storing bytes on a relay is
            // metered like every other write, and this path stores the most of them.
            let cap = store
                .load_capability_for(&relay.id)
                .map_err(|e| format!("no credential to upload through this relay: {e}"))?;
            let (blob_id, key, hash, chunks) = client::blob_upload_with(
                &relay,
                &cap,
                Cursor::new(bytes),
                size,
                &cancel,
                |done, total| transfer_progress_step(&transfers, tid, done, total),
            )?;
            // SUCCESS ONLY: the FileRef goes out and history is written here — never optimistically,
            // so a cancelled/failed upload leaves no "sent" file that never arrived.
            let fr = Content::FileRef { blob_id, key, hash, name: name2.clone(), size, chunks };
            client::send_session(&store, &relay, &peer, &client::content::encode(&fr), ts)?;
            let _ = store.append_history(&HistoryRecord {
                from_me: true,
                peer_ik: peer,
                text: format!("📎 {name2}").into_bytes(),
                ts,
            });
            Ok(())
        })();
        match res {
            Ok(()) => transfer_finish(&transfers, tid, "done", None, None),
            Err(e) if e == "cancelled" => {
                // SEC-45: `stop_for_offline` cancels every active transfer the same way the
                // Cancel button does, but unlike a manual abandon this one is NOT data loss — the
                // bytes we were uploading are our own file, still untouched on the user's disk
                // (only the in-memory copy this thread held is dropped), so "reported" (not
                // "resumed") satisfies the never-silently-lose-data bar. Say which one happened.
                let msg = offline.load(Ordering::SeqCst).then(|| {
                    "stopped by Offline — resend when back online (nothing was sent; your file \
                     on disk is untouched)"
                        .to_string()
                });
                transfer_finish(&transfers, tid, "cancelled", None, msg);
            }
            Err(e) => transfer_finish(&transfers, tid, "error", None, Some(e)),
        }
    });
    Ok(FileSent { from_me: true, name, size, ts, done: false, tid: Some(tid) })
}

/// Offer a contact the §15 routes you use to reach your relay — the primitive for moving a
/// contact onto a different (e.g. private) node. Explicit and one-to-one: it hands THEM your
/// routes, so it is never a broadcast and the recipient only SEES it (they decide whether to
/// try it). Requires routes to be configured — there is nothing to offer otherwise.
#[tauri::command]
fn offer_route(app: State<App>, peer_ik: String) -> Result<(), String> {
    let peer = parse_ik(&peer_ik)?;
    let (store, relays) = app.snapshot()?;
    let relay = relays.first().cloned().ok_or("no relay configured — set one in settings")?;
    let net = store.load_net().unwrap_or_default();
    let routes = net.routes.trim().to_string();
    if routes.is_empty() {
        return Err("no routes configured to offer — add relay routes in settings first".into());
    }
    let ps = store.as_proxy(proxy_for_contact(&store, &peer));
    client::send_route_offer(&ps, &relay, &peer, &routes, now_secs())
}

/// A poll's result for the UI: the incoming items, plus which relays were REACHABLE this poll
/// (aligned to the relay set, index 0 = primary). The reachability lets the connection dots
/// reflect a real probe instead of mere configuration.
#[derive(Serialize)]
struct PollOut {
    messages: Vec<Incoming>,
    reachable: Vec<bool>,
}

/// A chat message from someone not yet in your contacts must still create a conversation.
/// Without this, a FIRST-CONTACT message is decrypted and persisted to history but stays
/// invisible: the chat list (`contacts` command) is built only from saved `ContactRecord`s, so
/// an unknown sender's `_unread` mark points at an IK that never renders. Register the sender
/// with a short-IK placeholder label (the user can rename / verify); idempotent, never
/// overwrites an existing label. Called only for real chat messages (text / file), not posts or
/// control frames. Matches the connection-channel model: a handed-out channel that gets spammed
/// is burned, so auto-surfacing a sender costs nothing the address didn't already expose.
/// Ensure a CONVERSATION exists for `ik` (so the chat shows) WITHOUT confirming them as a contact: a
/// newly-seen peer is added chat-only (flagged unconfirmed) — you can talk to anyone by IK without
/// "adding" them, and until you do you never see their self-declared name/avatar/posts. An
/// already-known peer is left as-is (a re-DM from a confirmed contact must NOT demote them).
fn ensure_conversation(root: &Store, ik: [u8; 32]) {
    // SEC-44: the cap (and the write-cost/log-on-refusal reasoning) lives with the persisted
    // state in `Store::add_unconfirmed_contact`, not here — this is now a thin call site.
    let _ = root.add_unconfirmed_contact(ik);
}

/// Ensure `ik` is a CONFIRMED contact: add the record if new AND clear any unconfirmed flag. Used
/// when a mutual add completes (ContactAccept) — this is what unlocks showing their
/// name/avatar/posts and fanning ours out to them.
///
/// SEC-44: the cap lives with the persisted state in `Store::add_confirmed_contact` (this call
/// site is driven by a REMOTE `ContactAccept`, processed automatically on receipt — the same
/// flood surface as `ensure_conversation`), not here — this is now a thin call site.
fn ensure_confirmed_contact(root: &Store, ik: [u8; 32]) {
    let _ = root.add_confirmed_contact(ik);
}

/// Whether `ik`'s publications belong in our feed: an account we SUBSCRIBED to, OR one we live-pulled
/// from (visited their profile). Posts are decoupled from contacts — you subscribe to follow, or pull
/// to peek; a pulled author's reply posts land in their profile view.
///
/// The rule itself moved to `Store` (SEC-31): the client receive path has to apply the SAME gate to
/// a `PostAttachmentRef` before it commits the work, and two copies of a consent rule is how they
/// drift apart. This stays as the local spelling every feed call site already reads.
fn is_feed_source(store: &Store, ik: &[u8; 32]) -> bool {
    store.is_feed_source(ik)
}

/// Whether an inline transfer MANIFEST from `sender` may open a reassembly slot (SEC-31, the inline
/// half). Post media reaches us two ways — a blob pointer, gated in `recv_session_multi`, or these
/// inline chunk transfers — and a gate on only one of them is not a gate. Files, avatars and
/// galleries are unaffected: they are addressed to the CONVERSATION, which anyone may open, and
/// carry their own caps. Only the two post-media manifests need the feed gate, because only they
/// claim to decorate a post.
///
/// A predicate rather than an inline condition so the decision is testable on its own; the poll
/// dispatch it guards is not.
fn inline_transfer_admitted(store: &Store, sender: &[u8; 32], c: &Content) -> bool {
    if matches!(c, Content::PostImageManifest { .. } | Content::PostAttachmentManifest { .. }) {
        return is_feed_source(store, sender);
    }
    true
}

/// COVER-TRAFFIC tick (Loopix-style, opt-in): emit ONE dummy deposit through the exact real send
/// path (per active proxy), so an observer can't read this client's real send timing from the wire.
/// The JS fires this on a Poisson (exponential-interval) schedule while cover traffic is enabled.
/// Honest scope: additive noise masking THIS client's timing — not full unobservability.
#[tauri::command]
async fn cover_tick(app: State<'_, App>) -> Result<(), String> {
    // Held until the (single, unchunked) deposit below is sent or skipped — SEC-45:
    // `stop_for_offline` waits on this so it can't report success while a tick that read
    // offline=false a moment ago is still about to touch the wire. Entered BEFORE the offline
    // check for the same reason `NetGuard::enter`'s doc gives: check-then-act must not straddle
    // the flip.
    let guard = NetGuard::enter(&app.net_active);
    // OFFLINE mode must emit NOTHING — cover traffic is a network deposit, so skip it too.
    if app.offline.load(Ordering::SeqCst) {
        return Ok(());
    }
    let (root, relays) = app.snapshot()?;
    let Some(relay) = relays.into_iter().next() else { return Ok(()) };
    let mut proxies = active_proxies(&root);
    if proxies.is_empty() {
        proxies.push(default_proxy(&root)?);
    }
    // A cover deposit from ONE random proxy this tick (not all — that would itself be a pattern).
    let idx = proxies[(now_secs() as usize) % proxies.len()];
    let ps = root.as_proxy(idx);
    let offline = app.offline.clone();
    std::thread::spawn(move || {
        let _guard = guard; // released when this (one-shot, non-cancellable) call returns
        // HONEST LIMIT: `send_cover` is a single request/response with no chunk boundary to
        // recheck against — unlike a transfer, there is nowhere mid-call to notice `offline`
        // flipping. Re-checking right before the call at least shrinks the window to "between
        // spawn and send" instead of "any time this thread happens to run".
        if offline.load(Ordering::SeqCst) {
            return;
        }
        let _ = client::send_cover(&ps, &relay, now_secs());
    });
    Ok(())
}

/// Fetch incoming messages from every relay. Text and small inline files are handled inline
/// and returned; large `FileRef` blobs download OFF this thread and arrive later as a
/// "file-received" event. Also reports per-relay reachability from this poll.
#[tauri::command]
async fn poll(app: State<'_, App>) -> Result<PollOut, String> {
    let mut out: Vec<Incoming> = Vec::new();
    // Held for this whole call (dropped on every return path, including the ones below and any
    // `?`) — SEC-45: `stop_for_offline` waits on this reaching zero before it will report success,
    // so a poll that is mid-drain across several relays/proxies can't keep emitting after Offline
    // has already returned. Entered BEFORE the offline check: otherwise a poll that read
    // offline=false the instant before `stop_for_offline` observed `net_active == 0` could still
    // run its whole drain after Offline reported done.
    let _net_guard = NetGuard::enter(&app.net_active);
    // OFFLINE mode: emit nothing — no relay round trips at all, so there is no network signal.
    if app.offline.load(Ordering::SeqCst) {
        return Ok(PollOut { messages: out, reachable: Vec::new() });
    }
    let (vault, id, relays) = app.session_parts()?;
    if relays.is_empty() {
        return Ok(PollOut { messages: out, reachable: Vec::new() });
    }
    let root = vault.account(&id);
    let primary = relays.first().cloned();
    let mut proxies = active_proxies(&root);
    if proxies.is_empty() {
        proxies.push(default_proxy(&root)?);
    }
    // SEC-43: reap idle in-flight reassemblies on EVERY poll tick, whether or not this pass
    // drains any messages — the finding was that the only trigger was the SAME stalled sender
    // sending a fresh manifest, so a sender who starts a transfer and then goes silent forever
    // would pin RAM until the account was switched or the process exited. Cheap: the map is
    // normally small, and this is a pure in-memory scan (no I/O).
    client::reap_reassemblers(&mut app.reasm.lock().unwrap(), now_secs());
    // A relay counts as reachable if ANY proxy's poll reached it this pass.
    let mut reach_any = vec![false; relays.len()];
    // SEC-34: every lease this poll takes, across every page and every proxy, held UNSENT until
    // the one post-loop commit below. Nothing is deleted from any relay before the account's
    // authority (the container, for a container-backed session) has actually recorded it.
    let mut acks = client::DeferredAcks::default();
    // Did this poll change anything on disk that a container-backed session still has to commit?
    // Deliberately NOT `!out.is_empty()`: that was the second half of SEC-34. Control-only mail —
    // reactions, `ChannelMigrate`, the `FileRef`/`PostAttachmentRef`/`GalleryRef` pointers whose
    // pending entries are written before the ack — advances the ratchet and writes to the work
    // dir while producing ZERO UI events, so gating the container save on UI output left exactly
    // that mail acked-but-uncommitted.
    let mut dirty = false;
    // PROXY-IDENTITY MODEL: poll EACH proxy's mailbox (never the root). `store` below is the proxy
    // handle — its NETWORK state (sessions/opks) is per-proxy, while the history/feed/files it
    // writes land on the shared ROOT data paths, so incoming lands in one unified inbox.
    for pidx in proxies {
        // SEC-45: Offline can flip WHILE this poll is mid-drain across proxies/relays/pages — the
        // per-item checks below (and this one) stop it from starting the NEXT round trip once that
        // happens, instead of running the whole remaining drain to completion. The round trip
        // already in flight when the flag flips still finishes (no lower-level cancel exists for a
        // single blocking network call from this layer) — that residual is `stop_for_offline`'s
        // documented honest limit, not something this loop can close.
        if app.offline.load(Ordering::SeqCst) {
            break;
        }
        let store = root.as_proxy(pidx);
        // Send-side retry + MULTI-HOMING on the poll cadence: retransmit (verbatim) any queued
        // message across EVERY relay, so a down/blocked primary doesn't strand it — the first
        // reachable relay delivers it and it's removed from the outbox (the rest then have nothing
        // to flush). The recipient polls all relays + dedups, so wherever it lands, they get it.
        for p in &relays {
            if app.offline.load(Ordering::SeqCst) {
                break;
            }
            let _ = client::flush_outbox(&store, p, now_secs());
        }
        // DRAIN the mailbox this poll instead of one fetch page: a bulk transfer — a multi-image
        // post is hundreds of ~1 KiB chunks (packet size is MTU-pinned for traffic-shaping), and the
        // recipient mailbox caps at MAX_FETCH_SEALS — so at one page per poll an image post trickles
        // in over minutes. Loop recv until a page comes back empty (bounded, so a flood can't wedge
        // the poll), collect, then process in FIFO order. The poll is async, so this is off the UI
        // thread.
        let mut drained = Vec::new();
        for _ in 0..MAX_DRAIN_PAGES {
            if app.offline.load(Ordering::SeqCst) {
                break; // don't start another page's round trip once Offline is set
            }
            let poll = match client::recv_session_multi(&store, &relays, now_secs()) {
                Ok(p) => p,
                Err(_) => break,
            };
            for (i, ok) in (0..relays.len()).map(|i| !poll.failed.contains(&i)).enumerate() {
                if ok {
                    reach_any[i] = true;
                }
            }
            // Carry this page's leases forward unsent (SEC-34). A page that fetched envelopes we
            // could not decrypt still took leases and still advanced state, so `dirty` follows the
            // leases, not the decrypted count.
            dirty |= !poll.acks.is_empty();
            acks.merge(poll.acks);
            let before = drained.len();
            drained.extend(poll.messages.into_iter().flatten());
            if drained.len() == before {
                break; // empty page → mailbox drained this pass
            }
        }
        // SEC-40 / A6-6: re-apply anything a previous run parked because no handler had committed
        // it before the ack. The relay deleted its copy, so this log is the only remaining source;
        // running the items through the SAME dispatch below is what turns "recoverable" into
        // "recovered". Loaded (not cleared) here — the clear happens after the loop, so a crash
        // midway replays rather than loses.
        let parked = root.load_quarantine().unwrap_or_default();
        let replayed = !parked.is_empty();
        // A replay writes (the handlers' history/state, then the cleared log), so it too needs the
        // container commit below. HONEST LIMIT: the quarantine log is NOT a mitigation for SEC-34 —
        // it lives in the root store, which for a container-backed account IS the work dir, so a
        // container that rolls back rolls the log back with it. It only ever protected the
        // file-tree case.
        dirty |= replayed;
        let drained: Vec<_> = parked
            .into_iter()
            .map(|q| node::peer::Received {
                sender: q.sender,
                plaintext: q.plaintext,
                msg_id: [0u8; 32], // replayed, not freshly leased: nothing to ack
            })
            .chain(drained)
            .collect();

        for r in drained {
            // They reached us via THIS proxy — tag the contact so replies go out the same channel.
            let _ = root.set_contact_proxy(r.sender, pidx);
            let Ok(c) = decode(&r.plaintext) else { continue };
        // Carry the SENDER's timestamp for stamped variants — DTN store-and-forward means a
        // message can surface long after it was sent, so ordering by arrival would misplace it.
        let (text, ts, expire_at) = match c {
            Content::TextStamped { text, ts } | Content::TextReply { text, ts, .. } => (text, ts, None),
            Content::Text(t) => (t, now_secs(), None),
            Content::TextExpiring { text, expire_at } => {
                // Arrived after its self-destruct time (DTN store-and-forward can delay it) — it
                // came dead: never surface it, never persist it.
                if now_secs() >= expire_at {
                    continue;
                }
                (text, now_secs(), Some(expire_at))
            }
            Content::FileRef { .. } => {
                // The large-file announcement was already persisted as a durable PENDING
                // DOWNLOAD by `recv_session_multi` (before the ack), so it survives a crash.
                // The actual download is driven — crash-safely, with retry — by
                // `drive_pending_downloads` below, not inline here.
                continue;
            }
            Content::PostAttachmentRef { .. } => {
                // A post-attachment blob pointer, already persisted as a durable PENDING POST
                // ATTACHMENT before the ack. The fetch (into the feed_attachments sidecar) is
                // driven by `drive_pending_post_attachments` below, not inline here.
                continue;
            }
            Content::GalleryRef { .. } => {
                // A gallery blob pointer, already persisted as a durable PENDING GALLERY (keyed by
                // sender, confirmed-contacts-only) by `recv_session_multi` before the ack. The fetch
                // (into peer_profiles photos) is driven by `drive_pending_galleries` below.
                continue;
            }
            c @ (Content::FileManifest { .. }
            | Content::FileChunk { .. }
            | Content::AvatarManifest { .. }
            | Content::AvatarChunk { .. }
            | Content::PostImageManifest { .. }
            | Content::PostAttachmentManifest { .. }
            // The INLINE gallery header must reach the reassembler too — its chunks are `AvatarChunk`
            // (already listed), so without this the manifest fell through to `_` and every chunk hit
            // "chunk without manifest": inline (≤2-photo) gallery receive was silently dead.
            | Content::GalleryManifest { .. }) => {
                // SEC-31, inline half. Refusing the MANIFEST (not the assembled result) means the
                // transfer never opens, so its chunks are dropped by the reassembler's own "chunk
                // without manifest" rule instead of accumulating in RAM until the reaper takes them.
                if !inline_transfer_admitted(&store, &r.sender, &c) {
                    continue;
                }
                // `offer_reassembly` (not a raw per-sender `entry().or_default()`) enforces the
                // GLOBAL sender-count + RAM caps (SEC-43) before this reaches any one sender's
                // Reassembler — a flood of fresh sender IKs must not grow this map without bound.
                let mut reasm = app.reasm.lock().unwrap();
                match client::offer_reassembly(&mut reasm, r.sender, c, now_secs()) {
                    Ok(Some(Assembled::File(f))) => {
                        ensure_conversation(&root, r.sender); // first-contact file: surface the sender
                        let nm = sanitize_name(&f.name);
                        match store.save_received_file(&nm, &f.bytes) {
                            Ok(fid) => {
                                let ts = now_secs();
                                let size = f.bytes.len() as u64;
                                let _ = store.append_history(&HistoryRecord {
                                    from_me: false,
                                    peer_ik: r.sender,
                                    text: format!("📎 {nm}").into_bytes(),
                                    ts,
                                });
                                let _ = store.record_received_file(&ReceivedFile {
                                    id: fid.clone(),
                                    name: nm.clone(),
                                    size,
                                    sender: r.sender,
                                    ts,
                                    blob_id: [0u8; 32], // inline file: not a blob
                                });
                                out.push(Incoming::file(r.sender, nm, size, fid, ts));
                            }
                            Err(e) => eprintln!("[karst] saving received file: {e}"),
                        }
                    }
                    Ok(Some(Assembled::Avatar { bytes })) => {
                        let _ = store.set_peer_avatar(r.sender, bytes); // cache the contact's photo
                        // Signal the UI: the peer's avatar changed. Without this the bytes are
                        // cached but the contact list / chat header never re-render it (the same
                        // "data arrives but UI isn't told" class as the first-contact fix).
                        ensure_conversation(&root, r.sender);
                        out.push(Incoming::avatar(r.sender));
                    }
                    Ok(Some(Assembled::Gallery { bytes })) => {
                        // Replace the contact's whole gallery atomically (an empty pack clears it).
                        // A malformed pack from the wire is dropped, not stored (unpack_gallery gates).
                        // The stale-guard (ts) lives in set_peer_photos, so an out-of-order inline vs
                        // blob copy can't clobber a newer one.
                        if let Ok((ts, photos)) = client::content::unpack_gallery(&bytes) {
                            let _ = store.set_peer_photos(r.sender, photos, ts);
                            ensure_conversation(&root, r.sender);
                            out.push(Incoming::gallery(r.sender));
                        }
                    }
                    Ok(Some(Assembled::PostImage { post_id, bytes })) => {
                        // Reunite the image with its post (author = r.sender). If the image raced
                        // ahead of the text packet the post isn't stored yet, but the sidecar keeps
                        // the bytes keyed by (author, post_id) so the post picks it up on render.
                        let _ = store.set_feed_image(r.sender, post_id, bytes);
                        out.push(Incoming::post(r.sender, String::new(), now_secs()));
                    }
                    Ok(Some(Assembled::PostAttachment { post_id, index, kind, name, bytes })) => {
                        // Store the attachment against its post (author = r.sender), keyed by index.
                        let _ = store.set_feed_attachment(
                            r.sender,
                            post_id,
                            client::store::StoredAttachment { index, kind, name, bytes, failed: false },
                        );
                        out.push(Incoming::post(r.sender, String::new(), now_secs()));
                    }
                    Ok(None) => {}                           // chunk accumulated
                    Err(e) => eprintln!("[karst] inline file rejected: {e}"),
                }
                continue;
            }
            // A contact's self-declared profile: cache it (a HINT — never overrides the local
            // contact label/verified/safety-number anchor).
            Content::Profile { name, bio } => {
                let _ = store.set_peer_profile(r.sender, &name, &bio);
                // Surface it: a contact added with no local name now shows the name THEY chose, and
                // an open chat header updates. Reuses the avatar refresh path (coalesced per poll).
                ensure_conversation(&root, r.sender);
                out.push(Incoming::avatar(r.sender));
                continue;
            }
            // A contact offering the routes they use to reach a relay. Surfaced for the user to
            // SEE and act on manually — never auto-applied (an offered route reveals your IP to
            // whoever runs it). `matches` = the offer names a relay we already use.
            Content::RouteOffer { relay_noise_pub, routes } => {
                let matches = relays.iter().any(|rl| rl.id.noise_pub == relay_noise_pub);
                out.push(Incoming::route(r.sender, routes, matches, now_secs()));
                continue;
            }
            // A contact's PUBLICATION: store it in the feed (deduped by author+id) and surface a
            // live "post" event so an open feed refreshes / a badge can appear. NOT chat history.
            Content::Publication { id, text, ts } => {
                // Post privacy: only a CONFIRMED contact's (or a subscribed channel's) posts enter
                // the feed. A non-contact you merely DM can't put posts in front of you.
                if !is_feed_source(&store, &r.sender) {
                    continue;
                }
                // Clamp the sender's timestamp to "now": a post can't be from the future, and
                // the feed sorts by ts — otherwise a hostile ts=u64::MAX would pin a post to the
                // top forever. A legitimately DTN-delayed post carries a PAST ts, so it's unaffected.
                let ts = ts.min(now_secs());
                let _ = store.append_feed(&client::store::FeedRecord {
                    author: r.sender,
                    id,
                    text: text.clone(),
                    ts,
                    expire_at: None,
                });
                out.push(Incoming::post(r.sender, text, ts));
                continue;
            }
            // A STORY: an ephemeral publication. Drop it if it already arrived dead (DTN delay past
            // expiry); otherwise store it with its self-destruct time and surface it like a post.
            Content::Story { id, text, ts, expire_at } => {
                // Same contact-gate as Publication: no non-contact stories in your feed.
                if !is_feed_source(&store, &r.sender) {
                    continue;
                }
                if now_secs() >= expire_at {
                    continue; // came dead — never store or show
                }
                let ts = ts.min(now_secs());
                let _ = store.append_feed(&client::store::FeedRecord {
                    author: r.sender,
                    id,
                    text: text.clone(),
                    ts,
                    expire_at: Some(expire_at),
                });
                out.push(Incoming::post(r.sender, text, ts));
                continue;
            }
            // A contact RETRACTED a publication: drop it from the feed (by their author + id) and
            // signal a "post" refresh so an open feed updates. Idempotent if we never had it.
            Content::RetractPublication { id } => {
                let _ = store.delete_feed_post(r.sender, id);
                out.push(Incoming::post(r.sender, String::new(), now_secs()));
                continue;
            }
            // Someone asked to SUBSCRIBE to our posts. SECURITY: this NEVER writes our channel
            // flag — it only READS it. In channel mode we auto-accept (add subscriber + ack); a
            // private account queues it for manual approval. That's the whole power of a join
            // request: it can add the sender to our audience only if WE already chose channel mode.
            Content::JoinRequest => {
                // Auto-accept if we're a public CHANNEL, OR the requester is already a CONFIRMED
                // CONTACT — you added them, so subscribing needs no separate approval; their posts
                // just start flowing. Everyone else (a stranger to a private account) queues for
                // manual approval. `is_channel` in the accept reflects our real channel flag.
                let is_channel = store.load_channel().enabled;
                let auto = is_channel || store.is_confirmed_contact(&r.sender).unwrap_or(false);
                if auto {
                    if let Ok(true) = store.add_subscriber(r.sender, now_secs()) {
                        // SEC-45: this whole dispatch loop runs inside `poll`'s NetGuard, so
                        // `stop_for_offline` never reports done while it's mid-batch — but nothing
                        // stops it from replying to the REST of a drained batch once Offline is
                        // set. Same shape as the `PostsRequest` reply loop's per-item check, just
                        // with each reply already one atomic send (no separate thread to guard).
                        if !app.offline.load(Ordering::SeqCst) {
                            if let Some(relay) = relays.first() {
                                let _ = client::send_join_accept(&store, relay, &r.sender, is_channel, now_secs());
                            }
                        }
                        out.push(Incoming::join(r.sender, "joined"));
                    }
                } else if let Ok(true) = store.add_pending_sub(r.sender) {
                    out.push(Incoming::join(r.sender, "pending"));
                }
                continue;
            }
            // Our subscribe request was accepted: remember whether they're a channel (for the
            // contact badge) and surface it. NEVER touches our own channel flag.
            // Only from someone we actually asked (SEC-29). Consent has two halves; without a
            // record of the ask, an unsolicited "accept" from a stranger changed local trust just
            // as an answer to a real request would.
            Content::JoinAccept { is_channel } => {
                match store.take_outstanding_request(&r.sender) {
                    Ok(true) => {
                        let _ = store.set_channel_peer(r.sender, is_channel);
                        out.push(Incoming::join(r.sender, "accepted"));
                    }
                    Ok(false) => eprintln!(
                        "KARST: dropping a join accept from a peer we never asked to join"
                    ),
                    Err(e) => eprintln!("KARST: reading outstanding requests: {e}"),
                }
                continue;
            }
            // A live-pull visitor asked for our posts: answer with our recent PUBLIC posts only (never
            // a narrow-audience post) as ordinary Publications, so they can view us without
            // subscribing. Best-effort, off-thread; only public ids in `public_posts` qualify.
            Content::PostsRequest => {
                if let Some(relay) = relays.first().cloned() {
                    // SEC-30: admit BEFORE doing anything, because everything below is work an
                    // unsolicited message would otherwise buy for free — the feed and public-post
                    // sets are sealed files, so even "load, find nothing, send nothing" is a full
                    // decrypt per request. Reserve the worst case (`POSTS_PULL_LIMIT`) and hand
                    // back what we turn out not to need.
                    let granted = app.posts_reply.lock().unwrap().admit(now_secs(), POSTS_PULL_LIMIT);
                    if granted == 0 {
                        continue;
                    }
                    let slot = PostsReplySlot(app.posts_reply.clone());
                    let public = store.load_public_posts().unwrap_or_default();
                    let own = store.load_account().ok().map(|a| a.identity_public()).unwrap_or([0u8; 32]);
                    let mut posts: Vec<_> = store
                        .load_feed()
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|f| f.author == own && f.expire_at.is_none() && public.contains(&f.id))
                        .collect();
                    posts.sort_by_key(|f| std::cmp::Reverse(f.ts));
                    posts.truncate(granted); // `granted` ≤ POSTS_PULL_LIMIT and may be smaller
                    // Charge for the sends we will actually make, but never less than one: the two
                    // sealed reads above happened whatever the answer turns out to be, so a client
                    // with nothing public to serve must still pay for having been asked. Without
                    // the floor its whole reservation comes back and the window never fills.
                    app.posts_reply.lock().unwrap().refund(granted - posts.len().max(1));
                    if posts.is_empty() {
                        continue; // nothing to say — don't spend a thread saying it
                    }
                    let ps = store.as_proxy(proxy_for_contact(&store, &r.sender));
                    let to = r.sender;
                    // SEC-45: this loop can run long past `poll`'s own return (a visitor with a
                    // full POSTS_PULL_LIMIT history means up to 30 separate relay round trips), on
                    // a relay handle captured before any later Offline toggle. Its own `NetGuard`
                    // (not `poll`'s — this outlives that call) is what `stop_for_offline` waits on.
                    let offline = app.offline.clone();
                    let guard = NetGuard::enter(&app.net_active);
                    std::thread::spawn(move || {
                        let _guard = guard;
                        let _slot = slot; // released here, however this thread ends (SEC-30)
                        let now = now_secs();
                        for f in posts {
                            // Checked between posts, not mid-post: each `send_publication` is its
                            // own atomic request, same as cover traffic — no chunk boundary inside
                            // one to recheck against.
                            if offline.load(Ordering::SeqCst) {
                                break;
                            }
                            let _ = client::send_publication(&ps, &relay, &to, f.id, &f.text, f.ts, now);
                        }
                    });
                }
                continue;
            }
            // Someone wants to add us: store WHO is asking (their name+bio, so we can decide) and
            // queue the request. We do NOT auto-add them — accepting is what shares OUR profile back.
            Content::ContactRequest { name, bio } => {
                let _ = store.set_peer_profile(r.sender, &name, &bio);
                // Make sure the requester is a CONVERSATION row too (usually already is — you were
                // chatting), so the request surfaces ON that chat instead of as a floating, separate
                // "who is this" entry the user can't tie to the conversation they already have.
                ensure_conversation(&root, r.sender);
                if let Ok(true) = store.add_contact_request(r.sender) {
                    out.push(Incoming::contactreq(r.sender, "request"));
                }
                continue;
            }
            // Our request was accepted: NOW we may see their name+bio. Ensure they're a contact
            // (we initiated) and refresh so their chosen name replaces the bare address.
            // Same gate as `JoinAccept`, and the profile write sits INSIDE it: `name`/`bio` are
            // attacker-controlled state, so storing them before checking who asked would keep
            // half of the bug (SEC-29).
            Content::ContactAccept { name, bio } => {
                match store.take_outstanding_request(&r.sender) {
                    Ok(true) => {
                        let _ = store.set_peer_profile(r.sender, &name, &bio);
                        ensure_confirmed_contact(&root, r.sender);
                        out.push(Incoming::contactreq(r.sender, "accepted"));
                    }
                    Ok(false) => eprintln!(
                        "KARST: dropping a contact accept from a peer we never sent a request to"
                    ),
                    Err(e) => eprintln!("KARST: reading outstanding requests: {e}"),
                }
                continue;
            }
            // They asked to delete the conversation. We do NOT wipe automatically — you can't be
            // forced to destroy your own data — just surface it so the user can clear their copy.
            Content::DeleteConversation => {
                out.push(Incoming::contactreq(r.sender, "delete_request"));
                continue;
            }
            // A contact MOVED to a new channel — authenticated by arriving on our session with
            // their OLD address (r.sender). Re-point them to new_ik; the safety number changed, so
            // surface it for a re-verify. Future mail to/from them uses the new address.
            //
            // DELIBERATELY NOT behind SEC-29's outstanding-request ledger, and the reason is a
            // category difference, not an oversight. That ledger answers one question — "did WE
            // ask for this?" — and it works for `ContactAccept`/`JoinAccept` because each is the
            // second half of a request this client sent and recorded. A migration has no first
            // half: it is a contact telling us something about themselves, unprompted, exactly
            // like `Profile` or `RetractPublication`. Requiring a consumed ledger entry would mean
            // requiring an entry that can never exist, which is not a gate but a deletion of the
            // feature. What DOES stand in for consent here is `migrate_contact_ik`'s own
            // precondition: `r.sender` must already be a contact, so a stranger cannot reach this
            // path at all, and it refuses a `new_ik` that already belongs to a DIFFERENT contact
            // (SEC-36's collision half).
            //
            // The residual is real and is NOT the ledger: nothing proves the sender holds
            // `new_ik`, and the re-point is applied before the user sees it, so a compromised or
            // malicious contact can silently redirect our future mail to a third party's key.
            // `verified` is cleared (the UI prompts a re-verify) but the redirect has already
            // happened. Closing that needs a staged migration — persist as PENDING, apply only on
            // an explicit user action — which is SEC-36's auto-redirect half, tracked separately;
            // see `docs/STATUS.md`. Bolting a wrong-shaped gate on here would have hidden it.
            Content::ChannelMigrate { new_ik } => {
                if new_ik != r.sender {
                    match root.migrate_contact_ik(r.sender, new_ik) {
                        Ok(true) => out.push(Incoming::migrate(r.sender, new_ik)),
                        Ok(false) => {}
                        // A refused migration is an attempted hijack: an authenticated contact
                        // naming ANOTHER contact's address to collapse the two onto one key
                        // (SEC-36). Swallowing the error would make the attempt invisible.
                        Err(e) => eprintln!("KARST: refusing a contact migration: {e}"),
                    }
                }
                continue;
            }
            _ => continue, // reactions / control
        };
        // NB: incoming text is persisted to history by `recv_session_multi` itself now
        // (plaintext-first, deduped by payload_id) — do NOT append it again here, or the
        // same message lands twice. We only build the UI event from the returned message.
        // First-contact: surface an unknown sender as a conversation (else the message is
        // decrypted + stored but never rendered — see `ensure_contact`).
        ensure_conversation(&root, r.sender);
        out.push(Incoming::text(r.sender, String::from_utf8_lossy(&text).into_owned(), ts, expire_at));
        }
        // Clear the parked log only now, AFTER every handler above has run. Clearing first would
        // recreate exactly the loss the log exists to prevent; clearing after makes the replay
        // at-least-once, and a repeat is the same duplicate ordinary delivery already tolerates.
        if replayed {
            if let Err(e) = root.clear_quarantine() {
                eprintln!("KARST: clearing the replayed message log: {e}");
            }
        }
    }
    // Crash-safe large-file downloads: driven once with the ROOT store (downloads + the relay
    // capability are device-shared, un-namespaced), off-thread with retry. New downloads surface
    // as progress bubbles via `out`.
    if let Some(relay) = primary {
        // The HIDDEN account doesn't accept bulk media — a large file would bloat the fixed-size
        // container (and its whole point is to stay light). Metadata/text still flow.
        if !app.is_hidden_session() {
            drive_pending_downloads(&app, &vault, &id, &relay, &root, &mut out);
        }
        drive_pending_post_attachments(&app, &relay, &root, &mut out);
        drive_pending_galleries(&app, &relay, &root, &mut out);
    }
    // SEC-34, THE durability barrier of this poll: commit the account's authority, and only then
    // tell the relays they may forget the ciphertext. For a container-backed session the authority
    // is the encrypted container (the work dir the code above wrote to is a materialized working
    // copy, and the next unlock restores the container, not it); for a file-tree session the
    // writes above already were the authority, so the barrier is a no-op that still gates the ack.
    //
    // Gated on `dirty || !acks.is_empty()` — never on `out` (see `dirty`'s definition). `dirty`
    // covers the case where leases were taken but nothing decoded; `!acks.is_empty()` cannot be
    // true without `dirty`, and is kept because it is what makes "leases exist ⇒ a commit ran"
    // true by reading, not by inference.
    if dirty || !acks.is_empty() {
        // In-flight inline chunks are durable from here on: their carrier messages are about to be
        // acked, so RAM is no longer a safe place to keep them. Inside the barrier, so the same
        // commit that the ack waits on covers them too.
        client::save_reassemblers(&root, &app.reasm.lock().unwrap());
        // The container mutex is taken INSIDE the closure so it is released before the ACK round
        // trips: `commit_then_send` does one network request per receipt after the commit, and
        // `lock` (the duress-adjacent path) takes this same mutex. Holding it across the acks
        // would make locking the app wait on a whole batch of relay round trips.
        let committed = acks.commit_then_send(now_secs(), || {
            match app.container.lock().unwrap().as_mut() {
                Some(cv) => cv.save().map_err(|e| e.to_string()),
                None => Ok(()), // file-tree session: the store IS the authority
            }
        });
        // Not fatal (unlike `lock`): nothing was deleted anywhere — the leases went UNSENT, so the
        // relays still hold this batch and redeliver it once the leases expire. But it must not be
        // silent, or a container that has quietly stopped persisting looks identical to a healthy
        // one. HONEST LIMIT on "redeliverable": the work dir still holds the advanced ratchet, so
        // within THIS session a redelivery fails closed and shows as nothing. The recovery is the
        // one that matters — after a relock/restart the container's older snapshot is restored and
        // the redelivered ciphertext opens against it.
        if let Err(e) = committed {
            eprintln!(
                "warning: could not persist this batch into the container: {e} — \
                 NOT acking, the relay keeps this batch and will redeliver it"
            );
        }
    }
    Ok(PollOut { messages: out, reachable: reach_any })
}

/// How many large-file downloads may run at once. Downloads are one thread each, and the pending
/// list is attacker-influenced (a peer sends the references), so this is the difference between a
/// queue and a thread flood.
const MAX_CONCURRENT_DOWNLOADS: usize = 4;

/// Spawn a crash-safe download thread for each pending large-file download not already in
/// flight. `client::download_blob` owns completion (records the file + history + drops the
/// pending entry) and retry semantics; here we only wire progress + the terminal UI state and
/// track which blobs have a live thread. A pending entry left by a transient failure is picked
/// up again on the next poll; a completed / gone / cancelled one is dropped by `download_blob`.
fn drive_pending_downloads(
    app: &App,
    vault: &Vault,
    id: &str,
    relay: &Relay,
    store: &Store,
    out: &mut Vec<Incoming>,
) {
    let pending = store.list_pending_downloads().unwrap_or_default();
    for pd in pending {
        // SEC-45: don't START a new download thread once Offline is set — the pending entry just
        // stays and the next (online) poll picks it up. Already-running download threads from an
        // EARLIER poll are handled separately, by `stop_for_offline` flipping their `cancel` flag.
        if app.offline.load(Ordering::SeqCst) {
            break;
        }
        // Bounded concurrency. This spawned ONE OS THREAD PER PENDING DOWNLOAD, and the number of
        // pending downloads is set by how many file references a peer chose to send — so a single
        // poll could start up to a thousand threads on the recipient's machine (A8-5). Anything
        // over the limit simply stays pending; the loop below already re-drives leftovers on the
        // next poll, and the blob lives on the relay until its TTL.
        if app.in_flight.lock().unwrap().len() >= MAX_CONCURRENT_DOWNLOADS {
            break;
        }
        // Skip a blob whose download thread is already running.
        if !app.in_flight.lock().unwrap().insert(pd.blob_id) {
            continue;
        }
        let tid = app.new_tid();
        let cancel = Arc::new(AtomicBool::new(false));
        let nm = sanitize_name(&pd.name);
        let ts = now_secs();
        app.transfers.lock().unwrap().insert(
            tid,
            TransferState {
                dir: "down",
                peer: pd.sender,
                name: nm.clone(),
                done: 0,
                total: pd.size,
                state: "active",
                file_id: None,
                error: None,
                finished_at: None,
                cancel: cancel.clone(),
            },
        );
        out.push(Incoming::transfer(pd.sender, tid, nm, pd.size, ts));

        let v = vault.clone();
        let aid = id.to_string();
        let relay = relay.clone();
        let transfers = app.transfers.clone();
        let in_flight = app.in_flight.clone();
        let offline = app.offline.clone();
        let pd_for_resume = pd.clone();
        std::thread::spawn(move || {
            let store = v.account(&aid);
            let outcome = client::download_blob(
                &store,
                &relay,
                &pd,
                now_secs(),
                &cancel,
                |done, total| transfer_progress_step(&transfers, tid, done, total),
            );
            match outcome {
                client::DownloadOutcome::Done(fid) => transfer_finish(&transfers, tid, "done", Some(fid), None),
                client::DownloadOutcome::GaveUp(e) if e == "cancelled" => {
                    let (state, error) = download_cancelled_outcome(&store, pd_for_resume, offline.load(Ordering::SeqCst));
                    transfer_finish(&transfers, tid, state, None, error);
                }
                client::DownloadOutcome::GaveUp(e) => transfer_finish(&transfers, tid, "error", None, Some(e)),
                // Transient: the pending entry stays; the next poll re-drives it.
                client::DownloadOutcome::Retry(e) => transfer_finish(&transfers, tid, "error", None, Some(e)),
            }
            in_flight.lock().unwrap().remove(&pd.blob_id);
        });
    }
}

/// What to do with a pending download's record once its thread's outcome is
/// `GaveUp("cancelled")`, and what to tell the UI. `client::download_blob` treats ANY cancel as a
/// permanent user abandon: it already deleted the partial file and dropped the pending entry (its
/// own doc: "the FileRef was already consumed"). That is the right call for the explicit Cancel
/// button, but SEC-45 says Offline must never silently drop received data just because the user
/// flipped a toggle — so when `was_offline` (this cancel was `stop_for_offline`'s, not a manual
/// abandon), re-persist a FRESH pending-download entry from the announcement the caller still
/// holds. The file then RE-FETCHES from scratch on the next online poll (the sender's blob still
/// lives on the relay until its TTL) instead of being gone — not byte-for-byte resumed, but never
/// lost. `container_id` is cleared: the partial container it pointed to was just deleted.
///
/// Pulled out of the download thread closure so it's unit-testable against a real `Store` without
/// a live relay: the whole point is a durable-storage side effect (a pending-download row lands
/// or it doesn't), which a fake in-memory stand-in can't verify.
fn download_cancelled_outcome(store: &Store, pd: client::store::PendingDownload, was_offline: bool) -> (&'static str, Option<String>) {
    if !was_offline {
        return ("cancelled", None); // a genuine manual abandon — download_blob already cleaned up
    }
    let mut resumed = pd;
    resumed.container_id = None;
    if store.add_pending_download(&resumed).is_ok() {
        ("cancelled", Some("stopped by Offline — will resume automatically when back online".into()))
    } else {
        // The pending-download queue is full (or unwritable) — re-queuing itself failed, so say
        // so plainly rather than claim a resume that didn't happen.
        ("error", Some("stopped by Offline and could not be re-queued — ask the sender to resend".into()))
    }
}

/// Fetch pending post-attachment blobs into the `feed_attachments` sidecar — the receive side of the
/// #98 blob transport. Unlike `drive_pending_downloads`, these are NOT user-visible file transfers:
/// they're small feed media (bounded by `MAX_POST_IMAGE_BYTES`), fetched in-memory here on the poll
/// thread (already off the UI thread) and surfaced as a COALESCED `post` nudge so the feed
/// re-renders + re-hydrates once. Bounded per poll so one cycle never blocks on a long backlog — the
/// pending entries persist and the next poll drains more. `store` is the ROOT (feed/pending sidecars
/// live on the shared root paths, like downloads).
fn drive_pending_post_attachments(app: &App, relay: &Relay, store: &Store, out: &mut Vec<Incoming>) {
    /// Cap the work one poll does, so a big backlog is drained across cycles, not in one long stall.
    const MAX_PER_POLL: usize = 16;
    let pending = store.list_pending_post_attachments().unwrap_or_default();
    let mut done_senders: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for ppa in pending.into_iter().take(MAX_PER_POLL) {
        // SEC-45: stop starting NEW fetches once Offline is set; the entry stays pending for the
        // next (online) poll. HONEST LIMIT: `download_post_attachment` takes no cancel flag (see
        // the report) — a fetch already started when this check passes runs to completion, though
        // it's small (bounded by MAX_POST_IMAGE_BYTES) so that's at most a handful of chunks.
        if app.offline.load(Ordering::SeqCst) {
            break;
        }
        // Skip an entry another overlapping poll is already fetching (in_flight is keyed by blob_id,
        // which is unique across downloads + post attachments — both are random 32-byte ids).
        if !app.in_flight.lock().unwrap().insert(ppa.blob_id) {
            continue;
        }
        let outcome = client::download_post_attachment(store, relay, &ppa, now_secs());
        app.in_flight.lock().unwrap().remove(&ppa.blob_id);
        if let client::DownloadOutcome::Done(_) = outcome {
            done_senders.insert(ppa.sender);
        }
        // Transient (Retry) leaves the pending entry for the next poll; GaveUp already dropped it.
    }
    // One coalesced feed nudge per author whose media landed, so the feed re-renders + re-hydrates
    // the new attachment (the same signal the inline path emits on assembly).
    for s in done_senders {
        out.push(Incoming::post(s, String::new(), now_secs()));
    }
}

/// Fetch pending GALLERY blobs (the blob-path receive side), replacing each sender's peer photos on
/// completion. Mirrors `drive_pending_post_attachments`: bounded per poll, in_flight-guarded,
/// Retry leaves the entry, GaveUp already dropped it. Emits a `gallery` nudge so an open profile
/// re-renders (the same signal the inline `Assembled::Gallery` path emits).
fn drive_pending_galleries(app: &App, relay: &Relay, store: &Store, out: &mut Vec<Incoming>) {
    const MAX_PER_POLL: usize = 8;
    let pending = store.list_pending_galleries().unwrap_or_default();
    for pg in pending.into_iter().take(MAX_PER_POLL) {
        // SEC-45: same choke as `drive_pending_post_attachments` — same honest limit too
        // (`download_gallery` takes no cancel flag; an already-started fetch finishes).
        if app.offline.load(Ordering::SeqCst) {
            break;
        }
        if !app.in_flight.lock().unwrap().insert(pg.blob_id) {
            continue;
        }
        let outcome = client::download_gallery(store, relay, &pg, now_secs());
        app.in_flight.lock().unwrap().remove(&pg.blob_id);
        if let client::DownloadOutcome::Done(_) = outcome {
            out.push(Incoming::gallery(pg.sender));
        }
    }
}

/// Decrypt a received file into memory and hand it to the webview (base64) so it can trigger a
/// browser download — the sealed-at-rest file becomes plaintext only on this explicit action.
#[tauri::command]
fn export_file(app: State<App>, file_id: String) -> Result<Exported, String> {
    if app.is_hidden_session() {
        return Err("the hidden account keeps everything inside the container — exporting to disk would leave a trace".into());
    }
    let (store, _) = app.snapshot()?;
    let name = store.received_file_name(&file_id).map_err(|e| format!("reading file: {e}"))?;
    // Guard the IPC: a file received from a CLI/egui peer can be arbitrarily large (the blob
    // path streams multi-GB into the sealed file), but we buffer + base64 the whole thing to
    // hand it to the webview. Refuse before loading it into RAM.
    let sealed = store.received_file_size(&file_id).unwrap_or(0);
    if sealed > MAX_ATTACH_BYTES as u64 {
        return Err(format!(
            "'{name}' is too large to open in the app (max {} MB) — export it with the CLI",
            MAX_ATTACH_BYTES / (1024 * 1024)
        ));
    }
    let bytes = store.read_received_file(&file_id).map_err(|e| format!("decrypting file: {e}"))?;
    Ok(Exported { name, data: STANDARD.encode(&bytes) })
}

/// Snapshot of all live + just-finished transfers, for the UI's fast progress poll. Prunes
/// terminal transfers ~10 s after they finish (a grace window so a missed poll can't lose the
/// terminal state — the JS finalizes a bubble idempotently and ignores later updates).
#[tauri::command]
fn transfer_progress(app: State<App>) -> Vec<TransferInfo> {
    let now = now_secs();
    let mut m = app.transfers.lock().unwrap();
    m.retain(|_, t| t.finished_at.is_none_or(|f| now.saturating_sub(f) < 10));
    m.iter()
        .map(|(tid, t)| TransferInfo {
            tid: *tid,
            dir: t.dir,
            sender: hex::encode(t.peer),
            name: t.name.clone(),
            done: t.done,
            total: t.total,
            state: t.state,
            file_id: t.file_id.clone(),
            error: t.error.clone(),
        })
        .collect()
}

/// Cancel an in-flight transfer: flips its cancel flag; the upload/download thread ends at the
/// next chunk boundary with a "cancelled" terminal state (leaving no partial). A cancelled
/// download is not recoverable — its FileRef was already consumed.
#[tauri::command]
fn cancel_transfer(app: State<App>, tid: u64) {
    if let Some(t) = app.transfers.lock().unwrap().get(&tid) {
        t.cancel.store(true, Ordering::Relaxed);
    }
}

/// Sweep any stale hidden-account tmpfs work dirs left by a crash/kill/quit (they hold the hidden
/// account's plaintext in RAM and are normally deleted on lock; a non-clean exit skips that). Run at
/// startup so a machine lost or stolen after a crash doesn't still have a hidden account materialized.
fn sweep_stale_hidden_tmpfs() {
    let shm = std::path::Path::new("/dev/shm");
    if let Ok(rd) = std::fs::read_dir(shm) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.starts_with("karst-hid-") {
                continue;
            }
            if !hidden_dir_owner_is_gone(&name) {
                continue; // another process is USING it — deleting it would break a live session
            }
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// May this hidden-account directory be swept? Only when nobody is using it: either it is ours
/// (we just started, so it is a leftover of a previous run of this PID) or the process named in
/// its `-p<pid>` suffix no longer exists. A name without a suffix predates per-process naming and
/// cannot belong to a live session of this build, so it is collectable.
fn hidden_dir_owner_is_gone(name: &str) -> bool {
    let Some(pid) = name.rsplit_once("-p").and_then(|(_, p)| p.parse::<u32>().ok()) else {
        return true;
    };
    if pid == std::process::id() {
        return true;
    }
    !std::path::Path::new(&format!("/proc/{pid}")).exists()
}

fn main() {
    sweep_stale_hidden_tmpfs();
    tauri::Builder::default()
        .manage(App::default())
        .invoke_handler(tauri::generate_handler![
            account_exists,
            vault_dir,
            set_vault_dir,
            folder_has_account,
            pick_folder,
            generate_phrase,
            create_account,
            unlock,
            container_create,
            container_unlock,
            container_flush,
            container_active,
            container_hidden,
            container_add_hidden,
            container_add_cover,
            container_add_wipe,
            net_offline,
            set_net_offline,
            hidden_payload,
            set_hidden_container,
            set_relay,
            extra_relays,
            add_extra_relay,
            remove_extra_relay,
            import_capability,
            net,
            relay_lines,
            safety_number,
            lock,
            accounts,
            switch_account,
            show_phrase,
            security_state,
            add_decoy_password,
            add_wipe_password,
            remove_extra_password,
            set_deadman,
            channel_state,
            set_channel_mode,
            subscribe,
            pending_subscribers,
            approve_subscriber,
            reject_subscriber,
            reconnect_peer,
            discovery_status,
            discovery_on,
            discovery_rotate,
            discovery_off,
            create_invite,
            list_invites,
            revoke_invite,
            add_by_code,
            proxies,
            create_proxy,
            burn_proxy,
            contacts_on_proxy,
            migrate_channel,
            me,
            save_profile,
            set_avatar,
            gallery,
            set_gallery,
            create_post,
            delete_post,
            feed,
            post_images,
            post_attachments,
            save_post_attachment,
            peer_avatar,
            posts_of,
            view_profile,
            peer_profile,
            contacts,
            subscribers,
            add_contact,
            start_conversation,
            contact_requests,
            accept_contact_request,
            decline_contact_request,
            set_verified,
            rename_contact,
            remove_contact,
            clear_conversation,
            history,
            send,
            disappearing,
            set_disappearing,
            send_file,
            file_begin,
            file_push,
            file_commit,
            file_abort,
            offer_route,
            poll,
            cover_tick,
            export_file,
            save_received_file,
            received_files,
            all_received_files,
            transfer_progress,
            cancel_transfer,
            outbox_pending,
        ])
        .run(tauri::generate_context!())
        .expect("error while running KARST");
}

#[cfg(test)]
mod tests {
    use super::{
        append_chunk, transfer_finish, App, PostsReplyBudget, PostsReplySlot, TransferState,
        MAX_STREAM_BYTES, POSTS_PULL_LIMIT, POSTS_REPLY_BUDGET, POSTS_REPLY_MAX_ACTIVE,
        POSTS_REPLY_WINDOW_SECS,
    };
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    /// A minimal `TransferState` for tests that only care about the cancel/state machinery, not
    /// the transfer's own bookkeeping fields.
    fn fake_transfer(cancel: Arc<AtomicBool>) -> TransferState {
        TransferState {
            dir: "up",
            peer: [0u8; 32],
            name: "f".into(),
            done: 0,
            total: 10,
            state: "active",
            file_id: None,
            error: None,
            finished_at: None,
            cancel,
        }
    }

    /// Poll `flag` for up to ~10s (sleeping briefly between checks, never busy-spinning) and
    /// return whether it became true. `stop_for_offline` only re-checks every `STOP_WAIT_STEP`
    /// (20ms), so a `yield_now` loop with a fixed ITERATION cap is the wrong bound: it can burn
    /// through its whole budget in far less than one real tick and falsely report "never
    /// happened". Bounding on wall time that safely spans several ticks (well past
    /// `STOP_WAIT_STEPS * STOP_WAIT_STEP`'s own ~5s budget) instead makes this reliable — the
    /// PASS/FAIL fact under test is still "did the flag become true", not "how fast".
    fn spin_wait(flag: &AtomicBool, order: Ordering) -> bool {
        for _ in 0..2000 {
            if flag.load(order) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        false
    }

    /// SEC-45 — going Offline used to flip a bool and report success immediately while an
    /// already-running upload/download thread kept using the relay handle it captured before the
    /// flip. `stop_for_offline` must actually cancel it (the same `AtomicBool` convention
    /// `cancel_transfer` already uses) AND wait for it to actually stop before returning — not
    /// just ask and hope.
    ///
    /// The fake worker below stands in for `client::download_blob`/`blob_upload_with`'s chunk
    /// loop: it "emits" (increments a counter) once per iteration and checks its OWN cancel flag,
    /// exactly like a real chunked transfer checks at a chunk boundary, then reports itself
    /// terminal.
    #[test]
    fn stop_for_offline_cancels_an_active_transfer_and_waits_for_it_to_actually_stop() {
        let app = App::default();
        let tid = 1u64;
        let cancel = Arc::new(AtomicBool::new(false));
        app.transfers.lock().unwrap().insert(tid, fake_transfer(cancel.clone()));

        let emissions = Arc::new(AtomicU64::new(0));
        let transfers = app.transfers.clone();
        let worker_cancel = cancel.clone();
        let worker_emissions = emissions.clone();
        let handle = std::thread::spawn(move || loop {
            if worker_cancel.load(Ordering::SeqCst) {
                transfer_finish(&transfers, tid, "cancelled", None, None);
                return;
            }
            worker_emissions.fetch_add(1, Ordering::SeqCst);
            std::thread::yield_now();
        });
        // Don't race the worker's very first iteration — let it actually run before we stop it,
        // so a no-op "fix" can't pass by sheer luck of the worker never having started.
        while emissions.load(Ordering::SeqCst) == 0 {
            std::thread::yield_now();
        }

        super::stop_for_offline(&app).expect("the fake worker always honors cancel — this must converge, never time out");
        handle.join().unwrap();

        assert!(cancel.load(Ordering::SeqCst), "stop_for_offline must flip the transfer's cancel flag");
        assert_ne!(
            app.transfers.lock().unwrap().get(&tid).unwrap().state,
            "active",
            "stop_for_offline returned but the transfer it was supposed to stop is still marked active"
        );
    }

    /// SEC-45 — `drive_pending_downloads` reads `offline` and THEN (racily) inserts a fresh
    /// `TransferState { cancel: false, .. }` and spawns its thread; that insert can land AFTER
    /// `stop_for_offline` has already taken a snapshot of `transfers`. This proves the fix for
    /// that race: the cancel-flip must repeat every wait tick, not just once up front, so a
    /// transfer that appears mid-wait still gets caught within one tick.
    ///
    /// Determinism (no `yield_now`/sleep race to prove ordering): a CANARY transfer is inserted
    /// BEFORE the waiter even starts, so it is swept by any implementation's very first flip pass
    /// — bounded-spinning on ITS cancel flag going true is a real, observable proof that at least
    /// one flip pass has already completed, with no reliance on scheduling luck. Only once that is
    /// confirmed do we insert the LATE transfer, which a "flip once up front" implementation can no
    /// longer ever touch — reproducing the actual race deterministically instead of hoping the
    /// insert happens to land inside a timing window.
    #[test]
    fn a_transfer_registered_after_stop_for_offline_has_already_started_waiting_is_still_cancelled() {
        let app = Arc::new(App::default());
        let guard = super::NetGuard::enter(&app.net_active); // keeps stop_for_offline from returning at all yet

        let canary_tid = 0u64;
        let canary_cancel = Arc::new(AtomicBool::new(false));
        app.transfers.lock().unwrap().insert(canary_tid, fake_transfer(canary_cancel.clone()));

        let app2 = app.clone();
        let waiter = std::thread::spawn(move || super::stop_for_offline(&app2));

        // Bounded spin proving the flip logic has run at least once. A busy `yield_now` loop is
        // NOT good enough here: `stop_for_offline` only re-checks every `STOP_WAIT_STEP` (20ms),
        // and a tight `yield_now` loop can burn through a large iteration count in well under
        // that — "gave up" would then look identical to "never flipped". Sleeping a little each
        // iteration bounds this on real ticks instead of raw iteration count, while the CAP still
        // makes it a bounded wait, not an open-ended one.
        assert!(
            spin_wait(&canary_cancel, Ordering::SeqCst),
            "the canary transfer (present since before the waiter started) must have been cancelled"
        );

        // NOW insert the late transfer — deterministically after at least one flip pass, exactly
        // reproducing "this transfer did not exist for the earlier snapshot(s)."
        let tid = 1u64;
        let cancel = Arc::new(AtomicBool::new(false));
        app.transfers.lock().unwrap().insert(tid, fake_transfer(cancel.clone()));
        assert!(!waiter.is_finished(), "stop_for_offline must still be blocked on the held guard");

        drop(guard); // release — the NEXT tick can now converge, re-flipping cancel first

        assert!(spin_wait(&cancel, Ordering::SeqCst), "the late-registered transfer's cancel flag must have been flipped");
        // Stand in for the real worker threads reporting themselves terminal once they see cancel.
        transfer_finish(&app.transfers, tid, "cancelled", None, None);
        transfer_finish(&app.transfers, canary_tid, "cancelled", None, None);

        let result = waiter.join().unwrap();
        assert!(
            result.is_ok(),
            "once every transfer reports terminal, stop_for_offline must converge, not time out: {result:?}"
        );
        assert_ne!(app.transfers.lock().unwrap().get(&tid).unwrap().state, "active");
    }

    /// Control: with `stop_for_offline` never invoked (ordinary online operation), a transfer's
    /// cancel flag stays untouched and it keeps "emitting" — the machinery above must not affect
    /// a session that never goes offline.
    #[test]
    fn an_ordinary_online_transfer_is_never_touched_by_the_offline_machinery() {
        let app = App::default();
        let tid = 1u64;
        let cancel = Arc::new(AtomicBool::new(false));
        app.transfers.lock().unwrap().insert(tid, fake_transfer(cancel.clone()));

        let emissions = Arc::new(AtomicU64::new(0));
        let worker_cancel = cancel.clone();
        let worker_emissions = emissions.clone();
        let handle = std::thread::spawn(move || {
            for _ in 0..500 {
                if worker_cancel.load(Ordering::SeqCst) {
                    return; // would mean something cancelled it — the control asserts this never fires
                }
                worker_emissions.fetch_add(1, Ordering::SeqCst);
                std::thread::yield_now();
            }
        });
        handle.join().unwrap();

        assert_eq!(emissions.load(Ordering::SeqCst), 500, "ordinary online work must run to completion, uninterrupted");
        assert!(!cancel.load(Ordering::SeqCst), "nothing should have cancelled it — offline was never involved");
        assert_eq!(
            app.transfers.lock().unwrap().get(&tid).unwrap().state,
            "active",
            "an unfinished transfer stays active when nothing asked it to stop"
        );
    }

    /// SEC-45 — a `poll`/`cover_tick`/PostsRequest-reply call holds a `NetGuard` for as long as it
    /// might still touch the wire, and `stop_for_offline` is supposed to wait for every such guard
    /// to release before claiming success. This proves the wait is real, not a no-op: while a
    /// guard is held, `stop_for_offline` (run on another thread, since it blocks) must NOT have
    /// returned yet — checked deterministically (a bounded spin on `JoinHandle::is_finished`, not
    /// a wall-clock delay) — and only reports success once the guard is actually released.
    #[test]
    fn stop_for_offline_does_not_return_while_a_guarded_background_call_still_holds_net_active() {
        let app = Arc::new(App::default());
        let guard = super::NetGuard::enter(&app.net_active);
        assert_eq!(app.net_active.load(Ordering::SeqCst), 1, "the guard must be visible while held");

        let proceed = Arc::new(AtomicBool::new(false));
        let exited = Arc::new(AtomicBool::new(false));
        let proceed2 = proceed.clone();
        let exited2 = exited.clone();
        let holder = std::thread::spawn(move || {
            let _guard = guard; // released only when this returns
            while !proceed2.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
            exited2.store(true, Ordering::SeqCst);
        });

        let app2 = app.clone();
        let waiter = std::thread::spawn(move || super::stop_for_offline(&app2));

        // The holder cannot release until `proceed` is set, and no transfers exist, so a correct
        // `stop_for_offline` has nothing to do BUT wait on `net_active` — it must still be
        // running. A version that forgot to check `net_active` would already show finished here.
        for _ in 0..2000 {
            assert!(
                !waiter.is_finished(),
                "stop_for_offline returned success while a guarded background call still held net_active"
            );
            std::thread::yield_now();
        }

        proceed.store(true, Ordering::SeqCst);
        let result = waiter.join().unwrap();
        holder.join().unwrap();

        assert!(result.is_ok(), "once the guard is released, stop_for_offline must report success: {result:?}");
        assert!(exited.load(Ordering::SeqCst), "the background call must have actually run to its own exit");
        assert_eq!(app.net_active.load(Ordering::SeqCst), 0, "the guard must be released, not leaked");
    }

    /// SEC-45's "never silently drop user data" bar for downloads: `download_blob` treats any
    /// cancel — including one Offline caused — as a permanent abandon (it already deleted the
    /// partial + dropped the pending entry). `download_cancelled_outcome` is what stops that from
    /// meaning "the file is just gone": when the cancel was Offline's, it must re-persist a fresh
    /// pending-download row so the file re-fetches on the next online poll.
    #[test]
    fn an_offline_triggered_download_cancel_is_re_queued_so_the_file_is_not_lost() {
        let dir = std::env::temp_dir().join(format!("karst-desktop-test-offline-resume-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = client::store::Store::unlock(&dir, b"pw").unwrap();
        let pd = client::store::PendingDownload {
            blob_id: [9u8; 32], key: [1u8; 32], hash: [2u8; 32], name: "photo.jpg".into(),
            size: 100, chunks: 2, sender: [3u8; 32], ts: 1, queued_at: 1,
            container_id: Some("stale-partial-id".into()), // the partial download_blob just deleted
        };

        let (state, error) = super::download_cancelled_outcome(&store, pd.clone(), true);
        assert_eq!(state, "cancelled");
        assert!(
            error.as_deref().unwrap_or("").contains("resume"),
            "the UI must be told this will come back on its own: {error:?}"
        );
        let requeued = store.list_pending_downloads().unwrap();
        assert_eq!(requeued.len(), 1, "the announcement must be re-persisted, not lost");
        assert_eq!(requeued[0].blob_id, pd.blob_id);
        assert_eq!(requeued[0].container_id, None, "the deleted partial's container id must not be reused");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The manual Cancel button is a genuine, intentional abandon — `download_cancelled_outcome`
    /// must NOT auto-resume that (only an Offline-caused cancel gets re-queued), or clicking
    /// Cancel would silently keep re-fetching a file the user explicitly gave up on.
    #[test]
    fn a_manually_cancelled_download_is_not_auto_requeued() {
        let dir = std::env::temp_dir().join(format!("karst-desktop-test-manual-cancel-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = client::store::Store::unlock(&dir, b"pw").unwrap();
        let pd = client::store::PendingDownload {
            blob_id: [9u8; 32], key: [1u8; 32], hash: [2u8; 32], name: "photo.jpg".into(),
            size: 100, chunks: 2, sender: [3u8; 32], ts: 1, queued_at: 1, container_id: None,
        };

        let (state, error) = super::download_cancelled_outcome(&store, pd, false);
        assert_eq!(state, "cancelled");
        assert!(error.is_none(), "a manual cancel carries no Offline-specific message");
        assert!(
            store.list_pending_downloads().unwrap().is_empty(),
            "a manual abandon must stay abandoned, not silently come back"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn streamed_chunks_accumulate_in_order() {
        let mut sends = HashMap::new();
        sends.insert("u".to_string(), Vec::new());
        append_chunk(&mut sends, "u", b"hello ", MAX_STREAM_BYTES).unwrap();
        append_chunk(&mut sends, "u", b"world", MAX_STREAM_BYTES).unwrap();
        assert_eq!(sends.get("u").unwrap(), b"hello world");
    }

    #[test]
    fn a_stream_that_would_exceed_the_cap_is_rejected_and_dropped() {
        let mut sends = HashMap::new();
        sends.insert("u".to_string(), Vec::new());
        // First chunk fits under a tiny cap; the second would blow it.
        append_chunk(&mut sends, "u", &[0u8; 4], 8).unwrap();
        let err = append_chunk(&mut sends, "u", &[0u8; 8], 8).unwrap_err();
        assert!(err.contains("exceeds"), "{err}");
        // The buffer is dropped on rejection, so a hostile stream frees its memory immediately.
        assert!(!sends.contains_key("u"), "the rejected buffer must be removed");
    }

    #[test]
    fn pushing_to_an_unknown_id_errors() {
        let mut sends: HashMap<String, Vec<u8>> = HashMap::new();
        assert!(append_chunk(&mut sends, "nope", b"x", MAX_STREAM_BYTES).is_err());
    }

    /// **A3-10 — a streamed upload must not survive an account switch.** `file_begin` mints the id
    /// under one account; `file_commit` dispatches through whatever session is current when it runs.
    /// `reset_transient` — the single choke point every account change goes through — cleared the
    /// inline reassembly buffers and the transfers but not `pending_sends`, so a file begun as
    /// account A could be committed, and sent, as account B.
    ///
    /// Discriminating: it asserts the entry is GONE, which is exactly what a later `file_commit`
    /// keys off ("unknown upload id"). Neuter by removing the `pending_sends` line from
    /// `reset_transient` and the id survives the switch → RED. The `reasm` half is asserted
    /// alongside it purely as a control: it proves the reset ran at all, so a failure on
    /// `pending_sends` can only mean that one line.
    #[test]
    fn an_account_switch_drops_a_half_uploaded_file() {
        let app = App::default();
        app.pending_sends.lock().unwrap().insert("upload-a".into(), vec![1, 2, 3]);
        app.reasm.lock().unwrap().insert([9u8; 32], Default::default());

        app.reset_transient();

        assert!(
            app.pending_sends.lock().unwrap().is_empty(),
            "an upload begun by the previous account must not be committable by the next one"
        );
        assert!(app.reasm.lock().unwrap().is_empty(), "control: the reset did run");
    }

    /// A3-7 — the startup sweep must never delete a directory another process is USING.
    ///
    /// It used to remove every `karst-hid-*`, so launching a second window wiped the live
    /// plaintext work dir of the first — which kept running against a Store whose files had
    /// vanished. The name now carries the owning PID, and only our own or a dead owner's
    /// directory is collectable.
    #[test]
    fn the_sweep_spares_a_live_owner_and_collects_the_dead() {
        let me = std::process::id();
        assert!(
            super::hidden_dir_owner_is_gone(&format!("karst-hid-abc-p{me}")),
            "our own leftover is collectable"
        );
        // PID 1 always exists on Linux and is not us — stands in for another live instance.
        assert!(
            !super::hidden_dir_owner_is_gone("karst-hid-abc-p1"),
            "a LIVE owner's directory must be left alone — deleting it breaks that session"
        );
        // A PID that cannot be running (kernel max is far below this) → collectable.
        assert!(
            super::hidden_dir_owner_is_gone("karst-hid-abc-p4294967290"),
            "a dead owner's directory is collectable"
        );
        // Pre-per-process names carry no owner and cannot belong to a live session of this build.
        assert!(super::hidden_dir_owner_is_gone("karst-hid-abc"), "unowned legacy name is collectable");
    }

    /// SEC-30 — one unsolicited `PostsRequest` used to buy a feed load, an OS thread and up to
    /// `POSTS_PULL_LIMIT` outgoing publication sends, with nothing bounding how often. This pins
    /// the property that replaces it: however many requests arrive, from however many DISTINCT
    /// senders, the sends they can cause in one window are capped and the threads are capped.
    ///
    /// Every peer here is a fresh identity key, which is the point — an attacker gets a new one
    /// per request for free, so anything keyed per-peer would report success while the flood went
    /// through. Counting, no clock: `now` is passed in, so the window is exercised without ever
    /// measuring elapsed time.
    #[test]
    fn a_flood_of_posts_requests_cannot_exceed_the_windows_reply_budget() {
        let b = Arc::new(Mutex::new(PostsReplyBudget::default()));
        let now = 1_000_000;

        let mut granted_total = 0usize;
        let mut slots: Vec<PostsReplySlot> = Vec::new();
        let mut peak_active = 0usize;
        for _ in 0..500 {
            // Each iteration stands for a request from a brand-new sender.
            let granted = b.lock().unwrap().admit(now, POSTS_PULL_LIMIT);
            if granted > 0 {
                granted_total += granted;
                slots.push(PostsReplySlot(b.clone()));
                peak_active = peak_active.max(b.lock().unwrap().active);
            }
        }
        assert!(
            granted_total <= POSTS_REPLY_BUDGET,
            "500 requests were allowed {granted_total} sends; the window's ceiling is \
             {POSTS_REPLY_BUDGET}"
        );
        assert!(
            peak_active <= POSTS_REPLY_MAX_ACTIVE,
            "{peak_active} reply jobs ran at once; the ceiling is {POSTS_REPLY_MAX_ACTIVE}"
        );

        // Slots are returned when the jobs end, but the SPENT budget is not — otherwise the
        // concurrency cap alone would let a serial flood spend without limit.
        drop(slots);
        assert_eq!(b.lock().unwrap().active, 0, "finished jobs must release their slot");
        assert_eq!(
            b.lock().unwrap().admit(now, POSTS_PULL_LIMIT),
            0,
            "the window's budget must stay spent after its jobs finish"
        );

        // ...and the next window refills, so this is a bound on rate, not a permanent shutdown.
        assert!(
            b.lock().unwrap().admit(now + POSTS_REPLY_WINDOW_SECS, POSTS_PULL_LIMIT) > 0,
            "the budget must refill — a live pull that never recovers is a broken feature"
        );
    }

    /// SEC-31, the inline half. The blob-pointer path is gated in the client; the inline chunk path
    /// reaches the same feed sidecar and had no gate at all, so a stranger could still stream post
    /// media at a client that would never show their posts.
    ///
    /// Discriminating in three directions, because two of them are ways to get this wrong: the
    /// stranger's post manifests are refused, a subscribed channel's identical manifests are
    /// admitted, and a FILE manifest from the same stranger is still admitted — chats are open to
    /// anyone, and a gate that also closed those would break ordinary first-contact file sending.
    #[test]
    fn only_a_feed_source_may_open_an_inline_post_media_transfer() {
        use client::content::Content;
        let dir = std::env::temp_dir().join(format!("karst-inline-gate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = client::store::Store::unlock(&dir, b"pw").unwrap();
        let stranger = [0x41u8; 32];
        let channel = [0x42u8; 32];
        store.set_channel_peer(channel, true).unwrap();

        let post_img =
            Content::PostImageManifest { post_id: [1; 16], id: [2; 16], size: 10, chunks: 1, hash: [3; 32] };
        let post_att = Content::PostAttachmentManifest {
            post_id: [1; 16],
            index: 0,
            kind: 0,
            name: String::new(),
            id: [4; 16],
            size: 10,
            chunks: 1,
            hash: [3; 32],
        };
        let file = Content::FileManifest { id: [5; 16], name: "n".into(), size: 10, chunks: 1, hash: [3; 32] };

        assert!(!super::inline_transfer_admitted(&store, &stranger, &post_img));
        assert!(!super::inline_transfer_admitted(&store, &stranger, &post_att));
        assert!(super::inline_transfer_admitted(&store, &channel, &post_img));
        assert!(super::inline_transfer_admitted(&store, &channel, &post_att));
        assert!(
            super::inline_transfer_admitted(&store, &stranger, &file),
            "an ordinary file from a stranger is a CONVERSATION, not feed content — still allowed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The other direction: an ordinary client with a handful of public posts must not burn a
    /// full `POSTS_PULL_LIMIT` reservation per visitor. Reserving the worst case is what lets the
    /// admission decision happen BEFORE the feed is read (the read is itself per-request work),
    /// so the unused remainder has to come back.
    #[test]
    fn an_unused_reply_reservation_is_returned_to_the_window() {
        let mut b = PostsReplyBudget::default();
        let now = 2_000_000;
        // An account with three public posts. Without the refund the FIRST visitor would reserve
        // all 30 and the second would already be turned away; with it, the window pays only for
        // sends actually made, so the budget stretches to `POSTS_REPLY_BUDGET / 3` visitors.
        let visitors = POSTS_REPLY_BUDGET / 3;
        for i in 0..visitors {
            let granted = b.admit(now, POSTS_PULL_LIMIT);
            assert!(granted >= 3, "visitor {i} was refused while the window still had budget");
            b.refund(granted - 3);
            b.active -= 1; // the job finished
        }
        assert_eq!(b.spent, visitors * 3, "the window must be charged for sends made, not reserved");
    }

    /// The refund's own failure mode, and the common one: a client with NO public posts. Every
    /// request still costs two sealed-file reads to discover there is nothing to answer with, so
    /// if the reservation comes back in full the window never fills and the rate is unbounded —
    /// `POSTS_REPLY_MAX_ACTIVE` would bound threads at any instant but nothing would bound how
    /// many requests a mailbox burst could put through the feed decrypt. The floor of one unit per
    /// admitted request is what closes that.
    ///
    /// Discriminating: neutering the floor back to `refund(granted - posts.len())` lets this run
    /// forever without ever being refused.
    #[test]
    fn answering_nothing_still_costs_the_window_a_unit() {
        let mut b = PostsReplyBudget::default();
        let now = 3_000_000;
        let mut admitted = 0usize;
        for _ in 0..500 {
            let granted = b.admit(now, POSTS_PULL_LIMIT);
            if granted == 0 {
                break;
            }
            admitted += 1;
            let posts = 0usize; // nothing public to serve
            b.refund(granted - posts.max(1)); // the floor
            b.active -= 1;
        }
        assert_eq!(
            admitted, POSTS_REPLY_BUDGET,
            "a client with no public posts must still be able to refuse: {admitted} empty replies \
             were admitted against a budget of {POSTS_REPLY_BUDGET}"
        );
    }
}
