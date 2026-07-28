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
    offline: Mutex<bool>,
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
        if *self.offline.lock().unwrap() {
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
    /// half-received inline files, and CANCEL + drop any in-flight transfers so a new account
    /// never inherits another's threads or partial files.
    fn reset_transient(&self) {
        self.reasm.lock().unwrap().clear();
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
    relays
}

/// Announce our bundle to every relay (best-effort; a dead relay is not fatal).
/// Active proxy indices (channels currently offered), lowest first. Empty if none yet.
fn active_proxies(store: &Store) -> Vec<u32> {
    let mut v: Vec<u32> = store.load_proxies().into_iter().filter(|p| p.active).map(|p| p.index).collect();
    v.sort_unstable();
    v
}

/// The default proxy (lowest active index), provisioning proxy 0 if the account has none. The
/// proxy-identity model NEVER puts the root on the wire, so there must always be ≥1 proxy — a new
/// or pre-proxy account gets one here at first publish/send.
fn default_proxy(store: &Store) -> u32 {
    active_proxies(store).first().copied().unwrap_or_else(|| {
        store.create_proxy("default", now_secs()).map(|e| e.index).unwrap_or(0)
    })
}

/// The proxy that reaches a contact — their tag if set, else the default proxy.
fn proxy_for_contact(store: &Store, ik: &[u8; 32]) -> u32 {
    store.contact_proxy(ik).unwrap_or_else(|| default_proxy(store))
}

/// Announce presence. ROOT-NEVER-PUBLISHES INVARIANT: publish each ACTIVE PROXY's bundle via
/// `as_proxy`, never the root account — so the permanent identity never appears on a relay. A
/// proxy shares the device's relay capability (un-namespaced); publish itself is capability-free
/// on the reference relay, so a fresh proxy still announces.
fn do_publish(store: &Store, relays: &[Relay], offline: bool) {
    // The ONE choke every publish goes through: OFFLINE emits nothing, so no caller can accidentally
    // leak a bundle (some read `s.relays` directly, bypassing `relays_or_empty`).
    if offline || relays.is_empty() {
        return;
    }
    let mut proxies = active_proxies(store);
    if proxies.is_empty() {
        proxies.push(default_proxy(store));
    }
    for pidx in proxies {
        let p = store.as_proxy(pidx);
        let cap = p.load_capability().unwrap_or_else(|_| client::dev_capability());
        let _ = client::publish_all(&p, relays, cap, now_secs());
    }
}

fn me_of(store: &Store, id: &str) -> Me {
    let prof = store.load_profile().unwrap_or_default();
    // Proxy-identity model: "your address" is your DEFAULT PROXY's IK, never the root (which has
    // no address on the wire). This is the address others reach you at.
    let ik = store
        .as_proxy(default_proxy(store))
        .load_account()
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
    *app.offline.lock().unwrap() = offline;
    let store = vault.account(&id);
    // Refresh the DEV capability so an account made on an older build picks up quota changes (the
    // dev cap's request/byte window grew a lot so multi-image posts fit). ONLY overwrite our own
    // forgeable dev cap (id 0xCA..), never a real imported capability.
    if store.load_capability().map(|c| c.capability_id == [0xCA; 16]).unwrap_or(true) {
        let _ = store.save_capability(&client::dev_capability());
    }
    let relays = build_relays(&store);
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
    let store = vault.account(&id);
    if !store.has_capability() {
        let _ = store.save_capability(&client::dev_capability());
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
    let main_cap = n / 4 * 3; // reserve ~1/4 for the (future) hidden tail
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
    let store = vault.account(&id);
    if !store.has_capability() {
        let _ = store.save_capability(&client::dev_capability());
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
    .map_err(|_| "wrong password".to_string())?;
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
    *app.offline.lock().unwrap()
}

/// Toggle OFFLINE mode. Going ONLINE announces the account's bundle once (so it becomes reachable);
/// going offline stops all network activity. For a hidden account this is the deliberate,
/// user-controlled sync window — the rest of the time it emits nothing.
#[tauri::command]
fn set_net_offline(app: State<App>, offline: bool) -> Result<(), String> {
    *app.offline.lock().unwrap() = offline;
    if !offline {
        // Coming online: publish the bundle so the account is reachable this session.
        let (store, relays) = app.snapshot()?;
        do_publish(&store, &relays, *app.offline.lock().unwrap());
    }
    Ok(())
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
    let res = cv.add_hidden(hidden_password.as_bytes(), |region_key| {
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
            let store = hvault.account(&id);
            if !store.has_capability() {
                let _ = store.save_capability(&client::dev_capability());
            }
            client::container::snapshot_dir(&build)
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
    if let Ok(cap) = client::earn_capability(&relay) {
        let _ = store.save_capability(&cap);
    }
    s.relays = build_relays(&store);
    do_publish(&store, &s.relays, *app.offline.lock().unwrap());
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
    do_publish(&store, &s.relays, *app.offline.lock().unwrap());
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
    // Type inferred from `save_capability(&cap)` — no need to name the capability type here.
    let cap = serde_json::from_str(invite_json.trim()).map_err(|e| format!("parsing invite: {e}"))?;
    let (store, relays) = app.snapshot()?;
    store.save_capability(&cap).map_err(|e| format!("writing capability: {e}"))?;
    do_publish(&store, &relays, *app.offline.lock().unwrap());
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
    let relay = relays.into_iter().next().ok_or("no relay configured")?;
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
    if let Some(relay) = relays.into_iter().next() {
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
        if let Some(relay) = relays.first() {
            let ps = root.as_proxy(proxy_for_contact(&root, &peer));
            // A conversation-only peer must NOT receive your profile — send an EMPTY opener (it still
            // re-runs PQXDH to heal the session). A confirmed contact gets your real profile.
            let (n, b) = if root.is_confirmed_contact(&peer).unwrap_or(false) {
                let prof = root.load_profile().unwrap_or_default();
                (prof.name, prof.bio)
            } else {
                (String::new(), String::new())
            };
            let _ = client::send_profile(&ps, relay, &peer, &n, &b, now_secs());
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
    active: bool,
    created_at: u64,
    /// The proxy's derived identity key, hex — the disposable address for this channel.
    ik: String,
}

fn proxy_of(store: &Store, e: &client::store::ProxyEntry) -> Proxy {
    let ik = store
        .proxy_identity(e.index)
        .map(|d| hex::encode(d.account.identity_public()))
        .unwrap_or_default();
    Proxy { index: e.index, label: e.label.clone(), active: e.active, created_at: e.created_at, ik }
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
    let cap = np.load_capability().unwrap_or_else(|_| client::dev_capability());
    let _ = client::publish_all(&np, &relays, cap, now_secs());
    Ok(proxy_of(&store, &e))
}

/// Burn a proxy: stop offering it (its contacts can no longer be reached through it). Reversible
/// flag flip; the keys stay derivable so any last in-flight mail still decrypts.
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
    store.set_proxy_active(index, false).map_err(|e| e.to_string())
}

/// Contacts currently reached through proxy `index` — the migration picker's default set.
#[tauri::command]
fn contacts_on_proxy(app: State<App>, index: u32) -> Result<Vec<Contact>, String> {
    let (store, _) = app.snapshot()?;
    let profiles = store.load_peer_profiles().unwrap_or_default();
    let channels = store.load_channel_peers();
    let dflt = default_proxy(&store);
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
#[tauri::command]
fn migrate_channel(app: State<App>, old_index: u32, contacts: Vec<String>, new_label: String) -> Result<Proxy, String> {
    let (store, relays) = app.snapshot()?;
    let relay = relays.first().cloned().ok_or("no relay configured")?;
    // Mint + publish the new channel so contacts can open a session to it.
    let new_e = store.create_proxy(new_label.trim(), now_secs()).map_err(|e| format!("creating channel: {e}"))?;
    let np = store.as_proxy(new_e.index);
    let cap = np.load_capability().unwrap_or_else(|_| client::dev_capability());
    let _ = client::publish_all(&np, &relays, cap, now_secs());
    let new_ik = np.load_account().map_err(|e| e.to_string())?.identity_public();
    // Over the OLD channel's authenticated session, tell each chosen contact to move; re-tag locally.
    let old = store.as_proxy(old_index);
    for hex_ik in &contacts {
        if let Ok(peer) = parse_ik(hex_ik) {
            let _ = client::send_channel_migrate(&old, &relay, &peer, new_ik, now_secs());
            let _ = store.set_contact_proxy(peer, new_e.index);
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
    let dp = store.as_proxy(default_proxy(&store));
    let code = client::discovery_code(&dp)?;
    Ok(DiscoveryStatus { on: code.is_some(), code })
}

/// Turn discovery ON (mint + publish) and return the persistent contact code to share.
#[tauri::command]
fn discovery_on(app: State<App>) -> Result<String, String> {
    let (store, relays) = app.snapshot()?;
    let relay = relays.into_iter().next().ok_or("configure a relay first")?;
    client::discovery_publish(&store.as_proxy(default_proxy(&store)), &relay, now_secs())
}

/// Rotate the persistent contact code (old one stops resolving); returns the fresh code.
#[tauri::command]
fn discovery_rotate(app: State<App>) -> Result<String, String> {
    let (store, relays) = app.snapshot()?;
    let relay = relays.into_iter().next().ok_or("configure a relay first")?;
    client::discovery_rotate(&store.as_proxy(default_proxy(&store)), &relay, now_secs())
}

/// Turn discovery OFF: delete the relay record (best-effort) and clear the local key.
#[tauri::command]
fn discovery_off(app: State<App>) -> Result<(), String> {
    let (store, relays) = app.snapshot()?;
    let dp = store.as_proxy(default_proxy(&store));
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

/// Mint a ONE-TIME invite code to hand to one person (self-consumes on first use).
#[tauri::command]
fn create_invite(app: State<App>) -> Result<String, String> {
    let (store, relays) = app.snapshot()?;
    let relay = relays.into_iter().next().ok_or("configure a relay first")?;
    client::discovery_one_time(&store.as_proxy(default_proxy(&store)), &relay, now_secs())
}

/// Add a contact by a CONTACT CODE (persistent or one-time): resolve it to an IK at the relay
/// (the binding is self-verified — the relay never vouches), then save the contact. Returns the
/// resolved IK hex so the UI can open the chat. A one-time code is consumed by the relay here.
#[tauri::command]
fn add_by_code(app: State<App>, code: String, name: String, via_proxy: Option<u32>) -> Result<String, String> {
    let (store, relays) = app.snapshot()?;
    let relay = relays.into_iter().next().ok_or("configure a relay first")?;
    let (ik, _loc) = client::find_contact(&relay, code.trim(), now_secs())?;
    let mut cs = store.load_contacts().map_err(|e| e.to_string())?;
    if !cs.iter().any(|c| c.ik == ik) {
        // Empty name resolves to the peer's own profile name / a short IK at display time.
        cs.push(ContactRecord { name: name.trim().to_string(), ik, verified: false });
        store.save_contacts(&cs).map_err(|e| e.to_string())?;
    }
    // Looking someone up by their code is an EXPLICIT add → a confirmed contact (unlocks their
    // name/posts as they arrive), not a mere conversation.
    let _ = store.set_unconfirmed(ik, false);
    // The channel of OURS they'll see us on — chosen, else default (never the root).
    let proxy = via_proxy.unwrap_or_else(|| default_proxy(&store));
    let _ = store.set_contact_proxy(ik, proxy);
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
    if let (Some(relay), Ok(contacts)) = (relays.first().cloned(), store.load_contacts()) {
        // Only CONFIRMED contacts receive your profile — a conversation-only peer never does.
        let unconfirmed = store.load_unconfirmed().unwrap_or_default();
        let contacts: Vec<_> = contacts.into_iter().filter(|c| !unconfirmed.contains(&c.ik)).collect();
        let (v, aid) = (vault.clone(), id.clone());
        let (n, b) = (prof.name.clone(), prof.bio.clone());
        std::thread::spawn(move || {
            let store = v.account(&aid);
            let now = now_secs();
            for c in contacts {
                // Send each contact your profile AS the proxy they know (never the root identity).
                let ps = store.as_proxy(proxy_for_contact(&store, &c.ik));
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
    if let Some(relay) = relays.into_iter().next() {
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
    let _ = store.delete_conversation(ik_b);
    let _ = store.remove_peer_profile(ik_b);
    let _ = store.remove_contact_request(ik_b);
    let _ = store.set_unconfirmed(ik_b, false); // clear the chat-only flag so no orphan lingers
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
        if let Some(relay) = relays.into_iter().next() {
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
    if *app.offline.lock().unwrap() {
        return Err("you're offline — turn off Offline mode in Settings to send".into());
    }
    let peer = parse_ik(&peer_ik)?;
    let (root, relays) = app.snapshot()?;
    // Proxy-identity model: talk to this contact AS the proxy they know (their tag, or the default
    // proxy). Network state rides the proxy; history/prefs it reads/writes are shared root data.
    let store = root.as_proxy(proxy_for_contact(&root, &peer));
    let relay = relays.first().ok_or("no relay configured — set one in settings")?;
    let ts = now_secs();
    let ttl = store.load_prefs().map(|p| p.disappearing_secs).unwrap_or(0);
    if ttl > 0 {
        // Disappearing: send as TextExpiring, do NOT append to history. Both sides drop it at
        // `expire_at`; nothing durable is written on either end.
        client::send_text_expiring(&store, relay, &peer, text.as_bytes(), ttl, ts)?;
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
    let delivered = client::send_text(&store, relay, &peer, text.as_bytes(), ts, ts)?;
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
    let relay = relays.first().cloned().ok_or("no relay configured — set one in settings")?;
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
    std::thread::spawn(move || {
        let root = vault.account(&id);
        let store = root.as_proxy(proxy_for_contact(&root, &peer)); // the FileRef rides the contact's proxy
        let res = (|| -> Result<(), String> {
            let (blob_id, key, hash, chunks) = client::blob_upload_with(
                &relay,
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
            Err(e) if e == "cancelled" => transfer_finish(&transfers, tid, "cancelled", None, None),
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
    let Ok(mut cs) = root.load_contacts() else { return };
    if cs.iter().any(|c| c.ik == ik) {
        return; // already known — leave their confirmed/unconfirmed status untouched
    }
    // No frozen name: an EMPTY label resolves to the peer's self-declared profile name ONLY once
    // confirmed, else a short IK, and stays renameable — you never get stuck with a hex stub.
    cs.push(ContactRecord { name: String::new(), ik, verified: false });
    if root.save_contacts(&cs).is_ok() {
        let _ = root.set_unconfirmed(ik, true); // chat-only until explicitly added to contacts
    }
}

/// Ensure `ik` is a CONFIRMED contact: add the record if new AND clear any unconfirmed flag. Used
/// when a mutual add completes (ContactAccept) or the user explicitly confirms — this is what
/// unlocks showing their name/avatar/posts and fanning ours out to them.
fn ensure_confirmed_contact(root: &Store, ik: [u8; 32]) {
    let Ok(mut cs) = root.load_contacts() else { return };
    if !cs.iter().any(|c| c.ik == ik) {
        cs.push(ContactRecord { name: String::new(), ik, verified: false });
        let _ = root.save_contacts(&cs);
    }
    let _ = root.set_unconfirmed(ik, false); // promote to a confirmed contact
}

/// Whether `ik`'s publications belong in our feed: an account we SUBSCRIBED to, OR one we live-pulled
/// from (visited their profile). Posts are decoupled from contacts — you subscribe to follow, or pull
/// to peek; a pulled author's reply posts land in their profile view.
fn is_feed_source(store: &Store, ik: &[u8; 32]) -> bool {
    store.load_channel_peers().contains(ik) || store.load_pulled().is_ok_and(|s| s.contains(ik))
}

/// COVER-TRAFFIC tick (Loopix-style, opt-in): emit ONE dummy deposit through the exact real send
/// path (per active proxy), so an observer can't read this client's real send timing from the wire.
/// The JS fires this on a Poisson (exponential-interval) schedule while cover traffic is enabled.
/// Honest scope: additive noise masking THIS client's timing — not full unobservability.
#[tauri::command]
async fn cover_tick(app: State<'_, App>) -> Result<(), String> {
    // OFFLINE mode must emit NOTHING — cover traffic is a network deposit, so skip it too.
    if *app.offline.lock().unwrap() {
        return Ok(());
    }
    let (root, relays) = app.snapshot()?;
    let Some(relay) = relays.into_iter().next() else { return Ok(()) };
    let mut proxies = active_proxies(&root);
    if proxies.is_empty() {
        proxies.push(default_proxy(&root));
    }
    // A cover deposit from ONE random proxy this tick (not all — that would itself be a pattern).
    let idx = proxies[(now_secs() as usize) % proxies.len()];
    let ps = root.as_proxy(idx);
    std::thread::spawn(move || {
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
    // OFFLINE mode: emit nothing — no relay round trips at all, so there is no network signal.
    if *app.offline.lock().unwrap() {
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
        proxies.push(default_proxy(&root));
    }
    // A relay counts as reachable if ANY proxy's poll reached it this pass.
    let mut reach_any = vec![false; relays.len()];
    // PROXY-IDENTITY MODEL: poll EACH proxy's mailbox (never the root). `store` below is the proxy
    // handle — its NETWORK state (sessions/opks) is per-proxy, while the history/feed/files it
    // writes land on the shared ROOT data paths, so incoming lands in one unified inbox.
    for pidx in proxies {
        let store = root.as_proxy(pidx);
        // Send-side retry + MULTI-HOMING on the poll cadence: retransmit (verbatim) any queued
        // message across EVERY relay, so a down/blocked primary doesn't strand it — the first
        // reachable relay delivers it and it's removed from the outbox (the rest then have nothing
        // to flush). The recipient polls all relays + dedups, so wherever it lands, they get it.
        for p in &relays {
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
            let poll = match client::recv_session_multi(&store, &relays, now_secs()) {
                Ok(p) => p,
                Err(_) => break,
            };
            for (i, ok) in (0..relays.len()).map(|i| !poll.failed.contains(&i)).enumerate() {
                if ok {
                    reach_any[i] = true;
                }
            }
            let before = drained.len();
            drained.extend(poll.messages.into_iter().flatten());
            if drained.len() == before {
                break; // empty page → mailbox drained this pass
            }
        }
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
                let mut reasm = app.reasm.lock().unwrap();
                let re = reasm.entry(r.sender).or_default();
                match re.offer(c, now_secs()) {
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
                        if let Some(relay) = relays.first() {
                            let _ = client::send_join_accept(&store, relay, &r.sender, is_channel, now_secs());
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
            Content::JoinAccept { is_channel } => {
                let _ = store.set_channel_peer(r.sender, is_channel);
                out.push(Incoming::join(r.sender, "accepted"));
                continue;
            }
            // A live-pull visitor asked for our posts: answer with our recent PUBLIC posts only (never
            // a narrow-audience post) as ordinary Publications, so they can view us without
            // subscribing. Best-effort, off-thread; only public ids in `public_posts` qualify.
            Content::PostsRequest => {
                if let Some(relay) = relays.first().cloned() {
                    let public = store.load_public_posts().unwrap_or_default();
                    let own = store.load_account().ok().map(|a| a.identity_public()).unwrap_or([0u8; 32]);
                    let mut posts: Vec<_> = store
                        .load_feed()
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|f| f.author == own && f.expire_at.is_none() && public.contains(&f.id))
                        .collect();
                    posts.sort_by_key(|f| std::cmp::Reverse(f.ts));
                    posts.truncate(POSTS_PULL_LIMIT);
                    let ps = store.as_proxy(proxy_for_contact(&store, &r.sender));
                    let to = r.sender;
                    std::thread::spawn(move || {
                        let now = now_secs();
                        for f in posts {
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
            Content::ContactAccept { name, bio } => {
                let _ = store.set_peer_profile(r.sender, &name, &bio);
                ensure_confirmed_contact(&root, r.sender);
                out.push(Incoming::contactreq(r.sender, "accepted"));
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
            Content::ChannelMigrate { new_ik } => {
                if new_ik != r.sender {
                    if let Ok(true) = root.migrate_contact_ik(r.sender, new_ik) {
                        out.push(Incoming::migrate(r.sender, new_ik));
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
    // Persist a container-backed account after receiving (design: save on each message; a poll
    // batches a burst into one save). No-op for the file-tree path.
    if !out.is_empty() {
        if let Some(cv) = app.container.lock().unwrap().as_mut() {
            // Not fatal here (unlike `lock`): nothing is deleted, the work dir still holds the
            // data and the next poll's save retries. But it must not be SILENT, or a container
            // that has quietly stopped persisting looks identical to one that is fine.
            if let Err(e) = cv.save() {
                eprintln!("warning: could not persist this batch into the container: {e}");
            }
        }
    }
    Ok(PollOut { messages: out, reachable: reach_any })
}

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
                client::DownloadOutcome::GaveUp(e) if e == "cancelled" => transfer_finish(&transfers, tid, "cancelled", None, None),
                client::DownloadOutcome::GaveUp(e) => transfer_finish(&transfers, tid, "error", None, Some(e)),
                // Transient: the pending entry stays; the next poll re-drives it.
                client::DownloadOutcome::Retry(e) => transfer_finish(&transfers, tid, "error", None, Some(e)),
            }
            in_flight.lock().unwrap().remove(&pd.blob_id);
        });
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
    use super::{append_chunk, MAX_STREAM_BYTES};
    use std::collections::HashMap;

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
}
