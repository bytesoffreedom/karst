//! Хранение секретов клиента на диске под **at-rest шифрованием**.
//!
//! Секретные файлы (`identity.key`, `account.key`, `sessions.dat`) шифруются
//! `MasterKey` (`Argon2id(passphrase)` — см. `secretbox`) и лежат под 0600 (файл
//! создаётся СРАЗУ под 0600, не write-then-chmod). Защита ХОЛОДНОГО диска, НЕ
//! hot-процесса (см. `secretbox`). `capability.json` НЕ шифруется (дев-артефакт с
//! публичным секретом; настоящий провижининг — отдельный слой). Ключи relay
//! шифрованием НЕ покрыты (сервер рестартует unattended — своя граница доверия).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use admission::capability::Capability;
use karst_client_core::peer::PeerState;
use node::pqxdh::Account;
use node::seal::Identity;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::secretbox::{random_salt, MasterKey};

/// Контакт на диске: имя (алиас) + §2.1-IK + был ли сверен код безопасности.
/// Шифруется at-rest вместе со всем списком. `verified` — доверие подтверждено
/// пользователем по OOB-каналу (не выводимо из relay, только локальная пометка).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactRecord {
    pub name: String,
    pub ik: [u8; 32],
    pub verified: bool,
}

/// An invite this identity minted and has not retired: the discovery secret that owns its row at
/// the relay, plus when it was made and when the row lapses on its own. `secret` authorises
/// rewriting/deleting exactly that one discovery row — nothing decrypts with it (see the invite
/// section on `Store`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteRecord {
    pub secret: [u8; 32],
    pub created_at: u64,
    pub expiry: u64,
}

/// Where a contact said they are reachable: the relay descriptor that rode INSIDE the contact
/// code's IK-signed binding, plus when we resolved it. Provenance is the point — this descriptor
/// is signed by the contact's own identity key, unlike a gossiped node-list hint (CRYPTO-23),
/// which is why it is adoptable as a route for THAT contact and a hint is not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactEndpoint {
    pub relay: node::protocol::RelayDescriptor,
    pub discovered_at: u64,
}

/// SELF-DECLARED profile. Own profile lives in `profile.dat`; contacts' profiles in
/// the `peer_profiles.dat` sidecar (keyed by IK). NOT identity: the trust anchor is
/// the safety number + the local label/`verified` in `ContactRecord`; a received
/// profile never touches them (Principle 7). `avatar` holds image bytes (PNG),
/// populated by a SEPARATE slice (chunked, does not fit a packet) — always `None` in
/// Phase 1. postcard-positional: append fields ONLY at the end.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub bio: String,
    pub avatar: Option<Vec<u8>>,
    /// Extra profile PHOTOS beyond `avatar` — a small gallery (Telegram-style). Ordered by insertion;
    /// bounded to `MAX_GALLERY_PHOTOS`, each an avatar-sized image. Fanned to CONFIRMED contacts as one
    /// atomic transfer. postcard-positional: appended AFTER `avatar`; append ONLY at the end.
    pub photos: Vec<Vec<u8>>,
    /// Sender-clock timestamp of the gallery currently in `photos` — set from the packed blob on a
    /// RECEIVED gallery, so a stale copy arriving out of order (the same gallery can arrive twice via
    /// the inline and blob paths) is not applied over a newer one. 0 = unknown/own. postcard-appended.
    pub photos_ts: u64,
}

/// Одна запись истории чата (шифруется at-rest как отдельная запечатанная запись).
/// `peer_ik` — §2.1-IK собеседника (ключ чата, к кому/от кого); `from_me` —
/// исходящее ли; `text` — plaintext сообщения; `ts` — unix-секунды.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryRecord {
    pub from_me: bool,
    pub peer_ik: [u8; 32],
    pub text: Vec<u8>,
    pub ts: u64,
}

/// One publication in the feed (`feed.dat`) — a broadcast "post", either OUR own (author =
/// our IK) or one RECEIVED from a contact (author = their IK). Stored separately from chat
/// history because a publication is a timeline entry, not a 1:1 message. `expire_at` is
/// reserved for the ephemeral "story" variant (a follow-up); `None` = a permanent post.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedRecord {
    pub author: [u8; 32],
    pub id: [u8; 16],
    pub text: String,
    pub ts: u64,
    pub expire_at: Option<u64>,
}

/// One attachment on a post (multi-attachment posts), stored in the `feed_attachments` sidecar
/// keyed by (author, post_id). `kind` = 0 image / 1 file; `index` orders them; `name` is the file
/// name (empty for an image). Bytes are the already-encoded, bounded payload (same size gate as a
/// post image), inline like `feed_images` — no relay blob.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
///
/// NOTE: no field here carries `serde(default)`. Trailing-field defaults let an OLDER binary read
/// a NEWER record, silently drop the fields it does not know and write the loss straight back
/// (A6-5). `secretbox::STATE_VERSION` replaced that: change this struct, bump the version, and an
/// older build refuses the file out loud instead.
pub struct StoredAttachment {
    pub index: u32,
    pub kind: u8,
    pub name: String,
    pub bytes: Vec<u8>,
    /// A terminal FAILURE marker (blob-transport path): the fetch gave up (blob swept, hash
    /// mismatch, past TTL) so the bytes will never arrive. Kept as a zero-byte marker (not silently
    /// dropped) so the feed can show an error tile instead of the attachment just vanishing. A later
    /// successful fetch at the same index replaces it.
    pub failed: bool,
}

/// An authenticated message this build could not APPLY, parked before it was acked
/// (see [`Store::quarantine_incoming`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantinedMessage {
    pub sender: [u8; 32],
    pub plaintext: Vec<u8>,
    pub received_at: u64,
}

/// One message this build durably queued for delivery (`karst_client_core::peer::Peer::queue`) but has not
/// yet resolved — delivered, evicted, or expired. `PeerState`'s own outbox holds only ciphertext
/// keyed by an opaque id; once an entry is gone there, there is no way to ask it "whose message
/// was that". This is the client's own memory of that mapping, so a LATER loss (see
/// [`StrandedSend`]) can still be attributed to what it was, not just that it happened (R2-6).
/// Removed the moment its id resolves — delivered, evicted, or expired — so it never grows
/// beyond roughly what `karst_client_core::peer`'s own outbox cap allows.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingSend {
    pub id: u64,
    pub peer_ik: [u8; 32],
    pub plaintext: Vec<u8>,
    pub queued_at: u64,
}

/// Defensive ceiling on the pending-send ledger. In normal operation it never holds more than
/// `karst_client_core::peer`'s own outbox cap (512 as of this writing) — every entry here names one still-
/// queued outbox id — but that constant is private to `karst_client_core::peer` and this file cannot see it,
/// so this is our OWN generous headroom rather than the real number: a loud refusal if
/// reconciliation ever fell far enough behind to blow through it (a bug, not normal operation).
const MAX_LEDGER: usize = 4096;

/// A message that was durably queued (ratchet advanced, ciphertext committed to `sessions.dat`)
/// but will never reach a relay: `karst_client_core::peer`'s outbox cap evicted it to admit something newer,
/// or its TTL expired first. Either way the ratchet already moved past this position — there is
/// nothing to retry, only something to tell the user about instead of the "sent" they would
/// otherwise see (#215/R2-6). Durably appended by [`Store::park_stranded_send`], read back by
/// [`Store::load_stranded_sends`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrandedSend {
    pub peer_ik: [u8; 32],
    pub plaintext: Vec<u8>,
    /// When the sender originally queued it.
    pub queued_at: u64,
    /// When THIS build noticed it was gone (not when it actually vanished — nothing observes
    /// that moment directly for an eviction that happens inside another call, or a TTL sweep
    /// this process never ran).
    pub lost_at: u64,
    /// `"evicted"` — this build watched the outbox fail to grow right after queuing a message
    /// and could name exactly which older id had to make room for it; `"expired"` — a later
    /// flush found the id gone without ever having witnessed an eviction, so it aged out past
    /// its TTL instead. Attributed, never guessed at a distance — see `queue_and_note` in
    /// `lib.rs`.
    pub reason: String,
}

/// Channel configuration (`channel.dat`, sealed, LOCAL-ONLY). `enabled` = channel mode: the
/// account auto-accepts every subscribe request (a public channel) instead of queuing it for
/// manual approval (a private account). SECURITY INVARIANT: this bit is written ONLY by the
/// password-gated `set_channel_mode` path — no received-message code path ever writes it, so
/// nothing on the wire can flip an account into a channel. Its own file (not `Prefs`) to keep
/// that boundary crisp and avoid postcard-positional coupling.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelConfig {
    pub enabled: bool,
}

/// One subscriber to OUR posts (they asked to follow; we accepted — auto, if a channel, or
/// manually). Separate from contacts: a subscriber follows your feed but isn't necessarily
/// someone you chat with. `since` is when they were accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscriber {
    pub ik: [u8; 32],
    pub since: u64,
}

/// The on-disk history record: a `HistoryRecord` plus the `payload_id` (`msg_id`) of the
/// sealed envelope an INCOMING message was decrypted from (zeroed for outgoing / legacy
/// records). The id is kept OUT of `HistoryRecord` (which has ~50 construction sites) and
/// here at the storage boundary instead, so it costs no churn. It exists so the receive
/// path can persist plaintext BEFORE the ratchet commit and dedup a redelivered message by
/// id (the crash-before-save window). postcard-positional: appended after `rec`, so a
/// pre-`msg_id` record — bare `postcard(HistoryRecord)` — loads via the scan fallback.
#[derive(Clone, Serialize, Deserialize)]
struct StoredHistory {
    rec: HistoryRecord,
    msg_id: [u8; 32],
}

/// A received file's lookup record — the `files/` container hides sender/name/time inside the
/// sealed blob (the directory is random ids on purpose), so this small SEALED index is how a
/// client re-associates a saved file with WHO sent it and WHEN (for a per-contact file list and
/// for reattaching a download to a chat bubble after a restart). It carries exactly the metadata
/// the sealed-file format exists to hide, so it is sealed at rest like the files themselves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceivedFile {
    /// The `files/` container id (`<id>.dat`).
    pub id: String,
    pub name: String,
    pub size: u64,
    pub sender: [u8; 32],
    pub ts: u64,
    /// The source blob id, so a crash-safe download can tell "already completed" from
    /// "retry me" idempotently. Zero for the inline (non-blob) path.
    pub blob_id: [u8; 32],
}

/// A large-file download that was announced (a `FileRef` arrived) but not yet completed —
/// persisted so a crash mid-download can retry instead of losing the file. The blob lives on
/// the relay until its TTL, so the retry simply re-fetches. Keyed by `blob_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDownload {
    pub blob_id: [u8; 32],
    pub key: [u8; 32],
    pub hash: [u8; 32],
    pub name: String,
    pub size: u64,
    pub chunks: u32,
    pub sender: [u8; 32],
    pub ts: u64,
    /// When the FileRef was received (wall-clock). Used to give up once the blob's TTL has
    /// certainly passed, so a blob the relay swept can't leave an immortal retry entry.
    pub queued_at: u64,
    /// The `files/<id>.dat` container this download is streaming into, once the first attempt
    /// created it — so a retry RESUMES the same partial (skipping already-fetched chunks)
    /// instead of restarting. `None` before the first attempt. On any inconsistency the
    /// download degrades gracefully to a fresh start (the orphan sweep cleans the stale one).
    pub container_id: Option<String>,
}

/// A post ATTACHMENT announced by a `PostAttachmentRef` (blob transport) but not yet fetched —
/// persisted (before the ack) so a crash mid-fetch retries instead of losing the media, exactly
/// like [`PendingDownload`]. It is kept SEPARATE from `PendingDownload` on purpose: post
/// attachments are small (bounded by `MAX_POST_IMAGE_BYTES`), land in the `feed_attachments`
/// sidecar keyed by `(author, post_id, index)` rather than the files list, and must NOT surface as
/// a user-visible file transfer. Fetched in-memory (no on-disk resume needed at this size); a
/// failed attempt simply re-fetches from the blob (which lives on the relay until its TTL). Keyed
/// by `blob_id` (unique per recipient per attachment), so a redelivered ref is idempotent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingPostAttachment {
    pub blob_id: [u8; 32],
    pub key: [u8; 32],
    pub hash: [u8; 32],
    pub post_id: [u8; 16],
    pub index: u32,
    pub kind: u8,
    pub name: String,
    pub size: u64,
    pub chunks: u32,
    /// The post's author (the sender of the ref) — the `feed_attachments` key alongside `post_id`.
    pub sender: [u8; 32],
    /// When the ref arrived (wall-clock); past the blob TTL the entry is dropped so a swept blob
    /// can't leave an immortal retry.
    pub queued_at: u64,
}

/// A pending profile-GALLERY blob fetch (the receive side of a `GalleryRef`). Keyed by `sender` —
/// each contact has exactly one gallery, so a newer ref from the same sender supersedes the old
/// pending fetch. On completion the whole gallery replaces the sender's `peer_profiles` photos.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingGallery {
    pub sender: [u8; 32],
    pub blob_id: [u8; 32],
    pub key: [u8; 32],
    pub hash: [u8; 32],
    pub size: u64,
    pub chunks: u32,
    /// When the ref arrived (wall-clock); past the blob TTL the entry is dropped so a swept blob
    /// can't leave an immortal retry.
    pub queued_at: u64,
}

/// A large-file UPLOAD in flight, persisted so a crashed/interrupted send RESUMES instead of
/// re-uploading. Keyed in the store by `upload_id` (a stable hash of recipient+name+size), so
/// re-running the same send finds this record and reuses its `blob_id`+`key` to continue from the
/// relay's watermark (`blob_upload_resumable`). Cleared once the `FileRef` has been sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingUpload {
    pub upload_id: [u8; 32],
    pub blob_id: [u8; 32],
    pub key: [u8; 32],
    pub to_ik: [u8; 32],
    pub name: String,
    pub size: u64,
    pub queued_at: u64,
    /// The source file path, so a GUI resume-on-restart can re-read it (the CLI re-reads via the
    /// re-run command, so it stores `None`).
    pub path: Option<String>,
}

/// The pre-`blob_id` on-disk `ReceivedFile`, for loading an index written before the field
/// existed (see `list_received_files`' scan fallback).
#[derive(Deserialize)]
struct ReceivedFileV0 {
    id: String,
    name: String,
    size: u64,
    sender: [u8; 32],
    ts: u64,
}

/// Верхняя граница на длину одной записи истории (защита от абсурдного length-
/// prefix'а из мусорного хвоста → не аллоцируем гигабайты по битой длине).
const MAX_HISTORY_RECORD: usize = 1 << 20; // 1 MiB — ample for any text

/// The sealed history index is rounded up to a multiple of this before sealing, so its length
/// stops tracking how many people you talk to and how much.
const HISTORY_INDEX_PAGE: usize = 4096;

/// Where each peer's records sit in `history.dat`, so opening one chat costs that chat.
///
/// # A cache, not a second source of truth
///
/// The log is authoritative and this is derived from it, entirely. `covered_upto` is the byte
/// offset already consumed, and the index is brought up to date lazily on READ by scanning only
/// what has been appended since. Nothing in the append path touches it, which is the point: a
/// message write stays one `fsync` of one file, and there is no window where a crash freezes a
/// disagreement between index and log. The worst a crash does is leave the index behind, and
/// being behind is its ordinary state.
///
/// Truncation is handled by the same field. `load_history` cuts a torn tail, so the log can get
/// SHORTER; `covered_upto` past the end of the file means the bytes it described are gone, and
/// the index is rebuilt from zero rather than patched.
///
/// # Why there is no HMAC here, though the plan asked for one
///
/// The plan said `HMAC(index_key, peer_ik) → offsets`, to keep identity keys off the disk in the
/// clear. They are not in the clear either way: this file is sealed with the store key exactly
/// like the history records, and those records already carry `peer_ik` inside their own sealed
/// plaintext. An HMAC would add a key-derivation path and protect nothing the AEAD already does
/// — ceremony that reads as security. It becomes necessary the moment this index is written
/// unsealed or handed to anything but this store, which is the condition to re-check before
/// deleting this paragraph.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct HistoryIndex {
    covered_upto: u64,
    peers: Vec<([u8; 32], Vec<u64>)>,
}

/// Decode one history record's plaintext, tolerating the pre-`msg_id` layout.
///
/// Shared by the full scan and the index refresh so the two can never disagree about what counts
/// as a decodable record — a split between them would show up as a chat that is complete in one
/// view and missing its oldest messages in the other.
fn decode_stored_history(plain: &[u8]) -> Option<StoredHistory> {
    match postcard::from_bytes::<StoredHistory>(plain) {
        Ok(s) => Some(s),
        Err(_) => postcard::from_bytes::<HistoryRecord>(plain)
            .ok()
            .map(|rec| StoredHistory { rec, msg_id: [0u8; 32] }),
    }
}

/// How many recent incoming `msg_id`s the dedup ring keeps. Must be >= the window any caller
/// asks `recent_incoming_ids` for (`client::HISTORY_DEDUP_WINDOW`), or the answer would silently
/// be short and a duplicate would slip through. 2048 leaves a factor of two of headroom.
const DEDUP_RING_CAP: usize = 2048;

/// Cap on the number of cached peer profiles (anti-flood from unknown IKs).
const MAX_PEER_PROFILES: usize = 10_000;
/// SEC-44: cap on distinct peer IKs auto-registered from RECEIVED traffic — `contacts.dat`
/// (via `add_unconfirmed_contact`), `unconfirmed.dat`, and `contact_proxy.dat` (via
/// `set_contact_proxy`). All three are whole-file postcard blobs rewritten IN FULL on every
/// change (same shape as `contacts.dat`/`blocked.dat` elsewhere in this file: small lists meant
/// for a single GUI writer, not an append log), so admitting one more entry costs O(current
/// size) — a stream of N fresh sender IKs (free to mint; no identity cost) would otherwise cost
/// O(N^2) total disk I/O with an unbounded ceiling on N. This does NOT cap an EXPLICIT
/// `add_contact` from the user — only the automatic, attacker-reachable registration path.
/// Matches `MAX_PEER_PROFILES`: the same class of "anti-flood from unknown IKs" cap already
/// accepted for `peer_profiles.dat`.
const MAX_CONTACTS: usize = 10_000;
/// Cap on connection proxies in one root's registry. Generous for real use (one per contact/group
/// over a long time) while bounding `proxies.dat` and the poll fan-out that iterates them.
const MAX_PROXIES: usize = 10_000;
/// Cap on channel subscribers (people who follow your posts).
///
/// **A PRODUCT DECISION, not a data-structure bound** — see `docs/design/audience-scale.md`.
/// Publication is per-recipient: a post is encrypted separately for every subscriber over that
/// subscriber's own ratchet, and an attached image is uploaded once per recipient as its own blob
/// under its own key. That is what stops the relay reading an audience off its own disk — there is
/// no shared ciphertext for N recipients to fetch, so there is no set to observe — and it costs
/// LINEARLY in the audience.
///
/// This was 50 000, which quietly permitted a scale the crypto model charges linearly for.
/// "Mass reach" and "the relay cannot see who your audience is" cannot both be had, and nothing
/// said which one KARST gives up. It gives up reach.
///
/// 512 is where the cost becomes visible rather than where the container stops: one post with one
/// 300 KB image is ~150 MB of upload for the publisher, which is already at the edge of usable on
/// a mobile link. A cap set where the model stops being honest beats one set where the map runs
/// out of memory.
///
/// Anti-Sybil at the same time: a flood of join requests cannot grow `subscribers.dat` without
/// bound. On overflow a new subscriber is REFUSED, not silently dropped (existing ones keep
/// working) — the same discipline `MAX_MAILBOXES` and `MAX_SESSIONS` follow, because a silent
/// drop would leave a publisher believing they have readers they do not have.
const MAX_SUBSCRIBERS: usize = 512;
/// Cap on PENDING join requests awaiting manual approval (private account). Bounds the queue
/// against a flood; on overflow new requests from unknown IKs are dropped.
const MAX_PENDING_SUBS: usize = 5_000;
/// Cap on retained feed publications: bounds `feed.dat` size (on overflow the OLDEST posts by
/// ts are dropped). NOTE this cap is GLOBAL, not per-author (unlike `MAX_PEER_PROFILES`), so a
/// single contact flooding posts can still evict other contacts' and your own older posts — a
/// known limit; a per-author bound is a follow-up. Generous for a real timeline.
const MAX_FEED_POSTS: usize = 5_000;
/// Per-author cap on retained feed posts. Bounds any SINGLE author's share so a flooding contact
/// can only push out their own oldest, never other people's posts or yours (the flaw the global
/// cap alone had). Generous for a real person's timeline.
const MAX_FEED_POSTS_PER_AUTHOR: usize = 1_000;
/// Cap on the number of feed images retained in the `feed_images.dat` sidecar. Each image is
/// ≤ `MAX_POST_IMAGE_BYTES` (96 KiB), so this bounds the sidecar to ~48 MiB regardless of how
/// many text-only posts the feed holds. On overflow the images for the OLDEST posts (by their
/// feed `ts`) are dropped first; an image is also removed as soon as its post leaves the feed.
const MAX_FEED_IMAGES: usize = 500;
/// Total byte budget for the multi-attachment sidecar (`feed_attachments.dat`). A flood of
/// attachment posts evicts the OLDEST posts' attachments (by feed ts), never unbounded storage.
const MAX_FEED_ATTACH_BYTES: usize = 24 * 1024 * 1024;
/// Cap on concurrently-pending large-file downloads (bounds the retry file against a flood
/// of FileRefs; well past any real conversation's in-flight transfers).
const MAX_PENDING_DOWNLOADS: usize = 1024;
/// Magic that prefixes a version-enveloped at-rest blob (see `Store::seal_versioned` and
/// docs/design/format-versioning.md). Distinctive so it can't collide with a bare postcard
/// blob's leading bytes.
const FORMAT_MAGIC: &[u8; 4] = b"KRV1";
/// Current on-disk version of the pending-downloads store.
const DOWNLOADS_VERSION: u8 = 1;
/// Cap on concurrently-pending large-file UPLOADS (same anti-flood role as downloads).
const MAX_PENDING_UPLOADS: usize = 1024;
/// Current on-disk version of the pending-uploads store.
const UPLOADS_VERSION: u8 = 1;
/// Cap on concurrently-pending post-attachment blob fetches (anti-flood, like downloads).
const MAX_PENDING_POST_ATTACHMENTS: usize = 1024;
/// Current on-disk version of the pending-post-attachments store.
const POST_ATTACH_VERSION: u8 = 1;
/// Cap on concurrently-pending gallery blob fetches (one per sender; anti-flood).
const MAX_PENDING_GALLERIES: usize = 512;
/// Current on-disk version of the pending-galleries store.
const PENDING_GALLERY_VERSION: u8 = 1;

/// Truncate a string to `max` BYTES on a UTF-8 char boundary (never split a
/// multibyte char). Clamps a received/saved profile BEFORE writing to disk.
fn clamp_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// What `sessions.dat` holds, as it sits on disk (see `Store::read_session_file`).
///
/// The ratchet state stays OPAQUE here on purpose: a writer that only needs to carry the other
/// half across (an OPK top-up, say) must never decode and re-encode a state it has no business
/// touching — that would turn every unrelated write into a chance to rewrite it.
struct SessionFile {
    /// Monotonic rollback marker, checked against `sessions.anchor`.
    generation: u64,
    /// The serialized `PeerState`, untouched.
    state: Vec<u8>,
    /// The one-time prekey secrets, which commit in the SAME write as the state (CRYPTO-26).
    opks: Vec<node::pqxdh::OneTimeSecret>,
}

/// What `capabilities.dat` holds: the admission credentials this account has, split by whether
/// they belong to one channel or to all of them (A8-4).
///
/// One file rather than one per proxy on purpose. Every read is a read-modify-write of the whole
/// map, and the "an unreadable credential file is a loud error, never treated as absent" rule is
/// worth having in exactly one place; per-proxy files would fan that fail-closed behaviour out N
/// ways for nothing (the file is small, and it is already sealed under the account key).
#[derive(Serialize, Deserialize, Default)]
struct CapabilityFile {
    /// `"<relay-id hex>:<slot>"` → the credential THAT SLOT earned at THAT relay, where slot is
    /// `root` or `p<index>`. This is the per-proxy issuance A8-4 asks for: nothing here is
    /// readable by another channel, so a relay watching the wire sees N unrelated
    /// `capability_id`s where it used to see one account.
    per_slot: BTreeMap<String, Capability>,
    /// `"<relay-id hex>"` → a credential that cannot be split per channel, so every one presents
    /// it. Only two things belong here, both deliberate: an operator invite (one credential,
    /// revocable as a unit — the operator would have to mint N) and the public dev capability
    /// (the same id for every user of this repository, so splitting it separates nothing).
    /// Writing here is always an explicit call — see `Store::save_shared_capability_for`.
    shared: BTreeMap<String, Capability>,
}

/// Clone is a cheap handle (a path + the derived key), so an off-loop transfer thread
/// can seal straight into the vault instead of staging plaintext on disk.
#[derive(Clone)]
pub struct Store {
    dir: PathBuf,
    key: MasterKey,
    /// PROXY MODE (proxy-identity model). `None` = root store — identical paths and the frozen
    /// root `derive`, so existing behaviour is byte-for-byte unchanged (the regression guard).
    /// `Some(index)` = act AS that proxy: `load_account`/`load_identity` return the identity
    /// derived from THAT PROXY'S OWN random secret (`ProxyEntry::secret`, looked up in
    /// `proxies.dat` by `index` — see `Store::proxy_identity`), NOT from the seed/phrase (#207,
    /// A6-4). If the registry has no live entry for `index` (burned, or never created), this
    /// FAILS LOUDLY (`io::Error`) rather than falling back to any phrase-derivation — a silent
    /// fallback there would reinstate the exact "burn doesn't destroy" bug this model closes. The
    /// IDENTITY-keyed network files (sessions/opks/discovery) are namespaced by index so proxies
    /// never cross session/ratchet state. DEVICE/RELAY-scoped state (the relay capability, blob
    /// transfer queues) and all DATA (contacts/history/feed/profile/…) stay on the root paths, one
    /// copy — a proxy is a channel, not a persona.
    ///
    /// **A8-4 (fixed):** the relay capability USED to be shared across every proxy, so all of them
    /// presented one `capability_id` and a relay could cluster them back into one account with no
    /// effort at all. The dismissal written here before — "a relay already clusters them from
    /// fetch timing over one connection" — had its premise backwards: `Peer::scope_for` derives a
    /// SOCKS stream-isolation token per handle, and a handle is per-purpose, per-box, per-epoch,
    /// so over Tor each request already takes its own circuit and the connection links nothing.
    /// The shared `capability_id`, sent in the clear on every deposit, was therefore not a minor
    /// channel behind a stronger one — it was the ONLY one, in exactly the configuration proxies
    /// exist for. Credentials are now issued and stored per slot (see `CapabilityFile`).
    proxy: Option<u32>,
    /// At-rest CONTEXT prefix for this store (CRYPTO-05): `acct:<id>` inside a vault, `vault`
    /// for the vault's own files, `store` for a standalone single-account directory. Combined
    /// with the file's path relative to `dir` it forms the seal label, so one account's file
    /// cannot be swapped in for another's, nor one file for another.
    ///
    /// Deliberately NOT derived from `dir`: the on-disk path is the user's to move or rename,
    /// and binding to it would turn "I moved ~/.config to a bigger drive" into "wrong password".
    scope: String,
}

/// Plaintext bytes sealed per record before hitting disk. 64 KiB keeps the streaming
/// path's peak RAM flat while amortizing the per-record AEAD header.
const FILE_CHUNK: usize = 64 * 1024;

// Resume alignment (see `SealedFileWriter::checkpoint` / `open_or_resume_download`): a blob
// chunk must fit in ONE record, so it never auto-splits the write buffer into two. If this
// breaks, `chunks_done = records − 1` overcounts and a resume silently skips real data.
const _: () = assert!(crate::blob::BLOB_CHUNK < FILE_CHUNK);

/// A received file, encrypted at rest under the vault key.
///
/// Files used to be written straight into `received/` as ordinary plaintext, under the
/// name the SENDER chose — so a lost or stolen cold disk handed over every file you were sent,
/// content and name, sitting next to an encrypted history. Now the bytes are sealed and
/// the name rides INSIDE the container (the on-disk name is a random id), so the
/// directory listing alone no longer says "you were sent invoice-for-the-lawyer.pdf".
///
/// Layout: a sequence of `u32 length ‖ MasterKey::seal(record)`. The FIRST record is the
/// file name; the rest are ≤`FILE_CHUNK` plaintext chunks in order. Each record carries
/// its own fresh nonce (see `MasterKey::seal`). Chunked rather than one-shot so a
/// multi-GB blob download streams through with O(chunk) RAM.
///
/// **Named limit:** the container is not length-hiding — the file size is visible from
/// the on-disk size, and record boundaries reveal the chunking. It protects content and
/// name, not the fact that a file of roughly N bytes exists.
pub struct SealedFileWriter {
    file: std::fs::File,
    key: MasterKey,
    /// The at-rest label every record in THIS file is sealed under (CRYPTO-05): the file's own
    /// path, so records cannot be spliced in from another received file. Carried on the writer
    /// rather than passed per record — the two must never disagree.
    ///
    /// NAMED LIMIT: this binds records to the FILE, not to their position within it. Reordering
    /// records inside one container is still undetected here; the download's end-to-end
    /// plaintext hash is what catches that.
    label: String,
    buf: Vec<u8>,
}

impl SealedFileWriter {
    fn record(
        file: &mut std::fs::File,
        key: &MasterKey,
        label: &str,
        plain: &[u8],
    ) -> io::Result<()> {
        let sealed = key.seal(label, plain);
        let len: u32 = sealed.len().try_into().map_err(|_| io_err("sealed record too large"))?;
        file.write_all(&len.to_le_bytes())?;
        file.write_all(&sealed)
    }

    /// Seal whatever is buffered and finish the file (fsync). MUST be called — a
    /// dropped writer leaves the tail unwritten.
    pub fn finish(mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let buf = std::mem::take(&mut self.buf);
            Self::record(&mut self.file, &self.key, &self.label, &buf)?;
        }
        self.file.sync_all()
    }

    /// Seal whatever is buffered as ONE record, WITHOUT fsync. The resumable download calls this
    /// after each blob chunk, so each blob chunk becomes exactly one record (blob chunks are 60 KiB
    /// < the 64 KiB `FILE_CHUNK`, so a chunk never auto-splits) — the alignment that lets a resume
    /// count `clean records − 1` = chunks already fetched. Durability is provided separately by
    /// `sync`, batched so we do not fsync every 60 KiB.
    pub fn seal(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let buf = std::mem::take(&mut self.buf);
            Self::record(&mut self.file, &self.key, &self.label, &buf)?;
        }
        Ok(())
    }

    /// fsync the sealed records to disk. Called by the download in BATCHES (every few MiB) rather
    /// than per chunk: a resume tolerates a lost or torn unsynced tail (it truncates to the last
    /// clean record and re-fetches from there), so batching only risks re-fetching a few MiB after
    /// a crash — for a large cut in fsync traffic and disk wear.
    pub fn sync(&mut self) -> io::Result<()> {
        self.file.sync_all()
    }

    /// Seal the buffered record AND fsync it (per-record durability), in one step.
    pub fn checkpoint(&mut self) -> io::Result<()> {
        self.seal()?;
        self.sync()
    }
}

impl Write for SealedFileWriter {
    /// Buffers to `FILE_CHUNK` and seals full chunks — so an arbitrary write pattern
    /// (one 60 KiB blob chunk per call, or one big inline write) produces the same
    /// container.
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        while self.buf.len() >= FILE_CHUNK {
            let rest = self.buf.split_off(FILE_CHUNK);
            let chunk = std::mem::replace(&mut self.buf, rest);
            Self::record(&mut self.file, &self.key, &self.label, &chunk)?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn io_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// Известный plaintext для верификатора пароля (см. `unlock`).
const VERIFY_CONST: &[u8] = b"KARST-at-rest-verify-v1";

/// Прочитать соль каталога (`salt`, 16 Б plaintext) или создать при первом запуске.
/// `create_new`: не перезатирать (иначе все существующие шифртексты нечитаемы).
fn read_or_create_salt(dir: &std::path::Path) -> io::Result<Vec<u8>> {
    let salt_path = dir.join("salt");
    match std::fs::read(&salt_path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let s = random_salt();
            let mut f =
                OpenOptions::new().write(true).create_new(true).mode(0o644).open(&salt_path)?;
            f.write_all(&s)?;
            Ok(s.to_vec())
        }
        Err(e) => Err(e),
    }
}

/// At-rest label of the password verifier. A literal, not a path: the verifier is the ONE
/// file read before we know which store/account we are in, so it cannot be scoped by one.
const VERIFY_LABEL: &str = "verify";

/// Верификатор пароля: при первом разе запечатать известную константу, далее
/// сверять. Ловит НЕВЕРНЫЙ пароль СРАЗУ (fail-fast), до любой записи секрета.
fn check_or_seal_verify(dir: &std::path::Path, key: &MasterKey) -> io::Result<()> {
    let verify_path = dir.join("verify");
    match std::fs::read(&verify_path) {
        Ok(blob) => {
            let ok = key.open(VERIFY_LABEL, &blob).map(|p| p == VERIFY_CONST).unwrap_or(false);
            if !ok {
                return Err(io_err("wrong password"));
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let blob = key.seal(VERIFY_LABEL, VERIFY_CONST);
            let mut f =
                OpenOptions::new().write(true).create_new(true).mode(0o600).open(&verify_path)?;
            f.write_all(&blob)
        }
        Err(e) => Err(e),
    }
}

impl Store {
    /// Открыть каталог и вывести мастер-ключ из `passphrase` (Argon2id, ОДИН раз
    /// на процесс). Соль (`salt`, 16 Б plaintext) читается или создаётся при
    /// первом запуске. Одиночный аккаунт (salt/verify В ЭТОМ каталоге) — путь CLI
    /// и обратной совместимости. Мультиаккаунт GUI использует `Vault` (salt/verify
    /// на уровне базы, ключ раздаётся всем аккаунтам).
    pub fn unlock(dir: impl Into<PathBuf>, passphrase: &[u8]) -> io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        let salt = read_or_create_salt(&dir)?;
        let key = MasterKey::derive(passphrase, &salt).map_err(io_err)?;
        check_or_seal_verify(&dir, &key)?;
        Ok(Store { dir, key, proxy: None, scope: "store".into() })
    }

    /// Store поверх УЖЕ выведенного vault-ключа (salt/verify проверены на уровне
    /// базы). Не трогает salt/verify — их у аккаунт-подкаталога нет. Переключение
    /// аккаунтов = сменить `dir`, переиспользовать тот же `key` (без Argon2).
    pub fn at(dir: impl Into<PathBuf>, key: MasterKey) -> Self {
        Store { dir: dir.into(), key, proxy: None, scope: "store".into() }
    }

    /// The same store bound to an explicit at-rest `scope` (see [`Store::scope`]). Used by
    /// `Vault` to give every account its own key derivation, so account A's sealed file cannot
    /// be dropped in over account B's and still open.
    pub(crate) fn scoped(dir: impl Into<PathBuf>, key: MasterKey, scope: String) -> Self {
        Store { dir: dir.into(), key, proxy: None, scope }
    }

    /// The at-rest label for `path`: `<scope>/<path relative to this store's dir>`, with
    /// separators normalised so the label is identical on every platform. Derived from where
    /// the bytes actually LIVE, so it cannot drift from the file it protects the way a
    /// hand-passed string would.
    ///
    /// `path` must be the FINAL path, never a `.tmp` staging name — [`Store::write_sealed`]
    /// exists so that no caller has to remember this.
    pub(crate) fn label(&self, path: &std::path::Path) -> String {
        let rel = path.strip_prefix(&self.dir).unwrap_or(path);
        let rel: Vec<String> =
            rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
        format!("{}/{}", self.scope, rel.join("/"))
    }

    /// Seal `plain` FOR `path` and write it atomically (temp 0600 → fsync → rename). The label
    /// comes from `path` itself, so seal and open can never disagree about the context.
    pub(crate) fn write_sealed(&self, path: &std::path::Path, plain: &[u8]) -> io::Result<()> {
        let bytes = self.key.seal(&self.label(path), plain);
        self.write_atomic(path, &bytes)
    }

    /// A handle onto the SAME vault dir + key that acts AS proxy `index` (proxy-identity model):
    /// `load_account`/`load_identity` return that proxy's identity, derived from ITS OWN random
    /// secret stored in the registry (never from the seed — see the `proxy` field doc above), and
    /// the network files are namespaced by index. Data files are unchanged (root-owned). Cheap
    /// clone. Does NOT require the proxy to already exist in the registry — the failure (if any)
    /// only happens lazily, the first time something on this handle actually needs the identity.
    pub fn as_proxy(&self, index: u32) -> Store {
        Store { dir: self.dir.clone(), key: self.key.clone(), proxy: Some(index), scope: self.scope.clone() }
    }

    /// The proxy index this store is acting as, if any (`None` = root).
    pub fn proxy_index(&self) -> Option<u32> {
        self.proxy
    }

    /// Path for a NETWORK file (`sessions.dat`, `opks.dat`, …). Root: unchanged (`name`). Proxy
    /// mode: namespaced `sessions.p<index>.dat`, so proxies never share session/key/relay state.
    /// The `.p<index>` is inserted before the extension; a bare name (no dot) just gets it appended.
    fn net_file(&self, name: &str) -> PathBuf {
        match self.proxy {
            None => self.dir.join(name),
            Some(idx) => {
                let namespaced = match name.rsplit_once('.') {
                    Some((stem, ext)) => format!("{stem}.p{idx}.{ext}"),
                    None => format!("{name}.p{idx}"),
                };
                self.dir.join(namespaced)
            }
        }
    }

    /// `$KARST_HOME`, иначе `$XDG_CONFIG_HOME/karst`, иначе `~/.config/karst`.
    pub fn default_dir() -> PathBuf {
        if let Ok(d) = std::env::var("KARST_HOME") {
            return PathBuf::from(d);
        }
        let base = std::env::var("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".config")
        });
        base.join("karst")
    }

    fn net_path(&self) -> PathBuf {
        self.dir.join("net.dat")
    }

    /// This ACCOUNT's network config ([`NetSettings`]); defaults (all empty) when never
    /// saved. Per-account on purpose: an account is an identity, and a compartment is an
    /// identity **plus its own relay**. Sharing one relay across accounts hands the relay
    /// a link between your personas (same IP, same timing) that separate keys do nothing
    /// about — so the config lives with the identity it belongs to.
    ///
    /// Readable only with the device key, i.e. only after unlock.
    pub fn load_net(&self) -> io::Result<NetSettings> {
        match std::fs::read(self.net_path()) {
            Ok(blob) => {
                let bytes = self.key.open(&self.label(&self.net_path()), &blob).map_err(io_err)?;
                postcard::from_bytes(&bytes).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(NetSettings::default()),
            Err(e) => Err(e),
        }
    }

    /// ATOMICALLY save this account's network config (temp 0600 → fsync → rename),
    /// encrypted — same handling as the rest of the account's state.
    pub fn save_net(&self, net: &NetSettings) -> io::Result<()> {
        let plain = postcard::to_stdvec(net).map_err(io_err)?;
        let bytes = self.key.seal(&self.label(&self.net_path()), &plain);
        let tmp = self.dir.join("net.dat.tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, self.net_path())
    }

    fn relay_prefs_path(&self) -> PathBuf {
        self.dir.join("relay_prefs.dat")
    }

    /// This account's relay-selection preferences (empty = no preference). Sealed at-rest like the
    /// rest of the account state; readable only after unlock.
    pub fn load_relay_prefs(&self) -> io::Result<RelayPrefs> {
        match std::fs::read(self.relay_prefs_path()) {
            Ok(blob) => {
                let bytes = self.key.open(&self.label(&self.relay_prefs_path()), &blob).map_err(io_err)?;
                postcard::from_bytes(&bytes).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(RelayPrefs::default()),
            Err(e) => Err(e),
        }
    }

    /// Atomically save the relay-selection preferences (temp 0600 → fsync → rename), encrypted.
    pub fn save_relay_prefs(&self, prefs: &RelayPrefs) -> io::Result<()> {
        let plain = postcard::to_stdvec(prefs).map_err(io_err)?;
        let bytes = self.key.seal(&self.label(&self.relay_prefs_path()), &plain);
        let tmp = self.dir.join("relay_prefs.dat.tmp");
        {
            let mut f =
                OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, self.relay_prefs_path())
    }

    fn prefs_path(&self) -> PathBuf {
        self.dir.join("prefs.dat")
    }

    /// This account's privacy preferences (defaults = all off) — kept in their OWN sealed blob,
    /// deliberately NOT folded into `NetSettings`, whose relay-screen writers rewrite a fresh
    /// literal on every save and would clobber a field living there.
    pub fn load_prefs(&self) -> io::Result<Prefs> {
        match std::fs::read(self.prefs_path()) {
            Ok(blob) => {
                let bytes = self.key.open(&self.label(&self.prefs_path()), &blob).map_err(io_err)?;
                postcard::from_bytes(&bytes).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Prefs::default()),
            Err(e) => Err(e),
        }
    }

    /// Atomically save the privacy preferences (temp 0600 → fsync → rename), encrypted.
    pub fn save_prefs(&self, prefs: &Prefs) -> io::Result<()> {
        let plain = postcard::to_stdvec(prefs).map_err(io_err)?;
        let bytes = self.key.seal(&self.label(&self.prefs_path()), &plain);
        let tmp = self.dir.join("prefs.dat.tmp");
        {
            let mut f =
                OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, self.prefs_path())
    }

    fn files_dir(&self) -> PathBuf {
        self.dir.join("files")
    }

    /// Path of a sealed received file. The on-disk name is a random id — the real name
    /// lives sealed INSIDE, so a directory listing reveals nothing.
    fn file_path(&self, id: &str) -> PathBuf {
        self.files_dir().join(format!("{id}.dat"))
    }

    /// Begin a sealed received file; the name is written as the first sealed record.
    /// Returns its id and a writer to stream the bytes through (peak RAM O(chunk)).
    pub fn received_file_writer(&self, name: &str) -> io::Result<(String, SealedFileWriter)> {
        std::fs::create_dir_all(self.files_dir())?;
        let id = hex::encode(&crate::blob::random32()[..16]);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.file_path(&id))?;
        let label = self.label(&self.file_path(&id));
        SealedFileWriter::record(&mut file, &self.key, &label, name.as_bytes())?;
        Ok((id, SealedFileWriter { file, key: self.key.clone(), label, buf: Vec::new() }))
    }

    /// Save a small received file in one go (the inline path); returns its id.
    pub fn save_received_file(&self, name: &str, bytes: &[u8]) -> io::Result<String> {
        let (id, mut w) = self.received_file_writer(name)?;
        w.write_all(bytes)?;
        w.finish()?;
        Ok(id)
    }

    /// Save an inline received file, DEDUPED by its per-transfer manifest id. If a received file
    /// with this transfer id is already recorded, return its container id and `false` (a
    /// re-delivery — do not save a second copy, do not double-count); otherwise write the
    /// container, index it, and return `(id, true)`. Reuses the same `ReceivedFile` index and
    /// `blob_id` key the large-file path uses for idempotency (the transfer id occupies the first
    /// 16 bytes; the zero key stays the legacy/no-dedup sentinel).
    pub fn save_received_file_deduped(
        &self,
        transfer_id: [u8; 16],
        name: &str,
        bytes: &[u8],
        sender: [u8; 32],
        ts: u64,
    ) -> io::Result<(String, bool)> {
        let mut dedup_key = [0u8; 32];
        dedup_key[..16].copy_from_slice(&transfer_id);
        if let Some(existing) = self.list_received_files()?.into_iter().find(|f| f.blob_id == dedup_key) {
            return Ok((existing.id, false));
        }
        let id = self.save_received_file(name, bytes)?;
        self.record_received_file(&ReceivedFile {
            id: id.clone(),
            name: name.to_string(),
            size: bytes.len() as u64,
            sender,
            ts,
            blob_id: dedup_key,
        })?;
        Ok((id, true))
    }

    /// Read one sealed record at `pos`; `Ok(None)` at clean EOF.
    fn read_record(f: &mut File, key: &MasterKey, label: &str) -> io::Result<Option<Vec<u8>>> {
        use io::Read;
        let mut len = [0u8; 4];
        match f.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let n = u32::from_le_bytes(len) as usize;
        // Bound the allocation: a corrupt/hostile length must not ask for gigabytes.
        if n > FILE_CHUNK * 2 + 256 {
            return Err(io_err("sealed record length out of range"));
        }
        let mut sealed = vec![0u8; n];
        f.read_exact(&mut sealed)?;
        key.open(label, &sealed).map(Some).map_err(io_err)
    }

    /// The (sealed) original name of a received file.
    pub fn received_file_name(&self, id: &str) -> io::Result<String> {
        let mut f = File::open(self.file_path(id))?;
        let rec = Self::read_record(&mut f, &self.key, &self.label(&self.file_path(id)))?.ok_or_else(|| io_err("empty file record"))?;
        String::from_utf8(rec).map_err(io_err)
    }

    /// Drop a sealed received file (a failed/cancelled download leaves no partial).
    pub fn remove_received_file(&self, id: &str) -> io::Result<()> {
        std::fs::remove_file(self.file_path(id))
    }

    /// **Export**: decrypt a received file to `dest` — the user's explicit act.
    ///
    /// This is the honest cost of encrypting attachments: the vault can hold them
    /// sealed, but the moment you want to open one in an ordinary viewer it has to
    /// exist in the clear somewhere. So we never do that silently — the plaintext copy
    /// appears only where the user asked for it, and it is theirs to manage.
    /// Streams (peak RAM O(chunk)), so a multi-GB file exports fine.
    pub fn export_received_file(&self, id: &str, dest: &std::path::Path) -> io::Result<()> {
        let mut f = File::open(self.file_path(id))?;
        // First record is the name — skip it.
        Self::read_record(&mut f, &self.key, &self.label(&self.file_path(id)))?.ok_or_else(|| io_err("empty file record"))?;
        let mut out =
            OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(dest)?;
        while let Some(chunk) = Self::read_record(&mut f, &self.key, &self.label(&self.file_path(id)))? {
            out.write_all(&chunk)?;
        }
        out.sync_all()
    }

    /// On-disk (sealed) size of a received file — a cheap `stat`, so a caller can refuse to
    /// load an enormous file into memory before calling [`read_received_file`]. The sealed
    /// size is slightly larger than the plaintext (per-record overhead), so it is a safe upper
    /// bound for a "too large to buffer" guard.
    pub fn received_file_size(&self, id: &str) -> io::Result<u64> {
        Ok(std::fs::metadata(self.file_path(id))?.len())
    }

    /// Decrypt a received file **into memory** and return its bytes — for callers that hand
    /// the plaintext straight to the user (e.g. a webview download) rather than writing it to
    /// a path. Same posture as [`export_received_file`]: decryption is an explicit act; unlike
    /// the streaming export this holds the whole file, so keep it for reasonably sized files.
    pub fn read_received_file(&self, id: &str) -> io::Result<Vec<u8>> {
        let mut f = File::open(self.file_path(id))?;
        // First record is the name — skip it.
        Self::read_record(&mut f, &self.key, &self.label(&self.file_path(id)))?.ok_or_else(|| io_err("empty file record"))?;
        let mut out = Vec::new();
        while let Some(chunk) = Self::read_record(&mut f, &self.key, &self.label(&self.file_path(id)))? {
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    // ----- Sealed index of received files (WHO sent WHAT, WHEN) -----
    // Same append-log shape and locking as the chat history: `len(u32-LE) ‖ sealed` records,
    // a DEDICATED never-renamed lock file for a stable inode, torn-tail tolerant on read.
    // Sealed because it holds exactly the sender↔name↔time metadata the `files/` container
    // hides on disk. Written from the poll thread (inline files) AND the blob-download threads,
    // so the flock is load-bearing, not decorative.

    fn files_index_path(&self) -> PathBuf {
        self.files_dir().join("index.dat")
    }
    fn files_index_lock_path(&self) -> PathBuf {
        self.files_dir().join("index.lock")
    }
    fn lock_files_index(&self) -> io::Result<SessionLock> {
        std::fs::create_dir_all(self.files_dir())?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.files_index_lock_path())?;
        file.lock()?;
        Ok(SessionLock { _file: file })
    }

    /// Append one sealed received-file record (flock + O_APPEND, like `append_history`).
    /// Best-effort: the sealed file itself and the chat history remain the source of truth if
    /// this ever fails, so callers may ignore the error.
    pub fn record_received_file(&self, rec: &ReceivedFile) -> io::Result<()> {
        let plain = postcard::to_stdvec(rec).map_err(io_err)?;
        let blob = self.key.seal(&self.label(&self.files_index_path()), &plain);
        let len: u32 = blob.len().try_into().map_err(|_| io_err("index record too large"))?;
        let _lock = self.lock_files_index()?;
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(self.files_index_path())?;
        let mut framed = Vec::with_capacity(4 + blob.len());
        framed.extend_from_slice(&len.to_le_bytes());
        framed.extend_from_slice(&blob);
        f.write_all(&framed)?;
        f.sync_all()
    }

    /// Read the received-files index (torn-tail tolerant, like `load_history`).
    pub fn list_received_files(&self) -> io::Result<Vec<ReceivedFile>> {
        let _lock = self.lock_files_index()?;
        let bytes = match std::fs::read(self.files_index_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        let mut off = 0usize;
        while off + 4 <= bytes.len() {
            let len = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
            if len == 0 || len > MAX_HISTORY_RECORD {
                break;
            }
            let start = off + 4;
            let end = match start.checked_add(len) {
                Some(e) if e <= bytes.len() => e,
                _ => break,
            };
            let plain = match self.key.open(&self.label(&self.files_index_path()), &bytes[start..end]) {
                Ok(p) => p,
                Err(_) => break,
            };
            // Try the current layout (with `blob_id`); fall back to the pre-`blob_id` record
            // (postcard errors on the missing trailing field), which gets a zero blob id.
            let rec = match postcard::from_bytes::<ReceivedFile>(&plain) {
                Ok(r) => r,
                Err(_) => match postcard::from_bytes::<ReceivedFileV0>(&plain) {
                    Ok(v0) => ReceivedFile {
                        id: v0.id,
                        name: v0.name,
                        size: v0.size,
                        sender: v0.sender,
                        ts: v0.ts,
                        blob_id: [0u8; 32],
                    },
                    Err(_) => break,
                },
            };
            out.push(rec);
            off = end;
        }
        Ok(out)
    }

    fn downloads_path(&self) -> PathBuf {
        self.dir.join("downloads.dat")
    }

    /// Seal `plain` inside an explicit version envelope: `KRV1 ‖ version ‖ plain`, then the
    /// vault seal. The magic makes the version unambiguous (a bare postcard blob can't be
    /// mistaken for versioned data), and it sits INSIDE the seal so the version is
    /// authenticated. New at-rest formats should use this instead of growing another
    /// try-new-fallback mirror (see docs/design/format-versioning.md).
    fn seal_versioned(&self, path: &std::path::Path, version: u8, plain: &[u8]) -> Vec<u8> {
        let mut framed = Vec::with_capacity(5 + plain.len());
        framed.extend_from_slice(FORMAT_MAGIC);
        framed.push(version);
        framed.extend_from_slice(plain);
        self.key.seal(&self.label(path), &framed)
    }

    /// Open a version-enveloped blob → `(version, inner)`. `None` if it does not decrypt or
    /// lacks the magic (e.g. a pre-versioning blob), so the caller can fall back / reset.
    fn open_versioned(&self, path: &std::path::Path, blob: &[u8]) -> Option<(u8, Vec<u8>)> {
        let plain = self.key.open(&self.label(path), blob).ok()?;
        if plain.len() < 5 || &plain[..4] != FORMAT_MAGIC {
            return None;
        }
        Some((plain[4], plain[5..].to_vec()))
    }

    /// Load the pending-downloads map (blob_id → entry). A corrupt/missing file reads empty
    /// (these are recoverable retry hints, not secrets that must round-trip).
    pub fn load_pending_downloads(&self) -> io::Result<std::collections::BTreeMap<[u8; 32], PendingDownload>> {
        match std::fs::read(self.downloads_path()) {
            // Version-dispatched: only v1 is known. A pre-versioning or unknown blob → empty
            // (these are transient retry hints, safe to reset).
            Ok(blob) => Ok(match self.open_versioned(&self.downloads_path(), &blob) {
                Some((DOWNLOADS_VERSION, inner)) => postcard::from_bytes(&inner).unwrap_or_default(),
                _ => Default::default(),
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Default::default()),
            Err(e) => Err(e),
        }
    }

    /// Persist the pending-downloads map under the current version envelope.
    fn save_pending_downloads(&self, map: &std::collections::BTreeMap<[u8; 32], PendingDownload>) -> io::Result<()> {
        let plain = postcard::to_stdvec(map).map_err(io_err)?;
        self.write_atomic(&self.downloads_path(), &self.seal_versioned(&self.downloads_path(), DOWNLOADS_VERSION, &plain))
    }

    /// Every pending download, for the retry driver.
    pub fn list_pending_downloads(&self) -> io::Result<Vec<PendingDownload>> {
        Ok(self.load_pending_downloads()?.into_values().collect())
    }

    /// Record a FileRef as a pending download (idempotent by blob_id) so a crash mid-download
    /// can retry. Persisted BEFORE the receive path acks the message, so the announcement is
    /// durable before the relay may drop it. Bounded so a flood of FileRefs can't grow the
    /// file without limit.
    pub fn add_pending_download(&self, pd: &PendingDownload) -> io::Result<()> {
        let _lock = self.lock_files_index()?;
        let mut map = self.load_pending_downloads()?;
        if !map.contains_key(&pd.blob_id) && map.len() >= MAX_PENDING_DOWNLOADS {
            // An ERROR, not a silent drop. The caller treats `Ok` as "durably recorded" and then
            // acks the carrier message, so the relay deletes the only pointer to that file while
            // we quietly kept nothing — and an attacker who fills this queue with their own
            // objects makes everyone else's attachments disappear (A8-6). Failing here means the
            // message is not acked and stays on the relay until its TTL.
            return Err(io_err("pending-download queue is full — refusing to drop an announcement"));
        }
        map.insert(pd.blob_id, pd.clone());
        self.save_pending_downloads(&map)
    }

    /// Remember which container a pending download is streaming into, so a retry resumes it.
    pub fn set_pending_container(&self, blob_id: &[u8; 32], container_id: &str) -> io::Result<()> {
        let _lock = self.lock_files_index()?;
        let mut map = self.load_pending_downloads()?;
        if let Some(pd) = map.get_mut(blob_id) {
            pd.container_id = Some(container_id.to_string());
            self.save_pending_downloads(&map)?;
        }
        Ok(())
    }

    /// Open a received-file container to STREAM a download into: fresh, or RESUMING an existing
    /// partial. On resume it first truncates any torn trailing record (the writer only fsyncs
    /// whole records on `checkpoint`, so a crash can leave a partial one) — appending past a
    /// torn tail would make the file never verify, a stuck download. Returns the container id,
    /// an append writer, and how many blob chunks are already durably present (clean records
    /// minus the name record). A missing / unreadable / name-only container starts fresh.
    pub fn open_or_resume_download(
        &self,
        name: &str,
        container_id: Option<&str>,
    ) -> io::Result<(String, SealedFileWriter, u32)> {
        if let Some(id) = container_id {
            let path = self.file_path(id);
            if path.exists() {
                use std::io::Seek;
                // Count clean records and find the last clean boundary (torn tail tolerant).
                let mut f = File::open(&path)?;
                let mut records = 0u32;
                let mut last_good = 0u64;
                // Stop at the first non-clean record (Ok(None) = clean EOF, Err = torn tail).
                while let Ok(Some(_)) = Self::read_record(&mut f, &self.key, &self.label(&self.file_path(id))) {
                    records += 1;
                    last_good = f.stream_position()?;
                }
                if records >= 1 {
                    // Truncate the torn tail BEFORE appending — else [good][garbage][new]
                    // never hashes and the download is stuck forever.
                    OpenOptions::new().write(true).open(&path)?.set_len(last_good)?;
                    let file = OpenOptions::new().append(true).mode(0o600).open(&path)?;
                    let writer = SealedFileWriter {
                        file,
                        key: self.key.clone(),
                        label: self.label(&self.file_path(id)),
                        buf: Vec::new(),
                    };
                    return Ok((id.to_string(), writer, records - 1)); // minus the name record
                }
            }
        }
        // Fresh container (or the partial was unusable — start over; the orphan is swept).
        let (id, w) = self.received_file_writer(name)?;
        Ok((id, w, 0))
    }

    /// Seed a SHA-256 with the plaintext already present in a partial container (skipping the
    /// name record) — used ONLY on a resume, to reconstruct the running hash of the chunks a
    /// prior attempt fetched, so the fresh path never pays a second read. The download then
    /// feeds the remaining chunks in-line and finalizes; each chunk was already AEAD-
    /// authenticated at its position, so the SHA-256 is the whole-file integrity check.
    pub fn hasher_from_partial(&self, id: &str) -> io::Result<sha2::Sha256> {
        use sha2::{Digest, Sha256};
        let mut f = File::open(self.file_path(id))?;
        let mut hasher = Sha256::new();
        let mut first = true; // the first record is the file name, not content
        while let Some(rec) = Self::read_record(&mut f, &self.key, &self.label(&self.file_path(id)))? {
            if first {
                first = false;
            } else {
                hasher.update(&rec);
            }
        }
        Ok(hasher)
    }

    /// Drop a pending download (completed, given up, or expired). Idempotent.
    pub fn remove_pending_download(&self, blob_id: &[u8; 32]) -> io::Result<()> {
        let _lock = self.lock_files_index()?;
        let mut map = self.load_pending_downloads()?;
        if map.remove(blob_id).is_some() {
            self.save_pending_downloads(&map)?;
        }
        Ok(())
    }

    // ----- Pending POST ATTACHMENTS (blob transport for feed media), mirroring downloads -----

    fn post_attachments_path(&self) -> PathBuf {
        self.dir.join("post_attachments.dat")
    }

    fn load_pending_post_attachments(
        &self,
    ) -> io::Result<std::collections::BTreeMap<[u8; 32], PendingPostAttachment>> {
        match std::fs::read(self.post_attachments_path()) {
            Ok(blob) => Ok(match self.open_versioned(&self.post_attachments_path(), &blob) {
                Some((POST_ATTACH_VERSION, inner)) => postcard::from_bytes(&inner).unwrap_or_default(),
                _ => Default::default(),
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Default::default()),
            Err(e) => Err(e),
        }
    }

    fn save_pending_post_attachments(
        &self,
        map: &std::collections::BTreeMap<[u8; 32], PendingPostAttachment>,
    ) -> io::Result<()> {
        let plain = postcard::to_stdvec(map).map_err(io_err)?;
        self.write_atomic(&self.post_attachments_path(), &self.seal_versioned(&self.post_attachments_path(), POST_ATTACH_VERSION, &plain))
    }

    /// Every pending post-attachment fetch, for the download driver.
    pub fn list_pending_post_attachments(&self) -> io::Result<Vec<PendingPostAttachment>> {
        Ok(self.load_pending_post_attachments()?.into_values().collect())
    }

    /// Record a `PostAttachmentRef` as a pending blob fetch (idempotent by blob_id). Persisted
    /// BEFORE the receive path acks, so the announcement is durable before the relay may drop it.
    /// Bounded so a flood of refs can't grow the file without limit.
    pub fn add_pending_post_attachment(&self, ppa: &PendingPostAttachment) -> io::Result<()> {
        let _lock = self.lock_files_index()?;
        let mut map = self.load_pending_post_attachments()?;
        if !map.contains_key(&ppa.blob_id) && map.len() >= MAX_PENDING_POST_ATTACHMENTS {
            return Err(io_err("pending post-attachment queue is full — refusing to drop it silently"));
        }
        map.insert(ppa.blob_id, ppa.clone());
        self.save_pending_post_attachments(&map)
    }

    /// Drop a pending post-attachment fetch once it has completed (or is being abandoned).
    pub fn remove_pending_post_attachment(&self, blob_id: &[u8; 32]) -> io::Result<()> {
        let _lock = self.lock_files_index()?;
        let mut map = self.load_pending_post_attachments()?;
        if map.remove(blob_id).is_some() {
            self.save_pending_post_attachments(&map)?;
        }
        Ok(())
    }

    // ----- Pending GALLERY blob fetches (one per sender), mirroring pending post-attachments -----

    fn pending_galleries_path(&self) -> PathBuf {
        self.dir.join("pending_galleries.dat")
    }

    fn load_pending_galleries(&self) -> io::Result<std::collections::BTreeMap<[u8; 32], PendingGallery>> {
        match std::fs::read(self.pending_galleries_path()) {
            Ok(blob) => Ok(match self.open_versioned(&self.pending_galleries_path(), &blob) {
                Some((PENDING_GALLERY_VERSION, inner)) => postcard::from_bytes(&inner).unwrap_or_default(),
                _ => Default::default(),
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Default::default()),
            Err(e) => Err(e),
        }
    }

    fn save_pending_galleries(
        &self,
        map: &std::collections::BTreeMap<[u8; 32], PendingGallery>,
    ) -> io::Result<()> {
        let plain = postcard::to_stdvec(map).map_err(io_err)?;
        self.write_atomic(&self.pending_galleries_path(), &self.seal_versioned(&self.pending_galleries_path(), PENDING_GALLERY_VERSION, &plain))
    }

    /// Every pending gallery fetch, for the download driver.
    pub fn list_pending_galleries(&self) -> io::Result<Vec<PendingGallery>> {
        Ok(self.load_pending_galleries()?.into_values().collect())
    }

    /// Record a `GalleryRef` as a pending blob fetch, keyed by SENDER so a newer ref supersedes the
    /// old one (each contact has one gallery). Persisted BEFORE the receive path acks. Bounded.
    pub fn add_pending_gallery(&self, pg: &PendingGallery) -> io::Result<()> {
        let _lock = self.lock_files_index()?;
        let mut map = self.load_pending_galleries()?;
        if !map.contains_key(&pg.sender) && map.len() >= MAX_PENDING_GALLERIES {
            return Err(io_err("pending gallery queue is full — refusing to drop it silently"));
        }
        map.insert(pg.sender, pg.clone());
        self.save_pending_galleries(&map)
    }

    /// Drop a pending gallery fetch once complete/abandoned. Idempotent; a no-op if a newer ref for
    /// the same sender already replaced it (guarded by `blob_id` so we only remove the one we drove).
    pub fn remove_pending_gallery(&self, sender: &[u8; 32], blob_id: &[u8; 32]) -> io::Result<()> {
        let _lock = self.lock_files_index()?;
        let mut map = self.load_pending_galleries()?;
        if map.get(sender).is_some_and(|pg| &pg.blob_id == blob_id) {
            map.remove(sender);
            self.save_pending_galleries(&map)?;
        }
        Ok(())
    }

    // ----- Pending UPLOADS (resumable large-file send), mirroring the downloads store -----

    fn uploads_path(&self) -> PathBuf {
        self.dir.join("uploads.dat")
    }

    fn load_pending_uploads(&self) -> io::Result<std::collections::BTreeMap<[u8; 32], PendingUpload>> {
        match std::fs::read(self.uploads_path()) {
            // Absent = nothing pending. A file that EXISTS but cannot be opened, carries an
            // unknown version, or fails to decode is an ERROR — it used to collapse to "nothing
            // pending", silently forgetting an in-flight upload instead of reporting it, so a
            // resumable transfer vanished with no diagnosis (A4-12). Same rule already applied to
            // opks.dat and the proxy sidecars.
            Ok(blob) => {
                let (ver, inner) = self
                    .open_versioned(&self.uploads_path(), &blob)
                    .ok_or_else(|| io_err("pending uploads fail authentication"))?;
                if ver != UPLOADS_VERSION {
                    return Err(io_err(format!(
                        "pending uploads are version {ver}, this build understands {UPLOADS_VERSION}"
                    )));
                }
                postcard::from_bytes(&inner)
                    .map_err(|e| io_err(format!("pending uploads malformed: {e}")))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Default::default()),
            Err(e) => Err(e),
        }
    }

    fn save_pending_uploads(&self, map: &std::collections::BTreeMap<[u8; 32], PendingUpload>) -> io::Result<()> {
        let plain = postcard::to_stdvec(map).map_err(io_err)?;
        self.write_atomic(&self.uploads_path(), &self.seal_versioned(&self.uploads_path(), UPLOADS_VERSION, &plain))
    }

    /// Every pending upload (for a resume driver).
    pub fn list_pending_uploads(&self) -> io::Result<Vec<PendingUpload>> {
        Ok(self.load_pending_uploads()?.into_values().collect())
    }

    /// The pending upload for `upload_id`, if a prior attempt recorded one (→ resume its blob).
    pub fn get_pending_upload(&self, upload_id: &[u8; 32]) -> io::Result<Option<PendingUpload>> {
        Ok(self.load_pending_uploads()?.remove(upload_id))
    }

    /// Record an in-flight upload so a re-run resumes it. Idempotent by `upload_id`; bounded.
    pub fn add_pending_upload(&self, pu: &PendingUpload) -> io::Result<()> {
        let _lock = self.lock_files_index()?;
        let mut map = self.load_pending_uploads()?;
        if !map.contains_key(&pu.upload_id) && map.len() >= MAX_PENDING_UPLOADS {
            return Ok(());
        }
        map.insert(pu.upload_id, pu.clone());
        self.save_pending_uploads(&map)
    }

    /// Drop a pending upload once its `FileRef` has been delivered.
    pub fn remove_pending_upload(&self, upload_id: &[u8; 32]) -> io::Result<()> {
        let _lock = self.lock_files_index()?;
        let mut map = self.load_pending_uploads()?;
        if map.remove(upload_id).is_some() {
            self.save_pending_uploads(&map)?;
        }
        Ok(())
    }

    /// Remove orphaned partial files: `files/<id>.dat` that no completed `ReceivedFile` index
    /// entry points at. A crash mid-download leaves such a partial (its index/history are
    /// written only on success). Call at startup, BEFORE any download begins, so an
    /// in-progress partial is never swept. Returns how many were removed.
    pub fn sweep_orphan_files(&self) -> io::Result<usize> {
        let keep: std::collections::HashSet<String> =
            self.list_received_files()?.into_iter().map(|r| r.id).collect();
        let dir = self.files_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let mut removed = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue };
            // Only sweep container files (`<id>.dat`), never the index itself or its lock, and
            // never a file a completed record points at.
            if stem != "index"
                && path.extension().and_then(|e| e.to_str()) == Some("dat")
                && !keep.contains(stem)
                && std::fs::remove_file(&path).is_ok()
            {
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub fn capability_path(&self) -> PathBuf {
        // .dat, а не .json: на диске зашифрованный blob, не JSON.
        //
        // Deliberately `self.dir`, NOT `net_file`: ONE file holds every slot's credentials, keyed
        // `<relay-id>:<slot>` inside (see `CapabilityFile`). The per-proxy separation A8-4 asks
        // for is in the KEY, not in the filename — which keeps the "unreadable → loud error"
        // rule in a single place instead of N, and lets a burn remove one proxy's credentials
        // without the rest of the file being rewritten by anything else.
        self.dir.join("capabilities.dat")
    }

    /// **Единый корень личности** — 16 байт энтропии мнемонической фразы (§seed).
    /// ЕДИНСТВЕННЫЙ секрет-личность на диске: и seal, и account выводятся из него
    /// (`seed::derive`), поэтому диск и фраза НЕ МОГУТ разойтись. `.key`, но это
    /// зашифрованный at-rest blob.
    fn seed_path(&self) -> PathBuf {
        self.dir.join("seed.key")
    }

    pub fn has_seed(&self) -> bool {
        self.seed_path().exists()
    }

    /// Does this account hold an admission credential for THIS relay? (A credential for some
    /// other relay is not one for this one — see `save_capability_for`.)
    pub fn has_capability_for(&self, relay: &crate::RelayId) -> bool {
        self.load_capability_for(relay).is_ok()
    }

    /// Записать корень (энтропию фразы). `create_new` → НЕ перезаписывает: смена
    /// корня сменила бы IK/владение mailbox → осиротила бы всё запечатанное на
    /// старую личность и все сессии. Права 0600 при СОЗДАНИИ. Provisioning
    /// (create/restore) кладёт сюда энтропию свежей/введённой фразы.
    pub fn save_seed(&self, entropy: &[u8; crate::seed::ENTROPY_BYTES]) -> io::Result<()> {
        let blob = self.key.seal(&self.label(&self.seed_path()), entropy);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.seed_path())?;
        f.write_all(&blob)
    }

    /// Прочитать корень (для показа фразы / provisioning-проверок).
    pub fn load_entropy(&self) -> io::Result<[u8; crate::seed::ENTROPY_BYTES]> {
        let blob = std::fs::read(self.seed_path())?;
        let secret = self.key.open(&self.label(&self.seed_path()), &blob).map_err(io_err)?;
        secret
            .as_slice()
            .try_into()
            .map_err(|_| io_err("seed: entropy is not 16 bytes"))
    }

    /// seal-ключ (relay-facing). В корневом режиме **выводится** из фразы, не хранится отдельно.
    /// В proxy-режиме — seal ЭТОГО прокси, выведенный из его собственного случайного секрета
    /// (`proxy_identity`), НЕ из фразы (#207): если запись прокси сожжена/не существует, это
    /// ошибка, а не тихий откат на HD-вывод из фразы (см. `proxy_identity`).
    pub fn load_identity(&self) -> io::Result<Identity> {
        Ok(match self.proxy {
            None => crate::seed::derive(&self.load_entropy()?).seal,
            Some(idx) => self.proxy_identity(idx)?.seal,
        })
    }

    /// §2.1-account (ik‖prekey‖KEM). В корневом режиме **выводится** из фразы, не хранится
    /// отдельно. В proxy-режиме возвращает личность ПРОКСИ — выведенную из ЕЁ СОБСТВЕННОГО
    /// секрета в реестре (`proxy_identity`), НЕ из фразы (#207, A6-4) — поэтому весь session-слой
    /// (mailbox = IK, ownership-proof, ratchet) работает как этот прокси, а не как корень. Это
    /// единственное место, где сетевой identity подменяется — все сетевые операции идут через
    /// него. Если запись прокси сожжена (или никогда не создавалась), это `Err`: НИКАКОГО тихого
    /// отката на вывод из фразы — именно такой откат воссоздал бы "сожжённую" личность и обнулил
    /// бы весь смысл сжигания.
    pub fn load_account(&self) -> io::Result<Account> {
        Ok(match self.proxy {
            None => crate::seed::derive(&self.load_entropy()?).account,
            Some(idx) => self.proxy_identity(idx)?.account,
        })
    }

    /// Which SLOT of this account the current handle presents credentials as: `"root"` for the
    /// root store, `"p<index>"` acting as a proxy. Part of the capability map's key, so a proxy
    /// can only ever find the credential IT earned (A8-4 — see `capability_path`).
    fn cap_slot(&self) -> String {
        match self.proxy {
            None => "root".to_string(),
            Some(idx) => format!("p{idx}"),
        }
    }

    /// Key into `CapabilityFile::per_slot`: relay-id (128 hex) ‖ `:` ‖ slot. Both halves are
    /// required — a credential is issued BY one relay TO one slot, and neither substitution is
    /// allowed (CRYPTO-24 for the relay half, A8-4 for the slot half).
    fn cap_key(&self, relay: &crate::RelayId) -> String {
        format!("{}:{}", relay.hex(), self.cap_slot())
    }

    /// Every admission credential this account holds. Absent → none held.
    fn load_capabilities(&self) -> io::Result<CapabilityFile> {
        match std::fs::read(self.capability_path()) {
            Ok(blob) => {
                let json = self.key.open(&self.label(&self.capability_path()), &blob).map_err(|e| {
                    io_err(format!("admission credentials unreadable ({e}) — refusing to treat \
                         them as absent; restore the file or re-import the invite"))
                })?;
                serde_json::from_slice(&json).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Default::default()),
            Err(e) => Err(e),
        }
    }

    /// Write the whole credential file back, sealed. Callers read-modify-write so that one slot's
    /// change never drops another's entries.
    fn store_capabilities(&self, all: &CapabilityFile) -> io::Result<()> {
        let json = serde_json::to_vec(all).map_err(io_err)?;
        let blob = self.key.seal(&self.label(&self.capability_path()), &json);
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(self.capability_path())?;
        f.write_all(&blob)
    }

    /// Store an admission credential AS THIS SLOT'S CREDENTIAL FOR ONE RELAY (re-earning can
    /// repeat → overwrite allowed). The secret is an admission credential, so it is encrypted at
    /// rest like every other secret, not merely 0600.
    ///
    /// CRYPTO-24: a capability is relay-specific in production. A Private relay mints its own
    /// random `capability_id + secret`; a Public relay derives a stateless secret from ITS OWN
    /// issuer key. So one account-wide credential presented to a second relay is not merely
    /// useless there — it is rejected (`UnknownCapability`/`BadMac`), which silently broke the
    /// two things multi-homing exists for: publishing a bundle on a backup relay (creating a slot
    /// is metered — see `RelayNode::handle_publish`) and failing a send over to it. It also
    /// handed every relay the SAME `capability_id`, linking one account's traffic across relays
    /// that otherwise share nothing. Keyed by relay-id, none of that can happen by construction:
    /// there is no way to ask for "the" capability without naming the relay it is for.
    ///
    /// A8-4: the key names the SLOT too, so `store.as_proxy(3)` writes proxy 3's credential and
    /// nothing else can read it. The credential a proxy presents is the one that proxy earned.
    pub fn save_capability_for(&self, relay: &crate::RelayId, cap: &Capability) -> io::Result<()> {
        let mut all = self.load_capabilities()?;
        all.per_slot.insert(self.cap_key(relay), cap.clone());
        self.store_capabilities(&all)
    }

    /// Store a credential that CANNOT be split per proxy, so every slot presents the same one.
    ///
    /// This is the honest name for the one door where per-proxy issuance is impossible rather
    /// than merely unimplemented: an operator invite is a single credential, resolved once and
    /// revocable as a unit (#231), so N proxies cannot each hold their own — only the operator
    /// can mint N of them. The dev capability is the other case, and for the opposite reason:
    /// its secret is published in this repository, so it is the same id for every user on earth
    /// and splitting it would separate nothing.
    ///
    /// The cost is exactly the A8-4 linkage: at an invite-only relay, every proxy of this account
    /// presents one `capability_id` and the relay can cluster them. That is a property of the
    /// invite door, not of this code, and it is why it lives behind its own method — sharing must
    /// be something a caller ASKS for, never what happens when per-proxy issuance fails.
    pub fn save_shared_capability_for(
        &self,
        relay: &crate::RelayId,
        cap: &Capability,
    ) -> io::Result<()> {
        let mut all = self.load_capabilities()?;
        all.shared.insert(relay.hex(), cap.clone());
        self.store_capabilities(&all)
    }

    /// The credential THIS SLOT presents to THIS relay, or `NotFound` if it holds none.
    ///
    /// Resolution order is: this slot's own earned credential, then a credential explicitly
    /// marked unsplittable for this relay (`save_shared_capability_for`). Never another SLOT's
    /// credential and never another RELAY's — a caller that cannot get one must skip the relay,
    /// not substitute. Falling back to a sibling proxy's credential is precisely the linkage
    /// A8-4 names, so its absence here is load-bearing.
    ///
    /// An unreadable `capabilities.dat` is an ERROR here and on every save (the save reads first,
    /// to keep the other slots' entries), so a corrupt file wedges importing too. That is
    /// deliberate — silently starting a fresh map would drop credentials the user still has and
    /// cannot tell are gone — and the exit is manual and explicit: delete `capabilities.dat` and
    /// re-earn (`karst join`) or re-import (`karst import-cap`) for each relay.
    pub fn load_capability_for(&self, relay: &crate::RelayId) -> io::Result<Capability> {
        let mut all = self.load_capabilities()?;
        all.per_slot
            .remove(&self.cap_key(relay))
            .or_else(|| all.shared.remove(&relay.hex()))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        // Frontend-NEUTRAL on purpose. This crate serves the CLI and the
                        // desktop, and the message used to name `karst join` / `karst import-cap`
                        // — telling a desktop user to run commands their app does not have.
                        // Each frontend appends its own route to the fix.
                        "no admission credential for relay {} on channel {} — this relay is \
                         invite-only or has not been joined yet",
                        &relay.hex()[..16],
                        self.cap_slot()
                    ),
                )
            })
    }

    /// Whether THIS SLOT has already earned its OWN credential for `relay` — i.e. whether the
    /// backfill pass still owes it one. Distinct from `has_capability_for`, which is satisfied by
    /// a shared invite credential: a slot riding a shared credential should still earn its own
    /// the moment the relay's door allows it.
    pub fn has_own_capability_for(&self, relay: &crate::RelayId) -> io::Result<bool> {
        Ok(self.load_capabilities()?.per_slot.contains_key(&self.cap_key(relay)))
    }

    /// Drop every credential belonging to proxy `index` (all relays). Called from `burn_proxy`:
    /// the credentials are keyed per slot, so nothing else would ever remove them, and a burned
    /// proxy's admission secret lingering on disk is state a burn is supposed to destroy.
    fn forget_proxy_capabilities(&self, index: u32) -> io::Result<()> {
        let suffix = format!(":p{index}");
        let mut all = self.load_capabilities()?;
        let before = all.per_slot.len();
        all.per_slot.retain(|k, _| !k.ends_with(&suffix));
        if all.per_slot.len() != before {
            self.store_capabilities(&all)?;
        }
        Ok(())
    }

    // ----- Discovery key (opt-in contact code), encrypted at-rest -----
    //
    // A RANDOM secret decoupled from the seed-derived identity, stored in its own file so it can be
    // rotated (overwrite) or removed (turn discovery off) WITHOUT touching the recovery-phrase root.
    // Its absence = discovery is off.

    fn discovery_path(&self) -> PathBuf {
        self.net_file("discovery.key")
    }

    /// Whether the user has an active discovery key (i.e. discovery is on).
    pub fn has_discovery(&self) -> bool {
        self.discovery_path().exists()
    }

    /// Write (or rotate) the discovery secret. Overwrite is intentional: rotating retires the old
    /// contact code. 0600, sealed at-rest like the other secrets.
    pub fn save_discovery(&self, secret: &[u8; 32]) -> io::Result<()> {
        let blob = self.key.seal(&self.label(&self.discovery_path()), secret);
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(self.discovery_path())?;
        f.write_all(&blob)
    }

    /// Read the discovery secret, or `NotFound` if discovery is off.
    pub fn load_discovery(&self) -> io::Result<[u8; 32]> {
        let blob = std::fs::read(self.discovery_path())?;
        let secret = self.key.open(&self.label(&self.discovery_path()), &blob).map_err(io_err)?;
        secret.as_slice().try_into().map_err(|_| io_err("discovery: not 32 bytes"))
    }

    /// Remove the discovery key (turn discovery off locally). Idempotent.
    pub fn delete_discovery(&self) -> io::Result<()> {
        match std::fs::remove_file(self.discovery_path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    // ----- Invite codes (one discovery row each), encrypted at-rest -----
    //
    // An invite is a SECOND discovery row published under its own fresh random secret, so it
    // neither touches nor rotates the persistent contact code. That secret used to be thrown away
    // at mint time, which left the RELAY as the only party able to retire the row — and the relay
    // learns only that someone read it, never whether the invitee actually finished adding you
    // (A10-4). Keeping the secret moves the retire decision to the party that can know.
    //
    // What the secret authorises is exactly one thing: rewriting or deleting THAT discovery row
    // (`discovery::write_msg` / `delete_msg` are signed with it). It decrypts nothing, it is not
    // an identity key, and it cannot be used to publish a row pointing at a different IK — the
    // relay checks the IK's own signature over the binding.

    fn invites_path(&self) -> PathBuf {
        self.net_file("invites.dat")
    }

    /// How many outstanding invites one identity may hold. Each is a discovery row at the relay
    /// (bounded there by `MAX_BUNDLES`), so the cap keeps a stuck "mint invite" loop from filling
    /// the relay's discovery map — and keeps this file small.
    pub const MAX_INVITES: usize = 32;

    /// Every outstanding invite, oldest first. Absent file = none. An UNREADABLE file is an error,
    /// not "none": treating it as empty would silently drop the only keys that can revoke rows
    /// still published under this identity (same rule as `capabilities.dat`).
    pub fn load_invites(&self) -> io::Result<Vec<InviteRecord>> {
        match std::fs::read(self.invites_path()) {
            Ok(blob) => {
                let plain = self.key.open(&self.label(&self.invites_path()), &blob).map_err(|e| {
                    io_err(format!(
                        "invite list unreadable ({e}) — refusing to treat it as empty; those \
                         invites would stay published with nothing able to revoke them"
                    ))
                })?;
                postcard::from_bytes(&plain).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    fn save_invites(&self, invites: &[InviteRecord]) -> io::Result<()> {
        let plain = postcard::to_stdvec(invites).map_err(io_err)?;
        self.write_sealed(&self.invites_path(), &plain)
    }

    /// Record a freshly minted invite. Expired entries are dropped first (their rows are gone at
    /// the relay too), so the cap counts only invites that can still resolve.
    pub fn add_invite(&self, invite: InviteRecord, now: u64) -> io::Result<()> {
        let mut all = self.load_invites()?;
        all.retain(|i| i.expiry > now);
        if all.len() >= Self::MAX_INVITES {
            return Err(io_err(format!(
                "already holding {} outstanding invites — revoke one (or let it expire) first",
                Self::MAX_INVITES
            )));
        }
        all.push(invite);
        self.save_invites(&all)
    }

    /// Forget the invite with this secret (after its row is gone at the relay). Returns whether
    /// one was held.
    pub fn remove_invite(&self, secret: &[u8; 32]) -> io::Result<bool> {
        let mut all = self.load_invites()?;
        let before = all.len();
        all.retain(|i| &i.secret != secret);
        if all.len() == before {
            return Ok(false);
        }
        self.save_invites(&all)?;
        Ok(true)
    }

    // ----- Контакты (имена + флаг сверки), шифрованы at-rest -----

    fn contacts_path(&self) -> PathBuf {
        self.dir.join("contacts.dat")
    }

    /// Загрузить контакты (пусто, если файла нет). Расшифровывается at-rest-ключом.
    pub fn load_contacts(&self) -> io::Result<Vec<ContactRecord>> {
        match std::fs::read(self.contacts_path()) {
            Ok(blob) => {
                let bytes = self.key.open(&self.label(&self.contacts_path()), &blob).map_err(io_err)?;
                postcard::from_bytes(&bytes).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// АТОМАРНО сохранить список контактов (temp 0600 → fsync → rename). Полная
    /// перезапись (список маленький, не append-лог). Единственный писатель — GUI-
    /// процесс, поэтому без flock (в отличие от sessions/history, где гонка ведёт к
    /// keystream-reuse; тут максимум — потеря последнего переименования контакта).
    pub fn save_contacts(&self, contacts: &[ContactRecord]) -> io::Result<()> {
        let plain = postcard::to_stdvec(contacts).map_err(io_err)?;
        let bytes = self.key.seal(&self.label(&self.contacts_path()), &plain);
        let tmp = self.dir.join("contacts.dat.tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, self.contacts_path())
    }

    // ----- Блок-лист (IK, от которых НЕ принимаем входящее), шифрован at-rest -----
    //
    // Отдельный sidecar (НЕ поле в `ContactRecord`: тот postcard-позиционен, новое
    // поле осиротило бы имена/флаги сверки на диске). Whole-file atomic, как contacts.

    fn blocked_path(&self) -> PathBuf {
        self.dir.join("blocked.dat")
    }

    /// Загрузить множество заблокированных IK (пусто, если файла нет).
    pub fn load_blocked(&self) -> io::Result<BTreeSet<[u8; 32]>> {
        match std::fs::read(self.blocked_path()) {
            Ok(blob) => {
                let bytes = self.key.open(&self.label(&self.blocked_path()), &blob).map_err(io_err)?;
                postcard::from_bytes(&bytes).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
            Err(e) => Err(e),
        }
    }

    /// Заблокировать/разблокировать `ik`. Идемпотентно. Пустой список удаляет файл.
    /// Атомарно (temp→fsync→rename). Единственный писатель — GUI, поэтому без flock.
    pub fn set_blocked(&self, ik: [u8; 32], blocked: bool) -> io::Result<()> {
        let mut set = self.load_blocked()?;
        let changed = if blocked { set.insert(ik) } else { set.remove(&ik) };
        if !changed {
            return Ok(());
        }
        if set.is_empty() {
            match std::fs::remove_file(self.blocked_path()) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            return Ok(());
        }
        let plain = postcard::to_stdvec(&set).map_err(io_err)?;
        let bytes = self.key.seal(&self.label(&self.blocked_path()), &plain);
        let tmp = self.dir.join("blocked.dat.tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, self.blocked_path())
    }

    // ----- Unconfirmed peers: chat-only, NOT confirmed contacts (conversation vs contact) -----
    //
    // You can DM anyone by IK without "adding" them; such a peer goes in `contacts.dat` (so the chat
    // shows) but is FLAGGED here as unconfirmed. A confirmed contact = in contacts.dat and NOT in this
    // set. The distinction gates whether we render their self-declared name/avatar and their posts,
    // and whether OUR profile/posts fan out to them. A SEPARATE SIDECAR for the same reason as
    // `blocked.dat`: `ContactRecord` is postcard-positional, so a new field would orphan every
    // existing name/verify-flag on disk. Migration is inherently safe — an old vault has no sidecar,
    // so the set is empty and every existing contact stays confirmed.

    fn reduced_fs_path(&self) -> PathBuf {
        self.net_file("reduced_fs.dat")
    }

    /// Peers whose session was opened WITHOUT a one-time prekey — 3-DH instead of 4-DH.
    ///
    /// The relay serves the one-time prekey, and while it can no longer substitute one (each is
    /// signed — `pqxdh::SignedOpk`), it can withhold every one and claim exhaustion, which is
    /// indistinguishable from real exhaustion. Refusing to talk would turn a downgrade into a
    /// lockout, so the send proceeds — and lands here, so the fact is recoverable afterwards
    /// instead of vanishing into a discarded return value. IDENTITY-scoped (`net_file`): which
    /// proxy opened a session is not shared across proxies.
    pub fn load_reduced_fs(&self) -> io::Result<BTreeSet<[u8; 32]>> {
        match std::fs::read(self.reduced_fs_path()) {
            Ok(blob) => {
                let bytes =
                    self.key.open(&self.label(&self.reduced_fs_path()), &blob).map_err(io_err)?;
                postcard::from_bytes(&bytes).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
            Err(e) => Err(e),
        }
    }

    /// Record that first contact with `ik` got no one-time prekey. Idempotent.
    pub fn mark_reduced_fs(&self, ik: [u8; 32]) -> io::Result<()> {
        let mut set = self.load_reduced_fs()?;
        if !set.insert(ik) {
            return Ok(());
        }
        let plain = postcard::to_stdvec(&set).map_err(io_err)?;
        self.write_sealed(&self.reduced_fs_path(), &plain)
    }

    fn unconfirmed_path(&self) -> PathBuf {
        self.dir.join("unconfirmed.dat")
    }

    /// The set of chat-only peers (not confirmed contacts). Empty if the file is missing.
    pub fn load_unconfirmed(&self) -> io::Result<BTreeSet<[u8; 32]>> {
        match std::fs::read(self.unconfirmed_path()) {
            Ok(blob) => {
                let bytes = self.key.open(&self.label(&self.unconfirmed_path()), &blob).map_err(io_err)?;
                postcard::from_bytes(&bytes).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
            Err(e) => Err(e),
        }
    }

    /// Flag / unflag `ik` as unconfirmed (chat-only). `true` = a conversation that is not a contact;
    /// `false` = confirmed contact (or never was chat-only). Idempotent; empty set removes the file.
    /// Atomic (temp→fsync→rename), single GUI writer, like `blocked`/`contacts`.
    ///
    /// Bounded by `MAX_CONTACTS` (SEC-44) as defense in depth: the only caller that FLAGS a new ik
    /// (`add_unconfirmed_contact`) already gates on the same cap before ever reaching here, but a
    /// future caller must not be able to reopen the flood by forgetting to check first.
    pub fn set_unconfirmed(&self, ik: [u8; 32], unconfirmed: bool) -> io::Result<()> {
        let mut set = self.load_unconfirmed()?;
        if unconfirmed && !set.contains(&ik) && set.len() >= MAX_CONTACTS {
            eprintln!("warning: unconfirmed-peers set at cap ({MAX_CONTACTS}) — not flagging a new sender IK");
            return Ok(());
        }
        let changed = if unconfirmed { set.insert(ik) } else { set.remove(&ik) };
        if !changed {
            return Ok(());
        }
        if set.is_empty() {
            match std::fs::remove_file(self.unconfirmed_path()) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            return Ok(());
        }
        let plain = postcard::to_stdvec(&set).map_err(io_err)?;
        let bytes = self.key.seal(&self.label(&self.unconfirmed_path()), &plain);
        let tmp = self.dir.join("unconfirmed.dat.tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, self.unconfirmed_path())
    }

    /// Auto-register `ik` as a CHAT-ONLY (unconfirmed) conversation on first contact, so an
    /// unknown sender's message is never decrypted-and-invisible (the receive path surfaces it
    /// this way instead of silently dropping it from the UI — see the desktop poll loop).
    /// Idempotent: an already-known `ik` is returned as-is, confirmed/unconfirmed status
    /// untouched either way.
    ///
    /// Bounded by `MAX_CONTACTS` (SEC-44): past the cap a stream of fresh sender IKs (free to
    /// mint) stops growing `contacts.dat`/`unconfirmed.dat` — logged, not silently swallowed, but
    /// with no user-facing error (there is no channel to report "ignored" through on a receive
    /// path with no ack protocol). This is ONLY the automatic registration path; an EXPLICIT
    /// `add_contact` from the user is a different call and is never capped by this.
    ///
    /// Returns whether a new entry was added (false: already known, or refused at the cap).
    pub fn add_unconfirmed_contact(&self, ik: [u8; 32]) -> io::Result<bool> {
        let mut cs = self.load_contacts()?;
        if cs.iter().any(|c| c.ik == ik) {
            return Ok(false); // already known — leave confirmed/unconfirmed status untouched
        }
        if cs.len() >= MAX_CONTACTS {
            eprintln!("warning: contacts at cap ({MAX_CONTACTS}) — ignoring a new sender IK");
            return Ok(false);
        }
        // No frozen name: an EMPTY label resolves to the peer's self-declared profile name ONLY
        // once confirmed, else a short IK, and stays renameable — you never get stuck with a hex
        // stub.
        cs.push(ContactRecord { name: String::new(), ik, verified: false });
        self.save_contacts(&cs)?;
        self.set_unconfirmed(ik, true)?; // chat-only until explicitly added to contacts
        Ok(true)
    }

    /// Ensure `ik` is a CONFIRMED contact: add the record if new (subject to the SAME cap as
    /// `add_unconfirmed_contact`) and clear any unconfirmed flag either way — used when a mutual
    /// add completes (`ContactAccept`) or the user explicitly confirms.
    ///
    /// SEC-44: a `ContactAccept` is processed AUTOMATICALLY on receipt (no per-message human
    /// click gates it — see the desktop poll loop), so this call site is exactly as
    /// remote-reachable as `add_unconfirmed_contact`'s. It MUST share `MAX_CONTACTS`, or an
    /// attacker could bypass the cap entirely just by sending `ContactAccept` instead of any
    /// other content: unbounded `contacts.dat` growth, same O(N²) full-file rewrites. An EXPLICIT
    /// user action (`add_contact`) is a different call and is never capped by this.
    ///
    /// Returns whether a new entry was added (false: already known, or refused at the cap).
    pub fn add_confirmed_contact(&self, ik: [u8; 32]) -> io::Result<bool> {
        let mut cs = self.load_contacts()?;
        let added = if cs.iter().any(|c| c.ik == ik) {
            false
        } else if cs.len() >= MAX_CONTACTS {
            eprintln!("warning: contacts at cap ({MAX_CONTACTS}) — ignoring a new sender IK");
            return Ok(false); // refused outright: never partially add, never touch unconfirmed
        } else {
            cs.push(ContactRecord { name: String::new(), ik, verified: false });
            self.save_contacts(&cs)?;
            true
        };
        self.set_unconfirmed(ik, false)?; // promote to confirmed either way (already-known or new)
        Ok(added)
    }

    /// Whether `ik` is a CONFIRMED contact: present in `contacts.dat` and NOT flagged unconfirmed.
    /// The single gate for "may we show their name/avatar/posts and fan ours out to them".
    pub fn is_confirmed_contact(&self, ik: &[u8; 32]) -> io::Result<bool> {
        if self.load_unconfirmed()?.contains(ik) {
            return Ok(false);
        }
        Ok(self.load_contacts()?.iter().any(|c| &c.ik == ik))
    }

    // ----- PUBLIC posts: which of OUR posts may be served to a live-pull "visitor" (#109) -----
    //
    // A post published to ALL subscribers is PUBLIC and pullable by anyone who visits; a post with a
    // NARROW audience (specific subscribers) is NOT, and must never be handed to a random puller. We
    // record public post ids in this sidecar (a set of 16-byte ids) — a separate file for the same
    // reason as `blocked`/`unconfirmed`: `FeedRecord` is postcard-positional, so a new field would
    // orphan `feed.dat`.

    fn public_posts_path(&self) -> PathBuf {
        self.dir.join("public_posts.dat")
    }

    /// The set of OUR post ids that were published publicly (servable to a puller). Empty if missing.
    pub fn load_public_posts(&self) -> io::Result<BTreeSet<[u8; 16]>> {
        match std::fs::read(self.public_posts_path()) {
            Ok(blob) => {
                let bytes = self.key.open(&self.label(&self.public_posts_path()), &blob).map_err(io_err)?;
                postcard::from_bytes(&bytes).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
            Err(e) => Err(e),
        }
    }

    /// Mark one of our posts PUBLIC (pullable). Idempotent; pruned to posts still in the feed so the
    /// set can't grow forever. Atomic, single GUI writer, like the other sidecars.
    pub fn mark_public_post(&self, id: [u8; 16]) -> io::Result<()> {
        let mut set = self.load_public_posts()?;
        set.insert(id);
        // Drop ids whose post left the (capped) feed — keep the one we're adding.
        let live: BTreeSet<[u8; 16]> = self.load_feed()?.into_iter().map(|f| f.id).collect();
        set.retain(|id2| *id2 == id || live.contains(id2));
        let plain = postcard::to_stdvec(&set).map_err(io_err)?;
        let bytes = self.key.seal(&self.label(&self.public_posts_path()), &plain);
        let tmp = self.dir.join("public_posts.dat.tmp");
        {
            let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, self.public_posts_path())
    }

    // ----- PULLED authors: profiles we live-pulled posts from, so their reply posts are accepted -----
    //
    // Visiting a profile you don't subscribe to sends a `PostsRequest`; the author replies with their
    // public posts as `Publication`s. Those would normally be dropped (you're not subscribed), so we
    // record the pulled author here and the feed-source gate accepts them — the reply lands in the
    // profile view. Persisted so a reply arriving on a later poll still gets through.

    fn pulled_path(&self) -> PathBuf {
        self.dir.join("pulled.dat")
    }

    /// The set of author IKs we've live-pulled posts from. Empty if missing.
    pub fn load_pulled(&self) -> io::Result<BTreeSet<[u8; 32]>> {
        match std::fs::read(self.pulled_path()) {
            Ok(blob) => {
                let bytes = self.key.open(&self.label(&self.pulled_path()), &blob).map_err(io_err)?;
                postcard::from_bytes(&bytes).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
            Err(e) => Err(e),
        }
    }

    /// Record `ik` as an author we pulled from (idempotent). Atomic, single GUI writer.
    pub fn add_pulled(&self, ik: [u8; 32]) -> io::Result<()> {
        let mut set = self.load_pulled()?;
        if !set.insert(ik) {
            return Ok(());
        }
        let plain = postcard::to_stdvec(&set).map_err(io_err)?;
        let bytes = self.key.seal(&self.label(&self.pulled_path()), &plain);
        let tmp = self.dir.join("pulled.dat.tmp");
        {
            let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, self.pulled_path())
    }

    /// Whether `ik`'s feed content belongs to us: an account we SUBSCRIBED to (a `JoinAccept` we
    /// asked for wrote it into `channel_peers`) or one we live-pulled from (we sent them a
    /// `PostsRequest`). Both halves are anchored in a LOCAL act — there is no way for a peer to
    /// put itself in either set unilaterally, which is what makes this a consent gate and not a
    /// mere acquaintance check.
    ///
    /// Deliberately NOT `is_confirmed_contact`: posts are decoupled from the address book here
    /// (you follow or peek; a contact does not get feed rights for being a contact), so a
    /// contact-based gate would be wrong in BOTH directions — it would admit a contact you never
    /// followed and reject a channel you did.
    ///
    /// Lives on `Store` rather than in the desktop layer because the receive path (`lib.rs`)
    /// must apply the same gate BEFORE it commits attacker-supplied work to disk, and it has
    /// only a `Store`.
    pub fn is_feed_source(&self, ik: &[u8; 32]) -> bool {
        self.load_channel_peers().contains(ik) || self.load_pulled().is_ok_and(|s| s.contains(ik))
    }

    // ----- Profile: own (`profile.dat`) + cache of peers' (`peer_profiles.dat`) -----
    //
    // Both are BEST-EFFORT (corrupt/foreign blob -> empty, NOT an error): these are
    // display hints and must not block unlock/receive. A received peer profile is
    // length-clamped BEFORE storage (anti-absurd) and NEVER touches contacts.dat
    // (name/`verified`) — only its own per-IK cache. Whole-file atomic, like contacts.

    fn profile_path(&self) -> PathBuf {
        self.dir.join("profile.dat")
    }

    fn peer_profiles_path(&self) -> PathBuf {
        self.dir.join("peer_profiles.dat")
    }

    /// Path of the sealed in-flight inline-transfer state (see `content::Reassembler::export`).
    fn partials_path(&self) -> PathBuf {
        self.net_file("partials.dat")
    }

    /// Persist the in-flight inline transfers, sealed. Called after a receive batch so a crash
    /// cannot lose chunks whose carrier messages were already acked (the relay drops those).
    pub fn save_partials(&self, blob: &[u8]) -> io::Result<()> {
        self.write_sealed(&self.partials_path(), blob)
    }

    /// Load the in-flight inline transfers. Absent = nothing was in flight; a file that EXISTS but
    /// cannot be opened is an ERROR, not "nothing" — treating corruption as empty is exactly the
    /// silent loss this state was added to prevent.
    pub fn load_partials(&self) -> io::Result<Vec<u8>> {
        match std::fs::read(self.partials_path()) {
            Ok(blob) => self.key.open(&self.label(&self.partials_path()), &blob).map_err(|e| {
                io_err(format!("in-flight transfers unreadable ({e}) — refusing to treat them as absent"))
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Load the persisted one-time prekey SECRETS (see `pqxdh::Account::export_opk_secrets`).
    ///
    /// They live INSIDE the session state file — see `save_receive_commit` for why — so a
    /// file that exists but cannot be opened or decoded is an ERROR here, not "no keys".
    /// Returning an empty list made the client believe it held none, mint a fresh batch and
    /// publish it — while the relay went on handing out the OLD public keys whose secrets had
    /// just been declared missing. Every initiator that received one produced an opener the
    /// recipient could no longer accept: silent, one-sided first-contact failure that looks like
    /// the network dropping messages (R2-4). Absent is still legitimately empty.
    pub fn load_opks(&self) -> io::Result<Vec<node::pqxdh::OneTimeSecret>> {
        Ok(self.read_session_file()?.map(|f| f.opks).unwrap_or_default())
    }

    /// Persist the one-time prekey secrets alone, keeping the session state that shares their
    /// file. For the PUBLISH side (mint a batch, store the secrets, then advertise the public
    /// halves); the RECEIVE side must use `save_receive_commit` instead, because there the two
    /// halves change together. **Private keys in the clear** — 0600.
    ///
    /// Read-modify-write of a shared file: the caller must hold `lock_sessions`, or a concurrent
    /// send/receive can interleave and one of the two writes loses the other's half.
    pub fn save_opks(&self, opks: &[node::pqxdh::OneTimeSecret]) -> io::Result<()> {
        // Carry the session bytes across OPAQUELY (never decode → re-encode): a state this call
        // cannot parse is still a state the ratchet may need, and re-encoding would make every
        // OPK top-up a chance to rewrite it.
        let state = match self.read_session_file()? {
            Some(f) => f.state,
            None => postcard::to_stdvec(&PeerState::empty()).map_err(io_err)?,
        };
        self.write_session_file(&state, opks)
    }

    fn quic_endpoints_path(&self) -> PathBuf {
        self.dir.join("quic_endpoints.dat")
    }

    /// UDP endpoints each relay declared for ITSELF, cached as `(relay_id_hex, endpoints)`.
    ///
    /// A CACHE, not configuration: it holds an availability hint the relay gave about itself, and
    /// losing it costs one node-list round trip, never a message. Kept as its own sidecar so a
    /// relay learning QUIC does not rewrite `NetSettings`, whose postcard-positional layout is a
    /// bad place to grow a field, and so a stale entry can simply be dropped.
    ///
    /// It is worth being explicit about what a corrupted or hostile entry here could do: send the
    /// client at a wrong UDP address. That costs a connection attempt the transport race absorbs.
    /// It cannot reach a different relay, because identity is still `Noise_NK` against the pinned
    /// relay-id over whichever carrier answers.
    pub fn load_quic_endpoints(&self) -> io::Result<Vec<(String, Vec<String>)>> {
        match std::fs::read(self.quic_endpoints_path()) {
            Ok(blob) => Ok(self
                .key
                .open(&self.label(&self.quic_endpoints_path()), &blob)
                .ok()
                .and_then(|b| postcard::from_bytes(&b).ok())
                .unwrap_or_default()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Record what `relay_id_hex` says its QUIC endpoints are. An empty list is meaningful and is
    /// stored: it is the relay saying "I do not offer QUIC", which should stop the client trying.
    pub fn set_quic_endpoints(&self, relay_id_hex: &str, endpoints: &[String]) -> io::Result<()> {
        let mut all = self.load_quic_endpoints()?;
        match all.iter_mut().find(|(id, _)| id == relay_id_hex) {
            Some((_, v)) => *v = endpoints.to_vec(),
            None => all.push((relay_id_hex.to_string(), endpoints.to_vec())),
        }
        let plain = postcard::to_stdvec(&all).map_err(io_err)?;
        self.write_sealed(&self.quic_endpoints_path(), &plain)
    }

    fn extra_relays_path(&self) -> PathBuf {
        self.dir.join("extra_relays.dat")
    }

    /// SECONDARY relays this account multi-homes to, as `(addr, relay_id)` pairs — the
    /// primary lives in [`NetSettings`]; these are the extra ones. A SEPARATE sidecar on
    /// purpose: appending to the postcard-positional `NetSettings` would fail to
    /// deserialize every already-saved `net.dat`, silently dropping the primary config.
    /// Absent → empty (single-homed, backward compatible). Encrypted at rest.
    pub fn load_extra_relays(&self) -> io::Result<Vec<(String, String)>> {
        match std::fs::read(self.extra_relays_path()) {
            Ok(blob) => Ok(self
                .key
                .open(&self.label(&self.extra_relays_path()), &blob)
                .ok()
                .and_then(|b| postcard::from_bytes(&b).ok())
                .unwrap_or_default()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Atomically persist the secondary relay list (full rewrite).
    pub fn save_extra_relays(&self, relays: &[(String, String)]) -> io::Result<()> {
        let plain = postcard::to_stdvec(relays).map_err(io_err)?;
        self.write_sealed(&self.extra_relays_path(), &plain)
    }

    /// Own profile (empty by default / best-effort on corruption).
    pub fn load_profile(&self) -> io::Result<Profile> {
        match std::fs::read(self.profile_path()) {
            Ok(blob) => Ok(self
                .key
                .open(&self.label(&self.profile_path()), &blob)
                .ok()
                .and_then(|b| postcard::from_bytes(&b).ok())
                .unwrap_or_default()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Profile::default()),
            Err(e) => Err(e),
        }
    }

    /// ATOMICALLY save own profile (length-clamped before writing).
    pub fn save_profile(&self, p: &Profile) -> io::Result<()> {
        let clamped = Profile {
            name: clamp_str(&p.name, crate::content::MAX_PROFILE_NAME),
            bio: clamp_str(&p.bio, crate::content::MAX_PROFILE_BIO),
            avatar: p.avatar.clone(),
            // Defense in depth: bound gallery count + per-photo size even though the GUI already does.
            photos: p
                .photos
                .iter()
                .filter(|ph| !ph.is_empty() && ph.len() <= crate::content::MAX_AVATAR_BYTES)
                .take(crate::content::MAX_GALLERY_PHOTOS)
                .cloned()
                .collect(),
            photos_ts: p.photos_ts,
        };
        let plain = postcard::to_stdvec(&clamped).map_err(io_err)?;
        self.write_sealed(&self.profile_path(), &plain)
    }

    /// Cache of contacts' profiles (empty by default / best-effort on corruption).
    pub fn load_peer_profiles(&self) -> io::Result<BTreeMap<[u8; 32], Profile>> {
        match std::fs::read(self.peer_profiles_path()) {
            Ok(blob) => Ok(self
                .key
                .open(&self.label(&self.peer_profiles_path()), &blob)
                .ok()
                .and_then(|b| postcard::from_bytes(&b).ok())
                .unwrap_or_default()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(e),
        }
    }

    /// Apply a RECEIVED text profile from `ik`: clamps name/bio while PRESERVING an
    /// already-known avatar (the avatar rides a separate control message). NEVER
    /// writes to contacts.dat. Bounded by `MAX_PEER_PROFILES` (anti-flood from unknown
    /// IKs: on overflow a new key is ignored, known ones still update).
    pub fn set_peer_profile(&self, ik: [u8; 32], name: &str, bio: &str) -> io::Result<()> {
        let mut map = self.load_peer_profiles()?;
        if !map.contains_key(&ik) && map.len() >= MAX_PEER_PROFILES {
            return Ok(());
        }
        let entry = map.entry(ik).or_default();
        entry.name = clamp_str(name, crate::content::MAX_PROFILE_NAME);
        entry.bio = clamp_str(bio, crate::content::MAX_PROFILE_BIO);
        let plain = postcard::to_stdvec(&map).map_err(io_err)?;
        self.write_sealed(&self.peer_profiles_path(), &plain)
    }

    /// Forget a peer's cached profile (on removing a contact). Idempotent.
    pub fn remove_peer_profile(&self, ik: [u8; 32]) -> io::Result<()> {
        let mut map = self.load_peer_profiles()?;
        if map.remove(&ik).is_none() {
            return Ok(());
        }
        let plain = postcard::to_stdvec(&map).map_err(io_err)?;
        self.write_sealed(&self.peer_profiles_path(), &plain)
    }

    /// Set (or clear, with `None`) OUR avatar bytes, preserving name/bio. Rejects
    /// over-cap bytes (defense in depth — the GUI already bounds them).
    pub fn set_own_avatar(&self, avatar: Option<Vec<u8>>) -> io::Result<()> {
        if let Some(a) = &avatar {
            if a.len() > crate::content::MAX_AVATAR_BYTES {
                return Err(io_err("avatar over cap"));
            }
        }
        let mut prof = self.load_profile()?;
        prof.avatar = avatar;
        self.save_profile(&prof)
    }

    /// Apply a RECEIVED avatar from `ik`, preserving name/bio. Rejects over-cap bytes
    /// before storage; NEVER touches contacts.dat. Bounded by `MAX_PEER_PROFILES`.
    pub fn set_peer_avatar(&self, ik: [u8; 32], avatar: Vec<u8>) -> io::Result<()> {
        if avatar.len() > crate::content::MAX_AVATAR_BYTES {
            return Err(io_err("peer avatar over cap"));
        }
        let mut map = self.load_peer_profiles()?;
        if !map.contains_key(&ik) && map.len() >= MAX_PEER_PROFILES {
            return Ok(());
        }
        map.entry(ik).or_default().avatar = Some(avatar);
        let plain = postcard::to_stdvec(&map).map_err(io_err)?;
        self.write_sealed(&self.peer_profiles_path(), &plain)
    }

    /// Set OUR gallery photos (beyond the avatar), preserving name/bio/avatar. Bounds count +
    /// per-photo size (defense in depth — the GUI already re-encodes/bounds). `save_profile`
    /// re-applies the same clamp on write.
    pub fn set_own_photos(&self, photos: Vec<Vec<u8>>) -> io::Result<()> {
        let mut prof = self.load_profile()?;
        prof.photos = photos;
        self.save_profile(&prof)
    }

    /// Apply a RECEIVED gallery from `ik` with its sender-clock `ts`, replacing their whole gallery
    /// ATOMICALLY (mirrors how the sender edits it as one unit; an empty vec clears it). STALE-GUARD:
    /// a `ts` OLDER than the stored `photos_ts` is ignored — the same gallery can arrive twice out of
    /// order across the inline and blob paths, and the newer edit must win. Preserves name/bio/avatar;
    /// rejects over-cap photos; NEVER touches contacts.dat. Bounded by `MAX_PEER_PROFILES`.
    pub fn set_peer_photos(&self, ik: [u8; 32], photos: Vec<Vec<u8>>, ts: u64) -> io::Result<()> {
        let photos: Vec<Vec<u8>> = photos
            .into_iter()
            .filter(|p| !p.is_empty() && p.len() <= crate::content::MAX_AVATAR_BYTES)
            .take(crate::content::MAX_GALLERY_PHOTOS)
            .collect();
        let mut map = self.load_peer_profiles()?;
        if !map.contains_key(&ik) && map.len() >= MAX_PEER_PROFILES {
            return Ok(());
        }
        let entry = map.entry(ik).or_default();
        if ts < entry.photos_ts {
            return Ok(()); // an older gallery arrived after a newer one — keep the newer
        }
        entry.photos = photos;
        entry.photos_ts = ts;
        let plain = postcard::to_stdvec(&map).map_err(io_err)?;
        self.write_sealed(&self.peer_profiles_path(), &plain)
    }

    // ----- Feed: publications ("posts"), own + received (`feed.dat`) -----
    //
    // A single sealed file rewritten atomically per post (like `peer_profiles.dat`). Posts
    // are low-volume (nothing like per-keystroke chat), so an O(n) rewrite is cheap and keeps
    // us on the proven write_atomic path rather than the append-log machinery history needs.

    fn feed_path(&self) -> PathBuf {
        self.dir.join("feed.dat")
    }

    /// Load every retained publication (own + received), oldest first. A missing/corrupt
    /// file reads as an empty feed rather than an error (best-effort, like peer profiles).
    pub fn load_feed(&self) -> io::Result<Vec<FeedRecord>> {
        match std::fs::read(self.feed_path()) {
            Ok(blob) => Ok(self
                .key
                .open(&self.label(&self.feed_path()), &blob)
                .ok()
                .and_then(|b| postcard::from_bytes(&b).ok())
                .unwrap_or_default()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Append one publication, idempotently: a redelivered post (same author + id) is
    /// ignored, the text is clamped to one packet's budget, and the feed is capped to
    /// `MAX_FEED_POSTS` by dropping the oldest. Kept sorted by `ts` so readers get a stable
    /// timeline without re-sorting. Used for BOTH our own posts and received ones.
    pub fn append_feed(&self, rec: &FeedRecord) -> io::Result<()> {
        let mut feed = self.load_feed()?;
        if feed.iter().any(|f| f.author == rec.author && f.id == rec.id) {
            return Ok(()); // dedup a redelivered / re-sent copy
        }
        let mut rec = rec.clone();
        rec.text = clamp_str(&rec.text, crate::content::MAX_POST_TEXT);
        feed.push(rec);
        // PER-AUTHOR bound (anti-flood): keep only each author's newest `MAX_FEED_POSTS_PER_AUTHOR`,
        // so a contact flooding posts evicts only THEIR OWN oldest — never other people's or yours.
        feed.sort_by_key(|f| std::cmp::Reverse(f.ts)); // newest first
        {
            let mut per: BTreeMap<[u8; 32], usize> = BTreeMap::new();
            feed.retain(|f| {
                let c = per.entry(f.author).or_insert(0);
                *c += 1;
                *c <= MAX_FEED_POSTS_PER_AUTHOR
            });
        }
        feed.sort_by_key(|f| f.ts); // oldest first for the global cap
        // GLOBAL cap bounds the file; only reached if MANY authors each fill their quota.
        if feed.len() > MAX_FEED_POSTS {
            let drop = feed.len() - MAX_FEED_POSTS;
            feed.drain(0..drop); // oldest fall off the end of the window
        }
        let plain = postcard::to_stdvec(&feed).map_err(io_err)?;
        self.write_sealed(&self.feed_path(), &plain)
    }

    /// Remove a publication from the feed by (author, id). Used both for "delete for me" (our own
    /// post) and when a contact's RETRACTION arrives (their post). Idempotent: absent → no-op.
    /// Returns whether anything was removed.
    pub fn delete_feed_post(&self, author: [u8; 32], id: [u8; 16]) -> io::Result<bool> {
        let mut feed = self.load_feed()?;
        let before = feed.len();
        feed.retain(|f| !(f.author == author && f.id == id));
        if feed.len() == before {
            return Ok(false);
        }
        let plain = postcard::to_stdvec(&feed).map_err(io_err)?;
        self.write_sealed(&self.feed_path(), &plain)?;
        // A retracted/deleted post takes its image + attachments with it (no orphan in the sidecars).
        let _ = self.remove_feed_image(author, id);
        let _ = self.remove_feed_attachments(author, id);
        Ok(true)
    }

    // ----- Feed images: a per-post image in the `feed_images.dat` SIDECAR -----
    //
    // Kept OUT of `feed.dat` so adding image support never disturbs that file's postcard layout
    // (old text-only posts keep loading). Keyed by (author, post_id) — the same identity a post
    // has — so a `Publication`/`Story` and its (separately-chunked) image reunite on the receiver.

    fn feed_images_path(&self) -> PathBuf {
        self.dir.join("feed_images.dat")
    }

    /// Map of (author, post_id) → encoded image bytes. Absent/corrupt reads as empty (best-effort,
    /// like the feed itself). Public so the desktop can decrypt the sidecar ONCE per feed load
    /// (keys for `has_image`, all bytes for the lazy image batch) instead of per post.
    pub fn load_feed_images(&self) -> BTreeMap<([u8; 32], [u8; 16]), Vec<u8>> {
        std::fs::read(self.feed_images_path())
            .ok()
            .and_then(|b| self.key.open(&self.label(&self.feed_images_path()), &b).ok())
            .and_then(|b| postcard::from_bytes(&b).ok())
            .unwrap_or_default()
    }

    fn write_feed_images(&self, map: &BTreeMap<([u8; 32], [u8; 16]), Vec<u8>>) -> io::Result<()> {
        let plain = postcard::to_stdvec(map).map_err(io_err)?;
        self.write_sealed(&self.feed_images_path(), &plain)
    }

    /// The image attached to a post, if any.
    pub fn feed_image(&self, author: [u8; 32], id: [u8; 16]) -> Option<Vec<u8>> {
        self.load_feed_images().remove(&(author, id))
    }

    /// Attach an (already-encoded, bounded) image to a post. Rejects over-cap bytes at the door.
    /// Prunes any image whose post has left the feed, then bounds the sidecar to `MAX_FEED_IMAGES`
    /// by dropping the images for the oldest posts (by feed `ts`) — so a flood of image posts can
    /// only evict older images, never unbounded storage.
    pub fn set_feed_image(&self, author: [u8; 32], id: [u8; 16], bytes: Vec<u8>) -> io::Result<()> {
        if bytes.is_empty() || bytes.len() > crate::content::MAX_POST_IMAGE_BYTES {
            return Ok(()); // absurd size: ignore (the manifest check already gates the wire path)
        }
        let mut map = self.load_feed_images();
        map.insert((author, id), bytes);
        // Drop images orphaned by posts that already fell out of the (capped) feed.
        let feed = self.load_feed()?;
        let live: std::collections::HashSet<([u8; 32], [u8; 16])> =
            feed.iter().map(|f| (f.author, f.id)).collect();
        // A just-arrived image can precede its post packet, so keep the current key even if the
        // post isn't stored yet; every OTHER key must correspond to a live post.
        map.retain(|k, _| *k == (author, id) || live.contains(k));
        // Hard count cap: if still over, evict the images whose posts are oldest by ts.
        if map.len() > MAX_FEED_IMAGES {
            let ts_of: BTreeMap<([u8; 32], [u8; 16]), u64> =
                feed.iter().map(|f| ((f.author, f.id), f.ts)).collect();
            let mut keys: Vec<([u8; 32], [u8; 16])> = map.keys().copied().collect();
            keys.sort_by_key(|k| ts_of.get(k).copied().unwrap_or(u64::MAX)); // no post ⇒ newest, keep
            for k in keys.into_iter().take(map.len() - MAX_FEED_IMAGES) {
                map.remove(&k);
            }
        }
        self.write_feed_images(&map)
    }

    /// Remove a post's image (called when the post is deleted/retracted). Idempotent.
    fn remove_feed_image(&self, author: [u8; 32], id: [u8; 16]) -> io::Result<()> {
        let mut map = self.load_feed_images();
        if map.remove(&(author, id)).is_none() {
            return Ok(());
        }
        self.write_feed_images(&map)
    }

    fn feed_attachments_path(&self) -> PathBuf {
        self.dir.join("feed_attachments.dat")
    }

    /// (author, post_id) → its attachments. Public so the desktop decrypts the sidecar ONCE per feed
    /// load (counts for the list, all bytes for the lazy batch) rather than per post.
    pub fn load_feed_attachments(&self) -> BTreeMap<([u8; 32], [u8; 16]), Vec<StoredAttachment>> {
        std::fs::read(self.feed_attachments_path())
            .ok()
            .and_then(|b| self.key.open(&self.label(&self.feed_attachments_path()), &b).ok())
            .and_then(|b| postcard::from_bytes(&b).ok())
            .unwrap_or_default()
    }

    fn write_feed_attachments(&self, map: &BTreeMap<([u8; 32], [u8; 16]), Vec<StoredAttachment>>) -> io::Result<()> {
        let plain = postcard::to_stdvec(map).map_err(io_err)?;
        self.write_sealed(&self.feed_attachments_path(), &plain)
    }

    /// A post's attachments, ordered by index.
    pub fn feed_attachments(&self, author: [u8; 32], id: [u8; 16]) -> Vec<StoredAttachment> {
        let mut v = self.load_feed_attachments().remove(&(author, id)).unwrap_or_default();
        v.sort_by_key(|a| a.index);
        v
    }

    /// Attach ONE (already-encoded, bounded) image/file to a post at `index`. Replaces any existing
    /// attachment at that index (idempotent re-delivery). Prunes attachments orphaned by posts that
    /// left the feed, then bounds the sidecar to `MAX_FEED_ATTACH_BYTES` by dropping the OLDEST
    /// posts' attachments (by feed ts) — a flood evicts only older ones, never unbounded storage.
    pub fn set_feed_attachment(&self, author: [u8; 32], id: [u8; 16], att: StoredAttachment) -> io::Result<()> {
        if att.bytes.is_empty() || att.bytes.len() > crate::content::MAX_POST_IMAGE_BYTES {
            return Ok(()); // absurd size: ignore (the manifest check already gates the wire path)
        }
        let mut map = self.load_feed_attachments();
        let list = map.entry((author, id)).or_default();
        list.retain(|a| a.index != att.index); // replace same-index (re-delivery)
        list.push(att);
        // Drop attachments orphaned by posts that already fell out of the (capped) feed; keep the
        // current post even if its text packet hasn't arrived yet.
        let feed = self.load_feed()?;
        let live: std::collections::HashSet<([u8; 32], [u8; 16])> =
            feed.iter().map(|f| (f.author, f.id)).collect();
        map.retain(|k, _| *k == (author, id) || live.contains(k));
        // Byte-budget cap: evict whole posts' attachments, oldest post (by ts) first.
        let total: usize = map.values().flatten().map(|a| a.bytes.len()).sum();
        if total > MAX_FEED_ATTACH_BYTES {
            let ts_of: BTreeMap<([u8; 32], [u8; 16]), u64> =
                feed.iter().map(|f| ((f.author, f.id), f.ts)).collect();
            let mut keys: Vec<([u8; 32], [u8; 16])> = map.keys().copied().collect();
            keys.sort_by_key(|k| ts_of.get(k).copied().unwrap_or(u64::MAX)); // no post ⇒ newest, keep
            let mut have = total;
            for k in keys {
                if have <= MAX_FEED_ATTACH_BYTES {
                    break;
                }
                if k == (author, id) {
                    continue; // never evict the post we're writing
                }
                if let Some(v) = map.remove(&k) {
                    have -= v.iter().map(|a| a.bytes.len()).sum::<usize>();
                }
            }
        }
        self.write_feed_attachments(&map)
    }

    /// Record a TERMINAL failure marker for a post attachment whose blob fetch gave up (blob swept /
    /// hash mismatch / past TTL). A zero-byte `failed` entry at `index` so the feed shows an error
    /// tile rather than the attachment silently vanishing. Idempotent; replaced by a later success at
    /// the same index. Does NOT prune/evict (a marker is tiny) — just records the state.
    pub fn mark_post_attachment_failed(
        &self,
        author: [u8; 32],
        id: [u8; 16],
        index: u32,
        kind: u8,
        name: &str,
    ) -> io::Result<()> {
        let mut map = self.load_feed_attachments();
        let list = map.entry((author, id)).or_default();
        if list.iter().any(|a| a.index == index && !a.failed && !a.bytes.is_empty()) {
            return Ok(()); // a real attachment already landed at this index — don't overwrite it
        }
        list.retain(|a| a.index != index);
        list.push(StoredAttachment { index, kind, name: name.to_string(), bytes: Vec::new(), failed: true });
        self.write_feed_attachments(&map)
    }

    /// Remove a post's attachments (on delete/retract). Idempotent.
    fn remove_feed_attachments(&self, author: [u8; 32], id: [u8; 16]) -> io::Result<()> {
        let mut map = self.load_feed_attachments();
        if map.remove(&(author, id)).is_none() {
            return Ok(());
        }
        self.write_feed_attachments(&map)
    }

    // ----- Channels: local mode flag + subscribers + pending join requests -----
    //
    // All sealed, atomic-rewrite like the feed. The mode flag lives in its OWN file and is
    // written ONLY here + from the password-gated command — never from a receive path.

    fn channel_path(&self) -> PathBuf {
        self.dir.join("channel.dat")
    }

    /// Read the channel-mode flag (default: off = private account). A missing/corrupt file reads
    /// as off, never an error — a private account is the safe default.
    pub fn load_channel(&self) -> ChannelConfig {
        std::fs::read(self.channel_path())
            .ok()
            .and_then(|b| self.key.open(&self.label(&self.channel_path()), &b).ok())
            .and_then(|b| postcard::from_bytes(&b).ok())
            .unwrap_or_default()
    }

    /// Write the channel-mode flag. SECURITY: CALL ONLY from the password-gated `set_channel_mode`
    /// command — no received-message path may ever reach this. The invariant is auditable: this is
    /// the ONLY writer of `channel.dat`, and `grep 'save_channel('` must show exactly that one
    /// gated caller (the receive handlers touch subscribers/pending, never this).
    pub fn save_channel(&self, cfg: &ChannelConfig) -> io::Result<()> {
        let plain = postcard::to_stdvec(cfg).map_err(io_err)?;
        self.write_sealed(&self.channel_path(), &plain)
    }

    fn subscribers_path(&self) -> PathBuf {
        self.dir.join("subscribers.dat")
    }

    /// Everyone subscribed to our posts (own audience for public posts).
    pub fn load_subscribers(&self) -> Vec<Subscriber> {
        std::fs::read(self.subscribers_path())
            .ok()
            .and_then(|b| self.key.open(&self.label(&self.subscribers_path()), &b).ok())
            .and_then(|b| postcard::from_bytes(&b).ok())
            .unwrap_or_default()
    }

    /// Accept a subscriber (auto in channel mode, or on manual approval). Idempotent; bounded by
    /// `MAX_SUBSCRIBERS` (on overflow a NEW ik is refused). Returns whether it was newly added.
    pub fn add_subscriber(&self, ik: [u8; 32], now: u64) -> io::Result<bool> {
        let mut subs = self.load_subscribers();
        if subs.iter().any(|s| s.ik == ik) {
            return Ok(false);
        }
        if subs.len() >= MAX_SUBSCRIBERS {
            return Ok(false);
        }
        subs.push(Subscriber { ik, since: now });
        let plain = postcard::to_stdvec(&subs).map_err(io_err)?;
        self.write_sealed(&self.subscribers_path(), &plain)?;
        Ok(true)
    }

    /// Remove a subscriber (they stop receiving future posts). Idempotent.
    pub fn remove_subscriber(&self, ik: [u8; 32]) -> io::Result<()> {
        let mut subs = self.load_subscribers();
        subs.retain(|s| s.ik != ik);
        let plain = postcard::to_stdvec(&subs).map_err(io_err)?;
        self.write_sealed(&self.subscribers_path(), &plain)
    }

    fn contact_requests_path(&self) -> PathBuf {
        self.dir.join("contact_requests.dat")
    }

    /// Incoming CONTACT requests awaiting my accept/decline (mutual-consent add). IK list; the
    /// requester's name/bio live in `peer_profiles` (set when the request arrived).
    pub fn load_contact_requests(&self) -> Vec<[u8; 32]> {
        std::fs::read(self.contact_requests_path())
            .ok()
            .and_then(|b| self.key.open(&self.label(&self.contact_requests_path()), &b).ok())
            .and_then(|b| postcard::from_bytes(&b).ok())
            .unwrap_or_default()
    }

    /// Record an incoming contact request. Idempotent; bounded like pending subs so a flood can't
    /// grow the file without bound. Returns whether it was newly added (for a "new request" cue).
    pub fn add_contact_request(&self, ik: [u8; 32]) -> io::Result<bool> {
        let mut p = self.load_contact_requests();
        if p.contains(&ik) || p.len() >= MAX_PENDING_SUBS {
            return Ok(false);
        }
        p.push(ik);
        let plain = postcard::to_stdvec(&p).map_err(io_err)?;
        self.write_sealed(&self.contact_requests_path(), &plain)?;
        Ok(true)
    }

    /// Drop a contact request (after accept or decline). Idempotent.
    pub fn remove_contact_request(&self, ik: [u8; 32]) -> io::Result<()> {
        let mut p = self.load_contact_requests();
        p.retain(|x| *x != ik);
        let plain = postcard::to_stdvec(&p).map_err(io_err)?;
        self.write_sealed(&self.contact_requests_path(), &plain)
    }

    fn pending_subs_path(&self) -> PathBuf {
        self.dir.join("pending_subs.dat")
    }

    /// Join requests awaiting MANUAL approval (private account). IK list.
    pub fn load_pending_subs(&self) -> Vec<[u8; 32]> {
        std::fs::read(self.pending_subs_path())
            .ok()
            .and_then(|b| self.key.open(&self.label(&self.pending_subs_path()), &b).ok())
            .and_then(|b| postcard::from_bytes(&b).ok())
            .unwrap_or_default()
    }

    /// Queue a join request for manual approval. Idempotent; bounded by `MAX_PENDING_SUBS`.
    pub fn add_pending_sub(&self, ik: [u8; 32]) -> io::Result<bool> {
        let mut p = self.load_pending_subs();
        if p.contains(&ik) || p.len() >= MAX_PENDING_SUBS {
            return Ok(false);
        }
        p.push(ik);
        let plain = postcard::to_stdvec(&p).map_err(io_err)?;
        self.write_sealed(&self.pending_subs_path(), &plain)?;
        Ok(true)
    }

    /// Drop a pending request (after approve or reject).
    pub fn remove_pending_sub(&self, ik: [u8; 32]) -> io::Result<()> {
        let mut p = self.load_pending_subs();
        p.retain(|x| *x != ik);
        let plain = postcard::to_stdvec(&p).map_err(io_err)?;
        self.write_sealed(&self.pending_subs_path(), &plain)
    }

    fn channel_peers_path(&self) -> PathBuf {
        self.dir.join("channel_peers.dat")
    }

    /// IKs we KNOW are channels (learned from a `JoinAccept{is_channel:true}`) — for the contact
    /// list's channel badge. A hint, like a cached peer profile; never a trust anchor.
    pub fn load_channel_peers(&self) -> Vec<[u8; 32]> {
        std::fs::read(self.channel_peers_path())
            .ok()
            .and_then(|b| self.key.open(&self.label(&self.channel_peers_path()), &b).ok())
            .and_then(|b| postcard::from_bytes(&b).ok())
            .unwrap_or_default()
    }

    /// Record (or clear) that a peer is a channel.
    pub fn set_channel_peer(&self, ik: [u8; 32], is_channel: bool) -> io::Result<()> {
        let mut v = self.load_channel_peers();
        let had = v.contains(&ik);
        if is_channel && !had {
            v.push(ik);
        } else if !is_channel && had {
            v.retain(|x| *x != ik);
        } else {
            return Ok(());
        }
        let plain = postcard::to_stdvec(&v).map_err(io_err)?;
        self.write_sealed(&self.channel_peers_path(), &plain)
    }

    // ----- Connection proxies: disposable per-proxy-secret channels (proxy-identity model) -----
    //
    // #207 (A6-4): the registry (`proxies.dat`) used to list indices/labels/active and re-derive
    // every proxy's KEYS from the seed (`seed::derive_proxy(entropy, index)`). That made "burning"
    // a proxy (flipping `active`) an operational label, not destruction: the phrase alone could
    // still regenerate ANY past proxy's private keys forever, match them against historical relay
    // logs, enumerate future proxies, and link identities the UI presented as independently
    // destroyed. Now each `ProxyEntry` carries its OWN random 32-byte `secret`, minted (`OsRng`)
    // only at creation and stored ONLY in this sealed registry — never derivable from the seed.
    // Burning REMOVES the entry (and the secret with it): once gone, NOTHING — not even the
    // recovery phrase — can reproduce that identity's keys again. The honest cost: the phrase
    // recovers the ROOT account, not its proxies — a restored account starts with zero proxies,
    // by design (see `docs/design/proxy-identity.md`).
    //
    // The contact→proxy tag is a SEPARATE sidecar (`contact_proxy.dat`) so it never touches the
    // postcard layout of `contacts.dat`.

    fn proxies_path(&self) -> PathBuf {
        self.dir.join("proxies.dat")
    }

    fn load_registry(&self) -> io::Result<ProxyRegistry> {
        match std::fs::read(self.proxies_path()) {
            Ok(b) => {
                let plain = self
                    .key
                    .open(&self.label(&self.proxies_path()), &b)
                    .map_err(|e| io_err(format!("proxy list fails authentication: {e}")))?;
                let mut reg: ProxyRegistry = postcard::from_bytes(&plain)
                    .map_err(|e| io_err(format!("proxy list malformed: {e}")))?;
                reg.entries.sort_by_key(|p| p.index);
                Ok(reg)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(ProxyRegistry::default()),
            Err(e) => Err(e),
        }
    }

    fn save_registry(&self, reg: &ProxyRegistry) -> io::Result<()> {
        let plain = postcard::to_stdvec(reg).map_err(io_err)?;
        self.write_sealed(&self.proxies_path(), &plain)
    }

    /// Every LIVE proxy in the registry (burned ones are gone, not merely flagged), oldest
    /// index first.
    pub fn load_proxies(&self) -> Vec<ProxyEntry> {
        self.try_load_proxies().unwrap_or_else(|e| {
            // Not a silent default: an unreadable proxy list does not merely lose settings, it
            // changes WHICH NETWORK IDENTITY we present — the account would quietly fall back to
            // acting as a different (or the root) identity (CRYPTO-29). We cannot return an error
            // from this signature without touching every caller, so at minimum it is loud.
            eprintln!("warning: proxy list unreadable ({e}) — refusing to invent an empty one");
            Vec::new()
        })
    }

    /// Fallible form of [`Store::load_proxies`]: distinguishes "none configured" (absent file)
    /// from "cannot be authenticated" (present but undecryptable/malformed). Used (rather than the
    /// infallible form) by anything that DERIVES an identity from the registry — an unreadable
    /// registry must never present as "no such proxy, must be burned" (that would be the same
    /// CRYPTO-29 misclassification the infallible form's eprintln guards against, just one layer
    /// deeper: "corrupt" and "burned" are different failures and must stay distinguishable).
    pub fn try_load_proxies(&self) -> io::Result<Vec<ProxyEntry>> {
        Ok(self.load_registry()?.entries)
    }

    /// Mint a new proxy: a monotonic index (never reused, even across burns — see
    /// `ProxyRegistry::next_index`) and a fresh random 32-byte secret (`OsRng`) that is the ONLY
    /// thing this proxy's keys ever derive from. Bounded by `MAX_PROXIES`. Returns the new entry.
    pub fn create_proxy(&self, label: &str, now: u64) -> io::Result<ProxyEntry> {
        let mut reg = self.load_registry()?;
        if reg.entries.len() >= MAX_PROXIES {
            return Err(io_err("too many proxies"));
        }
        let index = reg.next_index;
        reg.next_index =
            reg.next_index.checked_add(1).ok_or_else(|| io_err("proxy index space exhausted"))?;
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let entry = ProxyEntry {
            index,
            label: clamp_str(label, crate::content::MAX_PROFILE_NAME),
            created_at: now,
            secret,
        };
        reg.entries.push(entry.clone());
        self.save_registry(&reg)?;
        Ok(entry)
    }

    /// Burn a proxy: DELETE its registry entry — and with it, its secret — outright (#207, A6-4).
    /// This is NOT a flag flip and NOT reversible: once the secret is gone, NOTHING can regenerate
    /// this identity's keys again, including the recovery phrase, because the phrase was never
    /// part of the derivation. That irreversibility is the fix, not a side effect — see the module
    /// note above and `docs/design/proxy-identity.md`. Also removes this proxy's own namespaced
    /// network files (`net_file`: sessions/OPKs/discovery-key/quarantine/send-ledger/stranded-
    /// sends/…, best-effort — a proxy that never published anything simply has none) and any
    /// contact→proxy tags still pointing at it, so no trace of a burned identity's channel state —
    /// including any outgoing plaintext parked by R2-6's stranded-send log — lingers on disk.
    /// Idempotent: burning an already-absent index is not an error.
    ///
    /// Refuses (CRYPTO-27) while this proxy's outbox still has anything undelivered queued in it —
    /// see the check just below — because that queue can hold the only authenticated proof of an
    /// in-progress migration, and this is the one place that actually deletes it. That is a DATA-
    /// INTEGRITY refusal and lives here, not in the caller. By contrast, "you must always keep one
    /// reachable channel" is a UX/session POLICY, not a data-integrity invariant, and deliberately
    /// does NOT live here — it belongs in the caller (see the desktop `burn_proxy` command, which
    /// enforces exactly that before calling this).
    pub fn burn_proxy(&self, index: u32) -> io::Result<()> {
        // CRYPTO-27: this proxy's outbox (in `sessions.dat`, removed a few lines down) can hold the
        // ONLY authenticated copy of a message it ever sent — most dangerously a `ChannelMigrate`,
        // the sole proof-of-continuity handed to a contact who is being moved OFF this exact
        // channel (`send_channel_migrate` durably queues it and reports `Ok(false)` rather than
        // losing it when the relay is down; see its doc comment). If burn is allowed to run anyway,
        // that queued ciphertext is deleted before it ever reaches the contact, who then never
        // learns `new_ik` and sees the next message from it as an unknown sender — a silent,
        // unrecoverable split. Refusing here, in the one method that actually destroys
        // `sessions.dat`, closes the path regardless of which caller forgot to check first.
        //
        // A read error (corrupt/unauthenticated `sessions.dat`) is refused too, NOT treated as "no
        // outbox": `unwrap_or(0)` here would be the exact "any failure → assume empty" shape 1dd5de7
        // fixed for the proxy registry — reintroducing it for the outbox would just move the bug.
        // An absent file (this proxy never sent anything) is genuinely empty and proceeds.
        let victim = self.as_proxy(index);
        let pending = victim.load_sessions()?.outbox_len();
        if pending > 0 {
            return Err(io_err(format!(
                "proxy #{index} still has {pending} undelivered message(s) queued — burning now \
                 would destroy them, including any in-flight channel migration; retry sending (or \
                 wait for the relay to come back) before burning this channel"
            )));
        }

        let mut reg = self.load_registry()?;
        let before = reg.entries.len();
        reg.entries.retain(|p| p.index != index);
        if reg.entries.len() != before {
            self.save_registry(&reg)?;
        }

        // Drop the namespaced network files this proxy owned. Best-effort: NotFound just means
        // this proxy never got that far (e.g. burned before its first publish).
        for path in [
            victim.net_file("discovery.key"),
            victim.net_file("reduced_fs.dat"),
            // No `opks.dat`: the one-time prekey secrets live INSIDE `sessions.dat` now
            // (CRYPTO-26), so removing that file takes them with it.
            victim.net_file("partials.dat"),
            victim.net_file("sessions.dat"),
            victim.net_file("sessions.lock"),
            victim.net_file("sessions.anchor"),
            victim.net_file("quarantine.dat"),
            victim.net_file("send_ledger.dat"),
            victim.net_file("stranded_sends.dat"),
        ] {
            if let Err(e) = std::fs::remove_file(&path) {
                if e.kind() != io::ErrorKind::NotFound {
                    // The PATH is not printed (PRIV-9, client half). It named the vault's location
                    // and which proxy this was, in a warning nobody asked for — and this vault may
                    // be a hidden account, whose whole property is that its existence is not
                    // evidenced anywhere. A stale file left behind is worth saying; where it lives
                    // is not.
                    eprintln!("warning: a burned proxy's file could not be removed: {e}");
                }
            }
        }

        // This proxy's own admission credentials (A8-4). They live keyed-by-slot in the ONE
        // `capabilities.dat`, not in a `net_file`, so the loop above cannot reach them and only
        // an explicit removal will — the same cascade shape as `forget_peer` (A5-9). A burned
        // channel's admission secret is exactly the kind of state a burn is supposed to destroy:
        // left behind, it is a live credential naming a dead identity.
        if let Err(e) = self.forget_proxy_capabilities(index) {
            eprintln!("warning: could not clear burned proxy #{index}'s credentials: {e}");
        }

        // A contact tagged to this now-dead index would otherwise sit pointing at nothing
        // forever (indices are never reused, so it can never silently reattach to a different,
        // newer identity either — but a stale tag is dead weight worth clearing).
        let mut map = self.load_contact_proxy();
        let before = map.len();
        map.retain(|_, v| *v != index);
        if map.len() != before {
            let plain = postcard::to_stdvec(&map).map_err(io_err)?;
            self.write_sealed(&self.contact_proxy_path(), &plain)?;
        }
        Ok(())
    }

    /// Remove state belonging to proxy indices the registry no longer knows (#144).
    ///
    /// `burn_proxy` destroys the registry entry — the proxy's only secret — FIRST, and only then
    /// removes its namespaced files, credentials and contact tags. That order is deliberate and
    /// stays: burning is the action taken under duress, and the property that matters is that the
    /// identity becomes unrecoverable as early as possible, not that the cleanup is tidy. A crash
    /// mid-burn therefore leaves the identity correctly gone and the residue behind — a
    /// `sessions.p7.dat` and an admission credential naming a channel that no longer exists.
    ///
    /// Reordering to fix that would trade the duress property for a housekeeping one, which is
    /// the wrong trade. Sweeping at unlock keeps both: the burn is still secret-first and
    /// irreversible, and the residue is collected the next time the vault opens.
    ///
    /// Returns how many stray items were removed. Errors on individual removals are reported and
    /// skipped rather than aborting: a sweep that gives up halfway is worse than one that gets
    /// most of the way.
    pub fn sweep_orphaned_proxy_state(&self) -> io::Result<usize> {
        let live: std::collections::HashSet<u32> =
            self.try_load_proxies()?.into_iter().map(|p| p.index).collect();
        let mut removed = 0usize;

        // Namespaced network files: `<stem>.p<index>.<ext>` (see `net_file`).
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                let Some(idx) = name
                    .split('.')
                    .find_map(|part| part.strip_prefix('p').and_then(|n| n.parse::<u32>().ok()))
                else {
                    continue;
                };
                if live.contains(&idx) {
                    continue;
                }
                match std::fs::remove_file(entry.path()) {
                    Ok(()) => removed += 1,
                    Err(e) => eprintln!("warning: could not sweep orphaned {name}: {e}"),
                }
            }
        }

        // Admission credentials keyed per slot — they live inside ONE file, so the sweep is a
        // read-modify-write rather than an unlink (A8-4).
        let mut caps = self.load_capabilities()?;
        let before = caps.per_slot.len();
        caps.per_slot.retain(|k, _| match k.rsplit_once(":p") {
            Some((_, idx)) => idx.parse::<u32>().map(|i| live.contains(&i)).unwrap_or(true),
            None => true, // the root slot, or a key shape we do not own
        });
        if caps.per_slot.len() != before {
            removed += before - caps.per_slot.len();
            self.store_capabilities(&caps)?;
        }

        // Contact tags pointing at a dead channel: harmless but they would keep a contact routed
        // to nothing (indices are never reused, so it can never reattach to a newer identity).
        let mut map = self.load_contact_proxy();
        let before = map.len();
        map.retain(|_, v| live.contains(v));
        if map.len() != before {
            removed += before - map.len();
            let plain = postcard::to_stdvec(&map).map_err(io_err)?;
            self.write_sealed(&self.contact_proxy_path(), &plain)?;
        }
        Ok(removed)
    }

    /// The derived identity (seal ‖ account) for proxy `index` — derived from THAT PROXY'S OWN
    /// random secret in the registry, never from the seed/phrase (#207, A6-4). `Err` if `index`
    /// names no live entry (burned, or never created) OR if the registry itself cannot be
    /// authenticated — deliberately using [`Store::try_load_proxies`] rather than the infallible
    /// [`Store::load_proxies`], so a corrupt registry reports as "registry unreadable", not as
    /// "no such proxy" (which would misrepresent a tampered/corrupt disk as an ordinary burn).
    /// There is NO fallback path to phrase-derivation here: that fallback is exactly the bug #207
    /// fixes, so its absence is load-bearing, not an oversight.
    pub fn proxy_identity(&self, index: u32) -> io::Result<crate::seed::DerivedIdentity> {
        let entry = self
            .try_load_proxies()?
            .into_iter()
            .find(|p| p.index == index)
            .ok_or_else(|| {
                io_err(format!(
                    "proxy #{index} has no live registry entry (burned or never created) — \
                     refusing to fall back to deriving it from the phrase"
                ))
            })?;
        Ok(crate::seed::derive_proxy_from_secret(&entry.secret))
    }

    fn contact_proxy_path(&self) -> PathBuf {
        self.dir.join("contact_proxy.dat")
    }

    /// Map of contact IK → the proxy index that reaches them (a SIDECAR, so `contacts.dat` is
    /// untouched). Absent = not yet assigned.
    fn load_contact_proxy(&self) -> BTreeMap<[u8; 32], u32> {
        match std::fs::read(self.contact_proxy_path()) {
            Ok(b) => self
                .key
                .open(&self.label(&self.contact_proxy_path()), &b)
                .map_err(|e| format!("fails authentication: {e}"))
                .and_then(|plain| {
                    postcard::from_bytes(&plain).map_err(|e| format!("malformed: {e}"))
                })
                .unwrap_or_else(|e| {
                    // Same rule as the proxy list: silently treating this as empty re-points every
                    // contact at the default proxy, i.e. changes the identity they are reached
                    // through, without telling anyone (CRYPTO-29).
                    eprintln!("warning: contact→proxy map unreadable ({e}) — not assuming empty");
                    BTreeMap::new()
                }),
            Err(_) => BTreeMap::new(),
        }
    }

    /// Which proxy reaches a contact, if tagged.
    pub fn contact_proxy(&self, ik: &[u8; 32]) -> Option<u32> {
        self.load_contact_proxy().get(ik).copied()
    }

    /// Re-point a contact from `old` IK to `new` (a CHANNEL MIGRATION they sent us over the
    /// authenticated session). Updates the contact record's IK, clears `verified` (the safety
    /// number changed with the key — the UI prompts a re-verify), and carries the local
    /// contact→proxy tag across to the new key. Returns whether a contact was actually migrated.
    ///
    /// **SEC-36 — refuses a migration onto an identity key another contact already holds.** The
    /// desktop caller only checks `new != sender`, i.e. "not a no-op onto yourself" — nothing
    /// upstream stops an already-authenticated contact from naming a *different* contact's IK as
    /// their "new" one. Without this check `c.ik = new` happily produced two `ContactRecord` rows
    /// sharing one `ik`; the sidecar carry-over just below is a plain `map.insert(new, …)` into
    /// `BTreeMap`s keyed by `ik`, so it would then silently overwrite the VICTIM's
    /// `contact_proxy` routing tag and `peer_profiles` cache with the attacker's — the migrating
    /// contact's row would win, the victim's would be clobbered with no signal anything happened.
    /// The check runs first, against the freshly-loaded (unmutated) `cs`, before `contacts.dat`,
    /// `contact_proxy.dat` or `peer_profiles.dat` are touched — a migration must be all-or-nothing;
    /// a torn one (say, the contact record moved but the profile carry-over refused, or vice
    /// versa) would leave the store inconsistent in a way nothing here could later detect.
    pub fn migrate_contact_ik(&self, old: [u8; 32], new: [u8; 32]) -> io::Result<bool> {
        let mut cs = self.load_contacts()?;
        if !cs.iter().any(|c| c.ik == old) {
            return Ok(false);
        }
        if new != old && cs.iter().any(|c| c.ik == new) {
            return Err(io_err(format!(
                "channel migration refused: identity key {} already belongs to a different contact",
                hex::encode(new)
            )));
        }
        let c = cs.iter_mut().find(|c| c.ik == old).expect("just checked above");
        c.ik = new;
        c.verified = false; // new key ⇒ old safety number no longer applies
        self.save_contacts(&cs)?;
        // Carry the local "which of MY proxies reaches them" tag onto the new IK.
        if let Some(idx) = self.contact_proxy(&old) {
            let mut map = self.load_contact_proxy();
            map.remove(&old);
            map.insert(new, idx);
            let plain = postcard::to_stdvec(&map).map_err(io_err)?;
            self.write_sealed(&self.contact_proxy_path(), &plain)?;
        }
        // Carry the peer's cached profile (display name / bio / avatar) onto the new IK.
        // These live in peer_profiles.dat keyed by IK; without this, a migration would
        // visually drop the contact's avatar/name until they next re-send it, even though
        // it's the SAME person on a fresh channel. (Cosmetic identity, not the trust anchor —
        // the safety number still resets so the UI prompts a re-verify.)
        let mut profiles = self.load_peer_profiles()?;
        if let Some(p) = profiles.remove(&old) {
            profiles.insert(new, p);
            let plain = postcard::to_stdvec(&profiles).map_err(io_err)?;
            self.write_sealed(&self.peer_profiles_path(), &plain)?;
        }
        // Carry their known relay across too: a migration changes which KEY reaches them, not
        // which relay they sit on, and dropping the route here would quietly send the next message
        // to the primary relay instead of theirs.
        let mut routes = self.load_contact_endpoints();
        if let Some(ep) = routes.remove(&old) {
            routes.insert(new, ep);
            let plain = postcard::to_stdvec(&routes).map_err(io_err)?;
            self.write_sealed(&self.contact_relays_path(), &plain)?;
        }
        Ok(true)
    }

    /// Tag which proxy reaches a contact (the channel they know you through). Called on EVERY
    /// inbound message (before the `Content` is even decoded — a proxy tag is about which channel
    /// carried the bytes, not what they mean), so SEC-44 applies here even harder than to
    /// `contacts.dat`: a flood of fresh sender IKs costs one full read+rewrite of this map PER
    /// distinct new IK, with no cardinality bound.
    ///
    /// Bounded by `MAX_CONTACTS`: past the cap a brand-new sender simply isn't tagged to a proxy —
    /// replies to them fall back to the default proxy (a routing nicety), never lost message
    /// content, since the message itself was already accepted independent of this tag.
    pub fn set_contact_proxy(&self, ik: [u8; 32], index: u32) -> io::Result<()> {
        let mut map = self.load_contact_proxy();
        if map.get(&ik) == Some(&index) {
            return Ok(());
        }
        if !map.contains_key(&ik) && map.len() >= MAX_CONTACTS {
            eprintln!("warning: contact→proxy map at cap ({MAX_CONTACTS}) — not tagging a new sender IK");
            return Ok(());
        }
        // CRYPTO-28: the safety number desktop displays is computed over
        // `own_proxy_ik_for_this_contact || peer_ik` — this tag IS the "own" half. Any real change
        // to it (we are past the no-op check above) means the pair a previous OOB verification
        // covered no longer matches what the UI would compute now, exactly like `migrate_contact_ik`
        // already does for a change on the PEER'S side. That includes the untagged→Some case, the
        // common one: a contact can be added and verified before their first inbound message ever
        // reaches `set_contact_proxy` (every inbound tags the sender's proxy before decoding
        // `Content`), so "only reset when replacing a DIFFERENT known index" would miss it — this
        // function cannot assume a not-yet-tagged contact is never already `verified`. Clearing
        // unconditionally on any tag change is the conservative side to err on: a false
        // "unverified" only re-prompts a check that already happened; a false "verified" is the bug.
        // Written to `contacts.dat` BEFORE `contact_proxy.dat` — a crash between the two writes
        // leaves "unverified, old tag" (harmless) rather than "verified, new tag" if reversed.
        let mut cs = self.load_contacts()?;
        if let Some(c) = cs.iter_mut().find(|c| c.ik == ik) {
            if c.verified {
                c.verified = false;
                self.save_contacts(&cs)?;
            }
        }
        map.insert(ik, index);
        let plain = postcard::to_stdvec(&map).map_err(io_err)?;
        self.write_sealed(&self.contact_proxy_path(), &plain)
    }

    // ----- Where a contact is reachable (their signed relay descriptor), encrypted at-rest -----
    //
    // A contact code resolves to IK **and** a `location` — the relay the contact says they are on
    // — and that half used to be dropped on the floor at the point of adding them (A10-6). The
    // contact model had nowhere to put a route, so discovery could carry one and the application
    // could not use it. This sidecar is that place: it is keyed by IK like `contact_proxy.dat`,
    // and it holds the descriptor exactly as the contact's own IK signed it.

    fn contact_relays_path(&self) -> PathBuf {
        self.dir.join("contact_relays.dat")
    }

    /// Map of contact IK → where their contact code said they are. Same rule as the proxy map: an
    /// unreadable file warns rather than silently reading as "no routes known".
    fn load_contact_endpoints(&self) -> BTreeMap<[u8; 32], ContactEndpoint> {
        match std::fs::read(self.contact_relays_path()) {
            Ok(b) => self
                .key
                .open(&self.label(&self.contact_relays_path()), &b)
                .map_err(|e| format!("fails authentication: {e}"))
                .and_then(|plain| postcard::from_bytes(&plain).map_err(|e| format!("malformed: {e}")))
                .unwrap_or_else(|e| {
                    eprintln!("warning: contact→relay map unreadable ({e}) — not assuming empty");
                    BTreeMap::new()
                }),
            Err(_) => BTreeMap::new(),
        }
    }

    /// Where this contact's code said they are reachable, if we ever resolved one.
    pub fn contact_endpoint(&self, ik: &[u8; 32]) -> Option<ContactEndpoint> {
        self.load_contact_endpoints().get(ik).cloned()
    }

    /// Remember where a contact's code said they are. Overwrite is intended: resolving a newer
    /// code for the same person is how a MOVED contact's route gets corrected. Bounded by
    /// `MAX_CONTACTS` like the proxy map — past the cap the route is simply not remembered
    /// (routing falls back to the primary relay), never a failed add.
    pub fn set_contact_endpoint(&self, ik: [u8; 32], ep: &ContactEndpoint) -> io::Result<()> {
        let mut map = self.load_contact_endpoints();
        if map.get(&ik).map(|e| &e.relay) == Some(&ep.relay) {
            return Ok(()); // same route — do not rewrite the file just to move `discovered_at`
        }
        if !map.contains_key(&ik) && map.len() >= MAX_CONTACTS {
            eprintln!("warning: contact→relay map at cap ({MAX_CONTACTS}) — not recording a new route");
            return Ok(());
        }
        map.insert(ik, ep.clone());
        let plain = postcard::to_stdvec(&map).map_err(io_err)?;
        self.write_sealed(&self.contact_relays_path(), &plain)
    }

    /// Forget where a contact was reachable (removing them from the roster). Idempotent.
    pub fn remove_contact_endpoint(&self, ik: &[u8; 32]) -> io::Result<()> {
        let mut map = self.load_contact_endpoints();
        if map.remove(ik).is_none() {
            return Ok(());
        }
        let plain = postcard::to_stdvec(&map).map_err(io_err)?;
        self.write_sealed(&self.contact_relays_path(), &plain)
    }

    /// Shared atomic blob write (temp 0600 -> fsync -> rename). The sole writer is
    /// the GUI process, so no flock (like contacts/blocked).
    fn write_atomic(&self, path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
        let tmp = path.with_extension("tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        rename_durable(&tmp, path)
    }

    // ----- §2.1 персистентные сессии (ratchet-состояние между процессами) -----

    fn sessions_path(&self) -> PathBuf {
        self.net_file("sessions.dat")
    }

    /// ВЫДЕЛЕННЫЙ lock-файл: он НИКОГДА не переименовывается и не удаляется, чтобы
    /// flock держался за стабильный inode. Если лочить `sessions.dat`, который мы
    /// перезаписываем через temp+rename, замок повис бы на откреплённом inode и
    /// взаимного исключения не было бы (класс «замок на переименованном файле»).
    fn sessions_lock_path(&self) -> PathBuf {
        self.net_file("sessions.lock")
    }

    /// Взять ЭКСКЛЮЗИВНЫЙ замок на всё окно операции (load → мутация → save).
    /// Блокирующий: второй процесс `karst` ждёт, а не мчится параллельно —
    /// иначе оба загрузили бы сессию на позиции N и зашифровали РАЗНЫЕ тексты
    /// одним `mk`+нулевым nonce (keystream-reuse). Замок снимается при `drop`.
    pub fn lock_sessions(&self) -> io::Result<SessionLock> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.sessions_lock_path())?;
        file.lock()?; // blocking exclusive lock; released when the file drops
        Ok(SessionLock { _file: file })
    }

    /// Загрузить персистентное состояние сессий (пусто, если файла нет).
    /// Держите `lock_sessions` вокруг load→save. Расшифровывается at-rest-ключом.
    fn sessions_anchor_path(&self) -> PathBuf {
        self.net_file("sessions.anchor")
    }

    /// The highest session-state generation this account has ever written, kept in a DIFFERENT
    /// file from the state it describes.
    ///
    /// Rolling the ratchet back is the one thing at-rest encryption cannot prevent: an attacker
    /// (or a helpful backup tool) who restores `sessions.dat` from yesterday replays chain keys.
    /// The per-message salt already makes that HARMLESS — two encryptions under a replayed chain
    /// key no longer collide (see `node::ratchet::message_aead`) — but harmless is not the same
    /// as unnoticed, and a user whose ratchet silently went backwards deserves to be told.
    ///
    /// HONEST LIMIT, and the reason this is detection rather than prevention: it catches a
    /// PARTIAL rollback — one file restored while the rest of the directory stayed current, which
    /// is what a backup restore, a file-level sync conflict or a targeted swap actually looks
    /// like. An attacker who restores the WHOLE directory, or simply deletes this file, is not
    /// caught: no purely local state can survive an adversary who controls all local state. A
    /// missing anchor reads as zero (never a false alarm on a fresh account).
    fn load_sessions_anchor(&self) -> u64 {
        let Ok(blob) = std::fs::read(self.sessions_anchor_path()) else { return 0 };
        let Ok(plain) = self.key.open(&self.label(&self.sessions_anchor_path()), &blob) else {
            return 0;
        };
        postcard::from_bytes(&plain).unwrap_or(0)
    }

    /// Read the session file as it sits on disk: `(generation, opaque state bytes, OPK secrets)`,
    /// or `None` if this account has never written one. An existing-but-unreadable file is an
    /// ERROR — every caller here holds secrets whose loss is silent (a ratchet position, a burnt
    /// prekey), so "unreadable" must never collapse into "empty".
    fn read_session_file(&self) -> io::Result<Option<SessionFile>> {
        let blob = match std::fs::read(self.sessions_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let plain = self.key.open(&self.label(&self.sessions_path()), &blob).map_err(|e| {
            io_err(format!("session state unreadable ({e}) — refusing to treat it as absent"))
        })?;
        let (generation, state, opks) = postcard::from_bytes(&plain).map_err(|e| {
            io_err(format!("session state malformed ({e}) — refusing to treat it as absent"))
        })?;
        Ok(Some(SessionFile { generation, state, opks }))
    }

    /// ATOMICALLY write the session file: seal in memory → temp (0600) → fsync → rename over.
    /// A crash mid-write leaves no truncated/torn file (which would wedge the account or lose a
    /// ratchet position); the temp sits in the same directory, so the rename is atomic within the
    /// filesystem. Ratchet keys and prekey secrets are encrypted at rest before the write.
    fn write_session_file(&self, state: &[u8], opks: &[node::pqxdh::OneTimeSecret]) -> io::Result<()> {
        // One past the highest generation EITHER file knows about, so a rolled-back state file
        // cannot lower the mark by being written over.
        let generation = self.load_sessions_anchor().max(self.sessions_generation()) + 1;
        let plain = postcard::to_stdvec(&(generation, state, opks)).map_err(io_err)?;
        let bytes = self.key.seal(&self.label(&self.sessions_path()), &plain);
        let tmp = self.net_file("sessions.dat.tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?; // durable before the rename
        }
        rename_durable(&tmp, &self.sessions_path())?;
        // The anchor goes LAST, deliberately. A crash between the two leaves the state AHEAD of
        // the anchor, which reads as fine — the state is newer, not older. Writing the anchor
        // first would make the same crash look exactly like a rollback and refuse to open a
        // perfectly good account.
        //
        // That claim was prose until now. This is where a crash test cuts the power (QA-2), so the
        // paragraph above is checked rather than believed.
        node::fail_point!("store.sessions.after_rename_before_anchor");
        self.write_sealed(&self.sessions_anchor_path(), &postcard::to_stdvec(&generation).map_err(io_err)?)
    }

    pub fn load_sessions(&self) -> io::Result<PeerState> {
        let Some(f) = self.read_session_file()? else {
            return Ok(PeerState::empty());
        };
        let (generation, state) = (f.generation, f.state);
        let anchor = self.load_sessions_anchor();
        if generation < anchor {
            return Err(io_err(format!(
                "session state rolled back: on disk is generation {generation}, but this                  account has already written {anchor}. Something restored sessions.dat                  from an older copy. Message keys are not reused (each message derives                  its own), but replies may be undecryptable until the session is                  re-established — reconnect the affected chats."
            )));
        }
        PeerState::from_bytes(&state).map_err(io_err)
    }

    /// Persist the ratchet state alone, keeping the one-time prekeys that share its file.
    /// For the SEND side, which never touches prekeys; the receive side commits both together
    /// (`save_receive_commit`).
    ///
    /// Read-modify-write of a shared file: hold `lock_sessions` across load → mutate → save, as
    /// every caller already does to keep two processes off the same ratchet position.
    pub fn save_sessions(&self, state: &PeerState) -> io::Result<()> {
        let opks = self.read_session_file()?.map(|f| f.opks).unwrap_or_default();
        self.write_session_file(&postcard::to_stdvec(state).map_err(io_err)?, &opks)
    }

    /// Commit BOTH halves of a receive — the remaining one-time prekeys and the ratchet state
    /// derived from the one that was just consumed — in a single durable write.
    ///
    /// CRYPTO-26. These used to be two files and two atomic renames (`save_opks` then
    /// `save_sessions`). Each rename was atomic on its own, but the PAIR was not: a crash or an
    /// I/O error in between left "OPK burnt, no session on disk", which is unrecoverable rather
    /// than merely stale. The ACK had not been sent, so the relay redelivered the opener — and
    /// `accept_key_agreement` could no longer find the prekey secret to re-derive the root key,
    /// while the sender, holding a perfectly good session, kept ratcheting into a mailbox the
    /// recipient could never open again. Swapping the order does not fix it either: session
    /// first, prekey still on disk, is a reuse window for a secret that is one-time by contract.
    ///
    /// One file, one rename, so the reachable crash states are only "both old" (the opener
    /// redelivers and re-opens) or "both new" (done) — never "neither".
    pub fn save_receive_commit(&self, state: &PeerState, opks: &[node::pqxdh::OneTimeSecret]) -> io::Result<()> {
        self.write_session_file(&postcard::to_stdvec(state).map_err(io_err)?, opks)
    }

    /// The generation recorded INSIDE the current session file (0 if absent/unreadable — a
    /// corrupt state file is reported by `load_sessions`, not silently by this helper).
    fn sessions_generation(&self) -> u64 {
        self.read_session_file().ok().flatten().map(|f| f.generation).unwrap_or(0)
    }

    // ----- Зашифрованный append-лог истории чатов -----
    //
    // Формат файла — последовательность записей `len(u32-LE) ‖ sealed`, где
    // `sealed` = независимо запечатанная (`secretbox::seal`, СВЕЖИЙ 192-бит nonce
    // на запись) запись. Независимое запечатывание безопасно без счётчика (при
    // 192-бит nonce коллизия ~2^-96) — это НЕ ratchet, keystream-reuse тут неоткуда
    // взяться. Append — O(1) (в отличие от переписывания всего файла O(n) на
    // сообщение → O(n²)). Конкурентность — ВЫДЕЛЕННЫЙ `history.lock` (никогда не
    // переименовывается, стабильный inode — как `sessions.lock`).

    fn outstanding_requests_path(&self) -> PathBuf {
        self.dir.join("outstanding_requests.dat")
    }

    /// The peers we have actually SENT a contact- or join-request to, and are therefore willing
    /// to accept an answer from.
    ///
    /// Nothing recorded what we had asked for, so an "accept" was applied unconditionally: a
    /// stranger could inject a `ContactAccept` and be written straight into the confirmed
    /// contacts, profile and all, having been invited by nobody (SEC-29). Consent has two halves
    /// and only one of them was on disk.
    ///
    /// Its own file rather than a field on an existing struct, so no state-version bump is needed
    /// and an absent file simply reads as "we have asked for nothing" — the same shape the
    /// INCOMING request list already uses.
    pub fn load_outstanding_requests(&self) -> io::Result<BTreeSet<[u8; 32]>> {
        match std::fs::read(self.outstanding_requests_path()) {
            Ok(blob) => {
                let plain = self
                    .key
                    .open(&self.label(&self.outstanding_requests_path()), &blob)
                    .map_err(io_err)?;
                postcard::from_bytes(&plain).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
            Err(e) => Err(e),
        }
    }

    /// Record that we asked `ik` for something, so their answer can be matched against it.
    /// Bounded by the same budget as the contact list — an outstanding request is a promise to
    /// accept state from that peer later, and unbounded promises are unbounded state.
    pub fn note_outstanding_request(&self, ik: [u8; 32]) -> io::Result<()> {
        let mut set = self.load_outstanding_requests()?;
        if set.contains(&ik) {
            return Ok(());
        }
        if set.len() >= MAX_CONTACTS {
            return Err(io_err("too many outstanding requests"));
        }
        set.insert(ik);
        let plain = postcard::to_stdvec(&set).map_err(io_err)?;
        self.write_sealed(&self.outstanding_requests_path(), &plain)
    }

    /// Consume an outstanding request: `true` if we really had asked this peer, `false` if not.
    ///
    /// CONSUMES on purpose — one request authorises exactly one accept. Otherwise a single
    /// request we once sent would keep validating replayed accepts forever.
    pub fn take_outstanding_request(&self, ik: &[u8; 32]) -> io::Result<bool> {
        let mut set = self.load_outstanding_requests()?;
        if !set.remove(ik) {
            return Ok(false);
        }
        let plain = postcard::to_stdvec(&set).map_err(io_err)?;
        self.write_sealed(&self.outstanding_requests_path(), &plain)?;
        Ok(true)
    }

    fn quarantine_path(&self) -> PathBuf {
        self.net_file("quarantine.dat")
    }

    /// Durably park an authenticated message this build cannot APPLY, before it is acked.
    ///
    /// An ACK tells the relay to delete its only copy. The receive path used to ack everything it
    /// could DECRYPT, but only a few `Content` kinds were durably stored before that point — a
    /// profile update, a publication, a contact request, an inline chunk or a `Content` variant
    /// from a newer build were handed to the caller in memory and then, if the process died or
    /// the disk was full, gone for good (SEC-40). Successfully advancing the ratchet proves the
    /// ciphertext cannot be read twice; it proves nothing about the application event surviving.
    ///
    /// So anything not committed by its own handler lands here first, plaintext-sealed, and only
    /// then is the ack allowed. Losing it now takes losing this file too.
    ///
    /// RESIDUAL, deliberately not overstated: this makes the message RECOVERABLE, not
    /// automatically re-applied — nothing yet drains this log back into the handlers on the next
    /// launch. That replay is its own slice; what this closes is the permanent, silent loss.
    pub fn quarantine_incoming(&self, sender: [u8; 32], plaintext: &[u8], now: u64) -> io::Result<()> {
        if plaintext.len() > MAX_HISTORY_RECORD {
            return Err(io_err("quarantined payload too large"));
        }
        let plain = postcard::to_stdvec(&(sender, plaintext, now)).map_err(io_err)?;
        let blob = self.key.seal(&self.label(&self.quarantine_path()), &plain);
        let len: u32 = blob.len().try_into().map_err(|_| io_err("quarantine record too large"))?;
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(self.quarantine_path())?;
        f.write_all(&len.to_le_bytes())?;
        f.write_all(&blob)?;
        f.sync_all()
    }

    /// Read the quarantined messages back. For an operator, or a later build that learns how to
    /// apply them; the receive path never reads this.
    pub fn load_quarantine(&self) -> io::Result<Vec<QuarantinedMessage>> {
        let bytes = match std::fs::read(self.quarantine_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let label = self.label(&self.quarantine_path());
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos + 4 <= bytes.len() {
            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if len == 0 || len > MAX_HISTORY_RECORD || pos + len > bytes.len() {
                break; // torn tail: stop, do not guess
            }
            let plain = self.key.open(&label, &bytes[pos..pos + len]).map_err(io_err)?;
            let (sender, plaintext, received_at) = postcard::from_bytes(&plain).map_err(io_err)?;
            out.push(QuarantinedMessage { sender, plaintext, received_at });
            pos += len;
        }
        Ok(out)
    }

    /// Drop the quarantine log once its contents have been re-applied.
    ///
    /// Called AFTER the handlers have run, never before: that ordering is what makes the replay
    /// at-least-once. A crash midway simply replays the same items on the next launch, and the
    /// handlers are the same ones ordinary delivery uses, so a repeat is the duplicate they
    /// already tolerate — whereas clearing first would recreate the loss this log exists to stop.
    pub fn clear_quarantine(&self) -> io::Result<()> {
        match std::fs::remove_file(self.quarantine_path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Network-scoped (proxy-namespaced, same as `sessions.dat`) — the ledger names outbox ids,
    /// and outbox ids are only meaningful against ONE proxy's `sessions.dat`.
    fn ledger_path(&self) -> PathBuf {
        self.net_file("send_ledger.dat")
    }

    /// Load the pending-send ledger — see [`PendingSend`]. Empty if the file does not exist
    /// (nothing queued yet that this build still needs to resolve).
    pub fn load_send_ledger(&self) -> io::Result<Vec<PendingSend>> {
        match std::fs::read(self.ledger_path()) {
            Ok(blob) => {
                let plain = self.key.open(&self.label(&self.ledger_path()), &blob).map_err(io_err)?;
                postcard::from_bytes(&plain).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Overwrite the ledger with exactly `entries`. Callers load, reconcile (drop resolved ids,
    /// add newly-queued ones) and save the whole thing back under the SAME `lock_sessions`
    /// window as the `sessions.dat` write it tracks, so the two never disagree about what is
    /// still in flight.
    pub fn save_send_ledger(&self, entries: &[PendingSend]) -> io::Result<()> {
        if entries.len() > MAX_LEDGER {
            return Err(io_err("pending-send ledger over its defensive cap — reconciliation fell behind"));
        }
        let plain = postcard::to_stdvec(entries).map_err(io_err)?;
        self.write_sealed(&self.ledger_path(), &plain)
    }

    fn stranded_path(&self) -> PathBuf {
        self.net_file("stranded_sends.dat")
    }

    /// Durably append a message that was queued but will never be delivered — see
    /// [`StrandedSend`]. Same append-only, length-prefixed-sealed-record shape as
    /// [`Store::quarantine_incoming`] (O(1) per record, torn-tail tolerant on read).
    pub fn park_stranded_send(
        &self,
        peer_ik: [u8; 32],
        plaintext: &[u8],
        queued_at: u64,
        lost_at: u64,
        reason: &str,
    ) -> io::Result<()> {
        if plaintext.len() > MAX_HISTORY_RECORD {
            return Err(io_err("stranded payload too large"));
        }
        let plain = postcard::to_stdvec(&(peer_ik, plaintext, queued_at, lost_at, reason)).map_err(io_err)?;
        let blob = self.key.seal(&self.label(&self.stranded_path()), &plain);
        let len: u32 = blob.len().try_into().map_err(|_| io_err("stranded record too large"))?;
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(self.stranded_path())?;
        f.write_all(&len.to_le_bytes())?;
        f.write_all(&blob)?;
        f.sync_all()
    }

    /// Read back every stranded send recorded so far — for a UI "these messages were never
    /// delivered" indicator. Reading does not consume the log.
    pub fn load_stranded_sends(&self) -> io::Result<Vec<StrandedSend>> {
        let bytes = match std::fs::read(self.stranded_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let label = self.label(&self.stranded_path());
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos + 4 <= bytes.len() {
            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if len == 0 || len > MAX_HISTORY_RECORD || pos + len > bytes.len() {
                break; // torn tail: stop, do not guess
            }
            let plain = self.key.open(&label, &bytes[pos..pos + len]).map_err(io_err)?;
            let (peer_ik, plaintext, queued_at, lost_at, reason): ([u8; 32], Vec<u8>, u64, u64, String) =
                postcard::from_bytes(&plain).map_err(io_err)?;
            out.push(StrandedSend { peer_ik, plaintext, queued_at, lost_at, reason });
            pos += len;
        }
        Ok(out)
    }

    /// Drop the stranded-send log once a caller (a UI, or the user dismissing the notice) has
    /// seen it. Same one-shot shape as [`Store::clear_quarantine`].
    pub fn clear_stranded_sends(&self) -> io::Result<()> {
        match std::fs::remove_file(self.stranded_path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn history_path(&self) -> PathBuf {
        self.dir.join("history.dat")
    }

    fn history_index_path(&self) -> PathBuf {
        self.dir.join("history_index.dat")
    }

    fn history_lock_path(&self) -> PathBuf {
        self.dir.join("history.lock")
    }

    /// Эксклюзивный замок на окно append/load истории (сериализует писателей между
    /// процессами; mid-file interleave был бы НЕвосстановим усечением хвоста).
    fn lock_history(&self) -> io::Result<SessionLock> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.history_lock_path())?;
        file.lock()?;
        Ok(SessionLock { _file: file })
    }

    /// Дописать одну запись истории (append + fsync под замком). Вызывать:
    /// входящие — БЕЗУСЛОВНО; исходящие — ТОЛЬКО после успешной `send_session`
    /// (иначе провал отправки стал бы ДОЛГОВЕЧНО залогирован как доставленное —
    /// та самая оптимистичная граница, но уже на диске).
    pub fn append_history(&self, rec: &HistoryRecord) -> io::Result<()> {
        self.append_history_with_id(rec, [0u8; 32])
    }

    /// Append an INCOMING record carrying its `msg_id` (`payload_id`) for later dedup. Used by
    /// the plaintext-first receive path: the plaintext lands here BEFORE the ratchet commit,
    /// and the id lets a redelivered copy be recognised and skipped.
    pub fn append_history_incoming(&self, rec: &HistoryRecord, msg_id: [u8; 32]) -> io::Result<()> {
        self.append_history_with_id(rec, msg_id)?;
        // The plaintext is now durable and the dedup ring is not. A crash HERE is the one this
        // ring exists to absorb, and the claimed cost is one re-appended message — never a lost
        // one. Checked by a crash test rather than asserted (QA-2, transaction 3).
        node::fail_point!("store.history.after_append_before_dedup");
        self.note_incoming_id(msg_id);
        Ok(())
    }

    fn append_history_with_id(&self, rec: &HistoryRecord, msg_id: [u8; 32]) -> io::Result<()> {
        let plain = postcard::to_stdvec(&StoredHistory { rec: rec.clone(), msg_id }).map_err(io_err)?;
        let blob = self.key.seal(&self.label(&self.history_path()), &plain);
        let len: u32 =
            blob.len().try_into().map_err(|_| io_err("history record too large"))?;
        let _lock = self.lock_history()?;
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(self.history_path())?;
        let mut framed = Vec::with_capacity(4 + blob.len());
        framed.extend_from_slice(&len.to_le_bytes());
        framed.extend_from_slice(&blob);
        f.write_all(&framed)?; // one record under O_APPEND + the lock
        f.sync_all()
    }

    /// Сканировать сырой файл истории до первой битой границы. Возвращает разобранные
    /// записи и смещение последней ЧИСТОЙ границы (`last_good`) — всё после него
    /// рваный/мусорный хвост. Чистая функция разбора (без замка/IO) — переиспользуется
    /// загрузкой (усекает хвост) и перезаписью (дропает хвост, переписав только целое).
    fn scan_history(&self, bytes: &[u8]) -> (Vec<StoredHistory>, usize) {
        let mut records = Vec::new();
        let mut off = 0usize;
        let mut last_good = 0usize;
        while off + 4 <= bytes.len() {
            let len = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
            if len == 0 || len > MAX_HISTORY_RECORD {
                break; // absurd length → the boundary of garbage
            }
            let start = off + 4;
            let end = match start.checked_add(len) {
                Some(e) if e <= bytes.len() => e,
                _ => break, // the record does not fit → a torn tail
            };
            let plain = match self.key.open(&self.label(&self.history_path()), &bytes[start..end]) {
                Ok(p) => p,
                Err(_) => break, // did not decrypt → boundary
            };
            // Try the current layout (with `msg_id`) first; fall back to a pre-`msg_id` bare
            // `HistoryRecord` (postcard errors on the missing trailing field, and try-new-first
            // because it would otherwise ignore trailing bytes). Old records get a zero id,
            // which never matches a real `payload_id`, so they simply don't dedup.
            let Some(stored) = decode_stored_history(&plain) else { break };
            records.push(stored);
            off = end;
            last_good = end;
        }
        (records, last_good)
    }

    /// Загрузить всю историю. При СТАРТЕ восстанавливает целостность: сканирует до
    /// последней чисто разобранной границы записи и УСЕКАЕТ файл до неё. Иначе
    /// рваный хвост (крах на середине append) не просто терял бы последнее
    /// сообщение — его битый length-prefix рассинхронизировал бы чтение и ОТРАВИЛ
    /// БЫ все будущие append'ы. Потеря последней записи — liveness, не reuse.
    pub fn load_history(&self) -> io::Result<Vec<HistoryRecord>> {
        let _lock = self.lock_history()?;
        let path = self.history_path();
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let (records, last_good) = self.scan_history(&bytes);
        if last_good < bytes.len() {
            // Отрезать рваный/мусорный хвост, чтобы будущие append'ы парсились.
            OpenOptions::new().write(true).open(&path)?.set_len(last_good as u64)?;
        }
        Ok(records.into_iter().map(|s| s.rec).collect())
    }

    /// Load only `peer`'s side of the conversation log.
    ///
    /// Opening a chat used to read and AEAD-open the WHOLE account history to display one
    /// conversation, so the cost grew with the AGE of the account rather than with anything the
    /// user was doing — it got slower by being used. This reads the index, seeks to that peer's
    /// records, and opens those.
    ///
    /// The index is a cache and is repaired here rather than maintained on write; see
    /// [`HistoryIndex`] for why that is the safer half of the trade.
    pub fn load_history_for_peer(&self, peer: &[u8; 32]) -> io::Result<Vec<HistoryRecord>> {
        let _lock = self.lock_history()?;
        let path = self.history_path();
        let mut f = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let file_len = f.metadata()?.len();
        let index = self.refresh_history_index(&mut f, file_len)?;

        let mut out = Vec::new();
        let Some((_, offsets)) = index.peers.iter().find(|(p, _)| p == peer) else {
            return Ok(out);
        };
        for &off in offsets {
            // A bad offset is a corrupt cache, not corrupt history: skip the entry rather than
            // failing the read, and the next rebuild will drop it.
            let Some(rec) = self.read_history_record_at(&mut f, off, file_len)? else { continue };
            out.push(rec);
        }
        Ok(out)
    }

    /// Read one record whose 4-byte length prefix starts at `off`. `None` = this offset does not
    /// point at a well-formed, openable record.
    fn read_history_record_at(
        &self,
        f: &mut std::fs::File,
        off: u64,
        file_len: u64,
    ) -> io::Result<Option<HistoryRecord>> {
        use std::io::{Read, Seek, SeekFrom};
        if off.saturating_add(4) > file_len {
            return Ok(None);
        }
        f.seek(SeekFrom::Start(off))?;
        let mut lenb = [0u8; 4];
        f.read_exact(&mut lenb)?;
        let len = u32::from_le_bytes(lenb) as usize;
        if len == 0 || len > MAX_HISTORY_RECORD || off + 4 + len as u64 > file_len {
            return Ok(None);
        }
        let mut blob = vec![0u8; len];
        f.read_exact(&mut blob)?;
        let Ok(plain) = self.key.open(&self.label(&self.history_path()), &blob) else {
            return Ok(None);
        };
        Ok(decode_stored_history(&plain).map(|s| s.rec))
    }

    /// Bring the index up to date with the log and return it. Cheap in the common case: it scans
    /// only the bytes appended since the last time, and writes nothing when there are none.
    fn refresh_history_index(
        &self,
        f: &mut std::fs::File,
        file_len: u64,
    ) -> io::Result<HistoryIndex> {
        let mut index = self.load_history_index();
        if index.covered_upto > file_len {
            // The log got SHORTER — `load_history` truncated a torn tail — so the bytes this
            // index describes past the new end are gone.
            index = HistoryIndex::default();
        }
        if index.covered_upto == file_len {
            return Ok(index);
        }
        let progressed = self.extend_history_index(&mut index, f, file_len)?;
        if !progressed && index.covered_upto > 0 {
            // Nothing parsed at the mark, yet the file is longer than the mark. That is not an
            // ordinary torn tail: it means the log was REWRITTEN under us — truncated mid-record
            // and then appended to, so the mark now sits inside a record that did not exist when
            // it was taken. Length alone cannot see this, because the regrown file is longer than
            // the mark again. Everything after the mark would silently never be indexed, so the
            // index is discarded and rebuilt from zero.
            //
            // A genuine torn tail reaches this only if it starts exactly at the mark, in which
            // case the rebuild costs one full rescan and lands on the same answer — and
            // `load_history` cuts that tail the next time it runs.
            index = HistoryIndex::default();
            self.extend_history_index(&mut index, f, file_len)?;
        }
        // Best-effort: a cache that fails to persist costs one rescan, never a message.
        let _ = self.save_history_index(&index);
        Ok(index)
    }

    /// Scan from `index.covered_upto` to the end, recording each record's offset. Returns whether
    /// it consumed at least one record — the caller uses that to tell "nothing new" from "the
    /// mark is not on a record boundary any more".
    fn extend_history_index(
        &self,
        index: &mut HistoryIndex,
        f: &mut std::fs::File,
        file_len: u64,
    ) -> io::Result<bool> {
        use std::io::{Read, Seek, SeekFrom};
        if index.covered_upto >= file_len {
            return Ok(false);
        }
        f.seek(SeekFrom::Start(index.covered_upto))?;
        let mut tail = Vec::new();
        f.read_to_end(&mut tail)?;

        let base = index.covered_upto;
        let mut off = 0usize;
        let mut progressed = false;
        while off + 4 <= tail.len() {
            let len = u32::from_le_bytes(tail[off..off + 4].try_into().unwrap()) as usize;
            if len == 0 || len > MAX_HISTORY_RECORD {
                break;
            }
            let start = off + 4;
            let Some(end) = start.checked_add(len).filter(|e| *e <= tail.len()) else { break };
            let Ok(plain) = self.key.open(&self.label(&self.history_path()), &tail[start..end])
            else {
                break; // a record that will not open is the same boundary `scan_history` stops at
            };
            let Some(stored) = decode_stored_history(&plain) else { break };
            let peer = stored.rec.peer_ik;
            let at = base + off as u64;
            match index.peers.iter_mut().find(|(p, _)| *p == peer) {
                Some((_, offsets)) => offsets.push(at),
                None => index.peers.push((peer, vec![at])),
            }
            off = end;
            index.covered_upto = base + end as u64;
            progressed = true;
        }
        Ok(progressed)
    }

    fn load_history_index(&self) -> HistoryIndex {
        let path = self.history_index_path();
        let Ok(blob) = std::fs::read(&path) else { return HistoryIndex::default() };
        let Ok(plain) = self.key.open(&self.label(&path), &blob) else {
            return HistoryIndex::default(); // corrupt or from another key: rebuild, do not fail
        };
        // postcard ignores trailing bytes, which is what makes the padding below free.
        postcard::from_bytes(&plain).unwrap_or_default()
    }

    fn save_history_index(&self, index: &HistoryIndex) -> io::Result<()> {
        let mut plain = postcard::to_stdvec(index).map_err(io_err)?;
        // Pad to a page multiple before sealing. Without it the FILE SIZE tracks the number of
        // records per contact closely enough to be a side channel of its own — how many people
        // you talk to and how much — visible to anyone who can see the directory but not open it.
        // The contents are sealed; the length is not, so the length is what gets rounded off.
        let padded = plain.len().next_multiple_of(HISTORY_INDEX_PAGE);
        plain.resize(padded, 0);
        self.write_sealed(&self.history_index_path(), &plain)
    }

    /// The `payload_id`s of the last `limit` INCOMING history records — the dedup set for the
    /// plaintext-first receive path. Only the recent tail is logically needed: a redelivered
    /// duplicate arises only in the crash-before-ratchet-save window and reappears on the very
    /// next poll, so its twin is among the newest records.
    ///
    /// **Bounded, and this comment used to say otherwise.** It described reading and AEAD-opening
    /// the WHOLE history file per poll and called that "acceptable for now" — true when written,
    /// false since the dedup ring landed. This reads `dedup.dat` alone: one sealed file capped at
    /// `DEDUP_RING_CAP`, so the cost is a fixed tail rather than O(history). The stale version was
    /// worse than no comment, because it sent a reader looking for a performance problem that had
    /// already been fixed — and it survived long enough to be filed as a backlog item on that
    /// premise.
    ///
    /// Zeroed ids (outgoing / pre-`msg_id` legacy) are excluded — they never match a real id.
    pub fn recent_incoming_ids(&self, limit: usize) -> io::Result<std::collections::HashSet<[u8; 32]>> {
        let ring = self.load_dedup_ring()?;
        let start = ring.len().saturating_sub(limit);
        Ok(ring[start..].iter().copied().collect())
    }

    fn dedup_ring_path(&self) -> PathBuf {
        self.dir.join("dedup.dat")
    }

    /// The newest incoming `msg_id`s, kept in their OWN small file.
    ///
    /// This used to be answered by reading and AEAD-opening the ENTIRE history log and slicing
    /// its tail — for a caller that wants at most a thousand 32-byte ids. It ran once per ack
    /// pass, including on an empty mailbox, and the desktop poll does that up to eighty times
    /// across its proxies, so a remote sender could grow your history legitimately and thereby
    /// turn every future poll into O(history) — and O(pages x history) while paging (SEC-42).
    ///
    /// The framed append-log has no reverse index, so "read the tail" was never possible in
    /// place. A dedicated ring makes the read proportional to the WINDOW instead of the log.
    fn load_dedup_ring(&self) -> io::Result<Vec<[u8; 32]>> {
        match std::fs::read(self.dedup_ring_path()) {
            Ok(blob) => {
                let plain =
                    self.key.open(&self.label(&self.dedup_ring_path()), &blob).map_err(io_err)?;
                postcard::from_bytes(&plain).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Record an incoming `msg_id` in the dedup ring, oldest evicted past `DEDUP_RING_CAP`.
    ///
    /// Best-effort ON PURPOSE, and the reason is worth stating: this ring only suppresses a
    /// DUPLICATE, and the duplicate it suppresses is the one produced by a crash between the
    /// history append and the ratchet save. Losing a ring entry costs one re-appended message,
    /// never a lost one — so failing the whole receive because a cache write failed would trade
    /// a cosmetic problem for a real one.
    fn note_incoming_id(&self, msg_id: [u8; 32]) {
        if msg_id == [0u8; 32] {
            return; // outgoing / unstamped: never matches a real id anyway
        }
        let Ok(mut ring) = self.load_dedup_ring() else { return };
        if ring.last() == Some(&msg_id) {
            return;
        }
        ring.push(msg_id);
        let over = ring.len().saturating_sub(DEDUP_RING_CAP);
        if over > 0 {
            ring.drain(..over);
        }
        if let Ok(plain) = postcard::to_stdvec(&ring) {
            let _ = self.write_sealed(&self.dedup_ring_path(), &plain);
        }
    }

    /// Перезаписать историю, оставив только записи, для которых `keep` вернул `true`
    /// (удаление сообщений / очистка переписки / истечение исчезающих). Возвращает
    /// УДАЛЁННЫЕ записи (не только счётчик) — вызывающий считает их `msg_id` и чистит
    /// метаданные (`prune_meta`), а `rewrite_history` остаётся single-purpose.
    ///
    /// Атомарно: пишем во временный файл (0600), fsync, `rename` поверх (замена
    /// inode за одну операцию ФС) — крах на середине не оставит полу-перезаписанной
    /// истории. Каждая оставленная запись запечатывается ЗАНОВО (свежий 192-бит
    /// nonce — как append), поэтому переписывание безопасно (это не ratchet). Рваный
    /// хвост при этом естественно отбрасывается: переписываем лишь целые записи.
    /// В отличие от append (O(1)) это O(n) — вызывать по действию пользователя/
    /// подметанию, а не на каждое сообщение.
    pub fn rewrite_history(
        &self,
        mut keep: impl FnMut(&HistoryRecord) -> bool,
    ) -> io::Result<Vec<HistoryRecord>> {
        let _lock = self.lock_history()?;
        let path = self.history_path();
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let (records, _) = self.scan_history(&bytes);
        let mut kept: Vec<&StoredHistory> = Vec::with_capacity(records.len());
        let mut removed: Vec<HistoryRecord> = Vec::new();
        for s in &records {
            if keep(&s.rec) {
                kept.push(s);
            } else {
                removed.push(s.rec.clone());
            }
        }
        if removed.is_empty() {
            return Ok(removed); // nothing to change — leave the file alone
        }
        let mut out = Vec::new();
        for stored in kept {
            // Re-seal the WHOLE stored record (rec + msg_id) so a rewrite (deletion / expiry)
            // preserves the dedup id of the records it keeps.
            let plain = postcard::to_stdvec(stored).map_err(io_err)?;
            let blob = self.key.seal(&self.label(&self.history_path()), &plain);
            let len: u32 =
                blob.len().try_into().map_err(|_| io_err("history record too large"))?;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&blob);
        }
        let tmp = self.dir.join("history.dat.tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&out)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        // fsync каталога — чтобы переименование пережило крах (запись деструктивна).
        if let Ok(dir) = File::open(&self.dir) {
            let _ = dir.sync_all();
        }
        Ok(removed)
    }

    /// Delete a whole CONVERSATION — drop every history record with this peer. Used on "remove
    /// contact" so a later re-add by the SAME IK starts clean instead of resurrecting the old
    /// thread. (Orphaned reaction/edit metadata is harmless — see `prune_meta` — so this stays
    /// simple; the `msg_id`s no longer render.)
    pub fn delete_conversation(&self, peer_ik: [u8; 32]) -> io::Result<()> {
        self.rewrite_history(|r| r.peer_ik != peer_ik)?;
        Ok(())
    }

    // ----- Метаданные сообщений (реакции; позже reply/edit), шифрованы at-rest -----
    //
    // Отдельный sidecar `meta.dat` (whole-file atomic, как contacts.dat), НЕ трогает
    // формат `HistoryRecord` (postcard-позиционный — новое поле сломало бы диск).
    // Ключ — канонический `msg_id` (см. `content::msg_id`): один и тот же у обеих
    // сторон, поэтому метаданные джойнятся к истории при рендере без относительных
    // полей. Метаданные — best-effort: их порча/потеря НИКОГДА не блокирует историю
    // (расшифровка не удалась → пусто, не ошибка). Отдельный `meta.lock` (не вложен
    // в history.lock — иначе реакции сериализовались бы против append'ов истории).

    fn meta_path(&self) -> PathBuf {
        self.dir.join("meta.dat")
    }

    fn meta_lock_path(&self) -> PathBuf {
        self.dir.join("meta.lock")
    }

    fn lock_meta(&self) -> io::Result<SessionLock> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.meta_lock_path())?;
        file.lock()?;
        Ok(SessionLock { _file: file })
    }

    /// Загрузить карту реакций (пусто, если файла нет ИЛИ он не расшифровался —
    /// метаданные best-effort, не блокируют историю). Анти-DoS: усечение сверх
    /// лимитов при разборе (не аллоцируем безгранично по чужому/битому файлу).
    pub fn load_meta(&self) -> io::Result<MetaMap> {
        let _lock = self.lock_meta()?;
        Ok(self.load_meta_unlocked())
    }

    fn load_meta_unlocked(&self) -> MetaMap {
        let blob = match std::fs::read(self.meta_path()) {
            Ok(b) => b,
            Err(_) => return MetaMap::new(),
        };
        let plain = match self.key.open(&self.label(&self.meta_path()), &blob) {
            Ok(p) => p,
            Err(_) => return MetaMap::new(), // not ours or corrupt → empty, never a panic
        };
        let mut map: MetaMap = match postcard::from_bytes(&plain) {
            Ok(m) => m,
            Err(_) => return MetaMap::new(),
        };
        // Оборонительно приводим к лимитам (файл мог прийти из будущего/битым).
        clamp_meta(&mut map);
        map
    }

    fn save_meta_unlocked(&self, map: &MetaMap) -> io::Result<()> {
        // Пустая карта → удаляем файл (не держим мусор).
        if map.is_empty() {
            match std::fs::remove_file(self.meta_path()) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            return Ok(());
        }
        let plain = postcard::to_stdvec(map).map_err(io_err)?;
        let bytes = self.key.seal(&self.label(&self.meta_path()), &plain);
        let tmp = self.dir.join("meta.dat.tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, self.meta_path())
    }

    /// Поставить/снять реакцию `author_ik` эмодзи `emoji` на сообщение `msg_id`.
    /// Идемпотентно (повтор `add` не дублирует — `BTreeSet`). Пустые множества/карты
    /// схлопываются (снятие последней реакции убирает запись). Анти-DoS: отвергаем
    /// абсурдный emoji / переполнение авторов-на-реакцию / числа сообщений ДО записи.
    pub fn set_reaction(
        &self,
        msg_id: [u8; 16],
        emoji: &str,
        author_ik: [u8; 32],
        add: bool,
    ) -> io::Result<()> {
        if emoji.is_empty() || emoji.len() > crate::content::MAX_EMOJI_BYTES {
            return Err(io_err("reaction emoji exceeds the length limit"));
        }
        let _lock = self.lock_meta()?;
        let mut map = self.load_meta_unlocked();
        if add {
            // Новый msg_id — только если не переполним карту (анти-память-DoS).
            if !map.contains_key(&msg_id) && map.len() >= MAX_META_MESSAGES {
                return Err(io_err("too many messages carrying metadata"));
            }
            let mm = map.entry(msg_id).or_default();
            if !mm.reactions.contains_key(emoji) && mm.reactions.len() >= MAX_REACTIONS_PER_MSG {
                return Err(io_err("too many distinct reactions on one message"));
            }
            let authors = mm.reactions.entry(emoji.to_string()).or_default();
            if !authors.contains(&author_ik) && authors.len() >= MAX_AUTHORS_PER_REACTION {
                return Err(io_err("too many authors for one reaction"));
            }
            authors.insert(author_ik);
        } else if let Some(mm) = map.get_mut(&msg_id) {
            if let Some(authors) = mm.reactions.get_mut(emoji) {
                authors.remove(&author_ik);
                if authors.is_empty() {
                    mm.reactions.remove(emoji);
                }
            }
            if mm.is_empty() {
                map.remove(&msg_id);
            }
        }
        self.save_meta_unlocked(&map)
    }

    /// Пометить сообщение `msg_id` как ОТВЕТ на `reply_to` (overlay в meta). Автор
    /// самого ответа — обычное сообщение в истории; здесь лишь связь «отвечает на».
    /// Анти-память-DoS: новый `msg_id` только под лимитом.
    pub fn set_reply(&self, msg_id: [u8; 16], reply_to: [u8; 16]) -> io::Result<()> {
        let _lock = self.lock_meta()?;
        let mut map = self.load_meta_unlocked();
        if !map.contains_key(&msg_id) && map.len() >= MAX_META_MESSAGES {
            return Err(io_err("too many messages carrying metadata"));
        }
        map.entry(msg_id).or_default().reply_to = Some(reply_to);
        self.save_meta_unlocked(&map)
    }

    /// Записать ПРАВКУ сообщения `msg_id`: `(edit_ts, new_text)` overlay в meta (сам
    /// `HistoryRecord` не трогаем — `msg_id` стабилен). Анти-DoS: длина текста и число
    /// сообщений под лимитом. Авторизацию (только автор цели) проверяет вызывающий
    /// ДО этого вызова (`incoming_edit_allowed`) — здесь только запись.
    /// Last-writer-by-`edit_ts` wins, NOT last-received: an edit is applied only if its
    /// `edit_ts` is at least the currently stored one. This makes edit application idempotent
    /// AND order-independent — a redelivered (crash-window) or reordered edit can never
    /// overwrite a newer edit with a stale one, and re-applying the same edit is a no-op. The
    /// sender stamps `edit_ts` monotonically, so ties (same author re-sending) keep the text.
    pub fn set_edit(&self, msg_id: [u8; 16], edit_ts: u64, new_text: &[u8]) -> io::Result<()> {
        if new_text.len() > crate::content::MAX_TEXT_BYTES {
            return Err(io_err("edit text exceeds the length limit"));
        }
        let _lock = self.lock_meta()?;
        let mut map = self.load_meta_unlocked();
        if let Some(mm) = map.get(&msg_id) {
            if let Some((have_ts, _)) = mm.edited {
                if edit_ts < have_ts {
                    return Ok(()); // a stale/reordered edit must not clobber a newer one
                }
            }
        }
        if !map.contains_key(&msg_id) && map.len() >= MAX_META_MESSAGES {
            return Err(io_err("too many messages carrying metadata"));
        }
        map.entry(msg_id).or_default().edited = Some((edit_ts, new_text.to_vec()));
        self.save_meta_unlocked(&map)
    }

    /// Удалить метаданные для набора `msg_id` (когда сами сообщения удалены из
    /// истории — delete/clear/tombstone/sweep). Best-effort, вызывать ПОСЛЕ
    /// `rewrite_history`; осиротевшая запись безвредна (ничего не рендерит) — но
    /// чистим, чтобы призрак не «прилип» к будущему сообщению с тем же `msg_id`.
    pub fn prune_meta(&self, ids: &[[u8; 16]]) -> io::Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let _lock = self.lock_meta()?;
        let mut map = self.load_meta_unlocked();
        let mut changed = false;
        for id in ids {
            if map.remove(id).is_some() {
                changed = true;
            }
        }
        if changed {
            self.save_meta_unlocked(&map)?;
        }
        Ok(())
    }
}

/// Метаданные ОДНОГО сообщения (sidecar `meta.dat`, ключ — канонический `msg_id`).
/// Все поля определены СРАЗУ: postcard кодирует поля позиционно, добавить поле
/// позже нельзя без слома диска (та же дисциплина, что у `HistoryRecord`). `BTree*`
/// — детерминированный at-rest blob.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsgMeta {
    /// Реакции: эмодзи → множество IK-авторов.
    pub reactions: BTreeMap<String, BTreeSet<[u8; 32]>>,
    /// Если это ответ/цитата — `msg_id` сообщения, на которое отвечают.
    pub reply_to: Option<[u8; 16]>,
    /// Правка: `(время правки, новый текст)` — overlay поверх текста истории. Сам
    /// `HistoryRecord` НЕ переписываем, чтобы `msg_id` (в нём есть текст) оставался
    /// стабильным — иначе реакции/ответы на это сообщение осиротели бы.
    pub edited: Option<(u64, Vec<u8>)>,
}

impl MsgMeta {
    /// Пусто (ни реакций, ни ответа, ни правки) → запись можно убрать из карты.
    pub fn is_empty(&self) -> bool {
        self.reactions.is_empty() && self.reply_to.is_none() && self.edited.is_none()
    }
}

/// Карта метаданных сообщений: `msg_id → MsgMeta`.
pub type MetaMap = BTreeMap<[u8; 16], MsgMeta>;

/// Максимум сообщений с метаданными (анти-память-DoS; осиротевшие реакции/ответы на
/// ещё-не-пришедшие/удалённые сообщения не должны копиться безгранично).
const MAX_META_MESSAGES: usize = 100_000;
/// Максимум РАЗНЫХ эмодзи-реакций на одно сообщение.
const MAX_REACTIONS_PER_MSG: usize = 64;
/// Максимум авторов одной эмодзи-реакции (в 1:1 практически 2, но с запасом на
/// будущие группы; главное — конечность против залива при приёме).
const MAX_AUTHORS_PER_REACTION: usize = 1024;

/// Оборонительно усечь карту к лимитам при загрузке (файл мог прийти битым/из
/// будущего с бóльшими лимитами). Тихо отбрасывает лишнее — не паникует.
fn clamp_meta(map: &mut MetaMap) {
    while map.len() > MAX_META_MESSAGES {
        let k = *map.keys().next_back().expect("non-empty");
        map.remove(&k);
    }
    for mm in map.values_mut() {
        while mm.reactions.len() > MAX_REACTIONS_PER_MSG {
            let k = mm.reactions.keys().next_back().expect("non-empty").clone();
            mm.reactions.remove(&k);
        }
        for authors in mm.reactions.values_mut() {
            while authors.len() > MAX_AUTHORS_PER_REACTION {
                let a = *authors.iter().next_back().expect("non-empty");
                authors.remove(&a);
            }
        }
        // Overlay правки из недоверенного файла — усечь абсурдную длину текста.
        if let Some((_, txt)) = &mut mm.edited {
            txt.truncate(crate::content::MAX_TEXT_BYTES);
        }
    }
}

/// RAII-замок сессий. Держите его на всё окно load→мутация→save; при `drop`
/// (в т.ч. при панике) замок снимается ОС.
pub struct SessionLock {
    _file: File,
}

/// Запись реестра аккаунтов (шифруется под vault-ключом). `id` — имя подкаталога
/// (`accounts/<id>`), `label` — пользовательское имя, `ik` — §2.1-адрес (для показа).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountEntry {
    pub id: String,
    pub label: String,
    pub ik: [u8; 32],
}

/// One CONNECTION PROXY in the root's registry (`proxies.dat`) — a disposable channel (see
/// docs/design/proxy-identity.md). Carries only what a channel needs: a stable `index` (used to
/// namespace this proxy's network files and to tag contacts — never reused, even after this entry
/// is burned), a random 32-byte `secret` (minted at creation, `OsRng` — the ONLY thing this
/// proxy's keys ever derive from; see `seed::derive_proxy_from_secret`), a human `label`, and when
/// it was made. A proxy owns NO contacts/profile/feed — those are the root's, one copy.
///
/// There is deliberately no `active` flag any more (#207, A6-4): existence in the registry IS
/// "active". Burning (`Store::burn_proxy`) removes the entry — and its `secret` — outright, so a
/// burned identity's keys become unrecoverable, including from the recovery phrase. The old model
/// (HD-derived from the phrase by index, burn = flip a flag) left every burned proxy's keys
/// forever re-derivable by anyone holding the phrase — burning was a label, not destruction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyEntry {
    pub index: u32,
    pub label: String,
    pub created_at: u64,
    /// Random per-proxy secret (32 bytes, `OsRng`), minted once at creation and never derived
    /// from the seed. This — not any HD index — is the sole root of this proxy's keys
    /// (`seed::derive_proxy_from_secret`). Deleting it (via `Store::burn_proxy`) is what makes a
    /// burned proxy's identity actually unrecoverable.
    pub secret: [u8; 32],
}

/// Full persisted payload of `proxies.dat`: the live entries AND the next index to mint.
/// Kept separate from `entries.len()`/`max(index)` because burning REMOVES an entry outright —
/// without a separately-tracked, monotonically-increasing counter, burning the highest-numbered
/// proxy would free its index for reuse, and the next mint would inherit that index's namespaced
/// network files (`net_file`: sessions/OPKs/discovery-key/…) and any stale contact→proxy tags
/// still pointing at it — silently reanimating state that belonged to the identity just burned.
/// `next_index` only ever increases.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ProxyRegistry {
    next_index: u32,
    entries: Vec<ProxyEntry>,
}

/// Network configuration remembered between launches, at the VAULT (device) level and
/// **encrypted at rest** with the device key.
///
/// Deliberately NOT a plaintext config file: a lost or stolen cold disk must not reveal that
/// this device talks to relay X over escape routes Y — that both identifies the owner
/// as a KARST user and hands the adversary the very routes they would need to block.
/// The price of that choice is the ordering: these can only be read AFTER the
/// passphrase opens the vault, so the login screen takes the passphrase and applies
/// the saved network config once unlocked (rather than prefilling fields before it).
///
/// Empty strings mean "not configured" — the same meaning the UI fields carry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetSettings {
    pub relay_addr: String,
    pub relay_id: String,
    /// SOCKS5 proxy of an external PT (Tor/obfs4/…) or a mixnet client; empty = none.
    pub socks5: String,
    /// Extra §15 failover routes, unified syntax (`ip:port` | `kind@ip:port`).
    pub routes: String,
    /// The `socks5` proxy is a mixnet (Nym) SOCKS client, so the carrier reads `mixnet`.
    pub mixnet: bool,
}

/// This account's privacy preferences. Its own sealed blob (`prefs.dat`), kept apart from
/// `NetSettings` on purpose (see `load_prefs`). postcard-positional: append fields ONLY at the end.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prefs {
    /// Default self-destruct timer for OUTGOING messages, in seconds; `0` = disabled (normal
    /// messages). When set, sends go out as `Content::TextExpiring` and are never written to disk
    /// on either side — they vanish from both UIs at the absolute `expire_at`.
    pub disappearing_secs: u32,
}

/// This account's preferences for WHICH relays to use, matched against each relay's advertised
/// policy (`node::protocol::RelayPolicy`). Empty = no preference (any relay).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPrefs {
    /// Prefer relays whose advertised blob persistence matches; `None` = don't care. The
    /// advertisement is operator-declared (durable is provable via `verify_durability`; ephemeral
    /// is a claim), so this is a preference, not a hard guarantee.
    pub prefer_persistence: Option<node::protocol::BlobPersistence>,
    /// Prefer relays whose advertised MAILBOX durability matches (R2-5, #161); `None` = don't
    /// care. This is the knob that makes the durability fix reachable by the code that needed
    /// it: `Response::Accepted` deliberately does not say whether the message was persisted, so
    /// the decision belongs here — at relay CHOICE — rather than per message. `Durable` means
    /// "an accepted message survives that relay restarting"; `Volatile` is the lower-residue
    /// posture, and (like ephemeral blobs) an unverifiable claim.
    pub prefer_mail_durability: Option<node::protocol::MailboxDurability>,
}

// ─── Multi-password keyslots (duress / decoy / dead-man — Tier 1, layout A′) ──────────────
//
// Every password (real, decoy, wipe) owns one fixed-size slot in `base/slots.dat`; each
// compartment's data lives under `base/c/<compartment_id>/` (real and decoy are STRUCTURALLY
// identical, so no on-disk blob is visibly "the primary one"). A slot is a normal sealed blob
// (`MAGIC ‖ nonce ‖ ct`) of a fixed 32-byte payload, so all slots are the same length; UNUSED
// slots are `MAGIC ‖ random` of that same length — indistinguishable from a used slot without the
// key, so the number of configured passwords is not inferable from `slots.dat`. On unlock, derive
// the key once and trial-`open()` each slot; the one that authenticates carries the role + which
// compartment to open (or that this password wipes). See docs/design/duress-multipassword.md.

const SLOT_COUNT: usize = 8;
/// Fixed plaintext: `role(1) ‖ compartment_id(16) ‖ reserved(15)`.
const SLOT_PLAIN: usize = 32;
/// Sealed slot length: `MAGIC(4) ‖ state_version(2) ‖ nonce(24) ‖ ct(SLOT_PLAIN + 16 tag)`.
/// Fixed on purpose — every slot is the same size whether used or not, so `slots.dat` never
/// reveals how many passwords are configured. Pinned by `multipassword_create_open_and_wrong_password`.
const SLOT_LEN: usize = 4 + 2 + 24 + SLOT_PLAIN + 16;

/// What a matching keyslot means for the password just entered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotRole {
    /// The real vault — the account(s) the owner actually uses.
    Real,
    /// A plausible, separate compartment (opened under coercion; hides the real one).
    Decoy,
    /// Not a login at all: entering this password crypto-erases everything.
    Wipe,
}

impl SlotRole {
    fn to_byte(self) -> u8 {
        match self {
            SlotRole::Real => 0,
            SlotRole::Decoy => 1,
            SlotRole::Wipe => 2,
        }
    }
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(SlotRole::Real),
            1 => Some(SlotRole::Decoy),
            2 => Some(SlotRole::Wipe),
            _ => None,
        }
    }
}

/// The outcome of opening a vault with a password: which compartment (real or decoy) to enter, or
/// that the password was a duress/wipe password (the erase already happened — show a fresh start).
pub enum Opened {
    Real(Vault),
    Decoy(Vault),
    Wipe,
}

/// An EXTRA (non-real) password configured on this device, for the Security card to list + manage.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExtraPassword {
    Decoy,
    Wipe,
}

/// Dead-man switch state. Kept PLAINTEXT (`base/deadman.dat`) because it must be evaluated at
/// LAUNCH, before any password is entered; it holds no secrets — only whether it is armed, the
/// interval, and the last real unlock. NOTE (honesty): being plaintext, it reveals that a dead-man
/// switch is armed and roughly when it will fire — accepted for Tier 1 (a pre-unlock check cannot
/// read a sealed file). Only a REAL unlock refreshes `last_seen`, so a coerced decoy login does not
/// keep the real data alive.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deadman {
    /// Seconds a real unlock must happen within, or `0` = disarmed.
    pub interval_secs: u64,
    /// Unix-secs of the last real unlock (the countdown restarts from here).
    pub last_seen: u64,
    /// High-water mark of the wall clock as we have actually OBSERVED it. The switch destroys
    /// data irreversibly, so it must not act on a single unverified `SystemTime::now()`: a
    /// forward jump (wrong RTC, restored VM snapshot, manual date change) would otherwise wipe a
    /// perfectly live vault on the next launch, and setting the clock BACK would postpone the
    /// wipe indefinitely. Comparing against this mark bounds both directions (A3-11).
    pub last_check: u64,
}

/// A forward clock movement larger than this, between two launches, is treated as a clock ANOMALY
/// rather than as evidence that the owner has been absent that long. 32 days: comfortably beyond
/// any real gap between launches we would act on, far below the multi-year jumps a wrong RTC or a
/// restored snapshot produces.
pub const DEADMAN_MAX_PLAUSIBLE_JUMP_SECS: u64 = 32 * 24 * 3600;

impl Deadman {
    pub fn armed(&self) -> bool {
        self.interval_secs > 0
    }
    /// Seconds left before the auto-wipe fires (`0` = overdue), or `None` when disarmed.
    pub fn remaining(&self, now: u64) -> Option<u64> {
        self.armed().then(|| self.last_seen.saturating_add(self.interval_secs).saturating_sub(now))
    }
}

fn slots_path(base: &std::path::Path) -> PathBuf {
    base.join("slots.dat")
}


/// Rename `tmp` over `dest` and make the RENAME itself durable by fsyncing the directory.
///
/// `sync_all` on the file only promises its CONTENTS survive a power loss — POSIX does not
/// promise the directory entry does. Without this a crash can leave the OLD file in place after a
/// write that reported success, which is not a cosmetic loss:
/// - for `sessions.dat` the ratchet silently rolls BACK, so the next send re-derives a message key
///   already used, under the fixed all-zero nonce → keystream reuse (CRYPTO-01);
/// - for the container a completed wipe can reappear (CRYPTO-12).
///
/// A failed directory sync is reported, not swallowed: the caller asked for a durable write.
pub(crate) fn rename_durable(tmp: &std::path::Path, dest: &std::path::Path) -> io::Result<()> {
    std::fs::rename(tmp, dest)?;
    #[cfg(unix)]
    {
        let dir = dest.parent().unwrap_or_else(|| std::path::Path::new("."));
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

fn write_fixed_0600(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    rename_durable(&tmp, path)
}

/// At-rest label of the slot directory (sealed under the REAL key).
const SLOTDIR_LABEL: &str = "slotmap";


fn compartment_dir(base: &std::path::Path, id: &[u8; 16]) -> PathBuf {
    base.join("c").join(hex::encode(id))
}

/// A random 16-byte id (compartment ids, publication ids). Public so the GUI can mint a
/// shared publication id to fan out across contacts.
pub fn random16() -> [u8; 16] {
    let mut id = [0u8; 16];
    id.copy_from_slice(&crate::blob::random32()[..16]);
    id
}

/// Pack a slot's fixed 32-byte plaintext.
fn slot_pack(role: SlotRole, id: &[u8; 16]) -> [u8; SLOT_PLAIN] {
    let mut p = [0u8; SLOT_PLAIN];
    p[0] = role.to_byte();
    p[1..17].copy_from_slice(id);
    p
}

fn slot_unpack(plain: &[u8]) -> Option<(SlotRole, [u8; 16])> {
    if plain.len() != SLOT_PLAIN {
        return None;
    }
    let role = SlotRole::from_byte(plain[0])?;
    let mut id = [0u8; 16];
    id.copy_from_slice(&plain[1..17]);
    Some((role, id))
}

/// Read the slot array (`SLOT_COUNT` fixed-size records), or `None` if `slots.dat` is absent.
fn slots_load(base: &std::path::Path) -> io::Result<Option<Vec<[u8; SLOT_LEN]>>> {
    match std::fs::read(slots_path(base)) {
        Ok(bytes) if bytes.len() == SLOT_COUNT * SLOT_LEN => {
            let mut out = Vec::with_capacity(SLOT_COUNT);
            for i in 0..SLOT_COUNT {
                let mut s = [0u8; SLOT_LEN];
                s.copy_from_slice(&bytes[i * SLOT_LEN..(i + 1) * SLOT_LEN]);
                out.push(s);
            }
            Ok(Some(out))
        }
        Ok(_) => Err(io_err("slots.dat: unexpected length")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// A fresh slot array with every slot UNUSED: `MAGIC ‖ random` at the full slot length, so an
/// empty slot is byte-shaped exactly like a sealed one (an adversary can't count real passwords).
fn slots_fresh() -> Vec<[u8; SLOT_LEN]> {
    (0..SLOT_COUNT).map(|_| slot_random()).collect()
}

/// One UNUSED slot: the sealed-blob magic prefix followed by random bytes (see `slots_fresh`).
fn slot_random() -> [u8; SLOT_LEN] {
    let mut s = [0u8; SLOT_LEN];
    s[..4].copy_from_slice(crate::secretbox::MAGIC);
    let mut off = 4;
    while off < SLOT_LEN {
        let r = crate::blob::random32();
        let n = (SLOT_LEN - off).min(r.len());
        s[off..off + n].copy_from_slice(&r[..n]);
        off += n;
    }
    s
}

/// Atomically write the slot array (temp 0600 → fsync → rename).
fn slots_save(base: &std::path::Path, slots: &[[u8; SLOT_LEN]]) -> io::Result<()> {
    let mut buf = Vec::with_capacity(SLOT_COUNT * SLOT_LEN);
    for s in slots {
        buf.extend_from_slice(s);
    }
    let tmp = base.join("slots.dat.tmp");
    {
        let mut f =
            OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(&buf)?;
        f.sync_all()?;
    }
    rename_durable(&tmp, &slots_path(base))
}

/// At-rest label for a keyslot record. Fixed rather than path-derived: slots are trial-opened by
/// password before any account is known, and every slot in the file must derive the same key or
/// the trial would leak which slot belongs where.
const SLOT_LABEL: &str = "keyslot";

/// Trial-open every slot with `key`; return the first that authenticates as a valid payload.
fn slot_find(base: &std::path::Path, key: &MasterKey) -> io::Result<Option<(SlotRole, [u8; 16])>> {
    let Some(slots) = slots_load(base)? else { return Ok(None) };
    for s in &slots {
        if let Ok(plain) = key.open(SLOT_LABEL, s) {
            if let Some(hit) = slot_unpack(&plain) {
                return Ok(Some(hit));
            }
        }
    }
    Ok(None)
}

/// The slot INDEX currently held by `key`, if any (used to overwrite in place rather than leak a
/// second slot for the same password).
fn slot_index_of(slots: &[[u8; SLOT_LEN]], key: &MasterKey) -> Option<usize> {
    slots.iter().position(|s| key.open(SLOT_LABEL, s).ok().and_then(|p| slot_unpack(&p)).is_some())
}

/// Seal `(role, id)` under `key` into a fixed-length slot record.
fn slot_seal(key: &MasterKey, role: SlotRole, id: &[u8; 16]) -> [u8; SLOT_LEN] {
    let blob = key.seal(SLOT_LABEL, &slot_pack(role, id));
    debug_assert_eq!(blob.len(), SLOT_LEN);
    let mut s = [0u8; SLOT_LEN];
    s.copy_from_slice(&blob);
    s
}

/// One entry of the slot DIRECTORY — sealed under the real key, so only a real session can read it.
/// A password can trial-open only its OWN slot, so it cannot see which indices belong to OTHER
/// passwords; the directory is what lets the owner (a) place a new slot without clobbering an
/// existing one and (b) ENUMERATE + remove specific extras (decoy/wipe) for the Security UI without
/// knowing their keys. NOTE (honesty, Tier-1): `slotmap.dat`'s existence is a base-level tell that a
/// real key exists — closed only by the fixed-dummy-compartment (Tier-2) work; see the design doc.
#[derive(Clone, Serialize, Deserialize)]
struct SlotEntry {
    index: u8,
    role: u8,                 // SlotRole::to_byte
    compartment_id: [u8; 16], // zeroed for Wipe
}

fn slotdir_path(base: &std::path::Path) -> PathBuf {
    base.join("slotmap.dat")
}

/// Load the slot directory (empty if absent). Sealed under the real key.
fn slotdir_load(base: &std::path::Path, real_key: &MasterKey) -> io::Result<Vec<SlotEntry>> {
    match std::fs::read(slotdir_path(base)) {
        Ok(blob) => {
            let bytes = real_key.open(SLOTDIR_LABEL, &blob).map_err(io_err)?;
            postcard::from_bytes(&bytes).map_err(io_err)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

fn slotdir_save(base: &std::path::Path, real_key: &MasterKey, dir: &[SlotEntry]) -> io::Result<()> {
    let plain = postcard::to_stdvec(dir).map_err(io_err)?;
    let blob = real_key.seal(SLOTDIR_LABEL, &plain);
    let tmp = base.join("slotmap.dat.tmp");
    {
        let mut f =
            OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(&blob)?;
        f.sync_all()?;
    }
    rename_durable(&tmp, &slotdir_path(base))
}

/// Write (or overwrite) `target_key`'s slot with `(role, id)` and record it in the directory,
/// preserving every other slot. Clobber-safe: a brand-new slot takes a random index the directory
/// (`real_key`) shows FREE, so it never overwrites another password's slot. `target_key == real_key`
/// for the real slot. The directory is written BEFORE the slot, so a crash between the two writes at
/// worst wastes an index (the add "didn't take") rather than clobbering an existing password.
fn slot_write(
    base: &std::path::Path,
    real_key: &MasterKey,
    target_key: &MasterKey,
    role: SlotRole,
    id: &[u8; 16],
) -> io::Result<()> {
    let mut slots = slots_load(base)?.unwrap_or_else(slots_fresh);
    let mut dir = slotdir_load(base, real_key)?;
    let idx = match slot_index_of(&slots, target_key) {
        Some(i) => i, // overwrite this password's own slot in place
        None => {
            let taken: Vec<u8> = dir.iter().map(|e| e.index).collect();
            let start = (crate::blob::random32()[0] as usize) % SLOT_COUNT;
            (0..SLOT_COUNT)
                .map(|k| (start + k) % SLOT_COUNT)
                .find(|&i| !taken.contains(&(i as u8)))
                .ok_or_else(|| io_err("no free keyslot"))?
        }
    };
    dir.retain(|e| e.index != idx as u8);
    dir.push(SlotEntry { index: idx as u8, role: role.to_byte(), compartment_id: *id });
    slotdir_save(base, real_key, &dir)?; // reserve first
    slots[idx] = slot_seal(target_key, role, id);
    slots_save(base, &slots)
}

/// Remove `target_key`'s slot (random-fill it) and its directory entry. No-op if not present.
fn slot_erase(base: &std::path::Path, real_key: &MasterKey, target_key: &MasterKey) -> io::Result<()> {
    let Some(mut slots) = slots_load(base)? else { return Ok(()) };
    let Some(idx) = slot_index_of(&slots, target_key) else { return Ok(()) };
    slots[idx] = slot_random();
    slots_save(base, &slots)?;
    let mut dir = slotdir_load(base, real_key)?;
    dir.retain(|e| e.index != idx as u8);
    slotdir_save(base, real_key, &dir)
}

fn deadman_path(base: &std::path::Path) -> PathBuf {
    base.join("deadman.dat")
}

/// Load the dead-man state (plaintext); a missing or corrupt file reads as disarmed, so it can
/// never wedge unlock.
fn deadman_load(base: &std::path::Path) -> Deadman {
    std::fs::read(deadman_path(base))
        .ok()
        .and_then(|b| postcard::from_bytes(&b).ok())
        .unwrap_or_default()
}

/// Atomically write the dead-man state (plaintext — it is checked before any password).
fn deadman_save(base: &std::path::Path, dm: &Deadman) -> io::Result<()> {
    let bytes = postcard::to_stdvec(dm).map_err(io_err)?;
    let tmp = base.join("deadman.dat.tmp");
    {
        let mut f =
            OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    rename_durable(&tmp, &deadman_path(base))
}

/// Crypto-erase the whole vault: shred the salt FIRST (that alone makes every sealed file — real
/// AND decoy — permanently unopenable), then unlink the compartments and slot table so the on-disk
/// footprint returns to "fresh install". Best-effort per file. NOTE (honesty): on SSD/CoW/journaled
/// filesystems a deleted 16-byte salt can linger in free space, so this is not guaranteed
/// unrecoverable against a forensic adversary — see the design doc.
fn crypto_erase(base: &std::path::Path) -> io::Result<()> {
    let _ = std::fs::remove_file(base.join("salt"));
    let _ = std::fs::remove_file(slots_path(base));
    let _ = std::fs::remove_file(slotdir_path(base));
    let _ = std::fs::remove_file(base.join("deadman.dat"));
    let _ = std::fs::remove_file(base.join("accounts.dat")); // pre-migration root registry, if any
    let _ = std::fs::remove_dir_all(base.join("accounts")); // pre-migration root accounts, if any
    let _ = std::fs::remove_dir_all(base.join("c"));
    Ok(())
}

/// Recursively copy `src` into `dst` (used by the A′ compartment migration — COPY, then delete the
/// originals only after the slot table commits, so a crash mid-move never orphans data).
fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> io::Result<()> {
    if !src.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// **Vault — мультиаккаунтное, мультипарольное хранилище.** Один пароль устройства (Argon2id ОДИН
/// раз) выводит `MasterKey`, защищающий один КОМПАРТМЕНТ (`base/c/<id>/`) со всеми его аккаунтами;
/// переключение аккаунтов внутри компартмента бесплатно (тот же ключ, другой подкаталог). Соль — на
/// уровне базы (`base/salt`, одна на устройство). Разные пароли открывают разные компартменты либо
/// запускают wipe — маршрутизация в `Vault::open` через `base/slots.dat`. Реестр аккаунтов
/// (`<compartment>/accounts.dat`) зашифрован. `Clone` дёшев (два PathBuf + 32-байтный ключ).
#[derive(Clone)]
pub struct Vault {
    /// Vault root: holds `salt`, `slots.dat`, and the `c/<id>/` compartments.
    base: PathBuf,
    /// This session's compartment directory (`base/c/<id>/`) — where accounts.dat + accounts/ live.
    dir: PathBuf,
    key: MasterKey,
}

impl Vault {
    /// At-rest label for one of the VAULT's own files (registry, dead-man record): `vault/<name
    /// relative to the compartment dir>`. Deliberately a different scope from any account's, so
    /// an account file can never be dropped in over a vault-level one and still open (CRYPTO-05).
    fn label(&self, path: &std::path::Path) -> String {
        let rel = path.strip_prefix(&self.dir).or_else(|_| path.strip_prefix(&self.base));
        let rel = rel.unwrap_or(path);
        let parts: Vec<String> =
            rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
        format!("vault/{}", parts.join("/"))
    }

    /// Открыть vault под паролем устройства. `salt`/`verify` на уровне базы.
    ///
    /// NO migration of a legacy single-account directory. That path was removed with format v2:
    /// at-rest keys are derived per (account, file), so relocating a file into an account
    /// directory changes its key by construction and a migration would have to re-seal
    /// everything. A bare pre-vault directory stays a standalone `Store` that still opens; a
    /// vault provisioned over it starts empty and leaves those files alone.
    /// COMPAT entry point — "open the compartment this password belongs to, or provision a fresh
    /// real one". A brand-new vault (nothing on disk) is created as the real compartment bound to
    /// this password; an existing vault is routed by [`Vault::open`] (real or decoy). A wipe
    /// password still wipes, then this reports an error (callers that aren't the login screen
    /// simply see a failed unlock). Keeps every pre-multipassword caller working unchanged.
    pub fn unlock(base: impl Into<PathBuf>, passphrase: &[u8]) -> io::Result<Self> {
        let base = base.into();
        if Self::is_fresh(&base) {
            return Self::create(&base, passphrase);
        }
        match Self::open(&base, passphrase)? {
            Opened::Real(v) | Opened::Decoy(v) => Ok(v),
            Opened::Wipe => Err(io_err("vault wiped")),
        }
    }

    /// True when no VAULT has been provisioned yet (no slot table, no compartment, no
    /// pre-multipassword registry) — the create-account path.
    ///
    /// A bare `seed.key` at the root used to count as "not fresh" so the legacy single-account
    /// MIGRATION could pick it up. That migration is gone: at-rest keys are now derived per
    /// (account, file), so moving a file into an account directory changes its key by design and
    /// a migration would have to re-seal everything — which pre-alpha, with no users, is not
    /// worth carrying. Such a directory is now simply a standalone store that `Store::unlock`
    /// still reads; a vault provisioned over it starts empty and leaves those files alone.
    fn is_fresh(base: &std::path::Path) -> bool {
        !slots_path(base).exists()
            && !base.join("accounts.dat").exists()
            && !base.join("accounts").exists()
    }

    /// Provision (or re-open) the REAL compartment for this password. Idempotent: if a real slot
    /// already exists for this key (re-run / restore into an existing vault), its compartment is
    /// reused; a pre-multipassword layout is migrated first. Otherwise a fresh compartment is
    /// created and a real slot written for it. Used by the create/restore-account flow.
    pub fn create(base: impl Into<PathBuf>, passphrase: &[u8]) -> io::Result<Self> {
        let base = base.into();
        std::fs::create_dir_all(&base)?;
        let salt = read_or_create_salt(&base)?;
        let key = MasterKey::derive(passphrase, &salt).map_err(io_err)?;
        // If this vault predates multipassword, migrate it first, then reuse the real compartment.
        let root = Vault { base: base.clone(), dir: base.clone(), key: key.clone() };
        if base.join("accounts.dat").exists() && root.load_registry().is_ok() {
            let id = Self::migrate_to_compartment(&base, &key)?;
            return Ok(Vault { base: base.clone(), dir: compartment_dir(&base, &id), key });
        }
        // Reuse an existing real compartment for this key, if any.
        if let Some((SlotRole::Real, id)) = slot_find(&base, &key)? {
            return Ok(Vault { base: base.clone(), dir: compartment_dir(&base, &id), key });
        }
        // Fresh real compartment.
        let id = random16();
        let dir = compartment_dir(&base, &id);
        std::fs::create_dir_all(&dir)?;
        slot_write(&base, &key, &key, SlotRole::Real, &id)?;
        Ok(Vault { base, dir, key })
    }

    /// Open an EXISTING vault, routing by which compartment (real/decoy) the password unlocks — or
    /// executing a wipe if it is the duress password. Runs the ONE surviving migration
    /// (pre-multipassword root → `c/<id>/`, which only MOVES a directory and so keeps every
    /// at-rest label intact) under the correct key. A password that opens nothing is a wrong
    /// password.
    pub fn open(base: impl Into<PathBuf>, passphrase: &[u8]) -> io::Result<Opened> {
        let base = base.into();
        std::fs::create_dir_all(&base)?;
        let salt = read_or_create_salt(&base)?;
        let key = MasterKey::derive(passphrase, &salt).map_err(io_err)?;

        // Legacy single-account (secrets directly at base root) → base/accounts/<ik>/ (unchanged).
        let root = Vault { base: base.clone(), dir: base.clone(), key: key.clone() };

        // Pre-multipassword multi-account layout: a registry sits at the base root. Only the REAL
        // password opens it (extras can't exist yet — adding one needs a logged-in real session).
        if base.join("accounts.dat").exists() {
            if root.load_registry().is_err() {
                return Err(io_err("wrong password or corrupt file"));
            }
            let id = Self::migrate_to_compartment(&base, &key)?;
            return Ok(Opened::Real(Vault { base: base.clone(), dir: compartment_dir(&base, &id), key }));
        }

        // Routed by the slot table.
        match slot_find(&base, &key)? {
            Some((SlotRole::Real, id)) => {
                Ok(Opened::Real(Vault { base: base.clone(), dir: compartment_dir(&base, &id), key }))
            }
            Some((SlotRole::Decoy, id)) => {
                Ok(Opened::Decoy(Vault { base: base.clone(), dir: compartment_dir(&base, &id), key }))
            }
            Some((SlotRole::Wipe, _)) => {
                crypto_erase(&base)?;
                Ok(Opened::Wipe)
            }
            None => Err(io_err("wrong password or corrupt file")),
        }
    }

    /// Relocate a pre-multipassword root layout (`base/accounts.dat` + `base/accounts/`) into a
    /// random-named compartment `base/c/<id>/` and record its real slot. COPY-then-commit-then-
    /// delete: the root originals are removed only AFTER the slot table (the commit point) is
    /// written and the copy verifies, so a crash at any point leaves the root intact and the
    /// migration simply re-runs (idempotent — a prior attempt's compartment id is reused).
    fn migrate_to_compartment(base: &std::path::Path, key: &MasterKey) -> io::Result<[u8; 16]> {
        let id = match slot_find(base, key)? {
            Some((SlotRole::Real, id)) => id, // resume an interrupted migration
            _ => random16(),
        };
        let cdir = compartment_dir(base, &id);
        std::fs::create_dir_all(&cdir)?;
        copy_dir_all(&base.join("accounts"), &cdir.join("accounts"))?;
        if base.join("accounts.dat").exists() {
            std::fs::copy(base.join("accounts.dat"), cdir.join("accounts.dat"))?;
        }
        // Verify the copy opens under the key before we commit or delete anything.
        let moved = Vault { base: base.to_path_buf(), dir: cdir.clone(), key: key.clone() };
        moved
            .load_registry()
            .map_err(|e| io_err(format!("compartment migration verify: {e}")))?;
        // Commit point: the real slot. After this the base has no root registry ⇒ migrated.
        slot_write(base, key, key, SlotRole::Real, &id)?;
        let _ = std::fs::remove_file(base.join("accounts.dat"));
        let _ = std::fs::remove_dir_all(base.join("accounts"));
        Ok(id)
    }

    // ── Extra-password management (decoy / wipe). REAL session only: the slot directory is sealed
    //    under the real key, so calling these from a decoy session fails to read it. ─────────────

    /// The EXTRA passwords configured on this device (decoy / wipe), for the Security card.
    pub fn extra_passwords(&self) -> io::Result<Vec<ExtraPassword>> {
        let dir = slotdir_load(&self.base, &self.key)?;
        Ok(dir
            .iter()
            .filter_map(|e| match SlotRole::from_byte(e.role) {
                Some(SlotRole::Decoy) => Some(ExtraPassword::Decoy),
                Some(SlotRole::Wipe) => Some(ExtraPassword::Wipe),
                _ => None, // the real entry
            })
            .collect())
    }

    /// Derive a candidate password's key against this device's salt, rejecting one already in use
    /// (the real password or an existing extra — `slot_find` catches both, since the real slot is
    /// present). Shared guard for adding a decoy/wipe password.
    fn prepare_extra_key(&self, pass: &[u8]) -> io::Result<MasterKey> {
        if pass.is_empty() {
            return Err(io_err("empty password"));
        }
        let salt = read_or_create_salt(&self.base)?;
        let key = MasterKey::derive(pass, &salt).map_err(io_err)?;
        if slot_find(&self.base, &key)?.is_some() {
            return Err(io_err("this password is already in use"));
        }
        Ok(key)
    }

    /// Add a DECOY password: it opens a separate, freshly-provisioned (empty) compartment under
    /// coercion, hiding the real one. Rejects a password already in use. Real session only.
    pub fn add_decoy(&self, decoy_pass: &[u8]) -> io::Result<()> {
        let dkey = self.prepare_extra_key(decoy_pass)?;
        let id = random16();
        let cdir = compartment_dir(&self.base, &id);
        std::fs::create_dir_all(&cdir)?;
        slot_write(&self.base, &self.key, &dkey, SlotRole::Decoy, &id)?;
        // Provision a fresh, empty account so the decoy looks like an ordinary (new) messenger.
        let decoy = Vault { base: self.base.clone(), dir: cdir, key: dkey };
        decoy.provision_fresh_account()?;
        Ok(())
    }

    /// Add a WIPE (duress) password: entering it at unlock crypto-erases everything instead of
    /// logging in. No compartment. Rejects a password already in use. Real session only.
    pub fn add_wipe(&self, wipe_pass: &[u8]) -> io::Result<()> {
        let wkey = self.prepare_extra_key(wipe_pass)?;
        slot_write(&self.base, &self.key, &wkey, SlotRole::Wipe, &[0u8; 16])
    }

    /// Remove an extra password (decoy or wipe); for a decoy its compartment is deleted too. No-op
    /// if the password isn't a configured extra. Refuses to remove the REAL password (that would
    /// orphan the account). Real session only.
    pub fn remove_extra(&self, pass: &[u8]) -> io::Result<()> {
        let salt = read_or_create_salt(&self.base)?;
        let key = MasterKey::derive(pass, &salt).map_err(io_err)?;
        let Some(slots) = slots_load(&self.base)? else { return Ok(()) };
        let Some(idx) = slot_index_of(&slots, &key) else { return Ok(()) };
        let dir = slotdir_load(&self.base, &self.key)?;
        let entry = dir.iter().find(|e| e.index == idx as u8);
        match entry.and_then(|e| SlotRole::from_byte(e.role)) {
            Some(SlotRole::Real) => return Err(io_err("cannot remove the real password")),
            Some(SlotRole::Decoy) => {
                if let Some(e) = entry {
                    let _ = std::fs::remove_dir_all(compartment_dir(&self.base, &e.compartment_id));
                }
            }
            _ => {}
        }
        slot_erase(&self.base, &self.key, &key)
    }

    /// Provision a brand-new random account into THIS compartment (used to make a decoy plausible).
    fn provision_fresh_account(&self) -> io::Result<()> {
        let entropy = crate::seed::entropy_of(&crate::seed::generate_mnemonic());
        let ik = crate::seed::derive(&entropy).account.identity_public();
        let id = hex::encode(ik);
        self.create_account_dir(&id)?;
        let store = self.account(&id);
        store.save_seed(&entropy)?;
        self.save_registry(&[AccountEntry { id, label: "Account 1".into(), ik }])?;
        // No admission credential is seeded: a capability now belongs to a specific relay
        // (CRYPTO-24) and this compartment has no relay configured yet, so writing one would mean
        // inventing a relay-id. The desktop seeds the dev credential per relay when one IS
        // configured, which is also what a real account looks like at this stage.
        Ok(())
    }

    // ── Dead-man switch ──────────────────────────────────────────────────────────────────────

    /// Fire the dead-man switch if overdue: if armed and `now` is at/past `last_seen + interval`,
    /// crypto-erase everything and report `true` (wiped). Call at LAUNCH, before any password.
    pub fn deadman_check(base: impl Into<PathBuf>, now: u64) -> io::Result<bool> {
        let base = base.into();
        let mut dm = deadman_load(&base);
        if !dm.armed() {
            return Ok(false);
        }

        // A wall clock alone must never authorise an irreversible wipe.
        //
        // FORWARD anomaly: if the clock has leapt further than any plausible gap between
        // launches, that is a broken RTC / restored snapshot / edited date — not proof the owner
        // vanished. Re-anchor the observation instead of destroying the vault; the countdown
        // continues from the corrected mark, so a genuinely absent owner still trips it later.
        if dm.last_check != 0 && now.saturating_sub(dm.last_check) > DEADMAN_MAX_PLAUSIBLE_JUMP_SECS
        {
            dm.last_check = now;
            let _ = deadman_save(&base, &dm);
            return Ok(false);
        }

        // BACKWARD movement: judge against the latest time we ever saw, so winding the clock back
        // cannot postpone the wipe forever.
        let effective_now = now.max(dm.last_check);
        let overdue = effective_now >= dm.last_seen.saturating_add(dm.interval_secs);

        if dm.last_check < now {
            dm.last_check = now;
            let _ = deadman_save(&base, &dm);
        }
        if overdue {
            crypto_erase(&base)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Arm (`interval_secs > 0`) or disarm (`0`) the dead-man switch, stamping `last_seen = now`.
    /// Real session only (the desktop hides this from a decoy session so a coerced login cannot
    /// disarm the wipe).
    ///
    /// Writes BOTH copies: the SEALED one (authoritative) and the plaintext hint the pre-password
    /// launch check reads. See [`Vault::deadman_reconcile`].
    pub fn set_deadman(&self, interval_secs: u64, now: u64) -> io::Result<()> {
        let dm = Deadman { interval_secs, last_seen: now, last_check: now };
        self.deadman_seal(&dm)?;
        deadman_save(&self.base, &dm)
    }

    /// Refresh `last_seen = now` if armed — call after a REAL unlock (never a decoy). No-op when
    /// disarmed. Updates the sealed copy first, then the hint.
    pub fn deadman_touch(&self, now: u64) -> io::Result<()> {
        let mut dm = self.deadman_sealed().unwrap_or_else(|| deadman_load(&self.base));
        if dm.armed() {
            dm.last_seen = now;
            dm.last_check = dm.last_check.max(now); // never let the observed mark go backwards
            self.deadman_seal(&dm)?;
            deadman_save(&self.base, &dm)?;
        }
        Ok(())
    }

    /// The AUTHORITATIVE dead-man state: sealed under the vault key, so it cannot be edited or
    /// forged by anyone who merely has the directory. `None` = absent or undecryptable.
    fn deadman_sealed(&self) -> Option<Deadman> {
        let blob = std::fs::read(self.base.join("deadman.sealed")).ok()?;
        let plain = self.key.open(&self.label(&self.base.join("deadman.sealed")), &blob).ok()?;
        postcard::from_bytes(&plain).ok()
    }

    fn deadman_seal(&self, dm: &Deadman) -> io::Result<()> {
        let blob = self.key.seal(&self.label(&self.base.join("deadman.sealed")), &postcard::to_stdvec(dm).map_err(io_err)?);
        write_fixed_0600(&self.base.join("deadman.sealed"), &blob)
    }

    /// Reconcile the plaintext hint against the SEALED truth — call right after a real unlock.
    ///
    /// `deadman.dat` has to be readable BEFORE any password exists, so it cannot be authenticated:
    /// editing or deleting it used to disarm the switch outright, and a corrupt file read as
    /// "disarmed" (A3-11 residual). Authentication alone could never fix that — an attacker with
    /// the directory can always delete a file. So the plaintext copy is demoted to a HINT that only
    /// makes the pre-password check possible, and the sealed copy decides:
    /// - sealed says armed and the deadline has passed → wipe NOW, whatever the hint claimed;
    /// - otherwise → rewrite the hint from the sealed state, undoing tampering or corruption.
    ///
    /// Honest boundary that remains: an adversary who simply never runs the app is not wiped by
    /// either copy — the switch fires on absence of the OWNER, and it cannot act while nothing runs.
    /// Returns `true` if the vault was wiped.
    pub fn deadman_reconcile(&self, now: u64) -> io::Result<bool> {
        let Some(mut sealed) = self.deadman_sealed() else {
            // No sealed copy yet (first run after upgrade): adopt whatever the hint says, so the
            // switch keeps working and is authoritative from here on.
            let hint = deadman_load(&self.base);
            if hint.armed() {
                self.deadman_seal(&hint)?;
            }
            return Ok(false);
        };
        if !sealed.armed() {
            deadman_save(&self.base, &sealed)?;
            return Ok(false);
        }
        let effective_now = now.max(sealed.last_check);
        let jumped = sealed.last_check != 0
            && now.saturating_sub(sealed.last_check) > DEADMAN_MAX_PLAUSIBLE_JUMP_SECS;
        if !jumped && effective_now >= sealed.last_seen.saturating_add(sealed.interval_secs) {
            crypto_erase(&self.base)?;
            return Ok(true);
        }
        sealed.last_check = sealed.last_check.max(now);
        self.deadman_seal(&sealed)?;
        deadman_save(&self.base, &sealed)?; // repair a tampered or corrupted hint
        Ok(false)
    }

    /// Current dead-man state, for the Security card. Prefers the sealed truth.
    pub fn deadman(&self) -> Deadman {
        self.deadman_sealed().unwrap_or_else(|| deadman_load(&self.base))
    }

    /// A handle to the SAME compartment but keyed from `pass` — for re-verifying the password inside
    /// an already-open session (e.g. before revealing the recovery phrase) WITHOUT routing to
    /// another compartment or triggering a wipe. A wrong password simply fails to decrypt later.
    pub fn rederive(&self, pass: &[u8]) -> io::Result<Vault> {
        let salt = read_or_create_salt(&self.base)?;
        let key = MasterKey::derive(pass, &salt).map_err(io_err)?;
        Ok(Vault { base: self.base.clone(), dir: self.dir.clone(), key })
    }

    fn accounts_dir(&self) -> PathBuf {
        self.dir.join("accounts")
    }

    fn registry_path(&self) -> PathBuf {
        self.dir.join("accounts.dat")
    }


    pub fn account_dir(&self, id: &str) -> PathBuf {
        self.accounts_dir().join(id)
    }

    /// Adopt an EXISTING account directory as a vault, with `key` as the account key — for the
    /// Tier-2 container path, where the deniable container (not `slots.dat`) provides the
    /// passwords and hands us a per-region key + a materialized work dir. No keyslot files are
    /// read or written here; the multi-account structure (`accounts.dat` + `accounts/<id>/`) is
    /// driven exactly as usual on top of `dir`.
    pub fn adopt(dir: impl Into<PathBuf>, key: MasterKey) -> Self {
        let dir = dir.into();
        Vault { base: dir.clone(), dir, key }
    }

    /// Store поверх аккаунта `id` (общий vault-ключ). Каталог должен существовать
    /// для записи (провижининг создаёт его через `create_account_dir`).
    pub fn account(&self, id: &str) -> Store {
        Store::scoped(self.account_dir(id), self.key.clone(), format!("acct:{id}"))
    }

    /// Создать каталог аккаунта `id` (перед первым `save_seed`).
    pub fn create_account_dir(&self, id: &str) -> io::Result<()> {
        std::fs::create_dir_all(self.account_dir(id))
    }

    /// Прочитать реестр аккаунтов (пусто, если файла нет). Расшифровывается
    /// vault-ключом.
    pub fn load_registry(&self) -> io::Result<Vec<AccountEntry>> {
        match std::fs::read(self.registry_path()) {
            Ok(blob) => {
                let bytes = self.key.open(&self.label(&self.registry_path()), &blob).map_err(io_err)?;
                postcard::from_bytes(&bytes).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// АТОМАРНО сохранить реестр (temp 0600 → fsync → rename), зашифрован. Temp — в том же
    /// каталоге компартмента, что и цель, чтобы rename был атомарным (одна ФС).
    pub fn save_registry(&self, entries: &[AccountEntry]) -> io::Result<()> {
        let plain = postcard::to_stdvec(entries).map_err(io_err)?;
        let bytes = self.key.seal(&self.label(&self.registry_path()), &plain);
        let tmp = self.dir.join("accounts.dat.tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, self.registry_path())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    /// SEC-40 / A6-6, the RECOVERY half. Parking an unappliable message before the ack stopped it
    /// being lost; it did not put it back. This pins the contract the desktop replay depends on:
    /// what was parked comes back intact, and clearing is a separate step — so a crash between
    /// reading and clearing replays rather than loses.
    ///
    /// Discriminating: it asserts the parked bytes and sender survive a reload (a write that
    /// dropped either would fail), and that clearing is what empties the log — not reading it.
    #[test]
    fn a_parked_message_survives_a_reload_and_is_only_gone_once_cleared() {
        let dir = std::env::temp_dir().join(format!("karst-replay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();

        s.quarantine_incoming([0x77; 32], b"an unapplied profile update", 500).unwrap();
        s.quarantine_incoming([0x88; 32], b"a publication nobody committed", 501).unwrap();

        // Reading must not consume: the handlers have not run yet.
        assert_eq!(s.load_quarantine().unwrap().len(), 2, "reading must not consume the log");

        let parked = s.load_quarantine().unwrap();
        assert_eq!(parked[0].sender, [0x77; 32]);
        assert_eq!(parked[0].plaintext, b"an unapplied profile update");
        assert_eq!(parked[0].received_at, 500);
        assert_eq!(parked[1].sender, [0x88; 32]);

        s.clear_quarantine().unwrap();
        assert!(s.load_quarantine().unwrap().is_empty(), "clearing is what empties it");
        s.clear_quarantine().expect("clearing an already-empty log is not an error");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-29, the ledger half. An "accept" writes the sender's profile into our contacts and
    /// marks them confirmed. Nothing recorded what WE had asked for, so a stranger's unsolicited
    /// accept did exactly what a real answer did — consent has two halves and only one was on
    /// disk.
    ///
    /// Discriminating on all three properties that matter: an unasked peer is refused, an asked
    /// one is admitted, and the request is CONSUMED so a single ask cannot validate a stream of
    /// replayed accepts. A test that only checked the refusal would pass with accepts broken
    /// outright.
    #[test]
    fn an_accept_is_only_honoured_from_a_peer_we_actually_asked() {
        let dir = std::env::temp_dir().join(format!("karst-consent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        let (asked, stranger) = ([0xA1; 32], [0xB2; 32]);

        s.note_outstanding_request(asked).unwrap();

        assert!(
            !s.take_outstanding_request(&stranger).unwrap(),
            "an accept from a peer we never asked must not be honoured — that is a stranger \
             writing themselves into the contact list"
        );
        assert!(s.take_outstanding_request(&asked).unwrap(), "the peer we DID ask must be honoured");
        assert!(
            !s.take_outstanding_request(&asked).unwrap(),
            "the request must be consumed: one ask authorises exactly one accept, or a replayed \
             accept keeps re-validating forever"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-42. Answering "which messages did I recently receive?" used to read and AEAD-open the
    /// WHOLE history log and slice its tail — for a caller that wants at most a thousand ids. It
    /// ran once per ack pass, on an empty mailbox too, and the desktop poll does that up to
    /// eighty times across its proxies: a remote sender could grow your history legitimately and
    /// thereby make every future poll cost O(history).
    ///
    /// Asserted STRUCTURALLY rather than by timing, which is both stronger and honest: the
    /// history file is deleted outright, and the query must still answer correctly. It cannot be
    /// reading what is not there. A timing test would only have shown "faster", would have needed
    /// a stopwatch that lies on a loaded machine, and would still have grown with the ring.
    #[test]
    fn recent_incoming_ids_does_not_read_the_history_log_at_all() {
        let dir = std::env::temp_dir().join(format!("karst-dedup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();

        let id = |n: u32| {
            let mut m = [0u8; 32];
            m[..4].copy_from_slice(&n.to_le_bytes());
            m
        };
        let rec = |n: u32| HistoryRecord {
            from_me: false,
            peer_ik: [3u8; 32],
            text: format!("msg {n}").into_bytes(),
            ts: n as u64,
        };

        // Ids start at 1: an all-zero id is the "outgoing / unstamped" sentinel the ring skips by
        // design, so n = 0 would produce exactly that and be (correctly) ignored.
        for n in 1..9 {
            s.append_history_incoming(&rec(n), id(n)).unwrap();
        }
        // An outgoing record must never appear: it carries no incoming id to dedup against.
        s.append_history(&HistoryRecord { from_me: true, ..rec(999) }).unwrap();

        assert_eq!(s.load_history().unwrap().len(), 9, "control: the log really holds the records");

        // The history log is now gone. Under the old implementation this query WAS the log scan,
        // so it could only return nothing.
        std::fs::remove_file(s.history_path()).unwrap();

        let ids = s.recent_incoming_ids(1024).unwrap();
        assert_eq!(
            ids.len(),
            8,
            "the dedup query still depends on the history log — that dependency is what made \
             every poll cost O(history); got {ids:?}"
        );
        assert!(ids.contains(&id(1)) && ids.contains(&id(8)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CRYPTO-01 residual, the DETECTION half. The per-message salt already made a ratchet
    /// rollback harmless — two encryptions under a replayed chain key no longer collide — but
    /// harmless is not unnoticed. Restoring `sessions.dat` from an older copy while the rest of
    /// the account stays current is what a backup restore, a file-level sync conflict or a
    /// targeted swap actually looks like, and it used to load in silence.
    ///
    /// Discriminating: it restores the OLD bytes over the current file and requires a loud error,
    /// AND requires that the same state loads fine when it is the newest one — so it cannot pass
    /// by refusing everything. Deleting the anchor comparison reds it.
    #[test]
    fn a_rolled_back_session_file_is_refused_not_loaded_in_silence() {
        use karst_client_core::peer::PeerState;
        let dir = std::env::temp_dir().join(format!("karst-anchor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();

        s.save_sessions(&PeerState::empty()).unwrap();
        let old_bytes = std::fs::read(s.sessions_path()).unwrap();
        assert!(s.load_sessions().is_ok(), "control: the state we just wrote loads");

        // Time passes; the account writes more state.
        for _ in 0..3 {
            s.save_sessions(&PeerState::empty()).unwrap();
        }
        assert!(s.load_sessions().is_ok(), "control: the newest state still loads");

        // The rollback: yesterday's sessions.dat, today's everything else.
        std::fs::write(s.sessions_path(), &old_bytes).unwrap();
        let err = match s.load_sessions() {
            Err(e) => e.to_string(),
            Ok(_) => panic!(
                "an older session file loaded without a word — the ratchet silently went backwards"
            ),
        };
        assert!(
            err.contains("rolled back"),
            "an older session file loaded without a word — the ratchet silently went backwards; \
             got: {err}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CRYPTO-05, THE carrying test. Two accounts in ONE vault share the device key, so before
    /// per-context derivation an attacker with disk write access could drop account A's
    /// `contacts.dat` into account B's directory and B would open it as its own — with no
    /// tampering detectable, because the ciphertext was bound to nothing but the key.
    ///
    /// Discriminating: it asserts the SPLICED file fails while B's own file still opens, so it
    /// cannot pass by breaking decryption in general. Neuter `Store::label` to return a constant
    /// and it goes red.
    #[test]
    fn one_accounts_sealed_file_does_not_open_in_another_account() {
        let dir = std::env::temp_dir().join(format!("karst-splice-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let vault = Vault::create(&dir, b"pw").unwrap();
        vault.create_account_dir("aaa").unwrap();
        vault.create_account_dir("bbb").unwrap();
        let (a, b) = (vault.account("aaa"), vault.account("bbb"));

        a.save_contacts(&[ContactRecord { name: "Alice's contact".into(), ik: [1u8; 32], verified: true }])
            .unwrap();
        b.save_contacts(&[ContactRecord { name: "Bob's contact".into(), ik: [2u8; 32], verified: false }])
            .unwrap();

        // The attack: A's sealed bytes, byte for byte, dropped into B's slot.
        std::fs::copy(a.contacts_path(), b.contacts_path()).unwrap();

        assert!(
            b.load_contacts().is_err(),
            "account B opened account A's sealed file — at-rest ciphertext must be bound to the \
             account it belongs to, not merely to the shared device key"
        );
        // ...and the binding is not just "everything fails now": A still reads its own file.
        assert_eq!(a.load_contacts().unwrap()[0].name, "Alice's contact");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same binding one level down: within ONE account, a sealed file must not open under a
    /// different NAME. Otherwise an attacker can swap one sidecar in for another and the client
    /// acts on the wrong list.
    ///
    /// `blocked.dat` and `unconfirmed.dat` are chosen deliberately: both hold `BTreeSet<[u8;32]>`,
    /// so a spliced file decodes PERFECTLY once decrypted. A pair with different schemas would
    /// have made this test pass on the postcard error alone — green for the wrong reason, and
    /// still green with the binding removed.
    #[test]
    fn a_sealed_file_does_not_open_under_a_different_name() {
        let dir = std::env::temp_dir().join(format!("karst-swap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        s.set_blocked([7u8; 32], true).unwrap();
        s.set_unconfirmed([8u8; 32], true).unwrap();

        // The attack: the block list, byte for byte, presented as the unconfirmed list.
        std::fs::copy(s.blocked_path(), s.unconfirmed_path()).unwrap();

        let err = s.load_unconfirmed().unwrap_err().to_string();
        assert!(
            err.contains("another location") || err.contains("corrupt"),
            "a sealed blob opened under another file's name — the label must be part of the \
             derivation, not decoration; got: {err}"
        );
        assert!(s.load_blocked().unwrap().contains(&[7u8; 32]), "its own file still opens");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A6-5. A file written by a build with a HIGHER `STATE_VERSION` must be refused, loudly and
    /// distinguishably — not read with defaults for the fields this build does not know and then
    /// written back with those fields dropped. Forges the version byte in place (the AAD covers
    /// it, so this is also a tamper test).
    #[test]
    fn a_state_file_from_a_newer_format_version_is_refused_out_loud() {
        let key = MasterKey::derive(b"pw", b"0123456789abcdef").unwrap();
        let mut blob = key.seal("acct:x/prefs.dat", b"state");
        let bumped = crate::secretbox::STATE_VERSION + 1;
        blob[4..6].copy_from_slice(&bumped.to_le_bytes());

        let err = key.open("acct:x/prefs.dat", &blob).unwrap_err();
        assert!(
            err.contains("newer") && err.contains("upgrade"),
            "a newer state format must say so and tell the user to upgrade, not look like a \
             wrong password or load with defaults; got: {err}"
        );
    }

    /// The label is LOGICAL, not the path on disk: moving the whole vault directory (a bigger
    /// drive, a restored backup) must not turn every file into "wrong password". Guards the
    /// obvious wrong implementation of the fix above.
    #[test]
    fn moving_the_vault_directory_does_not_break_decryption() {
        let dir = std::env::temp_dir().join(format!("karst-move-a-{}", std::process::id()));
        let moved = std::env::temp_dir().join(format!("karst-move-b-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&moved);
        {
            let vault = Vault::create(&dir, b"pw").unwrap();
            vault.create_account_dir("aaa").unwrap();
            vault
                .account("aaa")
                .save_contacts(&[ContactRecord { name: "Carol".into(), ik: [3u8; 32], verified: false }])
                .unwrap();
        }
        std::fs::rename(&dir, &moved).unwrap();

        let vault = Vault::unlock(&moved, b"pw").unwrap();
        assert_eq!(vault.account("aaa").load_contacts().unwrap()[0].name, "Carol");
        let _ = std::fs::remove_dir_all(&moved);
    }

    /// A text-only profile update must NOT wipe an already-received avatar (the
    /// avatar arrives on a separate control message; Phase 2 relies on this). Seeds a
    /// sealed peer profile WITH an avatar via the crate-internal key — which the
    /// integration test crate cannot do — then text-updates and asserts the avatar
    /// bytes survived. Neuter `set_peer_profile` to `map.insert(ik, Profile { name,
    /// bio, avatar: None })` and this goes red.
    #[test]
    fn set_peer_profile_text_update_preserves_avatar() {
        let dir = std::env::temp_dir().join(format!("karst-store-avatar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        let ik = [9u8; 32];

        // Seed a peer profile that already carries an avatar (sealed, on disk).
        let mut map: BTreeMap<[u8; 32], Profile> = BTreeMap::new();
        map.insert(
            ik,
            Profile { name: "old".into(), bio: "old bio".into(), avatar: Some(vec![1, 2, 3, 4]), photos: vec![], photos_ts: 0 },
        );
        let plain = postcard::to_stdvec(&map).unwrap();
        s.write_sealed(&s.peer_profiles_path(), &plain).unwrap();

        // Text-only update.
        s.set_peer_profile(ik, "new", "new bio").unwrap();

        let got = s.load_peer_profiles().unwrap();
        let p = got.get(&ik).unwrap();
        assert_eq!(p.name, "new", "name updated");
        assert_eq!(p.bio, "new bio", "bio updated");
        assert_eq!(p.avatar, Some(vec![1, 2, 3, 4]), "text update preserved the avatar");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The gallery stale-guard: a RECEIVED gallery with an older sender-clock `ts` must not clobber a
    /// newer one already applied (the same gallery can arrive twice out of order across the inline and
    /// blob paths). Newer or equal `ts` applies; strictly-older is ignored.
    #[test]
    fn set_peer_photos_ignores_a_stale_ts() {
        let dir = std::env::temp_dir().join(format!("karst-store-galts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        let ik = [5u8; 32];
        // Newer gallery applied first (ts=100).
        s.set_peer_photos(ik, vec![vec![1, 2, 3]], 100).unwrap();
        // An OLDER copy arrives after (ts=50) — must be ignored.
        s.set_peer_photos(ik, vec![vec![9, 9]], 50).unwrap();
        let p = s.load_peer_profiles().unwrap().get(&ik).cloned().unwrap();
        assert_eq!(p.photos, vec![vec![1u8, 2, 3]], "the stale (older-ts) gallery did not clobber the newer one");
        assert_eq!(p.photos_ts, 100);
        // A newer edit (ts=150) DOES apply.
        s.set_peer_photos(ik, vec![vec![7]], 150).unwrap();
        let p = s.load_peer_profiles().unwrap().get(&ik).cloned().unwrap();
        assert_eq!(p.photos, vec![vec![7u8]], "a newer gallery applies");
        assert_eq!(p.photos_ts, 150);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Conversation-vs-contact: the `unconfirmed` sidecar gates `is_confirmed_contact`, and — the
    /// load-bearing MIGRATION invariant — a vault with contacts but NO sidecar (every pre-change
    /// vault) reports every existing contact as CONFIRMED. If a future refactor made the absence of
    /// the sidecar default to "unconfirmed", every user's contacts would silently lose their
    /// names/avatars/posts at once; this test is the guard.
    #[test]
    fn unconfirmed_sidecar_gates_contacts_and_migration_is_safe() {
        let dir = std::env::temp_dir().join(format!("karst-store-unconf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        let (a, b, c) = ([1u8; 32], [2u8; 32], [9u8; 32]);

        // MIGRATION: a contact with no sidecar on disk is a CONFIRMED contact.
        s.save_contacts(&[
            ContactRecord { name: String::new(), ik: a, verified: false },
            ContactRecord { name: String::new(), ik: b, verified: false },
        ])
        .unwrap();
        assert!(!s.unconfirmed_path().exists(), "no sidecar exists for a legacy vault");
        assert!(s.is_confirmed_contact(&a).unwrap(), "existing contact stays confirmed (no sidecar)");
        assert!(s.is_confirmed_contact(&b).unwrap());

        // Flag b chat-only → not a confirmed contact; a is unaffected.
        s.set_unconfirmed(b, true).unwrap();
        assert!(s.is_confirmed_contact(&a).unwrap());
        assert!(!s.is_confirmed_contact(&b).unwrap(), "flagged peer is conversation-only");

        // Promote b → confirmed again; the (now-empty) sidecar file is removed.
        s.set_unconfirmed(b, false).unwrap();
        assert!(s.is_confirmed_contact(&b).unwrap());
        assert!(!s.unconfirmed_path().exists(), "empty sidecar is deleted");

        // A peer not in contacts at all is never a confirmed contact.
        assert!(!s.is_confirmed_contact(&c).unwrap());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A channel migration re-points a contact to a fresh IK; the SAME person's cached
    /// avatar/name (keyed by IK in peer_profiles.dat) must ride across to the new key,
    /// else the UI drops their avatar to a letter-fallback until they re-send it. Deleting
    /// the peer-profile carry-over block in `migrate_contact_ik` turns this red.
    #[test]
    fn migrate_contact_ik_carries_peer_avatar_and_profile() {
        let dir = std::env::temp_dir().join(format!("karst-store-migprof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        let old = [7u8; 32];
        let new = [8u8; 32];

        s.save_contacts(&[ContactRecord { name: "AliceDemo".into(), ik: old, verified: true }])
            .unwrap();
        s.set_peer_avatar(old, vec![9, 8, 7, 6]).unwrap();
        s.set_peer_profile(old, "AliceDemo", "Privacy first.").unwrap();

        assert!(s.migrate_contact_ik(old, new).unwrap(), "a contact was migrated");

        // Contact record re-pointed and un-verified (new safety number).
        let cs = s.load_contacts().unwrap();
        assert!(cs.iter().all(|c| c.ik != old), "old IK is gone");
        let c = cs.iter().find(|c| c.ik == new).expect("contact now at new IK");
        assert!(!c.verified, "migration resets verification");

        // Profile + avatar followed the person to the new IK; nothing orphaned at old.
        let profiles = s.load_peer_profiles().unwrap();
        assert!(!profiles.contains_key(&old), "no orphaned profile at old IK");
        let p = profiles.get(&new).expect("profile carried to new IK");
        assert_eq!(p.avatar, Some(vec![9, 8, 7, 6]), "avatar rode across the migration");
        assert_eq!(p.name, "AliceDemo", "cached name rode across the migration");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-36: an authenticated contact must not be able to hijack a DIFFERENT contact by
    /// naming their identity key as the migration target. Two contacts, Alice (`old`→migrating)
    /// and Bob (already sitting at `victim`) — migrating Alice onto Bob's key must be refused
    /// LOUDLY, and refused BEFORE anything is touched: Alice's own record must stay exactly as
    /// it was, and Bob's cached proxy tag + profile must be untouched, not silently overwritten
    /// by Alice's. A legitimate migration onto a key nobody holds yet must still succeed (the
    /// control case) — this is not "migrations are broken", only "collisions are refused".
    #[test]
    fn migrate_contact_ik_refuses_to_collide_with_a_different_contacts_identity_key() {
        let dir = std::env::temp_dir().join(format!("karst-store-migcollide-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        let old = [7u8; 32]; // Alice, migrating
        let victim = [9u8; 32]; // Bob, already at this key
        let free = [11u8; 32]; // nobody's key — legitimate target

        s.save_contacts(&[
            ContactRecord { name: "AliceDemo".into(), ik: old, verified: false },
            ContactRecord { name: "BobDemo".into(), ik: victim, verified: false },
        ])
        .unwrap();
        s.set_peer_avatar(old, vec![1, 2, 3]).unwrap();
        s.set_peer_profile(old, "AliceDemo", "alice bio").unwrap();
        s.set_contact_proxy(old, 0).unwrap();
        s.set_peer_avatar(victim, vec![9, 9, 9]).unwrap();
        s.set_peer_profile(victim, "BobDemo", "bob bio").unwrap();
        s.set_contact_proxy(victim, 1).unwrap();
        // Verify BOTH only now, after tagging (CRYPTO-28: `set_contact_proxy` itself resets
        // `verified` on a tag change, so setting it before tagging would not survive to this
        // point — verifying afterwards is also what a real user's OOB check looks like: the
        // proxy tag is already pinned by then).
        let mut cs = s.load_contacts().unwrap();
        for c in cs.iter_mut() {
            c.verified = true;
        }
        s.save_contacts(&cs).unwrap();

        // Attempt: migrate Alice (`old`) onto Bob's already-occupied key (`victim`).
        let err = s
            .migrate_contact_ik(old, victim)
            .expect_err("migrating onto another contact's identity key must be refused, not silently applied");
        assert!(
            err.to_string().contains("already belongs to a different contact"),
            "refusal must name what collided: {err}"
        );

        // Nothing moved: Alice is still at `old`, unverified-flag untouched, still two contacts.
        let cs = s.load_contacts().unwrap();
        assert_eq!(cs.len(), 2, "no rows were created or merged by the refused migration");
        assert!(cs.iter().any(|c| c.ik == old && c.verified), "Alice's record is untouched by the refused migration");
        assert!(cs.iter().any(|c| c.ik == victim && c.verified), "Bob's record is untouched by the refused migration");

        // Bob's cached profile/avatar/proxy tag were never touched by Alice's attempted migration.
        let profiles = s.load_peer_profiles().unwrap();
        assert_eq!(profiles.get(&victim).unwrap().name, "BobDemo", "Bob's profile survives the refused migration");
        assert_eq!(profiles.get(&victim).unwrap().avatar, Some(vec![9, 9, 9]), "Bob's avatar survives the refused migration");
        assert_eq!(s.contact_proxy(&victim), Some(1), "Bob's proxy tag survives the refused migration");
        assert_eq!(s.contact_proxy(&old), Some(0), "Alice's own proxy tag is untouched by the refused migration");

        // Control: a migration onto a FREE identity key (nobody holds it) still works.
        assert!(s.migrate_contact_ik(old, free).unwrap(), "a legitimate migration onto a free key must still succeed");
        let cs = s.load_contacts().unwrap();
        assert!(cs.iter().any(|c| c.ik == free && !c.verified), "legitimate migration re-points the contact and resets verification");
        assert!(cs.iter().all(|c| c.ik != old), "old key is gone after a legitimate migration");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The feed dedups a redelivered post (same author+id), sorts by ts, and survives a
    /// reload sealed on disk. Neuter the dedup (drop the `any(...)` guard) and the count reddens.
    #[test]
    fn feed_appends_dedups_and_sorts() {
        let dir = std::env::temp_dir().join(format!("karst-store-feed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        let a = [1u8; 32];
        let mk = |id: u8, ts: u64| FeedRecord { author: a, id: [id; 16], text: format!("post {id}"), ts, expire_at: None };

        s.append_feed(&mk(2, 200)).unwrap();
        s.append_feed(&mk(1, 100)).unwrap();
        s.append_feed(&mk(2, 200)).unwrap(); // redelivered duplicate → ignored

        // Reload from disk (sealed round-trip), assert dedup + ts order.
        let s2 = Store::unlock(&dir, b"pw").unwrap();
        let feed = s2.load_feed().unwrap();
        assert_eq!(feed.len(), 2, "duplicate (author+id) was not stored twice");
        assert_eq!(feed[0].id, [1u8; 16], "sorted oldest-first by ts");
        assert_eq!(feed[1].id, [2u8; 16]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Channel state round-trips sealed, subscribers dedup, and — the load-bearing security
    /// property — the channel flag is written ONLY by `save_channel`: adding subscribers (what the
    /// receive path does) never turns the account into a channel. Neuter that separation (have
    /// `add_subscriber` flip `enabled`) and the final assert reddens.
    #[test]
    fn channel_flag_is_independent_of_subscriber_writes() {
        let dir = std::env::temp_dir().join(format!("karst-store-chan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();

        assert!(!s.load_channel().enabled, "default is a private account (channel off)");
        // A flood of subscribe requests (what a received JoinRequest triggers) must NOT enable it.
        assert!(s.add_subscriber([1u8; 32], 10).unwrap(), "new subscriber added");
        assert!(!s.add_subscriber([1u8; 32], 11).unwrap(), "duplicate subscriber ignored");
        s.add_subscriber([2u8; 32], 12).unwrap();
        assert!(!s.load_channel().enabled, "adding subscribers never flips channel mode");
        assert_eq!(s.load_subscribers().len(), 2, "two distinct subscribers");

        // Only an explicit save flips it; it round-trips sealed on reload.
        s.save_channel(&ChannelConfig { enabled: true }).unwrap();
        let s2 = Store::unlock(&dir, b"pw").unwrap();
        assert!(s2.load_channel().enabled, "explicit save_channel persisted");
        assert_eq!(s2.load_subscribers().len(), 2, "subscribers persisted independently");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A single author flooding the feed evicts only THEIR OWN oldest posts, never another
    /// author's. Neuter the per-author retain and the "victim survives" assert reddens.
    #[test]
    fn feed_per_author_cap_protects_other_authors() {
        let dir = std::env::temp_dir().join(format!("karst-store-feedcap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        let flooder = [1u8; 32];
        let victim = [2u8; 32];

        // The victim posts once (oldest); then the flooder posts past its per-author quota.
        s.append_feed(&FeedRecord { author: victim, id: [9u8; 16], text: "keep me".into(), ts: 1, expire_at: None }).unwrap();
        for i in 0..(MAX_FEED_POSTS_PER_AUTHOR + 5) {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            s.append_feed(&FeedRecord { author: flooder, id, text: "spam".into(), ts: 100 + i as u64, expire_at: None }).unwrap();
        }

        let feed = s.load_feed().unwrap();
        assert!(feed.iter().any(|f| f.author == victim && f.id == [9u8; 16]), "the flood did not evict the victim");
        assert_eq!(
            feed.iter().filter(|f| f.author == flooder).count(),
            MAX_FEED_POSTS_PER_AUTHOR,
            "the flooder is capped to its own per-author quota"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A post image lives in the sidecar keyed by (author, post_id): it round-trips sealed, is
    /// dropped when its post is deleted (no orphan), and an over-cap image is refused.
    #[test]
    fn feed_image_sidecar_stores_reunites_and_prunes() {
        let dir = std::env::temp_dir().join(format!("karst-store-feedimg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        let author = [4u8; 32];
        let id = [5u8; 16];
        s.append_feed(&FeedRecord { author, id, text: "with photo".into(), ts: 1, expire_at: None }).unwrap();
        let img = vec![9u8; 4096];
        s.set_feed_image(author, id, img.clone()).unwrap();

        // Reloads sealed and reunites with the post.
        let s2 = Store::unlock(&dir, b"pw").unwrap();
        assert_eq!(s2.feed_image(author, id), Some(img), "image round-trips keyed by (author, id)");

        // An over-cap image is ignored (the wire manifest already gates this; belt-and-braces).
        s2.set_feed_image(author, [6u8; 16], vec![0u8; crate::content::MAX_POST_IMAGE_BYTES + 1]).unwrap();
        assert_eq!(s2.feed_image(author, [6u8; 16]), None, "over-cap image refused");

        // Deleting the post takes its image with it.
        s2.delete_feed_post(author, id).unwrap();
        assert_eq!(Store::unlock(&dir, b"pw").unwrap().feed_image(author, id), None, "image pruned with its post");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The proxy registry mints sequential indices with a fresh random secret each, derives each
    /// proxy's identity from ITS OWN secret (differing per proxy), and tags a contact with its
    /// proxy via a sidecar — all round-tripping sealed on disk. Burning removes the entry (and its
    /// tag) rather than flipping a flag — see `burning_a_proxy_deletes_its_secret_so_the_phrase_can_never_reproduce_it`
    /// for the discriminating check that this is real deletion, not a label.
    #[test]
    fn proxy_registry_mints_indices_sequentially_and_derives_from_its_own_secret() {
        let dir = std::env::temp_dir().join(format!("karst-store-proxy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        s.save_seed(&[3u8; crate::seed::ENTROPY_BYTES]).unwrap(); // the root's own seed; proxies do NOT use it

        assert!(s.load_proxies().is_empty(), "no proxies initially");
        let p0 = s.create_proxy("work", 10).unwrap();
        let p1 = s.create_proxy("family", 11).unwrap();
        assert_eq!((p0.index, p1.index), (0, 1), "sequential indices");
        assert_ne!(p0.secret, p1.secret, "each proxy mints its own random secret");
        assert_ne!(p0.secret, [0u8; 32], "the secret is not left zeroed");

        // Derived identity matches derivation from the entry's OWN secret, and differs per proxy.
        assert_eq!(
            s.proxy_identity(0).unwrap().account.identity_public(),
            crate::seed::derive_proxy_from_secret(&p0.secret).account.identity_public()
        );
        assert_ne!(
            s.proxy_identity(0).unwrap().account.identity_public(),
            s.proxy_identity(1).unwrap().account.identity_public()
        );

        // Burn p0, tag a contact to p1 — reload from disk and check both persisted.
        s.burn_proxy(0).unwrap();
        s.set_contact_proxy([9u8; 32], 1).unwrap();
        let s2 = Store::unlock(&dir, b"pw").unwrap(); // reopen from disk
        let list = s2.load_proxies();
        assert_eq!(list, vec![p1.clone()], "p0 gone entirely, p1 untouched");
        assert_eq!(s2.contact_proxy(&[9u8; 32]), Some(1), "contact tagged to its proxy");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Burning the highest-numbered proxy must NOT free its index for reuse: since burning now
    /// deletes the entry outright (rather than flagging it inactive), a naive `max(existing) + 1`
    /// would hand the next mint the exact index whose namespaced session/OPK files and contact
    /// tags used to belong to the just-destroyed identity — silently reanimating its leftover
    /// state under a "new" proxy. Discriminating: swap `create_proxy`'s index allocation back to
    /// `list.iter().map(|p| p.index).max().map(|m| m + 1).unwrap_or(0)` (the old formula) and this
    /// goes red, because burning p1 then minting again reissues index 1.
    #[test]
    fn burning_the_newest_proxy_does_not_free_its_index_for_reuse() {
        let dir = std::env::temp_dir().join(format!("karst-store-noreuse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();

        let p0 = s.create_proxy("p0", 1).unwrap();
        let p1 = s.create_proxy("p1", 2).unwrap();
        assert_eq!((p0.index, p1.index), (0, 1));

        s.burn_proxy(1).unwrap(); // burn the newest (highest index)
        let p2 = s.create_proxy("p2", 3).unwrap();
        assert_eq!(p2.index, 2, "the burned index 1 must never be reissued");

        s.burn_proxy(0).unwrap();
        s.burn_proxy(2).unwrap();
        let p3 = s.create_proxy("p3", 4).unwrap();
        assert_eq!(p3.index, 3, "monotonic even once the registry is entirely burned empty");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE fix for #207 (A6-4): burning a proxy must destroy its identity, not just relabel it.
    /// Before, burning only flipped `active`; the keys stayed forever re-derivable from the
    /// recovery phrase (`seed::derive_proxy(entropy, index)`), so a "destroyed" proxy was really
    /// still live to anyone holding the phrase. Now each proxy's keys come from a random secret
    /// that lives ONLY in the registry, and burning deletes that secret — so after a burn, NOTHING
    /// (not `as_proxy(index).load_account()`, not a fresh `Store::unlock` from disk, not minting a
    /// replacement) reproduces the old identity, even though the very same phrase is still in use.
    ///
    /// Discriminating: give `load_account`'s proxy arm a fallback like
    /// `.or_else(|_| Ok(crate::seed::derive(&self.load_entropy()?).account))` (the exact silent
    /// fallback the fix must not have) and the "burned proxy is now an error" assertions below go
    /// red — the fallback happily reconstructs SOME identity instead of failing.
    #[test]
    fn burning_a_proxy_deletes_its_secret_so_the_phrase_can_never_reproduce_it() {
        let dir = std::env::temp_dir().join(format!("karst-store-burn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        s.save_seed(&[42u8; crate::seed::ENTROPY_BYTES]).unwrap();

        // Control: a LIVE proxy derives the same identity across independent reloads from disk.
        let entry = s.create_proxy("keeper", 1).unwrap();
        let ik_before = s.as_proxy(entry.index).load_account().unwrap().identity_public();
        let reopened = Store::unlock(&dir, b"pw").unwrap();
        let ik_reloaded = reopened.as_proxy(entry.index).load_account().unwrap().identity_public();
        assert_eq!(ik_before, ik_reloaded, "control: a live proxy is stable across reloads");

        // Burn a SECOND proxy and record its identity before burning.
        let burned = s.create_proxy("burned", 2).unwrap();
        let burned_ik = s.as_proxy(burned.index).load_account().unwrap().identity_public();
        s.burn_proxy(burned.index).unwrap();

        // Post-burn: this store, in-process, can no longer produce that identity.
        assert!(
            s.as_proxy(burned.index).load_account().is_err(),
            "a burned proxy must fail loudly, not silently hand back some identity"
        );
        assert!(s.as_proxy(burned.index).load_identity().is_err(), "same for the seal half");

        // Post-burn, reopened from disk (rules out any in-memory-only state): still gone, even
        // though the very same phrase (`load_entropy`) is still on disk and readable.
        let s2 = Store::unlock(&dir, b"pw").unwrap();
        assert!(
            s2.as_proxy(burned.index).load_account().is_err(),
            "not recoverable after a fresh unlock from the SAME phrase either"
        );
        assert!(s2.load_entropy().is_ok(), "sanity: the phrase itself is still intact and readable");

        // A brand-new proxy minted after the burn gets a FRESH, unrelated identity — the phrase +
        // registry cannot reproduce the burned one under a new index either.
        let replacement = s2.create_proxy("replacement", 3).unwrap();
        let replacement_ik = s2.as_proxy(replacement.index).load_account().unwrap().identity_public();
        assert_ne!(
            replacement_ik, burned_ik,
            "a fresh proxy must never coincide with the identity that was destroyed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-44: `add_unconfirmed_contact` is what the RECEIVE path calls for every first-contact
    /// message (a remote sender drives it, not the user), so it must not grow `contacts.dat` /
    /// `unconfirmed.dat` without bound. Built via a SINGLE bulk write of an already-at-cap
    /// `contacts.dat` (not `MAX_CONTACTS` individual calls) so the test exercises the cap
    /// boundary itself, not an O(n) fsync loop. Discriminating: drop the `cs.len() >= MAX_CONTACTS`
    /// check and the newcomer gets added, reddening both size assertions below.
    #[test]
    fn add_unconfirmed_contact_refuses_a_new_sender_ik_once_contacts_are_at_cap() {
        let dir = std::env::temp_dir().join(format!("karst-store-contactcap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();

        let full: Vec<ContactRecord> = (0..MAX_CONTACTS)
            .map(|i| {
                let mut ik = [0u8; 32];
                ik[..8].copy_from_slice(&(i as u64).to_le_bytes());
                ContactRecord { name: String::new(), ik, verified: false }
            })
            .collect();
        s.save_contacts(&full).unwrap();

        let newcomer = [0xAAu8; 32];
        assert!(
            !s.add_unconfirmed_contact(newcomer).unwrap(),
            "a brand-new sender ik must be refused once contacts.dat is at the cap"
        );
        assert_eq!(
            s.load_contacts().unwrap().len(),
            MAX_CONTACTS,
            "contacts.dat must not grow past the cap"
        );
        assert!(
            !s.load_unconfirmed().unwrap().contains(&newcomer),
            "a refused ik must not be flagged unconfirmed either"
        );

        // Control: an ALREADY-KNOWN ik is a no-op regardless of the cap — this is not a "new
        // sender flood" case, so the cap must never get in the way of it.
        let known = full[0].ik;
        assert!(
            !s.add_unconfirmed_contact(known).unwrap(),
            "an already-known ik returns false (no-op), same as before any cap existed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-44: `add_confirmed_contact` is the OTHER remote-reachable auto-registration path — a
    /// `ContactAccept` is processed automatically on receipt, with no per-message human click, so
    /// it must share `MAX_CONTACTS` with `add_unconfirmed_contact` rather than offering an
    /// attacker a second, uncapped door into `contacts.dat`.
    #[test]
    fn add_confirmed_contact_refuses_a_new_sender_ik_once_contacts_are_at_cap() {
        let dir = std::env::temp_dir().join(format!("karst-store-confirmedcap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();

        let full: Vec<ContactRecord> = (0..MAX_CONTACTS)
            .map(|i| {
                let mut ik = [0u8; 32];
                ik[..8].copy_from_slice(&(i as u64).to_le_bytes());
                ContactRecord { name: String::new(), ik, verified: false }
            })
            .collect();
        s.save_contacts(&full).unwrap();

        let newcomer = [0xCCu8; 32];
        assert!(
            !s.add_confirmed_contact(newcomer).unwrap(),
            "a brand-new sender ik must be refused once contacts.dat is at the cap, even via the \
             confirmed-contact path"
        );
        assert_eq!(
            s.load_contacts().unwrap().len(),
            MAX_CONTACTS,
            "contacts.dat must not grow past the cap via ContactAccept either"
        );

        // Control: an already-known ik is still promoted to confirmed (a no-op on contacts.dat,
        // but set_unconfirmed(false) must still run) — the cap must never block a legitimate
        // promotion of an existing contact.
        let known = full[0].ik;
        let _ = s.set_unconfirmed(known, true); // start it flagged chat-only
        assert!(
            !s.add_confirmed_contact(known).unwrap(),
            "an already-known ik returns false (no new record), same as before any cap existed"
        );
        assert!(
            !s.load_unconfirmed().unwrap().contains(&known),
            "an already-known ik must still be promoted to confirmed despite the cap"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-44: `set_contact_proxy` runs on EVERY inbound message (before the `Content` is even
    /// decoded), so its cap matters even more than `contacts.dat`'s. Same bulk-write construction
    /// as above to hit the cap boundary without an O(n) fsync loop.
    #[test]
    fn set_contact_proxy_refuses_a_new_sender_ik_once_the_map_is_at_cap() {
        let dir = std::env::temp_dir().join(format!("karst-store-proxycap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();

        let full: BTreeMap<[u8; 32], u32> = (0..MAX_CONTACTS)
            .map(|i| {
                let mut ik = [0u8; 32];
                ik[..8].copy_from_slice(&(i as u64).to_le_bytes());
                (ik, 0u32)
            })
            .collect();
        let plain = postcard::to_stdvec(&full).unwrap();
        s.write_sealed(&s.contact_proxy_path(), &plain).unwrap();

        let newcomer = [0xBBu8; 32];
        s.set_contact_proxy(newcomer, 3).unwrap();
        assert_eq!(
            s.contact_proxy(&newcomer),
            None,
            "a brand-new sender ik must not be tagged once contact_proxy.dat is at the cap"
        );

        // Control: an already-tagged ik can still be RE-tagged (moved to a different proxy) — the
        // cap only refuses a genuinely NEW key, never an update to one already present.
        let known = *full.keys().next().unwrap();
        s.set_contact_proxy(known, 7).unwrap();
        assert_eq!(
            s.contact_proxy(&known),
            Some(7),
            "re-tagging an already-known ik must still work at the cap"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CRYPTO-27: `burn_proxy` must refuse when its outbox check itself fails (a corrupt or
    /// unauthenticated `sessions.dat`), not treat the read failure as "outbox empty" — that
    /// `unwrap_or(0)` shape is exactly the bug 1dd5de7 fixed for the proxy registry, and doing it
    /// here for the outbox would reopen it: a tampered or torn `sessions.dat` could hide a still-
    /// undelivered migration exactly as effectively as a genuinely empty one would. Neuter the `?`
    /// on `load_sessions()` back into an `unwrap_or(0)` and this reddens.
    #[test]
    fn burn_proxy_refuses_when_its_own_outbox_cannot_be_authenticated() {
        let dir = std::env::temp_dir().join(format!("karst-store-burn-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();

        let e0 = s.create_proxy("p0", 0).unwrap();
        let p0 = s.as_proxy(e0.index);
        // Not a sealed blob at all — `MasterKey::open` fails authentication, distinct from the
        // file simply being absent (which correctly means "empty" and must keep working).
        std::fs::write(p0.sessions_path(), b"not a sealed blob").unwrap();

        let err = s.burn_proxy(e0.index).expect_err("an unauthenticated sessions.dat must refuse the burn");
        assert!(
            !err.to_string().to_lowercase().contains("undelivered"),
            "this must be the AUTHENTICATION failure, not the pending-outbox message: {err}"
        );
        assert!(
            s.try_load_proxies().unwrap().iter().any(|p| p.index == e0.index),
            "the refused burn must not have deleted the registry entry"
        );

        // Control: a proxy that never wrote a sessions.dat at all (genuinely no outbox, not a
        // corrupt one) still burns cleanly — absence must keep reading as empty.
        let e1 = s.create_proxy("p1", 0).unwrap();
        s.burn_proxy(e1.index).expect("control: a proxy with no sessions.dat at all must still burn");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CRYPTO-28: the safety number desktop shows is `own_proxy_ik_for_this_contact || peer_ik` —
    /// `set_contact_proxy` picks the own half. Proves `verified` is cleared whenever that tag
    /// actually changes, INCLUDING untagged→first-tag (a contact can be verified out-of-band
    /// before their first inbound message ever reaches this function — every inbound tags the
    /// sender's proxy before `Content` is even decoded), not only when it moves between two
    /// already-known indices. Neuter the reset and this reddens; the two controls (same-index
    /// re-tag, an unrelated contact) catch a fix that resets `verified` unconditionally instead of
    /// only on an actual change.
    #[test]
    fn set_contact_proxy_resets_a_stale_verified_flag_whenever_the_own_tag_actually_changes() {
        let dir = std::env::temp_dir().join(format!("karst-store-verifiedstale-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();

        let alice = [0xA1u8; 32];
        let carol = [0xC1u8; 32];
        s.save_contacts(&[
            ContactRecord { name: "Alice".into(), ik: alice, verified: true },
            ContactRecord { name: "Carol".into(), ik: carol, verified: true },
        ])
        .unwrap();

        // Alice was verified out-of-band BEFORE any inbound message ever tagged her proxy — the
        // untagged→Some case this fix has to cover, not just index→different-index.
        assert_eq!(s.contact_proxy(&alice), None, "not yet tagged");
        s.set_contact_proxy(alice, 0).unwrap();
        assert!(
            !s.load_contacts().unwrap().iter().find(|c| c.ik == alice).unwrap().verified,
            "the first-ever proxy tag must reset a pre-existing verified flag — the own half of \
             the safety number just became defined for the first time"
        );

        // Re-verify (a fresh OOB check against the p0 pairing), then re-tag to the SAME index —
        // control: a no-op tag must not disturb `verified`.
        let mut cs = s.load_contacts().unwrap();
        cs.iter_mut().find(|c| c.ik == alice).unwrap().verified = true;
        s.save_contacts(&cs).unwrap();
        s.set_contact_proxy(alice, 0).unwrap();
        assert!(
            s.load_contacts().unwrap().iter().find(|c| c.ik == alice).unwrap().verified,
            "control: re-tagging to the SAME index must not reset verified"
        );

        // A genuine change (0 -> 1) resets it again.
        s.set_contact_proxy(alice, 1).unwrap();
        assert!(
            !s.load_contacts().unwrap().iter().find(|c| c.ik == alice).unwrap().verified,
            "a real change of the own proxy tag resets verified — the safety number's own half \
             changed under it"
        );

        // Control: an unrelated contact was never tagged here and keeps her flag throughout.
        assert!(
            s.load_contacts().unwrap().iter().find(|c| c.ik == carol).unwrap().verified,
            "control: an unrelated contact's verified flag must never move"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Proxy mode: identities differ (each from its OWN secret, and from the root), NETWORK state
    /// is isolated per proxy (OPKs saved as one proxy never leak to another or to the root), while
    /// DATA (contacts) is shared root state. This is the isolation gate for the proxy-identity
    /// network layer — neuter `net_file`'s namespacing and the "p1 has its own opks" assert reddens.
    #[test]
    fn proxy_mode_isolates_network_state_but_shares_data() {
        let dir = std::env::temp_dir().join(format!("karst-store-pmode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        s.save_seed(&[7u8; crate::seed::ENTROPY_BYTES]).unwrap();
        let e0 = s.create_proxy("p0", 1).unwrap();
        let e1 = s.create_proxy("p1", 2).unwrap();
        let p0 = s.as_proxy(e0.index);
        let p1 = s.as_proxy(e1.index);

        // Identity: proxy != proxy, proxy != root, and matches derivation from the entry's secret.
        let ik_p0 = p0.load_account().unwrap().identity_public();
        assert_ne!(ik_p0, p1.load_account().unwrap().identity_public(), "proxies differ");
        assert_ne!(ik_p0, s.load_account().unwrap().identity_public(), "proxy != root");
        assert_eq!(ik_p0, crate::seed::derive_proxy_from_secret(&e0.secret).account.identity_public());
        // The seal (relay-facing) is proxy-scoped too.
        assert_ne!(
            p0.load_identity().unwrap().public.to_bytes(),
            s.load_identity().unwrap().public.to_bytes(),
            "proxy seal != root seal"
        );

        // NETWORK isolation: OPKs saved as p0 are invisible to p1 and to the root.
        let unit = |b: u8| node::pqxdh::OneTimeSecret {
            x: [b; 32],
            kem_seed_lo: [b; 32],
            kem_seed_hi: [b; 32],
        };
        p0.save_opks(&[unit(1), unit(2)]).unwrap();
        assert_eq!(p0.load_opks().unwrap().len(), 2, "p0 has its OPKs");
        assert!(p1.load_opks().unwrap().is_empty(), "p1 has its own OPK namespace");
        assert!(s.load_opks().unwrap().is_empty(), "root OPKs untouched");

        // DATA is shared: a contact saved on the root is visible through a proxy handle.
        s.save_contacts(&[ContactRecord { name: "x".into(), ik: [9u8; 32], verified: false }]).unwrap();
        assert_eq!(p0.load_contacts().unwrap().len(), 1, "contacts are shared root data");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A history record written in the PRE-`msg_id` format (bare `postcard(HistoryRecord)`)
    /// still loads, and a new record written beside it with an id round-trips. The old record
    /// carries a zero id, so it never participates in dedup. Neuter the scan fallback (drop the
    /// bare-`HistoryRecord` branch) and the load of the old record reddens.
    #[test]
    fn history_reads_pre_msgid_records_and_new_ones() {
        let dir = std::env::temp_dir().join(format!("karst-store-histmig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();

        // Write ONE record in the OLD format: [len][seal(postcard(HistoryRecord))] — no msg_id.
        let old = HistoryRecord { from_me: false, peer_ik: [3u8; 32], text: b"legacy".to_vec(), ts: 9 };
        let blob = s.key.seal(&s.label(&s.history_path()), &postcard::to_stdvec(&old).unwrap());
        let mut framed = (blob.len() as u32).to_le_bytes().to_vec();
        framed.extend_from_slice(&blob);
        std::fs::write(s.history_path(), &framed).unwrap();

        // A new incoming record with a real id appends after it.
        s.append_history_incoming(
            &HistoryRecord { from_me: false, peer_ik: [3u8; 32], text: b"fresh".to_vec(), ts: 10 },
            [5u8; 32],
        )
        .unwrap();

        let hist = s.load_history().unwrap();
        assert_eq!(hist.len(), 2, "both the legacy and the new record load");
        assert_eq!(hist[0].text, b"legacy");
        assert_eq!(hist[1].text, b"fresh");

        // Only the NEW record's id participates in dedup; the legacy one is zero-id.
        let ids = s.recent_incoming_ids(1024).unwrap();
        assert!(ids.contains(&[5u8; 32]), "new record's id is a dedup key");
        assert_eq!(ids.len(), 1, "legacy zero-id does not participate");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A redelivered reaction (the crash-window duplicate) is a no-op: `set_reaction` uses set
    /// semantics, so re-applying the same add/remove converges to one authored reaction, never
    /// a phantom double. This is why the non-text residual does not bite reactions.
    #[test]
    fn set_reaction_is_idempotent_under_redelivery() {
        let dir = std::env::temp_dir().join(format!("karst-store-react-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        let (mid, author) = ([1u8; 16], [2u8; 32]);

        s.set_reaction(mid, "👍", author, true).unwrap();
        s.set_reaction(mid, "👍", author, true).unwrap(); // redelivered add
        let authors = s.load_meta().unwrap().get(&mid).unwrap().reactions.get("👍").unwrap().clone();
        assert_eq!(authors.len(), 1, "one author despite the duplicate add");

        s.set_reaction(mid, "👍", author, false).unwrap();
        s.set_reaction(mid, "👍", author, false).unwrap(); // redelivered remove
        assert!(!s.load_meta().unwrap().contains_key(&mid), "reaction cleared, no residue");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The version envelope round-trips, and a pre-versioning blob (bare seal, no magic) is
    /// rejected by `open_versioned` — so `load_pending_downloads` resets it rather than
    /// mis-parsing. This is the explicit-versioning pattern new formats adopt.
    #[test]
    fn version_envelope_round_trips_and_rejects_legacy() {
        let dir = std::env::temp_dir().join(format!("karst-store-ver-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();

        let sealed = s.seal_versioned(&s.downloads_path(), 7, b"payload");
        assert_eq!(s.open_versioned(&s.downloads_path(), &sealed), Some((7, b"payload".to_vec())));
        // A bare (unversioned) seal has no magic → None.
        assert_eq!(s.open_versioned(&s.downloads_path(), &s.key.seal(&s.label(&s.downloads_path()), b"payload")), None);

        // A pending-downloads file written in the OLD (unversioned) way loads as empty.
        let pd = PendingDownload {
            blob_id: [1u8; 32], key: [2u8; 32], hash: [3u8; 32], name: "f".into(),
            size: 1, chunks: 1, sender: [4u8; 32], ts: 0, queued_at: 0, container_id: None,
        };
        let mut map = std::collections::BTreeMap::new();
        map.insert(pd.blob_id, pd);
        s.write_sealed(&s.downloads_path(), &postcard::to_stdvec(&map).unwrap()).unwrap();
        assert!(s.list_pending_downloads().unwrap().is_empty(), "legacy unversioned file resets");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Pending downloads round-trip (idempotent by blob_id) and `sweep_orphan_files` removes a
    /// crashed partial (a `files/<id>.dat` not in the received-files index) while keeping a
    /// recorded one — the two durability primitives the crash-safe download rests on.
    #[test]
    fn pending_downloads_and_orphan_sweep() {
        let dir = std::env::temp_dir().join(format!("karst-store-pd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();

        let pd = PendingDownload {
            blob_id: [1u8; 32], key: [2u8; 32], hash: [3u8; 32], name: "f".into(),
            size: 10, chunks: 1, sender: [4u8; 32], ts: 5, queued_at: 5, container_id: None,
        };
        s.add_pending_download(&pd).unwrap();
        s.add_pending_download(&pd).unwrap(); // idempotent by blob_id
        assert_eq!(s.list_pending_downloads().unwrap().len(), 1, "one entry despite the duplicate add");
        s.remove_pending_download(&[1u8; 32]).unwrap();
        assert!(s.list_pending_downloads().unwrap().is_empty(), "removed");

        // A recorded file (in the index) survives the sweep; an orphan partial is removed.
        let keep = s.save_received_file("keep", b"hi").unwrap();
        s.record_received_file(&ReceivedFile {
            id: keep.clone(), name: "keep".into(), size: 2, sender: [0u8; 32], ts: 0, blob_id: [7u8; 32],
        }).unwrap();
        let orphan = s.save_received_file("orphan", b"partial").unwrap(); // written, never indexed
        assert_eq!(s.sweep_orphan_files().unwrap(), 1, "the orphan was swept");
        assert!(s.received_file_size(&keep).is_ok(), "the indexed file survived");
        assert!(s.received_file_size(&orphan).is_err(), "the orphan is gone");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A re-delivered inline file is saved ONCE: the second save of the same transfer id returns
    /// the existing container and `false`, leaving a single indexed file — the inline analogue of
    /// the blob path's `blob_id` idempotency.
    #[test]
    fn inline_file_save_is_deduped_by_transfer_id() {
        let dir = std::env::temp_dir().join(format!("karst-store-dedup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        let tid = [9u8; 16];
        let sender = [4u8; 32];

        let (id1, new1) = s.save_received_file_deduped(tid, "note.txt", b"hello", sender, 100).unwrap();
        assert!(new1, "first delivery is new");
        // A re-delivery of the SAME transfer → same container, not new, nothing saved twice.
        let (id2, new2) = s.save_received_file_deduped(tid, "note.txt", b"hello", sender, 100).unwrap();
        assert!(!new2, "re-delivery is a duplicate");
        assert_eq!(id1, id2, "resolves to the already-saved file");
        assert_eq!(s.list_received_files().unwrap().iter().filter(|f| f.blob_id[..16] == tid).count(), 1);

        // A genuinely different transfer (even same name/bytes) is its own file.
        let (id3, new3) = s.save_received_file_deduped([1u8; 16], "note.txt", b"hello", sender, 100).unwrap();
        assert!(new3);
        assert_ne!(id3, id1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Pending uploads round-trip and expose the record (blob_id+key) that a resume reuses.
    #[test]
    fn pending_uploads_persist_and_expose_the_resume_record() {
        let dir = std::env::temp_dir().join(format!("karst-store-pu-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        let pu = PendingUpload {
            upload_id: [1u8; 32], blob_id: [2u8; 32], key: [3u8; 32], to_ik: [4u8; 32],
            name: "big.bin".into(), size: 12_345, queued_at: 7, path: Some("/tmp/big.bin".into()),
        };
        assert!(s.get_pending_upload(&[1u8; 32]).unwrap().is_none(), "nothing before add");
        s.add_pending_upload(&pu).unwrap();
        // A resume reads back the SAME blob_id + key, so it continues the same blob (not a new one).
        assert_eq!(s.get_pending_upload(&[1u8; 32]).unwrap(), Some(pu.clone()));
        assert_eq!(s.list_pending_uploads().unwrap().len(), 1);
        s.remove_pending_upload(&[1u8; 32]).unwrap();
        assert!(s.get_pending_upload(&[1u8; 32]).unwrap().is_none(), "cleared after remove");
        assert!(s.list_pending_uploads().unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Privacy prefs default to OFF when never saved and round-trip through their own sealed blob
    /// (`prefs.dat`). Kept apart from `NetSettings` so a relay-screen save cannot reset the
    /// disappearing timer — this test pins the isolated persistence, not that coupling.
    #[test]
    fn privacy_prefs_round_trip_and_default_off() {
        let dir = std::env::temp_dir().join(format!("karst-store-prefs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        // Never saved → default (disappearing off).
        assert_eq!(s.load_prefs().unwrap(), Prefs::default());
        assert_eq!(s.load_prefs().unwrap().disappearing_secs, 0);
        // A real timer round-trips.
        s.save_prefs(&Prefs { disappearing_secs: 30 }).unwrap();
        assert_eq!(s.load_prefs().unwrap().disappearing_secs, 30);
        // And back to off.
        s.save_prefs(&Prefs { disappearing_secs: 0 }).unwrap();
        assert_eq!(s.load_prefs().unwrap().disappearing_secs, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Edits converge to the LATEST `edit_ts`, independent of delivery order: a stale or
    /// redelivered edit never overwrites a newer one, and re-applying the same edit is a no-op.
    #[test]
    fn set_edit_keeps_the_newest_regardless_of_order() {
        let dir = std::env::temp_dir().join(format!("karst-store-edit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        let mid = [7u8; 16];

        s.set_edit(mid, 100, b"first").unwrap();
        s.set_edit(mid, 200, b"second").unwrap(); // newer
        s.set_edit(mid, 100, b"first").unwrap(); // stale redelivery — must NOT clobber
        let edited = s.load_meta().unwrap().get(&mid).unwrap().edited.clone().unwrap();
        assert_eq!(edited.0, 200);
        assert_eq!(edited.1, b"second", "the newer edit survived the stale redelivery");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── Multi-password (duress / decoy / wipe), layout A′ ────────────────────

    fn mp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("karst-mp-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// A fresh vault provisions the REAL compartment under `c/<id>/` (nothing at the root); the
    /// right password reopens it, a wrong one opens nothing.
    #[test]
    fn multipassword_create_open_and_wrong_password() {
        let dir = mp_dir("cr");
        let v = Vault::create(&dir, b"realpw").unwrap();
        v.create_account_dir("acc").unwrap();
        v.save_registry(&[AccountEntry { id: "acc".into(), label: "A".into(), ik: [1u8; 32] }]).unwrap();
        assert!(!dir.join("accounts.dat").exists(), "no primary blob at the root");
        assert!(dir.join("c").exists());
        assert!(dir.join("slots.dat").exists());
        match Vault::open(&dir, b"realpw").unwrap() {
            Opened::Real(v2) => assert_eq!(v2.load_registry().unwrap().len(), 1),
            _ => panic!("expected Real"),
        }
        assert!(Vault::open(&dir, b"wrongpw").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pre-multipassword vault (registry + account at the root) is relocated into a compartment
    /// on first open, with data intact, and re-opening is idempotent (stays in the same one).
    #[test]
    fn multipassword_migrates_pre_compartment_layout_idempotently() {
        let dir = mp_dir("mig");
        std::fs::create_dir_all(&dir).unwrap();
        let salt = read_or_create_salt(&dir).unwrap();
        let key = MasterKey::derive(b"realpw", &salt).unwrap();
        let root = Vault { base: dir.clone(), dir: dir.clone(), key };
        root.create_account_dir("acc").unwrap();
        root.account("acc").save_seed(&[7u8; crate::seed::ENTROPY_BYTES]).unwrap();
        root.save_registry(&[AccountEntry { id: "acc".into(), label: "A".into(), ik: [9u8; 32] }]).unwrap();
        assert!(dir.join("accounts.dat").exists(), "pre-migration root registry present");

        let v = match Vault::open(&dir, b"realpw").unwrap() { Opened::Real(v) => v, _ => panic!() };
        assert_eq!(v.load_registry().unwrap()[0].id, "acc");
        assert_eq!(v.account("acc").load_entropy().unwrap(), [7u8; crate::seed::ENTROPY_BYTES]);
        assert!(!dir.join("accounts.dat").exists(), "root registry removed after migration");
        assert!(!dir.join("accounts").exists());

        let v2 = match Vault::open(&dir, b"realpw").unwrap() { Opened::Real(v) => v, _ => panic!() };
        assert_eq!(v2.account("acc").load_entropy().unwrap(), [7u8; crate::seed::ENTROPY_BYTES]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Real / decoy / wipe passwords route to distinct outcomes, and adding the extras never
    /// clobbers the real slot (the occupancy map keeps them on separate indices). Wipe crypto-
    /// erases so even the real password then opens nothing.
    #[test]
    fn multipassword_decoy_wipe_route_without_clobber() {
        let dir = mp_dir("dw");
        let real = Vault::create(&dir, b"realpw").unwrap();
        real.save_registry(&[AccountEntry { id: "r".into(), label: "R".into(), ik: [1u8; 32] }]).unwrap();
        let salt = read_or_create_salt(&dir).unwrap();
        let realkey = MasterKey::derive(b"realpw", &salt).unwrap();

        let dkey = MasterKey::derive(b"decoypw", &salt).unwrap();
        let did = random16();
        std::fs::create_dir_all(compartment_dir(&dir, &did)).unwrap();
        slot_write(&dir, &realkey, &dkey, SlotRole::Decoy, &did).unwrap();
        Vault { base: dir.clone(), dir: compartment_dir(&dir, &did), key: dkey }
            .save_registry(&[AccountEntry { id: "d".into(), label: "D".into(), ik: [2u8; 32] }])
            .unwrap();

        let wkey = MasterKey::derive(b"wipepw", &salt).unwrap();
        slot_write(&dir, &realkey, &wkey, SlotRole::Wipe, &[0u8; 16]).unwrap();

        // All three configured passwords survive (no clobber) and route correctly.
        match Vault::open(&dir, b"realpw").unwrap() {
            Opened::Real(v) => assert_eq!(v.load_registry().unwrap()[0].id, "r"),
            _ => panic!("expected Real"),
        }
        match Vault::open(&dir, b"decoypw").unwrap() {
            Opened::Decoy(v) => assert_eq!(v.load_registry().unwrap()[0].id, "d"),
            _ => panic!("expected Decoy"),
        }
        assert!(matches!(Vault::open(&dir, b"wipepw").unwrap(), Opened::Wipe));
        assert!(!dir.join("salt").exists(), "salt shredded on wipe");
        assert!(!dir.join("slots.dat").exists());
        assert!(!dir.join("c").exists());
        assert!(Vault::open(&dir, b"realpw").is_err(), "real password opens nothing post-wipe");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Removing an extra password (slot_erase) revokes exactly that password and leaves the rest.
    #[test]
    fn multipassword_slot_erase_removes_one_password() {
        let dir = mp_dir("er");
        let _real = Vault::create(&dir, b"realpw").unwrap();
        let salt = read_or_create_salt(&dir).unwrap();
        let realkey = MasterKey::derive(b"realpw", &salt).unwrap();
        let dkey = MasterKey::derive(b"decoypw", &salt).unwrap();
        let did = random16();
        std::fs::create_dir_all(compartment_dir(&dir, &did)).unwrap();
        slot_write(&dir, &realkey, &dkey, SlotRole::Decoy, &did).unwrap();
        assert!(matches!(Vault::open(&dir, b"decoypw").unwrap(), Opened::Decoy(_)));

        slot_erase(&dir, &realkey, &dkey).unwrap();
        assert!(Vault::open(&dir, b"decoypw").is_err(), "decoy password revoked");
        assert!(matches!(Vault::open(&dir, b"realpw").unwrap(), Opened::Real(_)), "real still works");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Unused slots are byte-shaped exactly like sealed ones: same length, same magic prefix, so
    /// the number of configured passwords is not inferable from `slots.dat`.
    #[test]
    fn multipassword_unused_slots_are_indistinguishable() {
        let fresh = slots_fresh();
        assert_eq!(fresh.len(), SLOT_COUNT);
        for s in &fresh {
            assert_eq!(s.len(), SLOT_LEN);
            assert_eq!(&s[..4], crate::secretbox::MAGIC, "same magic prefix as a sealed slot");
        }
        // A real sealed slot has the same length and prefix.
        let salt = [3u8; 16];
        let k = MasterKey::derive(b"x", &salt).unwrap();
        let sealed = slot_seal(&k, SlotRole::Real, &[1u8; 16]);
        assert_eq!(sealed.len(), SLOT_LEN);
        assert_eq!(&sealed[..4], crate::secretbox::MAGIC);
    }

    /// The real session can ADD a decoy (which provisions its own fresh empty account and routes to
    /// its OWN compartment), LIST it, refuse a duplicate password, and REMOVE it (deleting the decoy
    /// compartment) — all without touching the real account.
    #[test]
    fn multipassword_add_decoy_provisions_lists_and_removes() {
        let dir = mp_dir("adddecoy");
        let real = Vault::create(&dir, b"realpw").unwrap();
        real.save_registry(&[AccountEntry { id: "r".into(), label: "R".into(), ik: [1u8; 32] }]).unwrap();
        assert!(real.extra_passwords().unwrap().is_empty());

        real.add_decoy(b"decoypw").unwrap();
        assert_eq!(real.extra_passwords().unwrap(), vec![ExtraPassword::Decoy]);
        let decoy = match Vault::open(&dir, b"decoypw").unwrap() { Opened::Decoy(v) => v, _ => panic!("Decoy") };
        let dreg = decoy.load_registry().unwrap();
        assert_eq!(dreg.len(), 1, "decoy opens its OWN freshly-provisioned account");
        assert_ne!(dreg[0].ik, [1u8; 32], "decoy is a different identity from the real account");

        match Vault::open(&dir, b"realpw").unwrap() {
            Opened::Real(v) => assert_eq!(v.load_registry().unwrap()[0].id, "r", "real untouched"),
            _ => panic!("Real"),
        }

        assert!(real.add_decoy(b"realpw").is_err(), "cannot reuse the real password");
        assert!(real.add_decoy(b"decoypw").is_err(), "cannot reuse an existing decoy");

        let decoy_dir = decoy.dir.clone();
        real.remove_extra(b"decoypw").unwrap();
        assert!(real.extra_passwords().unwrap().is_empty());
        assert!(Vault::open(&dir, b"decoypw").is_err(), "decoy revoked");
        assert!(!decoy_dir.exists(), "decoy compartment deleted");
        assert!(real.remove_extra(b"realpw").is_err(), "cannot remove the real password");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A wipe/duress password is listed like an extra and crypto-erases everything on entry.
    #[test]
    fn multipassword_add_wipe_erases_on_entry() {
        let dir = mp_dir("addwipe");
        let real = Vault::create(&dir, b"realpw").unwrap();
        real.save_registry(&[AccountEntry { id: "r".into(), label: "R".into(), ik: [1u8; 32] }]).unwrap();
        real.add_wipe(b"wipepw").unwrap();
        assert_eq!(real.extra_passwords().unwrap(), vec![ExtraPassword::Wipe]);
        assert!(matches!(Vault::open(&dir, b"realpw").unwrap(), Opened::Real(_)), "real works pre-wipe");
        assert!(matches!(Vault::open(&dir, b"wipepw").unwrap(), Opened::Wipe));
        assert!(!dir.join("salt").exists(), "salt shredded");
        assert!(!dir.join("c").exists());
        assert!(Vault::open(&dir, b"realpw").is_err(), "real opens nothing post-wipe");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CRYPTO-01/12 — an atomic save must make the RENAME durable, not just the file contents.
    ///
    /// `sync_all` on the temp file promises its bytes survive a power loss; POSIX does not
    /// promise the directory entry does. A crash in that gap leaves the OLD file in place after a
    /// write that reported success — for `sessions.dat` that is a silent ratchet ROLLBACK, and a
    /// rolled-back ratchet re-derives a message key already used, under the fixed all-zero nonce.
    ///
    /// A unit test cannot cut the power, so this pins the reachable part: the helper completes,
    /// the destination holds the new bytes, and no temp file is left behind. The durability
    /// itself is asserted by construction (the directory fsync) and documented on the helper.
    #[test]
    fn a_durable_rename_publishes_the_new_bytes_and_leaves_no_temp() {
        let dir = mp_dir("durable-rename");
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("state.dat");
        std::fs::write(&dest, b"old").unwrap();
        let tmp = dir.join("state.dat.tmp");
        std::fs::write(&tmp, b"new").unwrap();

        rename_durable(&tmp, &dest).expect("durable rename must succeed on a normal filesystem");

        assert_eq!(std::fs::read(&dest).unwrap(), b"new", "the new bytes are published");
        assert!(!tmp.exists(), "the temp file must be gone, not left as debris");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A8-6 — a full pending queue must REPORT the overflow, not return success.
    ///
    /// It returned `Ok(())` while discarding the entry. The receive path reads that as "durably
    /// recorded", saves the ratchet and ACKs the carrier message — so the relay deletes the only
    /// pointer to that file while nothing was kept locally. An attacker who fills the queue with
    /// their own objects therefore makes OTHER contacts' attachments disappear silently. Failing
    /// instead leaves the message unacked and on the relay until its TTL.
    #[test]
    fn a_full_pending_download_queue_reports_the_overflow() {
        let dir = mp_dir("queue-full");
        let vault = Vault::create(&dir, b"pw").unwrap();
        vault.create_account_dir("a").unwrap();
        let store = vault.account("a");

        let mk = |n: u32| PendingDownload {
            blob_id: {
                let mut b = [0u8; 32];
                b[..4].copy_from_slice(&n.to_le_bytes());
                b
            },
            key: [1u8; 32],
            hash: [2u8; 32],
            name: format!("f{n}"),
            size: 10,
            chunks: 1,
            sender: [3u8; 32],
            ts: 1,
            queued_at: 1,
            container_id: None,
        };
        for n in 0..MAX_PENDING_DOWNLOADS as u32 {
            store.add_pending_download(&mk(n)).expect("fits under the cap");
        }
        assert!(
            store.add_pending_download(&mk(u32::MAX)).is_err(),
            "an overflow must be reported so the carrier message is not acked away"
        );
        // An entry already present is still an update, not an overflow.
        assert!(store.add_pending_download(&mk(0)).is_ok(), "updating an existing entry still works");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CRYPTO-29 — a proxy list that exists but fails authentication must not read as "none".
    ///
    /// Silently returning an empty list does not merely lose a setting: proxies ARE the network
    /// identity this account is reached through, so an empty list quietly switches which identity
    /// goes on the wire. Absent is legitimately empty; corrupt is an error the caller can see.
    #[test]
    fn a_corrupt_proxy_list_is_an_error_not_an_empty_one() {
        let dir = mp_dir("proxy-corrupt");
        let vault = Vault::create(&dir, b"pw").unwrap();
        vault.create_account_dir("a").unwrap();
        vault.save_registry(&[AccountEntry { id: "a".into(), label: "A".into(), ik: [1u8; 32] }]).unwrap();
        let store = vault.account("a");

        assert!(store.try_load_proxies().unwrap().is_empty(), "absent = legitimately none");

        store
            .save_registry(&ProxyRegistry {
                next_index: 1,
                entries: vec![ProxyEntry { index: 0, label: "p0".into(), created_at: 1, secret: [5u8; 32] }],
            })
            .unwrap();
        assert_eq!(store.try_load_proxies().unwrap().len(), 1, "control: it round-trips");

        // Corrupt the sealed file the way a bad disk or a tamper would.
        let path = dir.join("c").join("a").join("accounts");
        let _ = path; // the exact layout is internal; find the file by name instead
        let mut found = None;
        for e in walkdir_dat(&dir) {
            if e.file_name().map(|n| n == "proxies.dat").unwrap_or(false) {
                found = Some(e);
                break;
            }
        }
        let f = found.expect("proxies.dat was written somewhere under the vault");
        std::fs::write(&f, b"not a sealed blob").unwrap();

        assert!(
            store.try_load_proxies().is_err(),
            "an unauthenticated proxy list must be reported, not turned into a different identity"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Tiny recursive find used by the test above (no dev-dependency needed).
    fn walkdir_dat(root: &std::path::Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            if let Ok(rd) = std::fs::read_dir(&d) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else {
                        out.push(p);
                    }
                }
            }
        }
        out
    }

    /// A3-11 residual — deleting or editing the PLAINTEXT hint must not disarm the switch.
    ///
    /// `deadman.dat` has to be readable before any password exists, so it cannot be
    /// authenticated: an adversary with the directory could simply blank it, and a corrupt file
    /// read as "disarmed". Authentication alone could never fix that (a file can always be
    /// deleted), so the hint is demoted — the SEALED copy decides. Here the hint is tampered into
    /// "disarmed" and the vault is opened anyway: reconcile must still wipe.
    #[test]
    fn tampering_with_the_plaintext_hint_does_not_disarm_the_dead_man() {
        let dir = mp_dir("deadman-tamper");
        let real = Vault::create(&dir, b"realpw").unwrap();
        real.save_registry(&[AccountEntry { id: "r".into(), label: "R".into(), ik: [1u8; 32] }]).unwrap();
        real.set_deadman(100, 1_000).unwrap();

        // The attacker's move: rewrite the pre-password hint to say "disarmed".
        deadman_save(&dir, &Deadman { interval_secs: 0, last_seen: 0, last_check: 0 }).unwrap();
        assert!(
            !Vault::deadman_check(&dir, 5_000).unwrap(),
            "the pre-password check believes the hint — that is exactly why it cannot be the truth"
        );
        assert!(matches!(Vault::open(&dir, b"realpw").unwrap(), Opened::Real(_)), "still opens");

        // At a real unlock the sealed state is authoritative: overdue ⇒ wipe.
        let v = match Vault::open(&dir, b"realpw").unwrap() {
            Opened::Real(v) => v,
            _ => panic!("real password opens the real vault"),
        };
        assert!(
            v.deadman_reconcile(5_000).unwrap(),
            "a tampered hint must not save an overdue vault from the wipe"
        );
        assert!(!dir.join("salt").exists(), "the vault really was erased");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The mirror case: an armed, NOT-overdue switch survives a tampered hint, and the hint is
    /// repaired from the sealed truth — so the pre-password check works again next launch.
    #[test]
    fn reconcile_repairs_a_tampered_hint_without_wiping_a_live_vault() {
        let dir = mp_dir("deadman-repair");
        let real = Vault::create(&dir, b"realpw").unwrap();
        real.save_registry(&[AccountEntry { id: "r".into(), label: "R".into(), ik: [1u8; 32] }]).unwrap();
        real.set_deadman(10_000, 1_000).unwrap();

        deadman_save(&dir, &Deadman { interval_secs: 0, last_seen: 0, last_check: 0 }).unwrap();
        let v = match Vault::open(&dir, b"realpw").unwrap() {
            Opened::Real(v) => v,
            _ => panic!("real password opens the real vault"),
        };
        assert!(!v.deadman_reconcile(2_000).unwrap(), "a live vault must not be wiped");
        assert!(dir.join("salt").exists(), "still intact");
        let repaired = deadman_load(&dir);
        assert!(repaired.armed(), "the hint was repaired from the sealed state");
        assert_eq!(repaired.interval_secs, 10_000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A3-11 — the dead-man switch destroys data irreversibly, so a bare `SystemTime::now()`
    /// must not be enough to fire it.
    ///
    /// FORWARD: a wrong RTC, a restored VM snapshot or an edited date can jump the clock by
    /// years. Treating that as "the owner has been absent for years" wipes a vault that was in
    /// use yesterday — the accident this guard exists to prevent. The launch re-anchors instead,
    /// and a genuinely overdue owner still trips the switch afterwards, so the feature keeps
    /// working.
    ///
    /// BACKWARD: judged against the latest time ever OBSERVED, so winding the clock back cannot
    /// postpone the wipe indefinitely.
    #[test]
    fn deadman_survives_a_clock_jump_and_resists_a_rewind() {
        let dir = mp_dir("deadman-clock");
        let real = Vault::create(&dir, b"realpw").unwrap();
        real.save_registry(&[AccountEntry { id: "r".into(), label: "R".into(), ik: [1u8; 32] }]).unwrap();
        real.set_deadman(100, 1_000).unwrap();

        // A launch far in the future — a decade, not a plausible gap between launches.
        let decade = 1_000 + 10 * 365 * 24 * 3600;
        assert!(
            !Vault::deadman_check(&dir, decade).unwrap(),
            "an implausible forward clock jump must NOT wipe a live vault"
        );
        assert!(matches!(Vault::open(&dir, b"realpw").unwrap(), Opened::Real(_)), "vault intact");

        // Winding the clock back must not buy the coercer extra time: the observed high-water
        // mark from the previous launch already stands past the deadline.
        assert!(
            Vault::deadman_check(&dir, 900).unwrap(),
            "a backwards clock must not postpone an already-overdue wipe"
        );
        assert!(!dir.join("salt").exists(), "the overdue switch still fires");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A plausible absence still fires: the anomaly guard must not have disarmed the feature.
    #[test]
    fn deadman_still_fires_after_a_plausible_absence() {
        let dir = mp_dir("deadman-plausible");
        let real = Vault::create(&dir, b"realpw").unwrap();
        real.save_registry(&[AccountEntry { id: "r".into(), label: "R".into(), ik: [1u8; 32] }]).unwrap();
        real.set_deadman(24 * 3600, 1_000_000).unwrap(); // one day

        // Three days later — an ordinary gap, well inside the plausibility bound.
        assert!(
            Vault::deadman_check(&dir, 1_000_000 + 3 * 24 * 3600).unwrap(),
            "an overdue switch must still wipe after a NORMAL absence"
        );
        assert!(!dir.join("salt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The dead-man switch arms, a real unlock refreshes the countdown, and it auto-wipes once the
    /// interval lapses without a check-in.
    #[test]
    fn multipassword_deadman_arms_refreshes_and_fires() {
        let dir = mp_dir("deadman");
        let real = Vault::create(&dir, b"realpw").unwrap();
        real.save_registry(&[AccountEntry { id: "r".into(), label: "R".into(), ik: [1u8; 32] }]).unwrap();
        assert!(!Vault::deadman_check(&dir, 1_000_000).unwrap(), "disarmed by default");
        assert!(!real.deadman().armed());

        real.set_deadman(100, 1_000).unwrap();
        assert!(real.deadman().armed());
        assert_eq!(real.deadman().remaining(1_040), Some(60));
        assert!(!Vault::deadman_check(&dir, 1_050).unwrap(), "within interval → no wipe");
        assert!(matches!(Vault::open(&dir, b"realpw").unwrap(), Opened::Real(_)), "intact");

        real.deadman_touch(1_090).unwrap(); // a real unlock refreshes the countdown
        assert_eq!(real.deadman().last_seen, 1_090);
        assert!(!Vault::deadman_check(&dir, 1_150).unwrap(), "refreshed → not overdue at 1150");

        assert!(Vault::deadman_check(&dir, 1_090 + 100).unwrap(), "overdue → auto-wipe");
        assert!(!dir.join("salt").exists());
        assert!(!dir.join("c").exists());
        assert!(Vault::open(&dir, b"realpw").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Disarming stops the wipe even long past the old deadline.
    #[test]
    fn multipassword_deadman_disarm_stops_the_wipe() {
        let dir = mp_dir("deadmanoff");
        let real = Vault::create(&dir, b"realpw").unwrap();
        real.save_registry(&[AccountEntry { id: "r".into(), label: "R".into(), ik: [1u8; 32] }]).unwrap();
        real.set_deadman(50, 1_000).unwrap();
        real.set_deadman(0, 2_000).unwrap(); // disarm
        assert!(!real.deadman().armed());
        assert!(!Vault::deadman_check(&dir, 9_999_999).unwrap(), "disarmed → never fires");
        assert!(matches!(Vault::open(&dir, b"realpw").unwrap(), Opened::Real(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

}

/// A change to any PERSISTED shape must move `STATE_VERSION` — enforced here, because nothing
/// else can (#144).
///
/// The failure this closes happened twice in one day. `OneTimeSecret` widened the `opks` entries
/// inside `sessions.dat` from 32 bytes to 96 (CRYPTO-33), and `capabilities.dat` re-keyed per
/// channel (A8-4), and both landed with `STATE_VERSION` untouched. No test could have caught it:
/// every test writes a fresh vault into a temp directory, so nothing in the suite ever opens an
/// old file with a new binary. The version is the ONLY thing standing between a shape change and
/// "secrets unreadable" — a loud, wedging error that tells the user to delete and re-provision —
/// and it was being maintained by memory.
///
/// **What it hashes: the SOURCE TEXT of the type declarations**, not an encoding of sample values.
/// Postcard encodes values, so a golden-vector approach would miss a renamed field, and would miss
/// any change in a variant a chosen sample does not exercise. Hashing the declarations catches
/// field ADDITION, REMOVAL, REORDERING, RETYPING and RENAMING — every one of which changes either
/// the bytes or the meaning of the bytes. Comments and whitespace are stripped first, so writing
/// documentation does not trip it.
///
/// **What it does NOT catch, stated so nobody over-trusts it:** a change in a type this list does
/// not name (add the type here when you add a persisted one — the list IS the inventory of what
/// this vault writes), and a change in a NESTED type's declaration reached only through a field
/// (those are listed separately for the same reason). It also cannot know whether a change is
/// backward compatible; it only insists the version move.
#[cfg(test)]
mod at_rest_shape_guard {
    /// Every top-level shape this vault serializes, and the file it lives in. Adding a persisted
    /// type without adding it here is the one hole in the guard, so treat this list as part of
    /// the storage format rather than as test scaffolding.
    const PERSISTED: &[(&str, &str)] = &[
        // client/src/store.rs — the vault's own records
        ("store", "ContactRecord"),
        ("store", "InviteRecord"),
        ("store", "ContactEndpoint"),
        ("store", "Profile"),
        ("store", "HistoryRecord"),
        ("store", "FeedRecord"),
        ("store", "StoredAttachment"),
        ("store", "QuarantinedMessage"),
        ("store", "PendingSend"),
        ("store", "StrandedSend"),
        ("store", "ChannelConfig"),
        ("store", "Subscriber"),
        ("store", "StoredHistory"),
        ("store", "ReceivedFile"),
        ("store", "PendingDownload"),
        ("store", "PendingPostAttachment"),
        ("store", "PendingGallery"),
        ("store", "PendingUpload"),
        ("store", "SessionFile"),
        ("store", "CapabilityFile"),
        ("store", "MsgMeta"),
        ("store", "AccountEntry"),
        ("store", "ProxyEntry"),
        ("store", "ProxyRegistry"),
        ("store", "NetSettings"),
        ("store", "Prefs"),
        ("store", "RelayPrefs"),
        ("store", "Deadman"),
        ("store", "SlotEntry"),
        ("store", "SlotRole"),
        // Written INTO the vault by the session layer — a change here rewrites `sessions.dat`
        // just as surely as a change above does.
        ("peer", "PeerState"),
        ("ratchet", "SessionSnapshot"),
        ("ratchet", "SkippedKey"),
        ("pqxdh", "OneTimeSecret"),
    ];

    /// The pinned digest. Regenerate ONLY together with a `STATE_VERSION` bump: run the test, take
    /// the "actual" value from the failure, and move both in the same commit.
    const SHAPE_DIGEST: &str = "5dfb26491d9599f9";

    fn source(module: &str) -> &'static str {
        match module {
            "store" => include_str!("store.rs"),
            "peer" => include_str!("../../client-core/src/peer.rs"),
            "ratchet" => include_str!("../../crypto/src/ratchet.rs"),
            "pqxdh" => include_str!("../../crypto/src/pqxdh.rs"),
            other => panic!("no source registered for module {other}"),
        }
    }

    /// The declaration body of `struct NAME { … }` or `enum NAME { … }`, with comments and all
    /// whitespace removed — so the digest tracks the SHAPE and ignores prose.
    fn declaration(src: &str, name: &str) -> String {
        let mut found = None;
        for kw in ["struct ", "enum "] {
            let needle = format!("{kw}{name} ");
            for (i, _) in src.match_indices(&needle) {
                // Must start a top-level item: the line is `pub struct X {` or `struct X {`.
                let line_start = src[..i].rfind('\n').map(|n| n + 1).unwrap_or(0);
                let prefix = src[line_start..i].trim();
                if prefix.is_empty() || prefix == "pub" || prefix.starts_with("pub(") {
                    found = Some(i + needle.len() - 1);
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }
        let start = found.unwrap_or_else(|| panic!("no top-level declaration of `{name}`"));
        let bytes = src.as_bytes();
        let open = start + src[start..].find('{').expect("a braced declaration");
        let mut depth = 0usize;
        let mut end = open;
        for (k, b) in bytes[open..].iter().enumerate() {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + k + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        src[open..end]
            .lines()
            .map(|l| match l.find("//") {
                Some(c) => &l[..c],
                None => l,
            })
            .collect::<String>()
            .split_whitespace()
            .collect()
    }

    /// FNV-1a, so the guard needs no dependency of its own. Collision resistance is irrelevant
    /// here: the input is our own source, not attacker-chosen.
    fn digest(s: &str) -> String {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in s.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("{h:016x}")
    }

    #[test]
    fn a_persisted_shape_cannot_change_without_moving_state_version() {
        let joined: String =
            PERSISTED.iter().map(|(m, n)| format!("{n}{}", declaration(source(m), n))).collect();
        let actual = digest(&joined);
        assert_eq!(
            actual, SHAPE_DIGEST,
            "\n\nA PERSISTED SHAPE CHANGED (at-rest format v{}).\n\
             Bump `secretbox::STATE_VERSION` and set SHAPE_DIGEST to {actual:?} in the SAME commit.\n\
             Without the bump, an existing vault decodes the new shape from old bytes and surfaces \
             as \"secrets unreadable\" instead of naming itself.\n\
             If you did bump it: this is the regeneration step, not a failure.\n",
            crate::secretbox::STATE_VERSION
        );
    }
}

#[cfg(test)]
mod orphan_sweep_tests {
    use super::*;

    /// A burn interrupted after the registry write leaves the identity gone and its state behind;
    /// the next unlock must collect it (#144).
    ///
    /// Simulated exactly the way a crash would leave it: write the proxy's files and credential,
    /// then remove ONLY the registry entry — which is the first thing `burn_proxy` does and the
    /// last thing a crash can interrupt before.
    #[test]
    fn an_interrupted_burn_leaves_residue_that_the_next_unlock_collects() {
        let dir = std::env::temp_dir().join(format!(
            "karst-orphan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let s = Store::unlock(&dir, b"pw").unwrap();
        let e = s.create_proxy("doomed", 0).unwrap();
        let keeper = s.create_proxy("keeper", 0).unwrap();
        let victim = s.as_proxy(e.index);

        let relay = crate::RelayId { noise_pub: [1u8; 32], fetch_pub: [2u8; 32] };
        victim.save_capability_for(&relay, &crate::dev_capability()).unwrap();
        s.as_proxy(keeper.index).save_capability_for(&relay, &crate::dev_capability()).unwrap();
        victim.save_discovery(&[9u8; 32]).unwrap();
        s.set_contact_proxy([7u8; 32], e.index).unwrap();
        assert!(victim.net_file("discovery.key").exists(), "precondition: the file is there");

        // The crash: registry entry gone, nothing else touched.
        let mut reg = s.load_registry().unwrap();
        reg.entries.retain(|p| p.index != e.index);
        s.save_registry(&reg).unwrap();

        let swept = s.sweep_orphaned_proxy_state().unwrap();
        assert!(swept >= 3, "expected the file, the credential and the tag, swept {swept}");
        assert!(!victim.net_file("discovery.key").exists(), "the burned channel's file survived");
        assert!(
            !victim.has_own_capability_for(&relay).unwrap(),
            "the burned channel's admission credential survived"
        );
        assert!(s.contact_proxy(&[7u8; 32]).is_none(), "the tag still points at a dead channel");

        // Surgical: the channel that is still alive keeps everything.
        assert!(
            s.as_proxy(keeper.index).has_own_capability_for(&relay).unwrap(),
            "the sweep took a LIVE channel's credential with it"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The per-peer history index (#266): a cache that must never disagree with the log.
#[cfg(test)]
mod history_index_tests {
    use super::*;

    /// A per-peer read must return EXACTLY what a full scan would have returned for that peer.
    ///
    /// This is the test that matters: the index is a second path to the same bytes, and a second
    /// path is only safe while it cannot disagree with the first. DISCRIMINATING — drop a record
    /// from the refresh loop, or key it on the wrong field, and this reds.
    #[test]
    fn a_peer_read_returns_exactly_what_a_full_scan_would() {
        let dir = std::env::temp_dir().join(format!("karst-hidx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();

        let (a, b, c) = ([0xA1; 32], [0xB2; 32], [0xC3; 32]);
        // Interleaved on purpose: the offsets a peer's records sit at are not contiguous, which
        // is the whole reason an index is needed rather than a range.
        for i in 0..30u64 {
            let peer = match i % 3 {
                0 => a,
                1 => b,
                _ => c,
            };
            s.append_history(&HistoryRecord {
                peer_ik: peer,
                from_me: i % 2 == 0,
                text: format!("message {i}").into_bytes(),
                ts: 1_000 + i,
            })
            .unwrap();
        }

        for peer in [a, b, c] {
            let full: Vec<_> =
                s.load_history().unwrap().into_iter().filter(|r| r.peer_ik == peer).collect();
            let indexed = s.load_history_for_peer(&peer).unwrap();
            assert_eq!(indexed.len(), 10, "each peer has ten records");
            assert_eq!(indexed, full, "the indexed read disagrees with a full scan");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The index catches up with messages appended after it was last written, and appends never
    /// touch it. Being behind is its ordinary state, not an error state.
    #[test]
    fn the_index_catches_up_with_records_appended_since_it_was_built() {
        let dir = std::env::temp_dir().join(format!("karst-hidx-late-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        let peer = [0x5A; 32];

        s.append_history(&HistoryRecord { peer_ik: peer, from_me: true, text: b"one".to_vec(), ts: 1 })
            .unwrap();
        assert_eq!(s.load_history_for_peer(&peer).unwrap().len(), 1); // builds the index
        assert!(s.history_index_path().exists(), "the index was not persisted");

        // Two more, written by the ordinary append path, which knows nothing about the index.
        for (n, t) in [(b"two".to_vec(), 2u64), (b"three".to_vec(), 3)] {
            s.append_history(&HistoryRecord { peer_ik: peer, from_me: false, text: n, ts: t })
                .unwrap();
        }
        let got = s.load_history_for_peer(&peer).unwrap();
        assert_eq!(got.len(), 3, "the index did not pick up records appended after it was built");
        assert_eq!(got[2].text, b"three".to_vec(), "order must follow the log");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A log that got SHORTER, then GREW again, must not be read through stale offsets.
    ///
    /// `load_history` truncates a torn tail, so this is a real sequence: crash mid-append, reopen
    /// (tail cut), keep chatting. The index now claims to have consumed bytes the log no longer
    /// has, and the records written after that point sit at offsets it never learned — so they
    /// are invisible to a peer read while present in a full scan.
    ///
    /// DISCRIMINATING, and it took two attempts to make it so. The first version only truncated
    /// and re-read, which passed even with the rebuild removed: `read_history_record_at` bounds-
    /// checks every offset, so stale ones were simply skipped and the answer came out right by
    /// accident. Growing the log after the truncation is what separates the two implementations.
    #[test]
    fn a_truncated_log_that_grows_again_is_not_read_through_stale_offsets() {
        let dir = std::env::temp_dir().join(format!("karst-hidx-trunc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        let peer = [0x77; 32];

        for i in 0..6u64 {
            s.append_history(&HistoryRecord {
                peer_ik: peer,
                from_me: false,
                text: format!("before {i}").into_bytes(),
                ts: i,
            })
            .unwrap();
        }
        assert_eq!(s.load_history_for_peer(&peer).unwrap().len(), 6); // index now covers all six

        // The torn tail `load_history` would cut.
        let path = dir.join("history.dat");
        let len = std::fs::metadata(&path).unwrap().len();
        OpenOptions::new().write(true).open(&path).unwrap().set_len(len / 2).unwrap();

        // …and the conversation continues, writing into the byte range the stale index still
        // believes it has already consumed.
        for i in 0..4u64 {
            s.append_history(&HistoryRecord {
                peer_ik: peer,
                from_me: true,
                text: format!("after {i}").into_bytes(),
                ts: 100 + i,
            })
            .unwrap();
        }

        let indexed = s.load_history_for_peer(&peer).unwrap();
        let full: Vec<_> =
            s.load_history().unwrap().into_iter().filter(|r| r.peer_ik == peer).collect();
        assert_eq!(indexed, full, "a peer read must never disagree with the log it derives from");
        assert!(
            indexed.iter().any(|r| r.text.starts_with(b"after")),
            "the records written after the truncation went missing from the peer read"
        );
    }

    /// A corrupt or foreign index is rebuilt silently. It is a cache: it may be deleted, damaged
    /// or written by a key we no longer hold, and none of that may cost a message.
    #[test]
    fn a_damaged_index_is_rebuilt_instead_of_failing_the_read() {
        let dir = std::env::temp_dir().join(format!("karst-hidx-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        let peer = [0x33; 32];
        for i in 0..4u64 {
            s.append_history(&HistoryRecord { peer_ik: peer, from_me: true, text: vec![b'x'], ts: i })
                .unwrap();
        }
        assert_eq!(s.load_history_for_peer(&peer).unwrap().len(), 4);

        std::fs::write(s.history_index_path(), b"not a sealed index at all").unwrap();
        assert_eq!(
            s.load_history_for_peer(&peer).unwrap().len(),
            4,
            "a damaged cache must rebuild, never lose a message"
        );

        std::fs::remove_file(s.history_index_path()).unwrap();
        assert_eq!(s.load_history_for_peer(&peer).unwrap().len(), 4, "a missing cache must rebuild");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The index file's LENGTH must not track how many contacts you have or how much you talk to
    /// them. The contents are sealed; the size is not, so the size is rounded off.
    ///
    /// DISCRIMINATING: drop the padding and the file grows with every few records, which is a
    /// per-contact activity signal readable by anyone who can see the directory listing.
    #[test]
    fn the_index_file_size_is_quantised() {
        let dir = std::env::temp_dir().join(format!("karst-hidx-pad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();

        let mut sizes = Vec::new();
        for i in 0..40u64 {
            s.append_history(&HistoryRecord {
                peer_ik: [(i % 7) as u8; 32],
                from_me: false,
                text: vec![b'y'; 64],
                ts: i,
            })
            .unwrap();
            let _ = s.load_history_for_peer(&[0u8; 32]).unwrap(); // refresh + persist
            sizes.push(std::fs::metadata(s.history_index_path()).unwrap().len());
        }
        sizes.dedup();
        assert!(
            sizes.len() <= 2,
            "the index size moved {} times over 40 records — it is tracking activity: {sizes:?}",
            sizes.len()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The cost of opening a chat must stop scaling with the rest of the account.
    ///
    /// Counted, not timed: a wall-clock assertion in CI is a flake waiting to happen, and the
    /// claim being made is about WORK, not milliseconds. One peer holds a handful of messages
    /// while another holds many; opening the small chat must not pay for the large one, which is
    /// measured by how many records the read has to AEAD-open.
    #[test]
    fn opening_a_small_chat_does_not_pay_for_a_large_one() {
        let dir = std::env::temp_dir().join(format!("karst-hidx-cost-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        let (chatty, quiet) = ([0x0C; 32], [0x0D; 32]);

        for i in 0..200u64 {
            s.append_history(&HistoryRecord {
                peer_ik: chatty,
                from_me: false,
                text: vec![b'z'; 32],
                ts: i,
            })
            .unwrap();
        }
        for i in 0..3u64 {
            s.append_history(&HistoryRecord {
                peer_ik: quiet,
                from_me: true,
                text: b"hi".to_vec(),
                ts: 1_000 + i,
            })
            .unwrap();
        }

        let _ = s.load_history_for_peer(&quiet).unwrap(); // build the index once
        let index = s.load_history_index();
        let quiet_offsets = index.peers.iter().find(|(p, _)| *p == quiet).unwrap().1.len();
        let total: usize = index.peers.iter().map(|(_, o)| o.len()).sum();

        assert_eq!(quiet_offsets, 3, "the quiet chat is three records");
        assert_eq!(total, 203, "the log really does hold 203 records");
        assert_eq!(
            s.load_history_for_peer(&quiet).unwrap().len(),
            3,
            "opening the quiet chat must read three records, not 203"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
