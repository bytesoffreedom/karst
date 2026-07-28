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
use node::peer::PeerState;
use node::pqxdh::Account;
use node::seal::Identity;
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
pub struct StoredAttachment {
    pub index: u32,
    pub kind: u8,
    pub name: String,
    pub bytes: Vec<u8>,
    /// A terminal FAILURE marker (blob-transport path): the fetch gave up (blob swept, hash
    /// mismatch, past TTL) so the bytes will never arrive. Kept as a zero-byte marker (not silently
    /// dropped) so the feed can show an error tile instead of the attachment just vanishing. A later
    /// successful fetch at the same index replaces it. Appended field → `serde(default)` so older
    /// sidecars (which never carry a failure) load as `false`.
    #[serde(default)]
    pub failed: bool,
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
    /// "retry me" idempotently. Zero for a legacy record / the inline (non-blob) path.
    /// postcard-positional: appended last; old records load via the scan fallback.
    #[serde(default)]
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
    #[serde(default)]
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
    /// re-run command, so it stores `None`). postcard-positional: appended last, `serde(default)`
    /// so an older record loads.
    #[serde(default)]
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
const MAX_HISTORY_RECORD: usize = 1 << 20; // 1 MiB — с запасом на любой текст

/// Cap on the number of cached peer profiles (anti-flood from unknown IKs).
const MAX_PEER_PROFILES: usize = 10_000;
/// Cap on connection proxies in one root's registry. Generous for real use (one per contact/group
/// over a long time) while bounding `proxies.dat` and the poll fan-out that iterates them.
const MAX_PROXIES: usize = 10_000;
/// Cap on channel subscribers (people who follow your posts). Anti-Sybil: a flood of join
/// requests to a channel can't grow `subscribers.dat` without bound; on overflow new joins are
/// refused (existing subscribers keep working). Generous for a real channel on this tier.
const MAX_SUBSCRIBERS: usize = 50_000;
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

/// Clone is a cheap handle (a path + the derived key), so an off-loop transfer thread
/// can seal straight into the vault instead of staging plaintext on disk.
#[derive(Clone)]
pub struct Store {
    dir: PathBuf,
    key: MasterKey,
    /// PROXY MODE (proxy-identity model). `None` = root store — identical paths and the frozen
    /// root `derive`, so existing behaviour is byte-for-byte unchanged (the regression guard).
    /// `Some(index)` = act AS that proxy: `load_account`/`load_identity` return the HD-derived
    /// proxy identity, and the IDENTITY-keyed network files (sessions/opks/discovery) are
    /// namespaced by index so proxies never cross session/ratchet state. DEVICE/RELAY-scoped
    /// state (the relay capability, blob transfer queues) and all DATA (contacts/history/feed/
    /// profile/…) stay on the root paths, one copy — a proxy is a channel, not a persona.
    proxy: Option<u32>,
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
    buf: Vec<u8>,
}

impl SealedFileWriter {
    fn record(file: &mut std::fs::File, key: &MasterKey, plain: &[u8]) -> io::Result<()> {
        let sealed = key.seal(plain);
        let len: u32 = sealed.len().try_into().map_err(|_| io_err("sealed record too large"))?;
        file.write_all(&len.to_le_bytes())?;
        file.write_all(&sealed)
    }

    /// Seal whatever is buffered and finish the file (fsync). MUST be called — a
    /// dropped writer leaves the tail unwritten.
    pub fn finish(mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let buf = std::mem::take(&mut self.buf);
            Self::record(&mut self.file, &self.key, &buf)?;
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
            Self::record(&mut self.file, &self.key, &buf)?;
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
            Self::record(&mut self.file, &self.key, &chunk)?;
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

/// Верификатор пароля: при первом разе запечатать известную константу, далее
/// сверять. Ловит НЕВЕРНЫЙ пароль СРАЗУ (fail-fast), до любой записи секрета.
fn check_or_seal_verify(dir: &std::path::Path, key: &MasterKey) -> io::Result<()> {
    let verify_path = dir.join("verify");
    match std::fs::read(&verify_path) {
        Ok(blob) => {
            let ok = key.open(&blob).map(|p| p == VERIFY_CONST).unwrap_or(false);
            if !ok {
                return Err(io_err("неверный пароль"));
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let blob = key.seal(VERIFY_CONST);
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
        Ok(Store { dir, key, proxy: None })
    }

    /// Store поверх УЖЕ выведенного vault-ключа (salt/verify проверены на уровне
    /// базы). Не трогает salt/verify — их у аккаунт-подкаталога нет. Переключение
    /// аккаунтов = сменить `dir`, переиспользовать тот же `key` (без Argon2).
    pub fn at(dir: impl Into<PathBuf>, key: MasterKey) -> Self {
        Store { dir: dir.into(), key, proxy: None }
    }

    /// A handle onto the SAME vault dir + key that acts AS proxy `index` (proxy-identity model):
    /// `load_account`/`load_identity` return that proxy's HD-derived identity, and the network
    /// files are namespaced by index. Data files are unchanged (root-owned). Cheap clone.
    pub fn as_proxy(&self, index: u32) -> Store {
        Store { dir: self.dir.clone(), key: self.key.clone(), proxy: Some(index) }
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
                let bytes = self.key.open(&blob).map_err(io_err)?;
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
        let bytes = self.key.seal(&plain);
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
                let bytes = self.key.open(&blob).map_err(io_err)?;
                postcard::from_bytes(&bytes).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(RelayPrefs::default()),
            Err(e) => Err(e),
        }
    }

    /// Atomically save the relay-selection preferences (temp 0600 → fsync → rename), encrypted.
    pub fn save_relay_prefs(&self, prefs: &RelayPrefs) -> io::Result<()> {
        let plain = postcard::to_stdvec(prefs).map_err(io_err)?;
        let bytes = self.key.seal(&plain);
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
                let bytes = self.key.open(&blob).map_err(io_err)?;
                postcard::from_bytes(&bytes).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Prefs::default()),
            Err(e) => Err(e),
        }
    }

    /// Atomically save the privacy preferences (temp 0600 → fsync → rename), encrypted.
    pub fn save_prefs(&self, prefs: &Prefs) -> io::Result<()> {
        let plain = postcard::to_stdvec(prefs).map_err(io_err)?;
        let bytes = self.key.seal(&plain);
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
        SealedFileWriter::record(&mut file, &self.key, name.as_bytes())?;
        Ok((id, SealedFileWriter { file, key: self.key.clone(), buf: Vec::new() }))
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
    fn read_record(f: &mut File, key: &MasterKey) -> io::Result<Option<Vec<u8>>> {
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
        key.open(&sealed).map(Some).map_err(io_err)
    }

    /// The (sealed) original name of a received file.
    pub fn received_file_name(&self, id: &str) -> io::Result<String> {
        let mut f = File::open(self.file_path(id))?;
        let rec = Self::read_record(&mut f, &self.key)?.ok_or_else(|| io_err("empty file record"))?;
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
        Self::read_record(&mut f, &self.key)?.ok_or_else(|| io_err("empty file record"))?;
        let mut out =
            OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(dest)?;
        while let Some(chunk) = Self::read_record(&mut f, &self.key)? {
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
        Self::read_record(&mut f, &self.key)?.ok_or_else(|| io_err("empty file record"))?;
        let mut out = Vec::new();
        while let Some(chunk) = Self::read_record(&mut f, &self.key)? {
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
        let blob = self.key.seal(&plain);
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
            let plain = match self.key.open(&bytes[start..end]) {
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
    fn seal_versioned(&self, version: u8, plain: &[u8]) -> Vec<u8> {
        let mut framed = Vec::with_capacity(5 + plain.len());
        framed.extend_from_slice(FORMAT_MAGIC);
        framed.push(version);
        framed.extend_from_slice(plain);
        self.key.seal(&framed)
    }

    /// Open a version-enveloped blob → `(version, inner)`. `None` if it does not decrypt or
    /// lacks the magic (e.g. a pre-versioning blob), so the caller can fall back / reset.
    fn open_versioned(&self, blob: &[u8]) -> Option<(u8, Vec<u8>)> {
        let plain = self.key.open(blob).ok()?;
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
            Ok(blob) => Ok(match self.open_versioned(&blob) {
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
        self.write_atomic(&self.downloads_path(), &self.seal_versioned(DOWNLOADS_VERSION, &plain))
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
            return Ok(()); // over cap: drop the announcement rather than grow unbounded
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
                while let Ok(Some(_)) = Self::read_record(&mut f, &self.key) {
                    records += 1;
                    last_good = f.stream_position()?;
                }
                if records >= 1 {
                    // Truncate the torn tail BEFORE appending — else [good][garbage][new]
                    // never hashes and the download is stuck forever.
                    OpenOptions::new().write(true).open(&path)?.set_len(last_good)?;
                    let file = OpenOptions::new().append(true).mode(0o600).open(&path)?;
                    let writer = SealedFileWriter { file, key: self.key.clone(), buf: Vec::new() };
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
        while let Some(rec) = Self::read_record(&mut f, &self.key)? {
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
            Ok(blob) => Ok(match self.open_versioned(&blob) {
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
        self.write_atomic(&self.post_attachments_path(), &self.seal_versioned(POST_ATTACH_VERSION, &plain))
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
            return Ok(()); // over cap: drop the announcement rather than grow unbounded
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
            Ok(blob) => Ok(match self.open_versioned(&blob) {
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
        self.write_atomic(&self.pending_galleries_path(), &self.seal_versioned(PENDING_GALLERY_VERSION, &plain))
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
            return Ok(()); // over cap: drop rather than grow unbounded
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
                    .open_versioned(&blob)
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
        self.write_atomic(&self.uploads_path(), &self.seal_versioned(UPLOADS_VERSION, &plain))
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
        self.dir.join("capability.dat")
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

    pub fn has_capability(&self) -> bool {
        self.capability_path().exists()
    }

    /// Записать корень (энтропию фразы). `create_new` → НЕ перезаписывает: смена
    /// корня сменила бы IK/владение mailbox → осиротила бы всё запечатанное на
    /// старую личность и все сессии. Права 0600 при СОЗДАНИИ. Provisioning
    /// (create/restore) кладёт сюда энтропию свежей/введённой фразы.
    pub fn save_seed(&self, entropy: &[u8; crate::seed::ENTROPY_BYTES]) -> io::Result<()> {
        let blob = self.key.seal(entropy);
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
        let secret = self.key.open(&blob).map_err(io_err)?;
        secret
            .as_slice()
            .try_into()
            .map_err(|_| io_err("seed: не 16 байт энтропии"))
    }

    /// seal-ключ (relay-facing) — **выводится** из корня, не хранится отдельно. В proxy-режиме —
    /// seal этого прокси (тот же отдельный HD-домен, что и account прокси).
    pub fn load_identity(&self) -> io::Result<Identity> {
        let ent = self.load_entropy()?;
        Ok(match self.proxy {
            None => crate::seed::derive(&ent).seal,
            Some(idx) => crate::seed::derive_proxy(&ent, idx).seal,
        })
    }

    /// §2.1-account (ik‖prekey‖KEM) — **выводится** из корня, не хранится отдельно. В proxy-режиме
    /// возвращает личность ПРОКСИ (`derive_proxy`), поэтому весь session-слой (mailbox = IK,
    /// ownership-proof, ratchet) работает как этот прокси, а не как корень. Это единственное место,
    /// где сетевой identity подменяется — все сетевые операции идут через него.
    pub fn load_account(&self) -> io::Result<Account> {
        let ent = self.load_entropy()?;
        Ok(match self.proxy {
            None => crate::seed::derive(&ent).account,
            Some(idx) => crate::seed::derive_proxy(&ent, idx).account,
        })
    }

    /// Сохранить capability (импорт можно повторять → перезапись разрешена).
    /// Секрет capability = admission-credential → шифруется at-rest (как остальные
    /// секреты), а не только 0600. Дев-capability публична, но `import-cap` примет
    /// и настоящую — единый режим, без исключения.
    pub fn save_capability(&self, cap: &Capability) -> io::Result<()> {
        let json = serde_json::to_vec(cap).map_err(io_err)?;
        let blob = self.key.seal(&json);
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(self.capability_path())?;
        f.write_all(&blob)
    }

    pub fn load_capability(&self) -> io::Result<Capability> {
        let blob = std::fs::read(self.capability_path())?;
        let json = self.key.open(&blob).map_err(io_err)?;
        serde_json::from_slice(&json).map_err(io_err)
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
        let blob = self.key.seal(secret);
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
        let secret = self.key.open(&blob).map_err(io_err)?;
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

    // ----- Контакты (имена + флаг сверки), шифрованы at-rest -----

    fn contacts_path(&self) -> PathBuf {
        self.dir.join("contacts.dat")
    }

    /// Загрузить контакты (пусто, если файла нет). Расшифровывается at-rest-ключом.
    pub fn load_contacts(&self) -> io::Result<Vec<ContactRecord>> {
        match std::fs::read(self.contacts_path()) {
            Ok(blob) => {
                let bytes = self.key.open(&blob).map_err(io_err)?;
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
        let bytes = self.key.seal(&plain);
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
                let bytes = self.key.open(&blob).map_err(io_err)?;
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
        let bytes = self.key.seal(&plain);
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

    fn unconfirmed_path(&self) -> PathBuf {
        self.dir.join("unconfirmed.dat")
    }

    /// The set of chat-only peers (not confirmed contacts). Empty if the file is missing.
    pub fn load_unconfirmed(&self) -> io::Result<BTreeSet<[u8; 32]>> {
        match std::fs::read(self.unconfirmed_path()) {
            Ok(blob) => {
                let bytes = self.key.open(&blob).map_err(io_err)?;
                postcard::from_bytes(&bytes).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
            Err(e) => Err(e),
        }
    }

    /// Flag / unflag `ik` as unconfirmed (chat-only). `true` = a conversation that is not a contact;
    /// `false` = confirmed contact (or never was chat-only). Idempotent; empty set removes the file.
    /// Atomic (temp→fsync→rename), single GUI writer, like `blocked`/`contacts`.
    pub fn set_unconfirmed(&self, ik: [u8; 32], unconfirmed: bool) -> io::Result<()> {
        let mut set = self.load_unconfirmed()?;
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
        let bytes = self.key.seal(&plain);
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
                let bytes = self.key.open(&blob).map_err(io_err)?;
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
        let bytes = self.key.seal(&plain);
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
                let bytes = self.key.open(&blob).map_err(io_err)?;
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
        let bytes = self.key.seal(&plain);
        let tmp = self.dir.join("pulled.dat.tmp");
        {
            let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, self.pulled_path())
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

    fn opks_path(&self) -> PathBuf {
        self.net_file("opks.dat")
    }

    /// Load persisted one-time prekey SECRETS (see `pqxdh::Account::export_opk_secrets`).
    /// A sidecar, deliberately SEPARATE from `account.key`: the long-lived identity is
    /// never touched, so there is no migration risk. Absent → empty (backward compatible).
    /// Encrypted at rest like every other secret file.
    /// Path of the sealed in-flight inline-transfer state (see `content::Reassembler::export`).
    fn partials_path(&self) -> PathBuf {
        self.net_file("partials.dat")
    }

    /// Persist the in-flight inline transfers, sealed. Called after a receive batch so a crash
    /// cannot lose chunks whose carrier messages were already acked (the relay drops those).
    pub fn save_partials(&self, blob: &[u8]) -> io::Result<()> {
        self.write_atomic(&self.partials_path(), &self.key.seal(blob))
    }

    /// Load the in-flight inline transfers. Absent = nothing was in flight; a file that EXISTS but
    /// cannot be opened is an ERROR, not "nothing" — treating corruption as empty is exactly the
    /// silent loss this state was added to prevent.
    pub fn load_partials(&self) -> io::Result<Vec<u8>> {
        match std::fs::read(self.partials_path()) {
            Ok(blob) => self.key.open(&blob).map_err(|e| {
                io_err(format!("in-flight transfers unreadable ({e}) — refusing to treat them as absent"))
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    pub fn load_opks(&self) -> io::Result<Vec<[u8; 32]>> {
        match std::fs::read(self.opks_path()) {
            // A file that exists but cannot be opened or decoded is an ERROR, not "no keys".
            // Returning an empty list made the client believe it held none, mint a fresh batch and
            // publish it — while the relay went on handing out the OLD public keys whose secrets
            // had just been declared missing. Every initiator that received one produced an opener
            // the recipient could no longer accept: silent, one-sided first-contact failure that
            // looks like the network dropping messages (R2-4). Absent is still legitimately empty.
            Ok(blob) => {
                let plain = self
                    .key
                    .open(&blob)
                    .map_err(|e| io_err(format!("one-time prekeys unreadable ({e}) — refusing to \
                         treat a corrupt sidecar as 'no keys'; restore it or re-provision")))?;
                postcard::from_bytes(&plain).map_err(|e| {
                    io_err(format!("one-time prekeys malformed ({e}) — refusing to treat a corrupt \
                         sidecar as 'no keys'"))
                })
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Atomically persist the one-time prekey secrets (full rewrite; the set is small and
    /// changes as a whole on top-up/consumption). **Private keys in the clear** — 0600.
    pub fn save_opks(&self, opks: &[[u8; 32]]) -> io::Result<()> {
        let plain = postcard::to_stdvec(opks).map_err(io_err)?;
        self.write_atomic(&self.opks_path(), &self.key.seal(&plain))
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
                .open(&blob)
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
        self.write_atomic(&self.extra_relays_path(), &self.key.seal(&plain))
    }

    /// Own profile (empty by default / best-effort on corruption).
    pub fn load_profile(&self) -> io::Result<Profile> {
        match std::fs::read(self.profile_path()) {
            Ok(blob) => Ok(self
                .key
                .open(&blob)
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
        self.write_atomic(&self.profile_path(), &self.key.seal(&plain))
    }

    /// Cache of contacts' profiles (empty by default / best-effort on corruption).
    pub fn load_peer_profiles(&self) -> io::Result<BTreeMap<[u8; 32], Profile>> {
        match std::fs::read(self.peer_profiles_path()) {
            Ok(blob) => Ok(self
                .key
                .open(&blob)
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
        self.write_atomic(&self.peer_profiles_path(), &self.key.seal(&plain))
    }

    /// Forget a peer's cached profile (on removing a contact). Idempotent.
    pub fn remove_peer_profile(&self, ik: [u8; 32]) -> io::Result<()> {
        let mut map = self.load_peer_profiles()?;
        if map.remove(&ik).is_none() {
            return Ok(());
        }
        let plain = postcard::to_stdvec(&map).map_err(io_err)?;
        self.write_atomic(&self.peer_profiles_path(), &self.key.seal(&plain))
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
        self.write_atomic(&self.peer_profiles_path(), &self.key.seal(&plain))
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
        self.write_atomic(&self.peer_profiles_path(), &self.key.seal(&plain))
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
                .open(&blob)
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
        self.write_atomic(&self.feed_path(), &self.key.seal(&plain))
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
        self.write_atomic(&self.feed_path(), &self.key.seal(&plain))?;
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
            .and_then(|b| self.key.open(&b).ok())
            .and_then(|b| postcard::from_bytes(&b).ok())
            .unwrap_or_default()
    }

    fn write_feed_images(&self, map: &BTreeMap<([u8; 32], [u8; 16]), Vec<u8>>) -> io::Result<()> {
        let plain = postcard::to_stdvec(map).map_err(io_err)?;
        self.write_atomic(&self.feed_images_path(), &self.key.seal(&plain))
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
            .and_then(|b| self.key.open(&b).ok())
            .and_then(|b| postcard::from_bytes(&b).ok())
            .unwrap_or_default()
    }

    fn write_feed_attachments(&self, map: &BTreeMap<([u8; 32], [u8; 16]), Vec<StoredAttachment>>) -> io::Result<()> {
        let plain = postcard::to_stdvec(map).map_err(io_err)?;
        self.write_atomic(&self.feed_attachments_path(), &self.key.seal(&plain))
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
            .and_then(|b| self.key.open(&b).ok())
            .and_then(|b| postcard::from_bytes(&b).ok())
            .unwrap_or_default()
    }

    /// Write the channel-mode flag. SECURITY: CALL ONLY from the password-gated `set_channel_mode`
    /// command — no received-message path may ever reach this. The invariant is auditable: this is
    /// the ONLY writer of `channel.dat`, and `grep 'save_channel('` must show exactly that one
    /// gated caller (the receive handlers touch subscribers/pending, never this).
    pub fn save_channel(&self, cfg: &ChannelConfig) -> io::Result<()> {
        let plain = postcard::to_stdvec(cfg).map_err(io_err)?;
        self.write_atomic(&self.channel_path(), &self.key.seal(&plain))
    }

    fn subscribers_path(&self) -> PathBuf {
        self.dir.join("subscribers.dat")
    }

    /// Everyone subscribed to our posts (own audience for public posts).
    pub fn load_subscribers(&self) -> Vec<Subscriber> {
        std::fs::read(self.subscribers_path())
            .ok()
            .and_then(|b| self.key.open(&b).ok())
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
        self.write_atomic(&self.subscribers_path(), &self.key.seal(&plain))?;
        Ok(true)
    }

    /// Remove a subscriber (they stop receiving future posts). Idempotent.
    pub fn remove_subscriber(&self, ik: [u8; 32]) -> io::Result<()> {
        let mut subs = self.load_subscribers();
        subs.retain(|s| s.ik != ik);
        let plain = postcard::to_stdvec(&subs).map_err(io_err)?;
        self.write_atomic(&self.subscribers_path(), &self.key.seal(&plain))
    }

    fn contact_requests_path(&self) -> PathBuf {
        self.dir.join("contact_requests.dat")
    }

    /// Incoming CONTACT requests awaiting my accept/decline (mutual-consent add). IK list; the
    /// requester's name/bio live in `peer_profiles` (set when the request arrived).
    pub fn load_contact_requests(&self) -> Vec<[u8; 32]> {
        std::fs::read(self.contact_requests_path())
            .ok()
            .and_then(|b| self.key.open(&b).ok())
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
        self.write_atomic(&self.contact_requests_path(), &self.key.seal(&plain))?;
        Ok(true)
    }

    /// Drop a contact request (after accept or decline). Idempotent.
    pub fn remove_contact_request(&self, ik: [u8; 32]) -> io::Result<()> {
        let mut p = self.load_contact_requests();
        p.retain(|x| *x != ik);
        let plain = postcard::to_stdvec(&p).map_err(io_err)?;
        self.write_atomic(&self.contact_requests_path(), &self.key.seal(&plain))
    }

    fn pending_subs_path(&self) -> PathBuf {
        self.dir.join("pending_subs.dat")
    }

    /// Join requests awaiting MANUAL approval (private account). IK list.
    pub fn load_pending_subs(&self) -> Vec<[u8; 32]> {
        std::fs::read(self.pending_subs_path())
            .ok()
            .and_then(|b| self.key.open(&b).ok())
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
        self.write_atomic(&self.pending_subs_path(), &self.key.seal(&plain))?;
        Ok(true)
    }

    /// Drop a pending request (after approve or reject).
    pub fn remove_pending_sub(&self, ik: [u8; 32]) -> io::Result<()> {
        let mut p = self.load_pending_subs();
        p.retain(|x| *x != ik);
        let plain = postcard::to_stdvec(&p).map_err(io_err)?;
        self.write_atomic(&self.pending_subs_path(), &self.key.seal(&plain))
    }

    fn channel_peers_path(&self) -> PathBuf {
        self.dir.join("channel_peers.dat")
    }

    /// IKs we KNOW are channels (learned from a `JoinAccept{is_channel:true}`) — for the contact
    /// list's channel badge. A hint, like a cached peer profile; never a trust anchor.
    pub fn load_channel_peers(&self) -> Vec<[u8; 32]> {
        std::fs::read(self.channel_peers_path())
            .ok()
            .and_then(|b| self.key.open(&b).ok())
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
        self.write_atomic(&self.channel_peers_path(), &self.key.seal(&plain))
    }

    // ----- Connection proxies: disposable HD-derived channels (proxy-identity model) -----
    //
    // The registry (`proxies.dat`) lists indices/labels/active; the KEYS are never stored — they
    // re-derive from the seed via `seed::derive_proxy(entropy, index)`, so a proxy costs one small
    // record and is fully recoverable from the phrase. The contact→proxy tag is a SEPARATE sidecar
    // (`contact_proxy.dat`) so it never touches the postcard layout of `contacts.dat`.

    fn proxies_path(&self) -> PathBuf {
        self.dir.join("proxies.dat")
    }

    /// Every proxy in the registry (active and burned), oldest index first.
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
    /// from "cannot be authenticated" (present but undecryptable/malformed).
    pub fn try_load_proxies(&self) -> io::Result<Vec<ProxyEntry>> {
        match std::fs::read(self.proxies_path()) {
            Ok(b) => {
                let plain = self
                    .key
                    .open(&b)
                    .map_err(|e| io_err(format!("proxy list fails authentication: {e}")))?;
                let mut v: Vec<ProxyEntry> = postcard::from_bytes(&plain)
                    .map_err(|e| io_err(format!("proxy list malformed: {e}")))?;
                v.sort_by_key(|p| p.index);
                Ok(v)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    fn save_proxies(&self, list: &[ProxyEntry]) -> io::Result<()> {
        let plain = postcard::to_stdvec(list).map_err(io_err)?;
        self.write_atomic(&self.proxies_path(), &self.key.seal(&plain))
    }

    /// Mint a new proxy: the next unused index gets a registry entry. Keys are NOT stored (they
    /// derive from the seed). Bounded by `MAX_PROXIES`. Returns the new entry.
    pub fn create_proxy(&self, label: &str, now: u64) -> io::Result<ProxyEntry> {
        let mut list = self.load_proxies();
        if list.len() >= MAX_PROXIES {
            return Err(io_err("too many proxies"));
        }
        let index = list.iter().map(|p| p.index).max().map(|m| m + 1).unwrap_or(0);
        let entry = ProxyEntry {
            index,
            label: clamp_str(label, crate::content::MAX_PROFILE_NAME),
            created_at: now,
            active: true,
        };
        list.push(entry.clone());
        self.save_proxies(&list)?;
        Ok(entry)
    }

    /// Burn / un-burn a proxy (flip `active`). Burning stops offering it; its keys stay derivable
    /// so any last in-flight mail still decrypts. Idempotent.
    pub fn set_proxy_active(&self, index: u32, active: bool) -> io::Result<()> {
        let mut list = self.load_proxies();
        let Some(p) = list.iter_mut().find(|p| p.index == index) else { return Ok(()) };
        if p.active == active {
            return Ok(());
        }
        p.active = active;
        self.save_proxies(&list)
    }

    /// The derived identity (seal ‖ account) for proxy `index` — recomputed from the seed on
    /// demand, never stored. The network layer uses this to publish that proxy's bundle and run
    /// its sessions. `Err` if the seed is unreadable.
    pub fn proxy_identity(&self, index: u32) -> io::Result<crate::seed::DerivedIdentity> {
        Ok(crate::seed::derive_proxy(&self.load_entropy()?, index))
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
                .open(&b)
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
    pub fn migrate_contact_ik(&self, old: [u8; 32], new: [u8; 32]) -> io::Result<bool> {
        let mut cs = self.load_contacts()?;
        let Some(c) = cs.iter_mut().find(|c| c.ik == old) else { return Ok(false) };
        c.ik = new;
        c.verified = false; // new key ⇒ old safety number no longer applies
        self.save_contacts(&cs)?;
        // Carry the local "which of MY proxies reaches them" tag onto the new IK.
        if let Some(idx) = self.contact_proxy(&old) {
            let mut map = self.load_contact_proxy();
            map.remove(&old);
            map.insert(new, idx);
            let plain = postcard::to_stdvec(&map).map_err(io_err)?;
            self.write_atomic(&self.contact_proxy_path(), &self.key.seal(&plain))?;
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
            self.write_atomic(&self.peer_profiles_path(), &self.key.seal(&plain))?;
        }
        Ok(true)
    }

    /// Tag which proxy reaches a contact (the channel they know you through).
    pub fn set_contact_proxy(&self, ik: [u8; 32], index: u32) -> io::Result<()> {
        let mut map = self.load_contact_proxy();
        if map.get(&ik) == Some(&index) {
            return Ok(());
        }
        map.insert(ik, index);
        let plain = postcard::to_stdvec(&map).map_err(io_err)?;
        self.write_atomic(&self.contact_proxy_path(), &self.key.seal(&plain))
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
        file.lock()?; // блокирующий эксклюзив; снятие — на drop файла
        Ok(SessionLock { _file: file })
    }

    /// Загрузить персистентное состояние сессий (пусто, если файла нет).
    /// Держите `lock_sessions` вокруг load→save. Расшифровывается at-rest-ключом.
    pub fn load_sessions(&self) -> io::Result<PeerState> {
        match std::fs::read(self.sessions_path()) {
            Ok(blob) => {
                let bytes = self.key.open(&blob).map_err(io_err)?;
                // Tolerate a state file written before the outbox field: never brick an
                // in-flight ratchet to add a field (see `PeerState::from_bytes_compat`).
                PeerState::from_bytes_compat(&bytes).map_err(io_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(PeerState::empty()),
            Err(e) => Err(e),
        }
    }

    /// АТОМАРНО сохранить состояние сессий: шифруем в памяти → temp (0600) →
    /// fsync → rename поверх. Крах на середине записи не оставит усечённый/битый
    /// файл (иначе — wedge/потеря позиции). temp в том же каталоге (rename атомарен
    /// в пределах ФС). Ratchet-ключи шифруются at-rest перед записью.
    pub fn save_sessions(&self, state: &PeerState) -> io::Result<()> {
        let plain = postcard::to_stdvec(state).map_err(io_err)?;
        let bytes = self.key.seal(&plain);
        let tmp = self.net_file("sessions.dat.tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?; // durability до rename
        }
        rename_durable(&tmp, &self.sessions_path())
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

    fn history_path(&self) -> PathBuf {
        self.dir.join("history.dat")
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
        self.append_history_with_id(rec, msg_id)
    }

    fn append_history_with_id(&self, rec: &HistoryRecord, msg_id: [u8; 32]) -> io::Result<()> {
        let plain = postcard::to_stdvec(&StoredHistory { rec: rec.clone(), msg_id }).map_err(io_err)?;
        let blob = self.key.seal(&plain);
        let len: u32 =
            blob.len().try_into().map_err(|_| io_err("запись истории слишком велика"))?;
        let _lock = self.lock_history()?;
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(self.history_path())?;
        let mut framed = Vec::with_capacity(4 + blob.len());
        framed.extend_from_slice(&len.to_le_bytes());
        framed.extend_from_slice(&blob);
        f.write_all(&framed)?; // одна запись под O_APPEND + замок
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
                break; // абсурдная длина → граница мусора
            }
            let start = off + 4;
            let end = match start.checked_add(len) {
                Some(e) if e <= bytes.len() => e,
                _ => break, // запись не помещается → рваный хвост
            };
            let plain = match self.key.open(&bytes[start..end]) {
                Ok(p) => p,
                Err(_) => break, // не расшифровалась → граница
            };
            // Try the current layout (with `msg_id`) first; fall back to a pre-`msg_id` bare
            // `HistoryRecord` (postcard errors on the missing trailing field, and try-new-first
            // because it would otherwise ignore trailing bytes). Old records get a zero id,
            // which never matches a real `payload_id`, so they simply don't dedup.
            let stored = match postcard::from_bytes::<StoredHistory>(&plain) {
                Ok(s) => s,
                Err(_) => match postcard::from_bytes::<HistoryRecord>(&plain) {
                    Ok(rec) => StoredHistory { rec, msg_id: [0u8; 32] },
                    Err(_) => break,
                },
            };
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

    /// The `payload_id`s of the last `limit` INCOMING history records — the dedup set for the
    /// plaintext-first receive path. Only the recent tail is logically needed (a redelivered
    /// duplicate arises only in the crash-before-ratchet-save window and reappears on the very
    /// next poll, so its twin is among the newest records), but the framed append-log has no
    /// reverse index, so this currently reads and AEAD-opens the WHOLE file and then slices the
    /// tail. That is a full-history decrypt per poll for a large log — acceptable for now,
    /// flagged as a follow-up (a record index / reverse scan would bound it). Zeroed ids
    /// (outgoing / pre-`msg_id` legacy) are excluded — they never match a real id.
    pub fn recent_incoming_ids(&self, limit: usize) -> io::Result<std::collections::HashSet<[u8; 32]>> {
        let _lock = self.lock_history()?;
        let bytes = match std::fs::read(self.history_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Default::default()),
            Err(e) => return Err(e),
        };
        let (records, _) = self.scan_history(&bytes);
        let start = records.len().saturating_sub(limit);
        Ok(records[start..]
            .iter()
            .filter(|s| !s.rec.from_me && s.msg_id != [0u8; 32])
            .map(|s| s.msg_id)
            .collect())
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
            return Ok(removed); // нечего менять — не трогаем файл
        }
        let mut out = Vec::new();
        for stored in kept {
            // Re-seal the WHOLE stored record (rec + msg_id) so a rewrite (deletion / expiry)
            // preserves the dedup id of the records it keeps.
            let plain = postcard::to_stdvec(stored).map_err(io_err)?;
            let blob = self.key.seal(&plain);
            let len: u32 =
                blob.len().try_into().map_err(|_| io_err("запись истории слишком велика"))?;
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
        let plain = match self.key.open(&blob) {
            Ok(p) => p,
            Err(_) => return MetaMap::new(), // не наш/битый → пусто, не паника
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
        let bytes = self.key.seal(&plain);
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
            return Err(io_err("эмодзи реакции вне лимита длины"));
        }
        let _lock = self.lock_meta()?;
        let mut map = self.load_meta_unlocked();
        if add {
            // Новый msg_id — только если не переполним карту (анти-память-DoS).
            if !map.contains_key(&msg_id) && map.len() >= MAX_META_MESSAGES {
                return Err(io_err("слишком много сообщений с метаданными"));
            }
            let mm = map.entry(msg_id).or_default();
            if !mm.reactions.contains_key(emoji) && mm.reactions.len() >= MAX_REACTIONS_PER_MSG {
                return Err(io_err("слишком много разных реакций на сообщение"));
            }
            let authors = mm.reactions.entry(emoji.to_string()).or_default();
            if !authors.contains(&author_ik) && authors.len() >= MAX_AUTHORS_PER_REACTION {
                return Err(io_err("слишком много авторов одной реакции"));
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
            return Err(io_err("слишком много сообщений с метаданными"));
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
            return Err(io_err("текст правки вне лимита длины"));
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
            return Err(io_err("слишком много сообщений с метаданными"));
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
        let k = *map.keys().next_back().expect("непусто");
        map.remove(&k);
    }
    for mm in map.values_mut() {
        while mm.reactions.len() > MAX_REACTIONS_PER_MSG {
            let k = mm.reactions.keys().next_back().expect("непусто").clone();
            mm.reactions.remove(&k);
        }
        for authors in mm.reactions.values_mut() {
            while authors.len() > MAX_AUTHORS_PER_REACTION {
                let a = *authors.iter().next_back().expect("непусто");
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

/// One CONNECTION PROXY in the root's registry (`proxies.dat`) — a disposable HD-derived channel
/// (see docs/design/proxy-identity.md). Carries only what a channel needs: its HD `index` (the
/// keys are re-derived deterministically via `seed::derive_proxy(entropy, index)`, never stored),
/// a human `label`, when it was made, and whether it is `active` (burning a proxy flips this off —
/// its keys stay derivable for in-flight mail but it is no longer offered/rotated to). A proxy owns
/// NO contacts/profile/feed — those are the root's, one copy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyEntry {
    pub index: u32,
    pub label: String,
    pub created_at: u64,
    pub active: bool,
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
    /// `serde(default)` so configs written before this field still load.
    #[serde(default)]
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
/// policy (`node::node::RelayPolicy`). Empty = no preference (any relay).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPrefs {
    /// Prefer relays whose advertised blob persistence matches; `None` = don't care. The
    /// advertisement is operator-declared (durable is provable via `verify_durability`; ephemeral
    /// is a claim), so this is a preference, not a hard guarantee.
    pub prefer_persistence: Option<node::node::BlobPersistence>,
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
/// Sealed slot length: `MAGIC(4) ‖ nonce(24) ‖ ct(SLOT_PLAIN + 16 tag)`.
const SLOT_LEN: usize = 4 + 24 + SLOT_PLAIN + 16;

/// What a matching keyslot means for the password just entered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotRole {
    /// The real vault — the account(s) the owner actually uses.
    Real,
    /// A plausible, separate compartment (opened under coercion; hides the real one).
    Decoy,
    /// Not a login at all: entering this password crypto-erases everything.
    Wipe,
    /// Tier-2 OPAQUE HIDDEN VOLUME: this password opens the hidden container in `hidden.dat` — a
    /// fixed-size, always-present, random-looking region. Its slot sits in an otherwise-unused
    /// `slots.dat` slot (indistinguishable from unused) and is NOT recorded in the real `slotmap`, so
    /// its existence is undetectable even to someone holding the OUTER (real/decoy) password. See
    /// `set_hidden_container` and docs/design/duress-multipassword.md for the honest limits.
    Hidden,
}

impl SlotRole {
    fn to_byte(self) -> u8 {
        match self {
            SlotRole::Real => 0,
            SlotRole::Decoy => 1,
            SlotRole::Wipe => 2,
            SlotRole::Hidden => 3,
        }
    }
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(SlotRole::Real),
            1 => Some(SlotRole::Decoy),
            2 => Some(SlotRole::Wipe),
            3 => Some(SlotRole::Hidden),
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
    /// The password opened the Tier-2 OPAQUE HIDDEN container — carries its (bounded) decrypted
    /// payload. Its existence is undetectable to anyone holding the outer (real/decoy) password.
    Hidden(Vec<u8>),
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
    /// Appended field → `serde(default)`, so an older file reads as "never observed".
    #[serde(default)]
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

// ─── Tier-2 OPAQUE HIDDEN VOLUME (deniable, opt-in) ───────────────────────────────────────────────
//
// `base/hidden.dat` is a FIXED-SIZE region that EXISTS on every vault. Empty = random bytes; with a
// hidden volume = `seal_raw(fixed plaintext)` (nonce ‖ AEAD ct, NO magic) — both computationally
// indistinguishable from random, so its PRESENCE reveals nothing. The hidden password owns a `Hidden`
// slot placed in an otherwise-unused `slots.dat` slot and NOT recorded in the real `slotmap`, so even
// the outer (real/decoy) password cannot detect it. Layout inside: `[u32 len LE][payload][random]`.
//
// HONEST LIMITS (documented, not hidden): (1) a MULTI-SNAPSHOT adversary who sees the disk before and
// after you use the hidden volume can tell `hidden.dat` changed; (2) FS journaling / SSD wear-leveling
// can leave copies; (3) because the hidden slot is invisible to the slot directory, ADDING more
// passwords later can overwrite it (set it up last, TrueCrypt-style). This is a REFERENCE deniable
// container, not a guarantee against a forensic adversary.

/// Usable payload bytes of the hidden container (bounded — a secret note / key / small file).
pub const HIDDEN_CAP: usize = 60 * 1024;
/// Fixed plaintext length sealed into `hidden.dat`: a 4-byte length header + the capacity.
const HIDDEN_PLAIN: usize = 4 + HIDDEN_CAP;
/// On-disk `hidden.dat` length: `nonce(24) ‖ ct(HIDDEN_PLAIN) ‖ tag(16)` — ALWAYS this, never varies.
const HIDDEN_LEN: usize = 24 + HIDDEN_PLAIN + 16;

fn hidden_path(base: &std::path::Path) -> PathBuf {
    base.join("hidden.dat")
}

/// Fill `buf` with cryptographically-random bytes (reuses the blob RNG).
fn fill_random(buf: &mut [u8]) {
    let mut i = 0;
    while i < buf.len() {
        let r = crate::blob::random32();
        let n = (buf.len() - i).min(32);
        buf[i..i + n].copy_from_slice(&r[..n]);
        i += n;
    }
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

/// Ensure `hidden.dat` exists at the fixed size, RANDOM if absent — so EVERY vault carries the region
/// and its presence signals nothing. Never overwrites an existing one (that would wipe a real volume).
fn ensure_hidden(base: &std::path::Path) -> io::Result<()> {
    let p = hidden_path(base);
    if p.exists() {
        return Ok(());
    }
    let mut buf = vec![0u8; HIDDEN_LEN];
    fill_random(&mut buf);
    write_fixed_0600(&p, &buf)
}

/// Try to open the hidden container with `key` (the password just entered IS the hidden password).
/// `None` = wrong key or no hidden volume (indistinguishable). `Some(payload)` on success.
fn open_hidden_container(base: &std::path::Path, key: &MasterKey) -> Option<Vec<u8>> {
    let blob = std::fs::read(hidden_path(base)).ok()?;
    let plain = key.open_raw(&blob).ok()?;
    if plain.len() != HIDDEN_PLAIN {
        return None;
    }
    let len = u32::from_le_bytes(plain[..4].try_into().ok()?) as usize;
    if len > HIDDEN_CAP {
        return None;
    }
    Some(plain[4..4 + len].to_vec())
}

/// Place a `Hidden` slot for `hidden_key` in an unused `slots.dat` slot WITHOUT a slotmap entry (so it
/// stays invisible to the outer password). Overwrites the hidden key's own slot if re-setting.
fn slot_write_hidden(base: &std::path::Path, real_key: &MasterKey, hidden_key: &MasterKey) -> io::Result<()> {
    let mut slots = slots_load(base)?.unwrap_or_else(slots_fresh);
    // Avoid indices the real slotmap uses (so we don't clobber a known password); pick from the rest.
    let dir = slotdir_load(base, real_key)?;
    let taken: Vec<u8> = dir.iter().map(|e| e.index).collect();
    let idx = match slot_index_of(&slots, hidden_key) {
        Some(i) => i, // re-setting: overwrite the hidden key's own slot in place
        None => {
            let start = (crate::blob::random32()[0] as usize) % SLOT_COUNT;
            (0..SLOT_COUNT)
                .map(|k| (start + k) % SLOT_COUNT)
                .find(|&i| !taken.contains(&(i as u8)))
                .ok_or_else(|| io_err("no free keyslot for a hidden volume"))?
        }
    };
    // NB: NO slotmap entry — that invisibility is what makes it a hidden volume.
    slots[idx] = slot_seal(hidden_key, SlotRole::Hidden, &[0u8; 16]);
    slots_save(base, &slots)
}

/// Create/replace the opaque hidden container: seal `payload` (≤ `HIDDEN_CAP`) under `hidden_password`
/// into the fixed-size `hidden.dat`, and place its invisible `Hidden` slot. `real_key` is the current
/// (logged-in) real key — setting a hidden volume is a real-session action, and it's used only to
/// avoid clobbering known slots. Refuses a hidden password that collides with an existing slot.
pub fn set_hidden_container(
    base: &std::path::Path,
    real_key: &MasterKey,
    hidden_password: &[u8],
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > HIDDEN_CAP {
        return Err(io_err("hidden payload too large"));
    }
    let salt = read_or_create_salt(base)?;
    let hkey = MasterKey::derive(hidden_password, &salt).map_err(io_err)?;
    // A hidden password must not collide with the real/decoy/wipe passwords (that slot would win).
    if let Some(slots) = slots_load(base)? {
        if slots.iter().any(|s| hkey.open(s).is_ok()) {
            return Err(io_err("that password is already in use"));
        }
    }
    // Fixed plaintext: [u32 len][payload][random pad] → always HIDDEN_PLAIN bytes.
    let mut plain = vec![0u8; HIDDEN_PLAIN];
    fill_random(&mut plain);
    plain[..4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    plain[4..4 + payload.len()].copy_from_slice(payload);
    let blob = hkey.seal_raw(&plain);
    debug_assert_eq!(blob.len(), HIDDEN_LEN);
    write_fixed_0600(&hidden_path(base), &blob)?;
    slot_write_hidden(base, real_key, &hkey)
}

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

/// Trial-open every slot with `key`; return the first that authenticates as a valid payload.
fn slot_find(base: &std::path::Path, key: &MasterKey) -> io::Result<Option<(SlotRole, [u8; 16])>> {
    let Some(slots) = slots_load(base)? else { return Ok(None) };
    for s in &slots {
        if let Ok(plain) = key.open(s) {
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
    slots.iter().position(|s| key.open(s).ok().and_then(|p| slot_unpack(&p)).is_some())
}

/// Seal `(role, id)` under `key` into a fixed-length slot record.
fn slot_seal(key: &MasterKey, role: SlotRole, id: &[u8; 16]) -> [u8; SLOT_LEN] {
    let blob = key.seal(&slot_pack(role, id));
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
            let bytes = real_key.open(&blob).map_err(io_err)?;
            postcard::from_bytes(&bytes).map_err(io_err)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

fn slotdir_save(base: &std::path::Path, real_key: &MasterKey, dir: &[SlotEntry]) -> io::Result<()> {
    let plain = postcard::to_stdvec(dir).map_err(io_err)?;
    let blob = real_key.seal(&plain);
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
    /// Открыть vault под паролем устройства. `salt`/`verify` на уровне базы. При
    /// первом мультиаккаунтном запуске мигрирует legacy одиночный аккаунт (файлы
    /// прямо в базе) в `accounts/<ik>/` — БЕЗ перешифрования (соль та же → ключ
    /// тот же → файлы читаются как есть).
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
            Opened::Hidden(_) => Err(io_err("hidden container — not a login vault")),
        }
    }

    /// True when nothing has been provisioned yet (no slot table, no compartment, no pre-migration
    /// root account) — the create-account path.
    fn is_fresh(base: &std::path::Path) -> bool {
        !slots_path(base).exists()
            && !base.join("accounts.dat").exists()
            && !base.join("accounts").exists()
            && !base.join("seed.key").exists()
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
        // Every vault carries the fixed-size random hidden region from provisioning, so a vault that
        // NEVER had a hidden volume is indistinguishable from one that does.
        let _ = ensure_hidden(&base);
        // If this vault predates multipassword, migrate it first, then reuse the real compartment.
        let root = Vault { base: base.clone(), dir: base.clone(), key: key.clone() };
        root.migrate_legacy()?;
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
    /// executing a wipe if it is the duress password. Runs the transparent migrations (legacy
    /// single-account → `accounts/<ik>/`, then pre-multipassword root → `c/<id>/`) under the
    /// correct key. A password that opens nothing is a wrong password.
    pub fn open(base: impl Into<PathBuf>, passphrase: &[u8]) -> io::Result<Opened> {
        let base = base.into();
        std::fs::create_dir_all(&base)?;
        let salt = read_or_create_salt(&base)?;
        let key = MasterKey::derive(passphrase, &salt).map_err(io_err)?;
        // Every vault carries the fixed-size hidden region (random until a hidden volume is set), so
        // its presence never signals a hidden volume. Best-effort — never blocks a normal unlock.
        let _ = ensure_hidden(&base);

        // Legacy single-account (secrets directly at base root) → base/accounts/<ik>/ (unchanged).
        let root = Vault { base: base.clone(), dir: base.clone(), key: key.clone() };
        root.migrate_legacy()?;

        // Pre-multipassword multi-account layout: a registry sits at the base root. Only the REAL
        // password opens it (extras can't exist yet — adding one needs a logged-in real session).
        if base.join("accounts.dat").exists() {
            if root.load_registry().is_err() {
                return Err(io_err("неверный пароль или повреждённый файл"));
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
            Some((SlotRole::Hidden, _)) => match open_hidden_container(&base, &key) {
                Some(payload) => Ok(Opened::Hidden(payload)),
                None => Err(io_err("hidden container unreadable")),
            },
            None => Err(io_err("неверный пароль или повреждённый файл")),
        }
    }

    /// Create/replace the OPAQUE HIDDEN container under `hidden_password` (a real-session action —
    /// uses this vault's real key only to avoid clobbering known slots). `payload` ≤ `HIDDEN_CAP`.
    /// Its existence is undetectable to the outer password; see the honest limits above `HIDDEN_CAP`.
    pub fn set_hidden(&self, hidden_password: &[u8], payload: &[u8]) -> io::Result<()> {
        set_hidden_container(&self.base, &self.key, hidden_password, payload)
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
        let _ = store.save_capability(&crate::dev_capability());
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
        let plain = self.key.open(&blob).ok()?;
        postcard::from_bytes(&plain).ok()
    }

    fn deadman_seal(&self, dm: &Deadman) -> io::Result<()> {
        let blob = self.key.seal(&postcard::to_stdvec(dm).map_err(io_err)?);
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

    /// LEGACY path: the network config used to live at the VAULT root, one config for
    /// every account. That made accounts share a relay, so a relay linked all of a
    /// person's identities by IP+timing no matter how different their keys were — the
    /// opposite of a compartment. It is now per-account (`Store::load_net`); this reader
    /// exists only to migrate an old profile, and nothing writes here any more.
    fn legacy_net_path(&self) -> PathBuf {
        self.base.join("net.dat")
    }

    /// Read a pre-compartment (vault-level) network config, if one is still lying
    /// around. `None` = nothing to migrate.
    pub fn legacy_net(&self) -> Option<NetSettings> {
        let blob = std::fs::read(self.legacy_net_path()).ok()?;
        let bytes = self.key.open(&blob).ok()?;
        postcard::from_bytes(&bytes).ok()
    }

    /// Drop the migrated legacy config so it cannot come back or confuse a later read.
    pub fn remove_legacy_net(&self) {
        let _ = std::fs::remove_file(self.legacy_net_path());
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
        Store::at(self.account_dir(id), self.key.clone())
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
                let bytes = self.key.open(&blob).map_err(io_err)?;
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
        let bytes = self.key.seal(&plain);
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

    /// Мигрировать legacy одиночный аккаунт (секреты прямо в базе) в
    /// `accounts/<ik>/`. Идемпотентно: срабатывает лишь если в базе есть `seed.key`
    /// И ещё нет реестра. Реестр пишется ПОСЛЕДНИМ — это commit point (крах
    /// посреди перемещения → реестра нет → миграция повторится). Соль остаётся в
    /// базе, поэтому перемещённые файлы читаются тем же ключом без перешифрования.
    fn migrate_legacy(&self) -> io::Result<()> {
        let legacy_seed = self.base.join("seed.key");
        if !legacy_seed.exists() || self.registry_path().exists() {
            return Ok(());
        }
        // IK читаем ДО перемещения (id = ik-hex, стабилен и уникален).
        let ik = Store::at(&self.base, self.key.clone())
            .load_account()
            .map(|a| a.identity_public())
            .map_err(|e| io_err(format!("миграция: чтение account: {e}")))?;
        let id = hex::encode(ik);
        let acc = self.account_dir(&id);
        std::fs::create_dir_all(&acc)?;
        for name in [
            "seed.key",
            "contacts.dat",
            "history.dat",
            "history.lock",
            "meta.dat",
            "meta.lock",
            "blocked.dat",
            "profile.dat",
            "peer_profiles.dat",
            "sessions.dat",
            "sessions.lock",
            "capability.dat",
        ] {
            let src = self.base.join(name);
            if src.exists() {
                std::fs::rename(&src, acc.join(name))?;
            }
        }
        // Реестр — последним (commit point).
        self.save_registry(&[AccountEntry { id, label: "Account 1".into(), ik }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        s.write_atomic(&s.peer_profiles_path(), &s.key.seal(&plain)).unwrap();

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

    /// The proxy registry mints sequential indices, burns (flips active), derives each proxy's
    /// identity deterministically from the seed (recoverable, not stored), and tags a contact with
    /// its proxy via a sidecar — all round-tripping sealed on disk.
    #[test]
    fn proxy_registry_mints_burns_derives_and_tags() {
        let dir = std::env::temp_dir().join(format!("karst-store-proxy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        s.save_seed(&[3u8; 16]).unwrap(); // provision the seed so proxy identities can derive

        assert!(s.load_proxies().is_empty(), "no proxies initially");
        let p0 = s.create_proxy("work", 10).unwrap();
        let p1 = s.create_proxy("family", 11).unwrap();
        assert_eq!((p0.index, p1.index), (0, 1), "sequential indices");

        // Derived identity matches the frozen HD derivation and differs per index.
        let ent = s.load_entropy().unwrap();
        assert_eq!(
            s.proxy_identity(0).unwrap().account.identity_public(),
            crate::seed::derive_proxy(&ent, 0).account.identity_public()
        );
        assert_ne!(
            s.proxy_identity(0).unwrap().account.identity_public(),
            s.proxy_identity(1).unwrap().account.identity_public()
        );

        // Burn p0, tag a contact to p1 — reload from disk and check both persisted.
        s.set_proxy_active(0, false).unwrap();
        s.set_contact_proxy([9u8; 32], 1).unwrap();
        let s2 = Store::unlock(&dir, b"pw").unwrap(); // reopen from disk
        let list = s2.load_proxies();
        assert_eq!(list.len(), 2);
        assert!(!list[0].active && list[1].active, "p0 burned, p1 active");
        assert_eq!(s2.contact_proxy(&[9u8; 32]), Some(1), "contact tagged to its proxy");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Proxy mode: identities differ (per HD index, and from the root), NETWORK state is isolated
    /// per proxy (OPKs saved as one proxy never leak to another or to the root), while DATA
    /// (contacts) is shared root state. This is the isolation gate for the proxy-identity network
    /// layer — neuter `net_file`'s namespacing and the "p1 has its own opks" assert reddens.
    #[test]
    fn proxy_mode_isolates_network_state_but_shares_data() {
        let dir = std::env::temp_dir().join(format!("karst-store-pmode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::unlock(&dir, b"pw").unwrap();
        s.save_seed(&[7u8; 16]).unwrap();
        let p0 = s.as_proxy(0);
        let p1 = s.as_proxy(1);

        // Identity: proxy != proxy, proxy != root, and matches the frozen HD derivation.
        let ik_p0 = p0.load_account().unwrap().identity_public();
        assert_ne!(ik_p0, p1.load_account().unwrap().identity_public(), "proxies differ");
        assert_ne!(ik_p0, s.load_account().unwrap().identity_public(), "proxy != root");
        assert_eq!(ik_p0, crate::seed::derive_proxy(&[7u8; 16], 0).account.identity_public());
        // The seal (relay-facing) is proxy-scoped too.
        assert_ne!(
            p0.load_identity().unwrap().public.to_bytes(),
            s.load_identity().unwrap().public.to_bytes(),
            "proxy seal != root seal"
        );

        // NETWORK isolation: OPKs saved as p0 are invisible to p1 and to the root.
        p0.save_opks(&[[1u8; 32], [2u8; 32]]).unwrap();
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
        let blob = s.key.seal(&postcard::to_stdvec(&old).unwrap());
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

        let sealed = s.seal_versioned(7, b"payload");
        assert_eq!(s.open_versioned(&sealed), Some((7, b"payload".to_vec())));
        // A bare (unversioned) seal has no magic → None.
        assert_eq!(s.open_versioned(&s.key.seal(b"payload")), None);

        // A pending-downloads file written in the OLD (unversioned) way loads as empty.
        let pd = PendingDownload {
            blob_id: [1u8; 32], key: [2u8; 32], hash: [3u8; 32], name: "f".into(),
            size: 1, chunks: 1, sender: [4u8; 32], ts: 0, queued_at: 0, container_id: None,
        };
        let mut map = std::collections::BTreeMap::new();
        map.insert(pd.blob_id, pd);
        s.write_atomic(&s.downloads_path(), &s.key.seal(&postcard::to_stdvec(&map).unwrap())).unwrap();
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

        store.save_proxies(&[ProxyEntry { index: 0, label: "p0".into(), created_at: 1, active: true }]).unwrap();
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

    /// #95 THE JUDGE (per the advisor): a container WITH a hidden volume must be indistinguishable,
    /// to someone holding the OUTER password, from one WITHOUT. Two vaults with identical outer setup,
    /// one hidden volume, one none → the reserved region is the same fixed size and looks random in
    /// both, the outer password opens both identically, the hidden password opens ONLY the one that
    /// has a hidden volume, and the same password on the other is simply "wrong" (deniable). If this
    /// ever fails, the hidden volume is DETECTABLE and must not ship.
    #[test]
    fn hidden_volume_is_indistinguishable_and_deniable() {
        let da = std::env::temp_dir().join(format!("karst-hid-a-{}", std::process::id()));
        let db = std::env::temp_dir().join(format!("karst-hid-b-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&da);
        let _ = std::fs::remove_dir_all(&db);

        // Identical outer setup: both provisioned as Real vaults under the SAME outer password.
        let va = Vault::create(&da, b"outer").unwrap();
        let _vb = Vault::create(&db, b"outer").unwrap();
        // A gets a hidden volume; B does not.
        va.set_hidden(b"hiddenpw", b"the launch codes").unwrap();

        // 1) hidden.dat is the SAME FIXED SIZE with and without a hidden volume.
        let ha = std::fs::read(da.join("hidden.dat")).unwrap();
        let hb = std::fs::read(db.join("hidden.dat")).unwrap();
        assert_eq!(ha.len(), HIDDEN_LEN);
        assert_eq!(ha.len(), hb.len(), "same size — presence carries no signal");

        // 2) Indistinguishable-from-random: the raw-AEAD region carries NO KARST magic (a real magic
        //    prefix would be a dead giveaway). A raw ciphertext under a random nonce is comp. random.
        assert_ne!(&ha[..4], crate::secretbox::MAGIC, "no magic tell in the hidden region");
        assert_ne!(&hb[..4], crate::secretbox::MAGIC);

        // 3) The OUTER password opens both IDENTICALLY — a Real vault, with no hint a hidden one exists.
        assert!(matches!(Vault::open(&da, b"outer").unwrap(), Opened::Real(_)));
        assert!(matches!(Vault::open(&db, b"outer").unwrap(), Opened::Real(_)));

        // 4) The hidden password opens the hidden container on A, exact payload.
        match Vault::open(&da, b"hiddenpw").unwrap() {
            Opened::Hidden(p) => assert_eq!(p, b"the launch codes"),
            _ => panic!("hidden password must open the hidden container on A"),
        }
        // 5) The SAME hidden password on B (random region, no hidden volume) is simply WRONG — deniable.
        assert!(Vault::open(&db, b"hiddenpw").is_err(), "no hidden volume on B → just a wrong password");

        // 6) Non-destructive invariant: opening with the OUTER password must NOT rewrite the hidden
        //    region (a changed hidden.dat after a normal login would corrupt the container and, worse,
        //    leak that something reacts to logins). The hidden payload survives an outer open + relock.
        let before = std::fs::read(da.join("hidden.dat")).unwrap();
        assert!(matches!(Vault::open(&da, b"outer").unwrap(), Opened::Real(_)));
        let after = std::fs::read(da.join("hidden.dat")).unwrap();
        assert_eq!(before, after, "a real-password login must leave hidden.dat byte-for-byte unchanged");
        match Vault::open(&da, b"hiddenpw").unwrap() {
            Opened::Hidden(p) => assert_eq!(p, b"the launch codes", "hidden payload intact after an outer login"),
            _ => panic!("hidden container must still open after a real-password login"),
        }

        let _ = std::fs::remove_dir_all(&da);
        let _ = std::fs::remove_dir_all(&db);
    }
}
