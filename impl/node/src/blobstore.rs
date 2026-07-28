//! Disk-backed blob store for LARGE-file transfer (§15 dual-path). The relay parks an
//! **E2E-encrypted** blob (the client holds the key; the relay only ever sees
//! ciphertext) so a big file can be delivered offline — the recipient downloads it
//! later. This is the fat-relay side of the tradeoff the project otherwise avoids
//! (minimal mailbox = little exposed at the relay): here the relay holds bulk bytes, but they are
//! opaque ciphertext, TTL-swept, and hard-capped so it cannot be turned into free
//! unbounded storage.
//!
//! **DoS honesty:** with the skeleton's public dev-cap (anyone can authenticate), these
//! caps are the ONLY thing bounding an abusive uploader — real per-identity provisioning
//! is a separate layer that does not exist yet (see docs/STATUS.md). Caps + TTL keep it
//! bounded; they are not a substitute for admission that actually attributes cost.
//!
//! Streaming: chunks are appended to one file per blob and served by byte offset, so
//! neither upload nor download holds the whole blob in RAM — peak RAM is O(chunk).
//!
//! **Persistence:** the index is durable, so a big upload SURVIVES a relay restart (without it a
//! parked multi-GB blob would vanish on the next restart — the reliability gate before raising the
//! size limit). Each blob has a `<id>.meta` sidecar: a fixed header (`sender`, `count`,
//! `created_at`) plus an append-log of per-chunk ciphertext lengths. On [`BlobStore::open`] the
//! in-memory index is rebuilt from the sidecars, reconciled against the ciphertext files (a torn
//! tail from a crash is truncated to the last fully-recorded chunk, so the sender simply re-sends
//! that one), and TTL-swept. This does mean the relay now holds (opaque, capped, TTL-swept)
//! ciphertext across restarts — the deliberate fat-relay tradeoff, bounded as before.

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;

/// Magic + version for the metadata sidecar header. `KBM2` = per-chunk-file layout (out-of-order
/// capable); the older `KBM1` single-file+length-log format is discarded on recovery.
const META_MAGIC: &[u8; 4] = b"KBM2";
/// Sidecar header size: magic(4) + sender(32) + count(4 LE) + created_at(8 LE). The header is the
/// WHOLE sidecar now — per-chunk lengths are the chunk files' own sizes, not a log.
const META_HEADER_LEN: usize = 4 + 32 + 4 + 8;

/// Per-chunk ceiling (bytes of ciphertext). The client's plaintext chunk (`blob::BLOB_CHUNK`)
/// plus the AEAD tag must stay under this. Bounds a single hostile `BlobPut` allocation.
pub const MAX_BLOB_CHUNK: usize = 64 * 1024;
/// Per-blob size ceiling.
pub const MAX_BLOB_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
/// Per-blob chunk-count ceiling. The per-blob index is now sized to what actually ARRIVED, not
/// to this declared count (#209), so this bound isn't guarding an allocation any more — it caps
/// the declared range itself: `index`/`count` fields, the resume watermark, and a legitimate
/// blob's chunk arithmetic all stay in sane `u32` territory. 2 GiB / ~60 KiB chunks ≈ 35k, so
/// 40k leaves headroom.
pub const MAX_BLOB_CHUNKS: u32 = 40_000;
/// Per-sender total stored bytes (across their in-flight + complete blobs).
pub const MAX_SENDER_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
/// Global store ceiling — reject new bytes when full (never evict a live transfer).
pub const MAX_STORE_BYTES: u64 = 8 * 1024 * 1024 * 1024; // 8 GiB
/// Blob time-to-live; swept like the mailbox.
pub const BLOB_TTL_SECS: u64 = 7 * 24 * 3600;

/// Outcome of a `put_chunk`.
#[derive(Debug, PartialEq, Eq)]
pub enum BlobPut {
    /// Chunk stored; more expected.
    Ok,
    /// Final chunk stored; the blob is now complete and immutable.
    Complete,
    /// Rejected (cap, ownership, order, or immutability). String is a short reason.
    Rejected(String),
}

/// In-memory metadata for one blob. Each chunk's ciphertext lives in its OWN file
/// (`<id>.c<index>`), so chunks may arrive OUT OF ORDER (the relay pipelines) without any
/// offset math or truncation hazard: `lengths[i]` is present once chunk `i` is on disk.
struct Meta {
    sender: [u8; 32],
    count: u32,
    /// Per-index ciphertext length, keyed by the ARRIVED index. A `HashMap`, not a
    /// `Vec<Option<u32>>` sized to `count`: #209 — an uploader declares a huge `count` (up to
    /// `MAX_BLOB_CHUNKS`) and sends only a couple of chunks at extreme indices. A count-sized
    /// `Vec` allocated on first sight would cost the relay a 40_000-slot structure for that,
    /// and every scan over it (`size`, `received`, the old `next`) would be O(count) on every
    /// put/stat/sweep/recover regardless of how little actually arrived. Keyed by what's
    /// present, this struct costs O(received), which the sender actually paid for.
    lengths: HashMap<u32, u32>,
    created_at: u64,
    complete: bool,
    /// First index NOT yet stored — the contiguous watermark a sequential resumable upload
    /// continues from. Maintained INCREMENTALLY (advanced in `put_chunk` only when a fresh
    /// arrival closes the gap at the current watermark) instead of recomputed by scanning:
    /// `stat()` is an unauthenticated-cost read (no bytes required, no cap crossed) that a
    /// client can call as often as it likes, so it must not be allowed to cost O(count).
    contiguous: u32,
}

impl Meta {
    /// Actual stored bytes (sum of received chunk lengths) — NOT a slot extent, so the byte
    /// caps stay honest under out-of-order arrival. O(received), not O(count).
    fn size(&self) -> u64 {
        self.lengths.values().map(|&l| u64::from(l)).sum()
    }
    /// How many chunks are stored (completion = all `count`). O(1) — the map's own length.
    fn received(&self) -> u32 {
        self.lengths.len() as u32
    }
    /// First index NOT yet stored (see `contiguous` above) — O(1).
    fn next(&self) -> u32 {
        self.contiguous
    }
}

/// Disk-backed, capped, TTL-swept blob store. The index is DURABLE (rebuilt from per-blob
/// metadata sidecars on [`open`](BlobStore::open)), so parked blobs survive a relay restart.
pub struct BlobStore {
    dir: PathBuf,
    blobs: HashMap<[u8; 32], Meta>,
    total_bytes: u64,
}

impl BlobStore {
    /// Open (and RESET) the store directory. Wipes any prior contents — a fresh, empty store.
    /// Used by tests and anywhere a clean slate is wanted; the relay uses [`open`](Self::open) to
    /// recover instead.
    pub fn new(dir: PathBuf) -> io::Result<Self> {
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir, blobs: HashMap::new(), total_bytes: 0 })
    }

    /// Open the store directory, RECOVERING the index from the on-disk metadata sidecars so parked
    /// blobs survive a restart. Reconciles each blob's ciphertext against its sidecar (a crash's
    /// torn tail is truncated to the last fully-recorded chunk), drops junk (ciphertext without a
    /// valid sidecar, or an orphan sidecar), and TTL-sweeps against `now`.
    pub fn open(dir: PathBuf, now: u64) -> io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        let mut store = Self { dir, blobs: HashMap::new(), total_bytes: 0 };
        store.recover(now)?;
        Ok(store)
    }

    fn meta_path(&self, id: &[u8; 32]) -> PathBuf {
        self.dir.join(format!("{}.meta", hex::encode(id)))
    }

    /// Path of one chunk's ciphertext file (`<id>.c<index>`).
    fn chunk_path(&self, id: &[u8; 32], index: u32) -> PathBuf {
        self.dir.join(format!("{}.c{index}", hex::encode(id)))
    }

    fn sender_bytes(&self, sender: &[u8; 32]) -> u64 {
        self.blobs.values().filter(|m| &m.sender == sender).map(Meta::size).sum()
    }

    /// Append one ciphertext chunk. Enforces (in order): per-chunk size, ownership
    /// (first sender owns the id), immutability (a complete blob is frozen), in-order
    /// index, count sanity, and the per-blob / per-sender / global byte caps. Streams
    /// straight to disk.
    pub fn put_chunk(
        &mut self,
        sender: [u8; 32],
        id: [u8; 32],
        index: u32,
        count: u32,
        data: &[u8],
        now: u64,
    ) -> BlobPut {
        if data.len() > MAX_BLOB_CHUNK {
            return BlobPut::Rejected("chunk too large".into());
        }
        if count == 0 || count > MAX_BLOB_CHUNKS {
            return BlobPut::Rejected("bad chunk count".into());
        }
        if index >= count {
            return BlobPut::Rejected("index past count".into());
        }

        // Ownership + immutability, for an existing blob. Order is NOT enforced — chunks may
        // arrive in any order (the client pipelines them).
        let prev_len = if let Some(m) = self.blobs.get(&id) {
            if m.sender != sender {
                return BlobPut::Rejected("blob owned by another sender".into());
            }
            if m.complete {
                return BlobPut::Rejected("blob already complete".into());
            }
            if m.count != count {
                return BlobPut::Rejected("chunk count changed mid-transfer".into());
            }
            m.lengths.get(&index).copied() // Some(old_len) if this index is a re-send (idempotent)
        } else {
            None
        };

        // Byte caps (per-blob, per-sender, global) on the DELTA this put adds — a re-send of the
        // same index nets its length change (usually zero). Reject when full — never evict.
        let add = data.len() as u64;
        let delta = add.saturating_sub(prev_len.map(u64::from).unwrap_or(0));
        let cur_size = self.blobs.get(&id).map(Meta::size).unwrap_or(0);
        if cur_size.saturating_sub(prev_len.map(u64::from).unwrap_or(0)) + add > MAX_BLOB_SIZE {
            return BlobPut::Rejected("blob exceeds size cap".into());
        }
        if self.sender_bytes(&sender) + delta > MAX_SENDER_BYTES {
            return BlobPut::Rejected("sender over quota".into());
        }
        if self.total_bytes + delta > MAX_STORE_BYTES {
            return BlobPut::Rejected("blob store full".into());
        }

        // On the FIRST sight of a blob, persist the sidecar header BEFORE any chunk file: a crash
        // after the header but before the chunk just leaves an in-progress blob with fewer chunks
        // (the client resumes); a chunk file with no header would be an unrecoverable orphan.
        if !self.blobs.contains_key(&id) {
            if let Err(e) = self.write_meta_header(&id, &sender, count, now) {
                return BlobPut::Rejected(format!("store meta io: {e}"));
            }
        }
        // Write this chunk to its OWN file, atomically (temp + rename), so a re-send overwrites
        // cleanly and a crash can never leave a torn chunk that corrupts a neighbour.
        if let Err(e) = self.write_chunk_file(&id, index, data) {
            return BlobPut::Rejected(format!("store io: {e}"));
        }

        let m = self.blobs.entry(id).or_insert_with(|| Meta {
            sender,
            count,
            lengths: HashMap::new(),
            created_at: now,
            complete: false,
            contiguous: 0,
        });
        m.lengths.insert(index, add as u32);
        // Advance the watermark past whatever is now contiguously present. Each index can only
        // be stepped over once in the life of this blob, so this is amortized O(1) per put —
        // never a rescan of the whole (possibly count-sized) range.
        while m.lengths.contains_key(&m.contiguous) {
            m.contiguous += 1;
        }
        self.total_bytes += delta;
        if m.received() == m.count {
            m.complete = true;
            BlobPut::Complete
        } else {
            BlobPut::Ok
        }
    }

    /// Write one chunk's ciphertext to `<id>.c<index>` ATOMICALLY: fill a temp file, fsync it,
    /// then rename over the final name. Rename is atomic on POSIX, so the chunk file is either
    /// fully present or absent on recovery — never torn, and a re-send just replaces it.
    fn write_chunk_file(&self, id: &[u8; 32], index: u32, data: &[u8]) -> io::Result<()> {
        let final_path = self.chunk_path(id, index);
        let tmp_path = self.dir.join(format!("{}.c{index}.tmp", hex::encode(id)));
        {
            let mut f = OpenOptions::new().create(true).truncate(true).write(true).open(&tmp_path)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp_path, &final_path)
    }

    /// Write the sidecar HEADER (magic, sender, count, created_at). The whole sidecar — there is
    /// no per-chunk length log any more (a chunk file's size is its length). Written once, on the
    /// first sight of the blob, before any chunk file.
    fn write_meta_header(&self, id: &[u8; 32], sender: &[u8; 32], count: u32, created_at: u64) -> io::Result<()> {
        let mut header = Vec::with_capacity(META_HEADER_LEN);
        header.extend_from_slice(META_MAGIC);
        header.extend_from_slice(sender);
        header.extend_from_slice(&count.to_le_bytes());
        header.extend_from_slice(&created_at.to_le_bytes());
        let mut f = OpenOptions::new().create(true).truncate(true).write(true).open(self.meta_path(id))?;
        f.write_all(&header)?;
        f.sync_all()
    }

    /// Read one chunk by index. `Some` only for a chunk that has been stored (available
    /// even before the blob completes, though the client fetches after it has the
    /// `FileRef`). Bearer-by-id: knowing the 256-bit id is the download right (the bytes
    /// are ciphertext regardless).
    pub fn get_chunk(&self, id: &[u8; 32], index: u32) -> Option<Vec<u8>> {
        let m = self.blobs.get(id)?;
        // Only a stored chunk (its length is known) is readable — even before the blob completes.
        m.lengths.get(&index)?;
        std::fs::read(self.chunk_path(id, index)).ok()
    }

    /// `(count, complete)` for a blob, if known — lets a downloader learn how many
    /// chunks to expect and whether the upload has finished.
    pub fn meta(&self, id: &[u8; 32]) -> Option<(u32, bool)> {
        self.blobs.get(id).map(|m| (m.count, m.complete))
    }

    /// Upload progress of a blob: `(next, count, complete)` where `next` is how many chunks are
    /// already stored (so the next expected index) — the watermark a **resumable upload** continues
    /// from. `None` if the relay has never seen this blob (fresh upload starts at 0). Public read,
    /// like `meta`/`get_chunk` — it reveals only how far a bearer-known blob got, not its contents.
    pub fn stat(&self, id: &[u8; 32]) -> Option<(u32, u32, bool)> {
        self.blobs.get(id).map(|m| (m.next(), m.count, m.complete))
    }

    /// Drop blobs older than `BLOB_TTL_SECS` (delete ciphertext + sidecar + index).
    /// `saturating_sub` makes a regressed clock look fresh (kept), never spuriously stale.
    pub fn sweep(&mut self, now: u64) {
        let dir = self.dir.clone();
        let mut freed = 0u64;
        self.blobs.retain(|id, m| {
            let keep = now.saturating_sub(m.created_at) <= BLOB_TTL_SECS;
            if !keep {
                freed += m.size();
                // Only the indices that actually ARRIVED (#209) — not `0..m.count`, which for a
                // sparse blob would turn every sweep pass into `count` mostly-ENOENT removes for
                // a blob that only ever held a couple of real chunks.
                for &index in m.lengths.keys() {
                    let _ = std::fs::remove_file(dir.join(format!("{}.c{index}", hex::encode(id))));
                }
                let _ = std::fs::remove_file(dir.join(format!("{}.meta", hex::encode(id))));
            }
            keep
        });
        self.total_bytes -= freed.min(self.total_bytes);
    }

    /// Rebuild the in-memory index from the on-disk sidecars. Called by [`open`](Self::open).
    ///
    /// A SINGLE `read_dir` pass classifies every file by name (sidecar, chunk, `.tmp`, or junk)
    /// and only then reconciles each blob against exactly the chunk files it actually has. This
    /// used to be two directory passes, and the per-blob reconciliation inside them looped
    /// `0..count` — a stat call (plus a `.tmp` unlink attempt) per DECLARED index (#209). A
    /// sparse blob (a huge declared `count`, a couple of real chunks at extreme indices) made
    /// that loop cost the same regardless of how little actually arrived, so restart cost scaled
    /// with what senders *claimed*, not what they *sent* — parking a handful of such blobs could
    /// make every future relay restart do tens of thousands of pointless syscalls per blob.
    /// Building straight from the directory listing instead makes recovery cost proportional to
    /// the files really on disk.
    fn recover(&mut self, now: u64) -> io::Result<()> {
        let dir = self.dir.clone();
        let mut meta_bytes: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        let mut chunks: HashMap<[u8; 32], Vec<(u32, u64)>> = HashMap::new();
        let mut doomed: Vec<PathBuf> = Vec::new(); // `.tmp` leftovers + unrecognized junk

        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()).map(str::to_string) else {
                continue;
            };
            if let Some(id_str) = name.strip_suffix(".meta") {
                if let Some(blob_id) = parse_blob_id(id_str) {
                    meta_bytes.insert(blob_id, std::fs::read(&path).unwrap_or_default());
                    continue;
                }
            }
            let Some(blob_id) = leading_blob_id(&name) else { continue };
            let rest = &name[64..];
            let mut recognized = false;
            if let Some(chunk_part) = rest.strip_prefix(".c") {
                if let Some(idx_str) = chunk_part.strip_suffix(".tmp") {
                    if idx_str.parse::<u32>().is_ok() {
                        doomed.push(path.clone());
                        recognized = true;
                    }
                } else if let Ok(index) = chunk_part.parse::<u32>() {
                    let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    chunks.entry(blob_id).or_default().push((index, len));
                    recognized = true;
                }
            }
            if !recognized {
                // Recognized id, unrecognized suffix (e.g. an old KBM1 bare `<id>` single-data
                // file) — always junk.
                doomed.push(path);
            }
        }
        for path in doomed {
            let _ = std::fs::remove_file(path);
        }

        // Reconcile every id that showed up as EITHER a sidecar or a chunk file — an orphan
        // chunk with no sidecar is handled the same loop, just with `meta_bytes.get` coming back
        // empty.
        let ids: HashSet<[u8; 32]> = meta_bytes.keys().chain(chunks.keys()).copied().collect();
        for blob_id in ids {
            let header = meta_bytes.get(&blob_id).and_then(|raw| parse_meta_header(raw, now));
            let Some((sender, count, created_at)) = header else {
                self.drop_recovered(&blob_id, chunks.get(&blob_id));
                continue;
            };
            // Only chunk files inside the declared range and with a sane on-disk length count —
            // this loop is bounded by how many real chunk FILES were found for this id, not by
            // `count`.
            let mut lengths = HashMap::new();
            let mut acc = 0u64;
            if let Some(list) = chunks.get(&blob_id) {
                for &(index, len) in list {
                    if index < count && len > 0 && len <= MAX_BLOB_CHUNK as u64 {
                        lengths.insert(index, len as u32);
                        acc += len;
                    }
                }
            }
            if lengths.is_empty() {
                self.drop_recovered(&blob_id, chunks.get(&blob_id)); // header only — re-upload recreates it
                continue;
            }
            let complete = lengths.len() as u32 == count;
            let mut contiguous = 0u32;
            while lengths.contains_key(&contiguous) {
                contiguous += 1;
            }
            self.total_bytes += acc;
            self.blobs.insert(blob_id, Meta { sender, count, lengths, created_at, complete, contiguous });
        }
        Ok(())
    }

    /// Delete a blob's sidecar plus exactly the chunk files THIS recovery pass found for it — not
    /// `0..count` (a blob that never earns a kept `Meta` doesn't get to cost `count` probes on
    /// the way out either).
    fn drop_recovered(&self, id: &[u8; 32], chunks: Option<&Vec<(u32, u64)>>) {
        let _ = std::fs::remove_file(self.meta_path(id));
        if let Some(list) = chunks {
            for &(index, _) in list {
                let _ = std::fs::remove_file(self.chunk_path(id, index));
            }
        }
    }
}

/// Parse + validate a sidecar header's raw bytes (magic, count sanity, TTL). `None` means the
/// whole blob is unrecoverable: absent/short/old-format header, an insane `count`, or expiry.
fn parse_meta_header(bytes: &[u8], now: u64) -> Option<([u8; 32], u32, u64)> {
    if bytes.len() < META_HEADER_LEN || &bytes[..4] != META_MAGIC {
        return None; // absent, short, or an older format (KBM1) — discard
    }
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&bytes[4..36]);
    let count = u32::from_le_bytes(bytes[36..40].try_into().unwrap());
    let created_at = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
    if count == 0 || count > MAX_BLOB_CHUNKS {
        return None;
    }
    // TTL: an expired blob is dropped rather than recovered.
    if now.saturating_sub(created_at) > BLOB_TTL_SECS {
        return None;
    }
    Some((sender, count, created_at))
}

/// Parse a 64-hex blob-store filename back into a blob id, or `None` if it is not one.
fn parse_blob_id(name: &str) -> Option<[u8; 32]> {
    if name.len() != 64 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = hex::decode(name).ok()?;
    bytes.try_into().ok()
}

/// The blob id from the LEADING 64-hex of any blob-store filename (`<id>`, `<id>.meta`,
/// `<id>.c7`, `<id>.c7.tmp`), or `None` if the name does not start with a 64-hex id.
fn leading_blob_id(name: &str) -> Option<[u8; 32]> {
    if name.len() < 64 {
        return None;
    }
    let (head, rest) = name.split_at(64);
    if !rest.is_empty() && !rest.starts_with('.') {
        return None; // 64 hex chars must be the whole name or followed by an extension
    }
    parse_blob_id(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let p = std::env::temp_dir()
            .join(format!("karst-blobstore-test-{}-{:?}", std::process::id(), std::thread::current().id()));
        p
    }

    fn sender(n: u8) -> [u8; 32] {
        [n; 32]
    }
    fn id(n: u8) -> [u8; 32] {
        [0x80 | n; 32]
    }

    #[test]
    fn put_then_get_roundtrips_in_order() {
        let mut s = BlobStore::new(tmp().join("rt")).unwrap();
        let a = sender(1);
        let b = id(1);
        assert_eq!(s.put_chunk(a, b, 0, 3, b"aaa", 0), BlobPut::Ok);
        assert_eq!(s.put_chunk(a, b, 1, 3, b"bb", 0), BlobPut::Ok);
        assert_eq!(s.put_chunk(a, b, 2, 3, b"cccc", 0), BlobPut::Complete);
        assert_eq!(s.get_chunk(&b, 0).as_deref(), Some(&b"aaa"[..]));
        assert_eq!(s.get_chunk(&b, 1).as_deref(), Some(&b"bb"[..]));
        assert_eq!(s.get_chunk(&b, 2).as_deref(), Some(&b"cccc"[..]));
        assert_eq!(s.meta(&b), Some((3, true)));
    }

    #[test]
    fn out_of_order_puts_are_accepted_and_immutability_holds() {
        let mut s = BlobStore::new(tmp().join("oo")).unwrap();
        let a = sender(1);
        let b = id(2);
        // Chunks may arrive in ANY order — index 1 before index 0 is fine (the client pipelines).
        assert_eq!(s.put_chunk(a, b, 1, 2, b"y", 0), BlobPut::Ok);
        // A re-send of the same index is idempotent (overwrite), not a rejection.
        assert_eq!(s.put_chunk(a, b, 1, 2, b"y", 0), BlobPut::Ok);
        // The final missing chunk completes the blob regardless of arrival order.
        assert_eq!(s.put_chunk(a, b, 0, 2, b"x", 0), BlobPut::Complete);
        assert_eq!(s.get_chunk(&b, 0).as_deref(), Some(&b"x"[..]));
        assert_eq!(s.get_chunk(&b, 1).as_deref(), Some(&b"y"[..]));
        // A complete blob is frozen.
        assert!(matches!(s.put_chunk(a, b, 1, 2, b"z", 0), BlobPut::Rejected(_)));
    }

    #[test]
    fn the_last_chunk_first_survives_an_earlier_chunk() {
        // The discriminating out-of-order case (per review): store chunk N-1 FIRST, then chunk 0.
        // With per-chunk files neither write can truncate the other — the earlier design's single
        // file + set_len would have deleted the already-stored last chunk here.
        let mut s = BlobStore::new(tmp().join("lastfirst")).unwrap();
        let a = sender(1);
        let b = id(7);
        assert_eq!(s.put_chunk(a, b, 2, 3, b"cccc", 0), BlobPut::Ok); // last chunk first
        assert_eq!(s.put_chunk(a, b, 0, 3, b"aaa", 0), BlobPut::Ok);
        assert_eq!(s.get_chunk(&b, 2).as_deref(), Some(&b"cccc"[..]), "the last chunk was not truncated away");
        assert_eq!(s.put_chunk(a, b, 1, 3, b"bb", 0), BlobPut::Complete);
        assert_eq!(s.total_bytes, 3 + 4 + 2, "byte accounting sums ACTUAL chunk lengths");
    }

    #[test]
    fn a_different_sender_cannot_write_someone_elses_blob() {
        let mut s = BlobStore::new(tmp().join("own")).unwrap();
        let b = id(3);
        assert_eq!(s.put_chunk(sender(1), b, 0, 2, b"x", 0), BlobPut::Ok);
        assert!(matches!(s.put_chunk(sender(2), b, 1, 2, b"y", 0), BlobPut::Rejected(_)));
    }

    #[test]
    fn oversize_chunk_is_rejected_before_store() {
        let mut s = BlobStore::new(tmp().join("big")).unwrap();
        let huge = vec![0u8; MAX_BLOB_CHUNK + 1];
        assert!(matches!(s.put_chunk(sender(1), id(4), 0, 1, &huge, 0), BlobPut::Rejected(_)));
    }

    #[test]
    fn sweep_drops_blobs_past_ttl_and_frees_bytes() {
        let mut s = BlobStore::new(tmp().join("ttl")).unwrap();
        let b = id(5);
        s.put_chunk(sender(1), b, 0, 1, b"hello", 0);
        assert!(s.get_chunk(&b, 0).is_some());
        s.sweep(BLOB_TTL_SECS); // exactly at TTL: still fresh (<=)
        assert!(s.get_chunk(&b, 0).is_some(), "kept at exactly TTL");
        s.sweep(BLOB_TTL_SECS + 1); // past TTL: dropped
        assert!(s.get_chunk(&b, 0).is_none(), "swept past TTL");
        assert_eq!(s.total_bytes, 0, "bytes freed");
    }

    #[test]
    fn recovers_a_parked_blob_across_a_restart_and_resumes() {
        let dir = tmp().join("recover");
        let a = sender(1);
        let b = id(1);
        // A relay stores 2 of 3 chunks, then goes down mid-upload.
        {
            let mut s = BlobStore::new(dir.clone()).unwrap();
            assert_eq!(s.put_chunk(a, b, 0, 3, b"aaa", 100), BlobPut::Ok);
            assert_eq!(s.put_chunk(a, b, 1, 3, b"bb", 100), BlobPut::Ok);
        }
        // On restart the index is rebuilt from disk — the parked bytes did NOT vanish.
        let mut s = BlobStore::open(dir.clone(), 200).unwrap();
        assert_eq!(s.meta(&b), Some((3, false)), "incomplete blob recovered");
        assert_eq!(s.get_chunk(&b, 0).as_deref(), Some(&b"aaa"[..]));
        assert_eq!(s.get_chunk(&b, 1).as_deref(), Some(&b"bb"[..]));
        assert!(s.get_chunk(&b, 2).is_none(), "the never-uploaded chunk is absent");
        assert_eq!(s.total_bytes, 5, "recovered byte accounting");
        // The upload resumes cleanly from where it stopped.
        assert_eq!(s.put_chunk(a, b, 2, 3, b"cccc", 200), BlobPut::Complete);
        assert_eq!(s.get_chunk(&b, 2).as_deref(), Some(&b"cccc"[..]));
        // And the now-complete blob survives yet another restart.
        drop(s);
        let s2 = BlobStore::open(dir, 300).unwrap();
        assert_eq!(s2.meta(&b), Some((3, true)));
        assert_eq!(s2.get_chunk(&b, 2).as_deref(), Some(&b"cccc"[..]));
    }

    #[test]
    fn a_tmp_leftover_is_cleaned_and_gappy_chunks_recover() {
        let dir = tmp().join("torn");
        let a = sender(1);
        let b = id(2);
        {
            let mut s = BlobStore::new(dir.clone()).unwrap();
            // Store chunks 0 and 2 (a GAP at 1 — an in-flight pipelined upload).
            s.put_chunk(a, b, 0, 3, b"aaa", 0);
            s.put_chunk(a, b, 2, 3, b"cccc", 0);
        }
        // Simulate a crash mid-write of chunk 1: a `.tmp` file is left behind (rename never ran).
        std::fs::write(dir.join(format!("{}.c1.tmp", hex::encode(b))), b"partial").unwrap();
        let mut s = BlobStore::open(dir.clone(), 0).unwrap();
        // The two whole chunks recover across the gap; the torn `.tmp` is cleaned, chunk 1 absent.
        assert_eq!(s.meta(&b), Some((3, false)));
        assert_eq!(s.get_chunk(&b, 0).as_deref(), Some(&b"aaa"[..]));
        assert!(s.get_chunk(&b, 1).is_none(), "the never-finished chunk did not recover");
        assert_eq!(s.get_chunk(&b, 2).as_deref(), Some(&b"cccc"[..]));
        assert!(!dir.join(format!("{}.c1.tmp", hex::encode(b))).exists(), "the .tmp leftover is cleaned");
        assert_eq!(s.total_bytes, 3 + 4, "only whole chunks are counted");
        // The watermark has TWO writers now: `recover` computes it from scratch on open, and
        // `put_chunk` advances it incrementally afterwards. They must agree, or a resumer would
        // get told the wrong next index after a restart. Chunk 0 is present but 1 is the gap, so
        // the watermark must stop at 1 (NOT jump to 2, which is also present but not contiguous).
        assert_eq!(s.stat(&b), Some((1, 3, false)), "recovery computed the watermark, stopped at the gap");
        // The sender fills the gap and the blob completes.
        assert_eq!(s.put_chunk(a, b, 1, 3, b"bb", 0), BlobPut::Complete);
        assert_eq!(s.get_chunk(&b, 1).as_deref(), Some(&b"bb"[..]));
        // put_chunk's incremental advance must pick up cleanly from the recovery-computed
        // watermark and walk it all the way to `count` now that the gap is filled.
        assert_eq!(s.stat(&b), Some((3, 3, true)), "put_chunk's watermark advance agrees with recovery's");
    }

    #[test]
    fn an_expired_blob_is_swept_on_recovery() {
        let dir = tmp().join("ttlrec");
        let b = id(3);
        {
            let mut s = BlobStore::new(dir.clone()).unwrap();
            s.put_chunk(sender(1), b, 0, 1, b"hi", 0); // created_at = 0
        }
        let s = BlobStore::open(dir.clone(), BLOB_TTL_SECS + 1).unwrap();
        assert!(s.get_chunk(&b, 0).is_none(), "expired blob dropped on recovery");
        assert_eq!(s.total_bytes, 0);
        assert!(!dir.join(format!("{}.c0", hex::encode(b))).exists(), "chunk deleted");
        assert!(!dir.join(format!("{}.meta", hex::encode(b))).exists(), "sidecar deleted");
    }

    #[test]
    fn junk_files_are_dropped_on_recovery() {
        let dir = tmp().join("junk");
        std::fs::create_dir_all(&dir).unwrap();
        // An old-format single-data file (KBM1 layout) with no valid sidecar.
        let orphan_data = id(4);
        std::fs::write(dir.join(hex::encode(orphan_data)), b"loose ciphertext").unwrap();
        // A chunk file whose sidecar is gone (orphan).
        let orphan_chunk = id(6);
        std::fs::write(dir.join(format!("{}.c0", hex::encode(orphan_chunk))), b"loose chunk").unwrap();
        // A sidecar with a bad/old magic.
        let orphan_meta = id(5);
        std::fs::write(dir.join(format!("{}.meta", hex::encode(orphan_meta))), b"KBM1 not real").unwrap();
        let s = BlobStore::open(dir.clone(), 0).unwrap();
        assert_eq!(s.total_bytes, 0);
        assert!(!dir.join(hex::encode(orphan_data)).exists(), "old single-data file is swept");
        assert!(!dir.join(format!("{}.c0", hex::encode(orphan_chunk))).exists(), "orphan chunk swept");
        assert!(
            !dir.join(format!("{}.meta", hex::encode(orphan_meta))).exists(),
            "an orphan sidecar is swept"
        );
    }

    #[test]
    fn a_retried_chunk_is_idempotent() {
        // A re-sent chunk (mid-put failure, or a pipelined duplicate) must overwrite its own file
        // and net zero byte-cap change — never duplicate bytes or corrupt the sidecar.
        let dir = tmp().join("retry");
        let mut s = BlobStore::new(dir.clone()).unwrap();
        let b = id(6);
        let a = sender(1);
        assert_eq!(s.put_chunk(a, b, 0, 3, b"aaa", 0), BlobPut::Ok);
        assert_eq!(s.put_chunk(a, b, 0, 3, b"aaa", 0), BlobPut::Ok); // retry same index
        assert_eq!(s.total_bytes, 3, "a retry does not double-count bytes");
        assert_eq!(std::fs::metadata(s.chunk_path(&b, 0)).unwrap().len(), 3, "chunk not duplicated");
        // And it still parses cleanly on recovery.
        let s2 = BlobStore::open(dir, 0).unwrap();
        assert_eq!(s2.meta(&b), Some((3, false)));
        assert_eq!(s2.get_chunk(&b, 0).as_deref(), Some(&b"aaa"[..]));
    }

    #[test]
    fn a_sparse_blob_does_not_cost_the_relay_its_declared_size() {
        // #209: an uploader declares MAX_BLOB_CHUNKS but sends only two chunks, at the extreme
        // ends of the range. Before the fix, `Meta.lengths` was a `Vec<Option<u32>>` allocated to
        // `count` on first sight, and `received()`/`next()` (driving `put_chunk`'s completion
        // check and `stat()`'s watermark) each did a full O(count) scan over it. So a handful of
        // real bytes forced a 40_000-slot allocation, and every later put/stat on that one blob
        // rescanned all 40_000 slots. Timing is the only externally observable signature of that:
        // if the scan is back, 20_000 put/stat round trips on this blob take seconds; if the
        // structure and the watermark are both proportional to what arrived, they take
        // milliseconds.
        let mut s = BlobStore::new(tmp().join("sparse-cost")).unwrap();
        let a = sender(9);
        let b = id(9);
        assert_eq!(s.put_chunk(a, b, 0, MAX_BLOB_CHUNKS, b"first", 0), BlobPut::Ok);
        assert_eq!(s.put_chunk(a, b, MAX_BLOB_CHUNKS - 1, MAX_BLOB_CHUNKS, b"last", 0), BlobPut::Ok);
        assert_eq!(s.stat(&b), Some((1, MAX_BLOB_CHUNKS, false)), "only index 0 is contiguous");

        let started = std::time::Instant::now();
        for _ in 0..20_000 {
            // A re-send (idempotent, net-zero byte delta) exercises put_chunk's completion check;
            // stat() exercises the watermark. Neither adds a chunk, so any cost here is pure
            // per-declared-count overhead, not real upload work.
            assert_eq!(s.put_chunk(a, b, 0, MAX_BLOB_CHUNKS, b"first", 0), BlobPut::Ok);
            assert_eq!(s.stat(&b), Some((1, MAX_BLOB_CHUNKS, false)));
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "20_000 ops on a sparse {MAX_BLOB_CHUNKS}-count blob (2 real chunks) took {elapsed:?} \
             — looks like an O(count) scan is back on the put/stat hot path"
        );
    }

    #[test]
    fn a_sweep_of_many_sparse_blobs_does_not_walk_their_declared_size() {
        // #209, the "sweep" cost named in the finding: before the fix, sweeping an expiring blob
        // deleted `0..m.count` chunk files — a `remove_file` syscall (almost always ENOENT) per
        // DECLARED index. A handful of near-empty, MAX_BLOB_CHUNKS-declared blobs would turn one
        // sweep pass into millions of pointless syscalls. Deleting only the indices that actually
        // arrived makes sweep cost proportional to real chunks on disk, not declared ones.
        let mut s = BlobStore::new(tmp().join("sweep-cost")).unwrap();
        for n in 0..30u8 {
            assert_eq!(s.put_chunk(sender(n), id(n), 0, MAX_BLOB_CHUNKS, b"x", 0), BlobPut::Ok);
        }
        let started = std::time::Instant::now();
        s.sweep(BLOB_TTL_SECS + 1); // every blob above was created_at = 0, now past TTL
        let elapsed = started.elapsed();
        assert_eq!(s.total_bytes, 0, "all 30 sparse blobs were swept");
        // Neutered (0..count remove_file loop), this took 2.3s; fixed, it's low milliseconds — 2s
        // leaves an order of magnitude of headroom for a loaded/slow-disk CI box while still
        // sitting far under the neutered number.
        assert!(
            elapsed < std::time::Duration::from_millis(2000),
            "sweeping 30 sparse {MAX_BLOB_CHUNKS}-count blobs (1 real chunk each) took {elapsed:?} \
             — looks like sweep is walking 0..count again"
        );
    }

    #[test]
    fn a_restart_does_not_walk_the_declared_size_of_many_sparse_parked_blobs() {
        // #209, the "recover" cost: before the fix, rebuilding the index from disk looped
        // `0..count` per blob (a `stat` plus a `.tmp`-unlink attempt per DECLARED index) to see
        // which chunks survived. Many sparse, near-empty blobs parked at MAX_BLOB_CHUNKS would
        // make every relay restart cost millions of syscalls for chunks that were never written.
        // Rebuilding from a single directory listing instead makes restart cost proportional to
        // files actually on disk.
        let dir = tmp().join("recover-cost");
        {
            let mut s = BlobStore::new(dir.clone()).unwrap();
            for n in 0..30u8 {
                assert_eq!(s.put_chunk(sender(n), id(n), 0, MAX_BLOB_CHUNKS, b"x", 0), BlobPut::Ok);
            }
        }
        let started = std::time::Instant::now();
        let s = BlobStore::open(dir, 0).unwrap();
        let elapsed = started.elapsed();
        assert_eq!(s.meta(&id(0)), Some((MAX_BLOB_CHUNKS, false)), "a parked sparse blob still recovers");
        // Neutered (0..count stat+tmp-unlink loop), this took 4.8s; fixed, it's low milliseconds —
        // 2s leaves headroom for a loaded/slow-disk CI box while staying far under the neutered
        // number.
        assert!(
            elapsed < std::time::Duration::from_millis(2000),
            "recovering 30 sparse {MAX_BLOB_CHUNKS}-count blobs (1 real chunk each) took {elapsed:?} \
             — looks like recover is walking 0..count again"
        );
    }

    #[test]
    fn a_dense_legitimate_blob_still_completes_and_reads_back_correctly() {
        // Control for the fix above: a real, densely-filled upload (every index actually sent, in
        // order) must still complete and read back correctly under the new HashMap-backed index
        // and the incrementally-maintained watermark.
        let mut s = BlobStore::new(tmp().join("dense-control")).unwrap();
        let a = sender(10);
        let b = id(10);
        let count = 500u32;
        for i in 0..count {
            let data = vec![(i % 251) as u8; 10];
            let want = if i + 1 == count { BlobPut::Complete } else { BlobPut::Ok };
            assert_eq!(s.put_chunk(a, b, i, count, &data, 0), want);
            assert_eq!(s.stat(&b), Some((i + 1, count, i + 1 == count)), "watermark tracks every chunk");
        }
        assert_eq!(s.meta(&b), Some((count, true)));
        for i in 0..count {
            let want = vec![(i % 251) as u8; 10];
            assert_eq!(s.get_chunk(&b, i), Some(want), "chunk {i} reads back correctly");
        }
        // Survives a restart too, since the recovery path was also rewritten.
        let s2 = BlobStore::open(s.dir.clone(), 0).unwrap();
        assert_eq!(s2.meta(&b), Some((count, true)));
        assert_eq!(s2.get_chunk(&b, 499).as_deref(), Some(&[(499u32 % 251) as u8; 10][..]));
    }
}
