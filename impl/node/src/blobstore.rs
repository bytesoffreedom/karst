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

use std::collections::HashMap;
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
/// Per-blob chunk-count ceiling (rejects an absurd manifest before it allocates index
/// state). 2 GiB / ~60 KiB chunks ≈ 35k, so 40k leaves headroom.
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
/// offset math or truncation hazard: `lengths[i]` is `Some(len)` once chunk `i` is on disk.
struct Meta {
    sender: [u8; 32],
    count: u32,
    /// Per-index ciphertext length; `Some` iff that chunk file is stored. `len == count`.
    lengths: Vec<Option<u32>>,
    created_at: u64,
    complete: bool,
}

impl Meta {
    /// Actual stored bytes (sum of received chunk lengths) — NOT a slot extent, so the byte
    /// caps stay honest under out-of-order arrival.
    fn size(&self) -> u64 {
        self.lengths.iter().filter_map(|l| l.map(u64::from)).sum()
    }
    /// How many chunks are stored (completion = all `count`).
    fn received(&self) -> u32 {
        self.lengths.iter().filter(|l| l.is_some()).count() as u32
    }
    /// First index NOT yet stored — the contiguous watermark a sequential resumable upload
    /// continues from (re-sending an already-present later chunk is idempotent, so a resumer
    /// with gaps still converges).
    fn next(&self) -> u32 {
        self.lengths.iter().position(|l| l.is_none()).map(|i| i as u32).unwrap_or(self.count)
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
            m.lengths[index as usize] // Some(old_len) if this index is a re-send (idempotent)
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
            lengths: vec![None; count as usize],
            created_at: now,
            complete: false,
        });
        m.lengths[index as usize] = Some(add as u32);
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
        m.lengths.get(index as usize).copied().flatten()?;
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
                for i in 0..m.count {
                    let _ = std::fs::remove_file(dir.join(format!("{}.c{i}", hex::encode(id))));
                }
                let _ = std::fs::remove_file(dir.join(format!("{}.meta", hex::encode(id))));
            }
            keep
        });
        self.total_bytes -= freed.min(self.total_bytes);
    }

    /// Rebuild the in-memory index from the on-disk sidecars. Called by [`open`](Self::open).
    /// Sidecar-driven: each `<id>.meta` names a blob; its chunk files (`<id>.c<i>`) are scanned to
    /// see which chunks survived. Files not belonging to a recovered blob (orphan chunks, `.tmp`
    /// leftovers, old `KBM1` single-data files) are swept.
    fn recover(&mut self, now: u64) -> io::Result<()> {
        let dir = self.dir.clone();
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            let Some(id) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".meta"))
                .and_then(parse_blob_id)
            else {
                continue;
            };
            match self.recover_one(&id, now) {
                Ok(Some((meta, size))) => {
                    self.total_bytes += size;
                    self.blobs.insert(id, meta);
                }
                // Junk (bad/old-format sidecar, TTL-expired, or no chunks survived): drop it all.
                Ok(None) | Err(_) => self.drop_blob_files(&id),
            }
        }
        // Sweep stray files that belong to no recovered blob: orphan chunk/tmp files and old-format
        // single-data files (`<id>` with no suffix). Their leading 64-hex names the blob.
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
            if let Some(id) = leading_blob_id(name) {
                if !self.blobs.contains_key(&id) {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        Ok(())
    }

    /// Reconstruct one blob's `Meta` from its sidecar header + the chunk files present on disk.
    /// `Ok(None)` = drop it (bad/old-format header, TTL-expired, or no chunks survived).
    fn recover_one(&self, id: &[u8; 32], now: u64) -> io::Result<Option<(Meta, u64)>> {
        let meta_bytes = match std::fs::read(self.meta_path(id)) {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };
        if meta_bytes.len() < META_HEADER_LEN || &meta_bytes[..4] != META_MAGIC {
            return Ok(None); // absent, short, or an older format (KBM1) — discard
        }
        let mut sender = [0u8; 32];
        sender.copy_from_slice(&meta_bytes[4..36]);
        let count = u32::from_le_bytes(meta_bytes[36..40].try_into().unwrap());
        let created_at = u64::from_le_bytes(meta_bytes[40..48].try_into().unwrap());
        if count == 0 || count > MAX_BLOB_CHUNKS {
            return Ok(None);
        }
        // TTL: an expired blob is dropped rather than recovered.
        if now.saturating_sub(created_at) > BLOB_TTL_SECS {
            return Ok(None);
        }

        // Scan which chunk files survived (atomic rename → each is whole or absent, never torn).
        // Also clear any `.tmp` leftover from a crash mid-write.
        let mut lengths = vec![None; count as usize];
        let mut acc = 0u64;
        let mut received = 0u32;
        for i in 0..count {
            let _ = std::fs::remove_file(self.dir.join(format!("{}.c{i}.tmp", hex::encode(id))));
            if let Ok(meta) = std::fs::metadata(self.chunk_path(id, i)) {
                let len = meta.len();
                if len > 0 && len <= MAX_BLOB_CHUNK as u64 {
                    lengths[i as usize] = Some(len as u32);
                    acc += len;
                    received += 1;
                }
            }
        }
        if received == 0 {
            return Ok(None); // header only, no chunks — a fresh re-upload will recreate it
        }

        let complete = received == count;
        Ok(Some((Meta { sender, count, lengths, created_at, complete }, acc)))
    }

    /// Delete every on-disk file for a blob: its sidecar and all its chunk (+ `.tmp`) files.
    fn drop_blob_files(&self, id: &[u8; 32]) {
        let hex = hex::encode(id);
        let _ = std::fs::remove_file(self.meta_path(id));
        for entry in std::fs::read_dir(&self.dir).into_iter().flatten().flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with(&hex) && name != format!("{hex}.meta") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
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
        // The sender fills the gap and the blob completes.
        assert_eq!(s.put_chunk(a, b, 1, 3, b"bb", 0), BlobPut::Complete);
        assert_eq!(s.get_chunk(&b, 1).as_deref(), Some(&b"bb"[..]));
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
}
