//! E2E blob encryption for LARGE-file transfer (dual-path §15: small files stay on the
//! inline padded-mailbox path so fixed-size fetch still hides them; files above a
//! threshold ride an encrypted blob parked on the relay, so offline delivery works).
//!
//! Per file: a **fresh random key `K`** — so the relay stores only ciphertext (compromising
//! the blob store yields nothing) and a counter nonce is safe (no reuse across files).
//! Each chunk is sealed INDEPENDENTLY (`ChaCha20-Poly1305`) so encryption/decryption
//! STREAMS — peak RAM is O(chunk), not O(file), which is the whole point for GB files.
//! The chunk's position `(blob_id ‖ index ‖ count ‖ is_last)` is in the AEAD's AAD, so
//! the untrusted relay cannot reorder / truncate / splice chunks without detection.
//! A SHA-256 of the **plaintext** is the end-to-end backstop, verified incrementally on
//! download. `blob_id` is RANDOM (not a content hash) so the relay gets no
//! "do you have file X?" confirmation oracle.
//!
//! Honest scope: this makes the relay hold (encrypted) bulk data — a fatter relay than
//! the minimal mailbox, a deliberate tradeoff (see docs/STATUS.md). Large-file transfer
//! also leaks size + timing to the relay in a way the padded small path does not.

use std::io::Write;

use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use sha2::{Digest, Sha256};

/// Plaintext bytes per chunk. 60 KiB keeps per-chunk overhead negligible and — crucially
/// — a whole `BlobPut` (chunk ciphertext + tag + addressing) then fits ONE 64 KiB Noise
/// session bucket, so each chunk costs a single size class on the wire, not two. Bounds
/// peak RAM to O(chunk).
pub const BLOB_CHUNK: usize = 60 * 1024;

pub type BlobKey = [u8; 32];
pub type BlobId = [u8; 32];

/// Fresh 32 random bytes (a per-file key, or a random blob id).
pub fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

/// Counter nonce for chunk `index`. Unique within a file because `K` is fresh per file,
/// so there is no nonce reuse under a fixed key (the catastrophe this must avoid).
fn chunk_nonce(index: u32) -> Nonce {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&index.to_le_bytes());
    *Nonce::from_slice(&n)
}

/// Position-binding AAD: authenticates where this chunk sits so the relay cannot move,
/// drop, or splice chunks undetected. `count`/`is_last` also pin the total length.
fn chunk_aad(id: &BlobId, index: u32, count: u32, is_last: bool) -> [u8; 41] {
    let mut a = [0u8; 41];
    a[..32].copy_from_slice(id);
    a[32..36].copy_from_slice(&index.to_le_bytes());
    a[36..40].copy_from_slice(&count.to_le_bytes());
    a[40] = is_last as u8;
    a
}

/// Seal one plaintext chunk. Infallible for valid inputs (AEAD only fails on absurd
/// lengths, which our fixed chunking never produces).
pub fn seal_chunk(
    key: &BlobKey,
    id: &BlobId,
    index: u32,
    count: u32,
    is_last: bool,
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let aad = chunk_aad(id, index, count, is_last);
    cipher
        .encrypt(&chunk_nonce(index), Payload { msg: plaintext, aad: &aad })
        .expect("ChaCha20-Poly1305 seal")
}

/// Open one ciphertext chunk at its claimed position. Fails (closed) on any tamper:
/// flipped byte, wrong key, moved/relabelled chunk, or altered total.
pub fn open_chunk(
    key: &BlobKey,
    id: &BlobId,
    index: u32,
    count: u32,
    is_last: bool,
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let aad = chunk_aad(id, index, count, is_last);
    cipher
        .decrypt(&chunk_nonce(index), Payload { msg: ciphertext, aad: &aad })
        .map_err(|_| "blob chunk authentication failed".to_string())
}

/// Number of chunks a plaintext of `size` bytes splits into (≥1; a 0-byte file is one
/// empty chunk so `is_last` and the hash still have a well-defined transfer).
pub fn chunk_count(size: u64) -> u32 {
    if size == 0 {
        return 1;
    }
    size.div_ceil(BLOB_CHUNK as u64) as u32
}

/// Streaming decryptor: feed ciphertext chunks IN ORDER, each is verified and its
/// plaintext appended to `out` (e.g. a temp file) — so peak RAM stays O(chunk). On
/// `finish`, the count and the end-to-end plaintext SHA-256 are checked before the
/// caller promotes the temp file to its final name.
pub struct BlobReceiver<W: Write> {
    key: BlobKey,
    id: BlobId,
    count: u32,
    next: u32,
    hasher: Sha256,
    expected_hash: [u8; 32],
    out: W,
}

impl<W: Write> BlobReceiver<W> {
    pub fn new(key: BlobKey, id: BlobId, count: u32, expected_hash: [u8; 32], out: W) -> Self {
        Self { key, id, count, next: 0, hasher: Sha256::new(), expected_hash, out }
    }

    /// Feed the NEXT expected chunk (index must equal the running position — the relay
    /// cannot feed them out of order without the AAD check failing anyway).
    pub fn feed(&mut self, index: u32, ciphertext: &[u8]) -> Result<(), String> {
        if index != self.next {
            return Err(format!("blob chunk out of order: got {index}, expected {}", self.next));
        }
        if index >= self.count {
            return Err("blob chunk index past declared count".to_string());
        }
        let is_last = index + 1 == self.count;
        let pt = open_chunk(&self.key, &self.id, index, self.count, is_last, ciphertext)?;
        self.hasher.update(&pt);
        self.out.write_all(&pt).map_err(|e| format!("writing blob chunk: {e}"))?;
        self.next += 1;
        Ok(())
    }

    /// All chunks in? Verify completeness + the end-to-end plaintext hash. Consumes self
    /// (the transfer is done) and returns the sink so the caller can flush/rename it.
    pub fn finish(self) -> Result<W, String> {
        if self.next != self.count {
            return Err(format!("blob incomplete: {} of {} chunks", self.next, self.count));
        }
        let got: [u8; 32] = self.hasher.finalize().into();
        if got != self.expected_hash {
            return Err("blob plaintext hash mismatch (corrupt or tampered)".to_string());
        }
        Ok(self.out)
    }
}

/// SHA-256 of a plaintext (the manifest/`FileRef` backstop the receiver re-derives).
pub fn plaintext_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seal `data` into positioned chunks (the send path does this streaming from disk;
    /// here we do it in memory to drive the receiver in tests).
    fn seal_all(key: &BlobKey, id: &BlobId, data: &[u8]) -> (u32, Vec<Vec<u8>>) {
        let count = chunk_count(data.len() as u64);
        let mut chunks = Vec::new();
        for index in 0..count {
            let start = index as usize * BLOB_CHUNK;
            let end = (start + BLOB_CHUNK).min(data.len());
            let is_last = index + 1 == count;
            chunks.push(seal_chunk(key, id, index, count, is_last, &data[start..end]));
        }
        (count, chunks)
    }

    fn roundtrip(data: &[u8]) -> Result<Vec<u8>, String> {
        let key = random32();
        let id = random32();
        let (count, chunks) = seal_all(&key, &id, data);
        let mut rx = BlobReceiver::new(key, id, count, plaintext_hash(data), Vec::new());
        for (i, ct) in chunks.iter().enumerate() {
            rx.feed(i as u32, ct)?;
        }
        rx.finish()
    }

    #[test]
    fn roundtrip_various_sizes_is_byte_identical() {
        for size in [0usize, 1, BLOB_CHUNK - 1, BLOB_CHUNK, BLOB_CHUNK + 1, 3 * BLOB_CHUNK + 7] {
            let data: Vec<u8> = (0..size).map(|i| (i.wrapping_mul(31) ^ 0xA5) as u8).collect();
            let got = roundtrip(&data).expect("clean roundtrip");
            assert_eq!(got, data, "size {size}: byte-identical");
        }
    }

    #[test]
    fn flipped_ciphertext_byte_is_detected() {
        let key = random32();
        let id = random32();
        let data = vec![7u8; BLOB_CHUNK + 100];
        let (count, mut chunks) = seal_all(&key, &id, &data);
        chunks[1][0] ^= 0x01; // corrupt one byte of the second chunk
        let mut rx = BlobReceiver::new(key, id, count, plaintext_hash(&data), Vec::new());
        assert!(rx.feed(0, &chunks[0]).is_ok());
        assert!(rx.feed(1, &chunks[1]).is_err(), "flipped byte must fail the AEAD");
    }

    #[test]
    fn wrong_key_is_detected() {
        let key = random32();
        let id = random32();
        let data = vec![9u8; 2 * BLOB_CHUNK];
        let (count, chunks) = seal_all(&key, &id, &data);
        let mut rx = BlobReceiver::new(random32(), id, count, plaintext_hash(&data), Vec::new());
        assert!(rx.feed(0, &chunks[0]).is_err(), "wrong key must not decrypt");
    }

    #[test]
    fn swapped_chunks_are_detected() {
        // A relay that reorders chunks: feed chunk 1's ciphertext at position 0. The
        // position is in the AAD, so decrypt-at-index-0 of a chunk sealed for index 1
        // fails closed.
        let key = random32();
        let id = random32();
        let data: Vec<u8> = (0..2 * BLOB_CHUNK).map(|i| i as u8).collect();
        let (count, chunks) = seal_all(&key, &id, &data);
        let mut rx = BlobReceiver::new(key, id, count, plaintext_hash(&data), Vec::new());
        assert!(rx.feed(0, &chunks[1]).is_err(), "chunk moved to a new position must fail");
    }

    #[test]
    fn dropped_last_chunk_is_detected() {
        // A relay that truncates: deliver all but the final chunk. Each delivered chunk
        // authenticates, but `finish` catches the missing tail (and the hash never matches).
        let key = random32();
        let id = random32();
        let data = vec![3u8; 3 * BLOB_CHUNK];
        let (count, chunks) = seal_all(&key, &id, &data);
        let mut rx = BlobReceiver::new(key, id, count, plaintext_hash(&data), Vec::new());
        for i in 0..count - 1 {
            rx.feed(i, &chunks[i as usize]).expect("prefix chunks authenticate");
        }
        assert!(rx.finish().is_err(), "a truncated blob must not verify");
    }

    #[test]
    fn forged_shorter_count_is_detected() {
        // A relay that lies about the total (claims fewer chunks) re-seals nothing — it
        // can only replay the sender's chunks, which carry the TRUE count in their AAD.
        // Opening chunk 0 under a forged smaller count fails.
        let key = random32();
        let id = random32();
        let data = vec![1u8; 2 * BLOB_CHUNK];
        let (real_count, chunks) = seal_all(&key, &id, &data);
        let forged = real_count - 1;
        let mut rx = BlobReceiver::new(key, id, forged, plaintext_hash(&data), Vec::new());
        assert!(rx.feed(0, &chunks[0]).is_err(), "forged count changes the AAD → fails");
    }
}
