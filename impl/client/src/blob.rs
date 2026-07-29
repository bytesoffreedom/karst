//! E2E blob encryption for LARGE-file transfer (dual-path §15: small files stay on the
//! inline padded-mailbox path so fixed-size fetch still hides them; files above a
//! threshold ride an encrypted blob parked on the relay, so offline delivery works).
//!
//! Per file: a **fresh random key `K`** — so the relay stores only ciphertext (compromising
//! the blob store yields nothing). Each chunk is sealed INDEPENDENTLY
//! (`ChaCha20-Poly1305`) so encryption/decryption STREAMS — peak RAM is O(chunk), not
//! O(file), which is the whole point for GB files. Its actual key and nonce are DERIVED
//! per chunk from `K` and a fresh random salt (see [`chunk_aead`]), so a resume path that
//! hands the same `K` to different bytes cannot produce a two-time pad.
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

/// Per-chunk salt width, carried as a plaintext prefix on every sealed chunk. See
/// [`chunk_aead`] for why a counter nonce alone was not enough.
pub const CHUNK_SALT: usize = 16;

/// `(AEAD key, nonce)` for ONE chunk: HKDF-SHA256 over the file key `K`, salted with that
/// chunk's own random salt and bound to its index.
///
/// The old scheme was `key = K`, `nonce = LE32(index) ‖ 0^64`, safe under exactly one
/// invariant: `K` is fresh for each immutable file and never encrypts other bytes. The resume
/// layer broke it — `upload_id_for` identified a transfer by (recipient, basename, declared
/// size), so a DIFFERENT file with the same name and size resumed onto the stored `blob_id` and
/// `K`. Same key, same index, same nonce, same AAD, different plaintext: the relay holds two
/// ciphertexts whose XOR is the XOR of the two plaintexts, and the Poly1305 key is reused.
///
/// Reusing `K` is now HARMLESS rather than forbidden: a fresh salt per chunk lands every
/// encryption on its own key and nonce, whatever the resume layer does. `index` stays in the
/// derivation so even a repeated salt across two chunks of the SAME file cannot collide.
fn chunk_aead(key: &BlobKey, index: u32, salt: &[u8; CHUNK_SALT]) -> ([u8; 32], Nonce) {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), key);
    let mut info = [0u8; 23];
    info[..19].copy_from_slice(b"KARST-blob-chunk-v2");
    info[19..].copy_from_slice(&index.to_le_bytes());
    let mut okm = [0u8; 44];
    hk.expand(&info, &mut okm).expect("44 within HKDF output limit");
    let mut k = [0u8; 32];
    k.copy_from_slice(&okm[..32]);
    (k, *Nonce::from_slice(&okm[32..]))
}

/// The blob's DURABLE owner handle — what a `BlobPut` puts in `client_addr`. The relay's blob
/// store is first-writer-wins: it records the `sender` of a blob's first chunk and rejects later
/// chunks from anyone else ("blob owned by another sender"). That check needs an identity that
/// outlives the process, and the transport-level address was the opposite of one — a random value
/// minted per `Relay` and deliberately never persisted. So an upload
/// interrupted by a CLIENT restart could never be continued: the resume record survived, the
/// identity that owned the bytes did not, and every retry minted another stranger (A4-1). The
/// upload stayed stuck until the relay's 7-day TTL swept the partial blob.
///
/// Deriving the handle from the file key kills that class rather than the instance: the one thing
/// a resume already has to persist (`K`, in `PendingUpload`) now IS the proof of ownership, so
/// ownership is durable exactly when and because resumability is, with no second secret to keep in
/// sync. It is also per-blob, where the value it replaces was per-process: no field the
/// uploader sends now repeats across two of its blobs (`verify_durability`, which runs on the same
/// `blob_id` right after each upload, uses this handle too — a value shared across uploads would
/// have re-linked the blobs it had just separated).
///
/// Honest limits. (1) This is NOT anonymity: the relay still sees one connection uploading blob
/// after blob, so IP + timing correlate them however the addressing field is derived — this removes
/// a stable identifier the client was handing over for free, nothing more. The recipient's
/// downloads carry a fresh address per download for the same reason (`blob_get_addr`). (2) It is a bearer token, not a
/// challenge-response proof: the relay compares bytes, so anyone who learns the token can append to
/// an INCOMPLETE blob. Deriving it needs `K`, which only the uploader has until the `FileRef` goes
/// out — and by then the blob is complete and frozen. (3) The relay's per-sender caps
/// (`MAX_SENDER_BYTES`, `MAX_BLOBS_PER_SENDER`) now aggregate per BLOB for honest clients, i.e. they
/// stop binding; see the note on the upload driver in `lib.rs` for what still does.
pub fn owner_token(key: &BlobKey, id: &BlobId) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(id), key);
    let mut out = [0u8; 32];
    hk.expand(b"KARST-blob-owner-v1", &mut out).expect("32 within HKDF output limit");
    out
}

/// Position-binding AAD: authenticates where this chunk sits so the relay cannot move,
/// drop, or splice chunks undetected. `count`/`is_last` also pin the total length.
fn chunk_aad(
    id: &BlobId,
    index: u32,
    count: u32,
    is_last: bool,
    salt: &[u8; CHUNK_SALT],
) -> [u8; 41 + CHUNK_SALT] {
    let mut a = [0u8; 41 + CHUNK_SALT];
    a[..32].copy_from_slice(id);
    a[32..36].copy_from_slice(&index.to_le_bytes());
    a[36..40].copy_from_slice(&count.to_le_bytes());
    a[40] = is_last as u8;
    a[41..].copy_from_slice(salt);
    a
}

/// Seal one plaintext chunk as `salt(16) ‖ ciphertext`. Infallible for valid inputs (AEAD only
/// fails on absurd lengths, which our fixed chunking never produces). The salt rides in the
/// clear — it is a KDF input, not a secret — and is covered by the AAD, so altering it in
/// transit only breaks the tag.
pub fn seal_chunk(
    key: &BlobKey,
    id: &BlobId,
    index: u32,
    count: u32,
    is_last: bool,
    plaintext: &[u8],
) -> Vec<u8> {
    let mut salt = [0u8; CHUNK_SALT];
    OsRng.fill_bytes(&mut salt);
    let (k, nonce) = chunk_aead(key, index, &salt);
    let cipher = ChaCha20Poly1305::new((&k).into());
    let aad = chunk_aad(id, index, count, is_last, &salt);
    let ct = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad: &aad })
        .expect("ChaCha20-Poly1305 seal");
    let mut out = Vec::with_capacity(CHUNK_SALT + ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&ct);
    out
}

/// Open one `salt ‖ ciphertext` chunk at its claimed position. Fails (closed) on any tamper:
/// flipped byte, wrong key, moved/relabelled chunk, altered total, or a swapped salt.
pub fn open_chunk(
    key: &BlobKey,
    id: &BlobId,
    index: u32,
    count: u32,
    is_last: bool,
    stored: &[u8],
) -> Result<Vec<u8>, String> {
    if stored.len() < CHUNK_SALT {
        return Err("blob chunk shorter than its salt".to_string());
    }
    let mut salt = [0u8; CHUNK_SALT];
    salt.copy_from_slice(&stored[..CHUNK_SALT]);
    let (k, nonce) = chunk_aead(key, index, &salt);
    let cipher = ChaCha20Poly1305::new((&k).into());
    let aad = chunk_aad(id, index, count, is_last, &salt);
    cipher
        .decrypt(&nonce, Payload { msg: &stored[CHUNK_SALT..], aad: &aad })
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

    /// CRYPTO-31, THE carrying test. Re-sealing the SAME position under the SAME file key with
    /// DIFFERENT bytes is exactly what a resume onto a changed file did. Under the old scheme
    /// (`key = K`, `nonce = LE32(index)`) the relay could XOR the two stored ciphertexts and read
    /// the XOR of the two plaintexts without any key.
    ///
    /// Discriminating: it asserts that XOR relation is BROKEN, not merely that the two
    /// ciphertexts differ — the latter held under the broken scheme too.
    #[test]
    fn resealing_a_chunk_position_does_not_reuse_the_keystream() {
        let (key, id) = (random32(), random32());
        let pt1 = b"the original file's first chunk.";
        let pt2 = b"a different file, same position.";

        let c1 = seal_chunk(&key, &id, 0, 1, true, pt1);
        let c2 = seal_chunk(&key, &id, 0, 1, true, pt2);

        assert_ne!(&c1[..CHUNK_SALT], &c2[..CHUNK_SALT], "each chunk must carry a FRESH salt");
        let body1 = &c1[CHUNK_SALT..];
        let body2 = &c2[CHUNK_SALT..];
        let xor_ct: Vec<u8> = body1.iter().zip(body2).map(|(a, b)| a ^ b).collect();
        let xor_pt: Vec<u8> = pt1.iter().zip(pt2.iter()).map(|(a, b)| a ^ b).collect();
        assert_ne!(
            &xor_ct[..xor_pt.len()],
            &xor_pt[..],
            "keystream reuse: the relay can XOR two stored chunks and recover the XOR of both \
             plaintexts — the chunk key/nonce must depend on the per-chunk salt"
        );
    }

    /// A4-1: the owner handle must be a pure function of the two things a resume already persists
    /// (`blob_id`, `K`) — that is the whole reason it survives a client restart — while separating
    /// blobs from each other and never leaking the file key onto the wire.
    #[test]
    fn the_owner_token_is_derived_only_from_the_blob_id_and_key() {
        let (key, id) = (random32(), random32());
        assert_eq!(owner_token(&key, &id), owner_token(&key, &id), "same inputs → same handle");
        assert_ne!(owner_token(&key, &random32()), owner_token(&key, &id), "per-blob, not per-key");
        assert_ne!(owner_token(&random32(), &id), owner_token(&key, &id), "a stranger cannot claim it");
        // It travels in the clear as `client_addr`, so it must not be the key (nor the id, which
        // the relay already knows — that would make the handle no proof at all).
        assert_ne!(owner_token(&key, &id), key, "the file key must not ride on the wire");
        assert_ne!(owner_token(&key, &id), id, "the handle must not be public knowledge");
    }

    /// The salt is authenticated, not merely carried: swapping in another chunk's salt must fail
    /// the tag. Guards against deriving from the salt while forgetting to bind it into the AAD.
    #[test]
    fn a_swapped_chunk_salt_fails_the_tag() {
        let (key, id) = (random32(), random32());
        let mut c = seal_chunk(&key, &id, 0, 1, true, b"payload");
        c[0] ^= 1;
        assert!(open_chunk(&key, &id, 0, 1, true, &c).is_err(), "tampered salt must not open");
    }

    /// A sealed chunk must still fit the relay's per-chunk ceiling with the salt on top —
    /// otherwise a full-size upload would be rejected at the last moment, on the biggest files.
    #[test]
    fn a_full_size_sealed_chunk_stays_under_the_relay_ceiling() {
        let (key, id) = (random32(), random32());
        let sealed = seal_chunk(&key, &id, 0, 2, false, &vec![0u8; BLOB_CHUNK]);
        assert!(
            sealed.len() <= node::blobstore::MAX_BLOB_CHUNK,
            "sealed chunk is {} B, over the relay's {} B ceiling",
            sealed.len(),
            node::blobstore::MAX_BLOB_CHUNK
        );
    }

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
