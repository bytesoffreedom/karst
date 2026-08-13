//! One sealed record: the only shape anything in the container is written in.
//!
//! # Why a fresh random nonce and never a counter
//!
//! A counter is the obvious choice and it is wrong here. This container commits by switching
//! between two root generations, and recovery deliberately ROLLS BACK to the older one — which
//! means a counter that had already advanced is now behind again, and the next write reuses a
//! number it has used before. For ChaCha20-Poly1305 that is catastrophic, not merely untidy.
//!
//! A 24-byte random nonce removes the question: there is no state to roll back, and the collision
//! probability over any number of records this format can hold is not a number anyone needs to
//! reason about. The cost is 24 bytes a record, paid in the framing the geometry already subtracts.
//!
//! # Why domain separation is BOTH subkeys and AAD
//!
//! A label alone is not separation — it is a hope that every call site remembers the same string.
//! So each purpose gets its own key derived by HKDF, AND the record's position is bound into the
//! AAD. The first stops a record sealed for one purpose from opening under another's key at all;
//! the second stops a record valid in one PLACE from being valid in another, which is the attack a
//! subkey does not touch: lifting a map node to a different offset, or replaying a block from an
//! older generation.

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

/// Bytes of nonce carried by every record.
pub const NONCE_LEN: usize = 24;
/// Bytes of AEAD tag.
pub const TAG_LEN: usize = 16;
/// Version and type bytes.
pub const HEADER_LEN: usize = 2;

/// Format version of the record encoding itself. Bumped only when the framing changes.
const RECORD_VERSION: u8 = 1;

/// What a record is. On the wire it is one byte, and it is bound into the AAD so a record of one
/// kind cannot be accepted where another is expected — even under the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    /// A block of an object's data.
    Payload = 1,
    /// A node of a space's mapping tree.
    MapNode = 2,
    /// A root: the commit point of a space.
    Root = 3,
    /// A capsule of the hidden ownership layer.
    Capsule = 4,
    /// The transaction manifest.
    Manifest = 5,
    /// The free-block index (a hint, never the authority).
    FreeIndex = 6,
}

/// Which space a record belongs to. Bound into the AAD, so a record of the public space can never
/// authenticate as one of the hidden space or of the ownership layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpaceId {
    Public = 1,
    Hidden = 2,
    Ownership = 3,
}

/// Everything a record's validity is tied to besides its key.
///
/// All of it goes into the AAD, none of it is stored in the record: it is reconstructed by the
/// reader from where the record was FOUND. A record that authenticates therefore proves it was
/// written for exactly this place, generation and copy — not merely by someone holding the key.
#[derive(Debug, Clone, Copy)]
pub struct Context {
    /// Hash of the canonical `format_params`. Binds every record to the geometry it was written
    /// under, so an attacker cannot rewrite the open header and have old records still verify.
    pub format_hash: [u8; 32],
    pub record_type: RecordType,
    pub space: SpaceId,
    pub physical_block: u64,
    /// Logical block for payload, tree prefix for a map node, zero where neither applies.
    pub logical_or_prefix: u64,
    pub generation: u64,
    /// 0 or 1 for the two-copy structures; 0 elsewhere.
    pub copy_index: u8,
}

impl Context {
    fn aad(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + 1 + 1 + 8 + 8 + 8 + 1);
        v.extend_from_slice(&self.format_hash);
        v.push(self.record_type as u8);
        v.push(self.space as u8);
        v.extend_from_slice(&self.physical_block.to_le_bytes());
        v.extend_from_slice(&self.logical_or_prefix.to_le_bytes());
        v.extend_from_slice(&self.generation.to_le_bytes());
        v.push(self.copy_index);
        v
    }
}

/// A master key for one space or for the ownership layer. Never used to encrypt anything directly.
#[derive(Clone)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn from_bytes(k: [u8; 32]) -> Self {
        Self(k)
    }

    /// The raw key bytes.
    ///
    /// Needed where a key has to be STORED rather than used — a slot holds a space key, and the
    /// session layer compares two keys to prove that two passwords open one account. Kept narrow
    /// on purpose: everything else takes a `&MasterKey` and derives its own subkey.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// A fresh master key.
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        Self(k)
    }

    /// The key one record type is sealed under. Distinct per purpose, so a payload key cannot open
    /// a map node however the AAD is manipulated.
    fn subkey(&self, t: RecordType) -> [u8; 32] {
        let label: &[u8] = match t {
            RecordType::Payload => b"karst-vault-payload-v1",
            RecordType::MapNode => b"karst-vault-map-v1",
            RecordType::Root => b"karst-vault-root-v1",
            RecordType::Capsule => b"karst-vault-capsule-v1",
            RecordType::Manifest => b"karst-vault-manifest-v1",
            RecordType::FreeIndex => b"karst-vault-freeidx-v1",
        };
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut out = [0u8; 32];
        hk.expand(label, &mut out).expect("32 bytes is a valid HKDF length");
        out
    }
}

/// Seal `plaintext` as a record valid at exactly `ctx`.
pub fn seal(key: &MasterKey, ctx: &Context, plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new((&key.subkey(ctx.record_type)).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad: &ctx.aad() })
        .expect("XChaCha20-Poly1305 encryption cannot fail on a valid key");
    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ct.len());
    out.push(RECORD_VERSION);
    out.push(ctx.record_type as u8);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    out
}

/// Open a record, or `None`.
///
/// `None` is deliberately the ONLY failure: a wrong key, a record from another place, a record of
/// another generation, a torn write and plain random bytes are indistinguishable to the caller.
/// That is not laziness — the ownership layer's whole fail-closed rule is built on "could not read
/// it" being one answer, because a caller that could tell those apart would be an oracle.
pub fn open(key: &MasterKey, ctx: &Context, record: &[u8]) -> Option<Vec<u8>> {
    if record.len() < HEADER_LEN + NONCE_LEN + TAG_LEN {
        return None;
    }
    if record[0] != RECORD_VERSION || record[1] != ctx.record_type as u8 {
        return None;
    }
    let nonce = XNonce::from_slice(&record[HEADER_LEN..HEADER_LEN + NONCE_LEN]);
    let cipher = XChaCha20Poly1305::new((&key.subkey(ctx.record_type)).into());
    cipher
        .decrypt(nonce, Payload { msg: &record[HEADER_LEN + NONCE_LEN..], aad: &ctx.aad() })
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context {
        Context {
            format_hash: [7u8; 32],
            record_type: RecordType::Payload,
            space: SpaceId::Public,
            physical_block: 42,
            logical_or_prefix: 9,
            generation: 3,
            copy_index: 0,
        }
    }

    #[test]
    fn a_record_opens_where_it_was_sealed() {
        let k = MasterKey::generate();
        let sealed = seal(&k, &ctx(), b"hello");
        assert_eq!(open(&k, &ctx(), &sealed).as_deref(), Some(&b"hello"[..]));
    }

    /// Every field of the context is load-bearing. Moving a record to another block, another
    /// space, another generation or the other copy slot must invalidate it — a record that is
    /// valid anywhere is a record an attacker can relocate.
    #[test]
    fn every_context_field_is_bound_and_moving_the_record_breaks_it() {
        let k = MasterKey::generate();
        let sealed = seal(&k, &ctx(), b"payload");

        let mut moved = ctx();
        moved.physical_block += 1;
        assert!(open(&k, &moved, &sealed).is_none(), "relocated to another block");

        let mut other_space = ctx();
        other_space.space = SpaceId::Hidden;
        assert!(open(&k, &other_space, &sealed).is_none(), "accepted as the hidden space's");

        let mut older = ctx();
        older.generation -= 1;
        assert!(open(&k, &older, &sealed).is_none(), "replayed from another generation");

        let mut other_copy = ctx();
        other_copy.copy_index = 1;
        assert!(open(&k, &other_copy, &sealed).is_none(), "accepted as the other copy");

        let mut other_geometry = ctx();
        other_geometry.format_hash = [8u8; 32];
        assert!(open(&k, &other_geometry, &sealed).is_none(), "accepted under rewritten params");
    }

    /// A payload key must not open a map node even at the same place: the subkeys separate the
    /// purposes, so this holds independently of the AAD.
    #[test]
    fn one_record_type_cannot_be_opened_as_another() {
        let k = MasterKey::generate();
        let mut as_map = ctx();
        as_map.record_type = RecordType::MapNode;
        let sealed = seal(&k, &as_map, b"a node");
        assert!(open(&k, &ctx(), &sealed).is_none(), "a map node opened as a payload");
    }

    /// Two seals of identical plaintext at the identical place must not produce identical bytes —
    /// otherwise the container tells an observer that a block was rewritten with what it already
    /// held, which is exactly the kind of "nothing changed" signal §7 is trying not to emit.
    #[test]
    fn sealing_the_same_bytes_twice_gives_different_records() {
        let k = MasterKey::generate();
        let a = seal(&k, &ctx(), b"same");
        let b = seal(&k, &ctx(), b"same");
        assert_ne!(a, b, "the nonce is not fresh per record");
        assert_eq!(open(&k, &ctx(), &a), open(&k, &ctx(), &b));
    }

    /// A wrong key, random bytes and a truncated record are ONE answer. The ownership layer's
    /// fail-closed rule depends on this: a caller that could distinguish them would be an oracle.
    #[test]
    fn every_kind_of_failure_looks_the_same() {
        let k = MasterKey::generate();
        let stranger = MasterKey::generate();
        let sealed = seal(&k, &ctx(), b"secret");

        assert!(open(&stranger, &ctx(), &sealed).is_none());
        assert!(open(&k, &ctx(), &[0u8; 64]).is_none());
        assert!(open(&k, &ctx(), &sealed[..sealed.len() - 1]).is_none());
        assert!(open(&k, &ctx(), &[]).is_none());
    }

    /// The framing constant the geometry subtracts must match what a record actually costs.
    /// If these drift, the map claims room for entries that do not fit.
    #[test]
    fn the_framing_matches_what_the_geometry_subtracts() {
        let k = MasterKey::generate();
        let sealed = seal(&k, &ctx(), b"");
        assert_eq!(sealed.len(), crate::geometry::RECORD_FRAMING, "framing drifted");
        assert_eq!(HEADER_LEN + NONCE_LEN + TAG_LEN, crate::geometry::RECORD_FRAMING);
    }

    /// A tampered ciphertext byte is a failure, not a silently different plaintext.
    #[test]
    fn a_flipped_bit_fails_closed() {
        let k = MasterKey::generate();
        let mut sealed = seal(&k, &ctx(), b"integrity");
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(open(&k, &ctx(), &sealed).is_none());
    }
}
