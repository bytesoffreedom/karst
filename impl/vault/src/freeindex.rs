//! A hint about which blocks are free — and the reason it is never more than a hint.
//!
//! Scanning every capsule to find one free block would make allocation cost the whole container.
//! So the ownership layer keeps a bitmap: one bit per physical block, sealed under its own key,
//! living in blocks the layer owns.
//!
//! # It is a cache, and treating it as truth is the bug
//!
//! The index is written lazily and takes no part in the ordering of durable writes. That is a
//! deliberate choice, not an oversight: making it authoritative would put a second thing in the
//! commit path that has to be consistent with the capsules, and a disagreement between two
//! authorities is worse than one stale hint. A crash may leave it behind, another session may have
//! moved on without updating it, and the public mode does not know it exists at all — so anything
//! it says can be wrong.
//!
//! What makes that safe is that the capsule is re-read and verified before a block is taken
//! ([`crate::capsule::read_capsules`]). A stale index costs a wasted candidate, never a lost
//! block. The rule to keep is one line: **the index proposes, the capsule decides.**

use crate::record::{Context, MasterKey, RecordType, SpaceId};

/// One bit per physical block: set means "believed free".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreeIndex {
    generation: u64,
    bits: Vec<u8>,
    blocks: u64,
}

impl FreeIndex {
    /// A fresh index over `blocks` blocks, everything believed occupied.
    ///
    /// Empty rather than full on purpose. An index that starts out claiming everything is free
    /// would, if it were ever trusted before being rebuilt, propose every block in the container —
    /// including live ones. Starting empty degrades to "scan for candidates", which is slow and
    /// correct rather than fast and wrong.
    pub fn empty(blocks: u64) -> Self {
        Self { generation: 0, bits: vec![0u8; blocks.div_ceil(8) as usize], blocks }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn blocks(&self) -> u64 {
        self.blocks
    }

    /// Mark a block believed free, or believed taken.
    pub fn set(&mut self, block: u64, free: bool) {
        if block >= self.blocks {
            return;
        }
        let (byte, bit) = ((block / 8) as usize, (block % 8) as u8);
        if free {
            self.bits[byte] |= 1 << bit;
        } else {
            self.bits[byte] &= !(1 << bit);
        }
    }

    /// Whether the index BELIEVES this block is free. Never a decision on its own.
    pub fn believes_free(&self, block: u64) -> bool {
        if block >= self.blocks {
            return false;
        }
        self.bits[(block / 8) as usize] & (1 << (block % 8)) != 0
    }

    /// Blocks the index believes are free. A count for the user interface and for deciding whether
    /// to bother scanning — not a capacity guarantee.
    pub fn believed_free_count(&self) -> u64 {
        self.bits.iter().map(|b| u64::from(b.count_ones())).sum()
    }

    /// Bump the generation, so a reader can tell which of two indexes is newer.
    pub fn touch(&mut self) {
        self.generation += 1;
    }

    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(16 + self.bits.len());
        v.extend_from_slice(&self.generation.to_le_bytes());
        v.extend_from_slice(&self.blocks.to_le_bytes());
        v.extend_from_slice(&self.bits);
        v
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        let generation = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
        let blocks = u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes"));
        let bits = bytes[16..].to_vec();
        // A bitmap that does not cover the block count it claims is corrupt, not partly usable:
        // trusting the covered part would silently treat the rest as occupied and strand it.
        if bits.len() != blocks.div_ceil(8) as usize {
            return None;
        }
        Some(Self { generation, bits, blocks })
    }
}

fn ctx(format_hash: [u8; 32], block: u64, generation: u64) -> Context {
    Context {
        format_hash,
        record_type: RecordType::FreeIndex,
        space: SpaceId::Ownership,
        physical_block: block,
        logical_or_prefix: 0,
        generation,
        copy_index: 0,
    }
}

/// Seal the index for storage at `block`.
pub fn seal(key: &MasterKey, format_hash: [u8; 32], block: u64, index: &FreeIndex) -> Vec<u8> {
    crate::record::seal(key, &ctx(format_hash, block, index.generation), &index.encode())
}

/// Read an index that was sealed at `block` under `generation`, or `None`.
///
/// `None` is not an error worth reporting upward: the caller rebuilds by scanning capsules. That
/// is slow and always correct, which is the right fallback for a structure whose whole job is to
/// be a shortcut.
pub fn open(
    key: &MasterKey,
    format_hash: [u8; 32],
    block: u64,
    generation: u64,
    sealed: &[u8],
) -> Option<FreeIndex> {
    let plain = crate::record::open(key, &ctx(format_hash, block, generation), sealed)?;
    let idx = FreeIndex::decode(&plain)?;
    (idx.generation == generation).then_some(idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FH: [u8; 32] = [5u8; 32];

    /// A fresh index claims nothing is free. The opposite default would propose live blocks if it
    /// were ever consulted before a rebuild.
    #[test]
    fn a_fresh_index_believes_nothing_is_free() {
        let idx = FreeIndex::empty(1000);
        assert_eq!(idx.believed_free_count(), 0);
        assert!(!idx.believes_free(0));
        assert!(!idx.believes_free(999));
    }

    #[test]
    fn bits_set_and_clear_independently() {
        let mut idx = FreeIndex::empty(100);
        idx.set(7, true);
        idx.set(8, true);
        assert!(idx.believes_free(7) && idx.believes_free(8));
        idx.set(7, false);
        assert!(!idx.believes_free(7), "clearing 7 must not depend on 8");
        assert!(idx.believes_free(8), "clearing 7 cleared its neighbour");
        assert_eq!(idx.believed_free_count(), 1);
    }

    /// Out-of-range blocks are ignored rather than panicking or wrapping into another block's bit.
    #[test]
    fn a_block_past_the_end_is_ignored_not_wrapped() {
        let mut idx = FreeIndex::empty(10);
        idx.set(10_000, true);
        assert!(!idx.believes_free(10_000));
        assert_eq!(idx.believed_free_count(), 0, "an out-of-range set touched a real bit");
    }

    #[test]
    fn an_index_survives_a_round_trip() {
        let k = MasterKey::generate();
        let mut idx = FreeIndex::empty(500);
        idx.set(3, true);
        idx.set(499, true);
        idx.touch();
        let sealed = seal(&k, FH, 2, &idx);
        assert_eq!(open(&k, FH, 2, idx.generation(), &sealed).as_ref(), Some(&idx));
    }

    /// The index is bound to its generation: an older copy left behind by a crash does not open as
    /// the current one, so a reader cannot silently pick up a stale map.
    #[test]
    fn an_index_does_not_open_under_another_generation() {
        let k = MasterKey::generate();
        let mut idx = FreeIndex::empty(64);
        idx.touch();
        let sealed = seal(&k, FH, 1, &idx);
        assert!(open(&k, FH, 1, idx.generation() + 1, &sealed).is_none());
        assert!(open(&k, FH, 1, 0, &sealed).is_none());
    }

    /// And to its block, so a copy cannot be relocated to stand in for another.
    #[test]
    fn an_index_does_not_open_at_another_block() {
        let k = MasterKey::generate();
        let idx = FreeIndex::empty(64);
        let sealed = seal(&k, FH, 1, &idx);
        assert!(open(&k, FH, 2, idx.generation(), &sealed).is_none());
    }

    /// A bitmap that does not cover the count it claims is rejected. Accepting it would treat the
    /// uncovered tail as occupied and strand that capacity for good.
    #[test]
    fn a_bitmap_shorter_than_its_claimed_block_count_is_rejected() {
        let mut bytes = FreeIndex::empty(1000).encode();
        bytes.truncate(bytes.len() - 1);
        assert!(FreeIndex::decode(&bytes).is_none());
    }

    /// Junk does not decode into a usable index — the caller falls back to scanning.
    #[test]
    fn junk_does_not_decode() {
        assert!(FreeIndex::decode(&[]).is_none());
        assert!(FreeIndex::decode(&[0u8; 4]).is_none());
        let k = MasterKey::generate();
        assert!(open(&k, FH, 1, 0, &[0xABu8; 90]).is_none());
    }

    /// A stale index is allowed to be WRONG in the direction that costs a wasted candidate, and
    /// the capsule is what catches it. This test states the contract rather than checking code:
    /// nothing here may treat `believes_free` as permission.
    #[test]
    fn believing_a_block_is_free_is_not_permission_to_take_it() {
        let mut idx = FreeIndex::empty(10);
        idx.set(4, true);
        // The index says yes. That is all it can say — the decision needs the capsule, which lives
        // in another module and takes no argument from this one.
        assert!(idx.believes_free(4));
        assert_eq!(idx.believed_free_count(), 1);
    }
}
