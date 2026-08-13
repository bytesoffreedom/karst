//! The logical-to-physical map: a radix tree of fixed depth.
//!
//! # Why fixed depth and not a B-tree
//!
//! A B-tree splits nodes, and a split makes the cost of a write depend on how full its neighbours
//! happen to be. The credit protocol needs the worst case of a transaction to be computable BEFORE
//! the transaction starts (`plan`), and "however many splits cascade this time" is not computable.
//! A radix tree of fixed depth has no splits at all: a logical block number is just its digits in
//! base `fanout`, and the path to it is the same length forever.
//!
//! The price is one extra level compared to what a tighter fit would need, and that is the right
//! side to err on. The depth is a constant of the format — the same for every container, whatever
//! its size and whether or not a hidden space exists — which is the property §7 rests on.
//!
//! # Sparse by construction
//!
//! An entry of zero means "no mapping". Unused branches are not stored, not allocated, and cost
//! nothing, which is what lets the address space be enormously larger than the container. That in
//! turn is what lets every object own a static slice of it instead of a growable extent list.

use crate::geometry::{Geometry, ENTRY_LEN, RESERVED_BLOCK};

/// One node: `fanout` entries, each a physical block number.
///
/// Held decoded. Encoding and sealing happen at the storage boundary — a node does not know which
/// key it belongs under, and keeping it that way is what stops the tree from acquiring an opinion
/// about the ownership layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    entries: Vec<u64>,
}

impl Node {
    /// An empty node: every entry unmapped.
    pub fn empty(g: &Geometry) -> Self {
        Self { entries: vec![RESERVED_BLOCK; g.fanout() as usize] }
    }

    pub fn get(&self, slot: u64) -> Option<u64> {
        match self.entries.get(slot as usize).copied() {
            Some(RESERVED_BLOCK) | None => None,
            Some(b) => Some(b),
        }
    }

    /// Point `slot` at `block`, or clear it with [`RESERVED_BLOCK`].
    pub fn set(&mut self, slot: u64, block: u64) -> bool {
        match self.entries.get_mut(slot as usize) {
            Some(e) => {
                *e = block;
                true
            }
            None => false,
        }
    }

    /// Whether every entry is unmapped — the condition for retiring the node itself.
    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(|&e| e == RESERVED_BLOCK)
    }

    /// Encode for sealing: little-endian entries, fixed length.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.entries.len() * ENTRY_LEN);
        for e in &self.entries {
            out.extend_from_slice(&e.to_le_bytes());
        }
        out
    }

    /// Decode a node, or `None` if the bytes are not a whole number of entries or do not match the
    /// geometry. A short read is a corrupt node, never a partially usable one.
    pub fn decode(g: &Geometry, bytes: &[u8]) -> Option<Self> {
        if bytes.len() != g.fanout() as usize * ENTRY_LEN {
            return None;
        }
        let entries = bytes
            .chunks_exact(ENTRY_LEN)
            .map(|c| u64::from_le_bytes(c.try_into().expect("chunks_exact yields 8 bytes")))
            .collect();
        Some(Self { entries })
    }
}

/// The digits of `logical` in base `fanout`, most significant first — the slot to take at each
/// level, from the root down.
///
/// Length is always [`Geometry::depth`], so a caller cannot accidentally walk a shorter path for a
/// small block number and end up reading a node as if it were a leaf.
pub fn path(g: &Geometry, logical: u64) -> Vec<u64> {
    let f = g.fanout();
    let depth = g.depth() as usize;
    let mut digits = vec![0u64; depth];
    let mut rest = logical;
    for d in (0..depth).rev() {
        digits[d] = rest % f;
        rest /= f;
    }
    digits
}

/// Whether `logical` is addressable at all under this geometry.
pub fn addressable(g: &Geometry, logical: u64) -> bool {
    let f = g.fanout();
    let mut reach = 1u64;
    for _ in 0..g.depth() {
        reach = match reach.checked_mul(f) {
            Some(r) => r,
            None => return true, // the space overflows u64 long before it runs out
        };
    }
    logical < reach
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::{DEFAULT_BLOCK_PAYLOAD, LOGICAL_TOTAL};

    fn geo() -> Geometry {
        Geometry::new(DEFAULT_BLOCK_PAYLOAD, 1 << 20)
    }

    /// A path is always the full depth, even for logical block 0. A shorter path for small numbers
    /// would have the walker treat an interior node as a leaf.
    #[test]
    fn a_path_is_always_the_full_depth() {
        let g = geo();
        for logical in [0u64, 1, 12345, LOGICAL_TOTAL - 1] {
            assert_eq!(path(&g, logical).len(), g.depth() as usize, "logical {logical}");
        }
    }

    /// The path is the number's digits: rebuilding the number from them must give it back. This is
    /// the invariant the whole tree walk depends on.
    #[test]
    fn a_path_reconstructs_the_logical_block_it_came_from() {
        let g = geo();
        let f = g.fanout();
        for logical in [0u64, 1, 999, 1 << 20, LOGICAL_TOTAL - 1] {
            let rebuilt = path(&g, logical).iter().fold(0u64, |acc, &d| acc * f + d);
            assert_eq!(rebuilt, logical, "path did not reconstruct {logical}");
        }
    }

    /// Distinct logical blocks take distinct paths — no aliasing, or two objects would share a
    /// data block without either knowing.
    #[test]
    fn distinct_blocks_take_distinct_paths() {
        let g = geo();
        let a = path(&g, 4096);
        let b = path(&g, 4097);
        assert_ne!(a, b);
    }

    /// The whole declared address space is reachable. If it were not, `Geometry::slice` would hand
    /// out ranges that cannot be addressed and high object slots would be silently unusable.
    #[test]
    fn the_entire_logical_space_is_addressable() {
        let g = geo();
        assert!(addressable(&g, LOGICAL_TOTAL - 1), "the top of the space is unreachable");
        assert!(addressable(&g, 0));
    }

    /// A zero entry means "no mapping", and `get` must report that rather than returning block 0 —
    /// which is exactly why block 0 is never allocated.
    #[test]
    fn a_zero_entry_reads_as_unmapped_not_as_block_zero() {
        let g = geo();
        let mut n = Node::empty(&g);
        assert_eq!(n.get(0), None);
        n.set(0, 77);
        assert_eq!(n.get(0), Some(77));
        n.set(0, RESERVED_BLOCK);
        assert_eq!(n.get(0), None, "cleared entry came back as a real block");
    }

    /// A node survives a round trip through the bytes it will be sealed as.
    #[test]
    fn a_node_encodes_and_decodes_unchanged() {
        let g = geo();
        let mut n = Node::empty(&g);
        n.set(0, 5);
        n.set(g.fanout() - 1, 999);
        let bytes = n.encode();
        assert_eq!(Node::decode(&g, &bytes).as_ref(), Some(&n));
    }

    /// A truncated node is rejected outright. Accepting a short read as a partly valid node would
    /// turn a torn write into silently missing mappings — data loss reported as success.
    #[test]
    fn a_truncated_node_is_rejected_rather_than_partly_accepted() {
        let g = geo();
        let bytes = Node::empty(&g).encode();
        assert!(Node::decode(&g, &bytes[..bytes.len() - 1]).is_none());
        assert!(Node::decode(&g, &[]).is_none());
    }

    /// Writing past the end of a node fails instead of growing it: node size is geometry, and a
    /// node that could grow would break the "one node is one block" arithmetic the planner uses.
    #[test]
    fn a_node_cannot_be_grown_past_the_fanout() {
        let g = geo();
        let mut n = Node::empty(&g);
        assert!(!n.set(g.fanout(), 1), "a slot past the fanout was accepted");
        assert_eq!(n.encode().len(), g.fanout() as usize * ENTRY_LEN);
    }

    /// Emptiness is what lets an interior node be retired when its last mapping goes. A node
    /// holding one mapping is not empty; clearing that mapping makes it so.
    #[test]
    fn a_node_is_empty_only_when_every_entry_is_cleared() {
        let g = geo();
        let mut n = Node::empty(&g);
        assert!(n.is_empty());
        n.set(3, 42);
        assert!(!n.is_empty());
        n.set(3, RESERVED_BLOCK);
        assert!(n.is_empty());
    }
}
