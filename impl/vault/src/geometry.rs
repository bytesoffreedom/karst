//! Where everything lives, as arithmetic.
//!
//! Every number here is derived from three inputs — the block payload size, the logical address
//! space, and the container size — and nothing here is chosen by rounding to something pretty.
//! That direction matters: the container's whole deniability argument rests on the geometry being
//! a CONSTANT OF THE FORMAT rather than a function of what the owner configured. A depth that
//! varied with container size would say nothing on its own; a depth that varied with whether a
//! hidden space exists would say everything.

/// Bytes of usable payload in one physical block, before the record framing comes off.
///
/// A placeholder until measured. It is deliberately NOT a `const` the rest of the crate reads
/// directly — everything takes a [`Geometry`], so changing this is a parameter change and not a
/// recompile-the-world edit.
pub const DEFAULT_BLOCK_PAYLOAD: usize = 64 * 1024;

/// Framing every sealed record carries: version, type, nonce, tag.
///
/// A logical block therefore holds strictly less than a physical block's payload, and a map node
/// holds strictly fewer entries than `payload / 8`. Getting this wrong in the optimistic direction
/// is how a transaction ends up needing one more block than it reserved, which is the one failure
/// the credit protocol exists to make impossible.
pub const RECORD_FRAMING: usize = 2 + 24 + 16;

/// One entry of a map node: a physical block number.
pub const ENTRY_LEN: usize = 8;

/// Physical block 0 is never handed out for data, so a zero entry in a map node has exactly one
/// meaning: no mapping here.
pub const RESERVED_BLOCK: u64 = 0;

/// Logical blocks the address space spans. Far larger than any container's physical block count
/// on purpose: the map is sparse, unused branches do not exist on disk, and that is what lets every
/// object own a static slice of the address space instead of an extent list (see [`Geometry::slice`]).
pub const LOGICAL_TOTAL: u64 = 1 << 32;

/// Object slots. Slot 0 is the catalogue itself; objects are numbered from 1.
pub const OBJ_MAX: u64 = 1 << 16;

/// Bytes a stored capsule occupies: the clear generation prefix plus a sealed claim.
///
/// A capsule is `generation(8) ‖ record(framing + claim)`, and the claim is
/// `state(1) ‖ generation(8) ‖ transaction(8) ‖ binding(32)`.
pub const CAPSULE_SLOT: usize = 8 + RECORD_FRAMING + 49;

/// Alignment of a capsule slot within a block.
///
/// The two copies must not share a unit a single torn write can span. Alignment alone does not
/// PROVE that — on a plain file the true atomic unit belongs to the filesystem, the page cache,
/// the block layer and the device, and the application does not know it. What alignment buys is
/// that the two copies are never issued in one write and never share a page; the correctness
/// argument is then carried by the model, where any single unfinished write may tear arbitrarily.
pub const CAPSULE_ALIGN: usize = 4096;

/// The derived shape of one container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    /// Usable bytes in a physical block's payload area.
    pub block_payload: usize,
    /// Physical blocks in the container.
    pub blocks: u64,
}

impl Geometry {
    pub fn new(block_payload: usize, blocks: u64) -> Self {
        Self { block_payload, blocks }
    }

    /// Bytes of DATA a logical block holds, once the record framing is subtracted.
    pub fn logical_data(&self) -> usize {
        self.block_payload.saturating_sub(RECORD_FRAMING)
    }

    /// Entries per map node — how many child pointers fit in one sealed node.
    pub fn fanout(&self) -> u64 {
        (self.logical_data() / ENTRY_LEN) as u64
    }

    /// Levels of map nodes between the root and a data block.
    ///
    /// Computed over the LOGICAL address space, not the physical block count: the depth must not
    /// shift when a container is made bigger or smaller, and it must not shift when a hidden space
    /// is created. It is the same number for every container of this format.
    pub fn depth(&self) -> u32 {
        let f = self.fanout();
        if f < 2 {
            return u32::MAX; // degenerate geometry; `is_sane` rejects it before anyone asks
        }
        let mut levels = 0u32;
        let mut reach = 1u64;
        while reach < LOGICAL_TOTAL {
            reach = reach.saturating_mul(f);
            levels += 1;
        }
        levels
    }

    /// The logical block range object `slot` owns, as `[start, end)`.
    ///
    /// Static: an object's address range is decided by its slot number and never moves. There is no
    /// logical fragmentation to manage and no extent list to spill, because physical placement is
    /// random anyway (§7 of the plan) — logical contiguity buys nothing and costs nothing.
    pub fn slice(slot: u64) -> (u64, u64) {
        let per = LOGICAL_TOTAL / OBJ_MAX;
        (slot * per, (slot + 1) * per)
    }

    /// Largest object this geometry can hold, in bytes.
    pub fn max_object_bytes(&self) -> u64 {
        (LOGICAL_TOTAL / OBJ_MAX) * self.logical_data() as u64
    }

    /// Bytes one physical block occupies on disk, capsules and alignment included.
    pub fn block_stride(&self) -> u64 {
        (2 * CAPSULE_ALIGN + self.block_payload) as u64
    }

    /// Byte offset of block `b`, after the header.
    pub fn block_offset(&self, header_len: u64, b: u64) -> u64 {
        header_len + b * self.block_stride()
    }

    /// Byte offset of copy `copy` of block `b`'s capsule.
    pub fn capsule_offset(&self, header_len: u64, b: u64, copy: u8) -> u64 {
        self.block_offset(header_len, b) + u64::from(copy) * CAPSULE_ALIGN as u64
    }

    /// Byte offset of block `b`'s payload.
    pub fn payload_offset(&self, header_len: u64, b: u64) -> u64 {
        self.block_offset(header_len, b) + 2 * CAPSULE_ALIGN as u64
    }

    /// Whether this geometry is usable at all. A fanout below 2 cannot address the space at any
    /// depth, and a container with fewer blocks than the map alone needs is not a container.
    pub fn is_sane(&self) -> bool {
        self.fanout() >= 2 && self.blocks > u64::from(self.depth()) + 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The depth is a property of the FORMAT, not of the container. Two containers of wildly
    /// different sizes must produce the same tree shape — otherwise the shape is a fingerprint,
    /// and the whole point of §7 is that geometry says nothing about its owner.
    #[test]
    fn depth_does_not_depend_on_container_size() {
        let small = Geometry::new(DEFAULT_BLOCK_PAYLOAD, 1 << 10);
        let large = Geometry::new(DEFAULT_BLOCK_PAYLOAD, 1 << 24);
        assert_eq!(small.depth(), large.depth(), "tree depth leaked the container size");
        assert_eq!(small.fanout(), large.fanout());
    }

    /// The framing really is subtracted. A node that assumed `payload / 8` entries would claim
    /// more room than a sealed node has, and the credit arithmetic downstream would under-reserve.
    #[test]
    fn a_node_holds_fewer_entries_than_the_raw_payload_would_suggest() {
        let g = Geometry::new(DEFAULT_BLOCK_PAYLOAD, 1 << 20);
        let naive = (DEFAULT_BLOCK_PAYLOAD / ENTRY_LEN) as u64;
        assert!(g.fanout() < naive, "framing was not subtracted: {} vs {naive}", g.fanout());
        assert_eq!(g.fanout(), ((DEFAULT_BLOCK_PAYLOAD - RECORD_FRAMING) / ENTRY_LEN) as u64);
    }

    /// At the default block size the tree is three levels, and it stays three levels across every
    /// container size we would ship. Pinned because the credit formulas quote it.
    #[test]
    fn the_default_geometry_is_three_levels_deep() {
        let g = Geometry::new(DEFAULT_BLOCK_PAYLOAD, 1 << 20);
        assert_eq!(g.depth(), 3, "fanout {} gave an unexpected depth", g.fanout());
    }

    /// Object slices tile the address space exactly: no gaps to lose blocks in, no overlap to
    /// corrupt a neighbour through.
    #[test]
    fn object_slices_tile_the_address_space_without_gap_or_overlap() {
        let (_, first_end) = Geometry::slice(0);
        let (second_start, _) = Geometry::slice(1);
        assert_eq!(first_end, second_start, "a gap between slot 0 and slot 1");
        let (_, last_end) = Geometry::slice(OBJ_MAX - 1);
        assert_eq!(last_end, LOGICAL_TOTAL, "the last slice does not reach the end of the space");
    }

    /// The two capsule copies never share an aligned unit, so no single write can span both and a
    /// tear in one cannot reach the other. The model does the rest of the work — see
    /// `CAPSULE_ALIGN` for why alignment alone is not a proof.
    #[test]
    fn the_two_capsule_copies_are_in_separate_aligned_units() {
        let g = Geometry::new(DEFAULT_BLOCK_PAYLOAD, 1 << 20);
        let (a, b) = (g.capsule_offset(0, 5, 0), g.capsule_offset(0, 5, 1));
        assert_ne!(a / CAPSULE_ALIGN as u64, b / CAPSULE_ALIGN as u64, "same aligned unit");
        assert!(a + CAPSULE_SLOT as u64 <= b, "copy 0 overruns into copy 1");
    }

    /// Blocks do not overlap: block n's payload ends before block n+1's first capsule starts.
    #[test]
    fn blocks_do_not_overlap() {
        let g = Geometry::new(DEFAULT_BLOCK_PAYLOAD, 1 << 20);
        let end = g.payload_offset(0, 3) + g.block_payload as u64;
        assert!(end <= g.block_offset(0, 4), "block 3 runs into block 4");
    }

    /// A degenerate block size is rejected rather than producing a tree of absurd depth.
    #[test]
    fn a_block_too_small_to_hold_entries_is_not_sane() {
        let g = Geometry::new(RECORD_FRAMING + 8, 1 << 20);
        assert!(!g.is_sane(), "a one-entry node cannot address anything");
    }

    /// **The two capsule copies never share a page**, for every block, at a real header offset.
    ///
    /// This is the plan's medium rule, and it is the reason `CAPSULE_ALIGN` has the value it has.
    /// It held before this test existed — but by arithmetic nobody had written down: the copies sit
    /// `CAPSULE_ALIGN` apart, so they are in different pages exactly while `CAPSULE_ALIGN` is a
    /// multiple of the page size. Halve it to 512 and both copies land in ONE page, a single torn
    /// write can damage both, the format loses the property its recovery rests on — and every
    /// existing test still passes, because nothing else looks at where the copies are.
    ///
    /// Checked against a real `header_len`, which is NOT page-aligned (2458 bytes as of this
    /// writing). An assertion that only held for an aligned header would be testing a container
    /// this crate never builds.
    ///
    /// Not a duplicate of `the_two_capsule_copies_are_in_separate_aligned_units`: that one divides
    /// by `CAPSULE_ALIGN` and starts at header 0, so it is true by construction for ANY alignment
    /// — including one smaller than a page. This one divides by the PAGE and starts where the
    /// header really ends, which is the form the medium rule is actually stated in.
    #[test]
    fn capsules_never_share_a_page() {
        const PAGE: u64 = crate::file::PAGE;
        assert!(
            (CAPSULE_ALIGN as u64).is_multiple_of(PAGE),
            "capsule alignment must be a whole number of pages, or the two copies can share one"
        );
        let g = Geometry::new(DEFAULT_BLOCK_PAYLOAD, 1 << 30);
        let header = crate::params::header_len();
        for b in 0..64u64 {
            let c0 = g.capsule_offset(header, b, 0);
            let c1 = g.capsule_offset(header, b, 1);
            assert_ne!(c0 / PAGE, c1 / PAGE, "block {b}: both capsule copies are in one page");
            // And each copy must fit inside its own page, so writing one never reaches the other's.
            assert_eq!(
                c0 / PAGE,
                (c0 + CAPSULE_SLOT as u64 - 1) / PAGE,
                "block {b}: copy 0 spills out of its page"
            );
            assert_eq!(
                c1 / PAGE,
                (c1 + CAPSULE_SLOT as u64 - 1) / PAGE,
                "block {b}: copy 1 spills out of its page"
            );
        }
    }

    /// The payload never overlaps either capsule — the other half of "a write to one cannot
    /// damage the other".
    #[test]
    fn the_payload_starts_after_both_capsules() {
        let g = Geometry::new(DEFAULT_BLOCK_PAYLOAD, 1 << 30);
        let header = crate::params::header_len();
        for b in 0..8u64 {
            let payload = g.block_offset(header, b) + 2 * CAPSULE_ALIGN as u64;
            let c1_end = g.capsule_offset(header, b, 1) + CAPSULE_SLOT as u64;
            assert!(payload >= c1_end, "block {b}: the payload starts inside a capsule");
            assert!(
                payload + g.block_payload as u64 <= g.block_offset(header, b + 1),
                "block {b}: the payload runs into the next block"
            );
        }
    }
}
