//! What a transaction will cost, computed BEFORE it changes a byte.
//!
//! This is the admission half of the write path. Every mutation reserves the physical blocks it
//! could possibly need first; only then may it touch anything readable through the public key. If
//! the reservation fails, nothing has happened — no data block, no map node, no catalogue entry, no
//! transaction id burned.
//!
//! The reason it is a planner and not a formula: a formula that multiplies touched blocks by the
//! tree depth over-counts badly (paths share prefixes) and a formula that ignores the catalogue
//! under-counts (a slot allocation touches the header too). Under-counting is the dangerous
//! direction — it means running out of space in the middle of an atomic update, which is exactly
//! the failure the credit protocol exists to make impossible. So the planner enumerates the real
//! set and reports its size.

use crate::geometry::Geometry;

/// The catalogue lives in object slot 0, and one object's record sits in exactly one of its blocks.
const CATALOGUE_SLOT: u64 = 0;
/// Logical block 0 of the catalogue slot holds the header (the slot-occupancy bitmap).
const CATALOGUE_HEADER_BLOCK: u64 = 0;
/// Object records per catalogue block, at 32 bytes a record.
const RECORDS_PER_BLOCK: u64 = 2048;
/// Bytes per manifest entry: one physical block number.
const MANIFEST_ENTRY: usize = 8;

/// What one mutation will touch. Every field is a COUNT of distinct blocks, never an estimate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    /// Logical data blocks that will be rewritten.
    pub data_blocks: u64,
    /// Catalogue blocks that will be rewritten (the record's block, plus the header when a slot is
    /// allocated or released).
    pub catalogue_blocks: u64,
    /// Distinct map nodes on the paths to everything above — counted by prefix, so a run of
    /// neighbouring blocks pays for one leaf, not one leaf each.
    pub map_nodes: u64,
    /// Blocks the manifest itself occupies (§13.2): it lists what to retire and what to release.
    pub manifest_blocks: u64,
}

impl Plan {
    /// Physical blocks to reserve before touching anything.
    pub fn need(&self) -> u64 {
        self.data_blocks + self.catalogue_blocks + self.map_nodes + self.manifest_blocks
    }
}

/// The mutation being planned.
#[derive(Debug, Clone, Copy)]
pub enum Mutation {
    /// Write `len` bytes into object `slot` at byte `offset`.
    Write { slot: u64, offset: u64, len: u64 },
    /// Create an object: allocate a slot (header) and write its record.
    Create { slot: u64 },
    /// Delete an object holding `mapped_blocks` logical blocks. The data blocks themselves are
    /// RETIRED, not allocated — but clearing their mappings rewrites map nodes, and those are new.
    Delete { slot: u64, mapped_blocks: u64 },
}

/// Distinct nodes at every level above a contiguous logical range `[first, last]`.
///
/// Counted by prefix rather than as `count * depth`: at level `d` the range spans
/// `floor(last / f^d) - floor(first / f^d) + 1` nodes, which collapses to 1 as soon as the divisor
/// exceeds the range. The root is one node at the top level, always.
fn nodes_for_range(g: &Geometry, first: u64, last: u64) -> u64 {
    let f = g.fanout();
    let mut total = 0u64;
    let mut divisor = f;
    for _ in 0..g.depth() {
        total += last / divisor - first / divisor + 1;
        divisor = divisor.saturating_mul(f);
    }
    total
}

/// Union of the node sets for two ranges, without double-counting the levels they share.
///
/// Two ranges in the same object are usually adjacent and share every node above the leaf; two
/// ranges in different objects share only the root. Counting them separately would over-reserve —
/// harmless for correctness, but it would make the planner's numbers useless as a measurement.
fn nodes_for_two_ranges(g: &Geometry, a: (u64, u64), b: (u64, u64)) -> u64 {
    let f = g.fanout();
    let mut total = 0u64;
    let mut divisor = f;
    for _ in 0..g.depth() {
        let (a_lo, a_hi) = (a.0 / divisor, a.1 / divisor);
        let (b_lo, b_hi) = (b.0 / divisor, b.1 / divisor);
        let a_count = a_hi - a_lo + 1;
        let b_count = b_hi - b_lo + 1;
        // Overlap of two inclusive integer intervals, or zero when they are disjoint.
        let overlap = (a_hi.min(b_hi) + 1).saturating_sub(a_lo.max(b_lo));
        total += a_count + b_count - overlap;
        divisor = divisor.saturating_mul(f);
    }
    total
}

/// Logical block range a byte range inside an object maps to, as absolute logical blocks.
///
/// The count comes from the range's BOUNDARIES, not from its length: a 1-byte write straddling a
/// block edge touches two blocks, and `len / block + 1` would miss it. A partial block is rewritten
/// whole under copy-on-write, so a straddle really does cost the second block.
fn data_range(g: &Geometry, slot: u64, offset: u64, len: u64) -> Option<(u64, u64)> {
    if len == 0 {
        return None;
    }
    let lds = g.logical_data() as u64;
    let (base, _) = Geometry::slice(slot);
    let first = base + offset / lds;
    let last = base + (offset + len - 1) / lds;
    Some((first, last))
}

/// Where object `slot`'s record lives, as an absolute logical block in the catalogue slice.
fn catalogue_record_block(slot: u64) -> u64 {
    let (base, _) = Geometry::slice(CATALOGUE_SLOT);
    base + CATALOGUE_HEADER_BLOCK + 1 + slot / RECORDS_PER_BLOCK
}

/// Plan a mutation: enumerate what it touches and how many physical blocks that needs.
pub fn plan_mutation(g: &Geometry, m: Mutation) -> Plan {
    let (base_cat, _) = Geometry::slice(CATALOGUE_SLOT);
    let header = base_cat + CATALOGUE_HEADER_BLOCK;

    let (data, catalogue_lo, catalogue_hi) = match m {
        Mutation::Write { slot, offset, len } => {
            let rec = catalogue_record_block(slot);
            (data_range(g, slot, offset, len), rec, rec)
        }
        // Creating an object flips a bit in the header AND writes the record, so the catalogue
        // range spans both — they are usually in different blocks.
        Mutation::Create { slot } => {
            let rec = catalogue_record_block(slot);
            (None, header.min(rec), header.max(rec))
        }
        Mutation::Delete { slot, .. } => {
            let rec = catalogue_record_block(slot);
            (None, header.min(rec), header.max(rec))
        }
    };

    let catalogue_blocks = catalogue_hi - catalogue_lo + 1;

    let (data_blocks, map_nodes) = match (data, m) {
        (Some((first, last)), _) => (
            last - first + 1,
            nodes_for_two_ranges(g, (first, last), (catalogue_lo, catalogue_hi)),
        ),
        // A delete allocates no data blocks, but clearing the mappings rewrites the map nodes that
        // held them — leaving those entries in place would keep the blocks physically occupied
        // while the object no longer exists anywhere.
        (None, Mutation::Delete { slot, mapped_blocks }) if mapped_blocks > 0 => {
            let (base, _) = Geometry::slice(slot);
            let range = (base, base + mapped_blocks - 1);
            (0, nodes_for_two_ranges(g, range, (catalogue_lo, catalogue_hi)))
        }
        (None, _) => (0, nodes_for_range(g, catalogue_lo, catalogue_hi)),
    };

    let entries = data_blocks + catalogue_blocks + map_nodes;
    let manifest_bytes = entries as usize * MANIFEST_ENTRY;
    let manifest_blocks = manifest_bytes.div_ceil(g.logical_data()).max(1) as u64;

    Plan { data_blocks, catalogue_blocks, map_nodes, manifest_blocks }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::DEFAULT_BLOCK_PAYLOAD;

    fn geo() -> Geometry {
        Geometry::new(DEFAULT_BLOCK_PAYLOAD, 1 << 20)
    }

    /// A write that fits inside one logical block costs one data block — not a block per byte and
    /// not a rounded-up guess.
    #[test]
    fn a_small_write_costs_exactly_one_data_block() {
        let g = geo();
        let p = plan_mutation(&g, Mutation::Write { slot: 1, offset: 0, len: 10 });
        assert_eq!(p.data_blocks, 1, "a 10-byte write should touch one block");
        assert!(p.need() > p.data_blocks, "the map path and catalogue are not free");
    }

    /// The boundary case the naive formula gets wrong: a write of ONE byte that straddles a block
    /// edge touches two blocks, because copy-on-write rewrites each partial block whole.
    #[test]
    fn a_one_byte_write_across_a_block_edge_costs_two_data_blocks() {
        let g = geo();
        let lds = g.logical_data() as u64;
        let p = plan_mutation(&g, Mutation::Write { slot: 1, offset: lds - 1, len: 2 });
        assert_eq!(p.data_blocks, 2, "a straddling write must pay for both blocks");
    }

    /// Nodes are counted by shared prefix. A run of neighbouring blocks pays for ONE leaf, so the
    /// planner must be far below the `blocks * depth` upper bound it replaces.
    #[test]
    fn neighbouring_blocks_share_their_path_instead_of_paying_for_it_each() {
        let g = geo();
        let lds = g.logical_data() as u64;
        let p = plan_mutation(&g, Mutation::Write { slot: 1, offset: 0, len: lds * 100 });
        assert_eq!(p.data_blocks, 100);
        let naive_upper_bound = p.data_blocks * u64::from(g.depth());
        assert!(
            p.map_nodes < naive_upper_bound,
            "prefix sharing did not happen: {} nodes for {} blocks",
            p.map_nodes,
            p.data_blocks
        );
    }

    /// Deleting an object is NOT free just because it writes no data: the map nodes that held its
    /// mappings are rewritten, and those are newly allocated blocks like any other.
    #[test]
    fn deleting_an_object_still_costs_map_nodes() {
        let g = geo();
        let p = plan_mutation(&g, Mutation::Delete { slot: 7, mapped_blocks: 500 });
        assert_eq!(p.data_blocks, 0, "a delete allocates no data");
        assert!(p.map_nodes > 0, "clearing mappings must rewrite the nodes that held them");
        assert!(p.need() > 0);
    }

    /// Creating an object touches the occupancy header as well as the record — two catalogue
    /// blocks, not one, because they are in different blocks of the catalogue.
    #[test]
    fn creating_an_object_touches_both_the_header_and_the_record() {
        let g = geo();
        let p = plan_mutation(&g, Mutation::Create { slot: 5000 });
        assert!(
            p.catalogue_blocks >= 2,
            "create must account for the occupancy header too, got {}",
            p.catalogue_blocks
        );
    }

    /// The manifest is never zero blocks: a transaction that retires nothing still records that it
    /// retired nothing, and a plan claiming zero would under-reserve by exactly one block.
    #[test]
    fn the_manifest_always_costs_at_least_one_block() {
        let g = geo();
        for m in [
            Mutation::Write { slot: 1, offset: 0, len: 1 },
            Mutation::Create { slot: 1 },
            Mutation::Delete { slot: 1, mapped_blocks: 0 },
        ] {
            assert!(plan_mutation(&g, m).manifest_blocks >= 1, "{m:?} planned a free manifest");
        }
    }

    /// `need()` is the sum of the parts and nothing else — no hidden slack, no fudge factor. If a
    /// margin is ever wanted it has to be added deliberately, where a reader can see it.
    #[test]
    fn need_is_exactly_the_sum_of_its_parts() {
        let g = geo();
        let p = plan_mutation(&g, Mutation::Write { slot: 3, offset: 12345, len: 99999 });
        assert_eq!(p.need(), p.data_blocks + p.catalogue_blocks + p.map_nodes + p.manifest_blocks);
    }

    /// Two ranges far apart in the address space share only the root, and the union must not
    /// double-count it. This is the case that separates a real union from an addition.
    #[test]
    fn distant_ranges_share_the_root_and_are_not_counted_twice() {
        let g = geo();
        let far = Geometry::slice(OBJ_MAX_TEST).0;
        let both = nodes_for_two_ranges(&g, (0, 0), (far, far));
        let apart = nodes_for_range(&g, 0, 0) + nodes_for_range(&g, far, far);
        assert_eq!(both, apart - 1, "the shared root was counted twice or not at all");
    }
    const OBJ_MAX_TEST: u64 = 60000;

    /// A zero-length write is a no-op on the data, but still a transaction: it must not claim data
    /// blocks it will not use.
    #[test]
    fn a_zero_length_write_claims_no_data_blocks() {
        let g = geo();
        let p = plan_mutation(&g, Mutation::Write { slot: 1, offset: 0, len: 0 });
        assert_eq!(p.data_blocks, 0);
    }
}
