//! The commit point: which root a space is currently reading, and how it moves.
//!
//! # Why the anchors are in the slot and not derived
//!
//! A root has to be findable before anything else can be read, which rules out storing its address
//! inside the structure it opens. Deriving anchor addresses from a key and walking the sequence
//! looking for one that decrypts sounds tidy, and it does not survive contact with the public
//! mode: that mode holds no ownership-layer key, so it cannot tell whether a candidate address is
//! free, and "the first R usable candidates" is not a question it can answer the same way twice.
//!
//! So the addresses are decided once, when the space is created, and written into the slot that
//! opens it. Public and protected passwords open the same space and therefore carry the same
//! anchors; the hidden space's anchors live only in its own slot and are invisible to everyone
//! else — which is also why the public mode can overwrite them, and why that is accepted rather
//! than prevented.
//!
//! # Why the anchor's capsule does not bind its contents
//!
//! A root is rewritten in place on every commit. A capsule that bound the block's bytes would go
//! invalid the moment the root changed, which is the one moment it must not. So anchors are `Meta`
//! blocks: the capsule says "permanently held, this type", and the root's own record authenticates
//! its contents.
//!
//! # Two anchors, alternating
//!
//! A commit writes the new root to the anchor NOT currently in use, then the old one stays readable
//! until the next commit needs it. A crash mid-write can therefore only damage the copy nobody is
//! reading. Writing both in one durability epoch would defeat that, so the rule is: the new root
//! becomes durable in one epoch, and only the NEXT transaction may reuse the other anchor.

use crate::record::{Context, MasterKey, RecordType, SpaceId};

/// Anchors per space.
pub const ANCHOR_COUNT: usize = 2;

/// What a root says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Root {
    /// Monotonic; the higher of two readable roots is the live one.
    pub generation: u64,
    /// Physical block of the map's top node.
    pub map_root: u64,
    /// Transaction that produced this root — ties it to the manifest that must be replayed.
    pub transaction: u64,
    /// Logical blocks the space currently maps. Not a capacity; a count, for the free-space
    /// estimate the interface shows.
    pub mapped_blocks: u64,
}

fn encode(r: &Root) -> Vec<u8> {
    let mut v = Vec::with_capacity(32);
    v.extend_from_slice(&r.generation.to_le_bytes());
    v.extend_from_slice(&r.map_root.to_le_bytes());
    v.extend_from_slice(&r.transaction.to_le_bytes());
    v.extend_from_slice(&r.mapped_blocks.to_le_bytes());
    v
}

fn decode(b: &[u8]) -> Option<Root> {
    if b.len() != 32 {
        return None;
    }
    let g = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().expect("8 bytes"));
    Some(Root { generation: g(0), map_root: g(8), transaction: g(16), mapped_blocks: g(24) })
}

fn ctx(format_hash: [u8; 32], space: SpaceId, block: u64, generation: u64) -> Context {
    Context {
        format_hash,
        record_type: RecordType::Root,
        space,
        physical_block: block,
        logical_or_prefix: 0,
        generation,
        copy_index: 0,
    }
}

/// Seal a root for storage in `block`, with its generation in the clear ahead of it.
///
/// The clear prefix exists for the same reason as the capsule's: the generation is bound into the
/// aad, so it must be known before decrypting. It is covered by that aad, so editing it makes the
/// record fail to open rather than pointing the reader at a generation of the editor's choosing.
pub fn seal_root(key: &MasterKey, format_hash: [u8; 32], space: SpaceId, block: u64, root: &Root) -> Vec<u8> {
    let sealed = crate::record::seal(key, &ctx(format_hash, space, block, root.generation), &encode(root));
    let mut out = Vec::with_capacity(8 + sealed.len());
    out.extend_from_slice(&root.generation.to_le_bytes());
    out.extend_from_slice(&sealed);
    out
}

fn open_root(key: &MasterKey, format_hash: [u8; 32], space: SpaceId, block: u64, raw: &[u8]) -> Option<Root> {
    if raw.len() < 8 {
        return None;
    }
    let generation = u64::from_le_bytes(raw[..8].try_into().expect("8 bytes"));
    let plain = crate::record::open(key, &ctx(format_hash, space, block, generation), &raw[8..])?;
    let root = decode(&plain)?;
    (root.generation == generation).then_some(root)
}

/// Which anchor a space is live on, and what it says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Live {
    pub root: Root,
    /// Index into the anchor list — the one holding the live root.
    pub anchor: usize,
}

/// Read both anchors and decide which root is live.
///
/// `None` means the space cannot be opened at all: neither anchor holds a readable root. That is
/// not the same as an empty space — an empty space still has a root saying so — and the caller must
/// treat it as "do not write", never as "start fresh here". Starting fresh over an unreadable root
/// is how a space with a torn anchor gets silently replaced by an empty one.
pub fn live_root(
    key: &MasterKey,
    format_hash: [u8; 32],
    space: SpaceId,
    anchors: &[u64; ANCHOR_COUNT],
    raw: [&[u8]; ANCHOR_COUNT],
) -> Option<Live> {
    let mut best: Option<Live> = None;
    for (i, block) in anchors.iter().enumerate() {
        if let Some(root) = open_root(key, format_hash, space, *block, raw[i]) {
            if best.is_none_or(|b| root.generation > b.root.generation) {
                best = Some(Live { root, anchor: i });
            }
        }
    }
    best
}

/// The anchor the next commit must write to: the one NOT holding the live root.
///
/// Taking this from the live root rather than from a stored cursor means a crash cannot leave the
/// cursor disagreeing with reality — there is no cursor to disagree.
pub fn next_anchor(live: &Live) -> usize {
    (live.anchor + 1) % ANCHOR_COUNT
}

#[cfg(test)]
mod tests {
    use super::*;

    const FH: [u8; 32] = [4u8; 32];
    const ANCHORS: [u64; ANCHOR_COUNT] = [100, 200];

    fn root(generation: u64) -> Root {
        Root { generation, map_root: 5, transaction: 1, mapped_blocks: 3 }
    }

    #[test]
    fn a_root_survives_a_round_trip() {
        let k = MasterKey::generate();
        let r = root(1);
        let sealed = seal_root(&k, FH, SpaceId::Public, ANCHORS[0], &r);
        let live = live_root(&k, FH, SpaceId::Public, &ANCHORS, [&sealed, &[]]).expect("readable");
        assert_eq!(live.root, r);
        assert_eq!(live.anchor, 0);
    }

    /// The newer generation wins, whichever anchor holds it.
    #[test]
    fn the_higher_generation_is_live_whichever_anchor_holds_it() {
        let k = MasterKey::generate();
        let old = seal_root(&k, FH, SpaceId::Public, ANCHORS[0], &root(3));
        let new = seal_root(&k, FH, SpaceId::Public, ANCHORS[1], &root(9));
        let live = live_root(&k, FH, SpaceId::Public, &ANCHORS, [&old, &new]).expect("readable");
        assert_eq!(live.root.generation, 9);
        assert_eq!(live.anchor, 1);
    }

    /// The next commit writes to the anchor that is NOT live, so a crash can only damage a copy
    /// nobody reads. Derived from the live root, so there is no cursor to fall out of step.
    #[test]
    fn the_next_commit_targets_the_anchor_that_is_not_live() {
        let k = MasterKey::generate();
        let new = seal_root(&k, FH, SpaceId::Public, ANCHORS[1], &root(9));
        let live = live_root(&k, FH, SpaceId::Public, &ANCHORS, [&[], &new]).expect("readable");
        assert_eq!(next_anchor(&live), 0);
    }

    /// A torn anchor does not lose the space: the other still speaks for it. This is the whole
    /// reason there are two.
    #[test]
    fn a_torn_anchor_is_survived_by_the_other() {
        let k = MasterKey::generate();
        let good = seal_root(&k, FH, SpaceId::Public, ANCHORS[0], &root(4));
        let torn = vec![0u8; 60];
        assert!(live_root(&k, FH, SpaceId::Public, &ANCHORS, [&good, &torn]).is_some());
    }

    /// Both anchors unreadable is "cannot open", and the caller must not read it as "empty".
    /// Writing a fresh root over a torn one silently replaces a space with an empty space.
    #[test]
    fn both_anchors_unreadable_is_not_an_empty_space() {
        let k = MasterKey::generate();
        assert!(live_root(&k, FH, SpaceId::Public, &ANCHORS, [&[], &[]]).is_none());
        let junk = vec![0xEEu8; 70];
        assert!(live_root(&k, FH, SpaceId::Public, &ANCHORS, [&junk, &junk]).is_none());
    }

    /// A root is bound to its space: the hidden space's key does not open the public space's root,
    /// even at the same block.
    #[test]
    fn a_root_does_not_open_as_another_spaces() {
        let k = MasterKey::generate();
        let sealed = seal_root(&k, FH, SpaceId::Public, ANCHORS[0], &root(1));
        assert!(live_root(&k, FH, SpaceId::Hidden, &ANCHORS, [&sealed, &[]]).is_none());
    }

    /// And to its anchor block, so a root cannot be copied from one anchor to the other to fake a
    /// generation.
    #[test]
    fn a_root_does_not_open_from_the_other_anchor() {
        let k = MasterKey::generate();
        let sealed = seal_root(&k, FH, SpaceId::Public, ANCHORS[0], &root(1));
        assert!(live_root(&k, FH, SpaceId::Public, &ANCHORS, [&[], &sealed]).is_none());
    }

    /// Editing the clear generation prefix breaks the record instead of redirecting it.
    #[test]
    fn editing_the_clear_generation_invalidates_the_root() {
        let k = MasterKey::generate();
        let mut sealed = seal_root(&k, FH, SpaceId::Public, ANCHORS[0], &root(7));
        sealed[0] ^= 0xFF;
        assert!(live_root(&k, FH, SpaceId::Public, &ANCHORS, [&sealed, &[]]).is_none());
    }

    /// A stranger's key reads nothing, and gets no hint that an anchor holds anything at all.
    #[test]
    fn a_stranger_reads_no_root() {
        let k = MasterKey::generate();
        let stranger = MasterKey::generate();
        let sealed = seal_root(&k, FH, SpaceId::Public, ANCHORS[0], &root(1));
        assert!(live_root(&stranger, FH, SpaceId::Public, &ANCHORS, [&sealed, &[]]).is_none());
    }
}
