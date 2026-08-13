//! What a committed transaction still owes: the blocks to retire and the ones to give back.
//!
//! # Why a manifest exists at all
//!
//! The commit point is the root switch, and the manifest has nothing to do with making that
//! atomic. It exists for what comes AFTER: once the new root is durable, the blocks reachable only
//! from the old one have to be wiped and released. Working out which those are means diffing two
//! trees, and doing that after a crash means walking both from scratch — expensive, and worse,
//! it has to be exactly right or blocks are either leaked or freed while still referenced.
//!
//! So the transaction writes down what it will owe BEFORE it commits, and recovery reads the list
//! instead of recomputing it.
//!
//! # Where it sits in the order, and why that exact place
//!
//! Payload and `Live` capsules are durable, THEN the manifest, THEN the root. Both boundaries
//! matter:
//!
//! - Before the root, because after the root switch the old blocks are already unreachable and
//!   there would be nothing left to derive the list from.
//! - After the payload, because a manifest naming blocks that were never written would have
//!   recovery retire blocks the transaction had not actually taken.
//!
//! # The rule that makes replay safe
//!
//! A manifest carries the generation of the root it belongs to. Comparing that against the LIVE
//! root is what tells recovery which of four situations it is in — and the interesting one is
//! "manifest newer than the live root", meaning the commit did not happen. There, `retire` must
//! not be touched: those blocks are still reachable from the live root and still hold live data.
//! Only `release` is safe to reclaim, because nothing ever referenced it.
//!
//! # The invariant [`Replay::Stale`] depends on, and who enforces it
//!
//! `Stale` discards a manifest older than the live root, on the grounds that its cleanup already
//! ran. That reasoning holds only while **a transaction cannot commit past an unfinished
//! cleanup**: if commit N crashed mid-cleanup and commit N+1 were allowed to proceed, N's manifest
//! would then be older than live, be discarded as stale, and its retire list would leak
//! permanently with nothing left recording that those blocks existed.
//!
//! There is nothing in this module that could enforce that — a manifest cannot know what the
//! driver is about to do. [`blocks_new_transaction`] is the check the driver must run, and
//! `a_pending_cleanup_blocks_the_next_transaction` is the test that says so. Leaving the rule in
//! prose only is how it stops being true.

use crate::record::{Context, MasterKey, RecordType, SpaceId};

/// What a transaction owes after it commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub transaction: u64,
    /// Generation of the root this manifest belongs to.
    pub root_generation: u64,
    /// Blocks reachable only from the OLD root: wipe, then free.
    pub retire: Vec<u64>,
    /// Blocks reserved for this transaction that it did not end up using: free directly, since
    /// nothing ever pointed at them.
    pub release: Vec<u64>,
}

/// What recovery should do with a manifest it found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    /// Nothing to do.
    Nothing,
    /// The commit happened: finish the cleanup and clear the manifest. Idempotent, so running it
    /// twice after a second crash is safe.
    FinishCleanup,
    /// The manifest belongs to a generation older than the live root — a previous transaction's
    /// cleanup already ran. Clear it.
    Stale,
    /// The commit did NOT happen. Reclaim `release` only; `retire` is still live data.
    RollBack,
}

/// Whether an unfinished cleanup is outstanding, which forbids starting another transaction.
///
/// The driver calls this before every mutation. See the module docs: `Replay::Stale` is only sound
/// while this is respected, because a manifest that falls behind the live root is discarded, and a
/// manifest discarded before its retire list ran is a permanent leak with no record of itself.
pub fn blocks_new_transaction(manifest: Option<&Manifest>, live_generation: u64) -> bool {
    matches!(replay_for(manifest, live_generation), Replay::FinishCleanup)
}

/// Decide what to do with `manifest` given the live root's generation.
pub fn replay_for(manifest: Option<&Manifest>, live_generation: u64) -> Replay {
    let Some(m) = manifest else { return Replay::Nothing };
    match m.root_generation.cmp(&live_generation) {
        std::cmp::Ordering::Equal => Replay::FinishCleanup,
        std::cmp::Ordering::Less => Replay::Stale,
        std::cmp::Ordering::Greater => Replay::RollBack,
    }
}

fn encode(m: &Manifest) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + (m.retire.len() + m.release.len()) * 8);
    v.extend_from_slice(&m.transaction.to_le_bytes());
    v.extend_from_slice(&m.root_generation.to_le_bytes());
    v.extend_from_slice(&(m.retire.len() as u64).to_le_bytes());
    v.extend_from_slice(&(m.release.len() as u64).to_le_bytes());
    for b in m.retire.iter().chain(m.release.iter()) {
        v.extend_from_slice(&b.to_le_bytes());
    }
    v
}

fn decode(b: &[u8]) -> Option<Manifest> {
    if b.len() < 32 {
        return None;
    }
    let g = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().expect("8 bytes"));
    let (transaction, root_generation) = (g(0), g(8));
    let (n_retire, n_release) = (g(16) as usize, g(24) as usize);
    // The declared counts must match the bytes present. A list longer than the record would be
    // read past the end; a list shorter would leave blocks silently unaccounted for, which is a
    // leak that never announces itself.
    let expected = 32 + (n_retire + n_release) * 8;
    if b.len() != expected {
        return None;
    }
    // The two lists are stored back to back after the fixed header, retire first. The ranges
    // below encode that layout; changing the write order in `encode` without changing them here
    // would silently swap the lists — and swapping "wipe these" with "free these" is destructive.
    let entry = |i: usize| g(32 + i * 8);
    let retire = (0..n_retire).map(entry).collect();
    let release = (n_retire..n_retire + n_release).map(entry).collect();
    Some(Manifest { transaction, root_generation, retire, release })
}

fn ctx(format_hash: [u8; 32], space: SpaceId, block: u64, generation: u64) -> Context {
    Context {
        format_hash,
        record_type: RecordType::Manifest,
        space,
        physical_block: block,
        logical_or_prefix: 0,
        generation,
        copy_index: 0,
    }
}

/// Seal a manifest for storage at `block`, with its root generation in the clear ahead of it.
pub fn seal_manifest(
    key: &MasterKey,
    format_hash: [u8; 32],
    space: SpaceId,
    block: u64,
    m: &Manifest,
) -> Vec<u8> {
    let sealed =
        crate::record::seal(key, &ctx(format_hash, space, block, m.root_generation), &encode(m));
    let mut out = Vec::with_capacity(8 + sealed.len());
    out.extend_from_slice(&m.root_generation.to_le_bytes());
    out.extend_from_slice(&sealed);
    out
}

/// Read a manifest, or `None` if there is not a valid one there.
pub fn open_manifest(
    key: &MasterKey,
    format_hash: [u8; 32],
    space: SpaceId,
    block: u64,
    raw: &[u8],
) -> Option<Manifest> {
    if raw.len() < 8 {
        return None;
    }
    let generation = u64::from_le_bytes(raw[..8].try_into().expect("8 bytes"));
    let plain = crate::record::open(key, &ctx(format_hash, space, block, generation), &raw[8..])?;
    let m = decode(&plain)?;
    (m.root_generation == generation).then_some(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FH: [u8; 32] = [6u8; 32];

    fn manifest(root_generation: u64) -> Manifest {
        Manifest {
            transaction: 42,
            root_generation,
            retire: vec![10, 11, 12],
            release: vec![20],
        }
    }

    #[test]
    fn a_manifest_survives_a_round_trip() {
        let k = MasterKey::generate();
        let m = manifest(5);
        let sealed = seal_manifest(&k, FH, SpaceId::Public, 3, &m);
        assert_eq!(open_manifest(&k, FH, SpaceId::Public, 3, &sealed).as_ref(), Some(&m));
    }

    /// The commit landed: finish what it owed. Running this twice must be safe, which is why the
    /// steps it drives are individually idempotent.
    #[test]
    fn a_manifest_matching_the_live_root_means_finish_the_cleanup() {
        assert_eq!(replay_for(Some(&manifest(7)), 7), Replay::FinishCleanup);
    }

    /// The dangerous case, and the reason the comparison exists at all: the manifest is NEWER than
    /// the live root, so the commit never happened. Its retire list still names blocks the live
    /// root reaches — retiring them would destroy confirmed data.
    #[test]
    fn a_manifest_newer_than_the_live_root_means_roll_back_and_never_retire() {
        assert_eq!(replay_for(Some(&manifest(9)), 8), Replay::RollBack);
    }

    /// An older manifest is a previous transaction's, already cleaned up.
    #[test]
    fn an_older_manifest_is_stale() {
        assert_eq!(replay_for(Some(&manifest(3)), 8), Replay::Stale);
    }

    /// The driver must not start a transaction while a cleanup is outstanding. Without this,
    /// commit N crashing mid-cleanup and N+1 proceeding would leave N's manifest older than live,
    /// discarded as stale, and its retire list leaked with nothing recording that it existed.
    #[test]
    fn a_pending_cleanup_blocks_the_next_transaction() {
        assert!(blocks_new_transaction(Some(&manifest(7)), 7), "cleanup outstanding at generation 7");
        assert!(!blocks_new_transaction(Some(&manifest(3)), 8), "an already-cleaned manifest");
        assert!(!blocks_new_transaction(Some(&manifest(9)), 8), "a rolled-back one blocks nothing");
        assert!(!blocks_new_transaction(None, 8));
    }

    #[test]
    fn no_manifest_means_nothing_to_do() {
        assert_eq!(replay_for(None, 8), Replay::Nothing);
    }

    /// An empty manifest is still a manifest: a transaction that owed nothing recorded that, and
    /// recovery must be able to tell it apart from a torn one.
    #[test]
    fn an_empty_manifest_round_trips_and_is_not_confused_with_a_missing_one() {
        let k = MasterKey::generate();
        let m = Manifest { transaction: 1, root_generation: 2, retire: vec![], release: vec![] };
        let sealed = seal_manifest(&k, FH, SpaceId::Public, 1, &m);
        assert_eq!(open_manifest(&k, FH, SpaceId::Public, 1, &sealed).as_ref(), Some(&m));
    }

    /// Declared counts must match the bytes present. A longer list would read past the end; a
    /// shorter one would leave blocks unaccounted for — a leak that never announces itself.
    #[test]
    fn a_manifest_whose_counts_disagree_with_its_length_is_rejected() {
        let m = manifest(1);
        let mut bytes = encode(&m);
        bytes.truncate(bytes.len() - 8);
        assert!(decode(&bytes).is_none(), "a truncated list was accepted");

        let mut lying = encode(&m);
        lying[16] = 99; // claim 99 retire entries
        assert!(decode(&lying).is_none(), "a lying count was accepted");
    }

    /// Bound to its space and block, so a manifest cannot be lifted between spaces or blocks to
    /// have recovery retire the wrong list.
    #[test]
    fn a_manifest_does_not_open_elsewhere() {
        let k = MasterKey::generate();
        let sealed = seal_manifest(&k, FH, SpaceId::Public, 3, &manifest(5));
        assert!(open_manifest(&k, FH, SpaceId::Hidden, 3, &sealed).is_none());
        assert!(open_manifest(&k, FH, SpaceId::Public, 4, &sealed).is_none());
    }

    /// Editing the clear generation prefix breaks the record rather than changing which branch of
    /// `replay_for` runs — which would be a way to turn a roll-back into a retire.
    #[test]
    fn editing_the_clear_generation_invalidates_the_manifest() {
        let k = MasterKey::generate();
        let mut sealed = seal_manifest(&k, FH, SpaceId::Public, 3, &manifest(5));
        sealed[0] ^= 0xFF;
        assert!(open_manifest(&k, FH, SpaceId::Public, 3, &sealed).is_none());
    }
}
