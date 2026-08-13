//! The mode that knows nothing, and the command that cleans up after it.
//!
//! # What the public mode must do, and why the "must" is the whole design
//!
//! Under the public password the container behaves as if a hidden space had never existed. Not
//! "behaves as if it were empty" — as if the concept were absent. That is the only behaviour a
//! container with no hidden space could have, and if the two ever diverged, the divergence would be
//! the answer someone is looking for.
//!
//! Concretely: this mode holds no ownership-layer key, never reads a capsule, and never asks
//! whether a block is claimed. It allocates any block its own map does not currently use. If that
//! block belonged to a hidden space, the hidden space loses it. That is not a bug being tolerated;
//! it is the property being bought.
//!
//! # Why it must destroy the capsules unconditionally
//!
//! Before writing a block, this mode overwrites both capsule copies with random. Always — whether
//! the block held a hidden space's data, a free marker, or nothing at all.
//!
//! If it skipped that when the capsules were already random, its behaviour would depend on what it
//! found, and "did this write take an extra step?" is observable in timing and in the write
//! pattern. Unconditional means the trace of a public-mode write is the same in a container that
//! has a hidden space and one that never did.
//!
//! Leaving a valid `FREE` capsule on a block it had taken would be worse still: the hidden space
//! would later be told the block is free, take it, and two spaces would both believe they own it.
//!
//! # Why P3 is sacrificial, and what that costs
//!
//! Because it cannot write capsules — that needs the ownership key — a block it retires becomes
//! permanently `Unknown`: not free, not claimed, unusable. After a public-mode session the
//! container's free space is whatever the public map still reaches plus whatever the ownership
//! layer can still vouch for, and the difference is stranded.
//!
//! The alternative was a certificate the public mode could write under its OWN key, saying "this
//! block is mine to reclaim", which the protected mode would verify and convert into a proper
//! release. It works and it was rejected: it adds a record type, a subkey and a recovery branch to
//! serve a case the threat model barely has — the public password is surrendered under duress, and
//! after that the hidden space is presumed lost anyway. If that presumption ever stops holding,
//! this is the design to bring back.
//!
//! So the way back is [`RebuildPlan`]: an explicit, owner-driven command that declares the hidden
//! space gone and rebuilds the ownership layer around what the public map actually reaches.

use crate::capsule::{Claim, Owner, State};

/// A block the public mode is about to take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicWrite {
    pub block: u64,
    /// Byte offsets of the two capsule copies.
    pub capsules: [u64; 2],
    pub payload: u64,
}

/// The ordered steps a public-mode write must take.
///
/// Returned as data for the same reason the commit protocol is: the ordering claim is testable by
/// running prefixes, and "we always invalidate first" is a sentence until something checks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicStep {
    /// Overwrite one capsule copy with random. Unconditional.
    InvalidateCapsule { offset: u64, bytes: Vec<u8> },
    Barrier,
    WritePayload { offset: u64, bytes: Vec<u8> },
}

/// Build the write sequence for one block taken by the public mode.
///
/// Both copies are invalidated before the payload, each followed by a barrier. Two barriers rather
/// than one is deliberate: it costs an extra flush and it removes the need for an exception to the
/// "never update both copies in one epoch" rule, which is a rule worth keeping unqualified.
pub fn public_write_steps(w: &PublicWrite, random: &dyn Fn() -> Vec<u8>, payload: Vec<u8>) -> Vec<PublicStep> {
    vec![
        PublicStep::InvalidateCapsule { offset: w.capsules[0], bytes: random() },
        PublicStep::Barrier,
        PublicStep::InvalidateCapsule { offset: w.capsules[1], bytes: random() },
        PublicStep::Barrier,
        PublicStep::WritePayload { offset: w.payload, bytes: payload },
    ]
}

/// What `destroy-hidden-and-rebuild-L` will do, worked out before it does any of it.
///
/// Presented to the owner first. The command destroys a hidden space if one is there, and a
/// destructive step that runs before anyone has seen its scope is how people lose data they meant
/// to keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuildPlan {
    /// Blocks the public map reaches: these become `Live(Public)`.
    pub keep: Vec<u64>,
    /// Everything else: wiped, then marked free.
    pub reclaim: Vec<u64>,
}

impl RebuildPlan {
    /// Work out the plan from what the public map reaches and how many blocks exist.
    ///
    /// Everything not reachable is reclaimed — INCLUDING anything a hidden space still held. There
    /// is no way to spare it, because the mode running this cannot tell hidden data from debris,
    /// and a version that could would be the distinguisher this whole design removes.
    pub fn new(reachable: &[u64], blocks: u64, reserved: &[u64]) -> Self {
        let mut keep: Vec<u64> = reachable.to_vec();
        keep.sort_unstable();
        keep.dedup();
        let reclaim = (1..blocks)
            .filter(|b| keep.binary_search(b).is_err() && !reserved.contains(b))
            .collect();
        Self { keep, reclaim }
    }

    /// The claim each kept block gets.
    pub fn claim_for_kept(&self, generation: u64, transaction: u64, digest: [u8; 32]) -> Claim {
        Claim { state: State::Live(Owner::Public), generation, transaction, binding: digest }
    }

    /// The claim each reclaimed block gets, after its payload has been wiped.
    pub fn claim_for_reclaimed(&self, generation: u64, transaction: u64, witness: [u8; 32]) -> Claim {
        Claim { state: State::Free, generation, transaction, binding: witness }
    }

    /// Whether this plan would destroy anything. What the confirmation prompt asks about.
    pub fn destroys_anything(&self) -> bool {
        !self.reclaim.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w() -> PublicWrite {
        PublicWrite { block: 5, capsules: [1000, 5000], payload: 9000 }
    }

    /// The capsules are invalidated BEFORE the payload, always. If the payload landed first, a
    /// crash would leave a block whose old `Live` capsule still claims it for the hidden space
    /// while holding the public space's bytes — two owners, one block.
    #[test]
    fn both_capsules_are_invalidated_before_the_payload_is_written() {
        let steps = public_write_steps(&w(), &|| vec![0xAA; 8], vec![1, 2, 3]);
        let payload_at = steps
            .iter()
            .position(|s| matches!(s, PublicStep::WritePayload { .. }))
            .expect("payload step");
        let invalidations: Vec<usize> = steps
            .iter()
            .enumerate()
            .filter(|(_, s)| matches!(s, PublicStep::InvalidateCapsule { .. }))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(invalidations.len(), 2, "both copies must be invalidated");
        assert!(invalidations.iter().all(|&i| i < payload_at), "a capsule survived the payload");
    }

    /// The two copies are invalidated in separate epochs, so the "never both in one epoch" rule
    /// needs no exception carved out for this mode.
    #[test]
    fn the_two_capsule_copies_are_invalidated_in_separate_epochs() {
        let steps = public_write_steps(&w(), &|| vec![0xAA; 8], vec![1]);
        let first = steps.iter().position(|s| matches!(s, PublicStep::InvalidateCapsule { .. })).unwrap();
        let second = steps
            .iter()
            .skip(first + 1)
            .position(|s| matches!(s, PublicStep::InvalidateCapsule { .. }))
            .map(|i| i + first + 1)
            .expect("second copy");
        assert!(
            steps[first..second].iter().any(|s| matches!(s, PublicStep::Barrier)),
            "both copies were invalidated in one epoch"
        );
    }

    /// The sequence does not depend on what was found. A version that skipped invalidation when
    /// the capsules were already random would make its own write pattern depend on whether a
    /// hidden space exists.
    #[test]
    fn the_write_sequence_is_the_same_whatever_the_block_held() {
        let a = public_write_steps(&w(), &|| vec![0u8; 8], vec![1]);
        let b = public_write_steps(&w(), &|| vec![0u8; 8], vec![1]);
        assert_eq!(a, b);
        let shape = |v: &[PublicStep]| {
            v.iter().map(std::mem::discriminant).collect::<Vec<_>>()
        };
        assert_eq!(shape(&a), shape(&b), "the shape of a public write varies with its input");
    }

    /// The rebuild keeps what the map reaches and reclaims the rest — including a hidden space's
    /// blocks, which is the point of the command and the reason it needs confirming.
    #[test]
    fn the_rebuild_reclaims_everything_the_public_map_does_not_reach() {
        let plan = RebuildPlan::new(&[2, 4], 8, &[]);
        assert_eq!(plan.keep, vec![2, 4]);
        assert_eq!(plan.reclaim, vec![1, 3, 5, 6, 7]);
        assert!(plan.destroys_anything());
    }

    /// Block 0 is never reclaimed: it is the reserved "no mapping" value and must never become
    /// allocatable.
    #[test]
    fn block_zero_is_never_reclaimed() {
        let plan = RebuildPlan::new(&[], 5, &[]);
        assert!(!plan.reclaim.contains(&0), "block 0 was offered up for reuse");
    }

    /// Reserved blocks — the header's anchors and the like — are left alone.
    #[test]
    fn reserved_blocks_are_not_reclaimed() {
        let plan = RebuildPlan::new(&[2], 6, &[3, 4]);
        assert_eq!(plan.reclaim, vec![1, 5]);
    }

    /// A plan with nothing to reclaim destroys nothing, so the confirmation can be skipped rather
    /// than asking about a destructive step that is not destructive.
    #[test]
    fn a_plan_that_reclaims_nothing_destroys_nothing() {
        let plan = RebuildPlan::new(&[1, 2, 3, 4], 5, &[]);
        assert!(!plan.destroys_anything());
        assert!(plan.reclaim.is_empty());
    }

    /// Duplicate entries in the reachable set do not produce duplicate keeps or accidentally
    /// reclaim a block twice.
    #[test]
    fn a_repeated_reachable_block_is_handled_once() {
        let plan = RebuildPlan::new(&[2, 2, 2], 4, &[]);
        assert_eq!(plan.keep, vec![2]);
        assert_eq!(plan.reclaim, vec![1, 3]);
    }
}
