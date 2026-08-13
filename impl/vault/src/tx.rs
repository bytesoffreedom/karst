//! The commit protocol: the order writes become durable in, expressed as data.
//!
//! # Why the order is a value and not control flow
//!
//! Every rule this module enforces is a statement about what may be durable when. Written as
//! straight-line code with barriers between statements, those rules are only checkable by crashing
//! the program at each line and seeing what happened — which is exactly the test that cannot be
//! written against an abort (see [`crate::faulty`]).
//!
//! So a commit is built as an ordered list of [`Step`]s first and executed second. A test can then
//! run any PREFIX of it, cut the power, and assert what survived. The crash matrix stops being a
//! description of intentions and becomes a loop over prefixes.
//!
//! # The order, and what each boundary is load-bearing for
//!
//! ```text
//!   reserve            (reads only; ENOSPC here has changed nothing)
//!   Reserved capsules  -> barrier
//!   payload            -> barrier
//!   Live capsules      -> barrier
//!   manifest           -> barrier
//!   root               -> barrier   <- COMMIT POINT
//!   wipe retired       -> barrier
//!   free retired       -> barrier
//!   clear manifest     -> barrier
//! ```
//!
//! - `Reserved` before payload: a block must be off the free list before anything is written into
//!   it, or a concurrent reader of the free list could hand the same block to someone else.
//! - Payload before `Live`: a `Live` capsule binds the payload's digest, so writing it first would
//!   claim bytes that are not there yet.
//! - Manifest before root: after the switch the old blocks are unreachable and there is nothing
//!   left to derive the retire list from.
//! - Root last: it IS the commit. Everything before it is invisible to a reader; everything after
//!   it is cleanup that recovery can finish.
//! - Wipe before free, with a barrier between: a block advertised as free while its retired
//!   contents are still on disk stays that way until something reuses it, which may be never.

use crate::manifest::Manifest;

/// One durable write, or the barrier that makes the preceding ones durable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Write bytes at a byte offset.
    Write { offset: u64, bytes: Vec<u8>, what: What },
    /// A successful `fsync`. Nothing before it may be reordered past it.
    Barrier,
}

/// What a write is, for tests and for reading a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum What {
    ReservedCapsule(u64),
    Payload(u64),
    LiveCapsule(u64),
    Manifest,
    Root,
    /// Overwriting a retired block's payload with random.
    Wipe(u64),
    FreeCapsule(u64),
    ClearManifest,
}

/// The commit point: the index of the barrier that makes the root durable.
///
/// Before it, a crash leaves the previous version. At or after it, the new version is live and
/// recovery finishes the rest. Exposed because it is the single fact every crash test asserts
/// against, and computing it in each test would be re-deriving the protocol per test.
pub fn commit_point(steps: &[Step]) -> Option<usize> {
    let root = steps.iter().position(|s| matches!(s, Step::Write { what: What::Root, .. }))?;
    steps[root..].iter().position(|s| matches!(s, Step::Barrier)).map(|b| root + b)
}

/// Build the ordered commit for a transaction.
///
/// Takes the already-sealed bytes rather than sealing anything itself: what belongs here is the
/// ORDER, and mixing key handling in would make the order harder to see and harder to test.
pub struct Commit {
    steps: Vec<Step>,
}

/// One block the transaction is writing.
pub struct BlockWrite {
    pub block: u64,
    pub reserved_capsule: (u64, Vec<u8>),
    pub payload: (u64, Vec<u8>),
    pub live_capsule: (u64, Vec<u8>),
}

/// One block the transaction is retiring after the commit.
pub struct BlockRetire {
    pub block: u64,
    pub wipe: (u64, Vec<u8>),
    pub free_capsule: (u64, Vec<u8>),
}

impl Commit {
    /// Assemble the commit. `manifest` and `root` are `(offset, sealed bytes)`.
    pub fn build(
        writes: &[BlockWrite],
        manifest: (u64, Vec<u8>),
        root: (u64, Vec<u8>),
        retires: &[BlockRetire],
        clear_manifest: (u64, Vec<u8>),
    ) -> Self {
        let mut steps = Vec::new();

        for w in writes {
            steps.push(Step::Write {
                offset: w.reserved_capsule.0,
                bytes: w.reserved_capsule.1.clone(),
                what: What::ReservedCapsule(w.block),
            });
        }
        steps.push(Step::Barrier);

        for w in writes {
            steps.push(Step::Write {
                offset: w.payload.0,
                bytes: w.payload.1.clone(),
                what: What::Payload(w.block),
            });
        }
        steps.push(Step::Barrier);

        for w in writes {
            steps.push(Step::Write {
                offset: w.live_capsule.0,
                bytes: w.live_capsule.1.clone(),
                what: What::LiveCapsule(w.block),
            });
        }
        steps.push(Step::Barrier);

        steps.push(Step::Write { offset: manifest.0, bytes: manifest.1, what: What::Manifest });
        steps.push(Step::Barrier);

        steps.push(Step::Write { offset: root.0, bytes: root.1, what: What::Root });
        steps.push(Step::Barrier); // commit point

        // Wipe and release are two stages with a barrier between them, not two writes. If the
        // FREE capsule landed while the wipe did not, the block would be advertised as free while
        // still holding the retired ciphertext — and it would stay that way until something
        // happened to reuse it, which may be never.
        for r in retires {
            steps.push(Step::Write {
                offset: r.wipe.0,
                bytes: r.wipe.1.clone(),
                what: What::Wipe(r.block),
            });
        }
        steps.push(Step::Barrier);

        for r in retires {
            steps.push(Step::Write {
                offset: r.free_capsule.0,
                bytes: r.free_capsule.1.clone(),
                what: What::FreeCapsule(r.block),
            });
        }
        steps.push(Step::Barrier);

        steps.push(Step::Write {
            offset: clear_manifest.0,
            bytes: clear_manifest.1,
            what: What::ClearManifest,
        });
        steps.push(Step::Barrier);

        Self { steps }
    }

    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// Run the first `n` steps against a store, then stop — as if the power went out there.
    pub fn run_prefix(&self, store: &mut crate::faulty::FaultyStore, n: usize) {
        for step in self.steps.iter().take(n) {
            match step {
                Step::Write { offset, bytes, .. } => store.write(*offset, bytes),
                Step::Barrier => store.barrier(),
            }
        }
    }
}

/// Why a transaction refused before doing anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not enough free blocks for the worst case. Nothing has been written.
    NoSpace,
    /// A previous commit's cleanup has not finished. Starting now would let that manifest fall
    /// behind the live root and be discarded with its retire list unprocessed.
    CleanupPending,
}

/// The read-only admission stage: may this transaction start, and is there room?
///
/// Nothing here writes, so a refusal is guaranteed to have changed nothing — which is the whole
/// point of separating it from the durable sequence above.
pub fn admit(
    need: u64,
    believed_free: u64,
    outstanding: Option<&Manifest>,
    live_generation: u64,
) -> Result<(), Refusal> {
    if crate::manifest::blocks_new_transaction(outstanding, live_generation) {
        return Err(Refusal::CleanupPending);
    }
    if believed_free < need {
        return Err(Refusal::NoSpace);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::faulty::FaultyStore;

    fn write_at(block: u64, base: u64) -> BlockWrite {
        BlockWrite {
            block,
            reserved_capsule: (base, vec![1u8; 8]),
            payload: (base + 100, vec![2u8; 8]),
            live_capsule: (base, vec![3u8; 8]),
        }
    }

    fn commit() -> Commit {
        Commit::build(
            &[write_at(1, 1000), write_at(2, 2000)],
            (5000, vec![4u8; 8]),
            (6000, vec![5u8; 8]),
            &[BlockRetire { block: 9, wipe: (9000, vec![0u8; 8]), free_capsule: (9100, vec![6u8; 8]) }],
            (5000, vec![0u8; 8]),
        )
    }

    /// The order is the protocol, so it is asserted directly rather than inferred from behaviour.
    #[test]
    fn the_durable_order_is_reserved_payload_live_manifest_root() {
        let c = commit();
        let kinds: Vec<What> = c
            .steps()
            .iter()
            .filter_map(|s| match s {
                Step::Write { what, .. } => Some(*what),
                Step::Barrier => None,
            })
            .collect();
        let pos = |p: fn(&What) -> bool| kinds.iter().position(p).expect("step missing");
        let reserved = pos(|w| matches!(w, What::ReservedCapsule(_)));
        let payload = pos(|w| matches!(w, What::Payload(_)));
        let live = pos(|w| matches!(w, What::LiveCapsule(_)));
        let manifest = pos(|w| matches!(w, What::Manifest));
        let root = pos(|w| matches!(w, What::Root));
        let wipe = pos(|w| matches!(w, What::Wipe(_)));
        assert!(reserved < payload, "a block was written before it left the free list");
        assert!(payload < live, "a Live capsule claimed a digest of bytes not yet written");
        assert!(live < manifest);
        assert!(manifest < root, "the retire list would be underivable after the switch");
        assert!(root < wipe, "cleanup ran before the commit it cleans up after");
    }

    /// Every write is separated from the next stage by a barrier. Without one, the stages could
    /// land in any order and every ordering argument above would be decoration.
    #[test]
    fn each_stage_ends_with_a_barrier() {
        let c = commit();
        let mut seen_kind: Option<std::mem::Discriminant<What>> = None;
        let mut barriers_between_kinds = 0;
        for s in c.steps() {
            match s {
                Step::Write { what, .. } => {
                    let d = std::mem::discriminant(what);
                    if seen_kind.is_some_and(|p| p != d) {
                        assert!(
                            barriers_between_kinds > 0,
                            "no barrier between {seen_kind:?} and {what:?}"
                        );
                    }
                    seen_kind = Some(d);
                    barriers_between_kinds = 0;
                }
                Step::Barrier => barriers_between_kinds += 1,
            }
        }
    }

    /// A cut anywhere BEFORE the commit point leaves the root untouched: the previous version of
    /// the space is what a reader still sees. This is the row of the matrix everything else rests
    /// on, and it is checked at every prefix rather than at one chosen point.
    #[test]
    fn no_prefix_before_the_commit_point_makes_the_root_durable() {
        let c = commit();
        let commit_at = commit_point(c.steps()).expect("there is a commit point");
        for n in 0..=commit_at {
            let mut store = FaultyStore::new(20_000);
            c.run_prefix(&mut store, n);
            store.power_cut_losing_everything();
            assert_eq!(
                store.read_durable(6000, 8),
                vec![0u8; 8],
                "the root became durable after only {n} of {commit_at} steps"
            );
        }
    }

    /// And a cut at the commit point or later leaves it durable — so the boundary is exactly where
    /// the protocol says, not one step either side.
    #[test]
    fn the_commit_point_is_exactly_where_the_root_becomes_durable() {
        let c = commit();
        let commit_at = commit_point(c.steps()).expect("there is a commit point");
        let mut store = FaultyStore::new(20_000);
        c.run_prefix(&mut store, commit_at + 1);
        store.power_cut_losing_everything();
        assert_eq!(store.read_durable(6000, 8), vec![5u8; 8], "the root should be durable here");
    }

    /// The manifest is durable before the root is. A cut between them is the case that must roll
    /// back rather than retire, and it can only exist if this ordering holds.
    #[test]
    fn the_manifest_is_durable_before_the_root() {
        let c = commit();
        let root_step = c
            .steps()
            .iter()
            .position(|s| matches!(s, Step::Write { what: What::Root, .. }))
            .expect("root step");
        let mut store = FaultyStore::new(20_000);
        c.run_prefix(&mut store, root_step);
        store.power_cut_losing_everything();
        assert_eq!(store.read_durable(5000, 8), vec![4u8; 8], "the manifest was not durable yet");
        assert_eq!(store.read_durable(6000, 8), vec![0u8; 8], "the root was durable too early");
    }

    /// A block is never advertised as free before its retired contents are gone. A crash between
    /// the two would otherwise leave a block on the free list still holding old ciphertext.
    #[test]
    fn a_block_is_never_freed_before_its_old_contents_are_wiped() {
        let c = commit();
        let free_step = c
            .steps()
            .iter()
            .position(|s| matches!(s, Step::Write { what: What::FreeCapsule(_), .. }))
            .expect("free step");
        for n in 0..=free_step {
            let mut store = FaultyStore::new(20_000);
            c.run_prefix(&mut store, n);
            store.power_cut_losing_everything();
            if store.read_durable(9100, 8) == vec![6u8; 8] {
                assert_eq!(
                    store.read_durable(9000, 8),
                    vec![0u8; 8],
                    "block freed at step {n} with its old contents still there"
                );
            }
        }
    }

    /// Cleanup happens strictly after the commit, so a crash during it leaves a committed space
    /// plus an unfinished cleanup — recoverable — never an uncommitted space with blocks already
    /// wiped.
    #[test]
    fn no_block_is_wiped_before_the_commit_is_durable() {
        let c = commit();
        let commit_at = commit_point(c.steps()).expect("commit point");
        for n in 0..=commit_at {
            let mut store = FaultyStore::new(20_000);
            c.run_prefix(&mut store, n);
            store.power_cut_losing_everything();
            assert_ne!(
                store.read_durable(9100, 8),
                vec![6u8; 8],
                "a block was freed at step {n}, before the commit"
            );
        }
    }

    /// Admission refuses without writing. Both refusals are read-only by construction — there is
    /// no store argument to write to — and that is the property, stated where it can be seen.
    #[test]
    fn admission_refuses_before_anything_is_written() {
        let m = Manifest { transaction: 1, root_generation: 5, retire: vec![], release: vec![] };
        assert_eq!(admit(10, 4, None, 5), Err(Refusal::NoSpace));
        assert_eq!(admit(1, 100, Some(&m), 5), Err(Refusal::CleanupPending));
        assert_eq!(admit(1, 100, Some(&m), 6), Ok(()), "a stale manifest does not block");
        assert_eq!(admit(1, 100, None, 5), Ok(()));
    }

    /// Exactly-enough space is allowed. An off-by-one here would refuse the last legal transaction
    /// in a nearly full container, which is the case a user actually hits.
    #[test]
    fn exactly_enough_space_is_enough() {
        assert_eq!(admit(7, 7, None, 0), Ok(()));
        assert_eq!(admit(8, 7, None, 0), Err(Refusal::NoSpace));
    }
}
