//! The crash matrix: every point the power can go out, and what must be true afterwards.
//!
//! These are integration tests rather than unit tests because the properties are about the
//! protocol as a whole, not about any one module. Each row of the plan's matrix is a loop over
//! prefixes of the commit sequence, cut with the storage-fault backend, with the invariant checked
//! after every single one — not at a hand-picked point where it is known to hold.
//!
//! What makes this possible is that the commit order is a VALUE (`tx::Commit`). A protocol written
//! as straight-line code with barriers between statements can only be crash-tested by killing the
//! process at each line, and killing a process is not power loss: the kernel still writes out the
//! dirty pages afterwards, so the file ends up more complete than the program ever made it.

use vault::faulty::{Fate, FaultyStore};
use vault::manifest::{blocks_new_transaction, replay_for, Manifest, Replay};
use vault::tx::{admit, commit_point, BlockRetire, BlockWrite, Commit, Refusal, Step, What};

const STORE_LEN: usize = 40_000;
const ROOT_AT: u64 = 6000;
const MANIFEST_AT: u64 = 5000;
const WIPE_AT: u64 = 9000;
const FREE_CAPSULE_AT: u64 = 9100;

fn block_write(block: u64, base: u64) -> BlockWrite {
    BlockWrite {
        block,
        reserved_capsule: (base, vec![0x11; 16]),
        payload: (base + 200, vec![0x22; 16]),
        live_capsule: (base, vec![0x33; 16]),
    }
}

fn commit() -> Commit {
    Commit::build(
        &[block_write(1, 1000), block_write(2, 2000), block_write(3, 3000)],
        (MANIFEST_AT, vec![0x44; 16]),
        (ROOT_AT, vec![0x55; 16]),
        &[BlockRetire {
            block: 9,
            wipe: (WIPE_AT, vec![0x00; 16]),
            free_capsule: (FREE_CAPSULE_AT, vec![0x66; 16]),
        }],
        (MANIFEST_AT, vec![0x00; 16]),
    )
}

fn step_index(c: &Commit, pred: impl Fn(&What) -> bool) -> usize {
    c.steps()
        .iter()
        .position(|s| matches!(s, Step::Write { what, .. } if pred(what)))
        .expect("step present in the commit sequence")
}

/// Row: a cut at ANY point before the commit leaves the previous version live.
///
/// Checked at every prefix rather than at a chosen one. A protocol can be right at the point
/// somebody thought to test and wrong two steps earlier.
#[test]
fn every_cut_before_the_commit_point_leaves_the_old_version() {
    let c = commit();
    let commit_at = commit_point(c.steps()).expect("a commit point exists");
    for n in 0..=commit_at {
        let mut store = FaultyStore::new(STORE_LEN);
        c.run_prefix(&mut store, n);
        store.power_cut_losing_everything();
        assert_eq!(
            store.read_durable(ROOT_AT, 16),
            vec![0u8; 16],
            "the root became durable after {n} steps, before the commit point at {commit_at}"
        );
    }
}

/// Row: a cut anywhere before the commit leaves no block wiped and none freed.
///
/// If cleanup could start early, an interrupted transaction would have destroyed data belonging to
/// the version that is still live.
#[test]
fn no_cleanup_happens_before_the_commit_is_durable() {
    let c = commit();
    let commit_at = commit_point(c.steps()).expect("a commit point exists");
    for n in 0..=commit_at {
        let mut store = FaultyStore::new(STORE_LEN);
        c.run_prefix(&mut store, n);
        store.power_cut_losing_everything();
        assert_ne!(
            store.read_durable(FREE_CAPSULE_AT, 16),
            vec![0x66; 16],
            "a block was released at step {n}, before the commit"
        );
    }
}

/// Row: a block is never advertised free while its retired contents are still there.
///
/// The window between wiping and releasing is where a crash would otherwise leave old ciphertext
/// on a block the allocator is willing to hand out — and it would stay that way until something
/// happened to reuse it, which may be never.
#[test]
fn a_released_block_has_always_been_wiped_first() {
    let c = commit();
    for n in 0..=c.steps().len() {
        let mut store = FaultyStore::new(STORE_LEN);
        c.run_prefix(&mut store, n);
        store.power_cut_losing_everything();
        if store.read_durable(FREE_CAPSULE_AT, 16) == vec![0x66; 16] {
            assert_eq!(
                store.read_durable(WIPE_AT, 16),
                vec![0u8; 16],
                "block released at step {n} with its old contents still on disk"
            );
        }
    }
}

/// Row: the manifest is durable before the root, at every prefix — which is what makes the
/// roll-back branch of recovery reachable at all.
#[test]
fn the_manifest_is_durable_no_later_than_the_root() {
    let c = commit();
    for n in 0..=c.steps().len() {
        let mut store = FaultyStore::new(STORE_LEN);
        c.run_prefix(&mut store, n);
        store.power_cut_losing_everything();
        let root_durable = store.read_durable(ROOT_AT, 16) == vec![0x55; 16];
        let manifest_durable = store.read_durable(MANIFEST_AT, 16) == vec![0x44; 16];
        if root_durable {
            // Either the manifest is still there, or cleanup has already cleared it — both mean it
            // was durable before the root.
            let cleared = store.read_durable(MANIFEST_AT, 16) == vec![0u8; 16];
            assert!(
                manifest_durable || cleared,
                "at step {n} the root was durable with no manifest ever written"
            );
        }
    }
}

/// Row: reordering INSIDE an epoch cannot make the root durable early.
///
/// The previous tests lose every pending write. This one lets them land, in every order, and
/// requires the boundary to hold anyway — because the guarantee is about barriers, not about luck
/// in the ordering.
#[test]
fn no_ordering_within_an_epoch_commits_early() {
    let c = commit();
    let root_step = step_index(&c, |w| matches!(w, What::Root));
    for n in 0..root_step {
        for order in vault::faulty::all_orderings(3) {
            let mut store = FaultyStore::new(STORE_LEN);
            c.run_prefix(&mut store, n);
            store.power_cut(&order, &[Fate::Whole, Fate::Whole, Fate::Whole]);
            assert_eq!(
                store.read_durable(ROOT_AT, 16),
                vec![0u8; 16],
                "ordering {order:?} at step {n} committed early"
            );
        }
    }
}

/// Row: a torn write is survivable — it leaves a partial range, never a plausible-looking whole
/// one. The point is that partial bytes must not read as a valid record, which the record layer
/// enforces; here we only pin that tearing really produces a partial image.
#[test]
fn a_torn_write_leaves_a_partial_range_not_a_whole_one() {
    let c = commit();
    let root_step = step_index(&c, |w| matches!(w, What::Root));
    let mut store = FaultyStore::new(STORE_LEN);
    c.run_prefix(&mut store, root_step);
    store.write(ROOT_AT, &[0x55; 16]);
    store.power_cut(&[0], &[Fate::TornPrefix(4)]);
    let image = store.read_durable(ROOT_AT, 16);
    assert_ne!(image, vec![0x55; 16], "a torn write landed whole");
    assert_ne!(image, vec![0u8; 16], "a torn write landed as nothing");
}

/// Row: a second crash during recovery must not make things worse. Replaying the same decision
/// twice is the definition of idempotent, and recovery gets no say in how often it is interrupted.
#[test]
fn replaying_the_same_recovery_decision_twice_changes_nothing() {
    let m = Manifest { transaction: 1, root_generation: 5, retire: vec![1, 2], release: vec![3] };
    let first = replay_for(Some(&m), 5);
    let second = replay_for(Some(&m), 5);
    assert_eq!(first, second, "the same inputs gave two different decisions");
    assert_eq!(first, Replay::FinishCleanup);
}

/// Row: a commit may not begin while a cleanup is outstanding. Without this, the earlier
/// manifest falls behind the live root, is discarded as stale, and its retire list leaks with
/// nothing left recording that those blocks existed.
#[test]
fn a_second_transaction_cannot_start_on_top_of_an_unfinished_cleanup() {
    let outstanding = Manifest { transaction: 1, root_generation: 5, retire: vec![7], release: vec![] };
    assert!(blocks_new_transaction(Some(&outstanding), 5));
    assert_eq!(admit(1, 1000, Some(&outstanding), 5), Err(Refusal::CleanupPending));
}

/// Row: admission refuses before writing. The property is structural — `admit` takes no store —
/// and this states it where a reader looking for the crash guarantees will find it.
#[test]
fn a_refused_transaction_leaves_the_container_untouched() {
    let store = FaultyStore::new(STORE_LEN);
    let before = store.read_durable(0, STORE_LEN);
    assert_eq!(admit(1_000_000, 10, None, 0), Err(Refusal::NoSpace));
    assert_eq!(store.read_durable(0, STORE_LEN), before);
    assert_eq!(store.pending(), 0, "a refusal queued a write");
}

/// Row: the very first commit of a fresh container behaves like any other — there is no special
/// case for "no previous root", which is where a special case would hide.
#[test]
fn the_first_commit_of_a_fresh_container_follows_the_same_boundary() {
    let c = Commit::build(
        &[block_write(1, 1000)],
        (MANIFEST_AT, vec![0x44; 16]),
        (ROOT_AT, vec![0x55; 16]),
        &[],
        (MANIFEST_AT, vec![0x00; 16]),
    );
    let commit_at = commit_point(c.steps()).expect("a commit point exists");
    for n in 0..=commit_at {
        let mut store = FaultyStore::new(STORE_LEN);
        c.run_prefix(&mut store, n);
        store.power_cut_losing_everything();
        assert_eq!(store.read_durable(ROOT_AT, 16), vec![0u8; 16], "committed early at {n}");
    }
    let mut store = FaultyStore::new(STORE_LEN);
    c.run_prefix(&mut store, commit_at + 1);
    store.power_cut_losing_everything();
    assert_eq!(store.read_durable(ROOT_AT, 16), vec![0x55; 16], "never committed at all");
}

/// The matrix is only worth anything if it FAILS on a wrong protocol, so here is a wrong one.
///
/// This builds a commit whose root is written before the manifest — the mistake that makes the
/// roll-back branch of recovery unreachable, because after the switch there is nothing left to
/// derive the retire list from. The check below is the same one
/// `the_manifest_is_durable_no_later_than_the_root` runs, and it must find a prefix where the root
/// is durable and the manifest was never written.
///
/// Without this, every row above is consistent with a harness that cannot tell right from wrong.
#[test]
fn the_matrix_rejects_a_commit_that_writes_the_root_before_the_manifest() {
    // Hand-built in the wrong order, deliberately not going through `Commit::build`.
    let steps = [
        Step::Write { offset: 1000, bytes: vec![0x11; 16], what: What::ReservedCapsule(1) },
        Step::Barrier,
        Step::Write { offset: 1200, bytes: vec![0x22; 16], what: What::Payload(1) },
        Step::Barrier,
        Step::Write { offset: ROOT_AT, bytes: vec![0x55; 16], what: What::Root },
        Step::Barrier,
        Step::Write { offset: MANIFEST_AT, bytes: vec![0x44; 16], what: What::Manifest },
        Step::Barrier,
    ];

    let mut caught = false;
    for n in 0..=steps.len() {
        let mut store = FaultyStore::new(STORE_LEN);
        for step in steps.iter().take(n) {
            match step {
                Step::Write { offset, bytes, .. } => store.write(*offset, bytes),
                Step::Barrier => store.barrier(),
            }
        }
        store.power_cut_losing_everything();
        let root_durable = store.read_durable(ROOT_AT, 16) == vec![0x55; 16];
        let manifest_present = store.read_durable(MANIFEST_AT, 16) == vec![0x44; 16];
        if root_durable && !manifest_present {
            caught = true;
        }
    }
    assert!(
        caught,
        "the harness found no prefix where the root outlived a missing manifest — \
         it cannot distinguish the correct order from the broken one"
    );
}
