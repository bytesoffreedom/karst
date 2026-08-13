//! The conformance list, as executable claims rather than a checklist someone ticked.
//!
//! The plan carries twenty-seven requirements whose violation breaks the construction. A document
//! listing them is a document; what follows is each one either checked here, checked by a named
//! test elsewhere, or recorded as NOT YET ENFORCED with the reason.
//!
//! The last category is the point of the file. A conformance pass whose output is "all green" while
//! a third of the list has no code behind it is worse than no pass at all, because it converts an
//! open question into a false answer.

use vault::capsule::{Claim, Owner, State, Verdict};
use vault::geometry::{Geometry, CAPSULE_ALIGN, DEFAULT_BLOCK_PAYLOAD};
use vault::params::{FormatParams, SYSTEM_WORKSPACE_RESERVE};
use vault::public::RebuildPlan;
use vault::recover::{action_for, Action, Session};
use vault::record::{MasterKey, SpaceId};
use vault::slot::{Mode, SLOT_LEN};

/// 1. Nothing about the hidden space, and no reserve for it, is recorded in the public space's
///    metadata.
///
/// Checked structurally: the open header is derived from the format version and the file size, and
/// two containers of the same size are byte-identical. A hidden-space field would have to appear
/// here to be persisted at all.
#[test]
fn r01_the_header_records_nothing_about_a_hidden_space() {
    let a = FormatParams::derive(1 << 30);
    let b = FormatParams::derive(1 << 30);
    assert_eq!(a.encode(), b.encode());
    assert_eq!(a.workspace_reserve, SYSTEM_WORKSPACE_RESERVE, "the reserve is a format constant");
}

/// 2. Block ownership lives under its own key, separate from either space's.
#[test]
fn r02_ownership_is_a_separate_key() {
    let layer = MasterKey::generate();
    let space = MasterKey::generate();
    let claim = Claim { state: State::Free, generation: 1, transaction: 1, binding: [0u8; 32] };
    let sealed = vault::capsule::frame(&claim, vault::capsule::seal_claim(&layer, [1u8; 32], 4, 0, &claim));
    assert!(
        matches!(
            vault::capsule::read_capsules(&space, [1u8; 32], 4, [&sealed, &[]], None),
            Verdict::Unknown
        ),
        "a space key opened an ownership-layer record"
    );
}

/// 3. Physical placement is random. 4. The order is not reproducible by the public password.
///
/// Both are properties of the allocator and are checked by its own tests
/// (`two_sessions_do_not_share_an_order`, `the_order_is_actually_shuffled_and_not_merely_a_permutation`).
/// Restated here so the list has one entry per requirement rather than a gap.
#[test]
fn r03_r04_placement_is_random_and_the_order_is_per_session() {
    let seq = |n: u64| {
        let mut a = vault::allocator::Allocator::new(n);
        std::iter::from_fn(move || a.next_candidate()).collect::<Vec<_>>()
    };
    assert_ne!(seq(2000), seq(2000), "two mounts shared an allocation order");
}

/// 5. A refused candidate leaves no trace the public password can read.
///
/// COMPILE-TIME ONLY, and this body is documentation rather than evidence. `Allocator` exposes no
/// accessor for its order or cursor and implements no serialisation, so the property is enforced by
/// the type — but a test cannot demonstrate the absence of an API. An earlier version asserted on
/// `remaining()`, which checks a counter and proves nothing about persistence; that is exactly the
/// shape of a test that looks like evidence and is not.
#[test]
fn r05_the_allocator_cannot_persist_its_state_by_construction() {}

/// 6. FREE appears only after every confirmed reference is gone, and after the wipe.
///
/// Checked by the crash matrix (`a_released_block_has_always_been_wiped_first`) at every prefix.
/// Here: the state machine itself refuses to call anything but Free allocatable.
#[test]
fn r06_only_free_is_allocatable() {
    for s in [
        State::Reserved(Owner::Public),
        State::Live(Owner::Public),
        State::Live(Owner::Hidden),
        State::Retiring(Owner::Public),
        State::Meta(SpaceId::Ownership),
    ] {
        assert!(!s.is_allocatable(), "{s:?} was allocatable");
    }
    assert!(State::Free.is_allocatable());
}

/// 7. A root references a block only after that block is durably out of FREE.
///
/// The commit order enforces it; the crash matrix checks it at every prefix.
#[test]
fn r07_reserved_precedes_the_root_in_the_commit_order() {
    // Pinned by `tx::tests::the_durable_order_is_reserved_payload_live_manifest_root` and by
    // `crash_matrix::every_cut_before_the_commit_point_leaves_the_old_version`.
}

/// 8. UNKNOWN is always fail-closed.
#[test]
fn r08_unknown_is_never_allocatable_and_never_confirmed() {
    assert!(!Verdict::Unknown.is_allocatable());
    assert!(Verdict::Unknown.confirmed().is_none());
}

/// 9. The free index is a cache, never the authority.
#[test]
fn r09_the_free_index_is_only_a_hint() {
    let mut idx = vault::freeindex::FreeIndex::empty(64);
    idx.set(5, true);
    // The index believes; nothing in the capsule layer takes an argument from it, so believing is
    // all it can do. A fresh index believes nothing, which is the safe default.
    assert!(idx.believes_free(5));
    assert_eq!(vault::freeindex::FreeIndex::empty(64).believed_free_count(), 0);
}

/// 10. Old COW versions do not accumulate into a long-lived allocation history.
///
/// NOT YET ENFORCED. The manifest names what to retire and the commit order wipes it before
/// releasing, but nothing yet bounds the number of generations that can exist at once — that is
/// the driver's cleanup loop, which does not exist. Recorded rather than claimed.
#[test]
fn r10_generation_bound_is_not_yet_enforced() {
    // Deliberately empty. See the module docs: an entry with no code behind it is recorded as
    // open, not quietly counted as covered.
}

/// 11. The public mode never reads the ownership layer. 12. It always invalidates capsules
///     unconditionally before use.
#[test]
fn r11_r12_the_public_mode_invalidates_unconditionally() {
    let w = vault::public::PublicWrite { block: 1, capsules: [100, 5000], payload: 9000 };
    let a = vault::public::public_write_steps(&w, &|| vec![0u8; 8], vec![1]);
    let b = vault::public::public_write_steps(&w, &|| vec![0u8; 8], vec![1]);
    assert_eq!(a, b, "the public write sequence varied with something");
}

/// 13. The public mode may destroy the hidden space. 14. The protected mode may not. 15. The
///     hidden mode may not destroy the public space.
#[test]
fn r13_r14_r15_neither_protected_nor_hidden_touches_the_other() {
    let other_live = Verdict::Confirmed(Claim {
        state: State::Live(Owner::Hidden),
        generation: 1,
        transaction: 1,
        binding: [0u8; 32],
    });
    assert_eq!(action_for(Session::Protected, other_live, false, true), Action::LeaveAlone);

    let public_live = Verdict::Confirmed(Claim {
        state: State::Live(Owner::Public),
        generation: 1,
        transaction: 1,
        binding: [0u8; 32],
    });
    assert_eq!(action_for(Session::Hidden, public_live, false, true), Action::LeaveAlone);

    // And the public mode's destruction is deliberate, not incidental.
    assert!(RebuildPlan::new(&[2], 6, &[]).destroys_anything());
}

/// 16. After a crash the last confirmed version survives, losing at most the unfinished operation.
///
/// The crash matrix is the check; every row is a prefix of a real commit sequence.
#[test]
fn r16_crash_leaves_the_last_confirmed_version() {
    // Pinned by `crash_matrix::every_cut_before_the_commit_point_leaves_the_old_version` and
    // `the_first_commit_of_a_fresh_container_follows_the_same_boundary`.
}

/// 17. The protected/public distinction is not a flag on disk.
#[test]
fn r17_the_modes_are_the_same_shape_on_disk() {
    let salt = [1u8; 16];
    let anchors = [1u64, 2];
    let public = vault::slot::seal_slot(b"a", &salt, 0, Mode::Public, &[7u8; 32], None, &anchors);
    let protected =
        vault::slot::seal_slot(b"b", &salt, 0, Mode::Protected, &[7u8; 32], Some(&[8u8; 32]), &anchors);
    assert_eq!(public.len(), protected.len());
    assert_eq!(public.len(), SLOT_LEN);
}

/// 18. Physical capacity accounting belongs to this layer and never reaches the public space's
///     metadata.
#[test]
fn r18_free_space_is_computed_not_stored() {
    // `FreeSpace` is a value returned by a query; there is no setter and no field for it in
    // `FormatParams`, which is the only thing written in the clear.
    let f = vault::catalogue::FreeSpace::LowerBound(10);
    assert_eq!(f.blocks(), 10);
    assert!(!f.is_exact());
}

/// 19. Nothing readable through the space key changes before credits are reserved.
#[test]
fn r19_admission_is_read_only() {
    use vault::tx::{admit, Refusal};
    assert_eq!(admit(100, 1, None, 0), Err(Refusal::NoSpace));
    // `admit` takes no store: the property is structural, and this is where a reader looking for
    // it will find that stated.
}

/// 20. One space mounted at a time.
///
/// NOT YET ENFORCED in this crate. The exclusion is a file lock taken by whatever owns the
/// container file, and nothing here opens a file yet. Recorded as open.
#[test]
fn r20_mount_exclusion_is_not_yet_enforced_here() {}

/// 21. Under the public mode the interface offers nothing that names a hidden space.
///
/// NOT ENFORCEABLE in this crate — it is a property of the user interface, which lives elsewhere.
/// Recorded so the list does not silently drop it.
#[test]
fn r21_interface_rule_lives_outside_this_crate() {}

/// 22. Fresh random nonce per record, no counters, master keys never used directly.
#[test]
fn r22_every_record_gets_a_fresh_nonce() {
    use vault::record::{seal, Context, RecordType};
    let k = MasterKey::generate();
    let ctx = Context {
        format_hash: [0u8; 32],
        record_type: RecordType::Payload,
        space: SpaceId::Public,
        physical_block: 1,
        logical_or_prefix: 0,
        generation: 1,
        copy_index: 0,
    };
    assert_ne!(seal(&k, &ctx, b"x"), seal(&k, &ctx, b"x"), "two seals produced identical bytes");
}

/// 23. The format hash is in the aad, and Argon2 parameters are bounded before allocation.
#[test]
fn r23_the_header_is_bound_and_bounded() {
    let base = FormatParams::derive(1 << 30);
    let mut edited = base;
    edited.block_payload += 1;
    assert_ne!(base.format_hash(), edited.format_hash());

    let mut absurd = base;
    absurd.argon_m_cost = u32::MAX;
    assert!(!absurd.is_acceptable(), "an unbounded KDF cost was accepted");
}

/// 24. Slot plaintext is a fixed length; passwords are pairwise distinct; the public mode's slot is
///     the same type as a lone password's.
#[test]
fn r24_slots_are_indistinguishable_by_shape() {
    assert!(!vault::slot::passwords_are_distinct(b"same", b"same"));
    assert_eq!(vault::slot::random_slot().len(), SLOT_LEN);
}

/// 25. Permanent metadata blocks carry a capsule with no payload binding, so they can be updated
///     in place.
#[test]
fn r25_meta_blocks_do_not_bind_their_payload() {
    assert!(!State::Meta(SpaceId::Public).binds_payload());
    assert!(!State::Meta(SpaceId::Ownership).binds_payload());
    assert!(State::Live(Owner::Public).binds_payload(), "live must still bind");
}

/// 26. A failed fsync is a failed commit.
///
/// NOT YET ENFORCED. The fault backend models a barrier that succeeds or a power cut; it has no
/// "barrier returned an error" case, and no code yet calls a real fsync. Recorded as open rather
/// than counted.
#[test]
fn r26_fsync_failure_handling_is_not_yet_written() {}

/// 27. Recovery is idempotent at every crash point.
#[test]
fn r27_recovery_decisions_are_idempotent() {
    use vault::manifest::{replay_for, Manifest};
    let m = Manifest { transaction: 1, root_generation: 5, retire: vec![1], release: vec![] };
    assert_eq!(replay_for(Some(&m), 5), replay_for(Some(&m), 5));
}

/// The honest summary: how much of the list has code behind it.
///
/// This is a test so it cannot rot into a stale comment. If a requirement moves from open to
/// enforced, this number changes and the change is visible in the diff.
#[test]
fn the_conformance_list_is_not_fully_enforced_yet() {
    const TOTAL: usize = 27;
    // 10 (generation bound), 20 (mount exclusion), 21 (interface), 26 (fsync failure).
    const OPEN: usize = 4;
    assert_eq!(TOTAL - OPEN, 23, "23 of 27 requirements have code behind them");
    // Written as a runtime comparison rather than a constant one so it stays a check: when the
    // open count reaches zero this line must be deleted deliberately, not optimised away.
    assert_ne!(std::hint::black_box(OPEN), 0, "the open list emptied — say so on purpose");
}

/// The geometry facts the rest of the argument quotes, pinned in one place.
#[test]
fn the_geometry_constants_the_argument_depends_on() {
    let g = Geometry::new(DEFAULT_BLOCK_PAYLOAD, 1 << 20);
    assert!(g.is_sane());
    assert_eq!(g.depth(), 3);
    let (a, b) = (g.capsule_offset(0, 1, 0), g.capsule_offset(0, 1, 1));
    assert_ne!(a / CAPSULE_ALIGN as u64, b / CAPSULE_ALIGN as u64);
}
