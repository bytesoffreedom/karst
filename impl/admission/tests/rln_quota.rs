//! Tests for the §7.4 RLN quota layer: double-presentation detection plus slashing.
//!
//! The load-bearing test is `second_different_message_deanonymizes_violator`: exceeding the quota
//! recovers the violator's secret (an economic penalty, not a preventive block). The boundary (the
//! layer assumes zk-verified shares) is carried by the type's documentation, not by a test.


use admission::rln::{external_nullifier, Field, IdentitySecret, RlnOutcome, RlnQuotaTracker};

fn identity(seed: u64) -> IdentitySecret {
    IdentitySecret(Field::from(seed) + Field::from(0x1000u64))
}

#[test]
fn first_message_accepted() {
    let mut t = RlnQuotaTracker::new(7, b"scope", 1024);
    let id = identity(1);
    let ext = external_nullifier(7, b"scope");
    let share = id.share(&ext, Field::from(100u64));
    assert_eq!(t.observe(&share), RlnOutcome::Accepted);
}

#[test]
fn second_different_message_deanonymizes_violator() {
    let mut t = RlnQuotaTracker::new(7, b"scope", 1024);
    let id = identity(42);
    let ext = external_nullifier(7, b"scope");

    // The first message — within quota.
    let s1 = id.share(&ext, Field::from(111u64));
    assert_eq!(t.observe(&s1), RlnOutcome::Accepted);

    // A second DIFFERENT message from the same identity in the same epoch → a violation, and the
    // secret is recovered.
    let s2 = id.share(&ext, Field::from(222u64));
    match t.observe(&s2) {
        RlnOutcome::QuotaViolation { recovered_secret } => {
            assert_eq!(
                recovered_secret,
                id.0.to_bytes(),
                "the recovered secret must equal the violator's secret"
            );
        }
        other => panic!("expected QuotaViolation, got {:?}", other),
    }
}

#[test]
fn same_message_replay_is_duplicate_not_violation() {
    let mut t = RlnQuotaTracker::new(7, b"scope", 1024);
    let id = identity(5);
    let ext = external_nullifier(7, b"scope");
    let m = Field::from(333u64);
    let share = id.share(&ext, m);
    assert_eq!(t.observe(&share), RlnOutcome::Accepted);
    // The very same message_hash again is one RLNProof, not a violation.
    assert_eq!(t.observe(&share), RlnOutcome::Duplicate);
}

#[test]
fn different_identities_do_not_cross_slash() {
    let mut t = RlnQuotaTracker::new(7, b"scope", 1024);
    let ext = external_nullifier(7, b"scope");
    let a = identity(1).share(&ext, Field::from(10u64));
    let b = identity(2).share(&ext, Field::from(20u64));
    assert_eq!(t.observe(&a), RlnOutcome::Accepted);
    // A different identity gives a different nullifier → separate accounting, no slash.
    assert_eq!(t.observe(&b), RlnOutcome::Accepted);
}

#[test]
fn epoch_rotation_resets_quota() {
    let mut t = RlnQuotaTracker::new(7, b"scope", 1024);
    let id = identity(9);

    let ext7 = external_nullifier(7, b"scope");
    let s7 = id.share(&ext7, Field::from(1u64));
    assert_eq!(t.observe(&s7), RlnOutcome::Accepted);

    // A new epoch resets the quota; the same identity may send again.
    t.roll_epoch(8);
    let ext8 = external_nullifier(8, b"scope");
    let s8 = id.share(&ext8, Field::from(1u64));
    assert_eq!(t.observe(&s8), RlnOutcome::Accepted);
}

#[test]
fn capacity_triggers_backpressure() {
    let mut t = RlnQuotaTracker::new(7, b"scope", 2); // capacity: 2 identities
    let ext = external_nullifier(7, b"scope");
    assert_eq!(t.observe(&identity(1).share(&ext, Field::from(1u64))), RlnOutcome::Accepted);
    assert_eq!(t.observe(&identity(2).share(&ext, Field::from(1u64))), RlnOutcome::Accepted);
    // A third NEW identity does not fit → backpressure.
    assert_eq!(t.observe(&identity(3).share(&ext, Field::from(1u64))), RlnOutcome::Backpressure);
}

// ---------- Load-bearing: epoch freshness (otherwise the limit is bypassed) ----------

#[test]
fn stale_or_future_epoch_rejected() {
    // The tracker is on epoch 7. A share built for epoch 5 (external_nullifier(5)) matches neither
    // the current epoch (7) nor the grace previous one (6) → WrongEpoch. Without this check an
    // identity would cycle epoch_id and send without limit.
    let mut t = RlnQuotaTracker::new(7, b"scope", 1024);
    let id = identity(1);
    let stale = id.share(&external_nullifier(5, b"scope"), Field::from(1u64));
    assert_eq!(t.observe(&stale), RlnOutcome::WrongEpoch);
    // And a future epoch (9) too.
    let future = id.share(&external_nullifier(9, b"scope"), Field::from(1u64));
    assert_eq!(t.observe(&future), RlnOutcome::WrongEpoch);
}

#[test]
fn straddle_across_epoch_boundary_still_slashes() {
    // THE most important test: an attempt to dodge slashing by spreading two different messages of
    // one epoch across a rotation boundary.
    // 1) On epoch 7 the identity sends message A (external_nullifier(7)).
    // 2) The tracker advances to epoch 8 (grace retains the state of epoch 7).
    // 3) The identity sends a SECOND, different message B, still for epoch 7.
    // Without the grace retention step 3 would come back Accepted (a bypass). With it, it is a
    // QuotaViolation: the same identity, the same epoch, two messages → slash.
    let mut t = RlnQuotaTracker::new(7, b"scope", 1024);
    let id = identity(77);
    let ext7 = external_nullifier(7, b"scope");

    let a = id.share(&ext7, Field::from(1u64));
    assert_eq!(t.observe(&a), RlnOutcome::Accepted);

    t.roll_epoch(8); // the epoch boundary

    let b = id.share(&ext7, Field::from(2u64)); // a second, different message of epoch 7
    match t.observe(&b) {
        RlnOutcome::QuotaViolation { recovered_secret } => {
            assert_eq!(recovered_secret, id.0.to_bytes());
        }
        other => panic!("straddling an epoch boundary must slash, got {:?}", other),
    }
}

#[test]
fn beyond_grace_window_epoch_rejected() {
    // An epoch jump larger than the grace: the previous state is not retained, and shares of the
    // old epoch are refused as WrongEpoch.
    let mut t = RlnQuotaTracker::new(7, b"scope", 1024);
    let id = identity(1);
    let ext7 = external_nullifier(7, b"scope");
    assert_eq!(t.observe(&id.share(&ext7, Field::from(1u64))), RlnOutcome::Accepted);

    t.roll_epoch(10); // a jump larger than grace(1)
    // Epoch 7 is now neither current(10) nor previous(9) → WrongEpoch.
    assert_eq!(t.observe(&id.share(&ext7, Field::from(2u64))), RlnOutcome::WrongEpoch);
}
