//! Tests for the §7.7 DTN admission class. The weight is carried by the adversarial ones: a Sybil
//! of many cheap mesh identities must hit the device budget, not the per-peer one.

use admission::dtn::{
    solve_pow, BudgetLimits, CarryBudgetTracker, CarryDecision, CarryOffer, DtnCapability,
    DtnCapabilityTable, DtnQuota, ReplayCheck, RollingReplayWindow, MAX_DTN_TRANSIT_TTL_SECS,
    SECS_PER_DAY,
};

/// An offer without PoW (for tests with pow_difficulty_bits = 0).
fn plain_offer(peer: [u8; 16], bytes: u64) -> CarryOffer<'static> {
    CarryOffer {
        peer,
        capsule_tag: b"tag",
        bytes,
        pow_nonce: 0,
    }
}

// ---------- DTN Capability ----------

fn sample_cap(now: u64) -> DtnCapability {
    DtnCapability {
        capability_id: [0xC1; 16],
        issued_at: now,
        not_after: now + MAX_DTN_TRANSIT_TTL_SECS,
        quota: DtnQuota {
            max_bytes: 1 << 20,
            max_hops: 16,
        },
        secret: [0x5A; 32],
    }
}

#[test]
fn dtn_capability_proof_verifies() {
    let now = 1_000_000u64;
    let cap = sample_cap(now);
    assert!(cap.validate_issue().is_ok());
    let mut table = DtnCapabilityTable::new();
    table.insert(cap.clone());

    let nonce = b"capsule-nonce";
    let proof = cap.prove(nonce);
    // Valid immediately and days later (there is no epoch quantisation).
    assert!(table.verify(&proof, nonce, 500, now).is_ok());
    assert!(table.verify(&proof, nonce, 500, now + 3 * SECS_PER_DAY).is_ok());
}

#[test]
fn dtn_capability_enforces_max_bytes() {
    let now = 1_000_000u64;
    let mut cap = sample_cap(now);
    cap.quota.max_bytes = 1_000;
    let mut table = DtnCapabilityTable::new();
    table.insert(cap.clone());
    let nonce = b"n";
    let proof = cap.prove(nonce);
    // Within quota — fine; beyond it — QuotaExceeded.
    assert!(table.verify(&proof, nonce, 1_000, now).is_ok());
    assert!(table.verify(&proof, nonce, 1_001, now).is_err());
}

#[test]
fn dtn_capability_expires_by_not_after() {
    let now = 1_000_000u64;
    let cap = sample_cap(now);
    let mut table = DtnCapabilityTable::new();
    table.insert(cap.clone());
    let nonce = b"n";
    let proof = cap.prove(nonce);
    // Past not_after — Expired.
    assert!(table.verify(&proof, nonce, 500, cap.not_after + 1).is_err());
}

#[test]
fn dtn_capability_bad_mac_rejected() {
    let now = 1_000_000u64;
    let cap = sample_cap(now);
    let mut table = DtnCapabilityTable::new();
    table.insert(cap.clone());
    let proof = cap.prove(b"nonce-A");
    // A different nonce → the MAC does not match.
    assert!(table.verify(&proof, b"nonce-B", 500, now).is_err());
}

#[test]
fn dtn_capability_ttl_too_long_rejected() {
    let now = 1_000_000u64;
    let mut cap = sample_cap(now);
    cap.not_after = now + MAX_DTN_TRANSIT_TTL_SECS + 1; // beyond the limit
    assert!(cap.validate_issue().is_err());
}

// ---------- Carry budget: per-peer ----------

fn limits() -> BudgetLimits {
    BudgetLimits {
        window_secs: SECS_PER_DAY,
        per_peer_max_messages: 5,
        per_peer_max_bytes: 5_000,
        device_max_messages: 20,
        device_max_bytes: 100_000,
        pow_difficulty_bits: 0, // PoW is tested separately below
    }
}

#[test]
fn per_peer_limit_caps_single_noisy_neighbor() {
    let mut t = CarryBudgetTracker::new(limits());
    let peer = [0xAA; 16];
    let now = 1_000u64;
    // Five messages pass, the sixth is RejectPerPeer (the device budget still has room).
    for _ in 0..5 {
        assert_eq!(t.offer(&plain_offer(peer, 100), now), CarryDecision::Accept);
    }
    assert_eq!(t.offer(&plain_offer(peer, 100), now), CarryDecision::RejectPerPeer);
}

#[test]
fn pow_throttle_rejects_insufficient_and_accepts_solved() {
    use admission::dtn::pow_leading_zero_bits;
    let difficulty = 12u32; // low, so the test solves it quickly
    let mut lim = limits();
    lim.pow_difficulty_bits = difficulty;
    let mut t = CarryBudgetTracker::new(lim);
    let peer = [0xCC; 16];
    let tag = b"capsule-xyz";
    let now = 1_000u64;

    // A solved PoW passes the throttle (and then the budget) → Accept.
    let solved = solve_pow(&peer, tag, difficulty);
    assert!(pow_leading_zero_bits(&peer, tag, solved) >= difficulty);
    let good = CarryOffer { peer, capsule_tag: tag, bytes: 100, pow_nonce: solved };
    assert_eq!(t.offer(&good, now), CarryDecision::Accept);

    // A deliberately insufficient nonce (the first one giving fewer than `difficulty` bits) →
    // Reject, and the PoW is checked BEFORE the budget.
    let mut bad_nonce = 0u64;
    while pow_leading_zero_bits(&peer, tag, bad_nonce) >= difficulty {
        bad_nonce += 1;
    }
    let bad = CarryOffer { peer, capsule_tag: tag, bytes: 100, pow_nonce: bad_nonce };
    assert_eq!(t.offer(&bad, now), CarryDecision::RejectPow);

    // The PoW is bound to capsule_tag: the same nonce under a different tag does not do.
    let other = CarryOffer { peer, capsule_tag: b"other-capsule", bytes: 100, pow_nonce: solved };
    // (Almost certainly insufficient — otherwise the test would pass falsely.)
    if pow_leading_zero_bits(&peer, b"other-capsule", solved) < difficulty {
        assert_eq!(t.offer(&other, now), CarryDecision::RejectPow);
    }
}

// ---------- Carry budget: Sybil (the load-bearing §7.7 test) ----------

#[test]
fn device_budget_caps_sybil_of_many_cheap_identities() {
    // The attacker: 100 DIFFERENT ephemeral identities, each sending only 3 messages, strictly
    // under per_peer_max=5. Without a device budget that would bury the device (300 messages).
    // With device_max=20, exactly 20 are accepted and the rest are RejectDevice, whatever the
    // number of "new" peers.
    let mut t = CarryBudgetTracker::new(limits());
    let now = 1_000u64;
    let mut accepted = 0;
    let mut rejected_device = 0;
    for id in 0u32..100 {
        let mut peer = [0u8; 16];
        peer[..4].copy_from_slice(&id.to_be_bytes());
        for _ in 0..3 {
            match t.offer(&plain_offer(peer, 100), now) {
                CarryDecision::Accept => accepted += 1,
                CarryDecision::RejectDevice => rejected_device += 1,
                other => panic!("unexpected: {:?} (3 < per_peer 5, PoW off)", other),
            }
        }
    }
    assert_eq!(accepted, 20, "the device budget must accept exactly device_max_messages");
    assert_eq!(rejected_device, 300 - 20);
}

#[test]
fn device_byte_budget_caps_aggregate() {
    // The same principle by bytes: many peers under per_peer_max_bytes, but the total is beyond
    // device_max_bytes.
    let lim = BudgetLimits {
        window_secs: SECS_PER_DAY,
        per_peer_max_messages: 100,
        per_peer_max_bytes: 10_000,
        device_max_messages: 100_000,
        device_max_bytes: 50_000,
        pow_difficulty_bits: 0,
    };
    let mut t = CarryBudgetTracker::new(lim);
    let now = 1_000u64;
    let mut accepted_bytes = 0u64;
    for id in 0u32..100 {
        let mut peer = [0u8; 16];
        peer[..4].copy_from_slice(&id.to_be_bytes());
        if t.offer(&plain_offer(peer, 1_000), now) == CarryDecision::Accept {
            accepted_bytes += 1_000;
        }
    }
    assert_eq!(accepted_bytes, 50_000, "the total bytes must not exceed device_max_bytes");
}

#[test]
fn sliding_window_frees_capacity_over_time() {
    let mut t = CarryBudgetTracker::new(limits());
    let peer = [0xBB; 16];
    let start = 1_000u64;
    // Fill the per-peer limit.
    for _ in 0..5 {
        assert_eq!(t.offer(&plain_offer(peer, 100), start), CarryDecision::Accept);
    }
    assert_eq!(t.offer(&plain_offer(peer, 100), start), CarryDecision::RejectPerPeer);
    // After window+1 the old events fall out → there is room again.
    let later = start + SECS_PER_DAY + 1;
    assert_eq!(t.offer(&plain_offer(peer, 100), later), CarryDecision::Accept);
    assert_eq!(t.device_message_count(), 1, "old events must be pruned");
}

// ---------- Rolling replay window ----------

#[test]
fn rolling_replay_detects_duplicate() {
    let mut w = RollingReplayWindow::new(8);
    let now = 100 * SECS_PER_DAY;
    let not_after = now + 3 * SECS_PER_DAY;
    let id = [0x11; 16];
    assert_eq!(w.check_and_insert(id, not_after, now), ReplayCheck::Fresh);
    assert_eq!(w.check_and_insert(id, not_after, now), ReplayCheck::Replayed);
}

#[test]
fn rolling_replay_expired_not_stored() {
    let mut w = RollingReplayWindow::new(8);
    let now = 100 * SECS_PER_DAY;
    let id = [0x22; 16];
    // not_after in the past → Expired.
    assert_eq!(w.check_and_insert(id, now - 1, now), ReplayCheck::Expired);
}

#[test]
fn rolling_replay_beyond_window_rejected() {
    let mut w = RollingReplayWindow::new(8);
    let now = 100 * SECS_PER_DAY;
    let id = [0x33; 16];
    // not_after more than 8 days ahead → BeyondWindow.
    let far = now + 8 * SECS_PER_DAY;
    assert_eq!(w.check_and_insert(id, far, now), ReplayCheck::BeyondWindow);
}

#[test]
fn rolling_replay_bucket_recycled_frees_old() {
    // A record on day D; N days later the same slot bucket is recycled for D+N, the old record is
    // cleared, and the same id is Fresh again (it had expired anyway).
    let mut w = RollingReplayWindow::new(8);
    let day0 = 100 * SECS_PER_DAY;
    let id = [0x44; 16];
    let na0 = day0 + SECS_PER_DAY; // expires the next day
    assert_eq!(w.check_and_insert(id, na0, day0), ReplayCheck::Fresh);
    assert_eq!(w.check_and_insert(id, na0, day0), ReplayCheck::Replayed);

    // Eight days later the same slot holds a new day → the old record is gone.
    let day8 = day0 + 8 * SECS_PER_DAY;
    let na8 = day8 + SECS_PER_DAY;
    // (The same id, but the bucket has been recycled — it counts as fresh.)
    assert_eq!(w.check_and_insert(id, na8, day8), ReplayCheck::Fresh);
}
