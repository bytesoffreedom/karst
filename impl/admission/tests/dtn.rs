//! Тесты DTN-класса допуска §7.7. Вес несут состязательные: Sybil из многих
//! дешёвых mesh-identity должен упираться в device-бюджет, а не в per-peer.

use admission::dtn::{
    solve_pow, BudgetLimits, CarryBudgetTracker, CarryDecision, CarryOffer, DtnCapability,
    DtnCapabilityTable, DtnQuota, ReplayCheck, RollingReplayWindow, MAX_DTN_TRANSIT_TTL_SECS,
    SECS_PER_DAY,
};

/// Предложение без PoW (для тестов с pow_difficulty_bits = 0).
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
    // Валиден сразу и спустя дни (нет epoch-квантования).
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
    // В пределах квоты — ок; сверх — QuotaExceeded.
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
    // За not_after — Expired.
    assert!(table.verify(&proof, nonce, 500, cap.not_after + 1).is_err());
}

#[test]
fn dtn_capability_bad_mac_rejected() {
    let now = 1_000_000u64;
    let cap = sample_cap(now);
    let mut table = DtnCapabilityTable::new();
    table.insert(cap.clone());
    let proof = cap.prove(b"nonce-A");
    // Другой nonce → MAC не совпал.
    assert!(table.verify(&proof, b"nonce-B", 500, now).is_err());
}

#[test]
fn dtn_capability_ttl_too_long_rejected() {
    let now = 1_000_000u64;
    let mut cap = sample_cap(now);
    cap.not_after = now + MAX_DTN_TRANSIT_TTL_SECS + 1; // за пределом
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
        pow_difficulty_bits: 0, // PoW отдельно тестируется ниже
    }
}

#[test]
fn per_peer_limit_caps_single_noisy_neighbor() {
    let mut t = CarryBudgetTracker::new(limits());
    let peer = [0xAA; 16];
    let now = 1_000u64;
    // 5 сообщений проходят, 6-е — RejectPerPeer (device-бюджет ещё есть).
    for _ in 0..5 {
        assert_eq!(t.offer(&plain_offer(peer, 100), now), CarryDecision::Accept);
    }
    assert_eq!(t.offer(&plain_offer(peer, 100), now), CarryDecision::RejectPerPeer);
}

#[test]
fn pow_throttle_rejects_insufficient_and_accepts_solved() {
    use admission::dtn::pow_leading_zero_bits;
    let difficulty = 12u32; // низкая, быстро решается в тесте
    let mut lim = limits();
    lim.pow_difficulty_bits = difficulty;
    let mut t = CarryBudgetTracker::new(lim);
    let peer = [0xCC; 16];
    let tag = b"capsule-xyz";
    let now = 1_000u64;

    // Решённый PoW проходит throttle (и далее бюджет) → Accept.
    let solved = solve_pow(&peer, tag, difficulty);
    assert!(pow_leading_zero_bits(&peer, tag, solved) >= difficulty);
    let good = CarryOffer { peer, capsule_tag: tag, bytes: 100, pow_nonce: solved };
    assert_eq!(t.offer(&good, now), CarryDecision::Accept);

    // Заведомо недостаточный nonce (первый, дающий < difficulty бит) → RejectPow,
    // причём PoW проверяется ДО бюджета.
    let mut bad_nonce = 0u64;
    while pow_leading_zero_bits(&peer, tag, bad_nonce) >= difficulty {
        bad_nonce += 1;
    }
    let bad = CarryOffer { peer, capsule_tag: tag, bytes: 100, pow_nonce: bad_nonce };
    assert_eq!(t.offer(&bad, now), CarryDecision::RejectPow);

    // PoW привязан к capsule_tag: тот же nonce под другой tag не годится.
    let other = CarryOffer { peer, capsule_tag: b"other-capsule", bytes: 100, pow_nonce: solved };
    // (почти наверняка недостаточен — иначе тест ложно прошёл бы; проверяем явно)
    if pow_leading_zero_bits(&peer, b"other-capsule", solved) < difficulty {
        assert_eq!(t.offer(&other, now), CarryDecision::RejectPow);
    }
}

// ---------- Carry budget: Sybil (несущий тест §7.7) ----------

#[test]
fn device_budget_caps_sybil_of_many_cheap_identities() {
    // Атакующий: 100 РАЗНЫХ эфемерных identity, каждая шлёт лишь 3 сообщения —
    // строго под per_peer_max=5. Без device-бюджета это забило бы устройство
    // (300 сообщений). С device_max=20 — принимается ровно 20, остальное
    // RejectDevice, независимо от числа «новых» пиров.
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
                other => panic!("не ожидалось: {:?} (3 < per_peer 5, PoW выкл)", other),
            }
        }
    }
    assert_eq!(accepted, 20, "device-бюджет должен принять ровно device_max_messages");
    assert_eq!(rejected_device, 300 - 20);
}

#[test]
fn device_byte_budget_caps_aggregate() {
    // Тот же принцип по байтам: много пиров под per_peer_max_bytes, но суммарно
    // за device_max_bytes.
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
    assert_eq!(accepted_bytes, 50_000, "суммарные байты не должны превысить device_max_bytes");
}

#[test]
fn sliding_window_frees_capacity_over_time() {
    let mut t = CarryBudgetTracker::new(limits());
    let peer = [0xBB; 16];
    let start = 1_000u64;
    // Забить per-peer лимит.
    for _ in 0..5 {
        assert_eq!(t.offer(&plain_offer(peer, 100), start), CarryDecision::Accept);
    }
    assert_eq!(t.offer(&plain_offer(peer, 100), start), CarryDecision::RejectPerPeer);
    // Спустя окно+1 старые события выпали → снова есть место.
    let later = start + SECS_PER_DAY + 1;
    assert_eq!(t.offer(&plain_offer(peer, 100), later), CarryDecision::Accept);
    assert_eq!(t.device_message_count(), 1, "старые события должны быть вычищены");
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
    // not_after в прошлом → Expired.
    assert_eq!(w.check_and_insert(id, now - 1, now), ReplayCheck::Expired);
}

#[test]
fn rolling_replay_beyond_window_rejected() {
    let mut w = RollingReplayWindow::new(8);
    let now = 100 * SECS_PER_DAY;
    let id = [0x33; 16];
    // not_after дальше 8 дней вперёд → BeyondWindow.
    let far = now + 8 * SECS_PER_DAY;
    assert_eq!(w.check_and_insert(id, far, now), ReplayCheck::BeyondWindow);
}

#[test]
fn rolling_replay_bucket_recycled_frees_old() {
    // Запись в день D; спустя N дней тот же слот-корзину переиспользует день
    // D+N, старая запись вычищается → та же id снова Fresh (и так истекла).
    let mut w = RollingReplayWindow::new(8);
    let day0 = 100 * SECS_PER_DAY;
    let id = [0x44; 16];
    let na0 = day0 + SECS_PER_DAY; // истекает на следующий день
    assert_eq!(w.check_and_insert(id, na0, day0), ReplayCheck::Fresh);
    assert_eq!(w.check_and_insert(id, na0, day0), ReplayCheck::Replayed);

    // Спустя 8 дней тот же слот займёт новый день → старая запись ушла.
    let day8 = day0 + 8 * SECS_PER_DAY;
    let na8 = day8 + SECS_PER_DAY;
    // (та же id, но теперь корзина переиспользована — считается свежей)
    assert_eq!(w.check_and_insert(id, na8, day8), ReplayCheck::Fresh);
}
