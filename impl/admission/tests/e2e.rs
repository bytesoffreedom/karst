//! End-to-end сценарии полного admission-пути через несколько модулей вместе.
//! В отличие от per-module тестов, здесь проверяются связки: cookie ↔ конвейер
//! ↔ credential, и особенно DTN carrier-budget ↔ ingress-return, которые
//! раньше тестировались порознь.

use admission::capability::{Capability, CapabilityTable, Quota, Scope};
use admission::cookie::CookieKeyring;
use admission::dtn::{
    solve_pow, BudgetLimits, CarryBudgetTracker, CarryDecision, CarryOffer, DtnCapability,
    DtnCapabilityTable, DtnQuota, RollingReplayWindow, MAX_DTN_TRANSIT_TTL_SECS,
};
use admission::params::EPOCH_DURATION_SECS;
use admission::pipeline::{
    capsule_hash, AdmissionPipeline, Credential, DtnRequest, Outcome, RejectReason, ReplayFilter,
    Request,
};
use admission::rln::{external_nullifier, Field, IdentitySecret, RlnOutcome, RlnQuotaTracker};
use admission::token::{IssuerRing, MockRingVerifier};

const NOW: u64 = 1_000_000;

fn keyring() -> CookieKeyring {
    CookieKeyring::new(EPOCH_DURATION_SECS, NOW, [0x11; 32], [0x22; 32])
}

fn dummy_ring() -> IssuerRing {
    IssuerRing { issuer_pubkeys: vec![[1u8; 32]], threshold_t: 1 }
}

// ============================================================================
// Live «сессия»: первый контакт → challenge → cookie → capability → Admit →
// within-epoch replay reject → свежий запрос снова Admit.
// ============================================================================

#[test]
fn live_session_journey() {
    let kr = keyring();
    let cap = Capability {
        capability_id: [0xA0; 16],
        scope: Scope::MessageDelivery,
        quota: Quota { max_requests: 100, max_bytes: 1 << 20, window_secs: 600 },
        not_before: 0,
        not_after: u32::MAX,
        secret: [0x33; 32],
    };
    let mut caps = CapabilityTable::new();
    caps.insert(cap.clone());
    let ring = dummy_ring();
    let verifier = MockRingVerifier;
    let pipe = AdmissionPipeline {
        keyring: &kr,
        capabilities: &caps,
        token_verifier: &verifier,
        issuer_ring: &ring,
    };
    let mut replay = ReplayFilter::new(0, 1024);

    let client = b"203.0.113.10:7000";
    let carrier = b"c";

    // 1. Первый контакт без cookie → Challenge.
    let first = Request {
        raw_len: 200,
        max_raw_len: admission::params::MAX_PACKET_SIZE,
        client_addr: client,
        carrier_id: carrier,
        cookie: None,
        request_nonce: b"nonce-1",
        requested_scope: Scope::MessageDelivery,
        credential: Credential::Capability(cap.prove(b"nonce-1", 0)),
    };
    assert!(matches!(
        pipe.process(&first, NOW, 0, [0x42; 64], &mut replay, &mut admission::capability::CapabilityQuotaTracker::new()),
        Outcome::Challenge(_)
    ));

    // 2. Клиент берёт cookie и повторяет с capability → Admit.
    let cookie = kr.issue(client, carrier, NOW as u32);
    let proof1 = cap.prove(b"nonce-1", 0);
    let admitted = Request {
        raw_len: 200,
        max_raw_len: admission::params::MAX_PACKET_SIZE,
        client_addr: client,
        carrier_id: carrier,
        cookie: Some(cookie),
        request_nonce: b"nonce-1",
        requested_scope: Scope::MessageDelivery,
        credential: Credential::Capability(proof1),
    };
    assert_eq!(pipe.process(&admitted, NOW, 0, [0; 64], &mut replay, &mut admission::capability::CapabilityQuotaTracker::new()), Outcome::Admit);

    // 3. Тот же proof в ту же эпоху → replay.
    assert_eq!(
        pipe.process(&admitted, NOW, 0, [0; 64], &mut replay, &mut admission::capability::CapabilityQuotaTracker::new()),
        Outcome::Reject(RejectReason::Replay)
    );

    // 4. Свежий запрос (новый nonce) → снова Admit.
    let proof2 = cap.prove(b"nonce-2", 0);
    let admitted2 = Request {
        raw_len: 200,
        max_raw_len: admission::params::MAX_PACKET_SIZE,
        client_addr: client,
        carrier_id: carrier,
        cookie: Some(cookie),
        request_nonce: b"nonce-2",
        requested_scope: Scope::MessageDelivery,
        credential: Credential::Capability(proof2),
    };
    assert_eq!(pipe.process(&admitted2, NOW, 0, [0; 64], &mut replay, &mut admission::capability::CapabilityQuotaTracker::new()), Outcome::Admit);
}

// ============================================================================
// DTN полный жизненный цикл: carrier-budget (нести?) → ingress-return
// (process_dtn) → replay → подмена содержимого. Связывает CarryBudgetTracker
// и process_dtn через ОДИН capsule-id.
// ============================================================================

fn dtn_cap() -> DtnCapability {
    DtnCapability {
        capability_id: [0xD0; 16],
        issued_at: NOW,
        not_after: NOW + MAX_DTN_TRANSIT_TTL_SECS,
        quota: DtnQuota { max_bytes: 1 << 20, max_hops: 16 },
        secret: [0x5A; 32],
    }
}

#[test]
fn dtn_full_lifecycle_carrier_then_ingress() {
    let cap = dtn_cap();
    let mut caps = DtnCapabilityTable::new();
    caps.insert(cap.clone());
    let kr = keyring();
    let ring = dummy_ring();
    let verifier = MockRingVerifier;
    let live_caps = CapabilityTable::new();
    let pipe = AdmissionPipeline {
        keyring: &kr,
        capabilities: &live_caps,
        token_verifier: &verifier,
        issuer_ring: &ring,
    };

    let ciphertext = b"encrypted-emergency-message-carried-through-mesh";
    // Один идентификатор capsule связывает обе стадии.
    let full_hash = capsule_hash(ciphertext);
    let mut capsule_tag = [0u8; 16];
    capsule_tag.copy_from_slice(&full_hash[..16]);

    // --- Стадия carrier: сосед предлагает нести capsule; устройство решает по
    //     бюджету (+ PoW, привязанный к capsule) ---
    let limits = BudgetLimits {
        window_secs: 24 * 60 * 60,
        per_peer_max_messages: 10,
        per_peer_max_bytes: 10 << 20,
        device_max_messages: 100,
        device_max_bytes: 100 << 20,
        pow_difficulty_bits: 8,
    };
    let mut carrier = CarryBudgetTracker::new(limits);
    let sender_peer = [0xEE; 16];
    let pow = solve_pow(&sender_peer, &capsule_tag, 8);
    let offer = CarryOffer {
        peer: sender_peer,
        capsule_tag: &capsule_tag,
        bytes: ciphertext.len() as u64,
        pow_nonce: pow,
    };
    assert_eq!(carrier.offer(&offer, NOW), CarryDecision::Accept, "носитель принимает capsule");

    // --- Стадия ingress-return: онлайн-носитель заливает capsule в сеть ---
    let mut dtn_replay = RollingReplayWindow::new(8);
    let client = b"203.0.113.11:7001";
    let carrier_id = b"c";
    let cookie = kr.issue(client, carrier_id, NOW as u32);
    let proof = cap.prove(&full_hash); // MAC над H(ciphertext)
    let mk_req = |ct: &'static [u8]| DtnRequest {
        raw_len: ct.len(),
        client_addr: client,
        carrier_id,
        cookie: Some(cookie),
        proof,
        ciphertext: ct,
    };
    assert_eq!(
        pipe.process_dtn(&mk_req(ciphertext), &caps, &mut dtn_replay, NOW, [0; 64]),
        Outcome::Admit,
        "пронесённая capsule принята ingress'ом"
    );

    // Replay той же capsule (другой mesh-путь принёс копию) → DtnReplay.
    assert_eq!(
        pipe.process_dtn(&mk_req(ciphertext), &caps, &mut dtn_replay, NOW, [0; 64]),
        Outcome::Reject(RejectReason::DtnReplay)
    );

    // Подмена содержимого при том же proof → Reject(Dtn).
    let other = b"attacker-substituted-different-content";
    let sub = DtnRequest {
        raw_len: other.len(),
        client_addr: client,
        carrier_id,
        cookie: Some(cookie),
        proof, // proof для исходного ciphertext
        ciphertext: other,
    };
    assert!(matches!(
        pipe.process_dtn(&sub, &caps, &mut dtn_replay, NOW, [0; 64]),
        Outcome::Reject(RejectReason::Dtn(_))
    ));
}

#[test]
fn dtn_carrier_sybil_capped_before_ingress() {
    // Sybil из многих дешёвых identity упирается в device-бюджет ещё на стадии
    // carrier — до всякого ingress. (e2e-подтверждение §7.7-аргумента в связке.)
    let limits = BudgetLimits {
        window_secs: 24 * 60 * 60,
        per_peer_max_messages: 5,
        per_peer_max_bytes: 5 << 20,
        device_max_messages: 20,
        device_max_bytes: 100 << 20,
        pow_difficulty_bits: 0,
    };
    let mut carrier = CarryBudgetTracker::new(limits);
    let mut accepted = 0;
    for id in 0u32..100 {
        let mut peer = [0u8; 16];
        peer[..4].copy_from_slice(&id.to_be_bytes());
        let offer = CarryOffer { peer, capsule_tag: b"t", bytes: 100, pow_nonce: 0 };
        for _ in 0..3 {
            if carrier.offer(&offer, NOW) == CarryDecision::Accept {
                accepted += 1;
            }
        }
    }
    assert_eq!(accepted, 20, "device-бюджет ограничивает Sybil на carrier-стадии");
}

// ============================================================================
// RLN — обе стороны честной границы одним тестом: quota-слой РАБОТАЕТ, но
// ветка конвейера остаётся RlnNotImplemented (нет zk-обёртки).
// ============================================================================

#[test]
fn rln_layer_works_but_pipeline_branch_not_implemented() {
    // (a) Слой наказания работает: второе разное сообщение → деанон.
    let mut tracker = RlnQuotaTracker::new(7, b"relay-scope", 1024);
    let id = IdentitySecret(Field::from(0xABCDu64));
    let ext = external_nullifier(7, b"relay-scope");
    assert_eq!(tracker.observe(&id.share(&ext, Field::from(1u64))), RlnOutcome::Accepted);
    match tracker.observe(&id.share(&ext, Field::from(2u64))) {
        RlnOutcome::QuotaViolation { recovered_secret } => {
            assert_eq!(recovered_secret, id.0.to_bytes());
        }
        other => panic!("ожидался slash, получено {:?}", other),
    }

    // (b) Но в конвейере RLN-ветка не проходит (zk-обёртка застаблена).
    let kr = keyring();
    let caps = CapabilityTable::new();
    let ring = dummy_ring();
    let verifier = MockRingVerifier;
    let pipe = AdmissionPipeline {
        keyring: &kr,
        capabilities: &caps,
        token_verifier: &verifier,
        issuer_ring: &ring,
    };
    let mut replay = ReplayFilter::new(0, 1024);
    let client = b"203.0.113.12:7002";
    let carrier = b"c";
    let cookie = kr.issue(client, carrier, NOW as u32);
    let req = Request {
        raw_len: 200,
        max_raw_len: admission::params::MAX_PACKET_SIZE,
        client_addr: client,
        carrier_id: carrier,
        cookie: Some(cookie),
        request_nonce: b"n",
        requested_scope: Scope::MessageDelivery,
        credential: Credential::RlnQuota,
    };
    assert_eq!(
        pipe.process(&req, NOW, 0, [0; 64], &mut replay, &mut admission::capability::CapabilityQuotaTracker::new()),
        Outcome::Reject(RejectReason::RlnNotImplemented)
    );
}

// ============================================================================
// Live с настоящей пороговой кольцевой подписью (feature-gated).
// Связывает tring::sign ↔ token::RealRingVerifier ↔ pipeline в одном сценарии.
// ============================================================================

#[cfg(feature = "unaudited-crypto")]
#[test]
fn live_real_ring_token_journey() {
    use admission::tring::{sign, IssuerKeypair};
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use admission::token::{AdmissionToken, RealRingVerifier};
    use sha2::{Digest, Sha512};

    fn kp(seed: &[u8]) -> IssuerKeypair {
        let mut h = Sha512::new();
        h.update(b"e2e-issuer");
        h.update(seed);
        let mut w = [0u8; 64];
        w.copy_from_slice(&h.finalize());
        IssuerKeypair::from_secret(Scalar::from_bytes_mod_order_wide(&w))
    }

    let kps: Vec<IssuerKeypair> = (0u8..5).map(|i| kp(&[i])).collect();
    let ring_pts: Vec<RistrettoPoint> = kps.iter().map(|k| k.public).collect();
    let token_nonce = [0x9C; 32];
    // 2 из 5 issuer'ов подписывают nonce токена.
    let signers = vec![(1usize, kps[1].secret), (3usize, kps[3].secret)];
    let sig = sign(&token_nonce, &ring_pts, 2, &signers).unwrap();

    let issuer_ring = IssuerRing {
        issuer_pubkeys: ring_pts.iter().map(|p| p.compress().to_bytes()).collect(),
        threshold_t: 2,
    };
    let kr = keyring();
    let caps = CapabilityTable::new();
    let verifier = RealRingVerifier;
    let pipe = AdmissionPipeline {
        keyring: &kr,
        capabilities: &caps,
        token_verifier: &verifier,
        issuer_ring: &issuer_ring,
    };
    let client = b"203.0.113.13:7003";
    let carrier = b"c";
    let cookie = kr.issue(client, carrier, NOW as u32);

    let good = AdmissionToken { ring_sig: sig.to_bytes(), t: token_nonce, epoch_id: 0 };
    let mut replay = ReplayFilter::new(0, 1024);
    let req = Request {
        raw_len: 400,
        max_raw_len: admission::params::MAX_PACKET_SIZE,
        client_addr: client,
        carrier_id: carrier,
        cookie: Some(cookie),
        request_nonce: b"n",
        requested_scope: Scope::MessageDelivery,
        credential: Credential::Token(good),
    };
    assert_eq!(pipe.process(&req, NOW, 0, [0; 64], &mut replay, &mut admission::capability::CapabilityQuotaTracker::new()), Outcome::Admit);

    // Искажение подписи → reject через тот же конвейер.
    let mut bad_bytes = sig.to_bytes();
    let n = bad_bytes.len();
    bad_bytes[n - 1] ^= 0x01;
    let bad = AdmissionToken { ring_sig: bad_bytes, t: token_nonce, epoch_id: 0 };
    let mut replay2 = ReplayFilter::new(0, 1024);
    let req_bad = Request {
        raw_len: 400,
        max_raw_len: admission::params::MAX_PACKET_SIZE,
        client_addr: client,
        carrier_id: carrier,
        cookie: Some(cookie),
        request_nonce: b"n",
        requested_scope: Scope::MessageDelivery,
        credential: Credential::Token(bad),
    };
    assert!(matches!(
        pipe.process(&req_bad, NOW, 0, [0; 64], &mut replay2, &mut admission::capability::CapabilityQuotaTracker::new()),
        Outcome::Reject(RejectReason::Token(_))
    ));
}

// ============================================================================
// R2-1 — an UNAUTHENTICATED request must not be able to burn replay capacity.
// ============================================================================

/// The live path used to commit the replay tag at Stage 3, BEFORE Stage 4 verified the
/// capability HMAC — and for a capability the tag is the client-supplied `proof.mac`. So anyone
/// holding an ordinary cookie could send `capacity` structurally valid requests carrying random
/// MACs: each is rejected later at Stage 4, but had already taken a filter slot. Once full, every
/// NEW unique request gets `BackpressurePow` until the epoch rolls — a cheap relay-wide denial of
/// message delivery, from a party that never proved it holds any capability.
///
/// The DTN path in the same module already documents the correct order (read-only check at
/// Stage 3, insert only after a successful HMAC); this pins the live path to the same rule.
/// Discriminating: restore the early insert and the final genuine request returns
/// `BackpressurePow` instead of `Admit`.
#[test]
fn an_invalid_capability_does_not_consume_replay_capacity() {
    let kr = keyring();
    let cap = Capability {
        capability_id: [0xB0; 16],
        scope: Scope::MessageDelivery,
        quota: Quota { max_requests: 100, max_bytes: 1 << 20, window_secs: 600 },
        not_before: 0,
        not_after: u32::MAX,
        secret: [0x44; 32],
    };
    let mut caps = CapabilityTable::new();
    caps.insert(cap.clone());
    let ring = dummy_ring();
    let verifier = MockRingVerifier;
    let pipe = AdmissionPipeline {
        keyring: &kr,
        capabilities: &caps,
        token_verifier: &verifier,
        issuer_ring: &ring,
    };

    let client = b"198.51.100.7:9000";
    let carrier = b"c";
    let cookie = kr.issue(client, carrier, NOW as u32);
    let capacity = 8;
    let mut replay = ReplayFilter::new(0, capacity);
    let mut quota = admission::capability::CapabilityQuotaTracker::new();

    // The attacker holds a cookie but NO valid capability: `capacity` requests, each with a
    // distinct junk MAC, so every one would claim its own filter slot under the old order.
    for i in 0..capacity as u8 {
        let mut junk = cap.prove(b"nonce-junk", 0);
        junk.mac = [i; 16]; // fails the HMAC check at Stage 4
        let req = Request {
            raw_len: 200,
            max_raw_len: admission::params::MAX_PACKET_SIZE,
            client_addr: client,
            carrier_id: carrier,
            cookie: Some(cookie),
            request_nonce: b"nonce-junk",
            requested_scope: Scope::MessageDelivery,
            credential: Credential::Capability(junk),
        };
        assert!(
            matches!(
                pipe.process(&req, NOW, 0, [0; 64], &mut replay, &mut quota),
                Outcome::Reject(RejectReason::Capability(_))
            ),
            "a junk MAC must be rejected at the capability stage"
        );
    }

    // A genuine, fully authenticated request must still be admitted: the junk must never have
    // reached the filter.
    let good = Request {
        raw_len: 200,
        max_raw_len: admission::params::MAX_PACKET_SIZE,
        client_addr: client,
        carrier_id: carrier,
        cookie: Some(cookie),
        request_nonce: b"nonce-good",
        requested_scope: Scope::MessageDelivery,
        credential: Credential::Capability(cap.prove(b"nonce-good", 0)),
    };
    assert_eq!(
        pipe.process(&good, NOW, 0, [0; 64], &mut replay, &mut quota),
        Outcome::Admit,
        "unauthenticated junk filled the replay filter — that is a relay-wide DoS"
    );

    // And a genuine replay is STILL cheaply rejected (the read-only check must remain).
    assert_eq!(
        pipe.process(&good, NOW, 0, [0; 64], &mut replay, &mut quota),
        Outcome::Reject(RejectReason::Replay),
        "replay detection must survive the reorder"
    );
}
