//! Тесты enforcement квоты capability (§7.2) — закрытие пробела, при котором
//! захваченный proof переиспользовался по разу в каждой новой эпохе до
//! `not_after`. Несущий тест — `captured_proof_replay_caught_across_epoch`.

use admission::capability::{
    Capability, CapabilityProof, CapabilityQuotaTracker, CapabilityTable, Quota, QuotaDecision,
    Scope,
};
use admission::cookie::CookieKeyring;
use admission::params::EPOCH_DURATION_SECS;
use admission::pipeline::{
    AdmissionPipeline, Credential, Outcome, RejectReason, ReplayFilter, Request,
};
use admission::token::{IssuerRing, MockRingVerifier};

const NOW: u64 = 1_000_000;

fn cap_with(max_requests: u32, max_bytes: u64, window_secs: u32) -> Capability {
    Capability {
        capability_id: [0xC0; 16],
        scope: Scope::MessageDelivery,
        quota: Quota { max_requests, max_bytes, window_secs },
        not_before: 0,
        not_after: u32::MAX,
        secret: [0x33; 32],
    }
}

// ---------- Юнит-уровень трекера ----------

#[test]
fn tracker_enforces_request_count() {
    let cap = cap_with(3, 1 << 20, 600);
    let mut t = CapabilityQuotaTracker::new();
    // 3 разных proof-тега проходят, 4-й — Exceeded.
    for i in 0..3u8 {
        assert_eq!(t.consume(cap.capability_id, &cap.quota,[i; 16], 100, NOW), QuotaDecision::Ok);
    }
    assert_eq!(t.consume(cap.capability_id, &cap.quota,[9; 16], 100, NOW), QuotaDecision::Exceeded);
}

#[test]
fn tracker_enforces_byte_budget() {
    let cap = cap_with(100, 1000, 600);
    let mut t = CapabilityQuotaTracker::new();
    assert_eq!(t.consume(cap.capability_id, &cap.quota,[1; 16], 600, NOW), QuotaDecision::Ok);
    assert_eq!(t.consume(cap.capability_id, &cap.quota,[2; 16], 400, NOW), QuotaDecision::Ok); // ровно 1000
    assert_eq!(t.consume(cap.capability_id, &cap.quota,[3; 16], 1, NOW), QuotaDecision::Exceeded);
}

#[test]
fn tracker_detects_verbatim_replay() {
    let cap = cap_with(100, 1 << 20, 600);
    let mut t = CapabilityQuotaTracker::new();
    assert_eq!(t.consume(cap.capability_id, &cap.quota,[7; 16], 100, NOW), QuotaDecision::Ok);
    // Тот же тег — дословный replay, не учитывается повторно.
    assert_eq!(t.consume(cap.capability_id, &cap.quota,[7; 16], 100, NOW), QuotaDecision::Replay);
}

#[test]
fn tracker_reap_drops_stale_windows() {
    let cap = cap_with(100, 1 << 20, 600);
    let mut t = CapabilityQuotaTracker::new();
    assert_eq!(t.consume(cap.capability_id, &cap.quota,[1; 16], 100, NOW), QuotaDecision::Ok);
    // Пока в окне — не убирается.
    assert_eq!(t.reap(NOW, 600), 0);
    // Спустя окно запись протухла → capability выметается.
    assert_eq!(t.reap(NOW + 601, 600), 1);
    // После уборки тот же тег снова свеж (не replay).
    assert_eq!(t.consume(cap.capability_id, &cap.quota,[1; 16], 100, NOW + 601), QuotaDecision::Ok);
}

#[test]
fn tracker_window_slides_and_frees_quota() {
    let cap = cap_with(1, 1 << 20, 600);
    let mut t = CapabilityQuotaTracker::new();
    assert_eq!(t.consume(cap.capability_id, &cap.quota,[1; 16], 100, NOW), QuotaDecision::Ok);
    assert_eq!(t.consume(cap.capability_id, &cap.quota,[2; 16], 100, NOW), QuotaDecision::Exceeded);
    // Спустя окно старая запись выпадает → снова есть место (и старый тег
    // больше не считается replay).
    assert_eq!(t.consume(cap.capability_id, &cap.quota,[2; 16], 100, NOW + 601), QuotaDecision::Ok);
}

// ---------- Через конвейер: несущее — закрытие пробела ----------

fn pipeline_env() -> (CookieKeyring, IssuerRing) {
    (
        CookieKeyring::new(EPOCH_DURATION_SECS, NOW, [0x11; 32], [0x22; 32]),
        IssuerRing { issuer_pubkeys: vec![[1u8; 32]], threshold_t: 1 },
    )
}

fn mk_req<'a>(
    client: &'a [u8],
    carrier: &'a [u8],
    cookie: admission::cookie::Cookie,
    nonce: &'a [u8],
    proof: CapabilityProof,
) -> Request<'a> {
    Request {
        raw_len: 300,
        client_addr: client,
        carrier_id: carrier,
        cookie: Some(cookie),
        request_nonce: nonce,
        requested_scope: Scope::MessageDelivery,
        credential: Credential::Capability(proof),
    }
}

#[test]
fn captured_proof_replay_caught_across_epoch() {
    // ПРОБЕЛ, который закрываем: раньше захваченный (nonce, proof) проходил
    // заново в КАЖДОЙ новой эпохе (epoch-scoped replay-фильтр сбрасывался, а
    // verify не проверяет актуальность эпохи). Теперь per-capability quota-
    // трекер (НЕ epoch-scoped) ловит дословный replay через границу эпохи.
    let cap = cap_with(100, 1 << 20, 600);
    let mut caps = CapabilityTable::new();
    caps.insert(cap.clone());
    let (kr, ring) = pipeline_env();
    let verifier = MockRingVerifier;
    let pipe = AdmissionPipeline {
        keyring: &kr,
        capabilities: &caps,
        token_verifier: &verifier,
        issuer_ring: &ring,
    };
    let client = b"203.0.113.30:8000";
    let carrier = b"c";
    let cookie = kr.issue(client, carrier, NOW as u32);
    let nonce = b"captured-nonce";
    let proof = cap.prove(nonce, 0); // proof для эпохи 0

    // Общие для узла состояние: replay-фильтр (epoch-scoped) и quota-трекер.
    let mut replay = ReplayFilter::new(0, 1024);
    let mut cq = CapabilityQuotaTracker::new();

    // Эпоха 0: допущен.
    assert_eq!(
        pipe.process(&mk_req(client, carrier, cookie, nonce, proof), NOW, 0, [0; 64], &mut replay, &mut cq),
        Outcome::Admit
    );

    // Эпоха 1: тот же захваченный proof. Stage-3 фильтр сброшен ротацией и
    // пропускает; но quota-трекер помнит proof.mac → Reject(Replay).
    // (Без трекера здесь был бы повторный Admit — это и есть закрытый пробел.)
    assert_eq!(
        pipe.process(&mk_req(client, carrier, cookie, nonce, proof), NOW, 1, [0; 64], &mut replay, &mut cq),
        Outcome::Reject(RejectReason::Replay)
    );
}

#[test]
fn pipeline_rejects_when_quota_exhausted() {
    let cap = cap_with(2, 1 << 20, 600); // всего 2 запроса за окно
    let mut caps = CapabilityTable::new();
    caps.insert(cap.clone());
    let (kr, ring) = pipeline_env();
    let verifier = MockRingVerifier;
    let pipe = AdmissionPipeline {
        keyring: &kr,
        capabilities: &caps,
        token_verifier: &verifier,
        issuer_ring: &ring,
    };
    let client = b"203.0.113.31:8001";
    let carrier = b"c";
    let cookie = kr.issue(client, carrier, NOW as u32);

    let mut replay = ReplayFilter::new(0, 1024);
    let mut cq = CapabilityQuotaTracker::new();

    // Два разных запроса (свежие nonce) — допущены.
    for i in 0..2u8 {
        let nonce = [b'n', i];
        let proof = cap.prove(&nonce, 0);
        assert_eq!(
            pipe.process(&mk_req(client, carrier, cookie, &nonce, proof), NOW, 0, [0; 64], &mut replay, &mut cq),
            Outcome::Admit
        );
    }
    // Третий свежий запрос — квота исчерпана.
    let proof3 = cap.prove(b"n3", 0);
    assert_eq!(
        pipe.process(&mk_req(client, carrier, cookie, b"n3", proof3), NOW, 0, [0; 64], &mut replay, &mut cq),
        Outcome::Reject(RejectReason::CapabilityQuota)
    );
}

/// A4-6 — each capability must be reaped against ITS OWN window, not one default for all.
///
/// `reap` applied a single caller-supplied window to every capability. A holder whose quota window
/// is LONGER than that default had its spend records dropped early, so the next `consume` saw a
/// nearly empty window and granted more than the quota allows — the limit silently stopped binding.
#[test]
fn reap_uses_each_capabilitys_own_window_not_one_default() {
    let mut t = CapabilityQuotaTracker::new();
    // A capability with a LONG window (1 hour), metered once at NOW.
    let long = Quota { max_requests: 2, max_bytes: 1 << 20, window_secs: 3600 };
    let id = [0xAA; 16];
    assert!(matches!(t.consume(id, &long, [1u8; 16], 10, NOW), QuotaDecision::Ok));

    // A reap run with the SHORT default (600s) must not discard a record that is still inside the
    // capability's own hour-long window.
    t.reap(NOW + 700, 600);

    // The spend is still counted: a second request fits (max_requests = 2), a third does not.
    assert!(matches!(t.consume(id, &long, [2u8; 16], 10, NOW + 700), QuotaDecision::Ok));
    assert!(
        matches!(t.consume(id, &long, [3u8; 16], 10, NOW + 700), QuotaDecision::Exceeded),
        "the early reap must not have erased the spend and handed back extra quota"
    );
}
