//! Интеграция DTN-класса (§7.7) в Ingress-конвейер (§7.5/§10).
//!
//! Вес несут два теста по блокерам, которые happy-path не показал бы (оба —
//! из-за того, что DTN-proof едет через недоверенных наблюдающих mesh-
//! носителей): (1) proof привязан к содержимому — нельзя прицепить к другому
//! контенту; (2) вставка в rolling-window только ПОСЛЕ верификации — мусорный
//! proof не блокирует настоящую capsule.

use admission::capability::CapabilityTable;
use admission::cookie::CookieKeyring;
use admission::dtn::{
    DtnCapability, DtnCapabilityProof, DtnCapabilityTable, DtnQuota, RollingReplayWindow,
    MAX_DTN_CAPSULE_SIZE, MAX_DTN_TRANSIT_TTL_SECS,
};
use admission::params::EPOCH_DURATION_SECS;
use admission::pipeline::{
    capsule_hash, AdmissionPipeline, DtnRequest, Outcome, RejectReason,
};
use admission::token::{IssuerRing, MockRingVerifier};

const NOW: u64 = 1_000_000;

fn keyring() -> CookieKeyring {
    CookieKeyring::new(EPOCH_DURATION_SECS, NOW, [0x11; 32], [0x22; 32])
}

fn dtn_cap(max_bytes: u64) -> DtnCapability {
    DtnCapability {
        capability_id: [0xD7; 16],
        issued_at: NOW,
        not_after: NOW + MAX_DTN_TRANSIT_TTL_SECS,
        quota: DtnQuota { max_bytes, max_hops: 16 },
        secret: [0x5A; 32],
    }
}

/// Собрать валидный DTN-proof для конкретного ciphertext (как это делает
/// добросовестный отправитель: MAC над H(ciphertext)).
fn proof_for(cap: &DtnCapability, ciphertext: &[u8]) -> DtnCapabilityProof {
    cap.prove(&capsule_hash(ciphertext))
}

/// Обёртка над pipeline с пустыми live-зависимостями (DTN их не использует).
fn run_dtn(
    caps: &DtnCapabilityTable,
    replay: &mut RollingReplayWindow,
    req: &DtnRequest,
) -> Outcome {
    let kr = keyring();
    let live_caps = CapabilityTable::new();
    let ring = IssuerRing { issuer_pubkeys: vec![[1u8; 32]], threshold_t: 1 };
    let verifier = MockRingVerifier;
    let pipe = AdmissionPipeline {
        keyring: &kr,
        capabilities: &live_caps,
        token_verifier: &verifier,
        issuer_ring: &ring,
    };
    pipe.process_dtn(req, caps, replay, NOW, [0x42; 64])
}

fn cookied_request<'a>(
    kr: &CookieKeyring,
    proof: DtnCapabilityProof,
    ciphertext: &'a [u8],
) -> DtnRequest<'a> {
    let client = b"203.0.113.9:6000";
    let carrier = b"c";
    let cookie = kr.issue(client, carrier, NOW as u32);
    DtnRequest {
        raw_len: 400,
        client_addr: client,
        carrier_id: carrier,
        cookie: Some(cookie),
        proof,
        ciphertext,
    }
}

// ---------- Happy path ----------

#[test]
fn valid_dtn_capsule_admitted() {
    let cap = dtn_cap(1 << 20);
    let mut caps = DtnCapabilityTable::new();
    caps.insert(cap.clone());
    let mut replay = RollingReplayWindow::new(8);
    let kr = keyring();

    let ct = b"encrypted-capsule-content";
    let req = cookied_request(&kr, proof_for(&cap, ct), ct);
    assert_eq!(run_dtn(&caps, &mut replay, &req), Outcome::Admit);
}

// ---------- Блокер 1: привязка proof к содержимому ----------

#[test]
fn proof_cannot_be_reattached_to_other_content() {
    // Наблюдатель в mesh видит валидный (proof, ct_A). Пытается прицепить его к
    // другому контенту ct_B. H(ct_B) ≠ H(ct_A) → MAC не сойдётся → отказ.
    let cap = dtn_cap(1 << 20);
    let mut caps = DtnCapabilityTable::new();
    caps.insert(cap.clone());
    let mut replay = RollingReplayWindow::new(8);
    let kr = keyring();

    let ct_a = b"original-capsule";
    let ct_b = b"attacker-substituted-content";
    let stolen_proof = proof_for(&cap, ct_a); // валиден для ct_a
    let req = cookied_request(&kr, stolen_proof, ct_b); // прицеплен к ct_b
    assert!(
        matches!(run_dtn(&caps, &mut replay, &req), Outcome::Reject(RejectReason::Dtn(_))),
        "proof, украденный из mesh, не должен подойти к другому содержимому"
    );
}

// ---------- Блокер 2: мусорный proof не блокирует настоящую capsule ----------

#[test]
fn garbage_proof_does_not_burn_capsule_id() {
    // Атакующий, подсмотревший ct в mesh, заливает его ПЕРВЫМ с мусорным proof.
    // Ступень 3 (read-only CHECK) не сжигает id, Ступень 4 отвергает мусор без
    // insert. Значит настоящая capsule с валидным proof потом проходит.
    let cap = dtn_cap(1 << 20);
    let mut caps = DtnCapabilityTable::new();
    caps.insert(cap.clone());
    let mut replay = RollingReplayWindow::new(8);
    let kr = keyring();

    let ct = b"capsule-visible-in-mesh";

    // (1) Атакующий: тот же ct, но мусорный MAC.
    let garbage = DtnCapabilityProof { capability_id: cap.capability_id, mac: [0xFF; 16] };
    let atk_req = cookied_request(&kr, garbage, ct);
    assert!(
        matches!(run_dtn(&caps, &mut replay, &atk_req), Outcome::Reject(RejectReason::Dtn(_))),
        "мусорный proof должен быть отвергнут"
    );

    // (2) Настоящая capsule с валидным proof — id НЕ был сожжён → Admit.
    let real_req = cookied_request(&kr, proof_for(&cap, ct), ct);
    assert_eq!(
        run_dtn(&caps, &mut replay, &real_req),
        Outcome::Admit,
        "настоящая capsule не должна быть заблокирована предшествующим мусором"
    );
}

// ---------- Replay настоящей capsule ----------

#[test]
fn genuine_replay_rejected() {
    let cap = dtn_cap(1 << 20);
    let mut caps = DtnCapabilityTable::new();
    caps.insert(cap.clone());
    let mut replay = RollingReplayWindow::new(8);
    let kr = keyring();
    let ct = b"capsule-once";

    let req1 = cookied_request(&kr, proof_for(&cap, ct), ct);
    assert_eq!(run_dtn(&caps, &mut replay, &req1), Outcome::Admit);
    // Тот же ct во второй раз (напр. другой mesh-путь принёс копию) → replay.
    let req2 = cookied_request(&kr, proof_for(&cap, ct), ct);
    assert_eq!(run_dtn(&caps, &mut replay, &req2), Outcome::Reject(RejectReason::DtnReplay));
}

// ---------- max_bytes и срок ----------

#[test]
fn oversize_capsule_rejected_by_quota() {
    let cap = dtn_cap(8); // очень маленькая квота
    let mut caps = DtnCapabilityTable::new();
    caps.insert(cap.clone());
    let mut replay = RollingReplayWindow::new(8);
    let kr = keyring();
    let ct = b"this-content-is-way-over-8-bytes";
    let req = cookied_request(&kr, proof_for(&cap, ct), ct);
    assert!(matches!(
        run_dtn(&caps, &mut replay, &req),
        Outcome::Reject(RejectReason::Dtn(_))
    ));
}

// ---------- Размер: DTN-капсула НЕ ограничена live-MTU ----------

#[test]
fn realistic_large_capsule_admitted_not_mtu_capped() {
    // 50 КБ — далеко за live-MTU (1400), но в пределах DTN-потолка и квоты.
    // Этот тест — доказательство, что общий precheck не навязывает DTN
    // live-MTU (иначе почти любая настоящая capsule дропалась бы на Ступени 0).
    let cap = dtn_cap(1 << 20);
    let mut caps = DtnCapabilityTable::new();
    caps.insert(cap.clone());
    let mut replay = RollingReplayWindow::new(8);
    let kr = keyring();

    let ct = vec![0xAB_u8; 50 * 1024];
    let mut req = cookied_request(&kr, proof_for(&cap, &ct), &ct);
    req.raw_len = ct.len(); // реальный размер загрузки
    assert_eq!(run_dtn(&caps, &mut replay, &req), Outcome::Admit);
}

#[test]
fn capsule_over_dtn_ceiling_dropped_before_hashing() {
    // Свыше глобального DTN-потолка → Drop на Ступени 0 (до хеширования),
    // защита от заведомо огромной загрузки.
    let cap = dtn_cap(u64::MAX); // квота не ограничивает — сработать должен потолок
    let mut caps = DtnCapabilityTable::new();
    caps.insert(cap.clone());
    let mut replay = RollingReplayWindow::new(8);
    let kr = keyring();

    let ct = vec![0u8; 8]; // содержимое неважно — raw_len заявлен огромным
    let mut req = cookied_request(&kr, proof_for(&cap, &ct), &ct);
    req.raw_len = MAX_DTN_CAPSULE_SIZE + 1;
    assert!(matches!(
        run_dtn(&caps, &mut replay, &req),
        Outcome::DropNoReply(_)
    ));
}

// ---------- Cookie сохраняется для DTN-ветки ----------

#[test]
fn dtn_without_cookie_gets_challenge() {
    let cap = dtn_cap(1 << 20);
    let mut caps = DtnCapabilityTable::new();
    caps.insert(cap.clone());
    let mut replay = RollingReplayWindow::new(8);
    let ct = b"content";
    let req = DtnRequest {
        raw_len: 400,
        client_addr: b"203.0.113.9:6000",
        carrier_id: b"c",
        cookie: None, // онлайн-аплинк без cookie
        proof: proof_for(&cap, ct),
        ciphertext: ct,
    };
    assert!(matches!(run_dtn(&caps, &mut replay, &req), Outcome::Challenge(_)));
}
