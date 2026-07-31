//! Integration of the DTN class (§7.7) into the Ingress pipeline (§7.5/§10).
//!
//! The weight is carried by two tests for the blockers a happy path would not show (both arise
//! because a DTN proof travels through untrusted, observing mesh carriers): (1) the proof is bound
//! to the content, so it cannot be attached to different content; (2) the insert into the rolling
//! window happens only AFTER verification, so a garbage proof cannot block the real capsule.


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

/// Build a valid DTN proof for a specific ciphertext (as an honest sender does: a MAC over
/// H(ciphertext)).
fn proof_for(cap: &DtnCapability, ciphertext: &[u8]) -> DtnCapabilityProof {
    cap.prove(&capsule_hash(ciphertext))
}

/// A wrapper over the pipeline with empty live dependencies (DTN does not use them).
fn run_dtn(
    caps: &DtnCapabilityTable,
    replay: &mut RollingReplayWindow,
    req: &DtnRequest,
) -> Outcome {
    let kr = keyring();
    let live_caps = CapabilityTable::new();
    let ring = IssuerRing { issuer_pubkeys: vec![[1u8; 32]], threshold_t: 1 };
    let verifier = MockRingVerifier::for_tests_only();
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

// ---------- Blocker 1: the proof is bound to the content ----------

#[test]
fn proof_cannot_be_reattached_to_other_content() {
    // An observer in the mesh sees a valid (proof, ct_A) and tries to attach it to different
    // content ct_B. H(ct_B) ≠ H(ct_A) → the MAC does not match → refused.
    let cap = dtn_cap(1 << 20);
    let mut caps = DtnCapabilityTable::new();
    caps.insert(cap.clone());
    let mut replay = RollingReplayWindow::new(8);
    let kr = keyring();

    let ct_a = b"original-capsule";
    let ct_b = b"attacker-substituted-content";
    let stolen_proof = proof_for(&cap, ct_a); // valid for ct_a
    let req = cookied_request(&kr, stolen_proof, ct_b); // attached to ct_b
    assert!(
        matches!(run_dtn(&caps, &mut replay, &req), Outcome::Reject(RejectReason::Dtn(_))),
        "a proof stolen from the mesh must not fit different content"
    );
}

// ---------- Blocker 2: a garbage proof does not block the real capsule ----------

#[test]
fn garbage_proof_does_not_burn_capsule_id() {
    // An attacker who glimpsed the ct in the mesh uploads it FIRST with a garbage proof. Stage 3
    // (a read-only CHECK) does not burn the id, and Stage 4 refuses the garbage before the insert.
    // So the real capsule with a valid proof passes afterwards.
    let cap = dtn_cap(1 << 20);
    let mut caps = DtnCapabilityTable::new();
    caps.insert(cap.clone());
    let mut replay = RollingReplayWindow::new(8);
    let kr = keyring();

    let ct = b"capsule-visible-in-mesh";

    // (1) The attacker: the same ct but a garbage MAC.
    let garbage = DtnCapabilityProof { capability_id: cap.capability_id, mac: [0xFF; 16] };
    let atk_req = cookied_request(&kr, garbage, ct);
    assert!(
        matches!(run_dtn(&caps, &mut replay, &atk_req), Outcome::Reject(RejectReason::Dtn(_))),
        "a garbage proof must be rejected"
    );

    // (2) The real capsule with a valid proof — the id was NOT burned → Admit.
    let real_req = cookied_request(&kr, proof_for(&cap, ct), ct);
    assert_eq!(
        run_dtn(&caps, &mut replay, &real_req),
        Outcome::Admit,
        "the real capsule must not be blocked by a preceding garbage upload"
    );
}

// ---------- Replay of the real capsule ----------

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
    // The same ct a second time (another mesh path brought a copy) → DtnReplay.
    let req2 = cookied_request(&kr, proof_for(&cap, ct), ct);
    assert_eq!(run_dtn(&caps, &mut replay, &req2), Outcome::Reject(RejectReason::DtnReplay));
}

// ---------- max_bytes and expiry ----------

#[test]
fn oversize_capsule_rejected_by_quota() {
    let cap = dtn_cap(8); // a very small quota
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

// ---------- Size: a DTN capsule is NOT bounded by the live MTU ----------

#[test]
fn realistic_large_capsule_admitted_not_mtu_capped() {
    // 50 KB — far beyond the live MTU (1400) but within the DTN ceiling and the quota.
    // This test proves the shared precheck does not impose the live MTU on DTN (otherwise almost
    // every real capsule would be dropped at Stage 0).
    let cap = dtn_cap(1 << 20);
    let mut caps = DtnCapabilityTable::new();
    caps.insert(cap.clone());
    let mut replay = RollingReplayWindow::new(8);
    let kr = keyring();

    let ct = vec![0xAB_u8; 50 * 1024];
    let mut req = cookied_request(&kr, proof_for(&cap, &ct), &ct);
    req.raw_len = ct.len(); // the real upload size
    assert_eq!(run_dtn(&caps, &mut replay, &req), Outcome::Admit);
}

#[test]
fn capsule_over_dtn_ceiling_dropped_before_hashing() {
    // Above the global DTN ceiling → a Drop at Stage 0 (before hashing) — protection against an
    // obviously huge upload.
    let cap = dtn_cap(u64::MAX); // the quota does not bind — the ceiling must fire
    let mut caps = DtnCapabilityTable::new();
    caps.insert(cap.clone());
    let mut replay = RollingReplayWindow::new(8);
    let kr = keyring();

    let ct = vec![0u8; 8]; // the contents do not matter — raw_len is declared huge
    let mut req = cookied_request(&kr, proof_for(&cap, &ct), &ct);
    req.raw_len = MAX_DTN_CAPSULE_SIZE + 1;
    assert!(matches!(
        run_dtn(&caps, &mut replay, &req),
        Outcome::DropNoReply(_)
    ));
}

// ---------- The cookie is kept for the DTN branch ----------

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
        cookie: None, // an online uplink without a cookie
        proof: proof_for(&cap, ct),
        ciphertext: ct,
    };
    assert!(matches!(run_dtn(&caps, &mut replay, &req), Outcome::Challenge(_)));
}
