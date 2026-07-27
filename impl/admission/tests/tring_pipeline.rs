//! Композиция §7.3 ↔ §7.5: настоящая пороговая кольцевая подпись, проходящая
//! через полный staged-конвейер допуска. Это и есть та проверка, ради которой
//! реализация вообще затевалась — что примитивы КОМПОНУЮТСЯ на реальной
//! крипте, а не только по отдельности «звучат согласованно».
//!
//! Запуск: cargo test --features unaudited-crypto --test tring_pipeline
#![cfg(feature = "unaudited-crypto")]

use admission::capability::{CapabilityTable, Scope};
use admission::cookie::CookieKeyring;
use admission::params::EPOCH_DURATION_SECS;
use admission::pipeline::{AdmissionPipeline, Credential, Outcome, ReplayFilter, RejectReason};
use admission::token::{AdmissionToken, IssuerRing, RealRingVerifier};
use admission::tring::{sign, IssuerKeypair, ThresholdRingSig};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

fn keypair(seed: &[u8]) -> IssuerKeypair {
    let mut h = Sha512::new();
    h.update(b"pipe-key");
    h.update(seed);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    IssuerKeypair::from_secret(Scalar::from_bytes_mod_order_wide(&wide))
}

fn make_ring(n: usize) -> (Vec<RistrettoPoint>, Vec<Scalar>) {
    let mut pubs = Vec::new();
    let mut secs = Vec::new();
    for i in 0..n {
        let kp = keypair(&[i as u8]);
        pubs.push(kp.public);
        secs.push(kp.secret);
    }
    (pubs, secs)
}

/// Построить AdmissionToken с настоящей пороговой кольцевой подписью над
/// nonce токена.
fn issue_token(
    token_nonce: [u8; 32],
    epoch: u32,
    ring: &[RistrettoPoint],
    t: usize,
    secs: &[Scalar],
    signer_idxs: &[usize],
) -> AdmissionToken {
    let signers: Vec<(usize, Scalar)> = signer_idxs.iter().map(|&i| (i, secs[i])).collect();
    let sig: ThresholdRingSig = sign(&token_nonce, ring, t, &signers).unwrap();
    AdmissionToken {
        ring_sig: sig.to_bytes(),
        t: token_nonce,
        epoch_id: epoch,
    }
}

fn issuer_ring(ring: &[RistrettoPoint], t: usize) -> IssuerRing {
    IssuerRing {
        issuer_pubkeys: ring.iter().map(|p| p.compress().to_bytes()).collect(),
        threshold_t: t,
    }
}

#[test]
fn real_threshold_token_admitted_through_pipeline() {
    let now = 1_000_000u64;
    let keyring = CookieKeyring::new(EPOCH_DURATION_SECS, now, [0x11; 32], [0x22; 32]);
    let caps = CapabilityTable::new();
    let (ring, secs) = make_ring(5);
    let iring = issuer_ring(&ring, 2); // политика «2 из 5»
    let verifier = RealRingVerifier;
    let pipe = AdmissionPipeline {
        keyring: &keyring,
        capabilities: &caps,
        token_verifier: &verifier,
        issuer_ring: &iring,
    };

    let client = b"203.0.113.7:5000";
    let carrier = b"c";
    let cookie = keyring.issue(client, carrier, now as u32);

    // Токен, подписанный настоящими 2 из 5 issuer'ами.
    let token = issue_token([0x33; 32], 0, &ring, 2, &secs, &[1, 3]);

    let mut replay = ReplayFilter::new(0, 1024);
    let req = admission::pipeline::Request {
        raw_len: 400,
        client_addr: client,
        carrier_id: carrier,
        cookie: Some(cookie),
        request_nonce: b"n",
        requested_scope: Scope::MessageDelivery,
        credential: Credential::Token(token),
    };
    assert_eq!(
        pipe.process(&req, now, 0, [0; 64], &mut replay, &mut admission::capability::CapabilityQuotaTracker::new()),
        Outcome::Admit,
        "валидный '2 из 5' токен должен пройти весь конвейер"
    );
}

#[test]
fn real_below_threshold_token_rejected_through_pipeline() {
    let now = 1_000_000u64;
    let keyring = CookieKeyring::new(EPOCH_DURATION_SECS, now, [0x11; 32], [0x22; 32]);
    let caps = CapabilityTable::new();
    let (ring, secs) = make_ring(5);
    let iring = issuer_ring(&ring, 2); // политика требует 2
    let verifier = RealRingVerifier;
    let pipe = AdmissionPipeline {
        keyring: &keyring,
        capabilities: &caps,
        token_verifier: &verifier,
        issuer_ring: &iring,
    };

    let client = b"203.0.113.8:5000";
    let carrier = b"c";
    let cookie = keyring.issue(client, carrier, now as u32);

    // Токен, подписанный лишь 1 issuer'ом (t=1) — не удовлетворяет политике 2.
    let token = issue_token([0x44; 32], 0, &ring, 1, &secs, &[2]);

    let mut replay = ReplayFilter::new(0, 1024);
    let req = admission::pipeline::Request {
        raw_len: 400,
        client_addr: client,
        carrier_id: carrier,
        cookie: Some(cookie),
        request_nonce: b"n",
        requested_scope: Scope::MessageDelivery,
        credential: Credential::Token(token),
    };
    assert!(
        matches!(
            pipe.process(&req, now, 0, [0; 64], &mut replay, &mut admission::capability::CapabilityQuotaTracker::new()),
            Outcome::Reject(RejectReason::Token(_))
        ),
        "токен ниже порога должен быть отвергнут конвейером"
    );
}
