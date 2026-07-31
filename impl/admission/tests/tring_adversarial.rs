//! Adversarial tests for the §7.3 threshold ring signature (tring).
//!
//! The whole file sits behind the `unaudited-crypto` feature flag. These are the tests that carry
//! the weight: a happy path over security crypto proves nothing — what proves something is what
//! MUST fail and does. Run with:
//!   cargo test --features unaudited-crypto --test tring_adversarial
#![cfg(feature = "unaudited-crypto")]

use admission::tring::{sign, verify, IssuerKeypair, ThresholdRingSig};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// A deterministic issuer secret from a seed (for reproducible tests).
fn keypair(seed: &[u8]) -> IssuerKeypair {
    let mut h = Sha512::new();
    h.update(b"tring-test-key");
    h.update(seed);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    IssuerKeypair::from_secret(Scalar::from_bytes_mod_order_wide(&wide))
}

/// A ring of N issuers plus their secrets by index.
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

fn signers(secs: &[Scalar], idxs: &[usize]) -> Vec<(usize, Scalar)> {
    idxs.iter().map(|&i| (i, secs[i])).collect()
}

// ---------- Basic correctness (the necessary minimum, not a proof) ----------

#[test]
fn valid_t_of_n_verifies() {
    let (ring, secs) = make_ring(5);
    let sig = sign(b"admission-token-nonce", &ring, 2, &signers(&secs, &[1, 3])).unwrap();
    assert!(verify(b"admission-token-nonce", &ring, 2, &sig));
}

// ---------- The direction of the inequality: ≥ t, not = t ----------

#[test]
fn more_than_t_signers_still_verifies_under_t_policy() {
    // Three signers under a policy of t=2 — stronger than required, and it MUST pass.
    let (ring, secs) = make_ring(5);
    let sig = sign(b"m", &ring, 2, &signers(&secs, &[0, 2, 4])).unwrap();
    assert!(verify(b"m", &ring, 2, &sig), "t+1 signers must satisfy a policy of t");
}

#[test]
fn fewer_than_t_signers_fails_under_t_policy() {
    // NOTE: this tests POLICY enforcement on an HONESTLY built signature, NOT unforgeability. It
    // shows that a legitimate t=1 signature does not count under a policy of t=2 (the polynomial
    // degree n−1 > n−2). Resistance to forgery by a malicious sub-threshold signer rests on the
    // CDS soundness theorem plus Fiat–Shamir (ROM) and is not checked by a unit test — do not
    // confuse the two (see the tring module docs).

    let (ring, secs) = make_ring(5);
    let sig_t1 = sign(b"m", &ring, 1, &signers(&secs, &[3])).unwrap();
    assert!(verify(b"m", &ring, 1, &sig_t1), "sanity: a t=1 signature is valid under t=1");
    assert!(
        !verify(b"m", &ring, 2, &sig_t1),
        "a single-signer signature must NOT satisfy a policy of two or more"
    );
}

#[test]
fn cannot_sign_below_threshold() {
    // The API does not let a signature be built with fewer than t secrets.
    let (ring, secs) = make_ring(5);
    assert!(sign(b"m", &ring, 3, &signers(&secs, &[0, 1])).is_err());
}

// ---------- Forgery: any distortion of the signature breaks verification ----------

#[test]
fn tampering_any_challenge_fails() {
    let (ring, secs) = make_ring(5);
    let mut sig = sign(b"m", &ring, 2, &signers(&secs, &[1, 4])).unwrap();
    sig.challenges[0] += Scalar::ONE;
    assert!(!verify(b"m", &ring, 2, &sig));
}

#[test]
fn tampering_any_response_fails() {
    let (ring, secs) = make_ring(5);
    let mut sig = sign(b"m", &ring, 2, &signers(&secs, &[1, 4])).unwrap();
    sig.responses[2] += Scalar::ONE;
    assert!(!verify(b"m", &ring, 2, &sig));
}

#[test]
fn all_zero_signature_fails() {
    let (ring, _secs) = make_ring(5);
    let sig = ThresholdRingSig {
        challenges: vec![Scalar::ZERO; 5],
        responses: vec![Scalar::ZERO; 5],
    };
    assert!(!verify(b"m", &ring, 2, &sig));
}

// ---------- Strong Fiat–Shamir: binding to the message, the ring and the threshold ----------

#[test]
fn wrong_message_fails() {
    let (ring, secs) = make_ring(5);
    let sig = sign(b"message-A", &ring, 2, &signers(&secs, &[0, 1])).unwrap();
    assert!(!verify(b"message-B", &ring, 2, &sig), "the signature is not bound to the message");
}

#[test]
fn reordered_ring_fails() {
    let (mut ring, secs) = make_ring(5);
    let sig = sign(b"m", &ring, 2, &signers(&secs, &[0, 1])).unwrap();
    ring.swap(0, 4); // the same key set, a different order
    assert!(!verify(b"m", &ring, 2, &sig), "the signature is not bound to the ring order");
}

#[test]
fn different_ring_member_fails() {
    let (mut ring, secs) = make_ring(5);
    let sig = sign(b"m", &ring, 2, &signers(&secs, &[0, 1])).unwrap();
    ring[2] = keypair(b"outsider").public; // substituting one ring member
    assert!(!verify(b"m", &ring, 2, &sig));
}

#[test]
fn threshold_in_hash_binds_policy() {
    // A signature made under t=2 is verified against a hash that t enters, so verifying under a
    // different t computes a different master challenge. (Separately from the degree check — this
    // is specifically about t being bound into Fiat–Shamir.)
    let (ring, secs) = make_ring(5);
    let sig = sign(b"m", &ring, 2, &signers(&secs, &[0, 1, 2])).unwrap();
    // Under t=2 it passes; under t=1 (a different master challenge) it does not, even though
    // "3 signers ≥ 1" by count. That is what catches the binding of t.
    assert!(verify(b"m", &ring, 2, &sig));
    assert!(!verify(b"m", &ring, 1, &sig));
}

// ---------- Unlinkability / anonymity (NECESSARY, not sufficient) ----------
// Full anonymity rests on a simulation (HVZK) argument — a proof, not an assertEq. The tests below
// check only the necessary symptoms; their names are honest and do not claim "proven anonymous".


#[test]
fn signatures_are_format_identical_across_signer_sets() {
    // An observer must not be able to tell signer sets apart by the shape of the signature.
    let (ring, secs) = make_ring(5);
    let a = sign(b"m", &ring, 2, &signers(&secs, &[0, 1])).unwrap();
    let b = sign(b"m", &ring, 2, &signers(&secs, &[2, 4])).unwrap();
    assert_eq!(a.challenges.len(), b.challenges.len());
    assert_eq!(a.responses.len(), b.responses.len());
    // Different sets give different signatures (otherwise the set would leak through equality).
    assert_ne!(a, b);
    assert!(verify(b"m", &ring, 2, &a) && verify(b"m", &ring, 2, &b));
}

#[test]
fn deterministic_repro_but_ring_rebinds_nonce() {
    // (1) The same input gives the same signature: no two different challenges under the same k,
    //     which is the secret-leak class (two shares, RLN §7.4).
    let (ring, secs) = make_ring(5);
    let s1 = sign(b"m", &ring, 2, &signers(&secs, &[0, 1])).unwrap();
    let s2 = sign(b"m", &ring, 2, &signers(&secs, &[0, 1])).unwrap();
    assert_eq!(s1, s2, "deterministic reproducibility is broken");

    // (2) The same signer and message but a DIFFERENT ring → the signer's response changes (the
    //     nonce is bound to the ring) rather than staying at the same k.
    let (mut ring2, secs2) = make_ring(5);
    ring2[4] = keypair(b"different-5th").public;
    let mut secs2b = secs2.clone();
    secs2b[4] = keypair(b"different-5th").secret;
    let s3 = sign(b"m", &ring2, 2, &signers(&secs2b, &[0, 1])).unwrap();
    // Signer 0's response must not match the one from s1 (otherwise k was not rebound to the
    // ring).
    assert_ne!(s1.responses[0], s3.responses[0], "the nonce was not rebound to the ring");

    // (3) The same ring and message but a DIFFERENT signer set ([0,1] vs [0,2]). A more direct
    //     same-k-different-c case: signer 0's response must change (the nonce is bound to the
    //     composition through sim_seed), otherwise the same k with a different c_0 would leak the
    //     secret x_0.
    let s4 = sign(b"m", &ring, 2, &signers(&secs, &[0, 2])).unwrap();
    assert_ne!(
        s1.responses[0], s4.responses[0],
        "the nonce was not rebound to the signer set (the leak class above)"
    );
}

// ---------- Threshold edge values ----------

#[test]
fn threshold_one_is_plain_ring_signature() {
    let (ring, secs) = make_ring(4);
    let sig = sign(b"m", &ring, 1, &signers(&secs, &[2])).unwrap();
    assert!(verify(b"m", &ring, 1, &sig));
}

#[test]
fn threshold_equals_n_requires_all() {
    let (ring, secs) = make_ring(4);
    let all = sign(b"m", &ring, 4, &signers(&secs, &[0, 1, 2, 3])).unwrap();
    assert!(verify(b"m", &ring, 4, &all));
    // Three signers cannot satisfy t=N=4.
    let three = sign(b"m", &ring, 3, &signers(&secs, &[0, 1, 2])).unwrap();
    assert!(!verify(b"m", &ring, 4, &three));
}
