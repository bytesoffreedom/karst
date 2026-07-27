//! §7 slice 4a — stateless PoW-capability verification (the Public door's crypto core).
//!
//! A PoW capability is NOT stored: the relay recomputes its secret from the issuer key on
//! every verify. These pin the properties that makes that safe — the secret binds `not_after`
//! and `scope` (so neither can be forged in the proof), expiry is enforced, and without an
//! issuer key an unknown id is simply rejected (Private/Dev never take this path).

use admission::capability::{
    pow_cap_id, pow_cap_secret, Capability, CapabilityError, CapabilityTable, Scope, POW_CAP_QUOTA,
};

const ISSUER: [u8; 32] = [9u8; 32];
const RELAY_ID: [u8; 32] = [3u8; 32];

/// Mint a PoW capability exactly as `RelayNode::handle_join` does, from the issuer key.
fn mint(not_after: u32) -> Capability {
    let cap_id = pow_cap_id(&ISSUER, &RELAY_ID, 42, &[1u8; 32], 7);
    let secret = pow_cap_secret(&ISSUER, &cap_id, not_after, Scope::MessageDelivery);
    Capability {
        capability_id: cap_id,
        scope: Scope::MessageDelivery,
        quota: POW_CAP_QUOTA,
        not_before: 0,
        not_after,
        secret,
    }
}

#[test]
fn stateless_verify_accepts_a_genuinely_issued_cap() {
    let mut table = CapabilityTable::new();
    table.set_pow_issuer(ISSUER);
    let cap = mint(2_000_000);
    let proof = cap.prove(b"nonce", 0);
    let v = table
        .verify(&proof, b"nonce", Scope::MessageDelivery, 1_000_000)
        .expect("a genuinely issued cap must verify with no stored record");
    assert_eq!(v.capability_id, cap.capability_id);
}

#[test]
fn a_forged_not_after_is_refused() {
    // `not_after` is bound into the secret, so a client that EXTENDS its expiry in the proof
    // makes the relay recompute a DIFFERENT secret — and its MAC (made with the real secret)
    // no longer verifies. Neuter the binding (drop `not_after` from `pow_cap_secret`) and
    // this reddens: a forged, immortal capability would then verify.
    let mut table = CapabilityTable::new();
    table.set_pow_issuer(ISSUER);
    let cap = mint(2_000_000);
    let mut proof = cap.prove(b"nonce", 0);
    proof.not_after = u32::MAX; // forge a far-later expiry
    let e = table.verify(&proof, b"nonce", Scope::MessageDelivery, 1_000_000).unwrap_err();
    assert_eq!(e, CapabilityError::BadMac, "a forged not_after must not verify");
}

#[test]
fn scope_is_bound_into_the_secret() {
    // The secret binds scope, so a MessageDelivery capability cannot be repurposed under a
    // different scope: the recomputed secret differs → BadMac.
    let mut table = CapabilityTable::new();
    table.set_pow_issuer(ISSUER);
    let cap = mint(2_000_000);
    let proof = cap.prove(b"nonce", 0);
    let e = table.verify(&proof, b"nonce", Scope::MailboxFetch, 1_000_000).unwrap_err();
    assert_eq!(e, CapabilityError::BadMac);
}

#[test]
fn an_expired_pow_cap_is_refused() {
    let mut table = CapabilityTable::new();
    table.set_pow_issuer(ISSUER);
    let cap = mint(1_000); // not_after = 1000
    let proof = cap.prove(b"nonce", 0);
    let e = table.verify(&proof, b"nonce", Scope::MessageDelivery, 2_000).unwrap_err(); // now > not_after
    assert_eq!(e, CapabilityError::Expired);
}

#[test]
fn without_a_pow_issuer_an_unknown_id_is_rejected() {
    // A Private/Dev relay never calls `set_pow_issuer`, so the stateless path is off and a
    // forged PoW capability is just an unknown id — the door does not exist there.
    let table = CapabilityTable::new();
    let cap = mint(2_000_000);
    let proof = cap.prove(b"nonce", 0);
    let e = table.verify(&proof, b"nonce", Scope::MessageDelivery, 1_000_000).unwrap_err();
    assert_eq!(e, CapabilityError::UnknownCapability);
}
