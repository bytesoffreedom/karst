//! §2.1 PQXDH — adversarial tests of the KEY AGREEMENT. The load-bearing properties:
//! - **agreement**: the initiator and the recipient derive ONE root_key;
//! - **sender authentication**: substituting IK_A gives the recipient a DIFFERENT key (a forger
//!   without Alice's private IK cannot agree the same one);
//! - **the PQ leg is load-bearing**: a corrupt ML-KEM ciphertext → a different pq_shared → a
//!   different root_key;
//! - the layers are orthogonal: a foreign recipient derives a different root_key.
//!
//! What is checked is the DIFFERENCE in root_key (not a decrypt failure): encryption belongs to the
//! ratchet, and pqxdh is only responsible for agreement. A root_key mismatch means the first
//! ratchet message will not decrypt (see the adversarial ratchet tests).
use node::pqxdh::{initiate_key_agreement, Account};
use node::seal::Identity;

#[test]
fn initiator_and_recipient_agree_on_root_key() {
    let mut bob = Account::generate();
    let bundle = bob.prekey_bundle();
    let alice = Identity::generate();

    let (alice_rk, ka) = initiate_key_agreement(&alice, &[7u8; 32], &bundle).expect("well-formed bundle");
    let (bob_rk, sender) = bob.accept_key_agreement(&ka).expect("a valid KEM ciphertext length");
    assert_eq!(alice_rk, bob_rk, "the initiator and recipient must agree one key");
    assert_eq!(sender, alice.public.to_bytes(), "Bob learns the sender from the claimed IK");
}

#[test]
fn cannot_impersonate_alice_without_her_identity_key() {
    // Load-bearing (sender auth): Mallory knows Alice's public key (it is public) but NOT her
    // private IK. Claiming Alice's IK, she does NOT agree the same root_key Bob would have got —
    // DH1 was computed with Mallory's key.
    let mut bob = Account::generate();
    let bundle = bob.prekey_bundle();
    let alice = Identity::generate();
    let mallory = Identity::generate();

    // An honest establishment from Mallory: both sides agree a key, and Bob sees Mallory.
    let (mallory_rk, honest) =
        initiate_key_agreement(&mallory, &[7u8; 32], &bundle).expect("well-formed bundle");
    let (bob_rk, sender) = bob.accept_key_agreement(&honest).unwrap();
    assert_eq!(mallory_rk, bob_rk);
    assert_eq!(sender, mallory.public.to_bytes());

    // The forgery: claim Alice's IK without holding her private key.
    let mut forged = honest.clone();
    forged.ik_a_pub = alice.public.to_bytes();
    let (forged_bob_rk, _) = bob.accept_key_agreement(&forged).unwrap();
    assert_ne!(
        forged_bob_rk, mallory_rk,
        "impersonating Alice is impossible: the recipient's root_key diverges"
    );
}

#[test]
fn corrupt_kem_ciphertext_breaks_agreement() {
    // The PQ leg is load-bearing end to end: corrupting the ML-KEM ciphertext gives the recipient a
    // different pq_shared, so the root_key no longer matches the initiator's.
    let mut bob = Account::generate();
    let bundle = bob.prekey_bundle();
    let alice = Identity::generate();

    let (alice_rk, mut ka) = initiate_key_agreement(&alice, &[7u8; 32], &bundle).expect("well-formed bundle");
    ka.kem_ct[0] ^= 0x01;
    let (bob_rk, _) = bob.accept_key_agreement(&ka).expect("the length is intact, decaps yields a value");
    assert_ne!(alice_rk, bob_rk, "a corrupt KEM ciphertext must break the agreement");
}

#[test]
fn malformed_kem_ciphertext_length_rejected() {
    // Structural protection: a KEM ciphertext of the wrong LENGTH is refused (None), never a panic.
    let mut bob = Account::generate();
    let bundle = bob.prekey_bundle();
    let alice = Identity::generate();

    let (_alice_rk, mut ka) = initiate_key_agreement(&alice, &[7u8; 32], &bundle).expect("well-formed bundle");
    ka.kem_ct.truncate(10);
    assert!(bob.accept_key_agreement(&ka).is_none(), "a KEM ciphertext of the wrong length → None");
}

/// CRYPTO-06 — a bundle advertising a small-order prekey must be REFUSED. X25519 against the
/// identity point yields an all-zero shared secret that the attacker also knows, so folding it
/// in would silently drop a whole DH leg's contribution. Note the bundle SIGNATURE says nothing
/// about a key's order, so this check is the only thing standing between a malicious contact's
/// degenerate key and the agreement.
#[test]
fn a_small_order_prekey_in_a_bundle_is_refused() {
    let mut bob = Account::generate();
    let alice = Identity::generate();

    let good = bob.prekey_bundle();
    assert!(
        initiate_key_agreement(&alice, &[7u8; 32], &good).is_ok(),
        "control: a healthy bundle agrees"
    );

    let mut degenerate = good.clone();
    degenerate.prekey_pub = [0u8; 32];
    assert!(
        initiate_key_agreement(&alice, &[7u8; 32], &degenerate).is_err(),
        "a small-order prekey must be refused"
    );

    // Signed BY ITS OWNER and still small-order: "signed" says nothing about group order, which
    // is exactly why the contributory check is separate from the signature check. Built by hand
    // from a genuine unit with its X25519 half swapped and RE-SIGNED, because a one-time unit now
    // carries a KEM key too (CRYPTO-33) and there is no such unit to look up under a key we never
    // minted.
    let real = bob.add_opk();
    let genuine = bob.signed_opk(&real).expect("just minted");
    let degenerate_opk = node::pqxdh::PreKeyBundle {
        opk: Some(node::pqxdh::SignedOpk {
            key: [0u8; 32],
            sig: bob.sign_opk(&[0u8; 32], &genuine.kem_ek),
            kem_ek: genuine.kem_ek.clone(),
        }),
        ..good.clone()
    };
    assert!(
        initiate_key_agreement(&alice, &[7u8; 32], &degenerate_opk).is_err(),
        "a small-order one-time prekey must be refused too"
    );
}

/// The mirror on the RECIPIENT's side: an initial agreement carrying a small-order ephemeral is
/// refused instead of deriving a root key from an all-zero DH.
#[test]
fn a_small_order_ephemeral_is_refused_on_accept() {
    let mut bob = Account::generate();
    let alice = Identity::generate();
    let (_rk, mut ka) =
        initiate_key_agreement(&alice, &[7u8; 32], &bob.prekey_bundle()).expect("well-formed bundle");
    ka.ek_a_pub = [0u8; 32];
    assert!(
        bob.accept_key_agreement(&ka).is_none(),
        "a non-contributory ephemeral must be refused on accept"
    );
}

#[test]
fn wrong_recipient_derives_different_key() {
    // The agreement is addressed to Bob (his bundle); another account derives a different root_key
    // — neither his prekey/IK nor his ML-KEM key fit.
    let mut bob = Account::generate();
    let mut eve = Account::generate();
    let bundle = bob.prekey_bundle();
    let alice = Identity::generate();

    let (alice_rk, ka) = initiate_key_agreement(&alice, &[7u8; 32], &bundle).expect("well-formed bundle");
    let (bob_rk, _) = bob.accept_key_agreement(&ka).unwrap();
    let (eve_rk, _) = eve.accept_key_agreement(&ka).unwrap();
    assert_eq!(alice_rk, bob_rk, "the addressee agrees the same key");
    assert_ne!(alice_rk, eve_rk, "a foreign recipient derives a different root_key");
}

/// A one-time prekey adds a fourth DH term to the agreement, both sides derive the same
/// root key with it, and the recipient CONSUMES it — a second agreement reusing the same
/// OPK fails. This is the forward-secrecy mechanism: the OPK secret is gone after one use.
#[test]
fn a_one_time_prekey_is_mixed_in_and_consumed_once() {
    let alice = node::seal::Identity::generate();
    let mut bob = Account::generate();

    // Bob mints a one-time prekey and publishes a bundle carrying it.
    let opk = bob.add_opk();
    assert_eq!(bob.opk_count(), 1);
    let bundle = bob.prekey_bundle_with_opk(opk);

    // Alice initiates against the OPK bundle; the KA records which OPK she used.
    let (alice_rk, ka) = initiate_key_agreement(&alice, &[7u8; 32], &bundle).expect("well-formed bundle");
    assert_eq!(ka.opk_pub, Some(opk), "the KA must name the OPK the sender used");

    // The root key differs from the SAME agreement without the OPK — proof the 4th DH is
    // load-bearing, not decorative.
    let (alice_rk_no_opk, _) =
        initiate_key_agreement(&alice, &[7u8; 32], &bob.prekey_bundle()).expect("well-formed bundle");
    assert_ne!(alice_rk, alice_rk_no_opk, "the one-time prekey did not affect the root key");

    // Bob accepts, derives the same key, and consumes the OPK.
    let (bob_rk, sender) = bob.accept_key_agreement(&ka).expect("agreement with OPK");
    assert_eq!(alice_rk, bob_rk, "sender and recipient disagree on the OPK root key");
    assert_eq!(sender, alice.public.to_bytes());
    assert_eq!(bob.opk_count(), 0, "the one-time prekey was not consumed");

    // Replaying the SAME KA (same OPK) must now FAIL — the OPK is gone, so it is truly
    // one-time. Neuter the `self.opks.remove(...)` consumption and this reddens.
    assert!(bob.accept_key_agreement(&ka).is_none(), "a consumed one-time prekey was reused");
}
