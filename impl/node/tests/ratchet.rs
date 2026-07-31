//! §2.1 Double Ratchet — adversarial black-box tests. The load-bearing properties of a ratchet,
//! not a happy path for the sake of it:
//! - a two-way ping-pong with DH steps (both sides advance the ratchet);
//! - **transactionality**: a corrupt packet is rejected AND the next valid one still decrypts (the
//!   session is not wedged — critical for a ratchet);
//! - **out-of-order tolerance** (skipped keys): a gap or a reorder inside a chain and across a
//!   chain boundary is caught up; a replay of a consumed message is rejected;
//! - **header binding**: substituting dh/pn/n in the header is caught by the AEAD AAD.
//!
//! (The discriminating white-box tests for FS non-retention and DH load-bearing PCS live in the
//! `#[cfg(test)]` module of `ratchet` itself, where the private fields are reachable.)

use node::ratchet::{RatchetError, RatchetMessage, Session, SessionSnapshot};
use node::seal::Identity;

/// Establish a session pair from a shared root_key (as PQXDH provides: root_key plus Bob's prekey
/// as his ratchet key). Bob is seeded with his prekey, Alice with its public half.
fn establish() -> (Session, Session) {
    let root = [42u8; 32];
    let bob_prekey = Identity::generate();
    let alice = Session::init_sender(root, bob_prekey.public.to_bytes());
    let bob = Session::init_receiver(root, bob_prekey);
    (alice, bob)
}

#[test]
fn bidirectional_ping_pong_with_dh_ratchet() {
    let (mut alice, mut bob) = establish();

    // Alice → Bob (the first message triggers a DH step at Bob, giving him a send chain).
    let m1 = alice.encrypt(b"hi bob");
    assert_eq!(bob.decrypt(&m1).unwrap(), b"hi bob");

    // Bob → Alice (Bob is on a new ratchet key now; Alice takes a DH step).
    let m2 = bob.encrypt(b"hi alice");
    assert_eq!(alice.decrypt(&m2).unwrap(), b"hi alice");

    // Several in a row within one chain.
    let a1 = alice.encrypt(b"a1");
    let a2 = alice.encrypt(b"a2");
    assert_eq!(bob.decrypt(&a1).unwrap(), b"a1");
    assert_eq!(bob.decrypt(&a2).unwrap(), b"a2");

    // A full direction reversal again.
    let b1 = bob.encrypt(b"b1");
    assert_eq!(alice.decrypt(&b1).unwrap(), b"b1");
}

#[test]
fn distinct_key_per_message() {
    // A basic check (NOT forward secrecy — that is non-retention, in the module tests): every
    // message is encrypted under its own key, so ciphertexts differ for identical plaintext.
    let (mut alice, mut bob) = establish();
    let m1 = alice.encrypt(b"same");
    let m2 = alice.encrypt(b"same");
    assert_ne!(m1.ciphertext, m2.ciphertext, "the chain must give a different key per message");
    assert_eq!(bob.decrypt(&m1).unwrap(), b"same");
    assert_eq!(bob.decrypt(&m2).unwrap(), b"same");
}

#[test]
fn tampered_message_rejected_and_session_survives() {
    // TRANSACTIONALITY — the ratchet-specific "cannot be wedged": a corrupt packet is rejected
    // but does NOT advance or break the chain, so the next valid one still decrypts.
    let (mut alice, mut bob) = establish();

    let good0 = alice.encrypt(b"zero");
    assert_eq!(bob.decrypt(&good0).unwrap(), b"zero");

    let m1 = alice.encrypt(b"one");
    let mut bad = m1.clone();
    bad.ciphertext[0] ^= 0x01;
    assert_eq!(bob.decrypt(&bad), Err(RatchetError::Decrypt), "a corrupt ciphertext is rejected");

    // The session is NOT wedged: the original valid m1 (n=1) still decrypts.
    assert_eq!(bob.decrypt(&m1).unwrap(), b"one", "a corrupt packet must not break the session");
}

#[test]
fn header_tampering_is_caught() {
    // The header is bound in the AAD: substituting the number, pn or dh makes the AEAD fail.
    let (mut alice, mut bob) = establish();
    let m = alice.encrypt(b"payload");

    let mut tn = m.clone();
    tn.header.n ^= 0x01;
    assert!(bob.decrypt(&tn).is_err(), "substituting n in the header must be caught");

    let mut tp = m.clone();
    tp.header.pn ^= 0x01;
    assert!(bob.decrypt(&tp).is_err(), "substituting pn in the header must be caught");

    let mut td = m.clone();
    td.header.dh[0] ^= 0x01;
    assert!(bob.decrypt(&td).is_err(), "substituting the ratchet public key must be caught");

    // The original still passes (transactionality — the refusals did not advance anything).
    assert_eq!(bob.decrypt(&m).unwrap(), b"payload");
}

#[test]
fn out_of_order_within_chain_is_tolerated() {
    // Out of order WITHIN one chain is TOLERATED (skipped keys): the missed number is stored and
    // the late message decrypts. Exactly what a mailbox batch produces. Previously m2 after m0
    // gave OutOfOrder; now it passes.
    let (mut alice, mut bob) = establish();

    let m0 = alice.encrypt(b"m0"); // n=0
    let m1 = alice.encrypt(b"m1"); // n=1 — delivered AFTER m2
    let m2 = alice.encrypt(b"m2"); // n=2

    assert_eq!(bob.decrypt(&m0).unwrap(), b"m0");
    assert_eq!(bob.decrypt(&m2).unwrap(), b"m2", "skipping n=1 stores the key, m2 passes");
    assert_eq!(bob.decrypt(&m1).unwrap(), b"m1", "the late m1 comes from the skipped store");
    // A repeat of an already CONSUMED skipped message is rejected (the key was deleted).
    assert!(bob.decrypt(&m1).is_err(), "a replay of a consumed message is rejected");
}

#[test]
fn reorder_across_ratchet_boundary_is_tolerated() {
    // A gap ACROSS a chain boundary (a mailbox batch or a DTN reorder) is TOLERATED: the tail of
    // chain A is stored during the DH step and decrypts after a message from chain B. It used to
    // be rejected; now it is caught up without loss.
    let (mut alice, mut bob) = establish();

    let m0 = alice.encrypt(b"m0"); // chain A, n=0
    let m1 = alice.encrypt(b"m1"); // chain A, n=1 — delivered AFTER the reversal
    assert_eq!(bob.decrypt(&m0).unwrap(), b"m0"); // bob.nr = 1

    // A direction reversal → Alice takes a DH step on her next send.
    let r0 = bob.encrypt(b"r0");
    assert_eq!(alice.decrypt(&r0).unwrap(), b"r0");

    let m2 = alice.encrypt(b"m2"); // chain B, pn=2 (A had 2), n=0
    assert_eq!(bob.decrypt(&m2).unwrap(), b"m2", "a message from the new chain passes");
    // The late tail of chain A — from what was stored during the DH step.
    assert_eq!(bob.decrypt(&m1).unwrap(), b"m1", "the unreceived tail of A is caught up, not lost");
}

#[test]
fn replay_of_consumed_message_rejected() {
    // A repeat of a message already received IN ORDER: the key was consumed and deleted (it was
    // never a skipped one), so there is nothing to decrypt with → refused. Replay protection.
    let (mut alice, mut bob) = establish();
    let m0 = alice.encrypt(b"m0");
    assert_eq!(bob.decrypt(&m0).unwrap(), b"m0");
    assert!(bob.decrypt(&m0).is_err(), "a repeat of n=0 is rejected (the key was consumed)");
}

#[test]
fn populated_skipped_store_survives_postcard_roundtrip() {
    // The airtight version of the load-bearing test: a skipped key survives THE SAME postcard
    // serialisation the client runs in save_sessions/load_sessions (not only an in-memory
    // snapshot/restore). The late gap filler decrypts after a round trip through bytes.
    // a round trip through bytes.
    let (mut alice, mut bob) = establish();
    let m0 = alice.encrypt(b"m0");
    let m1 = alice.encrypt(b"m1"); // will be delayed → stored in the skipped store
    let m2 = alice.encrypt(b"m2");
    assert_eq!(bob.decrypt(&m0).unwrap(), b"m0");
    assert_eq!(bob.decrypt(&m2).unwrap(), b"m2"); // m1 is in the skipped store

    // A round trip through postcard (as the client's PersistedSession does).
    let bytes = postcard::to_allocvec(&bob.snapshot()).unwrap();
    let snap: SessionSnapshot = postcard::from_bytes(&bytes).unwrap();
    let mut bob2 = Session::restore(snap);

    assert_eq!(bob2.decrypt(&m1).unwrap(), b"m1", "the gap filler came from a store that survived bytes");
}

/// CRYPTO-06 — a small-order ratchet key must be REFUSED, not folded into the DH step. Its
/// shared secret is all-zero, i.e. known to the attacker, so the "healing" step would inject no
/// fresh entropy and silently void post-compromise security. Discriminating on BOTH sides: the
/// poisoned header must be rejected, AND the session must be left untouched (a guard that
/// wedged the session would be its own bug), so the next genuine message still decrypts.
#[test]
fn a_small_order_ratchet_key_is_refused_without_wedging_the_session() {
    let (mut alice, mut bob) = establish();
    let m1 = alice.encrypt(b"one");
    assert_eq!(bob.decrypt(&m1).unwrap(), b"one", "control: normal traffic flows");

    // The identity point is the canonical small-order X25519 key: X25519(x, 0) == 0 for any x.
    let mut poisoned = alice.encrypt(b"two");
    poisoned.header.dh = [0u8; 32];
    assert_eq!(
        bob.decrypt(&poisoned),
        Err(RatchetError::NonContributoryDh),
        "a non-contributory ratchet key must be rejected, not ratcheted on"
    );

    // Session untouched → a later genuine message from the real chain still opens.
    let m3 = alice.encrypt(b"three");
    assert_eq!(bob.decrypt(&m3).unwrap(), b"three", "the rejection must not wedge the session");
}

#[test]
fn cross_message_serialization_roundtrip() {
    // The message survives serialisation (it will go to the wire/mailbox later).
    let (mut alice, mut bob) = establish();
    let m = alice.encrypt(b"over the wire");
    let bytes = postcard::to_allocvec(&m).unwrap();
    let decoded: RatchetMessage = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(bob.decrypt(&decoded).unwrap(), b"over the wire");
}

/// A6-9 — skipped message keys must age out, not merely be capped in number.
///
/// They were bounded by `MAX_STORE` alone, so a key derived for a message that never arrived
/// could sit at rest indefinitely, widening the window in which a device compromise yields
/// plaintext. Age is counted in DH-ratchet GENERATIONS rather than wall-clock, because the local
/// clock is an unauthenticated input and "several chains ago" is the protocol's own measure of
/// staleness. Discriminating: a genuinely late message from the CURRENT era still opens.
#[test]
fn skipped_keys_expire_after_several_ratchet_generations() {
    let (mut alice, mut bob) = establish();

    // Alice sends two; Bob receives only the SECOND, so a gap-filler key is stored.
    let m1 = alice.encrypt(b"gap");
    let m2 = alice.encrypt(b"seen");
    assert_eq!(bob.decrypt(&m2).unwrap(), b"seen");

    // The still-fresh gap-filler works — the expiry must not eat live out-of-order mail.
    let mut bob_fresh = bob.clone();
    assert_eq!(bob_fresh.decrypt(&m1).unwrap(), b"gap", "a recent skipped key must still open");

    // Now run the conversation forward through several DH steps (each reply from Bob and the
    // next message from Alice advances the ratchet).
    for i in 0..6 {
        let r = bob.encrypt(format!("r{i}").as_bytes());
        assert!(alice.decrypt(&r).is_ok());
        let a = alice.encrypt(format!("a{i}").as_bytes());
        assert!(bob.decrypt(&a).is_ok());
    }

    // The ancient gap-filler is gone: it belongs to a chain many generations back.
    assert!(
        bob.decrypt(&m1).is_err(),
        "a skipped key many ratchet generations old must no longer be retained"
    );
}
