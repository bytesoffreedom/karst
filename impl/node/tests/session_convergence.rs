//! A6-1: simultaneous first contact used to leave two independent one-way ratchet chains
//! (see `peer::Peer::inbound_sessions`'s doc) that never converged — each side kept sending on
//! its OWN outbound and receiving the peer's on a separate one, so a reply never reached the
//! chain it was meant to heal and `Session::dh_ratchet` never fired across the pair. The only
//! cure used to be `forget_peer` + a fresh handshake.
//!
//! These tests simulate a GENUINE simultaneous first contact — both sides `connect_with_bundle`
//! before either has processed the other's opener — end to end (full PQXDH + relay). They prove
//! (1) both sides converge onto the SAME session with no wire message, and (2) delivery keeps
//! working across the convergence swap (no message goes missing). What they do NOT — and, by
//! construction, CANNOT — discriminate: whether the routing snapshot specifically prevents
//! misdelivery, or whether the ratchet keeps healing round after round. Both of those are
//! masked here by the same two mechanisms (dual-map trial-decrypt; `receive()` draining the
//! identity mailbox before polling boxes in one call) and are pinned instead, directly, in
//! `node/src/peer.rs`'s `convergence_route_tests` module — see each test's doc comment below for
//! exactly which unit test to look at.

use std::cell::RefCell;
use std::rc::Rc;

use admission::capability::{Capability, Quota, Scope};
use node::node::{InMemoryTransport, RelayNode, Response};
use node::peer::Peer;
use node::pqxdh::Account;
use x25519_dalek::PublicKey;

const NOW: u64 = 1_000_000;

fn dev_cap() -> Capability {
    Capability {
        capability_id: [0xCA; 16],
        scope: Scope::MessageDelivery,
        quota: Quota { max_requests: 100, max_bytes: 1 << 20, window_secs: 600 },
        not_before: 0,
        not_after: u32::MAX,
        secret: [0x33; 32],
    }
}

fn shared() -> (InMemoryTransport, PublicKey) {
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(dev_cap());
    let relay_pub = relay.relay_public();
    (InMemoryTransport::new(Rc::new(RefCell::new(relay))), relay_pub)
}

fn peer(transport: &InMemoryTransport, relay_pub: PublicKey) -> Peer<InMemoryTransport> {
    Peer::new(transport.clone(), Account::generate(), dev_cap(), relay_pub)
}

fn plaintexts(v: Vec<Option<node::peer::Received>>) -> Vec<Vec<u8>> {
    v.into_iter().flatten().map(|r| r.plaintext).collect()
}

/// Set up a GENUINE simultaneous first contact: both sides PQXDH-initiate to each other
/// BEFORE either has seen the other's opener. This is the exact precondition of the split —
/// each ends up with its OWN outbound session (`sessions[peer]`) plus, once each processes the
/// other's opener, a SEPARATE session for the peer's stream (`inbound_sessions[peer]`).
fn simultaneous_first_contact() -> (Peer<InMemoryTransport>, Peer<InMemoryTransport>, [u8; 32], [u8; 32]) {
    let (transport, relay_pub) = shared();
    let mut alice = peer(&transport, relay_pub);
    let mut bob = peer(&transport, relay_pub);
    let (alice_ik, bob_ik) = (alice.identity(), bob.identity());
    alice.connect_with_bundle(&bob.bundle()).expect("alice initiates to bob");
    bob.connect_with_bundle(&alice.bundle()).expect("bob initiates to alice, before receiving alice's");
    (alice, bob, alice_ik, bob_ik)
}

#[test]
fn simultaneous_first_contact_converges_both_sides_onto_the_same_session() {
    let (mut alice, mut bob, alice_ik, bob_ik) = simultaneous_first_contact();

    assert!(matches!(alice.send(&bob_ik, b"hi from alice", NOW), Response::Accepted));
    assert!(matches!(bob.send(&alice_ik, b"hi from bob", NOW), Response::Accepted));

    // Each side receives the OTHER's opener. This is where `process_opener` finds it already
    // holds an outbound session for this peer, routes the new one into `inbound_sessions`, and
    // (per the fix) runs `converge_split_session` right there.
    assert_eq!(plaintexts(bob.receive(NOW).unwrap()), vec![b"hi from alice".to_vec()]);
    assert_eq!(plaintexts(alice.receive(NOW).unwrap()), vec![b"hi from bob".to_vec()]);

    let (alice_out, alice_in) = alice.export_state().debug_peers();
    let (bob_out, bob_in) = bob.export_state().debug_peers();
    assert_eq!(alice_out.len(), 1, "alice holds exactly one outbound session with bob");
    assert_eq!(bob_out.len(), 1, "bob holds exactly one outbound session with alice");
    assert_eq!(alice_in.len(), 1, "the split half is retained, not discarded (draining, not deleted)");
    assert_eq!(bob_in.len(), 1, "same on bob's side");

    // THE convergence property. Before the fix, `alice_out[0].1` is the drop_seed of Alice's
    // OWN PQXDH agreement and `bob_out[0].1` is the drop_seed of Bob's OWN, INDEPENDENT
    // agreement — two different root keys, so these are essentially certain to differ. A
    // deterministic, no-negotiation rule both sides evaluate locally is what makes them land
    // on the SAME one without exchanging anything.
    assert_eq!(
        alice_out[0].1, bob_out[0].1,
        "both sides must independently converge onto the SAME session — this is what lets a \
         reply from either side reach the chain the other side actually sends on again, which \
         is what makes the DH ratchet heal across the pair instead of stalling on two one-way \
         chains forever"
    );
    // And the retained half is genuinely the LOSING seed, not a duplicate of the winner —
    // otherwise "convergence" could pass by leaving everything untouched.
    assert_ne!(alice_out[0].1, alice_in[0].1, "the retained split half is the losing seed");
    assert_eq!(alice_in[0].1, bob_in[0].1, "both sides retain the SAME losing seed, too");
}

/// The requirement this ticket names explicitly: convergence must never lose mail already in
/// flight on the losing chain. `queue`s a second message on EACH side's pre-split outbound
/// before either side has processed the other's opener, so by the time it is actually flushed
/// to the relay, its own peer's `sessions[peer_ik]` entry may already have been SWAPPED by
/// `converge_split_session` (if that side turns out to hold the losing chain).
///
/// **Known limit, stated plainly:** this test passes WITH OR WITHOUT `OutboxEntry`'s routing
/// snapshot (verified by neutering it) — end to end, `receive()` always drains the identity
/// mailbox (creating the peer's second session) before it polls drop-boxes IN THE SAME call,
/// and `process_for_peer` trial-decrypts a peer's traffic against BOTH of that peer's held
/// sessions regardless of which box it arrived on. Together those recover an address computed
/// from the wrong session in every ordering this harness can produce. So THIS test only proves
/// "convergence doesn't break ordinary delivery" — it is a regression check, not proof the
/// snapshot matters. The snapshot's actual, narrower claim (a queued envelope routes by what
/// encrypted it, not by whatever is CURRENTLY in `sessions[peer_ik]`) is pinned directly, by
/// address comparison, in `peer.rs`'s
/// `convergence_route_tests::a_queued_envelope_routes_by_its_own_snapshot_not_by_whatever_session_is_current`.
#[test]
fn a_message_queued_before_convergence_still_arrives_after_it_and_delivery_keeps_working() {
    let (mut alice, mut bob, alice_ik, bob_ik) = simultaneous_first_contact();

    // The opener travels immediately — an ordinary first message is never queued behind
    // anything, and it is what lets the other side detect the split at all.
    assert!(matches!(alice.send(&bob_ik, b"a0", NOW), Response::Accepted));
    assert!(matches!(bob.send(&alice_ik, b"b0", NOW), Response::Accepted));

    // A SECOND message, queued (encrypted + durably held) but deliberately NOT delivered yet —
    // this is mail "in flight" purely as encrypted-and-queued, sitting on whichever chain is
    // about to be relocated by this peer's OWN convergence.
    let a1 = alice.queue(&bob_ik, b"a1", NOW).expect("alice queues a second message");
    let b1 = bob.queue(&alice_ik, b"b1", NOW).expect("bob queues a second message");
    assert!(alice.is_queued(a1) && bob.is_queued(b1), "both still sitting in their own outbox");

    // Each side now processes the other's opener — the split is detected and
    // `converge_split_session` may SWAP `sessions[peer_ik]` right here, on whichever side just
    // lost the tie-break, while a1/b1 are STILL queued under the pre-swap session.
    assert_eq!(plaintexts(bob.receive(NOW).unwrap()), vec![b"a0".to_vec()]);
    assert_eq!(plaintexts(alice.receive(NOW).unwrap()), vec![b"b0".to_vec()]);

    // NOW flush the queued seconds — potentially AFTER this very peer's session was just
    // swapped out from under them. Without `OutboxEntry`'s routing snapshot, this would
    // re-derive the deposit address from whatever CURRENTLY occupies `sessions[peer_ik]` (the
    // winner, if a swap just happened here) instead of the session that actually encrypted
    // a1/b1 — landing the ciphertext at an address nobody is listening to for it.
    alice.flush_outbox(NOW);
    bob.flush_outbox(NOW);
    assert!(!alice.is_queued(a1), "a1 reached the relay");
    assert!(!bob.is_queued(b1), "b1 reached the relay");

    assert_eq!(
        plaintexts(bob.receive(NOW).unwrap()),
        vec![b"a1".to_vec()],
        "alice's message, queued before her own convergence swap (if any), still arrives"
    );
    assert_eq!(
        plaintexts(alice.receive(NOW).unwrap()),
        vec![b"b1".to_vec()],
        "same for bob's"
    );
}

/// Once converged, the conversation is an ORDINARY single bidirectional session again — not
/// two one-way chains. Runs several more rounds after the convergence-triggering receives,
/// exactly like `session_path.rs`'s non-split multi-round test, on what is now (per the first
/// test above) the SAME session on both sides.
///
/// **Discriminating power is the precondition assert below, not the round trip**: a plain
/// multi-round send/receive loop passes even in the UNCONVERGED split state (each one-way
/// chain already delivers plaintext correctly on its own — that was the previous slice's whole
/// point). What a split can never do is keep DH-ratcheting round after round; that property is
/// pinned separately, by ratchet-pubkey, in `peer.rs`'s
/// `convergence_route_tests::the_converged_session_keeps_dh_ratcheting_across_several_further_rounds`.
#[test]
fn the_converged_session_carries_an_ordinary_multi_round_conversation_afterward() {
    let (mut alice, mut bob, alice_ik, bob_ik) = simultaneous_first_contact();

    assert!(matches!(alice.send(&bob_ik, b"a0", NOW), Response::Accepted));
    assert!(matches!(bob.send(&alice_ik, b"b0", NOW), Response::Accepted));
    plaintexts(bob.receive(NOW).unwrap());
    plaintexts(alice.receive(NOW).unwrap());

    // Confirm convergence actually happened before relying on it (see the first test for why
    // this specific equality is the discriminating property).
    let (alice_out, _) = alice.export_state().debug_peers();
    let (bob_out, _) = bob.export_state().debug_peers();
    assert_eq!(alice_out[0].1, bob_out[0].1, "precondition: converged before the round trip below");

    for i in 0..3u8 {
        let from_bob = [b'B', i];
        assert!(matches!(bob.send(&alice_ik, &from_bob, NOW), Response::Accepted));
        assert_eq!(plaintexts(alice.receive(NOW).unwrap()), vec![from_bob.to_vec()]);

        let from_alice = [b'A', i];
        assert!(matches!(alice.send(&bob_ik, &from_alice, NOW), Response::Accepted));
        assert_eq!(plaintexts(bob.receive(NOW).unwrap()), vec![from_alice.to_vec()]);
    }
}
