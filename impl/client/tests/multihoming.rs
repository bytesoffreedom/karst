//! Multi-homed receive: one identity reachable through TWO relays, fetched in a single
//! `client::receive_threaded` pass. This is the end-to-end proof of the relay-scoped
//! multi-homing core — a delivery test, not just a handle-scoping unit test.
//!
//! Two invariants are pinned here, each with its neuter written in the asserts below:
//!   1. **Sequential state threading.** The Double Ratchet is per-peer, not per-relay, so
//!      the state exported after relay A must be imported before relay B. Rebuild each
//!      relay's `Peer` from the same base state instead (parallel fan-out) and the last
//!      export clobbers the earlier one — the follow-up from the peer reached via relay A
//!      no longer decrypts. That is the `from-alice-2` assert.
//!   2. **One-time prekeys on a single relay.** OPKs are published to relay 1 only; a
//!      sender via relay 2 falls back to 3-DH (`dh4 = None`). Publishing the same OPK to
//!      both relays would let relay 2's sender bind a secret relay 1's sender already
//!      burned, and its opener could not derive the 4th DH term.

use std::cell::RefCell;
use std::rc::Rc;

use node::node::{
    FetchRequest, FetchResponse, InMemoryTransport, PublishResponse, RelayNode, Response, Transport,
    WireMessage, LEASE_SECS,
};
use node::peer::{Peer, PeerState};
use node::pqxdh::Account;
use x25519_dalek::PublicKey;

const NOW: u64 = 1_000_000;

/// A fresh in-memory relay with the dev capability issued; returns its shared handle, a
/// transport onto it, and its fetch-auth public key.
fn relay() -> (Rc<RefCell<RelayNode>>, InMemoryTransport, PublicKey) {
    let r = Rc::new(RefCell::new(RelayNode::new(NOW)));
    r.borrow_mut().issue_capability(client::dev_capability());
    let pubk = r.borrow().relay_public();
    let transport = InMemoryTransport::new(r.clone());
    (r, transport, pubk)
}

/// Every decrypted plaintext in a `receive_threaded` batch (drops the `None`s that mean
/// "not addressed to us / tampered").
fn plaintexts(msgs: &[Option<node::peer::Received>]) -> Vec<Vec<u8>> {
    msgs.iter().flatten().map(|r| r.plaintext.clone()).collect()
}

#[test]
fn one_identity_receives_across_two_relays_and_the_ratchet_survives() {
    let (_r1, t1, r1_pub) = relay();
    let (_r2, t2, r2_pub) = relay();

    // Bob, one identity, multi-homed to both relays. He publishes his bundle to each, but
    // one-time prekeys go to relay 1 ONLY (invariant 2). `add_opks` mints into the R1
    // publishing peer's account clone; the R2 clone keeps an empty OPK batch.
    let bob_acct = Account::generate();
    let bob_ik = bob_acct.identity_public();

    let mut bob_r1 = Peer::new(t1.clone(), bob_acct.clone(), client::dev_capability(), r1_pub);
    bob_r1.add_opks(4);
    assert!(matches!(bob_r1.publish(NOW), PublishResponse::Published), "publish to relay 1");
    let bob_opks = bob_r1.export_opks();
    assert_eq!(bob_opks.len(), 4, "relay 1 carries Bob's one-time prekeys");

    let mut bob_r2 = Peer::new(t2.clone(), bob_acct.clone(), client::dev_capability(), r2_pub);
    assert!(matches!(bob_r2.publish(NOW), PublishResponse::Published), "publish to relay 2");

    // Alice reaches Bob via relay 1 (fetching his bundle there consumes an OPK → 4-DH
    // opener); Carol reaches him via relay 2 (no OPK there → 3-DH opener). Two independent
    // sessions, deposited on two different relays.
    let mut alice = Peer::new(t1.clone(), Account::generate(), client::dev_capability(), r1_pub);
    alice.connect(&bob_ik, NOW).expect("Alice opens a session via relay 1");
    assert!(matches!(alice.send(&bob_ik, b"from-alice-1", NOW), Response::Accepted));

    let mut carol = Peer::new(t2.clone(), Account::generate(), client::dev_capability(), r2_pub);
    carol.connect(&bob_ik, NOW).expect("Carol opens a session via relay 2");
    assert!(matches!(carol.send(&bob_ik, b"from-carol", NOW), Response::Accepted));

    // One multi-homed receive pass, threading the ratchet state through relay 1 then relay 2.
    let relays = [(t1.clone(), r1_pub), (t2.clone(), r2_pub)];
    let r = client::receive_threaded(bob_acct.clone(), PeerState::empty(), bob_opks, &relays, NOW);
    let got = plaintexts(&r.messages);
    assert!(r.failed.is_empty(), "both relays answered");
    assert!(got.contains(&b"from-alice-1".to_vec()), "message via relay 1 was not delivered");
    // Neuter: fetch from the first relay only (drop relay 2 from `relays`) and this reddens.
    assert!(got.contains(&b"from-carol".to_vec()), "message via relay 2 was not delivered");

    // Follow-up on Alice's session (a post-opener Ratchet deposit on relay 1). It only
    // decrypts if Bob's Alice-session ratchet survived the two-relay fetch — i.e. relay 2's
    // state export did NOT clobber relay 1's advance (invariant 1). This is the neuter for
    // parallel fan-out: rebuild each relay's Peer from the base state and this assert reds.
    assert!(matches!(alice.send(&bob_ik, b"from-alice-2", NOW), Response::Accepted));
    let r2 = client::receive_threaded(bob_acct.clone(), r.state, r.opks, &relays, NOW);
    assert!(
        plaintexts(&r2.messages).contains(&b"from-alice-2".to_vec()),
        "the ratchet with the relay-1 peer was clobbered by the relay-2 fetch"
    );
}

#[test]
fn one_session_split_across_two_relays_threads_within_a_single_pass() {
    // The TIGHTEST threading discriminator: ONE session whose messages are split across two
    // relays, fetched in ONE pass. The opener lands on relay 1; the next ratchet message on
    // relay 2. Bob can only fetch the relay-2 message once relay 1's opener has taught him
    // the session (the drop box is derived from the session root) AND the state from relay 1
    // has been threaded into the relay-2 fetch. A parallel fan-out (relay 2's Peer built from
    // the base state) never learns the session, never polls the box, and drops the message —
    // which the different-sender tests do NOT catch, because their sessions are independent.
    let (_r1, t1, r1_pub) = relay();
    let (_r2, t2, r2_pub) = relay();

    let bob_acct = Account::generate();
    let bob_ik = bob_acct.identity_public();
    let mut bob_r1 = Peer::new(t1.clone(), bob_acct.clone(), client::dev_capability(), r1_pub);
    assert!(matches!(bob_r1.publish(NOW), PublishResponse::Published));
    let mut bob_r2 = Peer::new(t2.clone(), bob_acct.clone(), client::dev_capability(), r2_pub);
    assert!(matches!(bob_r2.publish(NOW), PublishResponse::Published));

    // Alice's opener + first message go via relay 1; she then carries the SAME session to
    // relay 2 (export/import her own state) and sends the next ratchet message there.
    let alice_acct = Account::generate();
    let mut alice_a = Peer::new(t1.clone(), alice_acct.clone(), client::dev_capability(), r1_pub);
    alice_a.connect(&bob_ik, NOW).expect("Alice opens the session via relay 1");
    assert!(matches!(alice_a.send(&bob_ik, b"split-1", NOW), Response::Accepted));

    let mut alice_b = Peer::new(t2.clone(), alice_acct, client::dev_capability(), r2_pub);
    alice_b.import_state(alice_a.export_state());
    assert!(matches!(alice_b.send(&bob_ik, b"split-2", NOW), Response::Accepted));

    let relays = [(t1.clone(), r1_pub), (t2.clone(), r2_pub)];
    let r = client::receive_threaded(bob_acct.clone(), PeerState::empty(), Vec::new(), &relays, NOW);
    let got = plaintexts(&r.messages);
    assert!(got.contains(&b"split-1".to_vec()), "the opener on relay 1 was not delivered");
    assert!(
        got.contains(&b"split-2".to_vec()),
        "the follow-up on relay 2 was dropped — the session did not thread within the pass"
    );
}

/// One relay transport type that is either live (an in-memory relay) or dead (every
/// request rejected). Production multi-homes over a single transport type — a dead relay
/// is a runtime state of it, not a different type — so the dead-relay test models it the
/// same way rather than mixing transport types in one `receive_threaded` call.
#[derive(Clone)]
enum TestTransport {
    Live(InMemoryTransport),
    Dead,
}

impl Transport for TestTransport {
    fn send(&self, msg: &WireMessage, now: u64) -> Response {
        match self {
            TestTransport::Live(t) => t.send(msg, now),
            TestTransport::Dead => Response::Rejected("relay unreachable".into()),
        }
    }
    fn fetch(&self, req: &FetchRequest, now: u64) -> FetchResponse {
        match self {
            TestTransport::Live(t) => t.fetch(req, now),
            TestTransport::Dead => FetchResponse::Rejected("relay unreachable".into()),
        }
    }
    fn ack(&self, req: &node::node::AckRequest, now: u64) -> node::node::AckResponse {
        match self {
            TestTransport::Live(t) => t.ack(req, now),
            TestTransport::Dead => node::node::AckResponse::Rejected("relay unreachable".into()),
        }
    }
}

#[test]
fn a_dead_relay_does_not_cost_the_healthy_relay_its_messages() {
    // Principle 2, the whole reason to multi-home: losing one relay must not lose the
    // network. The dead relay is polled FIRST, so a fail-fast receive (the `?` this slice
    // removed) would abort before the healthy relay is ever reached and swallow its mail.
    let (_r1, t1, r1_pub) = relay();
    let dead_pub = PublicKey::from([9u8; 32]);

    let bob_acct = Account::generate();
    let bob_ik = bob_acct.identity_public();
    let mut bob_r1 = Peer::new(t1.clone(), bob_acct.clone(), client::dev_capability(), r1_pub);
    assert!(matches!(bob_r1.publish(NOW), PublishResponse::Published));

    let mut alice = Peer::new(t1.clone(), Account::generate(), client::dev_capability(), r1_pub);
    alice.connect(&bob_ik, NOW).expect("Alice opens a session via the live relay");
    assert!(matches!(alice.send(&bob_ik, b"still-here", NOW), Response::Accepted));

    // Dead relay at index 0, live relay at index 1.
    let relays = [(TestTransport::Dead, dead_pub), (TestTransport::Live(t1.clone()), r1_pub)];
    let r = client::receive_threaded(bob_acct.clone(), PeerState::empty(), Vec::new(), &relays, NOW);

    // Neuter: restore the `?` in `receive_threaded` and this whole assert block reddens —
    // the message is lost and `failed` is never returned at all.
    assert_eq!(r.failed, vec![0], "the dead relay must be reported, not fatal");
    assert!(
        plaintexts(&r.messages).contains(&b"still-here".to_vec()),
        "the live relay's message was dropped because a different relay was down"
    );
}

#[test]
fn the_same_opk_on_two_relays_breaks_the_second_sender() {
    // Confirms the hazard the "publish OPKs to ONE relay only" rule exists to avoid. A
    // one-time prekey secret is burned on first use, so if the SAME opk is advertised on
    // two relays, the second sender binds a key the first already consumed and its opener
    // can no longer derive the 4th DH term. Contrast with the main test, where Carol (no
    // OPK on her relay) IS delivered — so this is the collision half, not a generic failure.
    let (_r1, t1, r1_pub) = relay();
    let (_r2, t2, r2_pub) = relay();

    // Mint ONE opk into the shared account, then publish that same account to both relays,
    // so both hand out the identical opk.
    let mut bob_acct = Account::generate();
    bob_acct.add_opk();
    let bob_ik = bob_acct.identity_public();
    let bob_opk_secrets = bob_acct.export_opk_secrets();
    let bob_recv = Account::from_secret_bytes(&bob_acct.to_secret_bytes()); // same identity, empty OPKs

    let mut bob_r1 = Peer::new(t1.clone(), bob_acct.clone(), client::dev_capability(), r1_pub);
    assert!(matches!(bob_r1.publish(NOW), PublishResponse::Published));
    let mut bob_r2 = Peer::new(t2.clone(), bob_acct.clone(), client::dev_capability(), r2_pub);
    assert!(matches!(bob_r2.publish(NOW), PublishResponse::Published));

    let mut alice = Peer::new(t1.clone(), Account::generate(), client::dev_capability(), r1_pub);
    alice.connect(&bob_ik, NOW).expect("Alice fetches the bundle (with the opk) from relay 1");
    assert!(matches!(alice.send(&bob_ik, b"from-alice", NOW), Response::Accepted));

    let mut carol = Peer::new(t2.clone(), Account::generate(), client::dev_capability(), r2_pub);
    carol.connect(&bob_ik, NOW).expect("Carol fetches the bundle (SAME opk) from relay 2");
    assert!(matches!(carol.send(&bob_ik, b"from-carol", NOW), Response::Accepted));

    let relays = [(t1.clone(), r1_pub), (t2.clone(), r2_pub)];
    let r = client::receive_threaded(bob_recv, PeerState::empty(), bob_opk_secrets, &relays, NOW);
    let got = plaintexts(&r.messages);
    assert!(got.contains(&b"from-alice".to_vec()), "the first sender's opener must still open");
    assert!(
        !got.contains(&b"from-carol".to_vec()),
        "the second sender reused a burned opk yet its opener opened — the hazard is not real"
    );
}

// ---- lease/ACK across the multi-homed path ----

/// Publish Bob (3-DH, no OPK) to a relay so an opener from a stranger decrypts without an
/// OPK secret — keeps the lease/ACK tests free of the OPK-threading concern.
fn publish_bob(t: &InMemoryTransport, relay_pub: PublicKey, acct: &Account) {
    let mut b = Peer::new(t.clone(), acct.clone(), client::dev_capability(), relay_pub);
    assert!(matches!(b.publish(NOW), PublishResponse::Published), "publish bundle");
}

fn open_and_send(t: &InMemoryTransport, relay_pub: PublicKey, to: &[u8; 32], text: &[u8]) {
    let mut p = Peer::new(t.clone(), Account::generate(), client::dev_capability(), relay_pub);
    p.connect(to, NOW).expect("opener connects");
    assert!(matches!(p.send(to, text, NOW), Response::Accepted), "opener sends");
}

/// The multi-homed path ACKs each leased message through the SAME relay that leased it, so
/// after a receive both live relays' mailboxes are drained — proving the per-relay receipt
/// tag routed each ACK correctly. Break the tag (ack everything through relay 0) and relay
/// 1's mailbox would still hold its leased message.
#[test]
fn multihomed_receive_acks_and_drains_every_live_relay() {
    let (r1, t1, r1_pub) = relay();
    let (r2, t2, r2_pub) = relay();
    let bob = Account::generate();
    let bob_ik = bob.identity_public();
    publish_bob(&t1, r1_pub, &bob);
    publish_bob(&t2, r2_pub, &bob);
    open_and_send(&t1, r1_pub, &bob_ik, b"via-r1");
    open_and_send(&t2, r2_pub, &bob_ik, b"via-r2");

    let relays = [(t1.clone(), r1_pub), (t2.clone(), r2_pub)];
    let out = client::receive_threaded(bob.clone(), PeerState::empty(), Vec::new(), &relays, NOW);
    let got = plaintexts(&out.messages);
    assert!(got.contains(&b"via-r1".to_vec()) && got.contains(&b"via-r2".to_vec()), "both delivered");
    assert_eq!(out.acks.len(), 2, "one receipt per relay that leased a message");
    // Leased, not yet deleted: both relays still hold their message before the ACK.
    assert!(!r1.borrow().all_slots_for_test().is_empty(), "r1 holds a leased message");
    assert!(!r2.borrow().all_slots_for_test().is_empty(), "r2 holds a leased message");

    // State is durable ⇒ ack each receipt through its tagged relay's transport.
    for (i, receipt) in &out.acks {
        node::peer::send_ack(&relays[*i].0, receipt, NOW);
    }
    assert!(r1.borrow().all_slots_for_test().is_empty(), "relay 1 drained by its ACK");
    assert!(r2.borrow().all_slots_for_test().is_empty(), "relay 2 drained by its ACK");
}

/// Crash BEFORE the single save (multi-homed): the ratchet never advanced, so the message
/// redelivers once the lease expires and decrypts fresh — exactly once. Mirrors the
/// single-homed proof through the `receive_threaded` + `send_ack` API.
#[test]
fn multihomed_crash_before_save_redelivers_after_lease() {
    let (r1, t1, r1_pub) = relay();
    let bob = Account::generate();
    let bob_ik = bob.identity_public();
    publish_bob(&t1, r1_pub, &bob);
    open_and_send(&t1, r1_pub, &bob_ik, b"again");

    let relays = [(t1.clone(), r1_pub)];
    // Poll 1 crashes before save: deliver in memory, discard the state, send no ACK.
    let p1 = client::receive_threaded(bob.clone(), PeerState::empty(), Vec::new(), &relays, NOW);
    assert!(plaintexts(&p1.messages).contains(&b"again".to_vec()), "in-memory delivery pre-crash");
    // Poll 2 inside the lease window: the message is leased and hidden.
    let p2 = client::receive_threaded(bob.clone(), PeerState::empty(), Vec::new(), &relays, NOW);
    assert!(plaintexts(&p2.messages).is_empty(), "leased message hidden within the lease");
    // Poll 3 after the lease expires: redelivered and decrypts fresh (state never advanced).
    let later = NOW + LEASE_SECS + 1;
    let p3 = client::receive_threaded(bob.clone(), PeerState::empty(), Vec::new(), &relays, later);
    assert!(plaintexts(&p3.messages).contains(&b"again".to_vec()), "redelivered exactly once");
    for (i, receipt) in &p3.acks {
        node::peer::send_ack(&relays[*i].0, receipt, later);
    }
    assert!(r1.borrow().all_slots_for_test().is_empty(), "delivered message acked away");
}

/// Crash AFTER the save but BEFORE the ACK (multi-homed), WITH a dead relay in the set: the
/// redelivered duplicate fails closed against the already-advanced ratchet (delivered
/// exactly once, no dedup store), and the down relay is reported in `failed` without
/// breaking the pass or losing the healthy relay's mail.
#[test]
fn multihomed_crash_after_save_dedups_and_tolerates_a_dead_relay() {
    let (r1, t1, r1_pub) = relay();
    let dead_pub = PublicKey::from([9u8; 32]);
    let bob = Account::generate();
    let bob_ik = bob.identity_public();
    publish_bob(&t1, r1_pub, &bob);
    open_and_send(&t1, r1_pub, &bob_ik, b"once");

    // Dead relay FIRST (index 0), live relay second — a down relay must not abort the pass.
    let relays = [(TestTransport::Dead, dead_pub), (TestTransport::Live(t1.clone()), r1_pub)];
    // Poll 1: deliver + save (thread the state forward), then crash before the ACK.
    let p1 = client::receive_threaded(bob.clone(), PeerState::empty(), Vec::new(), &relays, NOW);
    assert_eq!(p1.failed, vec![0], "dead relay reported, not fatal");
    assert!(plaintexts(&p1.messages).contains(&b"once".to_vec()), "delivered");
    assert_eq!(p1.acks.len(), 1, "only the live relay leased (the dead one's receive rolled back)");

    // Poll 2 after the lease expires, from the SAVED (advanced) state: the message
    // redelivers but the ratchet already consumed it → fails closed → not delivered again.
    let later = NOW + LEASE_SECS + 1;
    let p2 = client::receive_threaded(bob.clone(), p1.state, p1.opks, &relays, later);
    assert_eq!(p2.failed, vec![0], "dead relay still reported");
    assert!(plaintexts(&p2.messages).is_empty(), "duplicate fails closed: delivered exactly once");
    // Ack the duplicate away (poll 2's receipt) so the relay stops redelivering it.
    for (i, receipt) in &p2.acks {
        node::peer::send_ack(&relays[*i].0, receipt, later);
    }
    assert!(r1.borrow().all_slots_for_test().is_empty(), "duplicate acked and removed");
}
