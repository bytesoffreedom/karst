//! Lease/ACK receive: the at-most-once → effectively-once slice, end to end through a
//! real `Peer` + mailbox, with the clock under test control so a lease can actually
//! expire (the socket relay's fixed clock can't show that).
//!
//! A "poll" here rebuilds `Peer` from the serialized on-disk state each cycle — exactly
//! what the CLI/desktop does (`recv_session` = load → receive → save → ACK). A "crash" is
//! a poll that STOPS at a chosen point: before saving the advanced ratchet, or after
//! saving but before the ACK. The two tests pin those two points by name (`Crash::…`) and
//! assert the message is delivered exactly once regardless — the whole point of the slice.

use std::cell::RefCell;
use std::rc::Rc;

use admission::capability::{Capability, Quota, Scope};
use node::node::{InMemoryTransport, RelayNode, Response, LEASE_SECS};
use node::peer::{Peer, PeerState};
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

fn plaintexts(v: Vec<Option<node::peer::Received>>) -> Vec<Vec<u8>> {
    v.into_iter().flatten().map(|r| r.plaintext).collect()
}

/// Where a simulated poll stops. `None` is a clean poll: save, then ACK.
#[derive(Clone, Copy)]
enum Crash {
    /// Fetch (under lease) and decrypt in memory, then die before persisting the ratchet.
    BeforeSave,
    /// Persist the advanced ratchet, then die before the ACK deletes the leased message.
    AfterSaveBeforeAck,
    /// Clean: save then ACK.
    None,
}

/// One receive cycle for `account`, threading the on-disk state (serialized `PeerState`,
/// like the store) and the OPK secrets. Returns the plaintexts decrypted THIS cycle.
fn poll(
    transport: &InMemoryTransport,
    relay_pub: PublicKey,
    account: &Account,
    disk: &mut Vec<u8>,
    opks: &mut Vec<[u8; 32]>,
    now: u64,
    crash: Crash,
) -> Vec<Vec<u8>> {
    let mut p = Peer::new(transport.clone(), account.clone(), dev_cap(), relay_pub);
    if !disk.is_empty() {
        let state: PeerState = postcard::from_bytes(disk).expect("state deserializes");
        p.import_state(state);
    }
    p.load_opks(opks);
    let texts = plaintexts(p.receive(now).expect("receive"));
    match crash {
        // Crash before save: the advanced ratchet is discarded (disk unchanged), and no ACK
        // fires, so the message stays leased on the relay and redelivers once the lease ends.
        Crash::BeforeSave => {}
        Crash::AfterSaveBeforeAck => {
            *disk = postcard::to_stdvec(&p.export_state()).expect("state serializes");
            *opks = p.export_opks();
        }
        Crash::None => {
            *disk = postcard::to_stdvec(&p.export_state()).expect("state serializes");
            *opks = p.export_opks();
            p.ack_all(now);
        }
    }
    texts
}

/// Crash BEFORE `save_sessions`: the ratchet never advanced on disk, so the redelivered
/// ciphertext decrypts fresh — delivered exactly once (the pre-crash in-memory delivery
/// evaporates with the process). Make `ack_all` run unconditionally (rather than only on
/// `Crash::None`) and poll 1 would DRAIN the relay, so poll 3 reds — this is what the lease
/// buys. The lease itself is no longer opt-in: since #179 every fetch takes one.
#[test]
fn crash_before_save_redelivers_exactly_once() {
    let (transport, relay_pub) = shared();
    let bob = Account::generate();
    let mut disk = Vec::new();
    let mut opks = Vec::new();

    // Alice opens a session to Bob and sends one message → Bob's identity mailbox.
    let bob_bundle = Peer::new(transport.clone(), bob.clone(), dev_cap(), relay_pub).bundle();
    let mut alice = Peer::new(transport.clone(), Account::generate(), dev_cap(), relay_pub);
    alice.connect_with_bundle(&bob_bundle).unwrap();
    let bob_ik = bob.identity_public();
    assert!(matches!(alice.send(&bob_ik, b"m0", NOW), Response::Accepted));

    // Poll 1 crashes before save: decrypts m0 in memory, then the process dies.
    let got1 = poll(&transport, relay_pub, &bob, &mut disk, &mut opks, NOW, Crash::BeforeSave);
    assert_eq!(got1, vec![b"m0".to_vec()], "in-memory delivery before the crash");
    assert!(disk.is_empty(), "crash before save left the ratchet un-advanced on disk");

    // Poll 2 within the lease window: the message is leased (still on the relay) but hidden.
    let got2 = poll(&transport, relay_pub, &bob, &mut disk, &mut opks, NOW, Crash::None);
    assert!(got2.is_empty(), "leased message stays hidden until the lease expires");

    // Poll 3 after the lease expires: redelivered and decrypts fresh — the durable delivery.
    let later = NOW + LEASE_SECS + 1;
    let got3 = poll(&transport, relay_pub, &bob, &mut disk, &mut opks, later, Crash::None);
    assert_eq!(got3, vec![b"m0".to_vec()], "redelivered exactly once after the lease expired");

    // Poll 4: the ACK from poll 3 deleted it — nothing left.
    let got4 = poll(&transport, relay_pub, &bob, &mut disk, &mut opks, later, Crash::None);
    assert!(got4.is_empty(), "ACK deleted the delivered message");
}

/// Crash AFTER `save_sessions` but BEFORE the ACK: the ratchet advanced on disk, so the
/// redelivered ciphertext is a duplicate — the transactional decrypt derives the wrong
/// message key and fails closed with no state mutation. Delivered exactly once, no dedup
/// store. (The residual [save → caller-history] loss is a caller-layer window, documented
/// in `recv_session`, not exercised here.)
#[test]
fn crash_after_save_before_ack_dedups_via_ratchet() {
    let (transport, relay_pub) = shared();
    let bob = Account::generate();
    let mut disk = Vec::new();
    let mut opks = Vec::new();

    let bob_bundle = Peer::new(transport.clone(), bob.clone(), dev_cap(), relay_pub).bundle();
    let mut alice = Peer::new(transport.clone(), Account::generate(), dev_cap(), relay_pub);
    alice.connect_with_bundle(&bob_bundle).unwrap();
    let bob_ik = bob.identity_public();
    assert!(matches!(alice.send(&bob_ik, b"m0", NOW), Response::Accepted));

    // Poll 1: deliver + persist the ratchet, then crash before the ACK.
    let got1 = poll(&transport, relay_pub, &bob, &mut disk, &mut opks, NOW, Crash::AfterSaveBeforeAck);
    assert_eq!(got1, vec![b"m0".to_vec()], "delivered and ratchet saved");
    assert!(!disk.is_empty(), "ratchet is durable");

    // Poll 2 after the lease expires: the message redelivers, but the ratchet already
    // consumed it → fails closed → NOT delivered again.
    let later = NOW + LEASE_SECS + 1;
    let got2 = poll(&transport, relay_pub, &bob, &mut disk, &mut opks, later, Crash::None);
    assert!(got2.is_empty(), "redelivered duplicate fails closed: delivered exactly once");

    // Poll 3: poll 2's ACK cleaned up the duplicate, so the relay is drained.
    let got3 = poll(&transport, relay_pub, &bob, &mut disk, &mut opks, later, Crash::None);
    assert!(got3.is_empty(), "duplicate was acked and removed");
}
