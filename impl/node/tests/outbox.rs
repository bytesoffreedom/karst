//! Send-side durable outbox: a message encrypted (ratchet advanced) but not accepted by a
//! relay is queued and retransmitted VERBATIM when the transport recovers, instead of being
//! lost with the advanced ratchet (the old at-most-once send gap). The clock is under test
//! control and the transport is toggleable so a real transport failure can be staged.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use admission::capability::{Capability, Quota, Scope};
use relay::node::{AckRequest, AckResponse, FetchRequest, FetchResponse, InMemoryTransport, PublishResponse, RelayNode, Response, Transport, WireMessage};
use node::peer::Peer;
use node::pqxdh::Account;

const NOW: u64 = 1_000_000;

fn dev_cap() -> Capability {
    Capability {
        capability_id: [0xCA; 16],
        scope: Scope::MessageDelivery,
        quota: Quota { max_requests: 1000, max_bytes: 1 << 20, window_secs: 600 },
        not_before: 0,
        not_after: u32::MAX,
        secret: [0x33; 32],
    }
}

/// An in-memory transport with a toggleable "up" flag: while down, every request is rejected
/// as unreachable — a staged transport/relay outage, not a protocol error.
#[derive(Clone)]
struct Flaky {
    inner: InMemoryTransport,
    up: Rc<Cell<bool>>,
}

impl Transport for Flaky {
    fn send(&self, msg: &WireMessage, now: u64) -> Response {
        if self.up.get() {
            self.inner.send(msg, now)
        } else {
            Response::Rejected("transport down".into())
        }
    }
    fn fetch(&self, req: &FetchRequest, now: u64) -> FetchResponse {
        if self.up.get() {
            self.inner.fetch(req, now)
        } else {
            FetchResponse::Rejected("transport down".into())
        }
    }
    fn ack(&self, req: &AckRequest, now: u64) -> AckResponse {
        if self.up.get() {
            self.inner.ack(req, now)
        } else {
            AckResponse::Rejected("transport down".into())
        }
    }
    fn fetch_bundle(&self, ik: &[u8; 32], now: u64) -> Result<Option<node::pqxdh::PreKeyBundle>, String> {
        if self.up.get() {
            self.inner.fetch_bundle(ik, now)
        } else {
            Err("transport down".into())
        }
    }
    /// Must be delegated too, or `Peer::connect` inherits the trait's "unsupported" default and
    /// this wrapper quietly stops exercising first contact at all.
    fn fetch_bundle_opk(
        &self,
        req: &relay::node::BundleOpkRequest,
        now: u64,
    ) -> Result<relay::node::BundleOpkResponse, String> {
        if self.up.get() {
            self.inner.fetch_bundle_opk(req, now)
        } else {
            Err("transport down".into())
        }
    }
}

fn plaintexts(v: Vec<Option<node::peer::Received>>) -> Vec<Vec<u8>> {
    v.into_iter().flatten().map(|r| r.plaintext).collect()
}

/// A transport failure queues the message (ratchet already advanced) instead of losing it;
/// when the transport recovers, `flush_outbox` retransmits the EXACT ciphertext and the
/// recipient decrypts it. Two queued messages deliver in FIFO (position) order.
#[test]
fn outbox_retransmits_after_the_transport_recovers() {
    let relay = Rc::new(RefCell::new(RelayNode::new(NOW)));
    relay.borrow_mut().issue_capability(dev_cap());
    let relay_pub = relay.borrow().relay_public();
    let direct = InMemoryTransport::new(relay.clone());
    let up = Rc::new(Cell::new(true));
    let flaky = Flaky { inner: InMemoryTransport::new(relay.clone()), up: up.clone() };

    // Bob publishes over the always-up transport; Alice reaches him over the flaky one.
    let bob_acct = Account::generate();
    let bob_ik = bob_acct.identity_public();
    let mut bob = Peer::new(direct.clone(), bob_acct.clone(), dev_cap(), relay_pub);
    assert!(matches!(bob.publish(NOW), PublishResponse::Published), "Bob's bundle is up");

    let mut alice = Peer::new(flaky.clone(), Account::generate(), dev_cap(), relay_pub);
    alice.connect(&bob_ik, NOW).expect("Alice opens the session while the transport is up");

    // Transport goes DOWN. Queue two messages and try to flush — both fail to deliver and
    // stay queued (the ratchet advanced, but the exact ciphertext is retained).
    up.set(false);
    let id0 = alice.queue(&bob_ik, b"m0", NOW).unwrap();
    let id1 = alice.queue(&bob_ik, b"m1", NOW).unwrap();
    assert!(alice.flush_outbox(NOW).is_empty(), "nothing delivered while down");
    assert!(alice.is_queued(id0) && alice.is_queued(id1), "both retained for retry");
    assert_eq!(alice.outbox_len(), 2);
    assert!(plaintexts(bob.receive(NOW).unwrap()).is_empty(), "Bob has nothing yet");

    // Transport RECOVERS: the exact ciphertexts retransmit and Bob decrypts both, in order.
    up.set(true);
    let delivered = alice.flush_outbox(NOW);
    assert_eq!(delivered.len(), 2, "both delivered on recovery");
    assert_eq!(alice.outbox_len(), 0, "queue drained");
    assert!(!alice.is_queued(id0) && !alice.is_queued(id1));
    let got = plaintexts(bob.receive(NOW).unwrap());
    assert_eq!(got, vec![b"m0".to_vec(), b"m1".to_vec()], "exact messages, FIFO order");
}

/// A queued message stays deliverable AFTER the recipient has DH-ratcheted PAST its chain —
/// via the skipped-key store, which is the mechanism the bound actually rests on. This forces
/// the recipient's skip path (not the trivial in-order one): the recipient receives a
/// new-chain message first, which stores the queued position as a skipped key and steps its
/// receiving chain, and only then does the old-chain retransmit arrive and decrypt via
/// `take_skipped`. So the honest bound is skipped-key eviction (`MAX_STORE`, ~2048 intervening
/// messages), not a single DH step. Break skipped-key retention and this reddens.
#[test]
fn a_queued_message_delivers_via_the_recipient_skipped_key_store() {
    let relay = Rc::new(RefCell::new(RelayNode::new(NOW)));
    relay.borrow_mut().issue_capability(dev_cap());
    let relay_pub = relay.borrow().relay_public();
    let up = Rc::new(Cell::new(true));
    let flaky = Flaky { inner: InMemoryTransport::new(relay.clone()), up: up.clone() };
    let direct = InMemoryTransport::new(relay.clone());

    let bob_acct = Account::generate();
    let bob_ik = bob_acct.identity_public();
    let mut bob = Peer::new(direct.clone(), bob_acct.clone(), dev_cap(), relay_pub);
    let _ = bob.publish(NOW);
    let mut alice = Peer::new(flaky.clone(), Account::generate(), dev_cap(), relay_pub);
    let alice_ik = alice.identity();
    alice.connect(&bob_ik, NOW).unwrap();

    // Alice's opener (chain A1, pos 0) reaches Bob; the session is live on both sides.
    assert!(matches!(alice.send(&bob_ik, b"m0", NOW), Response::Accepted));
    assert_eq!(plaintexts(bob.receive(NOW).unwrap()), vec![b"m0".to_vec()]);

    // Alice queues a second message on chain A1 (pos 1) while the transport is DOWN.
    up.set(false);
    let id = alice.queue(&bob_ik, b"m1", NOW).unwrap();
    assert!(alice.flush_outbox(NOW).is_empty());
    up.set(true);

    // Bob replies; Alice receives it and DH-steps her SENDING chain to A2.
    assert!(matches!(bob.send(&alice_ik, b"r0", NOW), Response::Accepted));
    assert_eq!(plaintexts(alice.receive(NOW).unwrap()), vec![b"r0".to_vec()]);

    // Alice sends a NEW-chain message m2 (A2/pos0) with pn = 2, and Bob receives it FIRST.
    // Bob's decrypt takes the DH-step branch: it stores A1/pos1 as a skipped key (nr..pn) and
    // moves his receiving chain to A2. Now A1 is in Bob's PAST.
    assert!(matches!(alice.send(&bob_ik, b"m2", NOW), Response::Accepted));
    assert_eq!(plaintexts(bob.receive(NOW).unwrap()), vec![b"m2".to_vec()]);

    // Only now flush the OLD-chain queued m1 (A1/pos1). Bob is on A2, so it can ONLY decrypt
    // via the retained skipped key — the exact path the eviction bound is about.
    assert_eq!(alice.flush_outbox(NOW), vec![id], "queued old-chain message still delivers");
    assert_eq!(
        plaintexts(bob.receive(NOW).unwrap()),
        vec![b"m1".to_vec()],
        "delivered through the recipient's skipped-key store after the DH step"
    );
}
