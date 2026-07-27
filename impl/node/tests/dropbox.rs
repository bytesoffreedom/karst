//! Rotating drop-boxes, judged from the RELAY's chair.
//!
//! These tests log exactly the two fields the relay reads on every request —
//! `client_addr` and the mailbox — because that, not "did the message arrive", is where
//! an addressing scheme is proved or exposed. A delivery test passes just as happily
//! when the rotation is decorative.
//!
//! # What rotation buys, and what it does not
//!
//! It buys this: after the opener, messages no longer address the recipient's PUBLISHED
//! identity key. An observer holding Bob's discovery key can no longer read his inbound
//! social graph off deposit addresses, and the boxes are underivable without the session
//! seed. It is also the prerequisite for PIR.
//!
//! It does NOT buy cross-epoch unlinkability against a relay that logs fetches, and this
//! file pins that gap rather than implying otherwise. The reason is structural, not a
//! missing optimisation: tolerating clock skew REQUIRES re-polling a box across an epoch
//! boundary (`poll_epochs` = `[e-1, e, e+1]`), and any box polled in two epochs bridges
//! them — transitively chaining the whole conversation. Rotating the handle cannot help,
//! because on a re-poll the ADDRESS is the linker. The alternative — polling only the
//! current epoch — buys unlinkability by silently stranding any mail that crosses a
//! boundary, which is a worse defect than the one it fixes. Closing this honestly needs
//! PIR (a fetch that does not reveal WHICH box is being read), which is its own slice.
//! `known_gap_the_relay_can_still_chain_epochs_through_the_overlap` asserts the gap so it
//! stays visible and flips loudly when PIR lands.

use std::cell::RefCell;
use std::rc::Rc;

use admission::capability::{Capability, Quota, Scope};
use node::drop::DROP_EPOCH_SECS;
use node::node::{
    FetchRequest, FetchResponse, InMemoryTransport, PublishRequest, PublishResponse, RelayNode,
    Response, Transport, WireMessage,
};
use node::peer::Peer;
use node::pqxdh::{Account, PreKeyBundle};
use x25519_dalek::PublicKey;

const NOW: u64 = 10 * DROP_EPOCH_SECS + 10;

fn dev_cap() -> Capability {
    Capability {
        capability_id: [0xCA; 16],
        scope: Scope::MessageDelivery,
        quota: Quota { max_requests: 10_000, max_bytes: 1 << 30, window_secs: 600 },
        not_before: 0,
        not_after: u32::MAX,
        secret: [0x33; 32],
    }
}

/// One row of the relay's log: precisely what it learns per request.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Row {
    client_addr: Vec<u8>,
    mailbox: [u8; 32],
}

/// A transport that records what the relay sees, then forwards unchanged.
#[derive(Clone)]
struct Wiretap {
    inner: InMemoryTransport,
    rows: Rc<RefCell<Vec<Row>>>,
}

impl Transport for Wiretap {
    fn send(&self, msg: &WireMessage, now: u64) -> Response {
        // On a deposit the mailbox IS the recipient field — the address the mail lands in.
        self.rows
            .borrow_mut()
            .push(Row { client_addr: msg.client_addr.clone(), mailbox: msg.recipient });
        self.inner.send(msg, now)
    }
    fn fetch(&self, req: &FetchRequest, now: u64) -> FetchResponse {
        self.rows
            .borrow_mut()
            .push(Row { client_addr: req.client_addr.clone(), mailbox: req.mailbox });
        self.inner.fetch(req, now)
    }
    fn publish_bundle(&self, req: &PublishRequest, now: u64) -> PublishResponse {
        self.inner.publish_bundle(req, now)
    }
    fn fetch_bundle(&self, ik: &[u8; 32], now: u64) -> Result<Option<PreKeyBundle>, String> {
        self.inner.fetch_bundle(ik, now)
    }
}

struct Fixture {
    alice: Peer<Wiretap>,
    bob: Peer<Wiretap>,
    rows: Rc<RefCell<Vec<Row>>>,
    relay: Rc<RefCell<RelayNode>>,
    tap: Wiretap,
    relay_pub: PublicKey,
}

impl Fixture {
    /// Everything the relay holds — the view a PIR reader would have.
    fn relay_slots(&self) -> Vec<node::node::Payload> {
        self.relay.borrow().all_slots_for_test()
    }
    fn alice_transport(&self) -> Wiretap {
        self.tap.clone()
    }
    fn relay_pub(&self) -> PublicKey {
        self.relay_pub
    }
}

fn fixture() -> Fixture {
    let relay = Rc::new(RefCell::new(RelayNode::new(NOW)));
    relay.borrow_mut().issue_capability(dev_cap());
    let relay_pub = relay.borrow().relay_public();
    let inner = InMemoryTransport::new(relay.clone());
    let rows = Rc::new(RefCell::new(Vec::new()));
    let tap = Wiretap { inner, rows: rows.clone() };
    let alice = Peer::new(tap.clone(), Account::generate(), dev_cap(), relay_pub);
    let bob = Peer::new(tap.clone(), Account::generate(), dev_cap(), relay_pub);
    Fixture { alice, bob, rows, relay, tap, relay_pub }
}

/// Everything the relay logged since `from`.
fn since(rows: &Rc<RefCell<Vec<Row>>>, from: usize) -> Vec<Row> {
    rows.borrow()[from..].to_vec()
}

#[test]
fn after_the_opener_a_deposit_never_names_the_recipients_published_key() {
    // The property rotation actually delivers. Bob's IK is PUBLISHED — anyone can fetch
    // his bundle — so a deposit addressed to it announces "someone is writing to Bob" to
    // anyone who knows that key. After the opener, deposits go to a box derivable only
    // from the session seed, so the same observer learns an address that means nothing.
    // Neuter `route_for` to send `Ratchet` to `peer_ik` and this reddens.
    let mut f = fixture();
    let bob_ik = f.bob.identity();
    f.bob.publish(NOW);
    f.alice.connect_with_bundle(&f.bob.bundle()).unwrap();
    assert!(matches!(f.alice.send(&bob_ik, b"hello", NOW), Response::Accepted));
    f.bob.receive(NOW).unwrap();

    let mark = f.rows.borrow().len();
    assert!(matches!(f.alice.send(&bob_ik, b"after the opener", NOW), Response::Accepted));
    let deposits = since(&f.rows, mark);

    assert!(!deposits.is_empty(), "the send must have produced a deposit");
    for r in &deposits {
        assert_ne!(r.mailbox, bob_ik, "a post-opener deposit still addressed Bob's published key");
    }
}

#[test]
fn the_drop_box_address_moves_when_the_epoch_does() {
    // Two sends over one session, an epoch apart, must land in DIFFERENT boxes. This is
    // rotation itself: without it there is one permanent per-session address, which is
    // just the IK-mailbox leak wearing a different key. Neuter `drop_identity` to ignore
    // `epoch` and this reddens.
    let mut f = fixture();
    let bob_ik = f.bob.identity();
    f.bob.publish(NOW);
    f.alice.connect_with_bundle(&f.bob.bundle()).unwrap();
    f.alice.send(&bob_ik, b"hello", NOW);
    f.bob.receive(NOW).unwrap();

    let deposit_at = |f: &mut Fixture, now: u64| -> [u8; 32] {
        let mark = f.rows.borrow().len();
        assert!(matches!(f.alice.send(&bob_ik, b"msg", now), Response::Accepted));
        let rows = since(&f.rows, mark);
        rows.iter().find(|r| r.mailbox != bob_ik).expect("a drop-box deposit").mailbox
    };
    let first = deposit_at(&mut f, NOW);
    let second = deposit_at(&mut f, NOW + DROP_EPOCH_SECS);
    assert_ne!(first, second, "the box did not move across the epoch boundary");
}

#[test]
fn known_gap_the_relay_can_still_chain_epochs_through_the_overlap() {
    // ASSERTS THE LEAK, deliberately. Not an aspiration — a pin.
    //
    // Skew tolerance makes the recipient poll `[e-1, e, e+1]`, so box(E) is fetched in
    // three consecutive windows. A relay that logs fetches sees the same address in
    // adjacent epochs, links them, and chains the whole conversation transitively. The
    // moving address does not prevent this; on a re-poll the address IS the linker.
    //
    // This is not fixable by rotating harder. Polling only the current epoch would close
    // it and silently strand every message that crosses a boundary — trading a
    // linkability leak for mail loss, which is the worse bug. The real answer is PIR: a
    // fetch that hides WHICH box is read. When that lands, this test flips loudly, which
    // is the point of writing it.
    let mut f = fixture();
    let bob_ik = f.bob.identity();
    f.bob.publish(NOW);
    f.alice.connect_with_bundle(&f.bob.bundle()).unwrap();
    f.alice.send(&bob_ik, b"hello", NOW);
    f.bob.receive(NOW).unwrap();

    let poll_at = |f: &mut Fixture, now: u64| -> Vec<[u8; 32]> {
        let mark = f.rows.borrow().len();
        f.bob.receive(now).unwrap();
        since(&f.rows, mark).iter().filter(|r| r.mailbox != bob_ik).map(|r| r.mailbox).collect()
    };
    let w1 = poll_at(&mut f, NOW);
    let w2 = poll_at(&mut f, NOW + DROP_EPOCH_SECS);

    let shared: Vec<_> = w1.iter().filter(|m| w2.contains(m)).collect();
    assert!(
        !shared.is_empty(),
        "GAP CLOSED: no box is polled in two epochs — cross-epoch chaining is gone. If PIR \
         or a non-overlapping poll landed, invert this test into the property it now holds."
    );
}

#[test]
fn polling_for_openers_does_not_relink_the_drop_boxes() {
    // Bob must poll his identity mailbox forever — that is where a stranger knocks. If he
    // polled it under a handle he also used for a drop-box, the relay would read straight
    // through: "the party fetching box X is the party who owns identity mailbox IK", and
    // every rotation would be undone at once. Give `Handle::Identity` and `Handle::Box`
    // the same handle and this reddens.
    let mut f = fixture();
    let bob_ik = f.bob.identity();
    f.bob.publish(NOW);
    f.alice.connect_with_bundle(&f.bob.bundle()).unwrap();
    f.alice.send(&bob_ik, b"hello", NOW);
    f.bob.receive(NOW).unwrap();

    let mark = f.rows.borrow().len();
    f.alice.send(&bob_ik, b"again", NOW);
    f.bob.receive(NOW).unwrap();
    let rows = since(&f.rows, mark);

    let ik_handles: Vec<Vec<u8>> =
        rows.iter().filter(|r| r.mailbox == bob_ik).map(|r| r.client_addr.clone()).collect();
    let box_handles: Vec<Vec<u8>> =
        rows.iter().filter(|r| r.mailbox != bob_ik).map(|r| r.client_addr.clone()).collect();
    assert!(!ik_handles.is_empty() && !box_handles.is_empty(), "need both kinds of traffic");
    for ik in &ik_handles {
        assert!(!box_handles.contains(ik), "identity-mailbox handle also used for a drop-box");
    }
}

#[test]
fn a_message_deposited_just_before_a_rollover_is_still_delivered() {
    // The liveness half. Rotation that loses mail at every boundary would be worse than
    // no rotation — and this is the case a `[prev, current]` poll window would strand:
    // deposited in the old epoch, fetched in the new one. Narrow `poll_epochs` to
    // `[e, e+1]` and this reddens.
    let mut f = fixture();
    let bob_ik = f.bob.identity();
    f.bob.publish(NOW);
    f.alice.connect_with_bundle(&f.bob.bundle()).unwrap();
    f.alice.send(&bob_ik, b"hello", NOW);
    f.bob.receive(NOW).unwrap();

    let before = 11 * DROP_EPOCH_SECS - 1; // last second of the epoch
    assert!(matches!(f.alice.send(&bob_ik, b"just in time", before), Response::Accepted));

    let after = 11 * DROP_EPOCH_SECS + 1; // first second of the next
    let got = f.bob.receive(after).unwrap();
    let texts: Vec<Vec<u8>> = got.into_iter().flatten().map(|r| r.plaintext).collect();
    assert!(texts.contains(&b"just in time".to_vec()), "mail was stranded across the rollover");
}

#[test]
fn an_idle_client_still_puts_traffic_on_the_wire() {
    // The property cover traffic exists for. The relay is asked "is this user writing to
    // anyone?" on every deposit, and silence answers it. A client that deposits only when
    // its user types has a shape; one that also loops does not. Neuter `send_loop` to a
    // no-op and this reddens — which is exactly the state where idle and active are
    // distinguishable.
    let mut f = fixture();
    f.bob.publish(NOW);

    let mark = f.rows.borrow().len();
    assert!(matches!(f.bob.send_loop(NOW), Response::Accepted));
    let deposits = since(&f.rows, mark);
    assert!(!deposits.is_empty(), "an idle client produced no traffic at all");

    // And the loop must come back — a loop that vanishes is how a dropping relay gets
    // caught, so the return path has to work before the signal means anything.
    assert_eq!(f.bob.receive_loops(NOW), 1, "the loop did not come back");
}

#[test]
fn a_loop_never_lands_in_a_real_conversations_box() {
    // A loop is addressed to our OWN box. If one could collide with a real session's box
    // it would consume a contact's mailbox and, worse, look exactly like mail loss.
    //
    // What holds the property is that the two seeds are keyed from INDEPENDENT secrets —
    // `loop_seed` from our identity secret, `drop_seed` from the session root key. The
    // `info` strings differ too, but that is belt-and-braces and NOT what this test
    // catches: giving both the same info string leaves it green, because the input key
    // material still differs. (Checked, rather than assumed — the obvious neuter is the
    // wrong one here.) Point `loop_box` at a session's `drop_seed` and it reddens; this
    // guards the refactor that derives both from one secret.
    let mut f = fixture();
    let bob_ik = f.bob.identity();
    f.bob.publish(NOW);
    f.alice.connect_with_bundle(&f.bob.bundle()).unwrap();
    f.alice.send(&bob_ik, b"hello", NOW);
    f.bob.receive(NOW).unwrap();

    let mark = f.rows.borrow().len();
    f.alice.send(&bob_ik, b"real", NOW);
    let real_box = since(&f.rows, mark)[0].mailbox;

    let mark = f.rows.borrow().len();
    f.bob.send_loop(NOW);
    let loop_box = since(&f.rows, mark)[0].mailbox;

    assert_ne!(real_box, loop_box, "a loop was deposited into a real conversation's box");
    assert_ne!(loop_box, bob_ik, "a loop named the identity mailbox");
}

#[test]
fn a_loops_two_legs_ride_different_circuits_like_a_real_messages_do() {
    // INVERTED from `known_gap_a_loop_is_distinguishable_from_real_mail_by_source_address`
    // when slice 3b landed — which is what that pin was written for.
    //
    // The gap: the relay reads the source address on both legs. A real message's box is
    // deposited into by the sender and fetched by the RECIPIENT — two addresses. A loop is
    // both parties, so if its legs shared a circuit the relay would see one address on
    // both and could tell cover from real mail at a glance. That breaks both things loops
    // buy: it can subtract them from your volume, and it can drop real mail while
    // returning loops so the detector reports all-clear while messages vanish.
    //
    // Closed by giving the legs separate handles (`LoopSend`/`LoopRecv`) and by per-handle
    // isolation turning separate handles into separate circuits. Now a loop wears a real
    // message's shape: two handles, two circuits, two source addresses.
    //
    // **The claim is conditional and stays that way.** Circuits exist only over an
    // isolating carrier (a SOCKS proxy honouring `IsolateSOCKSAuth`). Over direct TCP
    // there is one source address no matter how many handles ask for one, and no
    // addressing scheme can conjure a second — you have one IP. That residual belongs to
    // the carrier the user chooses, not to this layer.
    let (mut _alice, mut bob, scopes) = scope_fixture();
    bob.publish(NOW);

    let mark = scopes.borrow().len();
    bob.send_loop(NOW);
    bob.receive_loops(NOW);
    let rows = scopes.borrow()[mark..].to_vec();

    // Split by LEG, not by position: a cookie challenge retries a leg, so the second row
    // is another deposit, not the fetch.
    let deposit = rows.iter().find(|r| r.0 == Leg::Deposit).expect("the loop's deposit leg").clone();
    let fetches: Vec<_> = rows.iter().filter(|r| r.0 == Leg::Fetch).cloned().collect();
    assert!(!fetches.is_empty(), "the loop's fetch leg");

    for f in &fetches {
        assert_ne!(f.1, deposit.1, "a loop's two legs share a handle — the relay reads one party");
        assert_ne!(
            f.2, deposit.2,
            "a loop's two legs share a circuit — the relay reads one source address on both, \
             which is exactly what distinguishes cover from real mail"
        );
        assert!(f.2.is_some() && deposit.2.is_some(), "both legs must ask for isolation");
    }
}

#[test]
fn fetching_is_not_charged_against_the_capability_quota() {
    // Pins the fact an earlier version of this slice's comments got WRONG (they claimed
    // fetches were quota'd, and justified persisting cookies by it). `handle_fetch`
    // checks the cookie and the ownership proof and charges nothing — deposits are the
    // metered path. That asymmetry is load-bearing for the drop-box design: polling
    // `3 × sessions + 1` boxes per cycle is affordable ONLY because fetches are free.
    // If someone later meters fetches, rotation becomes unaffordable and this reddens
    // rather than the behaviour degrading quietly.
    let mut relay = RelayNode::new(NOW);
    let mut cap = dev_cap();
    cap.quota = Quota { max_requests: 1, max_bytes: 1 << 20, window_secs: 600 };
    relay.issue_capability(cap.clone());
    let relay_pub = relay.relay_public();
    let inner = InMemoryTransport::new(Rc::new(RefCell::new(relay)));
    let rows = Rc::new(RefCell::new(Vec::new()));
    let tap = Wiretap { inner, rows };
    let mut bob = Peer::new(tap, Account::generate(), cap, relay_pub);

    // A quota of ONE request. Fetch far more times than that; every one must succeed.
    for _ in 0..20 {
        bob.receive(NOW).expect("a fetch was refused — is the quota now charged on fetch?");
    }
}

#[test]
fn a_message_survives_the_recipient_being_offline_for_several_epochs() {
    // Store-and-forward's whole promise: go away, come back, find your mail. The relay
    // holds it for MAILBOX_TTL_SECS (7 days), so anything inside that window must be
    // reachable — no matter how long the recipient was gone.
    //
    // Rotation nearly broke this. A message is deposited into box(epoch-at-send) and is
    // never re-deposited, so if the recipient only ever polls the epochs around its own
    // CURRENT clock, mail older than that window sits at an address it will never ask for
    // again. It then rots until the TTL sweep with no error anywhere — the mailbox is
    // fine, the relay is honest, the message is simply unreachable. Silent loss, and a
    // regression: the old fixed IK-mailbox held everything until TTL.
    //
    // Narrow the sweep to the hot window (`poll_epochs`) and this reddens.
    let mut f = fixture();
    let bob_ik = f.bob.identity();
    f.bob.publish(NOW);
    f.alice.connect_with_bundle(&f.bob.bundle()).unwrap();
    f.alice.send(&bob_ik, b"hello", NOW);
    f.bob.receive(NOW).unwrap();

    assert!(matches!(f.alice.send(&bob_ik, b"while you were out", NOW), Response::Accepted));

    // Bob comes back three epochs later — still far inside the 7-day TTL.
    let later = NOW + 3 * DROP_EPOCH_SECS;
    let got = f.bob.receive(later).unwrap();
    let texts: Vec<Vec<u8>> = got.into_iter().flatten().map(|r| r.plaintext).collect();
    assert!(
        texts.contains(&b"while you were out".to_vec()),
        "mail deposited 3 epochs ago is unreachable — the delivery window collapsed to the \
         poll window instead of the relay's TTL"
    );
}

// ---------------------------------------------------------------------------------
// Slice 3b: per-handle path isolation — the layer the rotation was standing on.
// ---------------------------------------------------------------------------------

/// Which leg of a round trip a row came from. Needed because a cookie challenge makes a
/// leg retry, so "the second row" is not "the other leg".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Leg {
    Deposit,
    Fetch,
}

/// One row of the CARRIER's view: which leg, under which handle, asking for which circuit.
type ScopeRow = (Leg, Vec<u8>, Option<String>);

/// A transport that records the isolation SCOPE each request asked for, alongside the
/// handle it used. This is the carrier's view, not the relay's: what a proxy would key a
/// circuit on.
#[derive(Clone)]
struct ScopeTap {
    inner: InMemoryTransport,
    scopes: Rc<RefCell<Vec<ScopeRow>>>,
}

impl Transport for ScopeTap {
    fn send(&self, msg: &WireMessage, now: u64) -> Response {
        self.inner.send(msg, now)
    }
    fn fetch(&self, req: &FetchRequest, now: u64) -> FetchResponse {
        self.inner.fetch(req, now)
    }
    fn send_isolated(&self, msg: &WireMessage, now: u64, scope: Option<&str>) -> Response {
        self.scopes.borrow_mut().push((Leg::Deposit, msg.client_addr.clone(), scope.map(str::to_string)));
        self.inner.send(msg, now)
    }
    fn fetch_isolated(&self, req: &FetchRequest, now: u64, scope: Option<&str>) -> FetchResponse {
        self.scopes.borrow_mut().push((Leg::Fetch, req.client_addr.clone(), scope.map(str::to_string)));
        self.inner.fetch(req, now)
    }
    fn publish_bundle(&self, req: &PublishRequest, now: u64) -> PublishResponse {
        self.inner.publish_bundle(req, now)
    }
    fn fetch_bundle(&self, ik: &[u8; 32], now: u64) -> Result<Option<PreKeyBundle>, String> {
        self.inner.fetch_bundle(ik, now)
    }
}

fn scope_fixture() -> (Peer<ScopeTap>, Peer<ScopeTap>, Rc<RefCell<Vec<ScopeRow>>>) {
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(dev_cap());
    let relay_pub = relay.relay_public();
    let inner = InMemoryTransport::new(Rc::new(RefCell::new(relay)));
    let scopes = Rc::new(RefCell::new(Vec::new()));
    let tap = ScopeTap { inner, scopes: scopes.clone() };
    let alice = Peer::new(tap.clone(), Account::generate(), dev_cap(), relay_pub);
    let bob = Peer::new(tap, Account::generate(), dev_cap(), relay_pub);
    (alice, bob, scopes)
}

#[test]
fn every_handle_asks_for_its_own_circuit() {
    // The point of slice 3b, and the thing that decides whether slices 2 and 3 were real.
    //
    // Handles make two requests unlinkable to the RELAY by construction. Then they arrive
    // over one connection from one source address and the relay relinks them for free —
    // rotating an identifier above the IP means nothing while the IP is shared. So each
    // distinct handle must ask the carrier for a distinct circuit.
    //
    // Neuter `scope_for` to return `None` (or a constant) and this reddens: every request
    // then shares one circuit, which is exactly the state slices 2 and 3 shipped in.
    let (mut alice, mut bob, scopes) = scope_fixture();
    let bob_ik = bob.identity();
    bob.publish(NOW);
    alice.connect_with_bundle(&bob.bundle()).unwrap();
    alice.send(&bob_ik, b"hello", NOW);
    bob.receive(NOW).unwrap();
    alice.send(&bob_ik, b"again", NOW);
    bob.receive(NOW).unwrap();

    let rows = scopes.borrow().clone();
    assert!(rows.len() > 3, "not enough traffic to judge");

    // Every request carries a scope: a `None` anywhere is a request riding the default
    // shared circuit, which is the leak.
    for (_, addr, scope) in &rows {
        assert!(scope.is_some(), "a request under handle {addr:02x?} asked for no isolation");
    }

    // The mapping is a bijection: one handle ↔ one scope. Two handles sharing a scope
    // would share a circuit (relinked); one handle drawing two scopes would burn a new
    // circuit per request, which is churn, not privacy.
    for (_, addr_a, scope_a) in &rows {
        for (_, addr_b, scope_b) in &rows {
            if addr_a == addr_b {
                assert_eq!(scope_a, scope_b, "one handle drew two different circuits");
            } else {
                assert_ne!(scope_a, scope_b, "two distinct handles would share a circuit");
            }
        }
    }
}

#[test]
fn the_scope_handed_to_the_proxy_is_not_the_handle_the_relay_reads() {
    // A proxy operator and a relay operator are different parties, and the design's whole
    // bet is that they cannot join their logs. If the scope WERE the handle, the join is
    // an exact string match — no timing analysis, no inference, just a lookup. So the
    // scope must be derived from the handle, never be it.
    let (mut alice, mut bob, scopes) = scope_fixture();
    let bob_ik = bob.identity();
    bob.publish(NOW);
    alice.connect_with_bundle(&bob.bundle()).unwrap();
    alice.send(&bob_ik, b"hello", NOW);

    for (_, addr, scope) in scopes.borrow().iter() {
        let scope = scope.as_deref().expect("a scope");
        let addr_hex: String = addr.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!addr_hex.contains(scope), "the proxy was handed the relay's own identifier");
    }
}

// ---------------------------------------------------------------------------------
// Slice 5 groundwork: does PIR even FIT? The question is not the cipher.
// ---------------------------------------------------------------------------------

#[test]
fn a_mailbox_payload_is_useless_to_anyone_but_its_recipient() {
    // THE GO/NO-GO FOR PIR, and worth settling before a line of lattice code.
    //
    // Today a fetch names the mailbox and the relay proves ownership with
    // `DH(relay_identity, mailbox)` before it hands anything over. PIR's entire premise is
    // that the client does NOT name the box — so that proof cannot run, and PIR by
    // construction lets a client retrieve any slot it likes. PIR therefore DELETES the
    // access control that fetch-auth provides.
    //
    // Whether that is fatal depends on what fetch-auth was actually protecting. It reads
    // like confidentiality; it is not. Every payload is already sealed to its recipient —
    // ratchet ciphertext, or a `SkeletonSeal` addressed to their identity key — so a slot
    // read by a stranger yields bytes they cannot open. What fetch-auth really protects is
    // DELETION: a fetch DRAINS the mailbox, so without the proof anyone who knew your
    // address could throw your mail away. That is availability, and under PIR the attack
    // is structurally impossible — you cannot target what you cannot name.
    //
    // So: PIR-over-sealed-slots preserves confidentiality without the ownership proof.
    // This test is that claim, executable. If it ever reddens, PIR does not fit and the
    // architecture is wrong — not the crypto.
    let mut f = fixture();
    let bob_ik = f.bob.identity();
    f.bob.publish(NOW);
    f.alice.connect_with_bundle(&f.bob.bundle()).unwrap();
    let alice_ik = f.alice.identity();
    let mut mallory = Peer::new(f.alice_transport(), Account::generate(), dev_cap(), f.relay_pub());

    // Both payload shapes a slot can hold, each inspected WHILE IT IS STILL THERE.
    //
    // Collecting the slots once at the end would have inspected only the second: a fetch
    // DRAINS, so `receive` removes the opener before it can be looked at. The first
    // version of this test did exactly that and, when the opener was un-sealed to check,
    // stayed green — it was asserting the sealed-opener property against a payload that
    // was no longer in the mailbox. Same vacuity as the fast-sender test in audit 3, and
    // caught the same way: by neutering and watching for a red that never came.
    assert!(matches!(f.alice.send(&bob_ik, b"the opener", NOW), Response::Accepted));
    let opener_slots = f.relay_slots();
    assert!(!opener_slots.is_empty(), "the opener must be in the mailbox to be judged");
    f.bob.receive(NOW).unwrap();

    assert!(matches!(f.alice.send(&bob_ik, b"after the opener", NOW), Response::Accepted));
    let later_slots = f.relay_slots();
    assert!(!later_slots.is_empty(), "the post-opener message must be in the mailbox");

    for payload in opener_slots.iter().chain(later_slots.iter()) {
        let bytes = postcard::to_stdvec(payload).expect("a payload encodes");
        // Neither plaintext survives contact with a stranger's eyes.
        assert!(!contains(&bytes, b"the opener"), "plaintext readable from a raw slot");
        assert!(!contains(&bytes, b"after the opener"), "plaintext readable from a raw slot");
        // Nor does either party's identity — the sealed opener's whole job.
        assert!(!contains(&bytes, &alice_ik), "the sender's identity is readable from a raw slot");
        assert!(!contains(&bytes, &bob_ik), "the recipient's identity is readable from a raw slot");
        // And handing it to a real Peer with real keys yields nothing.
        assert!(mallory.open_for_test(payload).is_none(), "a stranger opened a sealed slot");
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------------
// Multi-homing: handles are relay-scoped, so two relays cannot join one account.
// ---------------------------------------------------------------------------------

/// A transport that records the `client_addr` of the LAST publish it carried, so a test
/// can see which handle one account presented to this particular relay.
#[derive(Clone)]
struct PublishTap {
    inner: InMemoryTransport,
    last_addr: Rc<RefCell<Vec<u8>>>,
}

impl Transport for PublishTap {
    fn send(&self, msg: &WireMessage, now: u64) -> Response {
        self.inner.send(msg, now)
    }
    fn fetch(&self, req: &FetchRequest, now: u64) -> FetchResponse {
        self.inner.fetch(req, now)
    }
    fn publish_bundle(&self, req: &PublishRequest, now: u64) -> PublishResponse {
        *self.last_addr.borrow_mut() = req.client_addr.clone();
        self.inner.publish_bundle(req, now)
    }
    fn fetch_bundle(&self, ik: &[u8; 32], now: u64) -> Result<Option<PreKeyBundle>, String> {
        self.inner.fetch_bundle(ik, now)
    }
}

fn relay_with_publish_tap() -> (PublishTap, PublicKey, Rc<RefCell<Vec<u8>>>) {
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(dev_cap());
    let relay_pub = relay.relay_public();
    let last = Rc::new(RefCell::new(Vec::new()));
    let tap = PublishTap { inner: InMemoryTransport::new(Rc::new(RefCell::new(relay))), last_addr: last.clone() };
    (tap, relay_pub, last)
}

#[test]
fn one_account_presents_a_different_handle_to_each_relay() {
    // THE multi-homing security invariant. A user multi-homes across two relays with one
    // identity; those relays, comparing logs, must not be able to join them by a shared
    // `client_addr`. Handles are keyed by relay, so the SAME purpose (publishing your
    // bundle) yields a DIFFERENT handle on each relay — and, critically, importing the
    // state saved against relay 1 does NOT make relay 2 reuse relay 1's handle.
    //
    // Neuter: key handles by `Handle` alone (drop the relay dimension in the maps) →
    // peer2, importing peer1's state, finds the `Identity` handle already set and reuses
    // it → both relays see one `client_addr` → the assert reddens.
    let (tap1, relay1_pub, addr1) = relay_with_publish_tap();
    let (tap2, relay2_pub, addr2) = relay_with_publish_tap();
    let mut peer1 = Peer::new(tap1, Account::generate(), dev_cap(), relay1_pub);
    peer1.publish(NOW);
    let state = peer1.export_state();

    // Second relay, carrying over the persisted state (as a real multi-homing client
    // would: one on-disk PeerState shared across the relays it uses). The account is
    // incidental here — the handle comes from the relay-keyed map, not from the identity,
    // which is exactly why importing relay 1s state must not leak its handle to relay 2.
    let mut peer2 = Peer::new(tap2, Account::generate(), dev_cap(), relay2_pub);
    peer2.import_state(state);
    peer2.publish(NOW);

    let a1 = addr1.borrow().clone();
    let a2 = addr2.borrow().clone();
    assert!(!a1.is_empty() && !a2.is_empty(), "both relays must have seen a publish");
    assert_ne!(a1, a2, "one account presented the SAME handle to two relays — they can join you");
}

#[test]
fn state_saved_against_one_relay_carries_the_others_handles_intact() {
    // Round-trip safety: a Peer bound to relay 2, saving its state back, must NOT drop the
    // handles/cookies belonging to relay 1 — otherwise every poll cycle a multi-homing
    // client would erase the other relay's cached cookies and pay a NeedCookie round trip
    // for them forever.
    let (tap1, relay1_pub, _a1) = relay_with_publish_tap();
    let (tap2, relay2_pub, _a2) = relay_with_publish_tap();
    let mut peer1 = Peer::new(tap1, Account::generate(), dev_cap(), relay1_pub);
    peer1.publish(NOW);
    let state1 = peer1.export_state();

    let mut peer2 = Peer::new(tap2, Account::generate(), dev_cap(), relay2_pub);
    peer2.import_state(state1);
    peer2.publish(NOW);
    let state2 = peer2.export_state();

    // state2 must still contain relay 1's Identity handle AND relay 2's — two distinct
    // relay-scoped entries, neither lost.
    let relays = state2.relay_ids_for_test();
    assert!(relays.contains(&relay1_pub.to_bytes()), "relay 1's handle was dropped on save");
    assert!(relays.contains(&relay2_pub.to_bytes()), "relay 2's handle is missing");
}

#[test]
fn the_sender_does_not_drain_its_own_outbound_before_the_recipient_fetches() {
    // P0 fix, proven. A SINGLE shared box per session let the sender fetch — and thus
    // DRAIN — the very message it deposited for the recipient: if Alice polls before Bob,
    // she pulls her own outbound out of the shared box (she cannot even decrypt it), and
    // Bob then finds nothing. Per-direction boxes fix it: Alice deposits into (A->B) and
    // polls (B->A), so her poll never touches Bob's mail.
    //
    // Discriminating: neuter `direction` to a constant → one shared box → Alice's poll
    // drains it → Bob receives nothing → red.
    let mut f = fixture();
    let bob_ik = f.bob.identity();
    f.bob.publish(NOW);
    f.alice.connect_with_bundle(&f.bob.bundle()).unwrap();
    f.alice.send(&bob_ik, b"opener", NOW);
    f.bob.receive(NOW).unwrap(); // establish Bob's side

    assert!(matches!(f.alice.send(&bob_ik, b"for bob only", NOW), Response::Accepted));

    // Alice polls FIRST — the adversarial order for the shared-box bug.
    let alice_got: Vec<Vec<u8>> =
        f.alice.receive(NOW).unwrap().into_iter().flatten().map(|r| r.plaintext).collect();
    assert!(!alice_got.contains(&b"for bob only".to_vec()), "sender received its own outbound");

    // Bob must STILL get it — Alice's poll must not have drained his box.
    let bob_got: Vec<Vec<u8>> =
        f.bob.receive(NOW).unwrap().into_iter().flatten().map(|r| r.plaintext).collect();
    assert!(
        bob_got.contains(&b"for bob only".to_vec()),
        "the sender drained its own outbound from a shared box before the recipient fetched"
    );
}
