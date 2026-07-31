//! The §2.1 session E2E: PQXDH plus the Double Ratchet over the REAL message path (admission §7 →
//! mailbox → fetch-auth), through `karst_client_core::peer::Peer`.
//!
//! Load-bearing (not a single round trip, which would touch neither the chain nor the
//! Initial→Ratchet transition): MULTIPLE messages in BOTH directions through a real mailbox with a
//! batch fetch, the first envelope `Initial` and then `Ratchet`, plus a SECOND send→fetch round
//! that continues THE SAME session (the chains survive fetches). Along the way it pins the seam:
//! the PQXDH `root_key` really seeds a working ratchet session.

use std::cell::RefCell;
use std::rc::Rc;

use admission::capability::{Capability, Quota, Scope};
use relay::node::{FetchRequest, FetchResponse, InMemoryTransport, Payload, RelayNode, Response, SessionEnvelope, Transport, WireMessage};
use karst_client_core::peer::Peer;
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

/// A shared relay and transport on which the test brings up as many peers as it needs.
fn shared() -> (InMemoryTransport, PublicKey) {
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(dev_cap());
    let relay_pub = relay.relay_public();
    (InMemoryTransport::new(Rc::new(RefCell::new(relay))), relay_pub)
}

fn peer(transport: &InMemoryTransport, relay_pub: PublicKey) -> Peer<InMemoryTransport> {
    Peer::new(transport.clone(), Account::generate(), dev_cap(), relay_pub)
}

/// Only the non-`None` decryptions, in order.
fn plaintexts(v: Vec<Option<karst_client_core::peer::Received>>) -> Vec<Vec<u8>> {
    v.into_iter().flatten().map(|r| r.plaintext).collect()
}

#[test]
fn bidirectional_multi_message_across_fetches() {
    let (transport, relay_pub) = shared();
    let mut alice = peer(&transport, relay_pub);
    let mut bob = peer(&transport, relay_pub);
    let bob_ik = bob.identity();
    let alice_ik = alice.identity();

    // Alice initiates a session to Bob from his bundle (out of band — §12 is deferred).
    alice.connect_with_bundle(&bob.bundle()).unwrap();

    // --- Round 1: Alice → Bob, two messages (Initial then Ratchet) ---
    assert!(matches!(alice.send(&bob_ik, b"m0", NOW), Response::Accepted));
    assert!(matches!(alice.send(&bob_ik, b"m1", NOW), Response::Accepted));

    let got = plaintexts(bob.receive(NOW).expect("bob fetch"));
    assert_eq!(got, vec![b"m0".to_vec(), b"m1".to_vec()], "batch fetch: Initial+Ratchet in order");

    // --- Bob replies (over the established session — a DH ratchet at both ends) ---
    assert!(matches!(bob.send(&alice_ik, b"r0", NOW), Response::Accepted));
    let got = plaintexts(alice.receive(NOW).expect("alice fetch"));
    assert_eq!(got, vec![b"r0".to_vec()], "the reply decrypted (Alice takes a DH step)");

    // --- Round 2: Alice continues THE SAME session through a new fetch cycle ---
    // (Alice already moved to chain B by receiving r0 → this is a ratchet boundary crossing.)
    assert!(matches!(alice.send(&bob_ik, b"m2", NOW), Response::Accepted));
    assert!(matches!(alice.send(&bob_ik, b"m3", NOW), Response::Accepted));
    let got = plaintexts(bob.receive(NOW).expect("bob fetch 2"));
    assert_eq!(got, vec![b"m2".to_vec(), b"m3".to_vec()], "the chains survive fetches");

    // --- And one more reversal: Bob → Alice again ---
    assert!(matches!(bob.send(&alice_ik, b"r1", NOW), Response::Accepted));
    let got = plaintexts(alice.receive(NOW).expect("alice fetch 2"));
    assert_eq!(got, vec![b"r1".to_vec()]);
}

#[test]
fn receive_attributes_sender_across_two_peers() {
    // Load-bearing (attribution): two different senders → Bob; every incoming message must carry
    // the CORRECT sender IK (so the UI can sort them into chats). An Initial carries the IK in the
    // KA; a Ratchet is attributed by the session that decrypted it.
    let (transport, relay_pub) = shared();
    let mut alice = peer(&transport, relay_pub);
    let mut carol = peer(&transport, relay_pub);
    let mut bob = peer(&transport, relay_pub);
    let (alice_ik, carol_ik, bob_ik) = (alice.identity(), carol.identity(), bob.identity());

    alice.connect_with_bundle(&bob.bundle()).unwrap();
    carol.connect_with_bundle(&bob.bundle()).unwrap();
    assert!(matches!(alice.send(&bob_ik, b"from alice", NOW), Response::Accepted));
    assert!(matches!(carol.send(&bob_ik, b"from carol", NOW), Response::Accepted));

    let mut got: Vec<(Vec<u8>, Vec<u8>)> = bob
        .receive(NOW)
        .unwrap()
        .into_iter()
        .flatten()
        .map(|r| (r.sender.to_vec(), r.plaintext))
        .collect();
    got.sort();
    let mut want = vec![
        (alice_ik.to_vec(), b"from alice".to_vec()),
        (carol_ik.to_vec(), b"from carol".to_vec()),
    ];
    want.sort();
    assert_eq!(got, want, "every incoming message is attributed to the right sender");
}

#[test]
fn recipient_only_sees_own_mailbox_and_eve_gets_nothing() {
    // Mailbox isolation: Alice sends to Bob; Eve (a third peer) collects HER OWN mailbox and finds
    // it empty. Bob's payload is unreachable for her (addressed to Bob's ik, sitting in his box).
    let (transport, relay_pub) = shared();
    let mut alice = peer(&transport, relay_pub);
    let mut bob = peer(&transport, relay_pub);
    let mut eve = peer(&transport, relay_pub);

    alice.connect_with_bundle(&bob.bundle()).unwrap();
    assert!(matches!(alice.send(&bob.identity(), b"secret", NOW), Response::Accepted));

    assert!(plaintexts(eve.receive(NOW).expect("eve fetch")).is_empty(), "Eve does not see a foreign mailbox");
    assert_eq!(plaintexts(bob.receive(NOW).expect("bob fetch")), vec![b"secret".to_vec()]);
}

/// A "tap" transport: it refuses the FIRST send and lets everything through afterwards, recording
/// every WireMessage that left (the ciphertext is ALREADY at the relay, in the threat model).
#[derive(Clone)]
struct TapTransport {
    inner: InMemoryTransport,
    sent: Rc<RefCell<Vec<WireMessage>>>,
    reject_next: Rc<RefCell<bool>>,
}
impl Transport for TapTransport {
    fn send(&self, msg: &WireMessage, now: u64) -> Response {
        self.sent.borrow_mut().push(msg.clone());
        if std::mem::replace(&mut *self.reject_next.borrow_mut(), false) {
            return Response::Rejected("tap: first send rejected".into());
        }
        self.inner.send(msg, now)
    }
    fn fetch(&self, req: &FetchRequest, now: u64) -> FetchResponse {
        self.inner.fetch(req, now)
    }
}

#[test]
fn failed_send_never_reuses_ratchet_position() {
    // LOAD-BEARING (keystream reuse): the chain advances unconditionally, so we prove that after a
    // REFUSED send the next (different) plaintext does NOT take the same chain position. A zero
    // nonce is safe only with a unique mk per message — this pins that a refusal does not
    // resurrect an mk.
    let (transport, relay_pub) = shared();
    let tap = TapTransport {
        inner: transport,
        sent: Rc::new(RefCell::new(Vec::new())),
        reject_next: Rc::new(RefCell::new(true)),
    };
    let mut alice = Peer::new(tap.clone(), Account::generate(), dev_cap(), relay_pub);
    let bob = Peer::new(tap.inner.clone(), Account::generate(), dev_cap(), relay_pub);
    let bob_ik = bob.identity();

    alice.connect_with_bundle(&bob.bundle()).unwrap();
    // The first cookie challenge goes through (it is not counted as reject_next — NeedCookie is
    // not our reject). reject_next fires on the first real send frame.
    let _ = alice.send(&bob_ik, b"AAAA", NOW); // refused by the tap
    let _ = alice.send(&bob_ik, b"BBBB", NOW); // a different plaintext

    // The invariant: the same position `(dh,n)` implies the same ciphertext (a cookie retry
    // legitimately resends THE SAME envelope). Different plaintexts MUST take different positions
    // — otherwise one `mk` and a zero nonce cover two texts (keystream reuse).
    let mut seen: std::collections::HashMap<([u8; 32], u32), Vec<u8>> =
        std::collections::HashMap::new();
    for m in tap.sent.borrow().iter() {
        if let Payload::Session(env) = &m.payload {
            // PRIV-4: ordinary envelopes ride the wire VEILED for one relay, so the header this
            // invariant is about is inside. Unveil with the sender's own session seed — skipping
            // veiled envelopes instead would leave this test inspecting only openers while still
            // passing, which is the failure mode of a test that stopped testing.
            let unveiled: Option<SessionEnvelope> = match env {
                SessionEnvelope::Veiled { nonce, inner } => {
                    let st = alice.export_state();
                    let (out, inb) = st.debug_peers();
                    out.iter()
                    .chain(inb.iter())
                    .filter_map(|(_, seed)| node::veil::unveil(seed, nonce, inner))
                    .filter_map(|b| postcard::from_bytes::<SessionEnvelope>(&b).ok())
                    .find(|e| matches!(e, SessionEnvelope::Ratchet(_)))
                }
                _ => None,
            };
            let env = unveiled.as_ref().unwrap_or(env);
            let (h, ct) = match env {
                SessionEnvelope::InitialSealed { msg, .. } => (msg.header, msg.ciphertext.clone()),
                SessionEnvelope::Ratchet(msg) => (msg.header, msg.ciphertext.clone()),
                SessionEnvelope::Veiled { .. } => {
                    panic!("a veiled envelope could not be unveiled with any held session seed")
                }
            };
            match seen.get(&(h.dh, h.n)) {
                Some(prev) => assert_eq!(
                    *prev, ct,
                    "position (dh,n) reused under a DIFFERENT ciphertext → keystream reuse"
                ),
                None => {
                    seen.insert((h.dh, h.n), ct);
                }
            }
        }
    }
    let ns: std::collections::BTreeSet<u32> = seen.keys().map(|(_, n)| *n).collect();
    assert!(ns.contains(&0) && ns.contains(&1), "both plaintexts were emitted at different positions");
}
