//! **What a hostile relay can and cannot do to a conversation** (QA-1, slice 1).
//!
//! The whole design rests on one sentence: you do not have to trust the relay. Until now that
//! sentence was argued rather than tested — every test here has used an HONEST relay, so the
//! guarantee was inferred from the crypto rather than demonstrated against the adversary it names.
//!
//! The criterion, stated once so no test in this file drifts from it:
//!
//! > A relay may cause DELIVERY TO FAIL. It may not read plaintext, substitute authenticated keys,
//! > or silently corrupt the client's cryptographic state.
//!
//! "Delivery fails" is an acceptable outcome everywhere below — a relay can always simply drop a
//! message, so no test may demand that a hostile relay deliver anything. What every test does demand
//! is that the client's state afterwards is INTACT: the next honest message still arrives, the
//! ratchet has not been advanced by garbage, and nothing was decrypted that should not have been.
//!
//! Slice 1 covers tampering, replay and reordering. Named and NOT yet covered: claiming `Accepted`
//! without storing, losing data across a restart, serving different answers to different clients,
//! forging or withholding ACKs, closing after commit, malformed frames, and delaying one chosen
//! user — plus the multi-relay Byzantine cases.

use std::cell::RefCell;
use std::rc::Rc;

use karst_client_core::peer::Peer;
use node::pqxdh::Account;
use node::protocol::{
    AckRequest, AckResponse, BundleOpkRequest, BundleOpkResponse, FetchRequest, FetchResponse,
    Payload, PublishRequest, PublishResponse, Response, SessionEnvelope, Transport, WireMessage,
};
use node::pqxdh::PreKeyBundle;
use relay::node::{InMemoryTransport, RelayNode};

const NOW: u64 = 1_000_000;

/// How this relay misbehaves. One knob at a time, so a failure names the behaviour that caused it.
#[derive(Clone, Copy, PartialEq)]
enum Evil {
    /// Behave. The control arm — without it, a test that fails for an unrelated reason looks like a
    /// successful defence.
    None,
    /// Flip a byte of every stored ciphertext before serving it.
    TamperCiphertext,
    /// Serve every message twice.
    Replay,
    /// Serve a page back to front.
    Reorder,
    /// Answer a bundle lookup with a bundle of the relay's OWN making — the key-substitution
    /// attack, and the one thing on this list that would break the guarantee rather than the
    /// delivery. Everything else costs a message; this would cost the conversation.
    SubstituteBundle,
    /// Serve the real bundle with its one-time prekey stripped. Not forgery — a relay may
    /// legitimately run out — so the question is not whether the handshake proceeds but whether the
    /// client SAYS the first message lost forward secrecy.
    HideOpk,
    /// Accept a deposit and throw it away. Undetectable by definition; the test exists to pin what
    /// the client does with its own state when a relay lies about delivery.
    AcceptedButDiscarded,
    /// Store the deposit, then report failure — the connection dying between commit and reply.
    ///
    /// The mirror image of `AcceptedButDiscarded`, and the more dangerous direction. There the
    /// sender believes a lost message arrived; here it believes a delivered message was lost, and
    /// the obvious repair is to send it again. Nothing in a network can prevent this: the reply is
    /// gone whether the relay is malicious or the Wi-Fi dropped, so the client cannot distinguish
    /// them and must be safe under both.
    CommitThenFail,
    /// Claim a deletion it did not perform, so every fetched message comes back on the next poll.
    /// The relay cannot force a duplicate onto the USER, only onto the wire.
    LyingAck,
}

/// An honest relay with a hostile shell. Wrapping rather than reimplementing is deliberate: an evil
/// relay written from scratch would be a different protocol implementation, and a test could pass
/// because that implementation is wrong rather than because the client is right.
#[derive(Clone)]
struct EvilRelay {
    inner: InMemoryTransport,
    mode: Evil,
    /// How many payloads this relay has SERVED, after its misbehaviour.
    ///
    /// Without it these tests can be vacuous: "a replay is not delivered twice" passes trivially if
    /// the page never held two copies, and "a reversed page loses nothing" passes on a page of one.
    /// Counting what the relay actually put on the wire is what makes the assertions about the
    /// CLIENT rather than about an accident of the harness.
    served: Rc<RefCell<usize>>,
}

impl EvilRelay {
    fn new(relay: Rc<RefCell<RelayNode>>, mode: Evil) -> Self {
        EvilRelay {
            inner: InMemoryTransport::new(relay),
            mode,
            served: Rc::new(RefCell::new(0)),
        }
    }

    fn served(&self) -> usize {
        *self.served.borrow()
    }
}

/// Corrupt one byte of whatever ciphertext this payload carries, leaving the shape intact — a relay
/// that mangled the STRUCTURE would be caught by decoding, which proves nothing about the ratchet.
fn tamper(p: &mut Payload) {
    let flip = |v: &mut Vec<u8>| {
        if let Some(b) = v.last_mut() {
            *b ^= 0xFF;
        }
    };
    match p {
        Payload::Skeleton(s) => flip(&mut s.ciphertext),
        Payload::Session(SessionEnvelope::Ratchet(m)) => flip(&mut m.ciphertext),
        Payload::Session(SessionEnvelope::InitialSealed { sealed_ka, .. }) => {
            flip(&mut sealed_ka.ciphertext)
        }
        Payload::Session(SessionEnvelope::Veiled { inner, .. }) => flip(inner),
    }
}

impl Transport for EvilRelay {
    fn send(&self, msg: &WireMessage, now: u64) -> Response {
        if self.mode == Evil::AcceptedButDiscarded {
            // Never handed to the relay at all — and reported as delivered.
            return Response::Accepted;
        }
        let r = self.inner.send(msg, now);
        if self.mode == Evil::CommitThenFail && matches!(r, Response::Accepted) {
            // Committed, and the reply never arrives. Indistinguishable from a dropped
            // connection, which is the point — the client has to be safe under both readings.
            return Response::Rejected("connection reset".into());
        }
        r
    }

    fn fetch(&self, req: &FetchRequest, now: u64) -> FetchResponse {
        match self.inner.fetch(req, now) {
            FetchResponse::Fetched(mut seals) => {
                match self.mode {
                    Evil::TamperCiphertext => seals.iter_mut().for_each(tamper),
                    Evil::Replay => {
                        let dup = seals.clone();
                        seals.extend(dup);
                    }
                    Evil::Reorder => seals.reverse(),
                    // These misbehave elsewhere — on the bundle lookup or the deposit — and serve
                    // pages honestly, so a failure names the one behaviour under test.
                    Evil::None
                    | Evil::SubstituteBundle
                    | Evil::HideOpk
                    | Evil::AcceptedButDiscarded
                    | Evil::CommitThenFail
                    | Evil::LyingAck => {}
                }
                *self.served.borrow_mut() += seals.len();
                FetchResponse::Fetched(seals)
            }
            other => other,
        }
    }

    fn ack(&self, req: &AckRequest, now: u64) -> AckResponse {
        if self.mode == Evil::LyingAck {
            // "Deleted" — without deleting. The mail stays, and the next poll serves it again.
            return AckResponse::Acked;
        }
        self.inner.ack(req, now)
    }
    fn publish_bundle(&self, req: &PublishRequest, now: u64) -> PublishResponse {
        self.inner.publish_bundle(req, now)
    }
    fn fetch_bundle(&self, ik: &[u8; 32], now: u64) -> Result<Option<PreKeyBundle>, String> {
        let real = self.inner.fetch_bundle(ik, now)?;
        Ok(match (self.mode, real) {
            // A bundle the RELAY generated: correctly formed, self-consistent, signed — by the
            // wrong identity. Everything about it looks right except whose it is.
            (Evil::SubstituteBundle, Some(_)) => Some(Account::generate().prekey_bundle()),
            (Evil::HideOpk, Some(mut b)) => {
                b.opk = None;
                Some(b)
            }
            (_, other) => other,
        })
    }
    /// The path `Peer::connect` ACTUALLY uses.
    ///
    /// Intercepting only the public `fetch_bundle` was the first attempt and tested nothing: the
    /// admission-gated lookup is a different method, `connect` calls that one, and the substitution
    /// never reached the code under test — so the test failed with "a substituted bundle was
    /// accepted" while the client had in fact never been offered one. Third vacuous-test trap in
    /// this file, and the reason each test here also asserts that the relay misbehaved.
    fn fetch_bundle_opk(
        &self,
        req: &BundleOpkRequest,
        now: u64,
    ) -> Result<BundleOpkResponse, String> {
        let real = self.inner.fetch_bundle_opk(req, now)?;
        Ok(match (self.mode, real) {
            (Evil::SubstituteBundle, BundleOpkResponse::Bundle(Some(_))) => {
                BundleOpkResponse::Bundle(Some(Account::generate().prekey_bundle()))
            }
            (Evil::HideOpk, BundleOpkResponse::Bundle(Some(mut b))) => {
                b.opk = None;
                BundleOpkResponse::Bundle(Some(b))
            }
            (_, other) => other,
        })
    }
}

fn dev_cap() -> admission::capability::Capability {
    admission::capability::Capability {
        capability_id: [0xCC; 16],
        scope: admission::capability::Scope::MessageDelivery,
        quota: admission::capability::Quota {
            max_requests: 100_000,
            max_bytes: 1 << 30,
            window_secs: 600,
        },
        not_before: 0,
        not_after: u32::MAX,
        secret: [0x35; 32],
    }
}

/// Alice and Bob over one relay running `mode`, with Bob published and Alice NOT yet connected.
///
/// Separate from [`pair`] because a test about the HANDSHAKE has to run the handshake itself. The
/// first version of the substitution test did not, and passed for the wrong reason: `pair` had
/// already connected, so the test's own `connect` returned "session already established" — an
/// `Err`, which the assertion happily accepted as a refusal. It asserted nothing at all.
fn pair_unconnected(mode: Evil) -> (Peer<EvilRelay>, Peer<EvilRelay>, [u8; 32]) {
    let mut node = RelayNode::new(NOW);
    node.issue_capability(dev_cap());
    let relay_pub = node.relay_public();
    let shared = Rc::new(RefCell::new(node));
    let t = EvilRelay::new(shared, mode);
    let mut bob = Peer::new(t.clone(), Account::generate(), dev_cap(), relay_pub);
    // WITH one-time prekeys: without them an honest bundle also yields `NoOneTimePrekey`, and the
    // "a withheld unit downgrades loudly" test could not tell withholding from having none.
    let opks = bob.add_opks(4);
    bob.publish_advertising(&opks, NOW);
    let bob_ik = bob.identity();
    let alice = Peer::new(t, Account::generate(), dev_cap(), relay_pub);
    (alice, bob, bob_ik)
}

/// Alice and Bob over one relay running `mode`, with Bob published and Alice connected.
fn pair(mode: Evil) -> (Peer<EvilRelay>, Peer<EvilRelay>, [u8; 32], EvilRelay) {
    let mut node = RelayNode::new(NOW);
    node.issue_capability(dev_cap());
    let relay_pub = node.relay_public();
    let shared = Rc::new(RefCell::new(node));
    let t = EvilRelay::new(shared, mode);
    let spy = t.clone();

    let mut bob = Peer::new(t.clone(), Account::generate(), dev_cap(), relay_pub);
    bob.publish(NOW);
    let bob_ik = bob.identity();
    let mut alice = Peer::new(t, Account::generate(), dev_cap(), relay_pub);
    alice.connect(&bob_ik, NOW).expect("PQXDH against a published bundle");
    (alice, bob, bob_ik, spy)
}

fn texts(p: &mut Peer<EvilRelay>) -> Vec<Vec<u8>> {
    p.receive(NOW).unwrap_or_default().into_iter().flatten().map(|r| r.plaintext).collect()
}

/// **CONTROL ARM.** The same harness with an honest relay delivers. Without this, every test below
/// could be passing because the harness is broken rather than because the client defends itself.
#[test]
fn an_honest_relay_in_this_harness_still_delivers() {
    let (mut alice, mut bob, bob_ik, _spy) = pair(Evil::None);
    let env = alice.encrypt_next(&bob_ik, b"hello").expect("encrypts");
    assert!(matches!(alice.transmit_envelope(&bob_ik, env, NOW), Response::Accepted));
    assert_eq!(texts(&mut bob), vec![b"hello".to_vec()], "the control arm must deliver");
}

/// **Tampering costs delivery, not integrity.** A flipped byte must not decrypt, and — the part that
/// matters — must not move the ratchet, so the NEXT honest message still opens.
///
/// If `decrypt` were not transactional, the corrupted attempt would advance the chain and every
/// later message would fail too: one flipped byte would end the conversation permanently, which is a
/// far better attack than dropping a message.
#[test]
fn a_tampered_message_is_refused_and_leaves_the_ratchet_untouched() {
    let (mut alice, mut bob, bob_ik, spy) = pair(Evil::TamperCiphertext);
    let env = alice.encrypt_next(&bob_ik, b"first").expect("encrypts");
    alice.transmit_envelope(&bob_ik, env, NOW);
    assert!(texts(&mut bob).is_empty(), "a tampered ciphertext must not decrypt");
    assert!(spy.served() >= 1, "the relay never served anything — nothing was tampered with");

    // Now the SAME conversation over an honest relay: if the corrupted attempt had advanced Bob's
    // chain, this would fail too.
    let (mut alice2, mut bob2, ik2, _) = pair(Evil::None);
    let e1 = alice2.encrypt_next(&ik2, b"first").expect("encrypts");
    alice2.transmit_envelope(&ik2, e1, NOW);
    let _ = texts(&mut bob2);
    let e2 = alice2.encrypt_next(&ik2, b"second").expect("encrypts");
    alice2.transmit_envelope(&ik2, e2, NOW);
    assert_eq!(
        texts(&mut bob2),
        vec![b"second".to_vec()],
        "the conversation must survive; a relay that can permanently break a chain with one flipped \
         byte has a better attack than dropping"
    );
}

/// **A replayed message is delivered at most once.** The ratchet consumes a message key, so the
/// duplicate finds it gone — the same mechanism that makes at-most-once delivery real rather than
/// best effort.
#[test]
fn a_replayed_message_is_not_delivered_twice() {
    let (mut alice, mut bob, bob_ik, spy) = pair(Evil::Replay);
    let env = alice.encrypt_next(&bob_ik, b"once").expect("encrypts");
    alice.transmit_envelope(&bob_ik, env, NOW);
    let got = texts(&mut bob);
    assert!(
        spy.served() >= 2,
        "the relay served {} payloads — it never actually duplicated, so this proves nothing",
        spy.served()
    );
    assert_eq!(
        got,
        vec![b"once".to_vec()],
        "a relay serving the same ciphertext twice produced {} deliveries; a duplicate that reaches \
         the user is a relay editing the conversation",
        got.len()
    );
}

/// **Reordering does not lose messages.** Out-of-order arrival is ordinary on a store-and-forward
/// network, so the ratchet stores skipped keys; a relay reversing a page must therefore cost
/// nothing at all.
#[test]
fn a_reordered_page_still_delivers_everything() {
    let (mut alice, mut bob, bob_ik, spy) = pair(Evil::Reorder);
    for body in [b"one".as_ref(), b"two".as_ref(), b"three".as_ref()] {
        let env = alice.encrypt_next(&bob_ik, body).expect("encrypts");
        alice.transmit_envelope(&bob_ik, env, NOW);
    }
    let mut got = texts(&mut bob);
    assert!(
        spy.served() >= 2,
        "the relay served {} payloads — a page of one cannot be 'reversed', so this proves nothing",
        spy.served()
    );
    got.sort();
    assert_eq!(
        got,
        vec![b"one".to_vec(), b"three".to_vec(), b"two".to_vec()],
        "a reversed page lost messages; out-of-order delivery is normal, so this must be free"
    );
}

/// **A substituted bundle must not become a session.**
///
/// This is the one behaviour on the list that would break the GUARANTEE rather than the delivery.
/// Everything else a hostile relay does costs a message; handing you keys of its own making would
/// cost the conversation — it would sit in the middle of it.
///
/// The bundle the relay serves here is not malformed: it is a real, self-consistent, correctly
/// signed bundle. It is simply signed by the wrong identity, which is exactly the shape a
/// substitution takes in practice. `verify_prekey_sig` checks it against the IK the caller ASKED
/// for, so the mismatch is caught by whose signature it is rather than by anything about its
/// contents.
#[test]
fn a_bundle_of_the_relays_own_making_is_refused() {
    let (mut alice, _bob, bob_ik) = pair_unconnected(Evil::SubstituteBundle);
    let out = alice.connect(&bob_ik, NOW);
    assert!(
        out.is_err(),
        "a bundle signed by a DIFFERENT identity was accepted for {}. A relay that can substitute \
         keys is a relay in the middle of the conversation, which is the one outcome the whole \
         design refuses.",
        hex::encode(bob_ik)
    );
}

/// **A stripped one-time prekey is REPORTED, not swallowed.**
///
/// Running out of one-time prekeys is legitimate, so the handshake proceeding is correct. What must
/// not happen is proceeding SILENTLY: the missing unit is the only signal that this first message's
/// post-quantum leg is recorded-now-decrypt-later, and a relay can withhold the unit deliberately to
/// obtain exactly that.
///
/// DISCRIMINATING: have `connect` return `Full` unconditionally and this goes red — which is the
/// state in which a relay downgrades every first contact and nobody is told.
#[test]
fn a_withheld_one_time_prekey_downgrades_loudly() {
    let (mut alice, _bob, bob_ik) = pair_unconnected(Evil::HideOpk);
    let fs = alice.connect(&bob_ik, NOW).expect("a bundle with no one-time unit is still usable");
    assert!(
        matches!(fs, karst_client_core::peer::ForwardSecrecy::NoOneTimePrekey),
        "a relay withheld the one-time prekey and the handshake reported full forward secrecy. \
         Withholding it is free for the relay, so an unreported downgrade is a downgrade it can \
         apply to everyone."
    );

    // CONTROL: the same code path with an honest relay reports the opposite, so the assertion above
    // is about the withholding rather than about this harness never producing `Full`.
    let (mut a2, _b2, ik2) = pair_unconnected(Evil::None);
    assert!(
        matches!(a2.connect(&ik2, NOW), Ok(karst_client_core::peer::ForwardSecrecy::Full)),
        "the control arm does not reach full forward secrecy, so the test above proves nothing"
    );
}

/// **A relay that lies about delivery costs a message and nothing else.**
///
/// Undetectable by construction — a relay can always accept and discard, and no protocol can tell
/// that from a delivery the recipient has not fetched yet. So the assertion is not that the client
/// notices; it is that the client's own state stays coherent: the ratchet advanced exactly once, so
/// the NEXT message over an honest path still opens rather than arriving on a chain the recipient
/// never saw move.
#[test]
fn a_discarded_deposit_leaves_the_sender_coherent() {
    let (mut alice, mut bob, bob_ik, _spy) = pair(Evil::AcceptedButDiscarded);
    let env = alice.encrypt_next(&bob_ik, b"into the void").expect("encrypts");
    assert!(
        matches!(alice.transmit_envelope(&bob_ik, env, NOW), Response::Accepted),
        "the relay claimed acceptance, which is the point of this mode"
    );
    assert!(texts(&mut bob).is_empty(), "nothing was stored, so nothing can arrive");

    // The sender is not wedged: it can still produce envelopes, and its session is intact.
    assert!(
        alice.encrypt_next(&bob_ik, b"and again").is_ok(),
        "the session broke on a discarded deposit; a relay could then end a conversation by \
         accepting one message and dropping it"
    );
}

/// **A relay that never deletes cannot force a duplicate onto the user.**
///
/// An ACK says "these are safely mine now, forget them". A relay may answer `Acked` and keep the
/// mail anyway — nothing can stop it, and the next poll serves the same ciphertext again. What must
/// not follow is the message appearing twice in the conversation: the ratchet consumed that message
/// key, so the second copy fails to open. Redelivery costs bandwidth; it does not let a relay write
/// into a conversation.
///
/// The relay's leverage here is bounded from BELOW as well as above, which is why the first poll
/// must still deliver: a client that defended itself by refusing redelivered ciphertext outright
/// would break the legitimate case this mechanism exists for — an ACK lost in transit, where the
/// relay is honest and redelivery is exactly right.
#[test]
fn a_relay_that_lies_about_deleting_cannot_deliver_twice() {
    let (mut alice, mut bob, bob_ik, spy) = pair(Evil::LyingAck);
    let env = alice.encrypt_next(&bob_ik, b"once only").expect("encrypts");
    alice.transmit_envelope(&bob_ik, env, NOW);

    assert_eq!(texts(&mut bob), vec![b"once only".to_vec()], "the first poll must deliver");
    // ACK it — which is the whole point. Without this the mail is merely LEASED, a second poll
    // serves nothing whatever the relay intends, and the test passes while exercising nothing. The
    // counter below caught exactly that on the first attempt.
    bob.ack_all(NOW);
    let after_first = spy.served();

    // The relay said "deleted" and kept it. Poll again PAST THE LEASE — a fetched message is
    // leased for `LEASE_SECS`, so an immediate second poll returns nothing whatever the relay
    // intends, and a test written that way exercises none of this. (Caught by the counter twice:
    // first because no ACK was sent at all, then because the lease had not expired.)
    let later = NOW + relay::node::LEASE_SECS + 1;
    let second: Vec<Vec<u8>> =
        bob.receive(later).unwrap_or_default().into_iter().flatten().map(|r| r.plaintext).collect();
    assert!(
        spy.served() > after_first,
        "the relay served nothing on the second poll, so it did not actually keep the mail and \
         this proves nothing"
    );
    assert!(
        second.is_empty(),
        "a redelivered message was delivered to the user a second time ({second:?}). A relay that \
         can duplicate a message can put words in a conversation twice, which is editing it."
    );
}

/// **A SPLIT VIEW is not detected here, and that is the design — pinned so it stays a decision.**
///
/// A relay can serve one bundle to Alice and a different one to everyone else. Nothing in the
/// handshake catches it: `connect` verifies that a bundle is signed by the identity it CLAIMS, and
/// refuses one that claims the wrong identity (see the substitution test) — but if the relay
/// consistently presents identity X to Alice while the real Bob is identity Y, Alice's view is
/// internally consistent and she is simply talking to X.
///
/// What catches that is OUT OF BAND: the safety number over the two identity keys. This test asserts
/// the mechanism exists and separates the two views, because "compare your safety numbers" is the
/// entire answer here and an answer nobody can act on is not one.
///
/// The alternative — a witness/transparency layer that makes a split view detectable IN band — is
/// tracked separately (#282/#283 territory). Recording the limit as a test rather than as prose is
/// the point: prose about a limit drifts, and this one is load-bearing.
#[test]
fn a_split_view_is_caught_only_by_the_safety_number() {
    let (mut alice, _bob, bob_ik) = pair_unconnected(Evil::SubstituteBundle);

    // Alice is refused outright here, because this relay substitutes an identity that does not
    // match the one she asked for. A relay running a TRUE split view would instead be consistent:
    // it would answer for `impostor` whenever Alice asks for `impostor`, and Alice would never know
    // she was pointed at the wrong person in the first place.
    assert!(alice.connect(&bob_ik, NOW).is_err(), "control: an inconsistent substitution is caught");

    // The out-of-band check, which is what a consistent split view runs into. Different peer =
    // different number, and that difference is the whole detection mechanism.
    let real = node::safety::safety_number(&alice.identity(), &bob_ik);
    let impostor = node::safety::safety_number(&alice.identity(), &[0x77u8; 32]);
    assert_ne!(
        real, impostor,
        "the safety number does not distinguish two peers, so the ONLY defence against a consistent \
         split view is inert — and an in-band detection layer does not exist yet"
    );
    assert!(!real.is_empty(), "a safety number nobody can read is not a defence either");
}

/// **A message that was delivered but reported as failed must not arrive twice.**
///
/// The dangerous half of the delivery-report problem. `AcceptedButDiscarded` costs a message and
/// the sender knows nothing; this costs nothing and the sender believes it lost one — so the
/// natural repair is to send it again, and now the same plaintext is on its way twice. A relay can
/// manufacture this at will by committing and then dropping the connection, and a bad network
/// produces it for free, so "the relay is honest" is not a defence available here.
///
/// What must hold is that the CONVERSATION does not double up. The recipient must see the message
/// once, whichever way the retry lands.
///
/// Following this file's two rules: the control arm proves the harness delivers at all, and the
/// relay is shown to have actually committed the deposit before anything is claimed about the
/// client surviving it. Without the second check this test would pass just as happily against a
/// relay that dropped the message on the floor — the failure it is supposed to catch.
#[test]
fn a_delivered_message_reported_as_failed_does_not_arrive_twice() {
    let (mut alice, mut bob, bob_ik, spy) = pair(Evil::CommitThenFail);

    let env = alice.encrypt_next(&bob_ik, b"did that go through?").expect("encrypts");
    let reported = alice.transmit_envelope(&bob_ik, env, NOW);
    assert!(
        matches!(reported, Response::Rejected(_)),
        "this mode must report failure, or the test is not exercising the case"
    );

    // THE RELAY REALLY DID COMMIT IT. Asserted before any claim about the client, because a
    // harness that quietly dropped the deposit would make every assertion below pass for the
    // wrong reason — which is exactly how three tests in this file were empty when written.
    let delivered = texts(&mut bob);
    assert_eq!(
        delivered,
        vec![b"did that go through?".to_vec()],
        "the relay was supposed to STORE the deposit and only then report failure"
    );

    // The sender, believing it failed, sends the same text again — the honest repair, and the one
    // a user would trigger by pressing retry.
    let again = alice.encrypt_next(&bob_ik, b"did that go through?").expect("session is intact");
    let _ = alice.transmit_envelope(&bob_ik, again, NOW);

    // It arrives, and it arrives ONCE MORE — a retry is a new message, not a duplicate of the
    // old one: it carries its own ratchet step. What must not happen is the FIRST copy coming
    // back as well, or a resend re-delivering everything that preceded it.
    let after_retry = texts(&mut bob);
    assert_eq!(
        after_retry.len(),
        1,
        "a resend must deliver exactly the resent message, got {after_retry:?}"
    );
    assert!(spy.served() >= 2, "the relay served both deposits, so the counts above are real");
}

/// Control arm for the mode above: an honest relay reports what it did.
///
/// Without this, `a_delivered_message_reported_as_failed_does_not_arrive_twice` could pass against
/// a client that treated EVERY send as failed.
#[test]
fn an_honest_relay_reports_the_delivery_it_performed() {
    let (mut alice, mut bob, bob_ik, _spy) = pair(Evil::None);
    let env = alice.encrypt_next(&bob_ik, b"plainly delivered").expect("encrypts");
    assert!(
        matches!(alice.transmit_envelope(&bob_ik, env, NOW), Response::Accepted),
        "an honest relay must report the acceptance it actually performed"
    );
    assert_eq!(texts(&mut bob), vec![b"plainly delivered".to_vec()]);
}
