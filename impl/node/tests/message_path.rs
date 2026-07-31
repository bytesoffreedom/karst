//! The end-to-end message path Alice → relay → Bob — the first time the pieces of §7 add up to a
//! MESSAGE. The load-bearing part is the layer separation: admission (§7) gates on the credential
//! and is blind to the contents; E2E (the §2.1 skeleton) catches substitution and does not depend
//! on admission. This is the proof that they compose; the rest is detail.

use std::cell::RefCell;
use std::rc::Rc;

use admission::capability::{Capability, Quota, Scope};
use admission::params::EPOCH_DURATION_SECS;
use karst_client_core::demo::{Client, Recipient};
use relay::node::{FetchRequest, FetchResponse, InMemoryTransport, Payload, RelayNode, Response, Transport, WireMessage};
use node::seal::Identity;
use node::protocol::MAX_FETCH_SEALS;
use node::wire::FETCH_CAP;
use x25519_dalek::PublicKey;

const NOW: u64 = 1_000_000;

fn capability(secret: [u8; 32]) -> Capability {
    Capability {
        capability_id: [0xCA; 16],
        scope: Scope::MessageDelivery,
        quota: Quota { max_requests: 100, max_bytes: 1 << 20, window_secs: 600 },
        not_before: 0,
        not_after: u32::MAX,
        secret,
    }
}

/// A relay with an issued capability plus Bob. Returns (relay, bob identity, relay public key).
fn setup() -> (Rc<RefCell<RelayNode>>, Identity, PublicKey) {
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(capability([0x33; 32]));
    let relay_pub = relay.relay_public();
    let bob = Identity::generate();
    (Rc::new(RefCell::new(relay)), bob, relay_pub)
}

#[test]
fn end_to_end_message_delivered() {
    let (relay, bob_id, relay_pub) = setup();
    let transport = InMemoryTransport::new(relay.clone());

    let mut alice = Client::new(transport.clone(), capability([0x33; 32]), b"alice");
    let mut bob = Recipient::new(transport, bob_id, relay_pub);
    let bob_pub = bob.public();
    // A hybrid seal needs the recipient's ML-KEM key too (PRIV-3) — taken from the receiver that
    // will actually open it, which is the whole point: any other key produces an envelope that
    // authenticates and cannot be read.
    let bob_kem = bob.kem_ek().to_vec();

    // Alice sends (the first time, with a cookie round trip inside).
    let resp = alice.send(&bob_pub, &bob_kem, b"hello bob", NOW);
    assert!(matches!(resp, Response::Accepted), "got: {:?}", resp);

    // Bob collects (fetch-auth) and decrypts.
    let msgs = bob.receive(NOW).expect("the fetch must succeed");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].as_deref(), Some(b"hello bob".as_ref()));
}

#[test]
fn cookie_roundtrip_then_cached() {
    // A second message from the same Alice needs no new cookie (it is cached), but still goes
    // through admission and is delivered.
    let (relay, bob_id, relay_pub) = setup();
    let transport = InMemoryTransport::new(relay.clone());
    let mut alice = Client::new(transport.clone(), capability([0x33; 32]), b"alice");
    let mut bob = Recipient::new(transport, bob_id, relay_pub);
    let bob_pub = bob.public();
    // A hybrid seal needs the recipient's ML-KEM key too (PRIV-3) — taken from the receiver that
    // will actually open it, which is the whole point: any other key produces an envelope that
    // authenticates and cannot be read.
    let bob_kem = bob.kem_ek().to_vec();

    assert!(matches!(alice.send(&bob_pub, &bob_kem, b"first", NOW), Response::Accepted));
    assert!(matches!(alice.send(&bob_pub, &bob_kem, b"second", NOW), Response::Accepted));
    let msgs: Vec<_> = bob.receive(NOW).unwrap().into_iter().flatten().collect();
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0], b"first");
    assert_eq!(msgs[1], b"second");
}

// ---------- Load-bearing: the layer separation ----------

/// A "MITM / malicious relay" transport that flips a byte of the sealed payload in flight. It does
/// not touch admission — the proof stays valid.
#[derive(Clone)]
struct TamperTransport {
    inner: InMemoryTransport,
}
impl Transport for TamperTransport {
    fn send(&self, msg: &WireMessage, now: u64) -> Response {
        let mut tampered = msg.clone();
        if let Payload::Skeleton(s) = &mut tampered.payload {
            if !s.ciphertext.is_empty() {
                s.ciphertext[0] ^= 0x01; // substitute the contents
            }
        }
        self.inner.send(&tampered, now)
    }
    fn fetch(&self, req: &FetchRequest, now: u64) -> FetchResponse {
        self.inner.fetch(req, now)
    }
}

#[test]
fn relay_tampering_admitted_but_e2e_rejects() {
    // The admission layer lets it through (the credential is valid and it does not inspect the
    // payload), while E2E catches the substitution: Bob's open() returns None. The node can
    // neither read nor forge the contents — it holds no key.
    let (relay, bob_id, relay_pub) = setup();
    let honest = InMemoryTransport::new(relay.clone());
    let tamper = TamperTransport { inner: honest.clone() };

    let mut alice = Client::new(tamper, capability([0x33; 32]), b"alice");
    let mut bob = Recipient::new(honest, bob_id, relay_pub);
    let bob_pub = bob.public();
    // A hybrid seal needs the recipient's ML-KEM key too (PRIV-3) — taken from the receiver that
    // will actually open it, which is the whole point: any other key produces an envelope that
    // authenticates and cannot be read.
    let bob_kem = bob.kem_ek().to_vec();

    // Admission PASSED despite the payload being substituted in transport.
    assert!(matches!(alice.send(&bob_pub, &bob_kem, b"secret", NOW), Response::Accepted));

    // But decryption fails — the AEAD caught the substitution.
    let msgs = bob.receive(NOW).unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0], None, "a substituted payload must not decrypt");
}

#[test]
fn bad_capability_rejected_regardless_of_content() {
    // A perfectly valid payload but the wrong credential (the secret does not match what the relay
    // issued) → admission refuses, whatever the contents. The other side of the layers being
    // orthogonal.
    let (relay, bob_id, relay_pub) = setup(); // the relay knows the secret 0x33
    let transport = InMemoryTransport::new(relay.clone());
    // The client holds a capability with a DIFFERENT secret.
    let mut mallory = Client::new(transport.clone(), capability([0x99; 32]), b"mallory");
    let mut bob = Recipient::new(transport, bob_id, relay_pub);
    let bob_pub = bob.public();
    // A hybrid seal needs the recipient's ML-KEM key too (PRIV-3) — taken from the receiver that
    // will actually open it, which is the whole point: any other key produces an envelope that
    // authenticates and cannot be read.
    let bob_kem = bob.kem_ek().to_vec();

    let resp = mallory.send(&bob_pub, &bob_kem, b"perfectly valid content", NOW);
    // The reject must be on the credential (Stage 4 crypto) rather than at some other stage —
    // otherwise the test would pass for the wrong reason.
    match &resp {
        Response::Rejected(reason) => assert!(
            reason.contains("Capability") || reason.contains("BadMac") || reason.contains("Crypto"),
            "expected a reject on the credential, got: {}",
            reason
        ),
        other => panic!("expected Rejected, got: {:?}", other),
    }

    // Nothing landed in the mailbox (Bob authenticates, but the fetch is empty).
    assert!(bob.receive(NOW).unwrap().is_empty());
}

#[test]
fn attacker_knowing_pubkey_cannot_drain_mailbox() {
    // Load-bearing for fetch-auth: an attacker knows Bob's public address (it is public) but NOT
    // his private key, so they cannot compute the DH proof and drain the queue. We check not only
    // that it is Rejected but that THE MESSAGE IS STILL THERE (rejected without a drain is the
    // property; checking the response code alone would pass even if the drain had happened).
    // would pass even if the drain had happened).
    let (relay, bob_id, relay_pub) = setup();
    let transport = InMemoryTransport::new(relay.clone());
    let mut alice = Client::new(transport.clone(), capability([0x33; 32]), b"alice");
    let bob_pub = bob_id.public;
    // Bob is built BEFORE the send: he opens this envelope at the end of the test, and a hybrid
    // seal (PRIV-3) has to name HIS ML-KEM key — `Recipient` mints its own, so there is nothing to
    // seal to until it exists. Same ordering the real path has, where a sender fetches the bundle.
    let mut bob = Recipient::new(transport.clone(), bob_id, relay_pub);

    assert!(matches!(
        alice.send(&bob_pub, bob.kem_ek(), b"for bob only", NOW),
        Response::Accepted
    ));

    // The attacker: a cookie handshake against Bob's mailbox, but the proof cannot be forged.
    let mailbox = bob_pub.to_bytes();
    let attacker_req = |cookie| FetchRequest {
        mailbox,
        client_addr: b"attacker".to_vec(),
        carrier_id: b"mem".to_vec(),
        cookie,
        proof: [0xAB; 16], // the wrong proof — the DH without Bob's secret does not match
        own_proof: Vec::new(),
    };
    let cookie = match transport.fetch(&attacker_req(None), NOW) {
        FetchResponse::NeedCookie(c) => c,
        other => panic!("expected a challenge, got something else: {:?}", matches!(other, FetchResponse::Rejected(_))),
    };
    let attack = transport.fetch(&attacker_req(Some(cookie)), NOW);
    assert!(matches!(attack, FetchResponse::Rejected(_)), "a foreign fetch must be rejected");

    // THE POINT: Bob's queue is UNTOUCHED — the legitimate Bob still receives the message.
    let got: Vec<_> = bob.receive(NOW).unwrap().into_iter().flatten().collect();
    assert_eq!(got, vec![b"for bob only".to_vec()], "a foreign fetch must not delete the message");
}

#[test]
fn client_refreshes_cookie_on_expiry() {
    // This checks the CLIENT's cookie refresh: as time passes the cached cookie expires and the
    // server challenges — the client re-obtains one itself and delivery succeeds (rather than
    // "cookie rejected", which would document a bug). NOTE: a fresh cookie here is killed by the
    // 30-second TTL (`COOKIE_TTL_SECS`), which always fires before the epoch grace (600s), so this
    // test does NOT pin the epoch wiring — the epoch clearing the replay filter is pinned
    // separately in admission (`roll_epoch_clears_replay_filter`). This is the client retry.

    let (relay, bob_id, relay_pub) = setup();
    let transport = InMemoryTransport::new(relay.clone());
    let mut alice = Client::new(transport.clone(), capability([0x33; 32]), b"alice");
    let mut bob = Recipient::new(transport, bob_id, relay_pub);
    let bob_pub = bob.public();
    // A hybrid seal needs the recipient's ML-KEM key too (PRIV-3) — taken from the receiver that
    // will actually open it, which is the whole point: any other key produces an envelope that
    // authenticates and cannot be read.
    let bob_kem = bob.kem_ek().to_vec();

    // t0: first contact, handshake, delivery.
    assert!(matches!(alice.send(&bob_pub, &bob_kem, b"m1", NOW), Response::Accepted));

    // Well past the TTL and past the epoch+grace boundary (3 epochs): the cache is stale and the
    // key has rotated.
    let later = NOW + 3 * EPOCH_DURATION_SECS;
    assert!(
        matches!(alice.send(&bob_pub, &bob_kem, b"m2", later), Response::Accepted),
        "delivery must survive the TTL/epoch boundary (the client re-obtains a cookie)"
    );

    let msgs: Vec<_> = bob.receive(later).unwrap().into_iter().flatten().collect();
    assert_eq!(msgs, vec![b"m1".to_vec(), b"m2".to_vec()]);
}

#[test]
fn mailbox_cap_rejects_instead_of_silent_loss() {
    // Invariant: a full mailbox is backpressure at INSERT (MailboxFull), never a
    // silent loss at fetch. Fetch now returns at most one fixed-size page (FETCH_CAP)
    // per poll, so the receiver drains the queue over several polls — but everything
    // accepted is eventually delivered, nothing is dropped.
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(Capability {
        capability_id: [0xCA; 16],
        scope: Scope::MessageDelivery,
        // max_requests with headroom over MAX_FETCH_SEALS, so the test hits the mailbox ceiling
        // rather than the quota.
        quota: Quota { max_requests: (MAX_FETCH_SEALS as u32) + 50, max_bytes: 1 << 24, window_secs: 600 },
        not_before: 0,
        not_after: u32::MAX,
        secret: [0x33; 32],
    });
    let relay_pub = relay.relay_public();
    let relay = Rc::new(RefCell::new(relay));
    let transport = InMemoryTransport::new(relay.clone());
    let mut alice = Client::new(transport.clone(), capability([0x33; 32]), b"alice");
    let mut bob = Recipient::new(transport, Identity::generate(), relay_pub);
    let bob_pub = bob.public();
    // A hybrid seal needs the recipient's ML-KEM key too (PRIV-3) — taken from the receiver that
    // will actually open it, which is the whole point: any other key produces an envelope that
    // authenticates and cannot be read.
    let bob_kem = bob.kem_ek().to_vec();

    for _ in 0..MAX_FETCH_SEALS {
        assert!(matches!(alice.send(&bob_pub, &bob_kem, b"x", NOW), Response::Accepted));
    }
    // Mailbox full -> backpressure, not a silent drop.
    match alice.send(&bob_pub, &bob_kem, b"overflow", NOW) {
        Response::Rejected(r) => assert!(r.contains("MailboxFull"), "got: {r}"),
        other => panic!("expected MailboxFull, got: {:?}", other),
    }
    // Drain over several polls; nothing accepted is lost. Each poll yields at most
    // one page (FETCH_CAP), so a 256-deep mailbox needs ceil(256/16) = 16 polls.
    let mut delivered = 0usize;
    for _ in 0..MAX_FETCH_SEALS {
        let got = bob.receive(NOW).unwrap();
        if got.is_empty() {
            break;
        }
        assert!(got.len() <= FETCH_CAP, "a fetch never returns more than one page");
        delivered += got.len();
    }
    assert_eq!(delivered, MAX_FETCH_SEALS);
}

#[test]
fn a_client_with_the_wrong_capability_secret_is_refused() {
    // The DOOR, proven real. A relay's admission accepts a capability only if the proof
    // was made with the secret the relay issued. This is what makes a Private node
    // invite-only: the invite IS the secret, and without it you do not get in.
    //
    // The relay issues a cap with one secret; Alice holds a cap with the SAME id but a
    // DIFFERENT secret (a forger who knows the public id but not the secret). Every send
    // must be refused — never Accepted.
    //
    // Discriminating: this is the property the whole Public/Private role rests on. If
    // admission stopped verifying the capability MAC (accept anyone), the assert on
    // `Accepted` would fire — red.
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(capability([0x33; 32])); // the real door secret
    let relay_pub = relay.relay_public();
    let bob = Identity::generate();
    let relay = Rc::new(RefCell::new(relay));
    let transport = InMemoryTransport::new(relay);

    // Alice forges: same capability_id, wrong secret.
    let mut alice = Client::new(transport.clone(), capability([0x99; 32]), b"alice");
    let mut bob = Recipient::new(transport, bob, relay_pub);
    let bob_pub = bob.public();
    // A hybrid seal needs the recipient's ML-KEM key too (PRIV-3) — taken from the receiver that
    // will actually open it, which is the whole point: any other key produces an envelope that
    // authenticates and cannot be read.
    let bob_kem = bob.kem_ek().to_vec();

    // The cookie round-trip may succeed (cookies are anti-spoofing, not the door), but the
    // capability check must refuse delivery. Try twice to get past the NeedCookie step.
    let mut accepted = false;
    for _ in 0..3 {
        if matches!(alice.send(&bob_pub, &bob_kem, b"let me in", NOW), Response::Accepted) {
            accepted = true;
            break;
        }
    }
    assert!(!accepted, "a wrong-secret capability was admitted — the door is not real");

    // And nothing landed in Bob's mailbox.
    let msgs = bob.receive(NOW).unwrap_or_default();
    assert!(msgs.iter().flatten().next().is_none(), "a refused message still reached the mailbox");
}

/// R2-7. The transport deliberately does NOT retry a request once it is on the wire: the relay
/// may already have applied it. But the sender's outbox retries later, retransmitting the EXACT
/// same ciphertext with a fresh nonce and capability proof — which admission correctly reads as a
/// new request. Underneath it is the same message, and storing it twice cost the recipient a
/// mailbox slot and the sender quota, while leaving every content type to dedup for itself.
///
/// Discriminating in both directions: the SAME payload deposited twice must leave ONE message,
/// and a DIFFERENT payload must still leave two — a relay that dropped every repeat deposit, or
/// swallowed everything after the first, fails one of the two.
#[test]
fn redepositing_the_same_ciphertext_does_not_duplicate_it_in_the_mailbox() {
    use node::seal::SkeletonSeal;

    let (relay, bob_id, _relay_pub) = setup();
    let bob_pub = bob_id.public;
    let cap = capability([0x33; 32]);
    // ONE recipient KEM key across both seals below: this test is about whether the RELAY
    // deduplicates identical bytes, so the two envelopes must differ only in the plaintext.
    let kem = node::seal::SealKemKeys::generate();

    // ONE sealed envelope, deposited twice — exactly what the outbox retransmits.
    let payload =
        Payload::Skeleton(SkeletonSeal::seal(&bob_pub, kem.ek(), b"same bytes").expect("seals"));

    let deposit = |relay: &Rc<RefCell<RelayNode>>, payload: &Payload, nonce: &[u8]| {
        let mut msg = WireMessage {
            client_addr: b"alice".to_vec(),
            carrier_id: b"test".to_vec(),
            cookie: None,
            request_nonce: nonce.to_vec(),
            capability_proof: cap.prove(nonce, 0),
            recipient: bob_pub.to_bytes(),
            payload: payload.clone(),
        };
        for _ in 0..2 {
            match relay.borrow_mut().handle(&msg, NOW) {
                Response::NeedCookie(c) => msg.cookie = Some(c),
                other => return other,
            }
        }
        panic!("persistent cookie challenge")
    };

    assert!(matches!(deposit(&relay, &payload, b"nonce-1"), Response::Accepted));
    // The retry: same bytes, fresh nonce and proof, as the outbox would send it.
    let again = deposit(&relay, &payload, b"nonce-2");
    assert!(
        matches!(again, Response::Accepted),
        "a retry of an already-stored deposit must be ACCEPTED — the sender cannot tell it from a \
         lost response and would retry forever: {again:?}"
    );
    assert_eq!(
        relay.borrow().mailbox_len_for_test(&bob_pub.to_bytes()),
        1,
        "the same ciphertext was stored twice — one message costing the recipient two mailbox \
         slots and the sender two quota units"
    );

    // Control: a genuinely different message must still land.
    let other = Payload::Skeleton(SkeletonSeal::seal(&bob_pub, kem.ek(), b"different bytes").expect("seals"));
    assert!(matches!(deposit(&relay, &other, b"nonce-3"), Response::Accepted));
    assert_eq!(
        relay.borrow().mailbox_len_for_test(&bob_pub.to_bytes()),
        2,
        "dedup must key on the payload, not swallow every deposit after the first"
    );
}
