//! §12 discovery E2E: publish/fetch prekey-bundle у relay + `Peer::connect`
//! через relay. Несущее — граница ДОВЕРИЯ, а не только round-trip:
//! - **composition**: publish → connect-через-relay → рабочая сессия;
//! - **fail-closed**: подмена prekey/KEM (при подлинном IK) → никто не
//!   расшифрует (relay не вычислит root_key) — не тихий частичный успех;
//! - **честная стена (executable-doc)**: подмена самого IK при OOB-непроверенном
//!   `peer_ik` → незаметный MITM на этом слое (почему нужна OOB-проверка IK);
//! - не опубликован → чистая ошибка connect.

use std::cell::RefCell;
use std::rc::Rc;

use admission::capability::{Capability, Quota, Scope};
use node::node::{InMemoryTransport, PublishResponse, RelayNode, Response};
use node::peer::Peer;
use node::pqxdh::{Account, PreKeyBundle};
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

fn peer(t: &InMemoryTransport, relay_pub: PublicKey) -> Peer<InMemoryTransport> {
    Peer::new(t.clone(), Account::generate(), dev_cap(), relay_pub)
}

fn plaintexts(v: Vec<Option<node::peer::Received>>) -> Vec<Vec<u8>> {
    v.into_iter().flatten().map(|r| r.plaintext).collect()
}

#[test]
fn publish_fetch_connect_roundtrip_session_works() {
    let (t, relay_pub) = shared();
    let mut alice = peer(&t, relay_pub);
    let mut bob = peer(&t, relay_pub);
    let bob_ik = bob.identity();
    let alice_ik = alice.identity();

    // Bob публикует свой bundle; Alice забирает его у relay и устанавливает сессию.
    assert!(matches!(bob.publish(NOW), PublishResponse::Published));
    alice.connect(&bob_ik, NOW).expect("connect через relay");

    assert!(matches!(alice.send(&bob_ik, b"hi via discovery", NOW), Response::Accepted));
    assert_eq!(plaintexts(bob.receive(NOW).unwrap()), vec![b"hi via discovery".to_vec()]);

    // Разворот — сессия двунаправленна.
    assert!(matches!(bob.send(&alice_ik, b"ack", NOW), Response::Accepted));
    assert_eq!(plaintexts(alice.receive(NOW).unwrap()), vec![b"ack".to_vec()]);
}

#[test]
fn connect_to_unpublished_ik_errors_cleanly() {
    let (t, relay_pub) = shared();
    let mut alice = peer(&t, relay_pub);
    let ghost = Account::generate().identity_public();
    assert!(alice.connect(&ghost, NOW).is_err(), "нет опубликованного bundle → ошибка, не паника");
}

#[test]
fn redundant_connect_does_not_kill_live_session() {
    // Silent-loss guard: повторный connect к УЖЕ установленному пиру не должен
    // молча заменить живую сессию новым root_key (иначе разговор тихо умрёт).
    let (t, relay_pub) = shared();
    let mut alice = peer(&t, relay_pub);
    let mut bob = peer(&t, relay_pub);
    let bob_ik = bob.identity();

    bob.publish(NOW);
    alice.connect(&bob_ik, NOW).expect("первый connect");
    assert!(matches!(alice.send(&bob_ik, b"one", NOW), Response::Accepted));

    // Повторный connect → Err (не перезапись), сессия жива.
    assert!(alice.connect(&bob_ik, NOW).is_err(), "повторный connect должен отказать, не перезаписать");
    assert!(matches!(alice.send(&bob_ik, b"two", NOW), Response::Accepted));
    assert_eq!(
        plaintexts(bob.receive(NOW).unwrap()),
        vec![b"one".to_vec(), b"two".to_vec()],
        "живая сессия переживает повторный connect"
    );
}

#[test]
fn publish_request_fits_request_frame() {
    // Frame-cap: PublishRequest несёт полный bundle (kem_ek ~1184 Б) — должен
    // влезать в MAX_REQUEST_FRAME (in-process тесты не кадрируют → регресс размера
    // проявился бы только по сокету). Проверяем реальную postcard-длину.
    use node::node::PublishRequest;
    use node::wire::{WireRequest, MAX_REQUEST_FRAME};

    let bundle = Account::generate().prekey_bundle();
    let req = PublishRequest {
        bundle,
        opks: Vec::new(),
        replace_opks: false,
        client_addr: vec![0u8; 32],
        carrier_id: b"mem".to_vec(),
        cookie: None,
        proof: [0u8; 16],
    };
    let wire = WireRequest::PublishBundle(req);
    let len = postcard::to_allocvec(&wire).unwrap().len();
    assert!(len <= MAX_REQUEST_FRAME, "PublishBundle {len} Б должен влезать в {MAX_REQUEST_FRAME}");
}

#[test]
fn swapped_prekey_bundle_is_rejected_by_the_signature() {
    // A relay hands back a bundle with Bob's REAL IK but someone else's prekey/KEM. Before
    // signed prekeys this only failed CLOSED later (nobody could decrypt); now the prekey
    // signature (over prekey ‖ KEM, under the IK) catches the swap EXPLICITLY at connect —
    // an attacker cannot forge it without Bob's identity private key.
    let (t, relay_pub) = shared();
    let mut alice = peer(&t, relay_pub);
    let bob = peer(&t, relay_pub);
    let bob_ik = bob.identity();
    let eve = Account::generate().prekey_bundle();

    let swapped = PreKeyBundle {
        ik_pub: bob_ik,             // Bob's genuine IK
        prekey_pub: eve.prekey_pub, // someone else's prekey
        kem_ek: eve.kem_ek,         // someone else's KEM
        opk: None,
        prekey_sig: eve.prekey_sig, // signed by EVE's IK, not Bob's → cannot verify under bob_ik
        mailbox_pub: eve.mailbox_pub,
    };
    assert!(
        alice.connect_with_bundle(&swapped).is_err(),
        "a prekey/KEM swapped under Bob's IK must be rejected by the signature, not silently accepted"
    );
    assert!(!alice.has_session(&bob_ik), "no session established from a rejected bundle");
}

#[test]
fn ik_swap_is_undetected_mitm_without_oob_verification() {
    // ЧЕСТНАЯ СТЕНА (executable-doc): если Alice доверилась НЕПРОВЕРЕННОМУ IK
    // (узнала «Bob = mallory_ik» из недоверенного каталога/relay), она установит
    // сессию с Mallory, и Mallory прочитает «для Bob». Этот слой этого НЕ ловит —
    // подлинность IK обязана проверяться вне канала (OOB/TOFU). Пиннит стену.
    let (t, relay_pub) = shared();
    let mut alice = peer(&t, relay_pub);
    let mut mallory = peer(&t, relay_pub);
    let mallory_ik = mallory.identity();

    assert!(matches!(mallory.publish(NOW), PublishResponse::Published));
    // Alice ДУМАЕТ, что это Bob (ей подсунули IK Mallory как «Bob»).
    alice.connect(&mallory_ik, NOW).expect("connect");
    assert!(matches!(alice.send(&mallory_ik, b"for bob only", NOW), Response::Accepted));

    assert_eq!(
        plaintexts(mallory.receive(NOW).unwrap()),
        vec![b"for bob only".to_vec()],
        "MITM удаётся, если IK не проверен вне канала — это внешняя стена, не баг слоя"
    );
}

#[test]
fn the_relay_hands_a_distinct_one_time_prekey_to_each_fetcher() {
    // End-to-end: Bob publishes two one-time prekeys; two DIFFERENT initiators each fetch
    // his bundle and open a conversation. Both openers must decrypt — which only happens
    // if each got a DISTINCT OPK. If the relay handed the SAME OPK to both, the second
    // opener's OPK secret is already consumed by the first accept, so the second agreement
    // fails and that message never arrives.
    //
    // Discriminating: neuter `get_bundle` to NOT pop (hand the same OPK every fetch) and
    // the second message is lost → red.
    let (t, relay_pub) = shared();
    let mut bob = peer(&t, relay_pub);
    let bob_ik = bob.identity();

    assert_eq!(bob.add_opks(2).len(), 2, "Bob holds two one-time prekeys");
    assert!(matches!(bob.publish(NOW), PublishResponse::Published));

    let mut alice1 = peer(&t, relay_pub);
    let mut alice2 = peer(&t, relay_pub);
    alice1.connect(&bob_ik, NOW).expect("alice1 fetches a bundle (with an OPK)");
    alice2.connect(&bob_ik, NOW).expect("alice2 fetches a bundle (with a DIFFERENT OPK)");
    assert!(matches!(alice1.send(&bob_ik, b"from alice1", NOW), Response::Accepted));
    assert!(matches!(alice2.send(&bob_ik, b"from alice2", NOW), Response::Accepted));

    let got = plaintexts(bob.receive(NOW).unwrap());
    assert!(got.contains(&b"from alice1".to_vec()), "alice1's opener was lost");
    assert!(
        got.contains(&b"from alice2".to_vec()),
        "alice2's opener was lost — the relay handed out the same OPK twice"
    );
}

#[test]
fn a_fetcher_still_connects_when_the_one_time_prekeys_run_out() {
    // Exhaustion must fall back, not fail: Bob publishes ONE OPK; two initiators fetch. The
    // second gets no OPK (empty batch → 3-DH), and its opener must still arrive.
    let (t, relay_pub) = shared();
    let mut bob = peer(&t, relay_pub);
    let bob_ik = bob.identity();
    bob.add_opks(1);
    bob.publish(NOW);

    let mut a1 = peer(&t, relay_pub);
    let mut a2 = peer(&t, relay_pub);
    a1.connect(&bob_ik, NOW).unwrap();
    a2.connect(&bob_ik, NOW).unwrap(); // no OPK left → 3-DH fallback
    a1.send(&bob_ik, b"one", NOW);
    a2.send(&bob_ik, b"two", NOW);

    let got = plaintexts(bob.receive(NOW).unwrap());
    assert!(got.contains(&b"one".to_vec()) && got.contains(&b"two".to_vec()), "OPK exhaustion broke delivery");
}

/// R2-4 — a client whose own one-time-prekey secrets are gone must be able to CLEAR the relay's
/// queue, not just append to it.
///
/// Publishing used to only append. So after a restored backup or a damaged sidecar the relay kept
/// handing out the OLD public keys — whose secrets no longer existed — and every initiator that
/// received one produced an opener the recipient could not accept: silent, one-sided first-contact
/// failure that looks like the network losing messages. Worse, once 256 stale entries filled the
/// queue, freshly minted keys could not even be stored.
#[test]
fn republishing_with_replace_clears_prekeys_whose_secrets_are_gone() {
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(dev_cap());
    let relay_pub = relay.relay_public();
    let relay = Rc::new(RefCell::new(relay));
    let mut bob = Peer::new(InMemoryTransport::new(relay.clone()), Account::generate(), dev_cap(), relay_pub);
    let bob_ik = bob.bundle().ik_pub;

    // Bob publishes a batch; then his secrets are gone (restored backup / damaged sidecar) and he
    // mints a completely new one, telling the relay to forget the old.
    let first = bob.add_opks(2);
    assert!(matches!(bob.publish_advertising(&first, NOW), PublishResponse::Published));
    let second = bob.add_opks(2);
    assert!(matches!(
        bob.publish_advertising_replacing(&second, true, NOW),
        PublishResponse::Published
    ));

    // Everything the relay now hands out must come from the NEW batch — an old key would produce
    // an opener nobody can accept.
    // Drained through the ADMISSION-GATED path — the public read stopped handing out one-time
    // prekeys entirely (R2-3), so this is the only door they come out of now.
    let mut served = Vec::new();
    loop {
        let mut req = node::node::BundleOpkRequest {
            ik: bob_ik,
            client_addr: format!("drain-{}", served.len()).into_bytes(),
            carrier_id: b"test".to_vec(),
            cookie: None,
            request_nonce: format!("drain-nonce-{}", served.len()).into_bytes(),
            capability_proof: dev_cap().prove(format!("drain-nonce-{}", served.len()).as_bytes(), 0),
        };
        let mut got = None;
        for _ in 0..2 {
            match relay.borrow_mut().handle_fetch_bundle_opk(&req, NOW) {
                node::node::BundleOpkResponse::NeedCookie(c) => req.cookie = Some(c),
                node::node::BundleOpkResponse::Bundle(b) => {
                    got = b;
                    break;
                }
                node::node::BundleOpkResponse::Rejected(e) => panic!("gated fetch rejected: {e}"),
            }
        }
        match got.and_then(|b| b.opk) {
            Some(k) => served.push(k.key),
            None => break,
        }
    }
    assert!(!served.is_empty(), "the new batch is being served");
    for k in &served {
        assert!(second.contains(k), "the relay served a prekey whose secret no longer exists");
        assert!(!first.contains(k), "a stale prekey survived the replace");
    }
}

/// R2-3, THE carrying test. `FetchBundle` was a fully public read with an irreversible side
/// effect: it popped a one-time prekey. Anyone who knew a victim's IK could spend sixteen
/// anonymous fetches — no cookie, no capability, no cost — and every later first contact with
/// that victim silently dropped from 4-DH to 3-DH until their next publish. An honest relay
/// carried out the attack exactly as implemented.
///
/// Discriminating: it drains through the PUBLIC path first, then has a real capability-bearing
/// peer connect, and requires `ForwardSecrecy::Full`. Asserting only "the anonymous fetch returns
/// opk: None" would pass even if the gated path were broken too — the point is that the victim's
/// keys are still THERE for the sender who is entitled to one.
#[test]
fn anonymous_bundle_reads_cannot_drain_a_victims_one_time_prekeys() {
    use node::node::Transport;
    use node::peer::ForwardSecrecy;

    let (t, relay_pub) = shared();
    let mut bob = peer(&t, relay_pub);
    let bob_ik = bob.identity();

    let opks = bob.add_opks(4);
    assert!(matches!(bob.publish_advertising(&opks, NOW), PublishResponse::Published));

    // The drain: many more anonymous reads than Bob has keys.
    for _ in 0..32 {
        let b = t.fetch_bundle(&bob_ik, NOW).unwrap().expect("published");
        assert!(
            b.opk.is_none(),
            "an unauthenticated read handed out a one-time prekey — that is the drain"
        );
    }

    // A legitimate sender, holding a capability, must still get one.
    let mut alice = peer(&t, relay_pub);
    assert_eq!(
        alice.connect(&bob_ik, NOW).unwrap(),
        ForwardSecrecy::Full,
        "anonymous reads consumed the victim's one-time prekeys: the next real sender was pushed \
         down to 3-DH without anyone noticing"
    );
}

/// The other side of the gate: presenting no valid capability must not yield a one-time prekey
/// either. Otherwise the "gate" would only be a different message name.
#[test]
fn a_bundle_opk_fetch_without_a_valid_capability_is_rejected() {
    use node::node::{BundleOpkRequest, BundleOpkResponse, Transport};

    let (t, relay_pub) = shared();
    let mut bob = peer(&t, relay_pub);
    let bob_ik = bob.identity();
    let opks = bob.add_opks(2);
    bob.publish_advertising(&opks, NOW);

    // A forged capability: right shape, wrong secret.
    let forged = Capability { secret: [0x99; 32], ..dev_cap() };
    let nonce = b"forged-nonce".to_vec();
    let mut req = BundleOpkRequest {
        ik: bob_ik,
        client_addr: b"attacker".to_vec(),
        carrier_id: b"test".to_vec(),
        cookie: None,
        request_nonce: nonce.clone(),
        capability_proof: forged.prove(&nonce, 0),
    };
    // First round trip is the cookie challenge; the second is the real verdict.
    let mut verdict = None;
    for _ in 0..2 {
        match t.fetch_bundle_opk(&req, NOW).unwrap() {
            BundleOpkResponse::NeedCookie(c) => req.cookie = Some(c),
            other => {
                verdict = Some(other);
                break;
            }
        }
    }
    match verdict.expect("a verdict after the cookie exchange") {
        BundleOpkResponse::Rejected(_) => {}
        BundleOpkResponse::Bundle(_) => {
            panic!("a forged capability was served a one-time prekey — the gate is decorative")
        }
        BundleOpkResponse::NeedCookie(_) => panic!("persistent cookie challenge"),
    }
}
