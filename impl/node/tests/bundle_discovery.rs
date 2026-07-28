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
        opk_pub: None,
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
