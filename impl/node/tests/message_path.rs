//! Сквозной путь сообщения Alice → relay → Bob — первый раз, когда куски §7
//! складываются в СООБЩЕНИЕ. Несущее — разделение слоёв: admission (§7) гейтит
//! по credential и слеп к содержимому; E2E (§2.1-скелет) ловит подмену и не
//! зависит от допуска. Это доказательство композиции, остальное — обвязка.

use std::cell::RefCell;
use std::rc::Rc;

use admission::capability::{Capability, Quota, Scope};
use admission::params::EPOCH_DURATION_SECS;
use node::node::{
    Client, FetchRequest, FetchResponse, InMemoryTransport, Payload, Recipient, RelayNode,
    Response, Transport, WireMessage,
};
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

/// Relay с выданной capability + Bob. Возвращает (relay, bob-identity, relay-pub).
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

    // Alice шлёт (первый раз — с cookie round-trip внутри).
    let resp = alice.send(&bob_pub, b"hello bob", NOW);
    assert!(matches!(resp, Response::Accepted), "получено: {:?}", resp);

    // Bob забирает (fetch-auth) и расшифровывает.
    let msgs = bob.receive(NOW).expect("fetch должен пройти");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].as_deref(), Some(b"hello bob".as_ref()));
}

#[test]
fn cookie_roundtrip_then_cached() {
    // Второе сообщение той же Alice уже не требует нового cookie (кэширован),
    // но всё равно проходит admission и доставляется.
    let (relay, bob_id, relay_pub) = setup();
    let transport = InMemoryTransport::new(relay.clone());
    let mut alice = Client::new(transport.clone(), capability([0x33; 32]), b"alice");
    let mut bob = Recipient::new(transport, bob_id, relay_pub);
    let bob_pub = bob.public();

    assert!(matches!(alice.send(&bob_pub, b"first", NOW), Response::Accepted));
    assert!(matches!(alice.send(&bob_pub, b"second", NOW), Response::Accepted));
    let msgs: Vec<_> = bob.receive(NOW).unwrap().into_iter().flatten().collect();
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0], b"first");
    assert_eq!(msgs[1], b"second");
}

// ---------- Несущее: разделение слоёв ----------

/// Транспорт-«MITM/злонамеренный relay», флипающий байт запечатанного груза в
/// пути. Admission он не трогает — proof остаётся валидным.
#[derive(Clone)]
struct TamperTransport {
    inner: InMemoryTransport,
}
impl Transport for TamperTransport {
    fn send(&self, msg: &WireMessage, now: u64) -> Response {
        let mut tampered = msg.clone();
        if let Payload::Skeleton(s) = &mut tampered.payload {
            if !s.ciphertext.is_empty() {
                s.ciphertext[0] ^= 0x01; // подмена содержимого
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
    // Слой допуска пропускает (credential валиден, груз он не проверяет), но
    // E2E ловит подмену: Bob'ов open() возвращает None. Узел не может ни
    // прочитать, ни подделать содержимое — ключа у него нет.
    let (relay, bob_id, relay_pub) = setup();
    let honest = InMemoryTransport::new(relay.clone());
    let tamper = TamperTransport { inner: honest.clone() };

    let mut alice = Client::new(tamper, capability([0x33; 32]), b"alice");
    let mut bob = Recipient::new(honest, bob_id, relay_pub);
    let bob_pub = bob.public();

    // Admission ПРОШЁЛ, несмотря на подмену груза в транспорте.
    assert!(matches!(alice.send(&bob_pub, b"secret", NOW), Response::Accepted));

    // Но расшифровка проваливается — подмену поймал AEAD.
    let msgs = bob.receive(NOW).unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0], None, "подменённый груз не должен расшифроваться");
}

#[test]
fn bad_capability_rejected_regardless_of_content() {
    // Идеально валидный груз, но credential не тот (секрет не совпадает с
    // выданным relay) → допуск отклоняет, независимо от содержимого. Обратная
    // сторона ортогональности слоёв.
    let (relay, bob_id, relay_pub) = setup(); // relay знает секрет 0x33
    let transport = InMemoryTransport::new(relay.clone());
    // Клиент держит capability с ДРУГИМ секретом.
    let mut mallory = Client::new(transport.clone(), capability([0x99; 32]), b"mallory");
    let mut bob = Recipient::new(transport, bob_id, relay_pub);
    let bob_pub = bob.public();

    let resp = mallory.send(&bob_pub, b"perfectly valid content", NOW);
    // Reject именно по credential (Ступень 4 crypto), а не по случайной другой
    // стадии — иначе тест «прошёл бы по неверной причине».
    match &resp {
        Response::Rejected(reason) => assert!(
            reason.contains("Capability") || reason.contains("BadMac") || reason.contains("Crypto"),
            "ожидался reject по credential, получено: {}",
            reason
        ),
        other => panic!("ожидался Rejected, получено: {:?}", other),
    }

    // В mailbox ничего не легло (Bob аутентифицируется, но выборка пуста).
    assert!(bob.receive(NOW).unwrap().is_empty());
}

#[test]
fn attacker_knowing_pubkey_cannot_drain_mailbox() {
    // Несущее для fetch-auth: злоумышленник знает pubkey-адрес Bob (он публичен),
    // но НЕ его приватный ключ → не может вычислить DH-доказательство владения и
    // слить очередь. Проверяем не только Rejected, а что СООБЩЕНИЕ ОСТАЛОСЬ на
    // месте (Rejected без drain — вот свойство; проверка только кода ответа
    // прошла бы, даже если drain случился).
    let (relay, bob_id, relay_pub) = setup();
    let transport = InMemoryTransport::new(relay.clone());
    let mut alice = Client::new(transport.clone(), capability([0x33; 32]), b"alice");
    let bob_pub = bob_id.public;

    assert!(matches!(alice.send(&bob_pub, b"for bob only", NOW), Response::Accepted));

    // Злоумышленник: cookie-handshake на mailbox Bob, но proof подделать не может.
    let mailbox = bob_pub.to_bytes();
    let attacker_req = |cookie| FetchRequest {
        mailbox,
        client_addr: b"attacker".to_vec(),
        carrier_id: b"mem".to_vec(),
        cookie,
        proof: [0xAB; 16], // не тот proof — DH без секрета Bob не сошёлся
        own_proof: Vec::new(),
    };
    let cookie = match transport.fetch(&attacker_req(None), NOW) {
        FetchResponse::NeedCookie(c) => c,
        other => panic!("ожидался challenge, получено иное: {:?}", matches!(other, FetchResponse::Rejected(_))),
    };
    let attack = transport.fetch(&attacker_req(Some(cookie)), NOW);
    assert!(matches!(attack, FetchResponse::Rejected(_)), "чужой fetch должен быть отклонён");

    // ГЛАВНОЕ: очередь Bob НЕ тронута — законный Bob всё ещё получает сообщение.
    let mut bob = Recipient::new(transport, bob_id, relay_pub);
    let got: Vec<_> = bob.receive(NOW).unwrap().into_iter().flatten().collect();
    assert_eq!(got, vec![b"for bob only".to_vec()], "чужой fetch не должен удалять сообщение");
}

#[test]
fn client_refreshes_cookie_on_expiry() {
    // Проверяет КЛИЕНТСКИЙ cookie-refresh: когда время идёт, кэшированный cookie
    // протухает и сервер challeng'ит — клиент сам перевыдаёт и доставка выживает
    // (а не «cookie отклонён», что документировало бы баг). ВНИМАНИЕ: свежесть
    // cookie здесь роняет 30-сек TTL (`COOKIE_TTL_SECS`), он всегда срабатывает
    // раньше epoch-grace (600с), поэтому этот тест НЕ пиннит проводку эпох —
    // сброс replay-фильтра по эпохе запиннен отдельно в admission
    // (`roll_epoch_clears_replay_filter`). Здесь — именно клиентский повтор.
    let (relay, bob_id, relay_pub) = setup();
    let transport = InMemoryTransport::new(relay.clone());
    let mut alice = Client::new(transport.clone(), capability([0x33; 32]), b"alice");
    let mut bob = Recipient::new(transport, bob_id, relay_pub);
    let bob_pub = bob.public();

    // t0: первый контакт, handshake, доставка.
    assert!(matches!(alice.send(&bob_pub, b"m1", NOW), Response::Accepted));

    // Далеко за TTL И за границу эпохи+grace (3 эпохи): кэш протух, ключ сменён.
    let later = NOW + 3 * EPOCH_DURATION_SECS;
    assert!(
        matches!(alice.send(&bob_pub, b"m2", later), Response::Accepted),
        "доставка должна пережить границу TTL/эпохи (клиент перевыдаёт cookie)"
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
        // max_requests с запасом над MAX_FETCH_SEALS, чтобы упереться именно в
        // потолок mailbox, а не в квоту.
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

    for _ in 0..MAX_FETCH_SEALS {
        assert!(matches!(alice.send(&bob_pub, b"x", NOW), Response::Accepted));
    }
    // Mailbox full -> backpressure, not a silent drop.
    match alice.send(&bob_pub, b"overflow", NOW) {
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

    // The cookie round-trip may succeed (cookies are anti-spoofing, not the door), but the
    // capability check must refuse delivery. Try twice to get past the NeedCookie step.
    let mut accepted = false;
    for _ in 0..3 {
        if matches!(alice.send(&bob_pub, b"let me in", NOW), Response::Accepted) {
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

    // ONE sealed envelope, deposited twice — exactly what the outbox retransmits.
    let payload = Payload::Skeleton(SkeletonSeal::seal(&bob_pub, b"same bytes"));

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
    let other = Payload::Skeleton(SkeletonSeal::seal(&bob_pub, b"different bytes"));
    assert!(matches!(deposit(&relay, &other, b"nonce-3"), Response::Accepted));
    assert_eq!(
        relay.borrow().mailbox_len_for_test(&bob_pub.to_bytes()),
        2,
        "dedup must key on the payload, not swallow every deposit after the first"
    );
}
