//! §2.1 сессионный E2E: PQXDH + Double Ratchet поверх РЕАЛЬНОГО пути сообщения
//! (admission §7 → mailbox → fetch-auth), через `karst_client_core::peer::Peer`.
//!
//! Несущее (не single-roundtrip, который не тронул бы ни цепочку, ни переход
//! Initial→Ratchet): МУЛЬТИсообщение в ОБЕ стороны через настоящий mailbox с
//! batch-fetch, первый конверт `Initial` затем `Ratchet`, и ВТОРОЙ раунд
//! send→fetch, продолжающий ТУ ЖЕ сессию (цепочки переживают fetch'и). Заодно —
//! seam: pqxdh-`root_key` реально засевает рабочую ratchet-сессию.

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

/// Общий relay + транспорт, на которых тест поднимает произвольно много peer'ов.
fn shared() -> (InMemoryTransport, PublicKey) {
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(dev_cap());
    let relay_pub = relay.relay_public();
    (InMemoryTransport::new(Rc::new(RefCell::new(relay))), relay_pub)
}

fn peer(transport: &InMemoryTransport, relay_pub: PublicKey) -> Peer<InMemoryTransport> {
    Peer::new(transport.clone(), Account::generate(), dev_cap(), relay_pub)
}

/// Только не-`None` расшифровки, в порядке.
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

    // Alice инициирует сессию к Bob по его bundle (вне канала — §12 отложен).
    alice.connect_with_bundle(&bob.bundle()).unwrap();

    // --- Раунд 1: Alice → Bob, два сообщения (Initial затем Ratchet) ---
    assert!(matches!(alice.send(&bob_ik, b"m0", NOW), Response::Accepted));
    assert!(matches!(alice.send(&bob_ik, b"m1", NOW), Response::Accepted));

    let got = plaintexts(bob.receive(NOW).expect("bob fetch"));
    assert_eq!(got, vec![b"m0".to_vec(), b"m1".to_vec()], "batch-fetch: Initial+Ratchet по порядку");

    // --- Bob отвечает (по установленной сессии — DH-ratchet у обоих) ---
    assert!(matches!(bob.send(&alice_ik, b"r0", NOW), Response::Accepted));
    let got = plaintexts(alice.receive(NOW).expect("alice fetch"));
    assert_eq!(got, vec![b"r0".to_vec()], "ответ расшифрован (Alice делает DH-шаг)");

    // --- Раунд 2: Alice продолжает ТУ ЖЕ сессию через новый fetch-цикл ---
    // (Alice уже перешла на цепочку B, приняв r0 → это ratchet-переход границы.)
    assert!(matches!(alice.send(&bob_ik, b"m2", NOW), Response::Accepted));
    assert!(matches!(alice.send(&bob_ik, b"m3", NOW), Response::Accepted));
    let got = plaintexts(bob.receive(NOW).expect("bob fetch 2"));
    assert_eq!(got, vec![b"m2".to_vec(), b"m3".to_vec()], "цепочки переживают fetch'и");

    // --- И ещё разворот: Bob → Alice снова ---
    assert!(matches!(bob.send(&alice_ik, b"r1", NOW), Response::Accepted));
    let got = plaintexts(alice.receive(NOW).expect("alice fetch 2"));
    assert_eq!(got, vec![b"r1".to_vec()]);
}

#[test]
fn receive_attributes_sender_across_two_peers() {
    // Несущее (атрибуция): два разных отправителя → Bob; каждое входящее должно
    // нести ПРАВИЛЬНЫЙ sender-IK (для раскладки по чатам в UI). Initial несёт IK
    // в KA; Ratchet атрибутируется по сессии, которая расшифровала.
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
    assert_eq!(got, want, "каждое входящее атрибутировано верному отправителю");
}

#[test]
fn recipient_only_sees_own_mailbox_and_eve_gets_nothing() {
    // Изоляция mailbox: Alice шлёт Bob; Eve (третий peer) забирает СВОЙ mailbox —
    // пусто. Груз Bob'а ей недоступен (адресован ik Bob, лежит в его ящике).
    let (transport, relay_pub) = shared();
    let mut alice = peer(&transport, relay_pub);
    let mut bob = peer(&transport, relay_pub);
    let mut eve = peer(&transport, relay_pub);

    alice.connect_with_bundle(&bob.bundle()).unwrap();
    assert!(matches!(alice.send(&bob.identity(), b"secret", NOW), Response::Accepted));

    assert!(plaintexts(eve.receive(NOW).expect("eve fetch")).is_empty(), "Eve не видит чужой mailbox");
    assert_eq!(plaintexts(bob.receive(NOW).expect("bob fetch")), vec![b"secret".to_vec()]);
}

/// Транспорт-«кран»: отвергает ПЕРВУЮ отправку, дальше пропускает; записывает
/// каждый ушедший WireMessage (шифртекст УЖЕ у relay — в модели угроз).
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
    // НЕСУЩЕЕ (keystream-reuse): цепочка продвигается безусловно, поэтому даже
    // после ОТКАЗа отправки следующий (другой) plaintext НЕ занимает ту же
    // позицию цепочки. Нулевой nonce безопасен только при уникальном mk на
    // сообщение — пиннит, что отказ не воскрешает mk.
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
    // Первый cookie-challenge проходит (не считается reject_next? — да, NeedCookie
    // не наш reject). reject_next срабатывает на первом реальном send-кадре.
    let _ = alice.send(&bob_ik, b"AAAA", NOW); // отвергнут краном
    let _ = alice.send(&bob_ik, b"BBBB", NOW); // другой plaintext

    // Инвариант: одинаковая позиция `(dh,n)` ⇒ одинаковый шифртекст (cookie-retry
    // легитимно дослыает ТОТ ЖЕ конверт). Разные plaintext ОБЯЗАНЫ занять разные
    // позиции — иначе один `mk`+нулевой nonce на два текста (keystream-reuse).
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
                    "позиция (dh,n) переиспользована под ДРУГОЙ шифртекст → keystream-reuse"
                ),
                None => {
                    seen.insert((h.dh, h.n), ct);
                }
            }
        }
    }
    let ns: std::collections::BTreeSet<u32> = seen.keys().map(|(_, n)| *n).collect();
    assert!(ns.contains(&0) && ns.contains(&1), "оба plaintext эмитнуты на разных позициях");
}
