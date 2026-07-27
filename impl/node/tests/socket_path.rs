//! Сокет-транспорт поверх Noise-сессии (§15). Несущее покрытие:
//! - **malformed-кадр не роняет сервер** (handshake-reader — новая внешняя
//!   граница доверия): oversized/truncated/garbage;
//! - **на проводе только шифртекст** — метаданные (pubkey получателя) НЕ видны
//!   пассивному наблюдателю (иначе Noise был бы no-op — та же ловушка «тест
//!   слабее имени»);
//! - **MITM с чужим Noise-ключом проваливает handshake** (relay аутентифицирован).
//!
//! Границы честно: on-path replay в пределах сессии закрыт (per-session эфемеры),
//! но это конфиденциальность+анти-MITM, НЕ обфускация транспорта — трафик опознаваем анализом трафика и
//! блокируем по IP:port (обфускация транспорта §15 — следующий срез).

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use admission::capability::{Capability, Quota, Scope};
use node::node::{
    Client, FetchRequest, FetchResponse, PublishResponse, Recipient, Response, Transport,
};
use node::peer::Peer;
use node::pqxdh::Account;
use node::seal::Identity;
use node::socket::{RelayServer, SocketTransport};
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

/// Поднять relay на эфемерном порту с фиксированными часами (детерминизм).
/// Возвращает (адрес, Noise-pub, fetch-auth-pub).
fn spawn_relay(with_cap: bool) -> (SocketAddr, [u8; 32], [u8; 32]) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut relay = node::node::RelayNode::new(NOW);
    if with_cap {
        relay.issue_capability(capability([0x33; 32]));
    }
    let fetch_pub = relay.relay_public().to_bytes();
    let server = RelayServer::new(relay, Arc::new(move || NOW));
    let noise_pub = server.noise_public();
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });
    (addr, noise_pub, fetch_pub)
}

/// Отправить сырые байты (БЕЗ Noise-handshake), закрыть запись, вернуть ответ.
/// Сервер ждёт handshake первым — мусор должен дать чистую ошибку, не панику.
fn raw_exchange(addr: SocketAddr, bytes: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(bytes).unwrap();
    s.flush().unwrap();
    s.shutdown(Shutdown::Write).ok();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    buf
}

/// Проба живости: полноценная Noise-сессия + Fetch без cookie → `NeedCookie`.
/// Доказывает, что сервер пережил враждебное соединение и всё ещё договаривается.
fn server_alive(addr: SocketAddr, noise_pub: [u8; 32]) -> bool {
    let t = SocketTransport::new(addr, noise_pub);
    let req = FetchRequest {
        mailbox: [0u8; 32],
        client_addr: b"probe".to_vec(),
        carrier_id: b"probe".to_vec(),
        cookie: None,
        proof: [0u8; 16],
        ack: false,
        own_proof: Vec::new(),
    };
    matches!(t.fetch(&req, 0), FetchResponse::NeedCookie(_))
}

#[test]
fn relay_with_fixed_noise_key_handshakes() {
    // Персистентность ключа relay: заданная Noise-пара (generate_noise_keypair →
    // persist → with_noise_keypair) должна давать РАБОЧИЙ handshake — т.е.
    // хранимый pub согласован с тем, что snow выводит из priv. Регресс на случай
    // рассинхрона деривации pub из priv.
    let (npriv, npub) = node::socket::generate_noise_keypair();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let relay = node::node::RelayNode::with_identity(NOW, Identity::generate());
    let server = RelayServer::with_noise_keypair(relay, Arc::new(move || NOW), npriv, npub);
    assert_eq!(server.noise_public(), npub, "сервер отдаёт заданный pub");
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });
    // Клиент с ХРАНИМЫМ pub — handshake должен пройти (Fetch без cookie → challenge).
    assert!(server_alive(addr, npub), "handshake с персистентным ключом должен работать");
}

#[test]
fn oversized_length_rejected_without_alloc() {
    // Первые 2 байта (handshake-длина LE) = 0xFFFF > потолка → отказ до аллокации.
    let (addr, npub, _) = spawn_relay(false);
    let resp = raw_exchange(addr, &u32::MAX.to_le_bytes());
    assert!(resp.is_empty(), "на oversized сервер не должен отвечать");
    assert!(server_alive(addr, npub), "сервер должен пережить oversized-кадр");
}

#[test]
fn truncated_frame_errors_cleanly() {
    let (addr, npub, _) = spawn_relay(false);
    let mut framed = 100u32.to_le_bytes().to_vec();
    framed.extend_from_slice(&[0xAB; 10]);
    let resp = raw_exchange(addr, &framed);
    assert!(resp.is_empty(), "на обрезанный кадр сервер не должен отвечать");
    assert!(server_alive(addr, npub), "сервер должен пережить обрезанный кадр");
}

#[test]
fn garbage_body_rejected() {
    // Валидная маленькая handshake-длина, но тело — не Noise-msg1 → чистая ошибка.
    let (addr, npub, _) = spawn_relay(false);
    let mut framed = 1u32.to_le_bytes().to_vec();
    framed.push(0x05);
    let resp = raw_exchange(addr, &framed);
    assert!(resp.is_empty(), "на мусорное тело сервер не должен отвечать");
    assert!(server_alive(addr, npub), "сервер должен пережить мусорное тело");
}

#[test]
fn loopback_happy_path() {
    // Реальный сокет + Noise-сессия: Alice → relay-в-потоке → Bob забирает.
    let (addr, npub, fpub) = spawn_relay(true);

    let mut alice = Client::new(SocketTransport::new(addr, npub), capability([0x33; 32]), b"alice");
    let mut bob = Recipient::new(SocketTransport::new(addr, npub), Identity::generate(), PublicKey::from(fpub));
    let bob_pub = bob.public();

    let resp = alice.send(&bob_pub, b"hello over noise", NOW);
    assert!(matches!(resp, Response::Accepted), "получено: {:?}", resp);

    let msgs = bob.receive(NOW).expect("fetch должен пройти");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].as_deref(), Some(b"hello over noise".as_ref()));
}

#[test]
fn session_publish_connect_send_over_socket() {
    // §2.1 E2E по РЕАЛЬНОМУ сокету+Noise: Bob публикует bundle (§12), Alice
    // забирает его у relay, инициирует PQXDH+ratchet, шлёт; Bob расшифровывает.
    // Проверяет §12-wire (PublishBundle/FetchBundle) + сериализацию Account
    // через провод + сессионный путь end-to-end поверх транспорта.
    let (addr, npub, fpub) = spawn_relay(true);
    let relay_pub = PublicKey::from(fpub);

    let mut bob = Peer::new(SocketTransport::new(addr, npub), Account::generate(), capability([0x33; 32]), relay_pub);
    let mut alice = Peer::new(SocketTransport::new(addr, npub), Account::generate(), capability([0x33; 32]), relay_pub);
    let bob_ik = bob.identity();

    assert!(matches!(bob.publish(NOW), PublishResponse::Published), "publish по сокету");
    alice.connect(&bob_ik, NOW).expect("connect (fetch bundle) по сокету");
    assert!(matches!(alice.send(&bob_ik, b"hi via discovery over noise", NOW), Response::Accepted));

    let got: Vec<_> = bob.receive(NOW).unwrap().into_iter().flatten().map(|r| r.plaintext).collect();
    assert_eq!(got, vec![b"hi via discovery over noise".to_vec()]);
}

// ---------- Несущее: реально ли шифрует и аутентифицирует ----------

/// Записывающий TCP-прокси: пересылает байты в обе стороны и КОПИТ всё, что
/// проходит. Наблюдатель на проводе.
fn spawn_recording_proxy(upstream: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let rec = recorded.clone();
    thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(client) = client else { continue };
            let Ok(up) = TcpStream::connect(upstream) else { continue };
            let (c2, u2) = (client.try_clone().unwrap(), up.try_clone().unwrap());
            let (r1, r2) = (rec.clone(), rec.clone());
            thread::spawn(move || pump(client, up, r1));
            thread::spawn(move || pump(u2, c2, r2));
        }
    });
    (addr, recorded)
}

fn pump(mut from: TcpStream, mut to: TcpStream, rec: Arc<Mutex<Vec<u8>>>) {
    let mut buf = [0u8; 4096];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => {
                let _ = to.shutdown(Shutdown::Write);
                break;
            }
            Ok(n) => {
                rec.lock().unwrap().extend_from_slice(&buf[..n]);
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn wire_bytes_are_ciphertext_recipient_metadata_hidden() {
    // Дискриминирующий: pubkey получателя лежит в WireMessage.recipient ОТКРЫТЫМ
    // postcard'ом — БЕЗ Noise он был бы на проводе. С Noise его там нет. Значит
    // тест провалится, если шифрование окажется no-op (в отличие от проверки
    // самого plaintext-сообщения — оно и так E2E-зашифровано SkeletonSeal).
    let (relay_addr, npub, _fpub) = spawn_relay(true);
    let (proxy_addr, recorded) = spawn_recording_proxy(relay_addr);

    let bob = Identity::generate();
    let bob_pub = bob.public.to_bytes();
    let mut alice = Client::new(SocketTransport::new(proxy_addr, npub), capability([0x33; 32]), b"alice");

    // send синхронен: вернулся Accepted → полный round-trip прошёл через прокси.
    assert!(matches!(alice.send(&bob.public, b"secret payload", NOW), Response::Accepted));

    let rec = recorded.lock().unwrap();
    assert!(!rec.is_empty(), "прокси должен был записать шифртекст");
    assert!(
        !contains(&rec, &bob_pub),
        "pubkey получателя (метаданные) не должен появляться на проводе — Noise его прячет"
    );
    assert!(!contains(&rec, b"secret payload"), "текст не должен быть на проводе");
}

#[test]
fn mitm_wrong_noise_key_fails_handshake() {
    // Клиент с ЧУЖИМ Noise-pub узла: handshake проваливается (relay
    // аутентифицирован своим static), данные не текут.
    let (addr, _npub, _fpub) = spawn_relay(true);
    let wrong = [0x77u8; 32];
    let mut alice = Client::new(SocketTransport::new(addr, wrong), capability([0x33; 32]), b"alice");
    let bob = Identity::generate();
    let resp = alice.send(&bob.public, b"hi", NOW);
    assert!(
        matches!(resp, Response::Rejected(_)),
        "handshake к чужому ключу должен провалиться, получено: {:?}",
        resp
    );
}

/// §7 slice 4a — the PUBLIC door over the REAL socket: a client earns a capability by
/// solving the relay's PoW (`JoinChallenge` → `Join` → `Issued`, all inside the Noise
/// session), then that capability opens the door for an actual send. This is the wire-path
/// proof that complements the in-memory `public_door` tests: the capability SECRET comes
/// back encrypted (it rides the session like every response), and the earned cap verifies
/// statelessly on the send that follows.
#[test]
fn earn_a_capability_over_the_socket_then_send() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut relay = node::node::RelayNode::with_identity(NOW, Identity::generate());
    relay.enable_pow_issue(8); // cheap PoW for the test
    let fetch_pub = relay.relay_public().to_bytes();
    let server = RelayServer::new(relay, Arc::new(move || NOW));
    let noise_pub = server.noise_public();
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });

    // Earn the capability over the wire (this solves the PoW client-side).
    let cap = SocketTransport::new(addr, noise_pub)
        .join()
        .expect("join over the socket should succeed");
    assert_eq!(cap.scope, Scope::MessageDelivery);
    assert_ne!(cap.secret, [0u8; 32], "an issued cap must carry a real secret");

    // The earned cap opens the door: a real send is Accepted and delivered.
    let mut alice = Client::new(SocketTransport::new(addr, noise_pub), cap, b"alice");
    let mut bob = Recipient::new(
        SocketTransport::new(addr, noise_pub),
        Identity::generate(),
        PublicKey::from(fetch_pub),
    );
    let bob_pub = bob.public();
    assert!(
        matches!(alice.send(&bob_pub, b"hello via earned cap", NOW), Response::Accepted),
        "a PoW-earned capability must open the door over the socket"
    );
    let msgs: Vec<_> = bob.receive(NOW).unwrap().into_iter().flatten().collect();
    assert_eq!(msgs, vec![b"hello via earned cap".to_vec()]);
}
