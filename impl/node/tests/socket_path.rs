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
use node::session::Session;
use node::socket::{RelayServer, SocketTransport};
use node::wire::{self, WireRequest, WireResponse, MAX_BLOB_FRAME, MAX_REQUEST_FRAME, MAX_RESPONSE_FRAME};
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

/// SEC-41 (#226): nothing server-side bounds what a relay may put in `PowRequired`'s
/// `difficulty_bits` — the relay declares it and, before this fix, `join()` just went and
/// solved it. A hostile or misconfigured relay could declare an absurd difficulty and the
/// client would burn unbounded CPU earning a capability while the relay spent nothing to
/// issue the challenge. 64 bits is chosen because it is not merely "slow" but computationally
/// infeasible: if the client-side ceiling check is ever neutered, this test does not just get
/// slower, it HANGS — so the join runs on a worker thread behind a bounded `recv_timeout`,
/// which turns "the fix regressed" into a clean, fast failure instead of a stuck suite.
#[test]
fn a_relay_declared_difficulty_above_the_ceiling_is_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut relay = node::node::RelayNode::with_identity(NOW, Identity::generate());
    relay.enable_pow_issue(64); // far past any reasonable ceiling; infeasible to solve
    let fetch_pub = relay.relay_public().to_bytes();
    let server = RelayServer::new(relay, Arc::new(move || NOW));
    let noise_pub = server.noise_public();
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });

    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(SocketTransport::new(addr, noise_pub).join());
    });
    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("a ceiling-respecting client refuses immediately instead of grinding forever");
    let err = result.expect_err("an absurd relay-declared difficulty must be refused, never solved");
    let msg = err.to_string();
    assert!(
        msg.contains(&hex::encode(fetch_pub)),
        "the refusal must name the offending relay: {msg}"
    );
    // The FULL phrase, not a bare "64": the relay id is 64 hex characters, so a substring
    // search for "64" alone would very likely hit the id itself and pass for the wrong reason.
    assert!(
        msg.contains("difficulty 64 bits"),
        "the refusal must state the declared difficulty: {msg}"
    );
}

/// §210 — the ordinary-request ceiling (`MAX_REQUEST_FRAME`) used to be dead on the server's
/// read path: EVERY inbound request was read with the wide blob ceiling, and nothing checked
/// the decoded frame against a tighter per-class limit afterward — a `Fetch` padded to tens of
/// KB was decoded and served exactly like a legitimate one.
///
/// Discriminating, and pinned tight against "the connection just died for some unrelated
/// reason": both requests below go over the SAME live Noise session, in order. The FIRST
/// (normal-sized) `Fetch` must round-trip to a concrete, decoded `WireResponse::NeedCookie` —
/// proving the session, the handshake, and this exact code path are all healthy. The SECOND
/// (oversized) `Fetch` — same session, same variant, only `client_addr` padded past the
/// ordinary ceiling — must then get NO response at all. Since the session was demonstrably
/// alive one message earlier, silence on the second can only be the new per-class check firing,
/// not a flaky handshake, a dead socket, or a decode failure. Neuter the check
/// (`socket::handle_conn`'s `if req_bytes.len() > class_max`) and the second request is instead
/// SERVED — directly observable.
#[test]
fn an_oversized_ordinary_request_is_dropped_instead_of_served() {
    let (addr, npub, _) = spawn_relay(false);

    let stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut session = Session::connect(stream, &npub).expect("noise handshake succeeds");

    // Control, first, on this SAME session: an ordinary-sized `Fetch` (no cookie) must be
    // served and decode to a concrete, expected response variant.
    let normal = WireRequest::Fetch(FetchRequest {
        mailbox: [0u8; 32],
        client_addr: b"probe".to_vec(),
        carrier_id: b"probe".to_vec(),
        cookie: None,
        proof: [0u8; 16],
        own_proof: Vec::new(),
    });
    let normal_bytes = wire::encode(&normal).expect("a well-formed Fetch always encodes");
    assert!(normal_bytes.len() <= MAX_REQUEST_FRAME, "test setup: control must fit the ordinary ceiling");
    session.write_msg(&normal_bytes, MAX_REQUEST_FRAME).expect("control write goes through");
    let normal_resp: WireResponse =
        wire::decode(&session.read_msg(MAX_RESPONSE_FRAME).expect("control must be served"))
            .expect("control response decodes");
    assert!(
        matches!(normal_resp, WireResponse::NeedCookie(_)),
        "control (no cookie) must get NeedCookie, got a different variant entirely"
    );

    // Now, same session: `Fetch` is not Ack/PublishBundle/BlobPut, so its ceiling is the tight
    // ordinary default. Pad `client_addr` WAY past that — but still comfortably under
    // `MAX_BLOB_FRAME`, so the outer read and postcard decode both succeed and only the new
    // per-class check can reject it.
    let oversized = WireRequest::Fetch(FetchRequest {
        mailbox: [0u8; 32],
        client_addr: vec![0u8; 20_000],
        carrier_id: b"probe".to_vec(),
        cookie: None,
        proof: [0u8; 16],
        own_proof: Vec::new(),
    });
    let req_bytes = wire::encode(&oversized).expect("a well-formed Fetch always encodes");
    assert!(req_bytes.len() > MAX_REQUEST_FRAME, "test setup: must exceed the ordinary ceiling");
    assert!(req_bytes.len() < MAX_BLOB_FRAME, "test setup: must still fit the outer read bound");
    // Write with the WIDE bound so the client library's own write-side guard doesn't stop us
    // from putting an oversized ORDINARY frame on the wire in the first place.
    session.write_msg(&req_bytes, MAX_BLOB_FRAME).expect("write goes through");

    let resp = session.read_msg(MAX_RESPONSE_FRAME);
    assert!(
        resp.is_err(),
        "oversized ordinary request must get NO response (the SAME session just served the \
         control above), got {resp:?}"
    );

    // Belt-and-braces: the server process overall survived too, and a fresh connection still
    // serves normally.
    assert!(server_alive(addr, npub), "server must survive the oversized frame and keep serving");
}

/// #142: a slow BLOB write must not stall everyone else's mail.
///
/// The relay used to keep one `Mutex<RelayNode>` over everything, so `handle_blob_put` did its
/// file I/O — tens of KiB per chunk — while holding the same lock that `Send`, `Fetch` and `Ack`
/// need. One upload head-of-line-blocked every other client on the relay; the connection cap
/// bounded threads but not this serial bottleneck.
///
/// The blob store now sits behind its OWN lock, and the serve loop takes the relay lock only to
/// ADMIT a blob request (cookie, nonce, capability, quota) before releasing it and doing the I/O.
/// This test makes that structural: the test thread HOLDS the blob store's lock — standing in
/// for an arbitrarily slow chunk write, without needing a slow disk or a timing threshold to
/// simulate one — an upload is issued against it and parks, and then an ordinary message must
/// still be Accepted. Put the write back under the relay lock and the send waits behind it: RED.
///
/// The bound on the send is deliberately generous (a fixed budget is fine here because it is not
/// measuring anything — when the fix works the send is immediate, and when it does not the send
/// can never complete at all while the lock is held).
#[test]
fn a_blob_write_in_progress_does_not_block_ordinary_mail() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut relay = node::node::RelayNode::new(NOW);
    relay.issue_capability(capability([0x33; 32]));
    let blob_dir = std::env::temp_dir().join(format!("karst-hol-{}", std::process::id()));
    relay
        .enable_blobs(blob_dir.clone(), NOW, node::node::BlobPersistence::Ephemeral)
        .unwrap();
    let store = relay.blob_store().expect("blobs are enabled");
    let fetch_pub = relay.relay_public().to_bytes();
    let server = RelayServer::new(relay, Arc::new(move || NOW));
    let noise_pub = server.noise_public();
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });

    // The stand-in for a slow disk: nothing can write a chunk until this guard is dropped.
    let guard = store.lock().expect("blob store mutex");

    // An upload that will park inside the relay, past admission, waiting for that guard.
    let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
    let uploader = thread::spawn(move || {
        let t = SocketTransport::new(addr, noise_pub);
        let mut cookie = None;
        let _ = started_tx.send(());
        loop {
            let nonce = node::node::blob_put_nonce(&[0xB1; 32], 0);
            let req = node::node::BlobPutRequest {
                request_nonce: nonce.clone(),
                capability_proof: capability([0x33; 32]).prove(&nonce, 0),
                client_addr: vec![0x44u8; 32],
                carrier_id: b"karst-blob".to_vec(),
                cookie,
                blob_id: [0xB1; 32],
                index: 0,
                count: 1,
                data: vec![7u8; 1024],
            };
            match t.blob_put(&req) {
                node::node::BlobResponse::NeedCookie(c) => cookie = Some(c), // one round trip, then it parks
                _ => break,
            }
        }
    });
    started_rx.recv().expect("uploader started");
    // Synchronisation, not a measurement: give the parked upload time to reach the relay. If it
    // has not, the test simply proves less — it can never produce a false GREEN, because the
    // guard above is held for the whole assertion below either way.
    thread::sleep(Duration::from_millis(300));

    // The actual claim: ordinary mail goes through while that upload is stuck.
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut alice = Client::new(SocketTransport::new(addr, noise_pub), capability([0x33; 32]), b"alice");
        let bob = Recipient::new(SocketTransport::new(addr, noise_pub), Identity::generate(), PublicKey::from(fetch_pub));
        let _ = tx.send(matches!(alice.send(&bob.public(), b"mail during a blob write", NOW), Response::Accepted));
    });
    let accepted = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("a send must not wait on blob file I/O — the relay lock is not the blob lock");
    assert!(accepted, "the message should have been admitted");

    drop(guard); // the "slow disk" finishes; the parked upload completes and the thread exits
    uploader.join().expect("the parked upload finishes once the store is free");
    std::fs::remove_dir_all(&blob_dir).ok();
}
