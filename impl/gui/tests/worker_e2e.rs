//! Интеграционный тест GUI-worker'а против ЖИВОГО relay (без дисплея — это та
//! часть GUI, что верифицируема в headless-среде). Два worker'а (Alice, Bob)
//! через каналы: Alice шлёт → Bob принимает с ВЕРНОЙ атрибуцией отправителя.
//! Доказывает, что GUI-слой реально проводит сообщение через `client::*`.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gui::controller::{App, AccountInfo, Cmd, Contact, Evt, ExpiringIn, IncomingText, StatusMsg};
use gui::worker::{run, WorkerCfg};

/// Render a worker `StatusMsg` to its English display text, so these tests can keep
/// asserting on substrings after status messages became language-agnostic values.
fn status_text(s: &StatusMsg) -> String {
    App::default().render_status(s.clone())
}
use node::node::RelayNode;
use node::socket::RelayServer;

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("karst-gui-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Relay на эфемерном порту, фиксированные часы. Возвращает (addr, relay-id hex).
fn spawn_relay() -> (String, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut relay = RelayNode::new(1_000_000);
    relay.issue_capability(client::dev_capability());
    relay.enable_blobs(temp_dir("relay-blobs"), 0, node::node::BlobPersistence::Durable).unwrap();
    let fetch_pub = relay.relay_public().to_bytes();
    let server = RelayServer::new(relay, Arc::new(|| 1_000_000));
    let noise_pub = server.noise_public();
    let relay_id = format!("{}{}", hex::encode(noise_pub), hex::encode(fetch_pub));
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });
    (addr.to_string(), relay_id)
}

/// Прокачать байты в одну сторону, закрыть write-half при EOF.
fn splice(mut from: TcpStream, mut to: TcpStream) {
    let mut buf = [0u8; 4096];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => {
                let _ = to.shutdown(Shutdown::Write);
                break;
            }
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

/// Заглушка SOCKS5 (CONNECT, no-auth, IPv4) на loopback: валидирует handshake
/// клиента, форвардит к запрошенному dest. Возвращает СЧЁТЧИК успешных CONNECT —
/// каждый round-trip worker'а через прокси инкрементит его. Счётчик (а не флаг)
/// нужен, чтобы пиннить маршрутизацию КАЖДОГО из publish/send/recv по отдельности.
fn spawn_socks5_stub() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut client) = conn else { continue };
            // Greeting: VER=5, NMETHODS, then that many method bytes. The worker's Relay
            // carries an isolation token, so the client now offers ONLY user/pass (0x02) —
            // fail-closed isolation. An isolating proxy MUST honour it, so this mock selects
            // user/pass and reads the RFC 1929 credential rather than falling back to
            // no-auth (a proxy that answered no-auth would now be refused by the client).
            let mut head = [0u8; 2]; // VER NMETHODS
            if client.read_exact(&mut head).is_err() || head[0] != 0x05 {
                continue;
            }
            let mut methods = vec![0u8; head[1] as usize];
            if client.read_exact(&mut methods).is_err() || !methods.contains(&0x02) {
                continue;
            }
            client.write_all(&[0x05, 0x02]).unwrap(); // select user/pass
            // RFC 1929 sub-negotiation: VER=1, ULEN, UNAME, PLEN, PASSWD → accept it.
            let mut ah = [0u8; 2]; // VER ULEN
            if client.read_exact(&mut ah).is_err() {
                continue;
            }
            let mut uname = vec![0u8; ah[1] as usize];
            if client.read_exact(&mut uname).is_err() {
                continue;
            }
            let mut pl = [0u8; 1];
            if client.read_exact(&mut pl).is_err() {
                continue;
            }
            let mut passwd = vec![0u8; pl[0] as usize];
            if client.read_exact(&mut passwd).is_err() {
                continue;
            }
            client.write_all(&[0x01, 0x00]).unwrap(); // auth OK
            let mut h = [0u8; 4]; // VER CMD RSV ATYP
            if client.read_exact(&mut h).is_err() || h[0] != 0x05 || h[1] != 0x01 || h[3] != 0x01 {
                continue;
            }
            let mut ap = [0u8; 6]; // IPv4 + port
            if client.read_exact(&mut ap).is_err() {
                continue;
            }
            let dest = SocketAddr::from((
                [ap[0], ap[1], ap[2], ap[3]],
                u16::from_be_bytes([ap[4], ap[5]]),
            ));
            let Ok(up) = TcpStream::connect(dest) else { continue };
            client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).unwrap();
            c.fetch_add(1, Ordering::SeqCst); // CONNECT состоялся
            let (c2, u2) = (client.try_clone().unwrap(), up.try_clone().unwrap());
            thread::spawn(move || splice(client, up));
            thread::spawn(move || splice(u2, c2));
        }
    });
    (addr, count)
}

/// Спин-ожидание, пока счётчик CONNECT'ов не превысит `prev` (для операций без
/// события — фоновый poll ничего не эмитит на пустом mailbox).
fn wait_count_above(counter: &Arc<AtomicUsize>, prev: usize) -> usize {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let n = counter.load(Ordering::SeqCst);
        if n > prev {
            return n;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("таймаут: счётчик SOCKS5-CONNECT не вырос выше {prev}");
}

/// Свободный, но не слушаемый порт (connect → refused).
fn dead_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

/// Поднять worker в потоке в ЗАДАННОМ каталоге (для сценариев рестарта на том же
/// состоянии) с заданным `poll_interval`.
fn spawn_worker_in(dir: PathBuf, poll_interval: Duration) -> (Sender<Cmd>, Receiver<Evt>) {
    let (cmd_tx, cmd_rx) = mpsc::channel();
    let (evt_tx, evt_rx) = mpsc::channel();
    // A sender clone for the worker (off-loop file transfers post internal Cmds back).
    let worker_cmd_tx = cmd_tx.clone();
    thread::spawn(move || {
        // Cover traffic OFF: these tests assert on the traffic they generate, and loops
        // would spend the same capability quota the assertions depend on. Cover is
        // exercised by its own tests, against the relay's log where it is observable.
        run(
            WorkerCfg { dir, poll_interval, cover_traffic: false },
            cmd_rx,
            worker_cmd_tx,
            evt_tx,
        );
    });
    (cmd_tx, evt_rx)
}

/// Поднять worker в свежем временном каталоге.
fn spawn_worker(tag: &str, poll_interval: Duration) -> (Sender<Cmd>, Receiver<Evt>) {
    spawn_worker_in(temp_dir(tag), poll_interval)
}

/// Создать аккаунт в ПУСТОМ профиле: свежая фраза → `Cmd::Provision`. Заменяет
/// прежний авто-провижининг на первом Unlock. Личность рандомна (тестам важна
/// стабильность через диск, а не конкретный IK — они ловят own_ik динамически).
fn provision_cmd(addr: &str, rid: &str, pass: &str, socks5: &str) -> Cmd {
    Cmd::Provision {
        passphrase: pass.into(),
        phrase: client::seed::generate_mnemonic().to_string(),
        relay_addr: addr.into(),
        relay_id: rid.into(),
        socks5: socks5.into(),
        routes: String::new(),
        extra_relays: String::new(),
    }
}

/// Повторно открыть СУЩЕСТВУЮЩИЙ профиль (после рестарта) — корень уже на диске,
/// та же личность. Прямое соединение (socks5 пуст).
fn unlock_cmd(addr: &str, rid: &str, pass: &str) -> Cmd {
    Cmd::Unlock {
        passphrase: pass.into(),
        relay_addr: addr.into(),
        relay_id: rid.into(),
        socks5: String::new(),
        routes: String::new(),
        extra_relays: String::new(),
    }
}

/// The network config is REMEMBERED: configure it once at provision, then a later
/// launch unlocks with the passphrase ALONE (empty relay fields) and still connects.
/// This is what makes escape routes usable — routes you must retype under pressure are
/// routes you will not use. Discriminating: make `resolve_net` ignore the saved config
/// and the second unlock errors with "no relay configured" instead of reaching Ready.
#[test]
fn network_config_is_remembered_so_a_later_unlock_needs_only_the_passphrase() {
    let (relay_addr, relay_id) = spawn_relay();
    let dir = temp_dir("netmem");

    // First launch: the user types the relay config once.
    let (tx, rx) = spawn_worker_in(dir.clone(), Duration::from_secs(60));
    tx.send(Cmd::Provision {
        passphrase: "pw".into(),
        phrase: client::seed::generate_mnemonic().to_string(),
        relay_addr: relay_addr.clone(),
        relay_id: relay_id.clone(),
        socks5: String::new(),
        routes: "127.0.0.1:9999".into(), // an extra failover route worth remembering
        extra_relays: String::new(),
    })
    .unwrap();
    let ik_first = wait_unlocked(&rx);
    drop(tx);

    // Later launch, SAME profile: passphrase only — no relay address, no relay-id.
    let (tx2, rx2) = spawn_worker_in(dir.clone(), Duration::from_secs(60));
    tx2.send(Cmd::Unlock {
        passphrase: "pw".into(),
        relay_addr: String::new(),
        relay_id: String::new(),
        socks5: String::new(),
        routes: String::new(),
        extra_relays: String::new(),
    })
    .unwrap();
    let ik_second = wait_unlocked(&rx2);
    assert_eq!(ik_second, ik_first, "same profile reopened using the remembered config");
    wait_publish(&rx2); // it really reached the relay — the saved config was applied
    let _ = tx2;
}

/// §15 route sharing, end-to-end through the real relay: Alice explicitly shares her
/// routes with Bob; Bob RECEIVES an offer (never auto-applied) and only an explicit
/// accept merges it into his saved config. Discriminating on the trust model: if the
/// worker applied offers on arrival, `Evt::RouteOffer` would not be the thing that
/// arrives — and the saved config would change without anyone consenting.
#[test]
fn routes_are_shared_only_on_request_and_applied_only_on_accept() {
    let (relay_addr, relay_id) = spawn_relay();
    let alice_dir = temp_dir("share-alice");
    let bob_dir = temp_dir("share-bob");
    let (alice_tx, alice_rx) = spawn_worker_in(alice_dir, Duration::from_secs(60));
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir.clone(), Duration::from_secs(60));

    // Bob is reachable; Alice knows an extra route worth sharing.
    bob_tx.send(provision_cmd(&relay_addr, &relay_id, "bobpw", "")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);
    alice_tx
        .send(Cmd::Provision {
            passphrase: "alicepw".into(),
            phrase: client::seed::generate_mnemonic().to_string(),
            relay_addr: relay_addr.clone(),
            relay_id: relay_id.clone(),
            socks5: String::new(),
            routes: "198.51.100.7:9000".into(),
            extra_relays: String::new(),
        })
        .unwrap();
    let _ = wait_unlocked(&alice_rx);

    // A session first (the offer rides an ordinary E2E packet), then the explicit share.
    alice_tx.send(Cmd::Send { id: 1, to_ik: bob_ik, text: "hi".into(), ts: 0 }).unwrap();
    alice_tx.send(Cmd::ShareRoutes { to_ik: bob_ik }).unwrap();

    // Bob receives an OFFER — not an applied config.
    let mut offered: Option<String> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline && offered.is_none() {
        bob_tx.send(Cmd::Poll).unwrap();
        if let Ok(Evt::RouteOffer { routes, .. }) = bob_rx.recv_timeout(Duration::from_millis(300)) {
            offered = Some(routes);
        }
    }
    let offered = offered.expect("Bob got a route offer");
    assert!(offered.contains("198.51.100.7:9000"), "Alice's extra route is in the offer: {offered}");
    assert!(offered.contains(&relay_addr), "…as is her primary endpoint: {offered}");

    // Nothing was applied on arrival: Bob's saved config is still untouched.
    let saved_before = account_net(&bob_dir, b"bobpw");
    assert!(
        !saved_before.routes.contains("198.51.100.7:9000"),
        "an offer must NOT change the saved config without consent (was {:?})",
        saved_before.routes
    );

    // Only an explicit accept merges it.
    bob_tx.send(Cmd::AcceptRoutes { routes: offered }).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut applied = false;
    while std::time::Instant::now() < deadline && !applied {
        std::thread::sleep(Duration::from_millis(200));
        let saved = account_net(&bob_dir, b"bobpw");
        applied = saved.routes.contains("198.51.100.7:9000");
    }
    assert!(applied, "after an explicit accept the route is remembered");
    let _ = (alice_tx, bob_tx);
}

/// **Compartments are real, not decorative**: a session must use ITS OWN account's
/// relay — even when that is inconvenient. Account 2 is given a DEAD relay of its own;
/// switching to it must FAIL to publish, not quietly succeed by reusing account 1's
/// working relay.
///
/// That is the same "no silent fallback" rule as the carrier allowlist, applied to
/// identities: silently borrowing the other compartment's relay would put both personas
/// in one room, linked by IP + timing however different their keys are — while looking
/// like it worked.
///
/// Discriminating: reuse the previous account's relay on switch (what the code used to
/// do) and account 2 publishes fine over relay A → this reds.
#[test]
fn a_session_uses_its_own_accounts_relay_not_the_previous_ones() {
    let (relay_a, id_a) = spawn_relay();
    let dead_relay = "127.0.0.1:1".to_string(); // nothing listens there
    let dir = temp_dir("compartments");
    let (tx, rx) = spawn_worker_in(dir.clone(), Duration::from_secs(60));

    // Account 1 on the live relay A.
    tx.send(provision_cmd(&relay_a, &id_a, "pw", "")).unwrap();
    let ik1 = wait_unlocked(&rx);
    wait_publish(&rx);

    // Account 2: added (inherits A — a co-tenant), then given a relay of ITS OWN.
    tx.send(Cmd::AddAccount { phrase: client::seed::generate_mnemonic().to_string(), label: "second".into() })
        .unwrap();
    let ik2 = wait_unlocked(&rx);
    assert_ne!(ik2, ik1, "a separate identity");
    wait_publish(&rx);
    tx.send(Cmd::SetNet {
        relay_addr: dead_relay.clone(),
        relay_id: id_a.clone(), // same relay-id, unreachable address
        socks5: String::new(),
        routes: String::new(),
    })
    .unwrap();
    let _ = wait_unlocked(&rx);

    // Its config is its own now.
    let vault = client::store::Vault::unlock(&dir, b"pw").unwrap();
    let reg = vault.load_registry().unwrap();
    let a2 = reg.iter().find(|e| e.ik == ik2).expect("account 2 in the registry");
    assert_eq!(
        vault.account(&a2.id).load_net().unwrap().relay_addr,
        dead_relay,
        "account 2 remembers ITS relay, not the device's"
    );

    // Back to account 1 (live A) — it works.
    let a1 = reg.iter().find(|e| e.ik == ik1).expect("account 1").id.clone();
    tx.send(Cmd::SwitchAccount { id: a1 }).unwrap();
    let _ = wait_unlocked(&rx);
    wait_publish(&rx);

    // Now switch to account 2. It must go to ITS dead relay and FAIL — never borrow
    // account 1's working one.
    tx.send(Cmd::SwitchAccount { id: a2.id.clone() }).unwrap();
    let mut published_anyway = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Evt::Status(st)) => {
                let t = status_text(&st);
                if t.contains("ready to receive") {
                    published_anyway = true;
                    break;
                }
                if t.contains("publish") || t.contains("relay") || t.contains("transport") {
                    break; // honest failure on its OWN relay — what we want
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    assert!(
        !published_anyway,
        "account 2 must not publish — its own relay is dead. Succeeding means the session \
         silently borrowed account 1's relay, which is the fake-compartment bug"
    );
    let _ = tx;
}

/// The ACTIVE account's saved network config (it is per-account now — a compartment is
/// an identity plus its own relay).
fn account_net(dir: &std::path::Path, pass: &[u8]) -> client::store::NetSettings {
    let vault = client::store::Vault::unlock(dir, pass).unwrap();
    let reg = vault.load_registry().unwrap();
    vault.account(&reg.first().unwrap().id).load_net().unwrap()
}

/// Read a received file's bytes back out of the vault (the sealed at-rest copy) by
/// exporting it, the same way the user's "save as…" does.
fn export_bytes(dir: &std::path::Path, pass: &[u8], file_id: &str) -> Vec<u8> {
    let vault = client::store::Vault::unlock(dir, pass).unwrap();
    let reg = vault.load_registry().unwrap();
    let store = vault.account(&reg.first().unwrap().id);
    let out = dir.join(format!("exported-{file_id}"));
    store.export_received_file(file_id, &out).expect("export");
    std::fs::read(&out).unwrap()
}

/// Дренировать события до Status(публикация) — между Unlocked и ним теперь идёт
/// `Evt::History` (восстановление с диска), который тут пропускаем.
fn wait_publish(rx: &Receiver<Evt>) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(Evt::Status(s)) => {
                assert!(status_text(&s).contains("ready to receive"), "ожидали успех публикации, дано: {s:?}");
                return;
            }
            Ok(_) => {} // History(пусто) и т.п. — пропускаем
            Err(_) => panic!("таймаут ожидания публикации"),
        }
    }
}

/// Дренировать до Status об ошибке отправки (подтверждает, что worker обработал
/// падение `send_session` и ПРИНЯЛ решение НЕ логировать).
fn wait_send_failed(rx: &Receiver<Evt>) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(Evt::Status(s)) if status_text(&s).contains("send failed") => return,
            Ok(_) => {}
            Err(_) => panic!("таймаут ожидания Status(отправка не удалась)"),
        }
    }
}

/// Дренировать события до Status, содержащего `needle`.
fn wait_status_contains(rx: &Receiver<Evt>, needle: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(Evt::Status(s)) if status_text(&s).contains(needle) => return,
            Ok(_) => {}
            Err(_) => panic!("таймаут ожидания Status(…{needle}…)"),
        }
    }
}

/// Читать события до `Evt::History` (эмитится сразу после Unlocked).
fn wait_history(rx: &Receiver<Evt>) -> Vec<client::store::HistoryRecord> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(Evt::History(recs)) => return recs,
            Ok(_) => {}
            Err(_) => panic!("таймаут ожидания History"),
        }
    }
}

/// Читать до первого Received (без явного Poll — доставку гонит авто-poll worker'а).
fn wait_received(rx: &Receiver<Evt>) -> Vec<IncomingText> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(Evt::Received(msgs)) => return msgs,
            Ok(Evt::Status(s)) => {
                assert!(!status_text(&s).contains("failed") && !status_text(&s).contains("poll:"), "ошибка worker: {s:?}")
            }
            Ok(_) => {}
            Err(_) => panic!("таймаут ожидания Received (авто-poll)"),
        }
    }
}

/// Прочитать события до `Evt::Contacts` (эмитится сразу после Unlocked).
fn wait_contacts(rx: &Receiver<Evt>) -> Vec<Contact> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(Evt::Contacts(list)) => return list,
            Ok(_) => {}
            Err(_) => panic!("таймаут ожидания Contacts"),
        }
    }
}

/// Read events until `Evt::ExtraRelays` (the account's configured secondary relays).
fn wait_extra_relays(rx: &Receiver<Evt>) -> Vec<(String, String)> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(Evt::ExtraRelays(list)) => return list,
            Ok(_) => {}
            Err(_) => panic!("timeout waiting for ExtraRelays"),
        }
    }
}

/// Прочитать события до `Evt::Accounts` (список аккаунтов + активный).
fn wait_accounts(rx: &Receiver<Evt>) -> (Vec<AccountInfo>, String) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(Evt::Accounts { list, active }) => return (list, active),
            Ok(_) => {}
            Err(_) => panic!("таймаут ожидания Accounts"),
        }
    }
}

/// Прочитать события до `Evt::SendResult` с заданным id (маркер, что очередь
/// команд worker'а дошла до этой точки — команды обрабатываются FIFO).
fn wait_send_result(rx: &Receiver<Evt>, want_id: u64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(Evt::SendResult { id, .. }) if id == want_id => return,
            Ok(_) => {}
            Err(_) => panic!("таймаут ожидания SendResult({want_id})"),
        }
    }
}

/// Прочитать события до Unlocked (вернуть own_ik) — с таймаутом.
fn wait_unlocked(rx: &Receiver<Evt>) -> [u8; 32] {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(Evt::Unlocked { own_ik }) => return own_ik,
            Ok(_) => continue,
            Err(_) => panic!("таймаут ожидания Unlocked"),
        }
    }
}

/// Опрашивать (явный `Cmd::Poll`) в цикле до первого Received — как делает
/// авто-poll реального UI. Устраняет гонку «опросил раньше доставки».
fn poll_until_received(tx: &Sender<Cmd>, rx: &Receiver<Evt>) -> Vec<IncomingText> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        tx.send(Cmd::Poll).unwrap();
        match rx.recv_timeout(Duration::from_millis(300)) {
            Ok(Evt::Received(msgs)) => return msgs,
            Ok(Evt::Status(s)) => {
                assert!(!status_text(&s).contains("failed") && !status_text(&s).contains("poll:"), "ошибка worker: {s:?}");
            }
            Ok(_) => {}
            Err(_) => {} // пустой опрос → повтор
        }
    }
    panic!("таймаут ожидания Received");
}

/// Слать `Cmd::Poll` до `Evt::FileReceived`. Возвращает (имя, file_id) — принятые
/// файлы шифруются at-rest, поэтому пути нет: содержимое достаётся `export_file`.
fn poll_until_file(tx: &Sender<Cmd>, rx: &Receiver<Evt>) -> (String, String) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        tx.send(Cmd::Poll).unwrap();
        match rx.recv_timeout(Duration::from_millis(300)) {
            Ok(Evt::FileReceived { name, file_id, .. }) => return (name, file_id),
            Ok(Evt::Status(s)) => {
                assert!(!status_text(&s).contains("rejected") && !status_text(&s).contains("poll:"), "ошибка worker: {s:?}")
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    panic!("таймаут ожидания FileReceived");
}

#[test]
fn two_workers_exchange_message_over_relay() {
    let (relay_addr, relay_id) = spawn_relay();

    // Длинный интервал → авто-poll не мешает детерминизму (гоним явным Cmd::Poll).
    let (alice_tx, alice_rx) = spawn_worker("alice", Duration::from_secs(60));
    let (bob_tx, bob_rx) = spawn_worker("bob", Duration::from_secs(60));

    // Первое открытие пустого профиля = создание аккаунта (Provision).
    let unlock = |addr: &str, rid: &str, pass: &str| provision_cmd(addr, rid, pass, "");

    // Bob разблокируется и публикует bundle ПЕРВЫМ (чтобы Alice его нашла).
    bob_tx.send(unlock(&relay_addr, &relay_id, "bobpw")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx); // дать publish завершиться (History + Status после Unlocked)

    alice_tx.send(unlock(&relay_addr, &relay_id, "alicepw")).unwrap();
    let alice_ik = wait_unlocked(&alice_rx);

    // Alice шлёт Bob.
    alice_tx.send(Cmd::Send { id: 1, to_ik: bob_ik, text: "hi from alice gui".into(), ts: 0 }).unwrap();

    // Bob опрашивает (в цикле) и получает — с верной атрибуцией.
    let got = poll_until_received(&bob_tx, &bob_rx);
    assert_eq!(got.len(), 1, "одно сообщение");
    assert_eq!(got[0].sender, alice_ik, "атрибутировано Alice");
    assert_eq!(got[0].plaintext, b"hi from alice gui", "текст доставлен");
    let _ = alice_rx; // держим канал живым до конца теста
}

/// Путь приёма, который РЕАЛЬНО использует приложение: worker сам опрашивает relay
/// по таймауту (ветка `Err(Timeout) => poll`), UI никогда не шлёт `Cmd::Poll`.
/// Здесь Bob получает БЕЗ единого явного Poll — только фоновым авто-опросом.
#[test]
fn auto_poll_delivers_without_explicit_poll() {
    let (relay_addr, relay_id) = spawn_relay();

    let (alice_tx, alice_rx) = spawn_worker("alice-auto", Duration::from_secs(60));
    // Короткий интервал у Bob → авто-poll срабатывает часто.
    let (_bob_tx, bob_rx) = spawn_worker("bob-auto", Duration::from_millis(200));

    // Первое открытие пустого профиля = создание аккаунта (Provision).
    let unlock = |addr: &str, rid: &str, pass: &str| provision_cmd(addr, rid, pass, "");

    _bob_tx.send(unlock(&relay_addr, &relay_id, "bobpw")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);

    alice_tx.send(unlock(&relay_addr, &relay_id, "alicepw")).unwrap();
    let alice_ik = wait_unlocked(&alice_rx);

    alice_tx.send(Cmd::Send { id: 1, to_ik: bob_ik, text: "auto-poll works".into(), ts: 0 }).unwrap();

    // Ни одного Cmd::Poll — доставку гонит только авто-poll Bob'а.
    let got = wait_received(&bob_rx);
    assert_eq!(got.len(), 1, "одно сообщение");
    assert_eq!(got[0].sender, alice_ik, "атрибутировано Alice");
    assert_eq!(got[0].plaintext, b"auto-poll works", "текст доставлен авто-poll'ом");
    let _ = alice_rx;
}

/// История ПЕРЕЖИВАЕТ рестарт worker'а: Alice→Bob, Bob получает и логирует; затем
/// НОВЫЙ worker Bob'а на ТОМ ЖЕ каталоге при unlock отдаёт `Evt::History` с этим
/// сообщением (входящее логируется безусловно). Это и есть закрытие границы
/// «история исчезает при закрытии».
#[test]
fn history_survives_worker_restart() {
    let (relay_addr, relay_id) = spawn_relay();
    let alice_dir = temp_dir("alice-hist");
    let bob_dir = temp_dir("bob-hist");

    let (alice_tx, alice_rx) = spawn_worker_in(alice_dir, Duration::from_secs(60));
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir.clone(), Duration::from_secs(60));

    // Первое открытие пустого профиля = создание аккаунта (Provision).
    let unlock = |addr: &str, rid: &str, pass: &str| provision_cmd(addr, rid, pass, "");

    bob_tx.send(unlock(&relay_addr, &relay_id, "bobpw")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);

    alice_tx.send(unlock(&relay_addr, &relay_id, "alicepw")).unwrap();
    let alice_ik = wait_unlocked(&alice_rx);

    alice_tx.send(Cmd::Send { id: 1, to_ik: bob_ik, text: "persist me".into(), ts: 0 }).unwrap();
    let got = poll_until_received(&bob_tx, &bob_rx);
    assert_eq!(got[0].plaintext, b"persist me", "Bob принял (и залогировал) до рестарта");

    // Рестарт Bob: закрываем каналы → worker-поток выходит, Store дропается.
    drop(bob_tx);
    drop(bob_rx);
    let (bob2_tx, bob2_rx) = spawn_worker_in(bob_dir, Duration::from_secs(60));
    bob2_tx.send(unlock_cmd(&relay_addr, &relay_id, "bobpw")).unwrap(); // рестарт: корень уже на диске
    let _ = wait_unlocked(&bob2_rx);

    // Ключевая проверка: история восстановлена с диска.
    let hist = wait_history(&bob2_rx);
    assert_eq!(hist.len(), 1, "одна запись пережила рестарт");
    assert!(!hist[0].from_me, "входящее (не своё)");
    assert_eq!(hist[0].peer_ik, alice_ik, "чат с Alice");
    assert_eq!(hist[0].text, b"persist me", "текст сохранён");

    let _ = alice_rx;
}

/// Worker пишет в историю `ts` ИЗ Cmd (штамп контроллера), а НЕ свои часы — так
/// ts в памяти и на диске совпадают (нужно для удаления по (ts,from_me,text)).
/// Дискриминирующий: если бы worker ставил `wall_clock()`, ts не был бы 7_654_321.
#[test]
fn worker_writes_controller_ts_to_history_not_wall_clock() {
    let (relay_addr, relay_id) = spawn_relay();
    let alice_dir = temp_dir("alice-ts");
    let bob_dir = temp_dir("bob-ts");
    let (alice_tx, alice_rx) = spawn_worker_in(alice_dir.clone(), Duration::from_secs(60));
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir, Duration::from_secs(60));
    let unlock = |addr: &str, rid: &str, pass: &str| provision_cmd(addr, rid, pass, "");

    bob_tx.send(unlock(&relay_addr, &relay_id, "bobpw")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);
    alice_tx.send(unlock(&relay_addr, &relay_id, "alicepw")).unwrap();
    let _ = wait_unlocked(&alice_rx);

    // Отправляем с известным ts; получатель нужен онлайн, чтобы send удался и записался.
    alice_tx.send(Cmd::Send { id: 1, to_ik: bob_ik, text: "stamped".into(), ts: 7_654_321 }).unwrap();
    let _ = poll_until_received(&bob_tx, &bob_rx);

    // Рестарт Alice → её история с диска: ts == штамп из Cmd.
    drop(alice_tx);
    drop(alice_rx);
    let (a2_tx, a2_rx) = spawn_worker_in(alice_dir, Duration::from_secs(60));
    a2_tx.send(unlock_cmd(&relay_addr, &relay_id, "alicepw")).unwrap();
    let _ = wait_unlocked(&a2_rx);
    let hist = wait_history(&a2_rx);
    assert_eq!(hist.len(), 1);
    assert!(hist[0].from_me, "исходящее Alice");
    assert_eq!(hist[0].ts, 7_654_321, "worker записал ts из Cmd, не wall_clock");
    let _ = bob_tx;
}

/// `Cmd::DeleteMessage` стирает ОДНУ запись на диске: после удаления первого из
/// двух сообщений и рестарта Alice в истории остаётся только второе. Дискриминирующий:
/// если бы worker не перезаписывал историю, удалённое пережило бы рестарт.
#[test]
fn delete_one_message_persists_and_keeps_the_rest() {
    let (relay_addr, relay_id) = spawn_relay();
    let alice_dir = temp_dir("alice-del1");
    let bob_dir = temp_dir("bob-del1");
    let (alice_tx, alice_rx) = spawn_worker_in(alice_dir.clone(), Duration::from_secs(60));
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir, Duration::from_secs(60));
    let unlock = |addr: &str, rid: &str, pass: &str| provision_cmd(addr, rid, pass, "");

    bob_tx.send(unlock(&relay_addr, &relay_id, "bobpw")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);
    alice_tx.send(unlock(&relay_addr, &relay_id, "alicepw")).unwrap();
    let _ = wait_unlocked(&alice_rx);

    alice_tx.send(Cmd::Send { id: 1, to_ik: bob_ik, text: "m1".into(), ts: 100 }).unwrap();
    let _ = poll_until_received(&bob_tx, &bob_rx);
    alice_tx.send(Cmd::Send { id: 2, to_ik: bob_ik, text: "m2".into(), ts: 200 }).unwrap();
    let _ = poll_until_received(&bob_tx, &bob_rx);

    // Удалить первое (m1, ts=100, своё).
    alice_tx
        .send(Cmd::DeleteMessage { ik: bob_ik, ts: 100, from_me: true, text: "m1".into() })
        .unwrap();

    drop(alice_tx);
    drop(alice_rx);
    let (a2_tx, a2_rx) = spawn_worker_in(alice_dir, Duration::from_secs(60));
    a2_tx.send(unlock_cmd(&relay_addr, &relay_id, "alicepw")).unwrap();
    let _ = wait_unlocked(&a2_rx);
    let hist = wait_history(&a2_rx);
    assert_eq!(hist.len(), 1, "осталась одна запись");
    assert_eq!(hist[0].text, b"m2", "удалено именно m1, m2 цело");
    let _ = bob_tx;
}

/// Кросс-девайс идентичность + «удалить у всех»: получатель хранит ts ОТПРАВИТЕЛЯ
/// (Content::TextStamped), поэтому tombstone от отправителя находит и стирает копию
/// получателя — и в памяти (Evt::MessageDeleted), и на диске (пережив рестарт).
/// Дискриминирующий: если бы получатель хранил своё время прибытия, ts не совпал бы
/// и удаление у всех не сработало.
#[test]
fn delete_for_everyone_reaches_recipient_via_shared_ts() {
    let (relay_addr, relay_id) = spawn_relay();
    let alice_dir = temp_dir("alice-dfe");
    let bob_dir = temp_dir("bob-dfe");
    let (alice_tx, alice_rx) = spawn_worker_in(alice_dir, Duration::from_secs(60));
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir.clone(), Duration::from_secs(60));
    let unlock = |addr: &str, rid: &str, pass: &str| provision_cmd(addr, rid, pass, "");

    bob_tx.send(unlock(&relay_addr, &relay_id, "bobpw")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);
    alice_tx.send(unlock(&relay_addr, &relay_id, "alicepw")).unwrap();
    let alice_ik = wait_unlocked(&alice_rx);

    // Alice шлёт со штампом ts=424242; получатель ДОЛЖЕН сохранить именно этот ts.
    alice_tx.send(Cmd::Send { id: 1, to_ik: bob_ik, text: "recall".into(), ts: 424_242 }).unwrap();
    let got = poll_until_received(&bob_tx, &bob_rx);
    assert_eq!(got[0].ts, 424_242, "получатель хранит ts ОТПРАВИТЕЛЯ (кросс-девайс id)");

    // Alice отзывает у всех.
    alice_tx.send(Cmd::DeleteForEveryone { to_ik: bob_ik, ts: 424_242, text: "recall".into() }).unwrap();
    // Bob опрашивает до tombstone.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut got_tombstone = false;
    while std::time::Instant::now() < deadline {
        bob_tx.send(Cmd::Poll).unwrap();
        if let Ok(Evt::MessageDeleted { peer, ts, .. }) = bob_rx.recv_timeout(Duration::from_millis(300)) {
            assert_eq!((peer, ts), (alice_ik, 424_242));
            got_tombstone = true;
            break;
        }
    }
    assert!(got_tombstone, "Bob получил tombstone");

    // Рестарт Bob → на диске записи нет (tombstone перезаписал историю).
    drop(bob_tx);
    drop(bob_rx);
    let (b2_tx, b2_rx) = spawn_worker_in(bob_dir, Duration::from_secs(60));
    b2_tx.send(unlock_cmd(&relay_addr, &relay_id, "bobpw")).unwrap();
    let _ = wait_unlocked(&b2_rx);
    assert!(wait_history(&b2_rx).is_empty(), "у всех: копия получателя стёрта и на диске");
    let _ = alice_rx;
}

/// Реакция доходит до собеседника ПО ПРОВОДУ и атрибутируется автору. Bob шлёт
/// со штампом → Alice реагирует по каноническому msg_id → Bob получает реакцию с
/// author = Alice в своей meta-карте. Дискриминирующий по кросс-устройственному
/// msg_id: обе стороны считают ОДИН id из абсолютного автора (bob_ik) — иначе
/// реакция села бы не на то сообщение (или никуда).
#[test]
fn reaction_reaches_peer_over_wire_and_attributes_to_author() {
    let (relay_addr, relay_id) = spawn_relay();
    let alice_dir = temp_dir("alice-react");
    let bob_dir = temp_dir("bob-react");
    let (alice_tx, alice_rx) = spawn_worker_in(alice_dir, Duration::from_secs(60));
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir, Duration::from_secs(60));
    let unlock = |addr: &str, rid: &str, pass: &str| provision_cmd(addr, rid, pass, "");

    // Оба публикуют (Bob шлёт Alice, затем Alice реагирует Bob'у — нужны оба bundle).
    alice_tx.send(unlock(&relay_addr, &relay_id, "alicepw")).unwrap();
    let alice_ik = wait_unlocked(&alice_rx);
    wait_publish(&alice_rx);
    bob_tx.send(unlock(&relay_addr, &relay_id, "bobpw")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);

    // Bob → Alice со штампом ts=T.
    let t = 987_654u64;
    bob_tx.send(Cmd::Send { id: 1, to_ik: alice_ik, text: "hello".into(), ts: t }).unwrap();
    let got = poll_until_received(&alice_tx, &alice_rx);
    assert_eq!(got[0].ts, t, "Alice хранит ts ОТПРАВИТЕЛЯ (кросс-девайс id)");

    // Alice реагирует на сообщение Bob'а: msg_id по АБСОЛЮТНОМУ автору = bob_ik.
    let id = client::content::msg_id(&bob_ik, t, b"hello");
    alice_tx
        .send(Cmd::React { to_ik: bob_ik, msg_id: id, emoji: "👍".into(), add: true })
        .unwrap();

    // Bob опрашивает до Evt::Meta с реакцией author=Alice на ЭТОТ msg_id.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut ok = false;
    while std::time::Instant::now() < deadline {
        bob_tx.send(Cmd::Poll).unwrap();
        if let Ok(Evt::Meta(map)) = bob_rx.recv_timeout(Duration::from_millis(300)) {
            if let Some(mm) = map.get(&id) {
                assert!(
                    mm.reactions.get("👍").is_some_and(|a| a.contains(&alice_ik)),
                    "реакция атрибутирована Alice (по расшифровавшей сессии)"
                );
                ok = true;
                break;
            }
        }
    }
    assert!(ok, "Bob получил реакцию Alice по проводу");
    let _ = alice_ik;
}

/// Блокировка: сообщение от заблокированного IK НЕ доставляется в UI. Дискриминирующий
/// — без enforcement (`continue` по блок-листу в начале приёма) текст Bob'а долетел бы
/// как `Evt::Received`.
#[test]
fn blocked_sender_messages_are_dropped_on_receive() {
    let (relay_addr, relay_id) = spawn_relay();
    let alice_dir = temp_dir("alice-block");
    let bob_dir = temp_dir("bob-block");
    let (alice_tx, alice_rx) = spawn_worker_in(alice_dir, Duration::from_secs(60));
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir, Duration::from_secs(60));
    let unlock = |a: &str, r: &str, p: &str| provision_cmd(a, r, p, "");

    alice_tx.send(unlock(&relay_addr, &relay_id, "apw")).unwrap();
    let alice_ik = wait_unlocked(&alice_rx);
    wait_publish(&alice_rx);
    bob_tx.send(unlock(&relay_addr, &relay_id, "bpw")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);

    // Alice блокирует Bob; ждём эхо Evt::Blocked с его IK.
    alice_tx.send(Cmd::SetBlocked { ik: bob_ik, blocked: true }).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut blocked_ok = false;
    while std::time::Instant::now() < deadline {
        if let Ok(Evt::Blocked(set)) = alice_rx.recv_timeout(Duration::from_millis(300)) {
            if set.contains(&bob_ik) {
                blocked_ok = true;
                break;
            }
        }
    }
    assert!(blocked_ok, "блокировка применена");

    // Bob шлёт Alice — должно быть дропнуто на приёме.
    bob_tx.send(Cmd::Send { id: 1, to_ik: alice_ik, text: "you blocked me".into(), ts: 111 }).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    let mut got_received = false;
    while std::time::Instant::now() < deadline {
        alice_tx.send(Cmd::Poll).unwrap();
        if let Ok(Evt::Received(_)) = alice_rx.recv_timeout(Duration::from_millis(300)) {
            got_received = true;
            break;
        }
    }
    assert!(!got_received, "сообщение от заблокированного НЕ доставлено в UI");
    let _ = bob_rx;
}

/// `Cmd::ClearChat` стирает переписку И НА ДИСКЕ: после очистки чата с Alice и
/// рестарта Bob'а история пуста (чат не «воскресает»). Дискриминирующий: если бы
/// ClearChat не трогал диск (только память UI), запись пережила бы рестарт.
#[test]
fn clear_chat_wipes_disk_history_across_restart() {
    let (relay_addr, relay_id) = spawn_relay();
    let alice_dir = temp_dir("alice-clear");
    let bob_dir = temp_dir("bob-clear");

    let (alice_tx, alice_rx) = spawn_worker_in(alice_dir, Duration::from_secs(60));
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir.clone(), Duration::from_secs(60));
    let unlock = |addr: &str, rid: &str, pass: &str| provision_cmd(addr, rid, pass, "");

    bob_tx.send(unlock(&relay_addr, &relay_id, "bobpw")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    let (_, bob_acct) = wait_accounts(&bob_rx);
    wait_publish(&bob_rx);

    alice_tx.send(unlock(&relay_addr, &relay_id, "alicepw")).unwrap();
    let alice_ik = wait_unlocked(&alice_rx);

    alice_tx.send(Cmd::Send { id: 1, to_ik: bob_ik, text: "temp".into(), ts: 0 }).unwrap();
    let got = poll_until_received(&bob_tx, &bob_rx);
    assert_eq!(got[0].plaintext, b"temp", "Bob принял и залогировал");

    // Очистить переписку с Alice → должно стереть запись на диске Bob'а.
    bob_tx.send(Cmd::ClearChat { ik: alice_ik }).unwrap();

    // Barrier before the restart: re-read history on the SAME worker. The command loop
    // is FIFO on one thread, so an empty History here proves ClearChat already reached
    // disk. Without it the restart could race a still-queued ClearChat — the worker
    // holds its own cmd_tx clone, so `drop(bob_tx)` neither flushes the queue nor stops
    // the thread, and on a slow runner bob2 read the disk before the clear landed.
    bob_tx.send(Cmd::SwitchAccount { id: bob_acct }).unwrap();
    assert!(wait_history(&bob_rx).is_empty(), "ClearChat wiped the on-disk history at once");

    // Рестарт Bob.
    drop(bob_tx);
    drop(bob_rx);
    let (bob2_tx, bob2_rx) = spawn_worker_in(bob_dir, Duration::from_secs(60));
    bob2_tx.send(unlock_cmd(&relay_addr, &relay_id, "bobpw")).unwrap();
    let _ = wait_unlocked(&bob2_rx);

    let hist = wait_history(&bob2_rx);
    assert!(hist.is_empty(), "после ClearChat история пуста и после рестарта");

    let _ = alice_rx;
}

/// Слать `Cmd::Poll` до `Evt::ReceivedExpiring` (исчезающее доставлено).
fn poll_until_expiring(tx: &Sender<Cmd>, rx: &Receiver<Evt>) -> Vec<ExpiringIn> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        tx.send(Cmd::Poll).unwrap();
        match rx.recv_timeout(Duration::from_millis(300)) {
            Ok(Evt::ReceivedExpiring(msgs)) => return msgs,
            Ok(Evt::Status(s)) => assert!(!status_text(&s).contains("failed") && !status_text(&s).contains("poll:"), "ошибка: {s:?}"),
            Ok(_) => {}
            Err(_) => {}
        }
    }
    panic!("таймаут ожидания ReceivedExpiring");
}

/// Исчезающее сообщение доставляется как `ReceivedExpiring` (с абсолютным
/// expire_at в будущем) И НЕ пишется в историю у получателя: после рестарта Bob'а
/// история пуста. Дискриминирующий на never-persist: если бы worker логировал этот
/// вариант, запись пережила бы рестарт.
#[test]
fn expiring_message_delivered_but_never_persisted() {
    let (relay_addr, relay_id) = spawn_relay();
    let alice_dir = temp_dir("alice-exp");
    let bob_dir = temp_dir("bob-exp");

    let (alice_tx, alice_rx) = spawn_worker_in(alice_dir, Duration::from_secs(60));
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir.clone(), Duration::from_secs(60));
    let unlock = |addr: &str, rid: &str, pass: &str| provision_cmd(addr, rid, pass, "");

    bob_tx.send(unlock(&relay_addr, &relay_id, "bobpw")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);

    alice_tx.send(unlock(&relay_addr, &relay_id, "alicepw")).unwrap();
    let alice_ik = wait_unlocked(&alice_rx);

    // Долгий TTL (час) → доставится живым; проверяем именно доставку + непопадание в лог.
    alice_tx
        .send(Cmd::SendExpiring { id: 1, to_ik: bob_ik, text: "burn after reading".into(), ttl_secs: 3600 })
        .unwrap();
    let got = poll_until_expiring(&bob_tx, &bob_rx);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].sender, alice_ik, "атрибуция отправителя");
    assert_eq!(got[0].text, b"burn after reading");
    assert!(got[0].expire_at > 0, "абсолютный expire_at проставлен worker'ом");

    // Рестарт Bob: исчезающее НЕ должно всплыть из истории.
    drop(bob_tx);
    drop(bob_rx);
    let (bob2_tx, bob2_rx) = spawn_worker_in(bob_dir, Duration::from_secs(60));
    bob2_tx.send(unlock_cmd(&relay_addr, &relay_id, "bobpw")).unwrap();
    let _ = wait_unlocked(&bob2_rx);
    let hist = wait_history(&bob2_rx);
    assert!(hist.is_empty(), "исчезающее не пишется на диск — истории нет");

    let _ = alice_rx;
}

/// Заголовочное свойство среза: УСПЕШНАЯ отправка сохраняется, а ПРОВАЛЬНАЯ —
/// исчезает на рестарте (не остаётся долговечно как «доставлено»). Alice шлёт
/// Bob'у (Ok → лог) и на несуществующий IK без bundle (send_session падает → НЕ
/// лог). После рестарта Alice в истории РОВНО одна запись — к Bob'у.
/// Дискриминирующий: убрать гейт `Ok(())` (логировать безусловно) → записей две.
#[test]
fn failed_send_vanishes_but_ok_send_persists_across_restart() {
    let (relay_addr, relay_id) = spawn_relay();
    let alice_dir = temp_dir("alice-failsend");
    let bob_dir = temp_dir("bob-failsend");

    let (alice_tx, alice_rx) = spawn_worker_in(alice_dir.clone(), Duration::from_secs(60));
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir, Duration::from_secs(60));

    // Первое открытие пустого профиля = создание аккаунта (Provision).
    let unlock = |addr: &str, rid: &str, pass: &str| provision_cmd(addr, rid, pass, "");

    // Bob публикует bundle — реальный получатель для успешной отправки.
    bob_tx.send(unlock(&relay_addr, &relay_id, "bobpw")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);

    alice_tx.send(unlock(&relay_addr, &relay_id, "alicepw")).unwrap();
    let _ = wait_unlocked(&alice_rx);

    // (1) Успешная отправка Bob'у. Приём Bob'ом подтверждает Ok → лог состоялся.
    alice_tx.send(Cmd::Send { id: 1, to_ik: bob_ik, text: "to bob".into(), ts: 0 }).unwrap();
    let got = poll_until_received(&bob_tx, &bob_rx);
    assert_eq!(got[0].plaintext, b"to bob");

    // (2) Отправка на IK без опубликованного bundle → send_session падает.
    alice_tx.send(Cmd::Send { id: 1, to_ik: [0xAB; 32], text: "into the void".into(), ts: 0 }).unwrap();
    wait_send_failed(&alice_rx); // worker принял решение НЕ логировать

    // Рестарт Alice на том же каталоге.
    drop(alice_tx);
    drop(alice_rx);
    let (alice2_tx, alice2_rx) = spawn_worker_in(alice_dir, Duration::from_secs(60));
    alice2_tx.send(unlock_cmd(&relay_addr, &relay_id, "alicepw")).unwrap(); // рестарт: корень уже на диске
    let _ = wait_unlocked(&alice2_rx);

    let hist = wait_history(&alice2_rx);
    assert_eq!(hist.len(), 1, "ровно одна запись: провальная отправка не сохранена");
    assert!(hist[0].from_me, "исходящее");
    assert_eq!(hist[0].peer_ik, bob_ik, "к Bob'у");
    assert_eq!(hist[0].text, b"to bob", "успешная отправка сохранена");

    let _ = bob_tx;
}

/// Заголовочное свойство пивота: GUI РЕАЛЬНО маршрутизирует через настроенный
/// SOCKS5 (Tor/obfs4) ВСЕ три сетевых вызова (publish/send/recv), а не роняет
/// прокси молча на каком-то из них. Пиннит каждый отдельным ростом счётчика
/// CONNECT. Дискриминирующий: верни ЛЮБОЙ вызов к `None` → его CONNECT исчезнет →
/// счётчик не вырастет на том шаге → красный. Тот самый catastrophic-and-invisible
/// баг: «думаю, что в Tor, а иду напрямую» — по каждому вызову.
#[test]
fn worker_routes_all_calls_through_configured_socks5_proxy() {
    let (relay_addr, relay_id) = spawn_relay();
    let (proxy_addr, count) = spawn_socks5_stub();

    let (tx, rx) = spawn_worker("socks-route", Duration::from_secs(60));
    tx.send(provision_cmd(&relay_addr, &relay_id, "pw", &proxy_addr.to_string())).unwrap();
    let _ = wait_unlocked(&rx);

    // (1) publish на unlock → CONNECT через прокси.
    wait_publish(&rx);
    let c_publish = wait_count_above(&count, 0);

    // (2) send (на несуществующий IK): fetch_bundle открывает CONNECT ДО провала.
    tx.send(Cmd::Send { id: 1, to_ik: [0xCD; 32], text: "via tor".into(), ts: 0 }).unwrap();
    wait_status_contains(&rx, "send failed");
    let c_send = wait_count_above(&count, c_publish);

    // (3) recv (явный Poll): fetch mailbox → CONNECT через прокси (даже на пустом).
    tx.send(Cmd::Poll).unwrap();
    wait_count_above(&count, c_send);

    let _ = tx;
}

/// No-fallback на уровне GUI: мёртвый SOCKS5 → publish ЖЁСТКО падает и НЕ уходит
/// на relay напрямую. Доказательство «не напрямую»: Alice (прямая) не может
/// достучаться до Bob'а — значит его bundle НЕ попал на relay в обход прокси.
#[test]
fn dead_socks5_hard_fails_no_direct_leak() {
    let (relay_addr, relay_id) = spawn_relay();
    let dead = dead_addr();

    // Bob с МЁРТВЫМ прокси: unlock проходит, но publish обязан упасть (без fallback).
    let (bob_tx, bob_rx) = spawn_worker("socks-dead-bob", Duration::from_secs(60));
    bob_tx.send(provision_cmd(&relay_addr, &relay_id, "pw", &dead.to_string())).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_status_contains(&bob_rx, "failed"); // publish жёстко упал

    // Alice ПРЯМАЯ: публикуется нормально, затем шлёт Bob'у.
    let (alice_tx, alice_rx) = spawn_worker("socks-dead-alice", Duration::from_secs(60));
    alice_tx.send(provision_cmd(&relay_addr, &relay_id, "pw", "")).unwrap();
    let _ = wait_unlocked(&alice_rx);
    wait_publish(&alice_rx);

    // Bob'а нет на relay (его publish не ушёл в обход мёртвого прокси) → send падает.
    alice_tx.send(Cmd::Send { id: 1, to_ik: bob_ik, text: "should not reach".into(), ts: 0 }).unwrap();
    wait_status_contains(&alice_rx, "send failed");
    let _ = (bob_tx, alice_tx);
}

/// Передача ФАЙЛА через worker'ы: Alice шлёт файл (Cmd::SendFile), Bob собирает
/// чанки МЕЖДУ poll'ами (reasm живёт в Session), сохраняет на диск байт-в-байт.
/// Poll (explicit `Cmd::Poll`) until Bob's `PeerProfiles` carries a non-empty avatar
/// for `sender`; returns the stored (sanitized/re-encoded) bytes.
fn poll_until_peer_avatar(tx: &Sender<Cmd>, rx: &Receiver<Evt>, sender: [u8; 32]) -> Vec<u8> {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        tx.send(Cmd::Poll).unwrap();
        match rx.recv_timeout(Duration::from_millis(300)) {
            Ok(Evt::PeerProfiles(map)) => {
                if let Some(av) = map.get(&sender).and_then(|p| p.avatar.clone()) {
                    if !av.is_empty() {
                        return av;
                    }
                }
            }
            Ok(Evt::Status(s)) => {
                assert!(!status_text(&s).contains("rejected") && !status_text(&s).contains("poll:"), "worker error: {s:?}")
            }
            _ => {}
        }
    }
    panic!("timeout waiting for peer avatar");
}

/// Full avatar path through the worker: Alice `Cmd::SetAvatar` → `avatar::ingest` →
/// broadcast → wire chunks → Bob reassembles → `Assembled::Avatar` arm →
/// `avatar::sanitize` (the security-critical untrusted-decode-on-receipt) →
/// `set_peer_avatar` → `Evt::PeerProfiles`. Asserts the stored avatar decodes and is
/// downscaled to <=128px, proving the ingest+sanitize pipeline actually ran (a 300x200
/// source that survived un-resized would be 300px). Bomb/non-PNG rejection is covered
/// by the neuter-verified unit tests in `gui::avatar`.
#[test]
fn worker_sends_and_receives_avatar_through_bounded_pipeline() {
    use std::io::Cursor;

    let (relay_addr, relay_id) = spawn_relay();
    let alice_dir = temp_dir("wav-alice");
    let bob_dir = temp_dir("wav-bob");

    let (alice_tx, alice_rx) = spawn_worker_in(alice_dir.clone(), Duration::from_secs(60));
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir.clone(), Duration::from_secs(60));

    let unlock = |addr: &str, rid: &str, pass: &str| provision_cmd(addr, rid, pass, "");
    bob_tx.send(unlock(&relay_addr, &relay_id, "bobpw")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);

    alice_tx.send(unlock(&relay_addr, &relay_id, "alicepw")).unwrap();
    let alice_ik = wait_unlocked(&alice_rx);

    // Alice must have Bob as a contact — the avatar broadcast iterates contacts.
    alice_tx
        .send(Cmd::SaveContacts {
            id: hex::encode(alice_ik),
            contacts: vec![Contact { name: "Bob".into(), ik: bob_ik, verified: false }],
        })
        .unwrap();
    // Establish a session with a text first (so chunks ride an existing ratchet).
    alice_tx.send(Cmd::Send { id: 1, to_ik: bob_ik, text: "avatar incoming".into(), ts: 0 }).unwrap();

    // A 300x200 PNG on disk — larger than the 128px cap, so a working pipeline MUST
    // downscale it.
    let png = {
        let buf = image::RgbaImage::from_pixel(300, 200, image::Rgba([200, 40, 90, 255]));
        let mut out = Vec::new();
        image::DynamicImage::ImageRgba8(buf)
            .write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
            .unwrap();
        out
    };
    let src = alice_dir.join("me.png");
    std::fs::write(&src, &png).unwrap();
    alice_tx.send(Cmd::SetAvatar { path: src.to_string_lossy().into_owned() }).unwrap();

    let got = poll_until_peer_avatar(&bob_tx, &bob_rx, alice_ik);

    // The stored avatar decodes and was downscaled to the 128px box by ingest+sanitize.
    let img = image::ImageReader::new(Cursor::new(&got))
        .with_guessed_format()
        .unwrap()
        .decode()
        .expect("stored avatar is a valid image");
    assert!(img.width() <= 128 && img.height() <= 128, "avatar downscaled to <=128px (was 300x200)");
    assert!(got.len() <= client::content::MAX_AVATAR_BYTES, "within byte cap");

    let _ = (alice_tx, bob_tx);
}

#[test]
fn worker_sends_and_receives_file_byte_identical() {
    let (relay_addr, relay_id) = spawn_relay();
    let alice_dir = temp_dir("wfile-alice");
    let bob_dir = temp_dir("wfile-bob");

    let (alice_tx, alice_rx) = spawn_worker_in(alice_dir.clone(), Duration::from_secs(60));
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir.clone(), Duration::from_secs(60));

    // Первое открытие пустого профиля = создание аккаунта (Provision).
    let unlock = |addr: &str, rid: &str, pass: &str| provision_cmd(addr, rid, pass, "");

    bob_tx.send(unlock(&relay_addr, &relay_id, "bobpw")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);

    alice_tx.send(unlock(&relay_addr, &relay_id, "alicepw")).unwrap();
    let _ = wait_unlocked(&alice_rx);

    // Установить сессию текстом (манифест поедет как Ratchet), затем послать файл.
    alice_tx.send(Cmd::Send { id: 1, to_ik: bob_ik, text: "лови файл".into(), ts: 0 }).unwrap();

    // Файл ~4 KiB (несколько чанков) — детерминированное содержимое.
    let payload: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(13)) as u8).collect();
    let src = alice_dir.join("payload.bin");
    std::fs::write(&src, &payload).unwrap();
    alice_tx
        .send(Cmd::SendFile { id: 1, to_ik: bob_ik, path: src.to_string_lossy().into_owned(), ts: 0 })
        .unwrap();

    let (name, file_id) = poll_until_file(&bob_tx, &bob_rx);
    assert_eq!(name, "payload.bin", "имя файла доехало");
    // The received copy is SEALED at rest — read it the way the user does: export it.
    let got = export_bytes(&bob_dir, b"bobpw", &file_id);
    assert_eq!(got, payload, "файл собран байт-в-байт через worker");

    let _ = (alice_tx, bob_tx);
}

/// §15 LARGE file through the worker: a file well over the inline 240 KiB limit takes
/// the blob path (streamed up as an E2E blob, delivered as a small `FileRef`, streamed
/// back down) and arrives byte-identical. This is the discriminating end-to-end test for
/// the whole large-file feature — the inline path physically cannot carry this size
/// (mailbox cap + capability quota), so a pass proves the blob transport is doing it.
#[test]
fn worker_sends_and_receives_large_file_via_blob() {
    let (relay_addr, relay_id) = spawn_relay();
    let alice_dir = temp_dir("wblob-alice");
    let bob_dir = temp_dir("wblob-bob");

    let (alice_tx, alice_rx) = spawn_worker_in(alice_dir.clone(), Duration::from_secs(60));
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir.clone(), Duration::from_secs(60));

    let unlock = |addr: &str, rid: &str, pass: &str| provision_cmd(addr, rid, pass, "");
    bob_tx.send(unlock(&relay_addr, &relay_id, "bobpw")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);
    alice_tx.send(unlock(&relay_addr, &relay_id, "alicepw")).unwrap();
    let _ = wait_unlocked(&alice_rx);

    // Session established with a text first (the FileRef rides a Ratchet packet).
    alice_tx.send(Cmd::Send { id: 1, to_ik: bob_ik, text: "big file coming".into(), ts: 0 }).unwrap();

    // ~745 KiB: over MAX_FILE_SIZE (240 KiB) → blob path (~13 chunks of 60 KiB + FileRef).
    let n = client::content::MAX_FILE_SIZE as usize + 500_000;
    let payload: Vec<u8> = (0..n).map(|i| (i.wrapping_mul(31) ^ 0x5a) as u8).collect();
    let src = alice_dir.join("big.bin");
    std::fs::write(&src, &payload).unwrap();
    alice_tx
        .send(Cmd::SendFile { id: 2, to_ik: bob_ik, path: src.to_string_lossy().into_owned(), ts: 0 })
        .unwrap();

    let (name, file_id) = poll_until_file(&bob_tx, &bob_rx);
    assert_eq!(name, "big.bin", "имя большого файла доехало");
    let got = export_bytes(&bob_dir, b"bobpw", &file_id);
    assert_eq!(got.len(), payload.len(), "размер совпал");
    assert_eq!(got, payload, "большой файл собран байт-в-байт через blob-путь");

    // The send went through the RESUMABLE path (spawn_blob_upload persists a record keyed by the
    // recipient+name+size, continued from the relay's watermark on a crash). A successful send
    // clears that record — only a crash before completion leaves it for a resume-on-login.
    let astore = client::store::Store::unlock(&alice_dir, b"alicepw").unwrap();
    assert!(
        astore.list_pending_uploads().unwrap().is_empty(),
        "the resumable-upload record is cleared once the send completes"
    );

    let _ = (alice_tx, bob_tx);
}

/// #42 crash-safe UPLOAD resume: an upload interrupted mid-flight (its resumable record left on
/// disk) is RE-DRIVEN when the account next logs in — a process restart. Simulates the crash by
/// persisting the record + source file under a store, then bringing a FRESH worker up on it, and
/// asserts the blob actually gets uploaded to the relay (via `blob_stat`), no user action.
#[test]
fn a_crashed_upload_resumes_on_the_next_login() {
    let (relay_addr, relay_id) = spawn_relay();
    let dir = temp_dir("resume");

    // Worker #1: provision the account, then shut it down (the "crash") so a fresh worker can open
    // the same store.
    let (tx1, rx1) = spawn_worker_in(dir.clone(), Duration::from_secs(60));
    tx1.send(provision_cmd(&relay_addr, &relay_id, "pw", "")).unwrap();
    let _ = wait_unlocked(&rx1);
    drop(tx1);
    std::thread::sleep(Duration::from_millis(400));

    // Persist a resumable-upload record + its source file, as a crash mid-upload would have left.
    let n = client::content::MAX_FILE_SIZE as usize + 200_000;
    let payload: Vec<u8> = (0..n).map(|i| (i.wrapping_mul(37) ^ 0x3c) as u8).collect();
    let src = dir.join("resumed.bin");
    std::fs::write(&src, &payload).unwrap();
    let blob_id = [0x42u8; 32];
    {
        // The GUI keeps each account's state under `accounts/<id>/`, reached via the vault.
        let vault = client::store::Vault::unlock(&dir, b"pw").unwrap();
        let reg = vault.load_registry().unwrap();
        let store = vault.account(&reg.first().unwrap().id);
        store
            .add_pending_upload(&client::store::PendingUpload {
                upload_id: client::upload_id_for(&[9u8; 32], "resumed.bin", payload.len() as u64),
                blob_id,
                key: client::blob::random32(),
                to_ik: [9u8; 32], // no bundle → the FileRef won't deliver, but the BLOB still uploads
                name: "resumed.bin".into(),
                size: payload.len() as u64,
                queued_at: 0,
                path: Some(src.to_string_lossy().into_owned()),
            })
            .unwrap();
    }

    // Worker #2 on the SAME store: a device unlock (return login). The None→Some session transition
    // re-drives the interrupted upload with NO user action.
    let (tx2, rx2) = spawn_worker_in(dir.clone(), Duration::from_secs(60));
    tx2.send(unlock_cmd(&relay_addr, &relay_id, "pw")).unwrap();
    let _ = wait_unlocked(&rx2);

    // The relay ends up holding the complete blob — proof the resume re-drove the upload from the
    // persisted record (it uploads the ciphertext BEFORE it would send the FileRef).
    let np = hex::decode(&relay_id[..64]).unwrap();
    let fp = hex::decode(&relay_id[64..]).unwrap();
    let relay = client::Relay::new(
        relay_addr.parse::<std::net::SocketAddr>().unwrap(),
        client::RelayId { noise_pub: np.try_into().unwrap(), fetch_pub: fp.try_into().unwrap() },
        None,
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(Some((_, _, true))) = client::blob_stat(&relay, blob_id) {
            break; // fully uploaded by the resumed transfer
        }
        assert!(std::time::Instant::now() < deadline, "the crashed upload did not resume + complete on login");
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = tx2;
}

/// Пара каналов одного worker'а (команды туда, события обратно).
type WorkerPair = (Sender<Cmd>, Receiver<Evt>);

/// Set up a fresh Alice→Bob pair and an `n`-byte large file on disk; returns
/// (alice, bob, bob_ik, src_path, payload). The session is established with a text.
fn setup_large_send(
    tag: &str,
    n: usize,
) -> (WorkerPair, WorkerPair, [u8; 32], std::path::PathBuf, Vec<u8>) {
    let (relay_addr, relay_id) = spawn_relay();
    let alice_dir = temp_dir(&format!("{tag}-alice"));
    let bob_dir = temp_dir(&format!("{tag}-bob"));
    let (alice_tx, alice_rx) = spawn_worker_in(alice_dir.clone(), Duration::from_secs(60));
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir, Duration::from_secs(60));
    let unlock = |addr: &str, rid: &str, pass: &str| provision_cmd(addr, rid, pass, "");
    bob_tx.send(unlock(&relay_addr, &relay_id, "bobpw")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);
    alice_tx.send(unlock(&relay_addr, &relay_id, "alicepw")).unwrap();
    let _ = wait_unlocked(&alice_rx);
    alice_tx.send(Cmd::Send { id: 1, to_ik: bob_ik, text: "session".into(), ts: 0 }).unwrap();
    let payload: Vec<u8> = (0..n).map(|i| (i.wrapping_mul(31) ^ 0x5a) as u8).collect();
    let src = alice_dir.join("big.bin");
    std::fs::write(&src, &payload).unwrap();
    ((alice_tx, alice_rx), (bob_tx, bob_rx), bob_ik, src, payload)
}

/// Large-file progress STREAMS (not just a final 100%): among the sender's events
/// there is at least one `FileProgress{done, total}` with `0 < done < total`.
/// Discriminating: neuter `on_progress` in `blob_upload_with` to a no-op — the
/// intermediate progress disappears and this reds.
#[test]
fn worker_large_file_send_reports_intermediate_progress() {
    // ~1.7 MiB → the 512 KiB throttle yields several intermediate points (524288, 1048576, …).
    let n = client::content::MAX_FILE_SIZE as usize + 1_500_000;
    let ((alice_tx, alice_rx), (bob_tx, _bob_rx), bob_ik, src, _payload) =
        setup_large_send("wprog", n);
    alice_tx
        .send(Cmd::SendFile { id: 2, to_ik: bob_ik, path: src.to_string_lossy().into_owned(), ts: 0 })
        .unwrap();

    let mut saw_intermediate = false;
    let mut done_ok = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        match alice_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Evt::FileProgress { done, total, .. }) => {
                assert!(done <= total, "done {done} ≤ total {total}");
                if done > 0 && done < total {
                    saw_intermediate = true;
                }
            }
            Ok(Evt::SendResult { id: 2, ok }) => {
                assert!(ok, "the large file was sent");
                done_ok = true;
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    assert!(saw_intermediate, "an intermediate progress 0<done<total must arrive");
    assert!(done_ok, "the transfer finished successfully");
    let _ = (alice_tx, bob_tx);
}

/// Off-loop PROVEN: while a large upload runs, a quick text overtakes its result.
/// Alice sends the file (id 2) and then a text (id 3); `SendResult{id:3}` arrives
/// BEFORE `SendResult{id:2}`. With a blocking transfer (the old code) the file would
/// have owned the thread and the text would only be handled AFTER — the order would be
/// reversed. Discriminating.
#[test]
fn worker_stays_responsive_during_large_upload() {
    // ~3 MiB — the upload certainly outlasts a single text packet.
    let n = client::content::MAX_FILE_SIZE as usize + 3_000_000;
    let ((alice_tx, alice_rx), (bob_tx, _bob_rx), bob_ik, src, _payload) =
        setup_large_send("wresp", n);
    alice_tx
        .send(Cmd::SendFile { id: 2, to_ik: bob_ik, path: src.to_string_lossy().into_owned(), ts: 0 })
        .unwrap();
    // Immediately after: a quick text.
    alice_tx.send(Cmd::Send { id: 3, to_ik: bob_ik, text: "quick".into(), ts: 0 }).unwrap();

    let mut order: Vec<u64> = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    while std::time::Instant::now() < deadline && order.len() < 2 {
        match alice_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Evt::SendResult { id, ok }) if id == 2 || id == 3 => {
                assert!(ok, "both the text and the file were sent (id {id})");
                order.push(id);
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    assert_eq!(order, vec![3, 2], "the quick text (3) overtook the file (2) → the transfer is off-loop");
    let _ = (alice_tx, bob_tx);
}

/// Cancellation: a large upload can be aborted with `Cmd::CancelTransfer`; the bubble
/// is marked failed (`SendResult{ok:false}`) and the worker stays responsive (the next
/// text still goes out). Discriminating for off-loop + the cancel flag.
#[test]
fn worker_cancel_aborts_large_upload_and_stays_responsive() {
    // ~8 MiB — many chunks → a wide window for the cancel to land before the end.
    let n = client::content::MAX_FILE_SIZE as usize + 8_000_000;
    let ((alice_tx, alice_rx), (bob_tx, _bob_rx), bob_ik, src, _payload) =
        setup_large_send("wcancel", n);
    alice_tx
        .send(Cmd::SendFile { id: 2, to_ik: bob_ik, path: src.to_string_lossy().into_owned(), ts: 0 })
        .unwrap();
    // Cancel as early as possible (the flag is checked on a chunk boundary).
    alice_tx.send(Cmd::CancelTransfer { id: 2 }).unwrap();

    let mut file_ok: Option<bool> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    while std::time::Instant::now() < deadline {
        match alice_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Evt::SendResult { id: 2, ok }) => {
                file_ok = Some(ok);
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    assert_eq!(file_ok, Some(false), "a cancelled upload is marked failed");

    // The worker is alive: the next text goes out.
    alice_tx.send(Cmd::Send { id: 3, to_ik: bob_ik, text: "still alive".into(), ts: 0 }).unwrap();
    let mut alive = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        match alice_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Evt::SendResult { id: 3, ok }) => {
                alive = ok;
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    assert!(alive, "after the cancel the worker handled the next text");
    let _ = (alice_tx, bob_tx);
}

/// The receive lifecycle of a large file: the receiver sees `FileIncoming` (a
/// "receiving…" bubble with a bar) BEFORE `FileReceived`, with the same `id`, and at
/// least one `FileProgress{done<total}` in between. Discriminating for the off-loop
/// receive (otherwise there would be no bubble-with-bar — the file would just appear
/// finished).
#[test]
fn worker_receive_shows_incoming_bubble_then_progress() {
    // ~1.7 MiB → several progress points during the download.
    let n = client::content::MAX_FILE_SIZE as usize + 1_500_000;
    let ((alice_tx, _alice_rx), (bob_tx, bob_rx), bob_ik, src, _payload) =
        setup_large_send("wrecv", n);
    alice_tx
        .send(Cmd::SendFile { id: 2, to_ik: bob_ik, path: src.to_string_lossy().into_owned(), ts: 0 })
        .unwrap();

    let mut incoming_id: Option<u64> = None;
    let mut progress_for_incoming = false;
    let mut received_id: Option<u64> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline && received_id.is_none() {
        bob_tx.send(Cmd::Poll).unwrap();
        match bob_rx.recv_timeout(Duration::from_millis(300)) {
            Ok(Evt::FileIncoming { id, size, name, .. }) => {
                assert_eq!(name, "big.bin");
                assert_eq!(size as usize, n, "the receiving bubble knows the full size");
                assert_ne!(id, 0, "the receive id is non-zero");
                incoming_id = Some(id);
            }
            Ok(Evt::FileProgress { id, done, total }) => {
                if Some(id) == incoming_id && done > 0 && done < total {
                    progress_for_incoming = true;
                }
            }
            Ok(Evt::FileReceived { id, .. }) => received_id = Some(id),
            Ok(_) | Err(_) => {}
        }
    }
    assert!(incoming_id.is_some(), "FileIncoming arrived (the receiving bubble with a bar)");
    assert_eq!(received_id, incoming_id, "FileReceived finalized THE SAME bubble by id");
    assert!(progress_for_incoming, "download progress 0<done<total streamed in between");
    let _ = (alice_tx, bob_tx);
}

/// Восстановление на GUI-уровне: ДВА свежих профиля, спровиженные ОДНОЙ фразой,
/// дают ОДИН и тот же own_ik (адрес). Пиннит контракт восстановления через путь
/// worker → Store::save_seed → seed::derive: та же фраза = та же личность на любом
/// устройстве. Дискриминирующий: сделай derive недетерминированным → IK разойдутся.
#[test]
fn same_phrase_provisions_same_identity_on_fresh_profiles() {
    let (relay_addr, relay_id) = spawn_relay();
    let phrase = "abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon about"
        .to_string();
    let prov = || Cmd::Provision {
        passphrase: "pw".into(),
        phrase: phrase.clone(),
        relay_addr: relay_addr.clone(),
        relay_id: relay_id.clone(),
        socks5: String::new(),
        routes: String::new(),
        extra_relays: String::new(),
    };

    let (a_tx, a_rx) = spawn_worker("recover-a", Duration::from_secs(60));
    a_tx.send(prov()).unwrap();
    let ik_a = wait_unlocked(&a_rx);

    let (b_tx, b_rx) = spawn_worker("recover-b", Duration::from_secs(60));
    b_tx.send(prov()).unwrap();
    let ik_b = wait_unlocked(&b_rx);

    assert_eq!(ik_a, ik_b, "одна фраза → один IK на разных профилях (восстановление)");
    let _ = (a_tx, b_tx);
}

/// Мультиаккаунт: создать первый (Provision, задаёт пароль устройства), ДОБАВИТЬ
/// второй (AddAccount, без пароля → переключается на него), переключиться обратно,
/// пережить рестарт. Покрывает vault-проводку add/switch и стабильность реестра.
#[test]
fn add_and_switch_between_two_accounts() {
    let (relay_addr, relay_id) = spawn_relay();
    let dir = temp_dir("multiacct");
    let (tx, rx) = spawn_worker_in(dir.clone(), Duration::from_secs(60));

    // Первый аккаунт (Provision).
    tx.send(Cmd::Provision {
        passphrase: "pw".into(),
        phrase: client::seed::generate_mnemonic().to_string(),
        relay_addr: relay_addr.clone(),
        relay_id: relay_id.clone(),
        socks5: String::new(),
        routes: String::new(),
        extra_relays: String::new(),
    })
    .unwrap();
    let ik_a = wait_unlocked(&rx);
    let (a1, active1) = wait_accounts(&rx);
    assert_eq!(a1.len(), 1, "один аккаунт");
    assert_eq!(active1, a1[0].id);

    // Добавить второй (AddAccount, без пароля) → переключение на него.
    tx.send(Cmd::AddAccount {
        phrase: client::seed::generate_mnemonic().to_string(),
        label: "Второй".into(),
    })
    .unwrap();
    let ik_b = wait_unlocked(&rx);
    assert_ne!(ik_a, ik_b, "разные личности");
    let (a2, active2) = wait_accounts(&rx);
    assert_eq!(a2.len(), 2, "оба аккаунта в реестре");
    assert_eq!(a2.iter().find(|a| a.id == active2).unwrap().label, "Второй", "метка задана");
    assert_eq!(a2.iter().find(|a| a.id == active2).unwrap().ik, ik_b, "активен второй");

    // Переключиться обратно на первый.
    let id_a = a2.iter().find(|a| a.ik == ik_a).unwrap().id.clone();
    tx.send(Cmd::SwitchAccount { id: id_a }).unwrap();
    let ik_back = wait_unlocked(&rx);
    assert_eq!(ik_back, ik_a, "вернулись на первый аккаунт");

    // Рестарт → оба аккаунта переживают.
    drop(tx);
    drop(rx);
    let (tx2, rx2) = spawn_worker_in(dir, Duration::from_secs(60));
    tx2.send(unlock_cmd(&relay_addr, &relay_id, "pw")).unwrap();
    let _ = wait_unlocked(&rx2);
    let (a3, _) = wait_accounts(&rx2);
    assert_eq!(a3.len(), 2, "оба аккаунта пережили рестарт");
    let _ = tx2;
}

/// `SaveContacts { id }` пишет в аккаунт `id`, а НЕ в live-сессию worker'а. Ловит
/// кросс-аккаунтную порчу: в одном кадре GUI входящее ставит contacts_dirty, затем
/// клик переключает на A, а flush шлёт SaveContacts со СТАРЫМ активным id (B). По
/// FIFO SwitchAccount{A} применяется первым, и без ключа-id контакты B легли бы в A.
/// Здесь эмулируем именно этот порядок: Switch→A, затем Save c id=B, пока сессия=A.
/// Дискриминирующий: верни хендлер к `s.store.save_contacts` (live-сессия) →
/// маркер уедет в A вместо B → падают обе проверки.
#[test]
fn save_contacts_targets_account_by_id_not_live_session() {
    let (relay_addr, relay_id) = spawn_relay();
    let dir = temp_dir("save-by-id");
    let (tx, rx) = spawn_worker_in(dir.clone(), Duration::from_secs(60));

    // A (Provision) + B (AddAccount → активен B).
    tx.send(Cmd::Provision {
        passphrase: "pw".into(),
        phrase: client::seed::generate_mnemonic().to_string(),
        relay_addr: relay_addr.clone(),
        relay_id: relay_id.clone(),
        socks5: String::new(),
        routes: String::new(),
        extra_relays: String::new(),
    })
    .unwrap();
    let ik_a = wait_unlocked(&rx);
    let _ = wait_accounts(&rx); // поглощаем Accounts от Provision (иначе спутаем ниже)

    tx.send(Cmd::AddAccount {
        phrase: client::seed::generate_mnemonic().to_string(),
        label: "Б".into(),
    })
    .unwrap();
    let _ = wait_unlocked(&rx);
    let (accts, id_b) = wait_accounts(&rx); // активен B
    let id_a = accts.iter().find(|a| a.ik == ik_a).unwrap().id.clone();

    // Интерливинг: переключиться на A, затем сохранить в B, пока live-сессия = A.
    tx.send(Cmd::SwitchAccount { id: id_a.clone() }).unwrap();
    let _ = wait_unlocked(&rx); // сессия worker'а теперь A
    let marker = [0x99u8; 32];
    tx.send(Cmd::SaveContacts {
        id: id_b.clone(),
        contacts: vec![Contact { name: "BOnly".into(), ik: marker, verified: true }],
    })
    .unwrap();
    // Синхронизация: Send после Save → его SendResult доказывает, что файл записан.
    tx.send(Cmd::Send { id: 555, to_ik: [0x01; 32], text: "sync".into(), ts: 0 }).unwrap();
    wait_send_result(&rx, 555);

    // Рестарт: активен первый (A) — маркера в нём быть НЕ должно.
    drop(tx);
    drop(rx);
    let (tx2, rx2) = spawn_worker_in(dir, Duration::from_secs(60));
    tx2.send(unlock_cmd(&relay_addr, &relay_id, "pw")).unwrap();
    let _ = wait_unlocked(&rx2);
    let (_, active) = wait_accounts(&rx2);
    assert_eq!(active, id_a, "на рестарте активен первый аккаунт A");
    let a_contacts = wait_contacts(&rx2);
    assert!(!a_contacts.iter().any(|c| c.ik == marker), "маркер НЕ должен попасть в A");

    // Переключиться на B → маркер обязан быть там.
    tx2.send(Cmd::SwitchAccount { id: id_b.clone() }).unwrap();
    let _ = wait_unlocked(&rx2);
    let _ = wait_accounts(&rx2);
    let b_contacts = wait_contacts(&rx2);
    assert!(b_contacts.iter().any(|c| c.ik == marker), "маркер сохранён в B");
    let _ = tx2;
}

/// Контакты (имя + флаг сверки) ПЕРЕЖИВАЮТ рестарт worker'а через `contacts.dat`:
/// сохраняем `Cmd::SaveContacts` в worker A → рестарт на том же каталоге → при
/// unlock приходит `Evt::Contacts` с тем же контактом и `verified`. Покрывает
/// проводку worker↔store (SaveContacts→save_contacts, unlock→load_contacts→
/// Contacts), которую раньше держал только ручной скриншот. Дискриминирующий:
/// убери `save_contacts` в SaveContacts-хендлере → список пуст → красный.
#[test]
fn contacts_survive_worker_restart() {
    let (relay_addr, relay_id) = spawn_relay();
    let dir = temp_dir("contacts-persist");

    let (tx, rx) = spawn_worker_in(dir.clone(), Duration::from_secs(60));
    tx.send(provision_cmd(&relay_addr, &relay_id, "pw", "")).unwrap();
    let _ = wait_unlocked(&rx);
    let (_, active) = wait_accounts(&rx);

    let ik = [0x42u8; 32];
    tx.send(Cmd::SaveContacts {
        id: active,
        contacts: vec![Contact { name: "Alice".into(), ik, verified: true }],
    })
    .unwrap();
    // Синхронизация: Send ПОСЛЕ SaveContacts → его SendResult доказывает, что
    // очередь (FIFO) дошла до сохранения контактов, т.е. файл уже записан.
    tx.send(Cmd::Send { id: 777, to_ik: [0x01; 32], text: "sync".into(), ts: 0 }).unwrap();
    wait_send_result(&rx, 777);

    // Рестарт на том же каталоге.
    drop(tx);
    drop(rx);
    let (tx2, rx2) = spawn_worker_in(dir, Duration::from_secs(60));
    tx2.send(unlock_cmd(&relay_addr, &relay_id, "pw")).unwrap();
    let _ = wait_unlocked(&rx2);

    let contacts = wait_contacts(&rx2);
    let found = contacts.iter().find(|c| c.ik == ik).expect("контакт пережил рестарт");
    assert_eq!(found.name, "Alice", "имя сохранено");
    assert!(found.verified, "флаг сверки сохранён");
    let _ = tx2;
}

/// Provision с БИТЫМ relay-id (непустой, но не hex) НЕ должен оставить корень на
/// диске — иначе повтор упрётся в «аккаунт уже есть» и заклинит экран создания
/// (та самая «дальше не пройти»). Дискриминирующий: перенеси `save_seed` до
/// валидации сети → seed.key появится → красный.
#[test]
fn provision_with_bad_relay_id_does_not_persist_seed() {
    let dir = temp_dir("badrelay");
    let (tx, rx) = spawn_worker_in(dir.clone(), Duration::from_secs(60));
    tx.send(Cmd::Provision {
        passphrase: "pw".into(),
        phrase: client::seed::generate_mnemonic().to_string(),
        relay_addr: "127.0.0.1:9999".into(),
        relay_id: "not-hex-relay-id".into(), // непустой → пройдёт гейт контроллера
        socks5: String::new(),
        routes: String::new(),
        extra_relays: String::new(),
    })
    .unwrap();
    // Ждём Status с ошибкой (не Unlocked).
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut got_err = false;
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(Evt::Unlocked { .. }) => panic!("не должно разблокироваться на битом relay-id"),
            Ok(Evt::Status(_)) => got_err = true,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    assert!(got_err, "ожидался Status с ошибкой");
    assert!(!dir.join("seed.key").exists(), "корень НЕ должен быть записан при провале валидации");
    let _ = tx;
}

// 150 KiB sits in the old dead zone: too big for the inline path's quota
// (dev-cap max_requests=100, one request per 1 KiB chunk) yet under the old
// 240 KiB inline threshold. It must route to the blob path and arrive. Revert
// MAX_FILE_CHUNKS to 240 and this goes red (inline → CapabilityQuota).
#[test]
fn worker_medium_file_routes_to_blob_not_quota() {
    let (relay_addr, relay_id) = spawn_relay();
    let alice_dir = temp_dir("wprobe-alice");
    let bob_dir = temp_dir("wprobe-bob");
    let (alice_tx, alice_rx) = spawn_worker_in(alice_dir.clone(), Duration::from_secs(60));
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir.clone(), Duration::from_secs(60));
    let unlock = |addr: &str, rid: &str, pass: &str| provision_cmd(addr, rid, pass, "");
    bob_tx.send(unlock(&relay_addr, &relay_id, "bobpw")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);
    alice_tx.send(unlock(&relay_addr, &relay_id, "alicepw")).unwrap();
    let _ = wait_unlocked(&alice_rx);
    alice_tx.send(Cmd::Send { id: 1, to_ik: bob_ik, text: "hi".into(), ts: 0 }).unwrap();
    let payload: Vec<u8> = (0..150_000usize).map(|i| (i.wrapping_mul(31)) as u8).collect();
    let src = alice_dir.join("mid.bin");
    std::fs::write(&src, &payload).unwrap();
    alice_tx.send(Cmd::SendFile { id: 2, to_ik: bob_ik, path: src.to_string_lossy().into_owned(), ts: 0 }).unwrap();
    let (name, file_id) = poll_until_file(&bob_tx, &bob_rx);
    assert_eq!(name, "mid.bin");
    assert_eq!(export_bytes(&bob_dir, b"bobpw", &file_id), payload, "150 KiB file must arrive");
    let _ = (alice_tx, bob_tx);
}

/// The worker polls a MULTI-HOMED relay set, not just its primary. Bob is configured with a
/// secondary relay (via the `extra_relays` sidecar); a message deposited on that SECONDARY
/// is delivered by `poll()`. Alice can't first-contact Bob on the secondary (he only
/// publishes his bundle to the primary — that's the next slice), so the message rides the
/// drop-box follow-up path: opener on the primary, next ratchet message on the secondary.
///
/// Discriminating: revert `poll()` to `recv_session(&s.store, s.primary(), …)` and the
/// secondary message is never fetched — the assert reds.
#[test]
fn worker_receives_from_a_secondary_relay() {
    let (r1_addr, r1_id) = spawn_relay(); // Bob's primary
    let (r2_addr, r2_id) = spawn_relay(); // Bob's secondary
    let now = || SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let bob_dir = temp_dir("secondary-bob");
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir.clone(), Duration::from_secs(60));
    bob_tx.send(provision_cmd(&r1_addr, &r1_id, "bobpw", "")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    let (_, bob_id) = wait_accounts(&bob_rx);
    wait_publish(&bob_rx);

    // Add the secondary to Bob's account, then re-enter (SwitchAccount reloads the relay set
    // from config) so his worker now holds [primary, secondary].
    client::store::Vault::unlock(&bob_dir, b"bobpw")
        .unwrap()
        .account(&bob_id)
        .save_extra_relays(&[(r2_addr.clone(), r2_id.clone())])
        .unwrap();
    bob_tx.send(Cmd::SwitchAccount { id: bob_id }).unwrap();
    let _ = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);

    // Alice as a bare client: opener via the primary (where Bob's bundle lives), then the
    // next ratchet message via the secondary's drop box.
    let alice_dir = temp_dir("secondary-alice");
    let astore = client::store::Store::unlock(&alice_dir, b"alicepw").unwrap();
    astore.save_seed(&client::seed::entropy_of(&client::seed::generate_mnemonic())).unwrap();
    astore.save_capability(&client::dev_capability()).unwrap();
    let r1 = client::Relay::configured(r1_addr.parse::<std::net::SocketAddr>().unwrap(), client::RelayId::parse(&r1_id).unwrap(), None, "");
    let r2 = client::Relay::configured(r2_addr.parse::<std::net::SocketAddr>().unwrap(), client::RelayId::parse(&r2_id).unwrap(), None, "");
    client::send_text(&astore, &r1, &bob_ik, b"opener-r1", now(), now()).unwrap();
    client::send_text(&astore, &r2, &bob_ik, b"follow-r2", now(), now()).unwrap();

    // Poll Bob until the SECONDARY-relay message shows up (or time out).
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline && !seen.iter().any(|t| t == b"follow-r2") {
        bob_tx.send(Cmd::Poll).unwrap();
        if let Ok(Evt::Received(msgs)) = bob_rx.recv_timeout(Duration::from_millis(300)) {
            seen.extend(msgs.into_iter().map(|m| m.plaintext));
        }
    }
    assert!(
        seen.iter().any(|t| t == b"follow-r2"),
        "the message on the SECONDARY relay was never received — poll() is not multi-homed"
    );
    let _ = bob_tx;
}

/// Per-relay reachability: a LIVE primary plus a well-formed-but-unreachable backup must
/// surface as `RelayHealth([true, false])` — the primary is up, the backup is down — instead
/// of collapsing to one aggregate light. This is the "primary unreachable, backup carrying me"
/// visibility that matters under path disruption, shown here as its inverse (primary up, backup
/// dead). Discriminating: if `poll` stopped emitting the per-relay view, or reported the
/// backup as up, the `[true, false]` assertion never arrives and the test times out.
#[test]
fn per_relay_health_flags_a_dead_backup_while_the_primary_stays_up() {
    let (r1_addr, r1_id) = spawn_relay(); // live primary
    let bob_dir = temp_dir("relayhealth-bob");
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir.clone(), Duration::from_secs(60));
    bob_tx.send(provision_cmd(&r1_addr, &r1_id, "bobpw", "")).unwrap();
    let _ = wait_unlocked(&bob_rx);
    let (_, bob_id) = wait_accounts(&bob_rx);
    wait_publish(&bob_rx);

    // A backup that is WELL-FORMED (parses, so it joins the set — a malformed one would be
    // skipped) but points at a dead address, so its fetch fails to connect and it lands in
    // `failed`. Re-enter so the worker reloads the set as [primary(live), backup(dead)].
    client::store::Vault::unlock(&bob_dir, b"bobpw")
        .unwrap()
        .account(&bob_id)
        .save_extra_relays(&[("127.0.0.1:1".into(), r1_id.clone())])
        .unwrap();
    bob_tx.send(Cmd::SwitchAccount { id: bob_id }).unwrap();
    let _ = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);

    // Poll until the per-relay health reports the primary up and the backup down.
    let mut got: Option<Vec<bool>> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline && got.as_deref() != Some(&[true, false]) {
        bob_tx.send(Cmd::Poll).unwrap();
        while let Ok(evt) = bob_rx.recv_timeout(Duration::from_millis(300)) {
            if let Evt::RelayHealth(h) = evt {
                got = Some(h);
                break;
            }
        }
    }
    assert_eq!(
        got.as_deref(),
        Some(&[true, false][..]),
        "expected the primary reachable and the dead backup unreachable"
    );
    let _ = bob_tx;
}

/// A corrupt SECONDARY relay entry must not lock the account out — the same Principle-2
/// resilience the receive path has, applied to config: a bad backup relay is skipped, the
/// account still opens single-homed on its primary. Discriminating: make the extras loop in
/// `relays_for_account` fail closed (`?` on `parse_net`) and the unlock never completes.
#[test]
fn a_malformed_secondary_relay_does_not_lock_the_account_out() {
    let (r1_addr, r1_id) = spawn_relay();
    let bob_dir = temp_dir("badsec-bob");

    // Provision the account (primary config), then corrupt its secondary list on disk.
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir.clone(), Duration::from_secs(60));
    bob_tx.send(provision_cmd(&r1_addr, &r1_id, "bobpw", "")).unwrap();
    let _ = wait_unlocked(&bob_rx);
    let (_, bob_id) = wait_accounts(&bob_rx);
    wait_publish(&bob_rx);
    client::store::Vault::unlock(&bob_dir, b"bobpw")
        .unwrap()
        .account(&bob_id)
        .save_extra_relays(&[("not-an-address".into(), "zz".into())])
        .unwrap();
    drop(bob_tx);
    drop(bob_rx);

    // Restart and unlock the existing account: a garbage backup relay must not sink it.
    let (bob2_tx, bob2_rx) = spawn_worker_in(bob_dir, Duration::from_secs(60));
    bob2_tx.send(unlock_cmd(&r1_addr, &r1_id, "bobpw")).unwrap();
    let _ = wait_unlocked(&bob2_rx); // panics on timeout if the unlock failed closed
    wait_publish(&bob2_rx); // and it works single-homed on the primary
    let _ = bob2_tx;
}

/// Publish-to-all in the worker: a fresh contact can FIRST-CONTACT Bob through a SECONDARY
/// relay, because his bundle is now published there too (not just on the primary). Alice
/// only knows the secondary; she fetches Bob's bundle from it, opens a session, deposits the
/// opener, and Bob's multi-homed poll delivers it.
///
/// Discriminating: revert the worker's `publish()` to the primary only and Alice's first
/// contact fails — the secondary has no bundle to fetch (`send_text` errs at `connect`).
#[test]
fn worker_can_be_first_contacted_via_a_secondary_relay() {
    let (r1_addr, r1_id) = spawn_relay(); // primary
    let (r2_addr, r2_id) = spawn_relay(); // secondary
    let now = || SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let bob_dir = temp_dir("firstcontact-bob");
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir.clone(), Duration::from_secs(60));
    bob_tx.send(provision_cmd(&r1_addr, &r1_id, "bobpw", "")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    let (_, bob_id) = wait_accounts(&bob_rx);
    wait_publish(&bob_rx);

    // Add the secondary, then re-enter so publish-to-all announces Bob's bundle on it too.
    client::store::Vault::unlock(&bob_dir, b"bobpw")
        .unwrap()
        .account(&bob_id)
        .save_extra_relays(&[(r2_addr.clone(), r2_id.clone())])
        .unwrap();
    bob_tx.send(Cmd::SwitchAccount { id: bob_id }).unwrap();
    let _ = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);

    // Alice, a stranger who ONLY knows the secondary relay, first-contacts Bob there.
    let alice_dir = temp_dir("firstcontact-alice");
    let astore = client::store::Store::unlock(&alice_dir, b"alicepw").unwrap();
    astore.save_seed(&client::seed::entropy_of(&client::seed::generate_mnemonic())).unwrap();
    astore.save_capability(&client::dev_capability()).unwrap();
    let r2 = client::Relay::configured(r2_addr.parse::<std::net::SocketAddr>().unwrap(), client::RelayId::parse(&r2_id).unwrap(), None, "");
    client::send_text(&astore, &r2, &bob_ik, b"first-via-r2", now(), now())
        .expect("first contact via the secondary relay (its bundle must be published)");

    let mut seen: Vec<Vec<u8>> = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline && !seen.iter().any(|t| t == b"first-via-r2") {
        bob_tx.send(Cmd::Poll).unwrap();
        if let Ok(Evt::Received(msgs)) = bob_rx.recv_timeout(Duration::from_millis(300)) {
            seen.extend(msgs.into_iter().map(|m| m.plaintext));
        }
    }
    assert!(
        seen.iter().any(|t| t == b"first-via-r2"),
        "a fresh contact could not reach Bob through his secondary relay"
    );
    let _ = bob_tx;
}

/// The GUI path end to end: a secondary relay typed into the provision command (what the
/// login form's backup-relays field sends) actually multi-homes the account — Bob publishes
/// to it, and a fresh contact reaches him there. Discriminating: pass an empty `extra_relays`
/// and the secondary is never configured, so the first contact via it fails.
#[test]
fn provision_command_configures_a_secondary_relay() {
    let (r1_addr, r1_id) = spawn_relay();
    let (r2_addr, r2_id) = spawn_relay();
    let now = || SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let bob_dir = temp_dir("provsec-bob");
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir, Duration::from_secs(60));
    bob_tx
        .send(Cmd::Provision {
            passphrase: "bobpw".into(),
            phrase: client::seed::generate_mnemonic().to_string(),
            relay_addr: r1_addr.clone(),
            relay_id: r1_id.clone(),
            socks5: String::new(),
            routes: String::new(),
            extra_relays: format!("{r2_addr} {r2_id}"), // the backup-relays field
        })
        .unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);

    // Fresh Alice who only knows the secondary first-contacts Bob there.
    let alice_dir = temp_dir("provsec-alice");
    let astore = client::store::Store::unlock(&alice_dir, b"alicepw").unwrap();
    astore.save_seed(&client::seed::entropy_of(&client::seed::generate_mnemonic())).unwrap();
    astore.save_capability(&client::dev_capability()).unwrap();
    let r2 = client::Relay::configured(r2_addr.parse::<std::net::SocketAddr>().unwrap(), client::RelayId::parse(&r2_id).unwrap(), None, "");
    client::send_text(&astore, &r2, &bob_ik, b"hi via configured secondary", now(), now())
        .expect("the secondary from the provision command must be live");

    let mut seen: Vec<Vec<u8>> = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline
        && !seen.iter().any(|t| t == b"hi via configured secondary")
    {
        bob_tx.send(Cmd::Poll).unwrap();
        if let Ok(Evt::Received(msgs)) = bob_rx.recv_timeout(Duration::from_millis(300)) {
            seen.extend(msgs.into_iter().map(|m| m.plaintext));
        }
    }
    assert!(
        seen.iter().any(|t| t == b"hi via configured secondary"),
        "the secondary relay typed at provision was not configured"
    );
    let _ = bob_tx;
}

/// Display + add + remove of secondaries at RUNTIME via `SetExtraRelays`: adding one makes
/// the account multi-homed (a fresh contact reaches Bob on it) and the worker echoes the
/// list back for the UI; clearing it removes the relay. This is the display/remove path the
/// login field alone (add/replace, "empty = keep") cannot do.
#[test]
fn set_extra_relays_adds_then_clears_a_secondary_at_runtime() {
    let (r1_addr, r1_id) = spawn_relay();
    let (r2_addr, r2_id) = spawn_relay();
    let now = || SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let bob_dir = temp_dir("setextra-bob");
    let (bob_tx, bob_rx) = spawn_worker_in(bob_dir, Duration::from_secs(60));
    bob_tx.send(provision_cmd(&r1_addr, &r1_id, "bobpw", "")).unwrap();
    let bob_ik = wait_unlocked(&bob_rx);
    wait_publish(&bob_rx);

    // Add the secondary at runtime; the worker echoes the new list and re-publishes to it.
    bob_tx
        .send(Cmd::SetExtraRelays { relays: vec![(r2_addr.clone(), r2_id.clone())] })
        .unwrap();
    let listed = wait_extra_relays(&bob_rx);
    assert_eq!(listed, vec![(r2_addr.clone(), r2_id.clone())], "the added secondary is echoed for the UI");
    wait_publish(&bob_rx);

    // A fresh contact now reaches Bob on the runtime-added secondary.
    let alice_dir = temp_dir("setextra-alice");
    let astore = client::store::Store::unlock(&alice_dir, b"alicepw").unwrap();
    astore.save_seed(&client::seed::entropy_of(&client::seed::generate_mnemonic())).unwrap();
    astore.save_capability(&client::dev_capability()).unwrap();
    let r2 = client::Relay::configured(r2_addr.parse::<std::net::SocketAddr>().unwrap(), client::RelayId::parse(&r2_id).unwrap(), None, "");
    client::send_text(&astore, &r2, &bob_ik, b"runtime-secondary", now(), now())
        .expect("the runtime-added secondary must be live");
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline && !seen.iter().any(|t| t == b"runtime-secondary") {
        bob_tx.send(Cmd::Poll).unwrap();
        if let Ok(Evt::Received(msgs)) = bob_rx.recv_timeout(Duration::from_millis(300)) {
            seen.extend(msgs.into_iter().map(|m| m.plaintext));
        }
    }
    assert!(seen.iter().any(|t| t == b"runtime-secondary"), "adding a secondary did not multi-home the account");

    // Clear it — the login field's "empty = keep" can never do this; SetExtraRelays can.
    bob_tx.send(Cmd::SetExtraRelays { relays: Vec::new() }).unwrap();
    assert!(wait_extra_relays(&bob_rx).is_empty(), "the secondary was not removed");
    let _ = bob_tx;
}
