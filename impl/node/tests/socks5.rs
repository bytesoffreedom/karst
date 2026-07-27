//! Подключаемый транспорт (§15): сессия транспорт-агностична (`dyn Channel`) и
//! KARST говорит корректный SOCKS5. Заглушка ПРОВЕРЯЕТ CONNECT-handshake и
//! форвардит к реальному relay — полный Noise-роунд-трип проходит сквозь неё.
//! Не заявляем «обфусцировано» (обфускация — у внешнего транспорта); проверяем шов.
//! Плюс: мёртвый прокси → ЖЁСТКАЯ ошибка, НИКОГДА не прямое соединение.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use admission::capability::{Capability, Quota, Scope};
use node::node::{Client, Recipient, Response};
use node::seal::Identity;
use node::socket::SocketTransport;
use node::transport::Socks5Adapter;
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

fn spawn_relay() -> (SocketAddr, [u8; 32], [u8; 32]) {
    spawn_relay_on("127.0.0.1:0")
}

fn spawn_relay_on(bind: &str) -> (SocketAddr, [u8; 32], [u8; 32]) {
    let listener = TcpListener::bind(bind).unwrap();
    let addr = listener.local_addr().unwrap();
    let mut relay = node::node::RelayNode::new(NOW);
    relay.issue_capability(capability([0x33; 32]));
    let fetch_pub = relay.relay_public().to_bytes();
    let server = node::socket::RelayServer::new(relay, Arc::new(move || NOW));
    let noise_pub = server.noise_public();
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });
    (addr, noise_pub, fetch_pub)
}

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

/// SOCKS5-заглушка (CONNECT, no-auth, IPv4). Валидирует протокол клиента,
/// подключается к запрошенному dest, форвардит. `validated` = handshake прошёл.
fn spawn_socks5_stub() -> (SocketAddr, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let validated = Arc::new(AtomicBool::new(false));
    let v = validated.clone();
    thread::spawn(move || {
        for c in listener.incoming() {
            let Ok(mut client) = c else { continue };
            // Greeting: VER=5, NMETHODS, then the method list. The client may offer
            // user/pass (stream isolation) alongside no-auth, so parse rather than
            // expect a fixed shape; this proxy picks no-auth.
            let mut head = [0u8; 2];
            if client.read_exact(&mut head).is_err() || head[0] != 0x05 {
                continue;
            }
            let mut methods = vec![0u8; head[1] as usize];
            if client.read_exact(&mut methods).is_err() || !methods.contains(&0x00) {
                continue;
            }
            client.write_all(&[0x05, 0x00]).unwrap();
            // CONNECT: VER=5 CMD=1 RSV=0 ATYP (1=IPv4, 4=IPv6)
            let mut h = [0u8; 4];
            if client.read_exact(&mut h).is_err() || h[0] != 0x05 || h[1] != 0x01 {
                continue;
            }
            let dest = match h[3] {
                0x01 => {
                    let mut ap = [0u8; 6]; // 4 addr + 2 port
                    if client.read_exact(&mut ap).is_err() {
                        continue;
                    }
                    SocketAddr::from(([ap[0], ap[1], ap[2], ap[3]], u16::from_be_bytes([ap[4], ap[5]])))
                }
                0x04 => {
                    let mut ap = [0u8; 18]; // 16 addr + 2 port
                    if client.read_exact(&mut ap).is_err() {
                        continue;
                    }
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&ap[..16]);
                    let port = u16::from_be_bytes([ap[16], ap[17]]);
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a)), port)
                }
                _ => continue,
            };
            let Ok(up) = TcpStream::connect(dest) else { continue };
            client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).unwrap();
            v.store(true, Ordering::SeqCst);
            let (c2, u2) = (client.try_clone().unwrap(), up.try_clone().unwrap());
            thread::spawn(move || splice(client, up));
            thread::spawn(move || splice(u2, c2));
        }
    });
    (addr, validated)
}

#[test]
fn routes_through_socks5_proxy() {
    let (relay_addr, npub, fpub) = spawn_relay();
    let (proxy_addr, validated) = spawn_socks5_stub();
    let adapter = Arc::new(Socks5Adapter::new(proxy_addr));

    let mut alice = Client::new(
        SocketTransport::with_adapter(relay_addr, npub, adapter.clone()),
        capability([0x33; 32]),
        b"alice",
    );
    let mut bob = Recipient::new(
        SocketTransport::with_adapter(relay_addr, npub, adapter),
        Identity::generate(),
        PublicKey::from(fpub),
    );
    let bob_pub = bob.public();

    assert!(matches!(alice.send(&bob_pub, b"via socks5", NOW), Response::Accepted));
    assert!(validated.load(Ordering::SeqCst), "прокси должен был провести SOCKS5-handshake");

    let msgs = bob.receive(NOW).expect("fetch через socks5");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].as_deref(), Some(b"via socks5".as_ref()));
}

#[test]
fn routes_through_socks5_proxy_ipv6() {
    // IPv6-relay → адаптер шлёт CONNECT с ATYP=4 (16-байтовый адрес). Тот же путь,
    // но другая ветка кодирования/разбора — закрываем «достижимо, ноль покрытия».
    let (relay_addr, npub, fpub) = spawn_relay_on("[::1]:0");
    assert!(relay_addr.is_ipv6());
    let (proxy_addr, validated) = spawn_socks5_stub();
    let adapter = Arc::new(Socks5Adapter::new(proxy_addr));

    let mut alice = Client::new(
        SocketTransport::with_adapter(relay_addr, npub, adapter.clone()),
        capability([0x33; 32]),
        b"alice",
    );
    let mut bob = Recipient::new(
        SocketTransport::with_adapter(relay_addr, npub, adapter),
        Identity::generate(),
        PublicKey::from(fpub),
    );
    let bob_pub = bob.public();

    assert!(matches!(alice.send(&bob_pub, b"via socks5 v6", NOW), Response::Accepted));
    assert!(validated.load(Ordering::SeqCst), "IPv6 SOCKS5-handshake должен пройти");
    let msgs = bob.receive(NOW).expect("fetch через socks5 v6");
    assert_eq!(msgs[0].as_deref(), Some(b"via socks5 v6".as_ref()));
}

#[test]
fn socks5_dead_proxy_hard_fails_no_direct() {
    let (relay_addr, npub, _fpub) = spawn_relay();
    // Свободный, но не слушаемый порт → connect refused.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        a
    };
    let adapter = Arc::new(Socks5Adapter::new(dead));
    let mut alice = Client::new(
        SocketTransport::with_adapter(relay_addr, npub, adapter),
        capability([0x33; 32]),
        b"alice",
    );
    let bob = Identity::generate();

    let resp = alice.send(&bob.public, b"should not send", NOW);
    // Прямой fallback вернул бы Accepted (relay доступен). Rejected доказывает,
    // что тихого прямого соединения НЕ произошло.
    assert!(
        matches!(resp, Response::Rejected(_)),
        "мёртвый прокси → жёсткая ошибка, не прямое соединение; получено: {:?}",
        resp
    );
}
