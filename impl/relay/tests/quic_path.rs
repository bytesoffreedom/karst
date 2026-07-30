//! End-to-end over the QUIC carrier (QUIC-3): a real client transport, a real relay listener, the
//! same wire protocol as TCP.
//!
//! The point is that NOTHING above the adapter changed. The request goes through the identical
//! Noise handshake, the identical admission pipeline and the identical framing — only the bytes
//! travel over UDP.

use std::sync::Arc;

use karst_transport::quic::QuicAdapter;
use karst_transport::socket::SocketTransport;
use karst_transport::transport::{Dest, Path};
use relay::node::RelayNode;
use relay::quic_server::QuicServer;

const NOW: u64 = 1_000_000;

/// The globally-known dev credential, rebuilt here so this test does not depend on the client
/// crate (the relay crate must not, and that is the point of the split).
fn dev_cap() -> admission::capability::Capability {
    admission::capability::Capability {
        capability_id: [0xCA; 16],
        scope: admission::capability::Scope::MessageDelivery,
        quota: admission::capability::Quota {
            max_requests: 10_000,
            max_bytes: 1 << 30,
            window_secs: 600,
        },
        not_before: 0,
        not_after: u32::MAX,
        secret: [0x33; 32],
    }
}

/// A QUIC-served relay on an ephemeral UDP port; returns its address and Noise public key.
fn spawn_quic_relay() -> (std::net::SocketAddr, [u8; 32]) {
    let (noise_priv, noise_pub) = relay::server::generate_noise_keypair();
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(dev_cap());
    let handle = Arc::new(std::sync::RwLock::new(relay));
    let server = QuicServer::bind(
        "127.0.0.1:0".parse().expect("valid"),
        handle,
        Arc::new(move || NOW),
        noise_priv,
    )
    .expect("bind quic");
    let addr = server.local_addr().expect("bound");
    std::thread::spawn(move || {
        let _ = server.serve();
    });
    (addr, noise_pub)
}

/// A request survives the whole stack over UDP: QUIC handshake, Noise handshake, framing, the
/// relay's dispatch, and an answer back.
///
/// `GetPolicy` is the probe on purpose — a public read, so a structured answer proves the request
/// reached the handler without a credential round trip needing to be arranged first. If any layer
/// had been skipped or reimplemented for this carrier, it fails here.
#[test]
fn a_request_completes_over_quic() {
    let (addr, noise_pub) = spawn_quic_relay();
    let quic = Arc::new(QuicAdapter::new().expect("client endpoint"));
    let transport = SocketTransport::with_paths(vec![Path::new(quic, Dest::from(addr))], noise_pub);

    let policy = transport.get_policy().expect("the relay answered over QUIC");
    // A dev relay issues nothing from a public door; what matters is that a STRUCTURED answer came
    // back rather than a transport error.
    assert!(policy.pow_bits.is_none(), "unexpected door policy: {:?}", policy.pow_bits);
}

/// A dead QUIC endpoint must not delay the request: the WSS/TCP path starts alongside after a
/// short head start and answers (QUIC-4).
///
/// Discriminating on TIME, but relatively — the assertion is that the request finishes well inside
/// a single `CONNECT_TIMEOUT`, which is what a sequential list would have cost before even trying
/// the second path. Networks drop UDP silently, so that timeout is the common case there, not the
/// exception.
#[test]
fn a_dead_quic_path_does_not_delay_the_tcp_one() {
    let (noise_priv, noise_pub) = relay::server::generate_noise_keypair();
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(dev_cap());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp");
    let tcp_addr = listener.local_addr().expect("bound");
    let server = relay::server::RelayServer::with_noise_keypair(
        relay,
        Arc::new(move || NOW),
        noise_priv,
        noise_pub,
    );
    std::thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });

    // A UDP port with nothing behind it — the silent-drop case, in miniature.
    let quic = Arc::new(QuicAdapter::new().expect("client endpoint"));
    let dead_quic = Path::new(quic, Dest::new("192.0.2.1", 9));
    let live_tcp = Path::new(
        Arc::new(karst_transport::transport::DirectTcpAdapter::default()),
        Dest::from(tcp_addr),
    );
    let transport = SocketTransport::with_paths(vec![dead_quic, live_tcp], noise_pub);

    let started = std::time::Instant::now();
    transport.get_policy().expect("the TCP path must answer");
    assert!(
        started.elapsed() < karst_transport::transport::CONNECT_TIMEOUT,
        "took {:?} — the dead QUIC path was waited out instead of raced past",
        started.elapsed()
    );
}

/// A fetch nobody can serve: no cookie, so the relay answers `NeedCookie` and the request counts
/// as UNADMITTED. Cheap on both sides and it exercises the leash, which is the point.
fn unservable_fetch() -> node::protocol::FetchRequest {
    node::protocol::FetchRequest {
        mailbox: [0x5A; 32],
        client_addr: vec![0x11; 32],
        carrier_id: b"quic-pool-test".to_vec(),
        cookie: None,
        proof: [0u8; 16],
        own_proof: Vec::new(),
    }
}

/// **The pool is real, and it is exactly as wide as the caller said** (QUIC-5).
///
/// DISCRIMINATING at the relay, not at a counter the client owns: `MAX_UNADMITTED_REQUESTS` is
/// shared by every stream of ONE connection (#239). So if requests carrying one scope really do
/// ride one connection, the ninth is refused by a leash the first eight spent — and if the pool
/// were not working, each request would arrive on its own connection with its own fresh count and
/// all nine would be answered. That is the whole slice observed from the outside.
///
/// This is also the first test that can see `MAX_UNADMITTED_STREAMS_PER_CONN` and the per-`ConnState`
/// counters do anything at all: before pooling, one connection never carried a second stream.
#[test]
fn requests_in_one_scope_share_a_connection_and_therefore_share_the_leash() {
    use node::protocol::Transport;

    let (addr, noise_pub) = spawn_quic_relay();
    let quic = Arc::new(QuicAdapter::new().expect("client endpoint"));
    let transport =
        SocketTransport::with_paths(vec![Path::new(quic.clone(), Dest::from(addr))], noise_pub);

    let leash = relay::server::MAX_UNADMITTED_REQUESTS;
    let answers: Vec<_> = (0..=leash)
        .map(|_| transport.fetch_isolated(&unservable_fetch(), NOW, Some("one-channel")))
        .collect();

    assert_eq!(quic.pooled(), 1, "one scope must hold exactly one connection");
    for (i, a) in answers.iter().take(leash).enumerate() {
        assert!(
            matches!(a, node::protocol::FetchResponse::NeedCookie(_)),
            "request {i} was within the leash and should have been answered"
        );
    }
    match answers.last().expect("one answer per request") {
        node::protocol::FetchResponse::Rejected(why) => assert!(
            why.starts_with("transport:"),
            "the leash should have cut the connection, not produced a protocol answer: {why}"
        ),
        _ => panic!("the {}th unadmitted request rode a fresh leash", leash + 1),
    }
}

/// **CONTROL ARM for the test above, and the rule that makes pooling safe.**
///
/// The same requests with NO scope must not pool: an unscoped caller has not said which compartment
/// it belongs to, and merging on "unknown" would put every unscoped request in the process — bundle
/// publishes, blob transfers, discovery lookups, across every channel — on one connection, which is
/// the A8-4 join rebuilt in the transport. So each gets its own connection, its own leash, and all
/// of them are answered.
///
/// If the rule were ever relaxed, this test fails at the same request the scoped one is refused at.
#[test]
fn unscoped_requests_are_never_pooled_together() {
    use node::protocol::Transport;

    let (addr, noise_pub) = spawn_quic_relay();
    let quic = Arc::new(QuicAdapter::new().expect("client endpoint"));
    let transport =
        SocketTransport::with_paths(vec![Path::new(quic.clone(), Dest::from(addr))], noise_pub);

    for i in 0..=relay::server::MAX_UNADMITTED_REQUESTS {
        let a = transport.fetch_isolated(&unservable_fetch(), NOW, None);
        assert!(
            matches!(a, node::protocol::FetchResponse::NeedCookie(_)),
            "unscoped request {i} shared a leash it should never have shared"
        );
    }
    assert_eq!(quic.pooled(), 0, "an unscoped request must leave nothing in the pool");
}

/// Two scopes are two connections — the separation the pool key exists to preserve.
///
/// Weaker than it looks on its own (a relay can still join them by source address on the direct
/// path, which is why QUIC is direct-only), and that is the honest claim: this stops the pool from
/// turning a same-IP INFERENCE into a same-connection CERTAINTY that also survives the address
/// changing.
#[test]
fn two_scopes_never_share_a_connection() {
    use node::protocol::Transport;

    let (addr, noise_pub) = spawn_quic_relay();
    let quic = Arc::new(QuicAdapter::new().expect("client endpoint"));
    let transport =
        SocketTransport::with_paths(vec![Path::new(quic.clone(), Dest::from(addr))], noise_pub);

    for scope in ["channel-a", "channel-b", "channel-c"] {
        // Twice each: the second must REUSE, so the count follows scopes and not requests.
        transport.fetch_isolated(&unservable_fetch(), NOW, Some(scope));
        transport.fetch_isolated(&unservable_fetch(), NOW, Some(scope));
    }
    assert_eq!(quic.pooled(), 3, "three scopes, three connections, six requests");
}

/// **Both listeners serve ONE relay** — what QUIC accepts lands in the state TCP serves.
///
/// The risk this pins is not subtle but it is silent: a relay that ran two listeners over two
/// `RelayNode`s would have two mailbox sets, and mail deposited on one carrier would simply not be
/// there on the other. From outside that does not look like a wiring mistake — it looks like the
/// relay losing messages, which is the hardest kind of bug to attribute.
///
/// DISCRIMINATING: hand `QuicServer::bind` a fresh `RelayNode` instead of `server.shared_node()`
/// and the shared state stays empty.
#[test]
fn a_deposit_over_quic_lands_in_the_state_the_tcp_listener_serves() {
    use node::protocol::Transport;

    let (noise_priv, noise_pub) = relay::server::generate_noise_keypair();
    let mut node = RelayNode::new(NOW);
    node.issue_capability(dev_cap());

    let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp");
    let server = relay::server::RelayServer::with_noise_keypair(
        node,
        Arc::new(move || NOW),
        noise_priv,
        noise_pub,
    );
    // The handle the binary hands to its QUIC listener (QUIC-10) — and the one this test reads
    // afterwards, which is what makes "shared" the thing being checked.
    let shared = server.shared_node();

    let quic = QuicServer::bind(
        "127.0.0.1:0".parse().expect("valid"),
        server.shared_node(),
        Arc::new(move || NOW),
        noise_priv,
    )
    .expect("bind quic");
    let quic_addr = quic.local_addr().expect("bound");
    std::thread::spawn(move || {
        let _ = quic.serve();
    });
    std::thread::spawn(move || {
        let _ = server.serve_listener(tcp);
    });

    assert_eq!(
        shared.read().expect("relay lock").mail_store().lock().expect("mail lock").all_payloads().len(),
        0,
        "the relay should start with nothing stored"
    );

    let over_quic = SocketTransport::with_paths(
        vec![Path::new(Arc::new(QuicAdapter::new().expect("endpoint")), Dest::from(quic_addr))],
        noise_pub,
    );
    let nonce = [0x31u8; 32];
    // The relay never decrypts a payload — it stores bytes — so an envelope shaped like one is
    // all this needs. What is under test is the plumbing, not the crypto.
    let mut msg = node::protocol::WireMessage {
        client_addr: vec![0x22; 32],
        carrier_id: b"quic-share-test".to_vec(),
        cookie: None,
        request_nonce: nonce.to_vec(),
        capability_proof: dev_cap().prove(&nonce, 0),
        recipient: [0x77u8; 32],
        payload: node::protocol::Payload::Skeleton(node::seal::SkeletonSeal { kem_ct: Vec::new(), ephemeral_pub: [0x55; 32],
            nonce: [0x66; 12],
            ciphertext: b"carried by udp, read out of the shared state".to_vec(),
        }),
    };
    // First send earns the cookie; the relay answers `NeedCookie` and the second carries it.
    let mut accepted = false;
    for _ in 0..2 {
        match over_quic.send(&msg, NOW) {
            node::protocol::Response::NeedCookie(c) => msg.cookie = Some(c),
            node::protocol::Response::Accepted => {
                accepted = true;
                break;
            }
            other => panic!("the QUIC listener refused the deposit: {other:?}"),
        }
    }
    assert!(accepted, "the QUIC listener never accepted the deposit");

    assert_eq!(
        shared.read().expect("relay lock").mail_store().lock().expect("mail lock").all_payloads().len(),
        1,
        "the deposit arrived over QUIC but is not in the state the TCP listener serves — the two \
         listeners are looking at different relays"
    );
}
