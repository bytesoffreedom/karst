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
