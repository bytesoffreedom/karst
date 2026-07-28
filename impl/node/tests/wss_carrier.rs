//! WebSocket-over-TLS carrier (§15): the Noise session rides inside a real `wss://`
//! connection, so the FIRST bytes on the wire are a TLS ClientHello — what an
//! ordinary HTTPS client sends — not the bare Noise handshake an on-path classifier can
//! fingerprint. Two proofs here:
//!   1. functional: a full Noise handshake + request/response round-trips through the
//!      TLS+WebSocket carrier on both ends;
//!   2. discriminating: the first client->server bytes over the wss carrier are a
//!      TLS record (0x16 = handshake, 0x03 = TLS major version), whereas over the
//!      direct TCP adapter they are the Noise handshake frame (a tiny length prefix),
//!      NOT a TLS hello.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use node::session::{Session, NOISE_PARAMS};
use node::transport::{DirectTcpAdapter, TransportAdapter};
use node::wss::{accept_wss, client_config_with_roots, WssAdapter};
use rustls::pki_types::PrivateKeyDer;
use rustls::{RootCertStore, ServerConfig};
use snow::Builder;

/// Records the first bytes READ from the wrapped stream (the client's opening bytes
/// as the server sees them), then behaves transparently.
struct Sniff {
    inner: TcpStream,
    seen: Arc<Mutex<Vec<u8>>>,
    cap: usize,
}

impl Read for Sniff {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        let mut seen = self.seen.lock().unwrap();
        if seen.len() < self.cap {
            let take = (self.cap - seen.len()).min(n);
            seen.extend_from_slice(&buf[..take]);
        }
        Ok(n)
    }
}

impl Write for Sniff {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A self-signed cert for "localhost" plus a client config that trusts exactly it
/// and a server config that presents it.
fn test_tls() -> (Arc<rustls::ClientConfig>, Arc<ServerConfig>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());

    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).unwrap();
    let client = client_config_with_roots(roots);

    let server = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .unwrap();

    (client, Arc::new(server))
}

/// A fresh Noise keypair for the relay end.
fn relay_keys() -> ([u8; 32], [u8; 32]) {
    let kp = Builder::new(NOISE_PARAMS.parse().unwrap()).generate_keypair().unwrap();
    let priv_: [u8; 32] = kp.private.as_slice().try_into().unwrap();
    let pub_: [u8; 32] = kp.public.as_slice().try_into().unwrap();
    (priv_, pub_)
}

#[test]
fn wss_carrier_round_trips_and_first_bytes_are_a_tls_hello() {
    let (client_tls, server_tls) = test_tls();
    let (relay_priv, relay_pub) = relay_keys();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_srv = seen.clone();

    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        // Capture enough of the opening flight to include the ClientHello's ALPN.
        let sniff = Sniff { inner: tcp, seen: seen_srv, cap: 2048 };
        // Relay side: terminate TLS + WebSocket, then run the Noise session over it.
        let channel = accept_wss(sniff, server_tls).unwrap();
        let mut sess = Session::accept(channel, &relay_priv).unwrap();
        let got = sess.read_msg(1 << 20).unwrap();
        assert_eq!(got, b"ping over https");
        sess.write_msg(b"pong over https", 1 << 20).unwrap();
    });

    // Client side: dial the relay through the wss carrier (SNI "localhost", trusting
    // the test root), then speak Noise inside it.
    let adapter = WssAdapter::with_config("localhost", client_tls);
    let channel = adapter.connect(&node::transport::Dest::from(addr)).unwrap();
    let mut sess = Session::connect(channel, &relay_pub).unwrap();
    sess.write_msg(b"ping over https", 1 << 20).unwrap();
    let reply = sess.read_msg(1 << 20).unwrap();
    assert_eq!(reply, b"pong over https");

    server.join().unwrap();

    // Discriminating: the very first bytes the relay saw are a TLS record —
    // 0x16 (handshake) then 0x03 (TLS major version) — i.e. a ClientHello.
    let first = seen.lock().unwrap().clone();
    assert!(first.len() >= 2, "captured opening bytes");
    assert_eq!(
        &first[..2],
        &[0x16, 0x03],
        "wss carrier opens with a TLS ClientHello, got {:02x?}",
        &first[..first.len().min(4)]
    );
    // The ClientHello advertises browser-like ALPN (protocol names ride in the clear
    // in the ALPN extension) — a modern HTTPS hello without it is itself a mild tell.
    assert!(
        contains(&first, b"http/1.1") && contains(&first, b"h2"),
        "ClientHello should advertise h2 + http/1.1 ALPN"
    );
}

/// Naive substring search (the ALPN protocol names appear verbatim in the hello).
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn wss_carrier_round_trips_a_multichunk_payload() {
    // The production workload: a message at the largest write_msg cap (MAX_BLOB_FRAME),
    // which pads up to the 65 536 bucket and the session splits into two Noise chunks inside
    // ONE WS binary frame per direction. Proves the byte-stream shim reassembles frame
    // boundaries under the real workload, not just tiny pings. Both stay under the carrier's
    // WS message ceiling (`ws_config`) that stops an unauthenticated peer from buffering
    // tungstenite's default 64 MiB before the Noise handshake reads its ~50 bytes — a payload
    // padding past that ceiling is not a production message and the carrier refuses it.
    let (client_tls, server_tls) = test_tls();
    let (relay_priv, relay_pub) = relay_keys();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // A 64 000-byte request and a 65 000-byte reply: both ≤ MAX_BLOB_FRAME, each padded to
    // the 65 536 bucket → two Noise chunks reassembled from one WS frame.
    let req: Vec<u8> = (0..64_000usize).map(|i| (i % 251) as u8).collect();
    let reply: Vec<u8> = (0..65_000usize).map(|i| (i % 241) as u8).collect();
    let req_srv = req.clone();
    let reply_srv = reply.clone();

    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let channel = accept_wss(tcp, server_tls).unwrap();
        let mut sess = Session::accept(channel, &relay_priv).unwrap();
        let got = sess.read_msg(1 << 20).unwrap();
        assert_eq!(got, req_srv);
        sess.write_msg(&reply_srv, 1 << 20).unwrap();
    });

    let adapter = WssAdapter::with_config("localhost", client_tls);
    let channel = adapter.connect(&node::transport::Dest::from(addr)).unwrap();
    let mut sess = Session::connect(channel, &relay_pub).unwrap();
    sess.write_msg(&req, 1 << 20).unwrap();
    let got = sess.read_msg(1 << 20).unwrap();
    assert_eq!(got, reply);

    server.join().unwrap();
}

#[test]
fn relay_server_with_tls_serves_a_wss_client_end_to_end() {
    // The wiring proof: a real `RelayServer` with the wss carrier ON, driven through
    // its actual serve loop by a `SocketTransport` using `WssAdapter`. A fetch with
    // no cookie must traverse the full TLS + WebSocket + Noise + wire path and come
    // back as `NeedCookie` — i.e. the carrier is not just a mechanism, it's usable
    // end to end from the relay binary's own server type.
    use node::node::{FetchRequest, FetchResponse, RelayNode, Transport};
    use node::socket::{generate_noise_keypair, RelayServer, SocketTransport};

    // Matched client/server TLS from the same self-signed test cert.
    let (client_tls, server_cfg) = test_tls();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (npriv, npub) = generate_noise_keypair();
    let relay = RelayNode::new(0);
    let server = RelayServer::with_noise_keypair(relay, Arc::new(|| 0u64), npriv, npub)
        .with_tls(server_cfg);
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });

    let adapter = Arc::new(WssAdapter::with_config("localhost", client_tls));
    let transport = SocketTransport::with_adapter(addr, npub, adapter);
    let req = FetchRequest {
        mailbox: [0u8; 32],
        client_addr: b"probe".to_vec(),
        carrier_id: b"probe".to_vec(),
        cookie: None,
        proof: [0u8; 16],
        ack: false,
        own_proof: Vec::new(),
    };
    assert!(
        matches!(transport.fetch(&req, 0), FetchResponse::NeedCookie(_)),
        "a wss fetch without a cookie should come back NeedCookie over the full carrier"
    );
}

#[test]
fn wss_trusts_an_extra_root_ca_loaded_from_pem() {
    // A self-hosted relay behind a private CA (or a local self-signed cert): the
    // client trusts webpki roots PLUS the CA in KARST_WSS_ROOT_CA. Proven by a full
    // wss round-trip whose cert is trusted ONLY via the extra PEM root — webpki-only
    // would reject it (UnknownIssuer).
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let pem_path = std::env::temp_dir().join(format!("karst-test-ca-{}.pem", std::process::id()));
    std::fs::write(&pem_path, cert.cert.pem()).unwrap();

    let client_tls = node::wss::client_config_with_extra_root_pem(&pem_path).unwrap();
    let server_cfg = node::wss::server_config(vec![cert_der], key_der).unwrap();
    std::fs::remove_file(&pem_path).ok();

    let (relay_priv, relay_pub) = relay_keys();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let channel = accept_wss(tcp, server_cfg).unwrap();
        let mut sess = Session::accept(channel, &relay_priv).unwrap();
        assert_eq!(sess.read_msg(1 << 20).unwrap(), b"private ca");
        sess.write_msg(b"ok", 1 << 20).unwrap();
    });

    let adapter = WssAdapter::with_config("localhost", client_tls);
    let channel = adapter.connect(&node::transport::Dest::from(addr)).unwrap();
    let mut sess = Session::connect(channel, &relay_pub).unwrap();
    sess.write_msg(b"private ca", 1 << 20).unwrap();
    assert_eq!(sess.read_msg(1 << 20).unwrap(), b"ok");
    server.join().unwrap();
}

/// An inner adapter that records it was used, delegating to direct TCP. Stands in
/// for a SOCKS5 hop underneath the wss carrier.
struct SpyAdapter {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl TransportAdapter for SpyAdapter {
    fn connect(
        &self,
        dest: &node::transport::Dest,
    ) -> io::Result<Box<dyn node::transport::Channel>> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        node::transport::DirectTcpAdapter::default().connect(dest)
    }
}

#[test]
fn wss_carrier_routes_through_an_inner_adapter() {
    // Defense in depth: the wss carrier must run its TLS+WebSocket over whatever
    // channel an inner adapter establishes (e.g. SOCKS5 → Tor), not only direct TCP.
    let (client_tls, server_tls) = test_tls();
    let (relay_priv, relay_pub) = relay_keys();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let channel = accept_wss(tcp, server_tls).unwrap();
        let mut sess = Session::accept(channel, &relay_priv).unwrap();
        assert_eq!(sess.read_msg(1 << 20).unwrap(), b"via inner");
        sess.write_msg(b"ok", 1 << 20).unwrap();
    });

    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let spy = Arc::new(SpyAdapter { calls: calls.clone() });
    let adapter = WssAdapter::with_config("localhost", client_tls).through(spy);
    let channel = adapter.connect(&node::transport::Dest::from(addr)).unwrap();
    let mut sess = Session::connect(channel, &relay_pub).unwrap();
    sess.write_msg(b"via inner", 1 << 20).unwrap();
    assert_eq!(sess.read_msg(1 << 20).unwrap(), b"ok");
    server.join().unwrap();

    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the wss carrier must connect through the inner adapter"
    );
}

#[test]
fn direct_tcp_first_bytes_are_not_a_tls_hello() {
    // The neuter's opposite: over the plain TCP adapter the first bytes are the Noise
    // handshake frame (a small little-endian u16 length prefix), never a TLS hello.
    let (relay_priv, relay_pub) = relay_keys();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_srv = seen.clone();

    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let sniff = Sniff { inner: tcp, seen: seen_srv, cap: 8 };
        let mut sess = Session::accept(sniff, &relay_priv).unwrap();
        let _ = sess.read_msg(1 << 20).unwrap();
    });

    let adapter = DirectTcpAdapter::default();
    let channel = adapter.connect(&node::transport::Dest::from(addr)).unwrap();
    let mut sess = Session::connect(channel, &relay_pub).unwrap();
    sess.write_msg(b"hello", 1 << 20).unwrap();
    server.join().unwrap();

    let first = seen.lock().unwrap().clone();
    assert!(first.len() >= 2, "captured opening bytes");
    assert_ne!(&first[..2], &[0x16, 0x03], "direct TCP must NOT look like a TLS hello");
}

/// The client requests the operator's configured secret path, not `/`.
///
/// This is what makes co-hosting a relay behind an ordinary website work: the reverse
/// proxy routes one secret path to the relay and serves the real site everywhere else, so
/// the client MUST send exactly that path. The obfuscation is the deployment's job (proxy +
/// an unreachable relay port); this test covers the mechanism the client provides.
///
/// Server-side capture via `accept_hdr` (the production `accept_wss` discards the path).
/// Discriminating: hardcode the request URI back to `/` in `WssAdapter::connect` and the
/// captured path is `/`, not the secret — red.
#[allow(clippy::result_large_err)]
#[test]
fn the_client_requests_the_configured_secret_path_not_root() {
    use tungstenite::handshake::server::{Request, Response};

    let (client_tls, server_tls) = test_tls();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(String::new()));
    let seen_srv = seen.clone();

    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let tls = rustls::StreamOwned::new(rustls::ServerConnection::new(server_tls).unwrap(), tcp);
        // Terminate the WebSocket upgrade, recording the requested path in the callback.
        let _ws = tungstenite::accept_hdr(tls, |req: &Request, resp: Response| {
            *seen_srv.lock().unwrap() = req.uri().path().to_string();
            Ok(resp)
        })
        .unwrap();
    });

    // The operator's secret co-hosting path — random and unguessable, never a KARST default.
    let secret = "/s3cret-9f2a-co-host";
    let adapter = WssAdapter::with_config("localhost", client_tls).path(secret);
    let _channel = adapter.connect(&node::transport::Dest::from(addr)).unwrap();

    server.join().unwrap();
    assert_eq!(
        seen.lock().unwrap().as_str(),
        secret,
        "the client must request the configured secret path, not /"
    );
}

/// A default `WssAdapter` (no path set) requests `/` — the neutral, non-KARST default.
///
/// The complement to the test above: `/` names nothing, so it is a safe default; the
/// security requirement is only that the code ships NO KARST-specific path. If someone
/// baked in `/karst`, this would catch it (the default would not be `/`).
#[allow(clippy::result_large_err)]
#[test]
fn the_default_path_is_neutral_root_not_a_karst_fingerprint() {
    use tungstenite::handshake::server::{Request, Response};

    let (client_tls, server_tls) = test_tls();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(String::new()));
    let seen_srv = seen.clone();

    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let tls = rustls::StreamOwned::new(rustls::ServerConnection::new(server_tls).unwrap(), tcp);
        let _ws = tungstenite::accept_hdr(tls, |req: &Request, resp: Response| {
            *seen_srv.lock().unwrap() = req.uri().path().to_string();
            Ok(resp)
        })
        .unwrap();
    });

    // No .path() call → the default.
    let adapter = WssAdapter::with_config("localhost", client_tls);
    let _channel = adapter.connect(&node::transport::Dest::from(addr)).unwrap();

    server.join().unwrap();
    assert_eq!(seen.lock().unwrap().as_str(), "/", "the default path must be the neutral /");
}
