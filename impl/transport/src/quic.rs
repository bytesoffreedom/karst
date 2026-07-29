//! QUIC carrier (§15, QUIC-2) — `quinn` behind the existing `TransportAdapter` seam.
//!
//! **Why this is small.** The adapter contract is
//! `connect(&Dest) -> Box<dyn Channel>` where `Channel: Read + Write + Send`, and ONE QUIC
//! bidirectional stream is exactly a `Read + Write`. So the "one operation, one stream" model maps
//! onto the existing "one connection, one request" model with no change above the adapter: Noise,
//! the framing, `round_trip`, admission and the per-class frame ceilings are all untouched.
//!
//! **Noise stays inside.** QUIC's TLS protects client ↔ relay; the Double Ratchet protects sender ↔
//! recipient. Different segments; neither substitutes for the other. Keeping Noise means relay
//! identity is still `Noise_NK` against the pinned relay-id and QUIC remains a swappable carrier —
//! the trust model does not move because the transport did. Removing it later is a change to the
//! one place the client decides whether it is talking to the right relay, and is audit-gated.
//!
//! **Where this may be used.** The DIRECT path only. See `docs/design/quic-transport.md` §1: a
//! long-lived multiplexed connection re-clusters handles that per-handle SOCKS isolation keeps
//! apart, which is the linkage A8-4 removed. Tor cannot carry QUIC anyway (no `UDP ASSOCIATE`), so
//! the privacy answer and the plumbing answer agree.
//!
//! **What `connect_isolated` means here, and what it does not.** This adapter implements it, but
//! not to isolate anything: on the direct path there is no circuit to separate, and two scopes ride
//! the same UDP socket from the same address whatever they are called. It implements it because
//! that is where the caller states which compartment a request belongs to, and a POOL needs exactly
//! that to be safe (QUIC-5, see `QuicAdapter::pool`). The scope is a key, not a boundary, and the
//! name is inherited from the seam rather than a claim about what QUIC provides.
//!
//! **Async, contained.** `quinn` is async and everything above here is blocking. This module owns
//! its runtime and bridges at the read/write boundary; async does not leak into the client's
//! execution model.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

use quinn::rustls;

use crate::transport::{Channel, Dest, TransportAdapter, CONNECT_TIMEOUT, READ_TIMEOUT};

/// The application-layer protocol name in the TLS handshake. A CONSTANT, not per-relay data: a
/// relay that could name its own would be negotiating which protocol is spoken at all.
pub const ALPN: &[u8] = b"karst-relay/1";

/// How many connections one adapter keeps alive at once.
///
/// A bound rather than a tuning knob: the pool is keyed by scope and scopes are minted freely
/// (a handle per epoch per conversation), so an unbounded map would hold a UDP connection per
/// scope the process ever used. When it is full the oldest-inserted entry is evicted and its
/// connection closed — a closed pooled connection costs a redial, which is what the unpooled
/// path pays on every single request anyway.
const MAX_POOLED_CONNECTIONS: usize = 32;

/// Direct QUIC over UDP.
pub struct QuicAdapter {
    endpoint: quinn::Endpoint,
    runtime: Arc<tokio::runtime::Runtime>,
    /// Live connections, keyed by `(destination, scope)` — QUIC-5.
    ///
    /// **Why the key is the scope, and why an absent scope is never pooled.** The point of QUIC
    /// is one connection carrying many requests, and the danger is that "many requests" silently
    /// becomes "requests from compartments that must not be joined". A relay that serves two
    /// requests on one connection knows they came from one party with certainty — an exact join,
    /// stronger than the same-IP inference it could already make, and one that survives the
    /// address changing. So the pool may only merge requests the CALLER has said belong together.
    /// The scope is that statement (`Peer::scope_for`, derived from the handle the relay already
    /// sees in the clear). A request that passes no scope has said nothing, and pooling on
    /// "unknown" would merge every unscoped request in the process — bundle publishes, blob
    /// transfers and discovery lookups across every channel — onto one connection. That is the
    /// A8-4 join rebuilt at the transport layer, so it is refused: no scope, no pool, a fresh
    /// connection every time, exactly the behaviour before this slice.
    ///
    /// This is a RULE, not a setting. There is no flag that turns unscoped pooling on.
    ///
    /// Insertion order is kept alongside so eviction has something to choose by; a `HashMap` of
    /// this size does not warrant a real LRU.
    pool: Mutex<Pool>,
}

/// The pooled connections plus the insertion order eviction uses.
#[derive(Default)]
struct Pool {
    live: HashMap<(String, String), quinn::Connection>,
    order: Vec<(String, String)>,
}

impl QuicAdapter {
    /// Build an endpoint bound to an ephemeral local UDP port.
    ///
    /// `rustls` verification is deliberately a no-op: the relay's certificate is not what
    /// authenticates it — Noise_NK against the pinned relay-id is, one layer up, exactly as on TCP
    /// and WSS. A public CA chain would be meaningless here (a relay is named by a key, not a DNS
    /// name) and pinning a fingerprint would be worse than meaningless while the descriptor's
    /// signature does not cover it (see `protocol::RelayDescriptor::quic_addrs`). The TLS layer is
    /// doing transport encapsulation; the authentication is inside it.
    pub fn new() -> io::Result<Self> {
        let runtime = Arc::new(
            // A single-threaded runtime: this drives one endpoint's I/O, and the work above it is
            // blocking anyway. More threads would only add scheduling for no parallelism.
            tokio::runtime::Builder::new_current_thread().enable_all().build()?,
        );
        let _guard = runtime.enter();

        let mut cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoiseAuthenticatesTheRelay))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![ALPN.to_vec()];
        // 0-RTT application data stays OFF (QUIC-0 §4): early data is replayable and nearly every
        // request this carries changes state. Session resumption is fine; early data is not.
        cfg.enable_early_data = false;

        let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(cfg)
            .map_err(|e| io::Error::other(format!("quic client config: {e}")))?;
        let mut client = quinn::ClientConfig::new(Arc::new(quic_cfg));
        let mut transport = quinn::TransportConfig::default();
        // Same wall-clock discipline the TCP carrier has: a silent path must become an error
        // rather than wedge the calling thread forever.
        transport.max_idle_timeout(Some(
            READ_TIMEOUT.try_into().map_err(|_| io::Error::other("idle timeout out of range"))?,
        ));
        // QUIC-6: connection MIGRATION is refused, and it is refused BY THE RELAY
        // (`relay::quic_server`), not here. Whether a session may follow a client to a new address
        // is the receiver's decision, and putting it there means the property does not depend on
        // every client being well-behaved.
        //
        // NO `keep_alive_interval`, deliberately (QUIC-8, docs/design/presence-and-typing.md).
        // With pooling in place this will read as a defect the first time somebody profiles it:
        // idle pooled connections keep going cold and getting redialled. Keeping them warm costs a
        // periodic packet PER SCOPE, sent while the user is doing nothing — which is presence, at a
        // lower resolution, arriving through the back door of a performance setting. A redial costs
        // one handshake on the next request; a heartbeat costs a graph of when the client was
        // running. If a future pass wants warm connections, the trade is argued in that document
        // first, not settled here.
        //
        // The client side of that rule is in `connect_isolated`: a pooled connection that has died
        // — which is what a local network change looks like from here, since the relay refuses to
        // migrate it — is EVICTED and redialled, never handed to the next caller as live.
        client.transport_config(Arc::new(transport));

        let mut endpoint = quinn::Endpoint::client("[::]:0".parse().expect("valid bind address"))?;
        endpoint.set_default_client_config(client);
        Ok(QuicAdapter { endpoint, runtime, pool: Mutex::new(Pool::default()) })
    }
}

impl TransportAdapter for QuicAdapter {
    fn carrier_label(&self) -> &'static str {
        "quic"
    }

    /// No scope: a fresh connection, never pooled and never reused. See `QuicAdapter::pool`.
    fn connect(&self, dest: &Dest) -> io::Result<Box<dyn Channel>> {
        self.stream_on(self.dial(dest)?)
    }

    /// Scoped: reuse this scope's connection at this destination if one is live, else dial and
    /// remember it. An absent scope falls through to `connect`, which never pools — the rule the
    /// `pool` field's doc states.
    fn connect_isolated(&self, dest: &Dest, scope: Option<&str>) -> io::Result<Box<dyn Channel>> {
        let Some(scope) = scope else { return self.connect(dest) };
        let key = (dest.to_string(), scope.to_string());

        // A pooled connection may have died since it was stored — the relay closed it, the leash
        // fired, or the local network moved under it (which the relay refuses to migrate, QUIC-6).
        // `close_reason` catches the ones already known dead; `open_bi` catches the rest. Either
        // way the entry is dropped and redialled rather than handed over as live, because a stale
        // pooled entry turns one transient failure into a permanently broken path.
        if let Some(conn) = self.take_live(&key) {
            match self.stream_on(conn.clone()) {
                Ok(channel) => {
                    self.store(key, conn);
                    return Ok(channel);
                }
                Err(_) => { /* dead after all: fall through to a fresh dial */ }
            }
        }
        let conn = self.dial(dest)?;
        let channel = self.stream_on(conn.clone())?;
        self.store(key, conn);
        Ok(channel)
    }
}

impl QuicAdapter {
    /// One QUIC connection to `dest`, with no pooling involved.
    fn dial(&self, dest: &Dest) -> io::Result<quinn::Connection> {
        // QUIC needs a socket address; a name only a carrier can resolve (`.onion`, `.i2p`) has no
        // meaning here and resolving it locally would either fail or leak the lookup — the same
        // refusal `DirectTcpAdapter` makes, for the same reason.
        let addr = dest.as_ip().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{dest} is a name, not an address — QUIC cannot resolve it, and resolving it \
                     here would leak the lookup to a DNS server the user never chose"
                ),
            )
        })?;
        // The TLS SNI has to be SOMETHING and names nothing here: the relay is identified by its
        // Noise key, not by a hostname. A fixed placeholder keeps it from leaking the address as a
        // hostname in the clear part of the handshake.
        self.runtime.block_on(async {
            let connecting = self
                .endpoint
                .connect(addr, "karst")
                .map_err(|e| io::Error::other(format!("quic connect: {e}")))?;
            tokio::time::timeout(CONNECT_TIMEOUT, connecting)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "quic handshake timed out"))?
                .map_err(|e| io::Error::other(format!("quic handshake: {e}")))
        })
    }

    /// Open one bidirectional stream on `conn` and present it as a blocking channel.
    fn stream_on(&self, conn: quinn::Connection) -> io::Result<Box<dyn Channel>> {
        let (send, recv) = self
            .runtime
            .block_on(conn.open_bi())
            .map_err(|e| io::Error::other(format!("quic stream: {e}")))?;
        Ok(Box::new(QuicStream {
            send,
            recv,
            runtime: self.runtime.clone(),
            // Held so the connection is not closed while the stream is alive.
            _conn: conn,
            pending: Vec::new(),
        }))
    }

    /// Remove and return this key's connection if it has not already failed.
    fn take_live(&self, key: &(String, String)) -> Option<quinn::Connection> {
        let mut pool = self.pool.lock().expect("quic pool mutex");
        let conn = pool.live.remove(key)?;
        pool.order.retain(|k| k != key);
        conn.close_reason().is_none().then_some(conn)
    }

    /// Remember `conn` for `key`, evicting the oldest entry if the pool is full.
    fn store(&self, key: (String, String), conn: quinn::Connection) {
        let mut pool = self.pool.lock().expect("quic pool mutex");
        if pool.live.len() >= MAX_POOLED_CONNECTIONS {
            if let Some(oldest) = pool.order.first().cloned() {
                if let Some(dead) = pool.live.remove(&oldest) {
                    dead.close(0u32.into(), b"pool full");
                }
                pool.order.remove(0);
            }
        }
        pool.order.retain(|k| *k != key);
        pool.order.push(key.clone());
        pool.live.insert(key, conn);
    }

    /// How many connections the pool is holding — a test seam for the rule that an unscoped
    /// request never pools, and for eviction.
    #[doc(hidden)]
    pub fn pooled(&self) -> usize {
        self.pool.lock().expect("quic pool mutex").live.len()
    }
}

/// One QUIC bidirectional stream, presented as a blocking byte channel.
struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    runtime: Arc<tokio::runtime::Runtime>,
    _conn: quinn::Connection,
    /// Bytes read from the stream but not yet handed to the caller. The framing layer above reads
    /// in small pieces (a length prefix, then a body), while a QUIC read returns whatever chunk
    /// arrived — so the remainder has to be kept rather than dropped.
    pending: Vec<u8>,
}

impl Read for QuicStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pending.is_empty() {
            let mut chunk = vec![0u8; 16 * 1024];
            let n = self
                .runtime
                .block_on(self.recv.read(&mut chunk))
                .map_err(|e| io::Error::other(format!("quic read: {e}")))?;
            match n {
                None | Some(0) => return Ok(0), // the peer finished its half
                Some(n) => {
                    chunk.truncate(n);
                    self.pending = chunk;
                }
            }
        }
        let take = self.pending.len().min(buf.len());
        buf[..take].copy_from_slice(&self.pending[..take]);
        self.pending.drain(..take);
        Ok(take)
    }
}

impl Write for QuicStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.runtime
            .block_on(self.send.write(buf))
            .map_err(|e| io::Error::other(format!("quic write: {e}")))
    }

    fn flush(&mut self) -> io::Result<()> {
        // A QUIC stream has no separate flush; the write above already queued the bytes. Finishing
        // the send half here would end the request before the response is read, so it is NOT done.
        Ok(())
    }
}

/// Accepts any certificate, on purpose.
///
/// The relay is authenticated by `Noise_NK` against the pinned relay-id INSIDE this tunnel, on
/// every carrier equally. Verifying a CA chain would authenticate a DNS name nobody uses, and
/// pinning a fingerprint from the descriptor would pin a value the descriptor's signature does not
/// cover — see `RelayDescriptor::quic_addrs`. Named as bluntly as it behaves so that nobody reads
/// "TLS" here as "authenticated".
#[derive(Debug)]
struct NoiseAuthenticatesTheRelay;

impl rustls::client::danger::ServerCertVerifier for NoiseAuthenticatesTheRelay {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The carrier names itself. `carrier_label` is required rather than defaulted precisely so a
    /// new adapter cannot inherit somebody else's label (A4-10) — a privacy indicator that can be
    /// wrong is worse than none.
    #[test]
    fn the_quic_carrier_reports_itself_as_quic() {
        let a = QuicAdapter::new().expect("endpoint binds");
        assert_eq!(a.carrier_label(), "quic");
    }

    /// A name QUIC cannot resolve is REFUSED, not silently resolved through whatever DNS the host
    /// happens to have. Same rule `DirectTcpAdapter` follows: resolving a `.onion` locally either
    /// fails or leaks the lookup.
    #[test]
    fn a_name_only_an_overlay_can_resolve_is_refused() {
        let a = QuicAdapter::new().expect("endpoint binds");
        let err = match a.connect(&Dest::new("somerelay.onion", 9000)) {
            Err(e) => e,
            Ok(_) => panic!("a name QUIC cannot resolve must be refused, not dialled"),
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("leak the lookup"), "the refusal must say why: {err}");
    }

    /// **No keepalive on a pooled connection**, and it is a decision rather than an omission
    /// (docs/design/presence-and-typing.md). A heartbeat per pooled connection is a heartbeat per
    /// SCOPE — presence at a lower resolution, introduced as a performance setting. An idle
    /// connection is meant to die and be redialled.
    ///
    /// Pinned as a test because the plausible "fix" is one line on the transport config that no
    /// reviewer would question, and the property it removes is invisible at the call site.
    #[test]
    fn a_pooled_connection_is_left_to_die_rather_than_kept_warm() {
        let src = include_str!("quic.rs");
        // The needle is split so this assertion does not match its own source.
        let setter = concat!("keep_alive", "_interval(");
        assert!(
            !src.contains(setter),
            "a keepalive was added to the client transport config. That is a packet per pooled \
             connection — i.e. per scope — emitted while the user is idle, which is the presence \
             signal QUIC-8 decided not to emit. Argue it in docs/design/presence-and-typing.md \
             before changing this."
        );
    }

    /// Connecting to a UDP port with nothing behind it fails within the connect timeout instead of
    /// hanging — the property that makes falling back to WSS possible at all (QUIC-4).
    #[test]
    fn a_dead_udp_endpoint_times_out_rather_than_hanging() {
        let a = QuicAdapter::new().expect("endpoint binds");
        let started = std::time::Instant::now();
        // Reserved-for-documentation address: nothing answers, and nothing on the LAN is disturbed.
        let err = match a.connect(&Dest::new("192.0.2.1", 9)) {
            Err(e) => e,
            Ok(_) => panic!("nothing is listening there; a connection must not succeed"),
        };
        assert!(
            started.elapsed() < CONNECT_TIMEOUT * 3,
            "a dead endpoint took {:?}, which is not a bounded failure",
            started.elapsed()
        );
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "unexpected error: {err}");
    }
}
