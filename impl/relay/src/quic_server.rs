//! QUIC listener (QUIC-3): a UDP endpoint beside the TCP one, feeding the SAME request loop.
//!
//! Every accepted bidirectional stream is handed to `server::serve_channel` — the identical Noise
//! handshake, request loop, per-class frame ceilings and deadlines the TCP carrier uses. There is
//! deliberately no second implementation: those are security properties, and a carrier that
//! reimplemented them would be a carrier where they drift apart.
//!
//! **The regression this slice exists to avoid.** `MAX_UNADMITTED_REQUESTS` (R2-13) bounds what a
//! peer can cost while holding a connection slot without ever authenticating. On TCP that works
//! because a connection carries one Noise session. Under QUIC an attacker opens a thousand streams
//! on ONE connection, and a per-stream count would let each of them pay the leash separately —
//! the protection closed on TCP and wide open on QUIC, which is worse than not having it, because
//! the record says it is closed. So the counter is per CONNECTION, shared across its streams, and
//! there is a second, tighter bound on how many streams a connection may have open before any of
//! them has been admitted.
//!
//! **The certificate is transport encapsulation, not identity.** It is self-signed and minted at
//! startup, because the relay is authenticated by `Noise_NK` against its pinned relay-id INSIDE
//! this tunnel — the same way on every carrier. Clients do not verify it (see
//! `node::quic::NoiseAuthenticatesTheRelay`); a CA chain would certify a DNS name nobody uses.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use quinn::rustls;

use crate::node::RelayNode;
use node::quic::ALPN;

use crate::server::{serve_channel, Clock, ConnLimiter, MAX_CONNECTIONS};

/// How many streams a connection may have open while NONE of them has been admitted.
///
/// Separate from `MAX_UNADMITTED_REQUESTS`, which bounds unadmitted REQUESTS: a stream that is
/// opened and then left silent sends no requests at all, so the request leash never fires on it.
/// Without this bound, "open ten thousand streams and say nothing" costs the attacker one
/// connection and costs the relay ten thousand tasks — the QUIC-shaped version of the slowloris
/// that `CONN_READ_TIMEOUT` handles on TCP.
///
/// Generous for the legitimate shape: a client opens one stream per operation and gets admitted on
/// the first request of each, so it never has more than a handful unadmitted at once.
const MAX_UNADMITTED_STREAMS_PER_CONN: usize = 16;

/// Per-connection state shared by all of its streams.
struct ConnState {
    /// Unadmitted REQUESTS across every stream of this connection (R2-13).
    unadmitted_requests: AtomicUsize,
    /// Streams currently open that have not yet had a request admitted.
    unadmitted_streams: AtomicUsize,
}

/// A QUIC endpoint serving one `RelayNode`.
pub struct QuicServer {
    endpoint: quinn::Endpoint,
    relay: Arc<RwLock<RelayNode>>,
    clock: Clock,
    noise_private: [u8; 32],
    runtime: tokio::runtime::Runtime,
}

impl QuicServer {
    /// Bind a QUIC endpoint on `addr`, minting a fresh self-signed certificate.
    ///
    /// UDP and TCP can use the same port number simultaneously, so a relay can offer QUIC on
    /// UDP/443 alongside WSS on TCP/443 without choosing between them.
    pub fn bind(
        addr: std::net::SocketAddr,
        relay: Arc<RwLock<RelayNode>>,
        clock: Clock,
        noise_private: [u8; 32],
    ) -> io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let _guard = runtime.enter();

        let cert = rcgen::generate_simple_self_signed(vec!["karst".to_string()])
            .map_err(|e| io::Error::other(format!("quic certificate: {e}")))?;
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(
            cert.key_pair.serialize_der(),
        )
        .map_err(|e| io::Error::other(format!("quic key: {e}")))?;

        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| io::Error::other(format!("quic tls config: {e}")))?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        // 0-RTT stays off on BOTH sides. Accepting early data the client never sends would be
        // dead configuration; accepting it if a future client did send it would reintroduce
        // replay on operations that change state.
        tls.max_early_data_size = 0;

        let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|e| io::Error::other(format!("quic server config: {e}")))?;
        let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
        let mut transport = quinn::TransportConfig::default();
        // A silent connection must become an error rather than hold resources forever — the same
        // discipline `CONN_READ_TIMEOUT` gives the TCP path.
        transport.max_idle_timeout(Some(
            crate::server::CONN_READ_TIMEOUT
                .try_into()
                .map_err(|_| io::Error::other("idle timeout out of range"))?,
        ));
        // A hard ceiling below the leash: even before any accounting runs, one connection cannot
        // have more than this many streams in flight.
        transport.max_concurrent_bidi_streams(
            u32::try_from(MAX_UNADMITTED_STREAMS_PER_CONN * 4).expect("small").into(),
        );
        transport.max_concurrent_uni_streams(0u32.into()); // nothing here uses unidirectional streams
        cfg.transport_config(Arc::new(transport));

        let endpoint = quinn::Endpoint::server(cfg, addr)?;
        Ok(QuicServer { endpoint, relay, clock, noise_private, runtime })
    }

    /// The bound local address (tests bind port 0 and need to know where).
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Accept connections until the endpoint closes. Blocking, like `serve_listener`.
    pub fn serve(self) -> io::Result<()> {
        let limiter = Arc::new(ConnLimiter::new(MAX_CONNECTIONS));
        let relay = self.relay;
        let clock = self.clock;
        let noise_private = self.noise_private;
        let endpoint = self.endpoint.clone();
        self.runtime.block_on(async move {
            while let Some(incoming) = endpoint.accept().await {
                // At capacity: refuse before the handshake, so a flood cannot buy handshakes.
                let Some(permit) = limiter.try_acquire() else {
                    incoming.refuse();
                    continue;
                };
                let (relay, clock) = (relay.clone(), clock.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    let Ok(conn) = incoming.await else { return };
                    let state = Arc::new(ConnState {
                        unadmitted_requests: AtomicUsize::new(0),
                        unadmitted_streams: AtomicUsize::new(0),
                    });
                    loop {
                        let Ok((send, recv)) = conn.accept_bi().await else { break };
                        if state.unadmitted_streams.load(Ordering::Relaxed)
                            >= MAX_UNADMITTED_STREAMS_PER_CONN
                        {
                            // Silent streams piling up on one connection: close the whole
                            // connection rather than the stream, so the cost of trying is the
                            // connection slot, not a free retry.
                            conn.close(0u32.into(), b"too many unadmitted streams");
                            break;
                        }
                        state.unadmitted_streams.fetch_add(1, Ordering::Relaxed);
                        let (relay, clock, state) = (relay.clone(), clock.clone(), state.clone());
                        let handle = tokio::runtime::Handle::current();
                        // The request loop is blocking (Noise + framing + the store), so it runs
                        // on the blocking pool rather than stalling the async reactor.
                        tokio::task::spawn_blocking(move || {
                            let channel = Box::new(QuicStream { send, recv, handle });
                            let _ = serve_channel(
                                channel,
                                relay,
                                clock,
                                noise_private,
                                &state.unadmitted_requests,
                            );
                            state.unadmitted_streams.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                });
            }
        });
        Ok(())
    }
}

/// One accepted QUIC stream as a blocking byte channel — the mirror of the client side.
struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    handle: tokio::runtime::Handle,
}

impl Read for QuicStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // `read` fills as much as it can and reports how much; the framing layer above loops, so
        // a short read is fine and no leftover buffer is needed on this side.
        let n = self
            .handle
            .block_on(self.recv.read(buf))
            .map_err(|e| io::Error::other(format!("quic read: {e}")))?;
        Ok(n.unwrap_or(0))
    }
}

impl Write for QuicStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.handle
            .block_on(self.send.write(buf))
            .map_err(|e| io::Error::other(format!("quic write: {e}")))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
