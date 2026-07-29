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
//! the privacy answer and the plumbing answer agree — and this adapter deliberately does not
//! implement `connect_isolated`, so it inherits the default and cannot pretend to isolate circuits
//! it has no way to separate.
//!
//! **Async, contained.** `quinn` is async and everything above here is blocking. This module owns
//! its runtime and bridges at the read/write boundary; async does not leak into the client's
//! execution model.

use std::io::{self, Read, Write};
use std::sync::Arc;

use quinn::rustls;

use crate::transport::{Channel, Dest, TransportAdapter, CONNECT_TIMEOUT, READ_TIMEOUT};

/// The application-layer protocol name in the TLS handshake. A CONSTANT, not per-relay data: a
/// relay that could name its own would be negotiating which protocol is spoken at all.
pub const ALPN: &[u8] = b"karst-relay/1";

/// Direct QUIC over UDP.
pub struct QuicAdapter {
    endpoint: quinn::Endpoint,
    runtime: Arc<tokio::runtime::Runtime>,
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
        client.transport_config(Arc::new(transport));

        let mut endpoint = quinn::Endpoint::client("[::]:0".parse().expect("valid bind address"))?;
        endpoint.set_default_client_config(client);
        Ok(QuicAdapter { endpoint, runtime })
    }
}

impl TransportAdapter for QuicAdapter {
    fn carrier_label(&self) -> &'static str {
        "quic"
    }

    fn connect(&self, dest: &Dest) -> io::Result<Box<dyn Channel>> {
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
        let conn = self.runtime.block_on(async {
            let connecting = self
                .endpoint
                .connect(addr, "karst")
                .map_err(|e| io::Error::other(format!("quic connect: {e}")))?;
            tokio::time::timeout(CONNECT_TIMEOUT, connecting)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "quic handshake timed out"))?
                .map_err(|e| io::Error::other(format!("quic handshake: {e}")))
        })?;
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
