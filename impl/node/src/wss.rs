//! WebSocket-over-TLS carrier (§15) — the first REAL carrier that isn't just a seam
//! to an external transport. The KARST Noise session rides inside an ordinary
//! `wss://` connection, so on the wire it looks like a browser talking to an HTTPS
//! WebSocket endpoint: a real TLS handshake (ClientHello, SNI, ALPN-less HTTP
//! upgrade) rather than the bare Noise prologue that an on-path classifier can fingerprint.
//!
//! **TLS here is TRANSPORT ENCAPSULATION, not security.** Noise (`session.rs`) already
//! authenticates the relay end-to-end and encrypts everything; the outer TLS adds
//! nothing to confidentiality. Its whole job is to make the traffic indistinguishable
//! from normal HTTPS — which is exactly why the client verifies the server against
//! real webpki roots and presents a real-looking SNI: a self-signed cert to an odd
//! endpoint would itself be a fingerprint, defeating the point. Tests use a
//! test-only root so they can run against a self-signed pair.
//!
//! Layering (both directions): `TCP → rustls → WebSocket → [this byte-stream shim] →
//! Noise Session`. The shim turns the message-framed WebSocket into the plain
//! `Read + Write` byte stream the Noise `Session` expects; because the session
//! flushes once per logical message (handshake frame / request / response), each
//! flush maps to exactly one WebSocket binary frame.

use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConnection, RootCertStore, ServerConnection, StreamOwned};
use tungstenite::{Message, WebSocket};

use crate::transport::{Channel, TransportAdapter};

/// Adapt a message-framed `WebSocket` into a byte-oriented `Read + Write` stream.
/// Writes are buffered and emitted as ONE binary frame per `flush`; reads serve
/// bytes out of the most recently received binary frame, pulling the next frame
/// only when the current one is drained. Control frames (ping/pong) are handled by
/// `tungstenite` and skipped here; a close frame reads as EOF.
pub struct WsByteStream<S: Read + Write> {
    ws: WebSocket<S>,
    rbuf: Vec<u8>,
    rpos: usize,
    wbuf: Vec<u8>,
}

impl<S: Read + Write> WsByteStream<S> {
    fn new(ws: WebSocket<S>) -> Self {
        WsByteStream { ws, rbuf: Vec::new(), rpos: 0, wbuf: Vec::new() }
    }
}

fn ws_err(e: tungstenite::Error) -> io::Error {
    io::Error::other(e)
}

/// WebSocket message/frame ceiling for the carrier. The Noise session sends exactly one
/// framed message per flush, ≤ `MAX_BLOB_FRAME` (~65 KB) + overhead — so 128 KiB is ~2×
/// headroom. Without this, tungstenite's default (`max_message_size` = 64 MiB) lets an
/// anonymous peer make the relay (or a client, from a malicious relay) buffer up to 64 MiB
/// per connection *before* the Noise handshake reads its ~50 bytes — a memory-cost DoS that
/// bypasses every other read cap in the system.
const WS_MAX_FRAME: usize = 128 * 1024;
fn ws_config() -> tungstenite::protocol::WebSocketConfig {
    tungstenite::protocol::WebSocketConfig {
        max_message_size: Some(WS_MAX_FRAME),
        max_frame_size: Some(WS_MAX_FRAME),
        ..Default::default()
    }
}

impl<S: Read + Write> Read for WsByteStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.rpos >= self.rbuf.len() {
            match self.ws.read().map_err(ws_err)? {
                Message::Binary(data) => {
                    self.rbuf = data;
                    self.rpos = 0;
                }
                // A clean close is end-of-stream for the byte reader.
                Message::Close(_) => return Ok(0),
                // Ping/Pong/Text/frame carry no session bytes — keep reading.
                _ => continue,
            }
        }
        let n = (self.rbuf.len() - self.rpos).min(buf.len());
        buf[..n].copy_from_slice(&self.rbuf[self.rpos..self.rpos + n]);
        self.rpos += n;
        Ok(n)
    }
}

impl<S: Read + Write> Write for WsByteStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.wbuf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.wbuf.is_empty() {
            let msg = std::mem::take(&mut self.wbuf);
            self.ws.write(Message::Binary(msg)).map_err(ws_err)?;
        }
        self.ws.flush().map_err(ws_err)
    }
}

/// Build a client TLS config that trusts the standard webpki root store — i.e.
/// behaves like an ordinary HTTPS client. Used in production.
fn webpki_client_config() -> Arc<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    client_config_with_roots(roots)
}

/// Build a client TLS config trusting exactly `roots`. Tests pass a store holding
/// only the test CA; production passes the webpki roots.
pub fn client_config_with_roots(roots: RootCertStore) -> Arc<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring provider supports the default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    // Advertise the same ALPN a browser does. A modern HTTPS ClientHello without an
    // ALPN extension is itself a mild tell; offering h2 + http/1.1 makes the hello
    // look ordinary. We never actually speak h2 — the server declines ALPN and the
    // WebSocket upgrade proceeds over HTTP/1.1 — this is purely for the hello's shape.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Client config trusting the standard webpki roots PLUS an extra root loaded from
/// a PEM file. For a self-hosted relay behind a private CA, or for local testing of
/// the wss carrier against a self-signed cert. The default path (no extra root)
/// stays webpki-only — this only ADDS trust, opt-in.
pub fn client_config_with_extra_root_pem(pem_path: &Path) -> io::Result<Arc<rustls::ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let pem = std::fs::read(pem_path)?;
    let mut added = 0usize;
    for cert in rustls_pemfile::certs(&mut &pem[..]) {
        roots.add(cert?).map_err(io::Error::other)?;
        added += 1;
    }
    if added == 0 {
        return Err(io::Error::other("no certificates parsed from the extra root CA PEM"));
    }
    Ok(client_config_with_roots(roots))
}

/// Client carrier: connect to `dest` over an INNER transport (direct TCP by
/// default, or any `TransportAdapter` — e.g. SOCKS5-to-Tor for defense in depth),
/// wrap it in TLS (SNI = `host`, verified against `config`'s roots), then run a
/// WebSocket upgrade — so the Noise session rides inside an ordinary `wss://host/`
/// connection. Composing wss over SOCKS gives "looks like HTTPS" **and** an
/// external PT's obfuscation at once.
pub struct WssAdapter {
    host: String,
    /// The HTTP path requested in the WebSocket upgrade. Defaults to `/`.
    ///
    /// This is what lets a relay **co-host behind an ordinary website on one domain**: the
    /// TLS handshake presents `host` as SNI (indistinguishable from the site), and the
    /// upgrade targets a secret path that the operator's reverse proxy routes to the relay
    /// while everything else serves the real site. The obfuscation is the DEPLOYMENT's
    /// (reverse proxy + a relay port not directly reachable); this field is the mechanism
    /// the client needs to participate in it.
    ///
    /// **No well-known default.** `/` is the neutral universal default — it names nothing.
    /// A baked-in KARST-specific path (`/karst`, …) would be a fingerprint an adversary probes
    /// for on every host to find every relay at once. The secret path is the operator's to
    /// choose, random and unguessable; the code must never ship one.
    path: String,
    config: Arc<rustls::ClientConfig>,
    inner: Arc<dyn TransportAdapter>,
}

impl WssAdapter {
    /// Production carrier over direct TCP: verify the relay's cert against the
    /// standard webpki roots and present `host` as SNI (a real hostname the relay
    /// has a cert for).
    pub fn new(host: impl Into<String>) -> Self {
        WssAdapter {
            host: host.into(),
            path: "/".into(),
            config: webpki_client_config(),
            inner: Arc::new(crate::transport::DirectTcpAdapter::default()),
        }
    }

    /// Test/advanced carrier over direct TCP: bring your own client config (e.g. a
    /// store trusting a self-signed test CA).
    pub fn with_config(host: impl Into<String>, config: Arc<rustls::ClientConfig>) -> Self {
        WssAdapter {
            host: host.into(),
            path: "/".into(),
            config,
            inner: Arc::new(crate::transport::DirectTcpAdapter::default()),
        }
    }

    /// Set the secret co-hosting path (see the `path` field). A leading `/` is added if
    /// missing; empty stays `/`, which is the neutral no-obfuscation default.
    pub fn path(mut self, p: impl Into<String>) -> Self {
        let p = p.into();
        self.path = if p.is_empty() {
            "/".into()
        } else if p.starts_with('/') {
            p
        } else {
            format!("/{p}")
        };
        self
    }

    /// Route the wss carrier through an inner transport (e.g. `Socks5Adapter`): the
    /// TLS+WebSocket runs over whatever channel `inner` establishes.
    pub fn through(mut self, inner: Arc<dyn TransportAdapter>) -> Self {
        self.inner = inner;
        self
    }
}

impl TransportAdapter for WssAdapter {
    fn connect(&self, dest: &crate::transport::Dest) -> io::Result<Box<dyn Channel>> {
        let channel = self.inner.connect(dest)?;
        let server_name: ServerName<'static> = ServerName::try_from(self.host.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid SNI host"))?;
        let conn = ClientConnection::new(self.config.clone(), server_name)
            .map_err(io::Error::other)?;
        let tls = StreamOwned::new(conn, channel);
        // WebSocket upgrade over the established TLS stream. The URI's host feeds the
        // `Host` header; the path is the operator's secret co-hosting path (default `/`),
        // which the relay's reverse proxy uses to route this to the relay.
        let uri = format!("ws://{}{}", self.host, self.path);
        let (ws, _resp) = tungstenite::client::client_with_config(uri.as_str(), tls, Some(ws_config()))
            .map_err(|e| io::Error::other(format!("ws upgrade: {e}")))?;
        Ok(Box::new(WsByteStream::new(ws)))
    }
}

/// Relay side: terminate TLS + WebSocket on an accepted TCP connection and return
/// the inner byte stream, ready for `Session::accept`. The caller owns the TLS
/// `ServerConfig` (its cert/key); this mirrors `WssAdapter::connect`.
pub fn accept_wss<S: Read + Write + Send + 'static>(
    stream: S,
    config: Arc<rustls::ServerConfig>,
) -> io::Result<Box<dyn Channel>> {
    let conn = ServerConnection::new(config).map_err(io::Error::other)?;
    let tls = StreamOwned::new(conn, stream);
    let ws = tungstenite::accept_with_config(tls, Some(ws_config()))
        .map_err(|e| io::Error::other(format!("ws accept: {e}")))?;
    Ok(Box::new(WsByteStream::new(ws)))
}

/// Build a relay TLS `ServerConfig` from a cert chain + private key (DER). The relay
/// presents this cert; for a realistic deployment it should be a REAL cert for the relay's
/// hostname (e.g. Let's Encrypt) so the endpoint is indistinguishable from any other
/// HTTPS site. Pass the result to `RelayServer::with_tls`.
pub fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> io::Result<Arc<rustls::ServerConfig>> {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(io::Error::other)?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(io::Error::other)?;
    Ok(Arc::new(config))
}

/// Load a relay TLS `ServerConfig` from PEM cert + key files (for the `karst-relay`
/// binary). The cert file may be a full chain; the key is the first private key found.
pub fn server_config_from_pem_files(
    cert_path: &Path,
    key_path: &Path,
) -> io::Result<Arc<rustls::ServerConfig>> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;
    let certs = rustls_pemfile::certs(&mut &cert_pem[..]).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(io::Error::other("no certificates in cert PEM"));
    }
    let key = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or_else(|| io::Error::other("no private key in key PEM"))?;
    server_config(certs, key)
}
