//! TCP-сервер вокруг `RelayNode`, **поверх Noise-сессии (§15)**.
//!
//! **СКЕЛЕТ.** Блокирующий, поток-на-соединение, std-only. Каждое соединение сначала проходит
//! Noise_NK-handshake (`node::session`), потом обменивается запрос-ответом внутри зашифрованного
//! сеанса.
//!
//! **Обязательный туннель — без тихого fallback на plaintext.** Провалившийся/отсутствующий
//! handshake = жёсткая ошибка, соединение закрывается; активный противник не может «раздеть»
//! сессию до старого открытого протокола.
//!
//! **Сервер ставит СВОЁ время** (см. `node::protocol`): `now` не едет по проводу.

use std::io;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use snow::Builder;

use node::protocol::{AckResponse, BlobResponse, BundleOpkResponse, FetchResponse, PublishResponse, Response};
use crate::node::{RelayNode};
use node::session::{Session, NOISE_PARAMS};
use karst_transport::transport::Channel;
use node::wire::{
    decode, encode, WireRequest, WireResponse, MAX_BLOB_FRAME, MAX_RESPONSE_FRAME,
};

/// Часы сервера: возвращают текущее время в секундах.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Сгенерировать Noise-static-пару `(private, public)` тем же resolver'ом, что
/// использует `RelayServer`. Бинарь зовёт на ПЕРВОМ запуске и персистит пару,
/// затем на рестартах поднимает через `with_noise_keypair` (стабильный relay-id).
pub fn generate_noise_keypair() -> ([u8; 32], [u8; 32]) {
    let kp = Builder::new(NOISE_PARAMS.parse().expect("valid noise params"))
        .generate_keypair()
        .expect("noise keygen");
    let private: [u8; 32] = kp.private.try_into().expect("25519 private is 32 bytes");
    let public: [u8; 32] = kp.public.try_into().expect("25519 public is 32 bytes");
    (private, public)
}

/// Per-connection read timeout: a hung/slow client (slowloris) becomes a clean
/// error, not a thread pinned forever. Thread COUNT is bounded by `ConnLimiter` below.
pub(crate) const CONN_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Hard bounds on a REUSED connection (§15 / FT4). A client may stream many requests over one
/// Noise session, but never more than this many, and never for longer than the wall-clock
/// deadline — so holding a `ConnLimiter` slot open can only ever be a small constant more costly
/// than a one-shot connection, not an unbounded slowloris amplifier.
const MAX_REQUESTS_PER_CONN: u32 = 4096;
const CONN_TOTAL_DEADLINE: Duration = Duration::from_secs(120);

/// Ceiling on connection-handler threads alive at once. A flood of connections
/// otherwise spawns an unbounded number of threads (FD / memory exhaustion). This
/// is RESOURCE HYGIENE for an untrusted relay — NOT the §7 admission gate (cookie/
/// capability), which is a separate layer. Generous: it stops exhaustion, not a
/// handful of legitimate concurrent clients.
pub(crate) const MAX_CONNECTIONS: usize = 1024;

/// How many requests a connection may make WITHOUT ever having one admitted, before it is
/// dropped (R2-13).
///
/// Admission is applied per REQUEST, after the Noise handshake — it cannot be applied earlier,
/// because the credential travels inside the encrypted channel. So a peer that never intends to
/// authenticate still costs a connection slot and a handshake, and could then sit in the request
/// loop until `CONN_TOTAL_DEADLINE` (two minutes) issuing rejects. With `MAX_CONNECTIONS` slots
/// that is a cheap way to hold the whole pool against everyone else.
///
/// This does not make admission happen sooner; nothing can. It makes an UNADMITTED connection
/// cheap to hold and expensive to keep. Eight is generous for the legitimate shape — the cookie
/// challenge costs one round trip, and a client that just had its cookie epoch rotate may spend
/// another — while a peer with no credential runs out almost immediately.
pub const MAX_UNADMITTED_REQUESTS: usize = 8;

/// Can this request class prove the sender was admitted?
///
/// True only for the classes that actually run the cookie/capability/quota gate. The public
/// reads (bundle lookup without a one-time prekey, node list, policy, blob stat, discovery
/// resolution) answer from state the relay publishes to anyone, so serving one says nothing
/// about the peer and must not extend its leash.
fn requires_admission(req: &WireRequest) -> bool {
    matches!(
        req,
        WireRequest::Send(_)
            | WireRequest::Fetch(_)
            | WireRequest::Ack(_)
            | WireRequest::PublishBundle(_)
            | WireRequest::FetchBundleOpk(_)
            | WireRequest::BlobPut(_)
            | WireRequest::BlobGet(_)
            | WireRequest::Join(_)
    )
}

/// Is this response the relay turning the peer away rather than serving it?
fn is_refusal(resp: &WireResponse) -> bool {
    matches!(
        resp,
        WireResponse::NeedCookie(_)
            | WireResponse::Rejected(_)
            | WireResponse::PowRequired { .. }
            | WireResponse::Blob(BlobResponse::NeedCookie(_) | BlobResponse::Rejected(_))
    )
}


/// Bounds live connection handlers. `try_acquire` reserves a slot iff under the cap;
/// the returned `Permit` releases it on `Drop`, so a handler that errors OR PANICS
/// on the Noise handshake (the common hostile case) still frees its slot — no manual
/// decrement to leak.
pub struct ConnLimiter {
    live: Arc<std::sync::atomic::AtomicUsize>,
    max: usize,
}

/// RAII slot reservation from [`ConnLimiter`]; releases on drop.
pub struct Permit(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl ConnLimiter {
    pub fn new(max: usize) -> Self {
        ConnLimiter { live: Arc::new(std::sync::atomic::AtomicUsize::new(0)), max }
    }

    /// Reserve a slot if fewer than `max` are live; `None` at capacity (the caller
    /// drops the connection, DropNoReply-style). CAS loop so the check-and-increment
    /// is atomic under concurrent accepts.
    pub fn try_acquire(&self) -> Option<Permit> {
        use std::sync::atomic::Ordering::SeqCst;
        let mut cur = self.live.load(SeqCst);
        loop {
            if cur >= self.max {
                return None;
            }
            match self.live.compare_exchange_weak(cur, cur + 1, SeqCst, SeqCst) {
                Ok(_) => return Some(Permit(self.live.clone())),
                Err(actual) => cur = actual,
            }
        }
    }

    #[cfg(test)]
    fn live(&self) -> usize {
        self.live.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// TCP-сервер. `RelayNode` под `Mutex` (admission сериализуется). Держит СВОЙ
/// Noise-static (транспортный ключ, отдельный от fetch-auth relay_identity —
/// переиспользование Noise-static вне Noise ломает его анализ безопасности).
pub struct RelayServer {
    /// `RwLock`, not `Mutex` (#142): the read-only handlers — bundle lookup, node list, policy,
    /// blob stat — are pure reads of relay state, and a bundle lookup happens on every first
    /// contact. Under one mutex they queued behind each other and behind every send. Writers
    /// (admission, publish, discovery mutations) still exclude everything, which is correct:
    /// they mutate the replay filter, quota windows and the epoch.
    relay: Arc<RwLock<RelayNode>>,
    clock: Clock,
    noise_private: [u8; 32],
    noise_public: [u8; 32],
    /// Connections that were accepted AND given a handler thread — i.e. one per Noise handshake.
    ///
    /// Exists to make a claim measurable: the client pools sessions (PERF-8), and "pooling saves
    /// handshakes" is only worth asserting if something counts them. A number the client cannot
    /// see, so it proves the property from the relay's side rather than from the client's intent.
    accepted: Arc<std::sync::atomic::AtomicU64>,
    /// Optional WebSocket-over-TLS carrier (§15): when set, each connection is TLS+WS
    /// terminated (`wss`) BEFORE the Noise handshake, so the relay presents a
    /// standards-compliant HTTPS/WSS endpoint. `None` = raw TCP + Noise (the default skeleton path).
    tls: Option<Arc<rustls::ServerConfig>>,
}

impl RelayServer {
    pub fn new(relay: RelayNode, clock: Clock) -> Self {
        let (noise_private, noise_public) = generate_noise_keypair();
        Self::with_noise_keypair(relay, clock, noise_private, noise_public)
    }

    /// Как `new`, но с ЗАДАННОЙ Noise-static-парой — для персистентности ключа
    /// relay (стабильный Noise-pub в relay-id между перезапусками). Персистится
    /// пара (priv+pub) целиком, чтобы не полагаться на совпадение деривации pub
    /// из priv у разных реализаций 25519.
    pub fn with_noise_keypair(
        relay: RelayNode,
        clock: Clock,
        noise_private: [u8; 32],
        noise_public: [u8; 32],
    ) -> Self {
        RelayServer {
            accepted: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            relay: Arc::new(RwLock::new(relay)),
            clock,
            noise_private,
            noise_public,
            tls: None,
        }
    }

    /// Enable the WebSocket-over-TLS carrier: every accepted connection is TLS+WS
    /// terminated before Noise. `config` carries the relay's cert/key. Off by default.
    pub fn with_tls(mut self, config: Arc<rustls::ServerConfig>) -> Self {
        self.tls = Some(config);
        self
    }

    /// Публичный Noise-ключ узла — клиент узнаёт его вне канала (аутентифицирует
    /// relay при handshake). Бинарь печатает его.
    pub fn noise_public(&self) -> [u8; 32] {
        self.noise_public
    }

    /// A handle to the shared relay state, so a test can inspect it after handing the
    /// server to a serving thread (e.g. assert a mailbox drained after a wire ACK). The
    /// serving thread holds its own clone of the same `Arc`.
    pub fn relay_handle(&self) -> Arc<RwLock<RelayNode>> {
        Arc::clone(&self.relay)
    }

    /// Bind и обслуживать вечно (для бинаря).
    pub fn serve<A: ToSocketAddrs>(self, addr: A) -> io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        self.serve_listener(listener)
    }

    /// Serve an already-bound listener. Handler threads are capped by `ConnLimiter`
    /// (`MAX_CONNECTIONS`): at capacity a new connection is dropped without a reply
    /// (DropNoReply), so a flood can't spawn unbounded threads.
    /// Build a server over relay state something else already holds.
    ///
    /// `with_noise_keypair` takes the node by value, which is right for the binary — it builds the
    /// node, hands it over, and asks for the shared handle back. A caller that already has the
    /// handle (a QUIC listener constructed first, say) would otherwise have no way to put a TCP
    /// listener on the same state without inventing a second node, which is the failure
    /// `shared_node` exists to prevent.
    pub fn from_shared(
        relay: Arc<RwLock<RelayNode>>,
        clock: Clock,
        noise_private: [u8; 32],
        noise_public: [u8; 32],
    ) -> Self {
        RelayServer {
            relay,
            clock,
            noise_private,
            noise_public,
            tls: None,
            accepted: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// The relay state this server serves, so a SECOND listener can serve the same one.
    ///
    /// Load-bearing rather than convenient: a relay that runs both a TCP and a QUIC listener must
    /// have them share ONE `RelayNode`. Two nodes would mean two mailbox sets — a message
    /// deposited over QUIC would be invisible to a fetch over TCP, and the failure would look like
    /// lost mail rather than like a wiring mistake.
    pub fn shared_node(&self) -> Arc<RwLock<RelayNode>> {
        self.relay.clone()
    }

    /// A handle on the accepted-connection counter — take it BEFORE `serve_listener`, which
    /// consumes `self`.
    #[doc(hidden)]
    pub fn accepted_counter(&self) -> Arc<std::sync::atomic::AtomicU64> {
        self.accepted.clone()
    }

    pub fn serve_listener(self, listener: TcpListener) -> io::Result<()> {
        let limiter = ConnLimiter::new(MAX_CONNECTIONS);
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            // At capacity: drop the connection. The FD closes with `stream`.
            let Some(permit) = limiter.try_acquire() else { continue };
            // Counted here rather than at accept: a connection refused for capacity never reaches
            // a handshake, so counting it would overstate what the client actually paid for.
            self.accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let relay = self.relay.clone();
            let clock = self.clock.clone();
            let noise_priv = self.noise_private;
            let tls = self.tls.clone();
            thread::spawn(move || {
                // The permit rides the thread and releases on exit — including a
                // panic unwind, so a hostile handshake can't leak the slot.
                let _permit = permit;
                // A failed handshake/frame just closes the connection (DropNoReply).
                let _ = handle_conn(stream, relay, clock, noise_priv, tls);
            });
        }
        Ok(())
    }
}

fn handle_conn(
    stream: TcpStream,
    relay: Arc<RwLock<RelayNode>>,
    clock: Clock,
    noise_priv: [u8; 32],
    tls: Option<Arc<rustls::ServerConfig>>,
) -> io::Result<()> {
    stream.set_read_timeout(Some(CONN_READ_TIMEOUT)).ok();
    // If the wss carrier is on, terminate TLS + WebSocket first, then run Noise over
    // the inner byte stream. Either way the Noise handshake comes BEFORE any
    // plaintext processing; a failure closes the connection.
    let channel: Box<dyn Channel> = match tls {
        Some(config) => karst_transport::wss::accept_wss(stream, config)?,
        None => Box::new(stream),
    };
    // A TCP connection carries one Noise session, so its unadmitted count is its own.
    serve_channel(channel, relay, clock, noise_priv, &AtomicUsize::new(0))
}

/// Run one Noise session over an already-established byte channel.
///
/// Split out of `handle_conn` so a QUIC STREAM can be served by the identical code (QUIC-3). There
/// must not be a second implementation of the request loop: the leash, the per-class frame
/// ceilings and the deadlines are security properties, and a carrier that reimplemented them would
/// be a carrier where they drift.
///
/// `unadmitted` is shared across everything that belongs to ONE transport connection. On TCP that
/// is this channel alone. On QUIC it is every stream of the connection together — which is the
/// point: `MAX_UNADMITTED_REQUESTS` bounds what a stranger can cost while holding a slot, and a
/// per-STREAM count would let one connection open a thousand streams and pay the leash once each
/// (R2-13, closed on TCP and wide open on QUIC without this).
pub(crate) fn serve_channel(
    channel: Box<dyn Channel>,
    relay: Arc<RwLock<RelayNode>>,
    clock: Clock,
    noise_priv: [u8; 32],
    unadmitted: &AtomicUsize,
) -> io::Result<()> {
    let mut session = Session::accept(channel, &noise_priv)?;

    // ONE Noise session, MANY requests (§15 / FT4): after the handshake the client may send a
    // run of requests over the SAME connection — a file upload streams its chunks without paying
    // a fresh TCP + Noise handshake each. The loop is HARD-BOUNDED so a reused connection can
    // never become a cheaper DoS than a one-shot: at most `MAX_REQUESTS_PER_CONN` requests AND at
    // most `CONN_TOTAL_DEADLINE` of wall-clock, each read still under `CONN_READ_TIMEOUT`, all
    // while holding a single `ConnLimiter` slot. A one-shot client is unchanged: it sends one
    // request, reads one response, closes — the next read hits EOF and the loop ends.
    let started = std::time::Instant::now();
    // Has this connection ever had a request ADMITTED? Until it has, it is a stranger holding a
    // slot, and is held to a much shorter leash (R2-13).
    let mut admitted = false;
    for _ in 0..MAX_REQUESTS_PER_CONN {
        if started.elapsed() > CONN_TOTAL_DEADLINE {
            break;
        }
        if !admitted && unadmitted.load(Ordering::Relaxed) >= MAX_UNADMITTED_REQUESTS {
            break;
        }
        // Read with the blob ceiling: it covers both the tight normal requests and a
        // ~60 KiB `BlobPut` chunk (the variant isn't known until decoded). Still a bounded,
        // post-Noise-handshake allocation. A read error/EOF ends the connection cleanly (the
        // normal way a client — one-shot or reusing — signals it is done).
        let req_bytes = match session.read_msg(MAX_BLOB_FRAME) {
            Ok(b) => b,
            Err(_) => break,
        };
        let req: WireRequest = decode(&req_bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decode"))?;

        // §210: `MAX_REQUEST_FRAME` used to be dead on this path — every request was read
        // with the wide blob ceiling above and NOTHING checked the decoded frame against a
        // tighter per-class limit, so a `Send`/`Fetch`/`Join`/... padded up to ~65 KB was
        // decoded and DISPATCHED exactly like a legitimate one. The class can't be known
        // before decode (the outer length is only a padding bucket, chosen by the sender),
        // so the tight bound has to be enforced HERE — before the request reaches any
        // handler — rather than at read time. Not widened to fit everything: `Ack` and
        // `PublishBundle` genuinely need more than the tight default (see
        // `wire::max_frame_for`), so they get their own, still-well-below-blob ceilings.
        let class_max = node::wire::max_frame_for(&req);
        if req_bytes.len() > class_max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame too large for request class: {} > {class_max}", req_bytes.len()),
            ));
        }

        if !admitted {
            unadmitted.fetch_add(1, Ordering::Relaxed);
        }
        // Whether THIS class can prove admission has to be read before `req` is consumed below.
        let credentialed = requires_admission(&req);
        let resp = match req {
        WireRequest::Send(msg) => {
            let now = (clock)(); // время СЕРВЕРА
            // #142, same shape as the blob path: ADMISSION under the relay lock, the mail work
            // after it is released. Admission is in-memory arithmetic; a deposit touches a queue
            // and, on a durable relay, an fsync. Under one mutex every client's admission queued
            // behind someone else's write barrier. The `admitted` binding is what forces the
            // guard to drop before the deposit runs — inlining it would hold the lock across it.
            let admitted = relay.write().expect("relay lock").admit_send(&msg, now);
            match admitted {
                Ok(a) => match a.deposit(&msg.payload, now) {
                    Response::NeedCookie(c) => WireResponse::NeedCookie(c),
                    Response::Accepted => WireResponse::Accepted,
                    Response::Rejected(s) => WireResponse::Rejected(s),
                },
                Err(Response::NeedCookie(c)) => WireResponse::NeedCookie(c),
                Err(Response::Rejected(s)) => WireResponse::Rejected(s),
                Err(Response::Accepted) => WireResponse::Accepted,
            }
        }
        WireRequest::Fetch(freq) => {
            let now = (clock)();
            let admitted = relay.write().expect("relay lock").admit_fetch(&freq, now);
            match admitted {
                // Serialize the drained seals into a constant-size page: the
                // response length no longer reveals how much mail was queued.
                Ok(a) => WireResponse::Fetched(node::wire::FetchPage::pack(&a.serve(now))),
                Err(FetchResponse::NeedCookie(c)) => WireResponse::NeedCookie(c),
                Err(FetchResponse::Rejected(s)) => WireResponse::Rejected(s),
                Err(FetchResponse::Fetched(seals)) => {
                    WireResponse::Fetched(node::wire::FetchPage::pack(&seals))
                }
            }
        }
        WireRequest::Ack(areq) => {
            let now = (clock)();
            let admitted = relay.write().expect("relay lock").admit_ack(&areq, now);
            match admitted {
                Ok(a) => {
                    a.apply();
                    WireResponse::Acked
                }
                Err(AckResponse::NeedCookie(c)) => WireResponse::NeedCookie(c),
                Err(AckResponse::Rejected(s)) => WireResponse::Rejected(s),
                Err(AckResponse::Acked) => WireResponse::Acked,
            }
        }
        WireRequest::PublishBundle(preq) => {
            let now = (clock)();
            match relay.write().expect("relay lock").handle_publish(&preq, now) {
                PublishResponse::NeedCookie(c) => WireResponse::NeedCookie(c),
                PublishResponse::Published => WireResponse::BundlePublished,
                PublishResponse::Rejected(s) => WireResponse::Rejected(s),
            }
        }
        WireRequest::FetchBundle(ik) => {
            // Публичный read; время серверу не нужно — этот путь НИКОГДА не выдаёт one-time
            // prekey, поэтому у него нет разрушающего побочного эффекта (R2-3).
            let bundle = relay.read().expect("relay lock").get_bundle(&ik);
            WireResponse::Bundle(bundle)
        }
        WireRequest::FetchBundleOpk(req) => {
            // Consumes a one-time prekey → full admission, so it needs the real clock (cookie
            // freshness, capability validity window, quota epoch) exactly like a send.
            let now = (clock)();
            match relay.write().expect("relay lock").handle_fetch_bundle_opk(&req, now) {
                BundleOpkResponse::NeedCookie(c) => WireResponse::NeedCookie(c),
                BundleOpkResponse::Bundle(b) => WireResponse::Bundle(b),
                BundleOpkResponse::Rejected(e) => WireResponse::Rejected(e),
            }
        }
        WireRequest::BlobPut(breq) => {
            let now = (clock)();
            // #142: admission under the relay lock, the FILE WRITE after it is released. A blob
            // chunk is tens of KiB of disk I/O; mail delivery, fetch and ACK are small in-memory
            // operations. Doing both under one mutex meant one slow chunk stalled every other
            // client's mail on the whole relay. The `admitted` binding is what forces the guard
            // to drop before `put` runs — inlining it would extend the borrow across the write.
            let admitted = relay.write().expect("relay lock").admit_blob_put(&breq, now);
            WireResponse::Blob(match admitted {
                Ok(a) => a.put(&breq, now),
                Err(refusal) => refusal,
            })
        }
        WireRequest::BlobGet(breq) => {
            let now = (clock)();
            let admitted = relay.write().expect("relay lock").admit_blob_get(&breq, now);
            WireResponse::Blob(match admitted {
                Ok(store) => crate::node::blob_get_chunk(&store, &breq),
                Err(refusal) => refusal,
            })
        }
        WireRequest::JoinChallenge => {
            let now = (clock)();
            let guard = relay.read().expect("relay lock");
            match guard.pow_policy(now) {
                Some((bucket, difficulty_bits)) => WireResponse::PowRequired {
                    bucket,
                    difficulty_bits,
                    relay_id: *guard.relay_public().as_bytes(),
                },
                None => WireResponse::Rejected("issuance disabled (this relay is not public)".into()),
            }
        }
        WireRequest::Join(jreq) => {
            let now = (clock)();
            match relay.write().expect("relay lock").handle_join(&jreq, now) {
                Ok(cap) => WireResponse::Issued(cap),
                Err(s) => WireResponse::Rejected(s),
            }
        }
        WireRequest::GetNodeList => {
            // Public read of the discovery plane; no time needed.
            WireResponse::NodeList(relay.read().expect("relay lock").node_list())
        }
        WireRequest::GetPolicy => {
            WireResponse::Policy(relay.read().expect("relay lock").policy())
        }
        WireRequest::BlobStat(req) => {
            // Admitted like every other blob request now (PRIV-7): a stat used to be the one blob
            // endpoint with no address, no cookie and no admission — the serve loop's own note
            // below observed a stranger could buy the full connection deadline with it.
            //
            // The BLOB lock is still taken outside the relay lock (#142): a stat stuck behind a
            // chunk write must not also be holding up everyone's mail.
            let now = (clock)();
            match relay.write().expect("relay lock").admit_blob_stat(&req, now) {
                Ok(store) => WireResponse::BlobStat(node::wire::BlobStatOutcome::Stat(
                    store.lock().expect("blob store mutex").stat(&req.blob_id),
                )),
                Err(BlobResponse::NeedCookie(c)) => {
                    WireResponse::BlobStat(node::wire::BlobStatOutcome::NeedCookie(c))
                }
                Err(BlobResponse::Rejected(s)) => WireResponse::Rejected(s),
                Err(_) => WireResponse::Rejected("blob stat refused".into()),
            }
        }
        WireRequest::PublishDiscovery { record, write_sig } => {
            let now = (clock)();
            let ok = relay.write().expect("relay lock").handle_publish_discovery(&record, &write_sig, now);
            WireResponse::DiscoveryAck(ok)
        }
        WireRequest::DeleteDiscovery { discovery_pub, delete_sig } => {
            let ok = relay.write().expect("relay lock").handle_delete_discovery(&discovery_pub, &delete_sig);
            WireResponse::DiscoveryAck(ok)
        }
        WireRequest::LookupDiscovery(pseudonym) => {
            let now = (clock)();
            WireResponse::Discovery(relay.write().expect("relay lock").handle_lookup_discovery(&pseudonym, now))
        }
    };

        // R2-13: did this request PROVE admission? Only a credentialed class that came back
        // with something other than a refusal does. The rule is an allowlist on purpose — the
        // obvious denylist ("anything that isn't NeedCookie/Rejected counts") would let a
        // stranger buy the full deadline with one `BlobStat`, since the public reads answer
        // without ever looking at a credential.
        //
        // Once earned, admission is not revoked by a later reject: a legitimate client that
        // trips a quota mid-upload should get its error responses, not a severed connection.
        if credentialed && !is_refusal(&resp) {
            admitted = true;
        }

        // A blob chunk download needs the large frame; every other response is small and
        // must stay on the tight ceiling (the fetch page's fixed 16 KiB size class).
        let resp_max = match &resp {
            WireResponse::Blob(BlobResponse::Chunk(Some(_))) => MAX_BLOB_FRAME,
            _ => MAX_RESPONSE_FRAME,
        };
        let resp_bytes = encode(&resp).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encode"))?;
        session.write_msg(&resp_bytes, resp_max)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_limiter_caps_and_releases_via_raii() {
        // Deterministic (no sockets): the cap holds, a released slot is reusable, and
        // dropping every permit returns the live count to zero. Neuter `try_acquire`
        // to ignore `max` (always Some) and the capacity assertions go red.
        let l = ConnLimiter::new(2);
        let a = l.try_acquire().expect("slot 1");
        let _b = l.try_acquire().expect("slot 2");
        assert!(l.try_acquire().is_none(), "at capacity → None");
        assert_eq!(l.live(), 2);
        drop(a);
        let c = l.try_acquire().expect("freed slot reusable");
        assert!(l.try_acquire().is_none(), "full again");
        drop(_b);
        drop(c);
        assert_eq!(l.live(), 0, "RAII released every slot");
    }
}
