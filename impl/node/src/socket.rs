//! TCP-сервер вокруг `RelayNode` + клиентский `SocketTransport`, **поверх
//! Noise-сессии (§15)**.
//!
//! **СКЕЛЕТ.** Блокирующий, поток-на-соединение, std-only. Каждое соединение
//! сначала проходит Noise_NK-handshake (`session`), потом обменивается ОДНИМ
//! запрос-ответом внутри зашифрованного сеанса.
//!
//! **Обязательный туннель — без тихого fallback на plaintext.** Провалившийся/
//! отсутствующий handshake = жёсткая ошибка, соединение закрывается; активный
//! противник не может «раздеть» сессию до старого открытого протокола. Открытый
//! путь остался только у `InMemoryTransport` (тесты).
//!
//! **Сервер ставит СВОЁ время** (см. `node`): `now` не едет по проводу.

use std::io;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use admission::capability::Capability;
use rand::rngs::OsRng;
use rand::RngCore;
use snow::Builder;

use crate::discovery::DiscoveryRecord;
use crate::node::{
    AckRequest, AckResponse, BlobGetRequest, BlobPutRequest, BlobResponse, BundleOpkRequest,
    BundleOpkResponse, FetchRequest, FetchResponse, JoinRequest, PublishRequest, PublishResponse,
    RelayDescriptor, RelayNode, RelayPolicy, Response, Transport, WireMessage,
};
use crate::pqxdh::PreKeyBundle;
use crate::session::{Session, NOISE_PARAMS};
use crate::transport::{Channel, Dest, DirectTcpAdapter, Path, TransportAdapter};
use crate::wire::{
    decode, encode, WireRequest, WireResponse, MAX_BLOB_FRAME, MAX_REQUEST_FRAME, MAX_RESPONSE_FRAME,
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
const CONN_READ_TIMEOUT: Duration = Duration::from_secs(30);

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
const MAX_CONNECTIONS: usize = 1024;

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

/// SEC-41 (#226): ceiling on the PoW difficulty a relay's `PowRequired` challenge may
/// declare before `join()` refuses to solve it. `admission::pow::solve` is a plain loop
/// over `WireResponse::PowRequired.difficulty_bits` — nothing bounded what the RELAY could
/// put in that field, so a hostile or misconfigured relay could declare an arbitrary
/// difficulty and the client would burn unbounded CPU trying to earn a capability, while
/// the relay itself spends nothing to issue the challenge. Expected work at `bits` is
/// `2^bits` hashes (hashcash: average trials to first success at success-probability
/// `2^-bits`). Measured on this dev machine (release build, single core, `sha2` crate):
/// ~8.2M hashes/sec, so `admission::params::DEFAULT_POW_BITS` (20 bits, ~1M hashes) solves
/// in well under a second, matching that constant's own doc comment. This ceiling (26 bits,
/// ~67M hashes) is 64x the default — on this machine that's ~8s on average; on a device an
/// order of magnitude slower (~800K h/s, e.g. aging or low-power hardware) it is still only
/// ~85s on average. That is real headroom for an operator to dial difficulty up under load,
/// while capping what "a relay declares its number" can cost a client. (Hashcash solve time
/// is exponentially distributed, so this bounds the AVERAGE case, not a hard worst case —
/// same caveat the rest of `pow.rs` states plainly for the mechanism as a whole.)
const MAX_ACCEPTED_POW_BITS: u32 = 26;

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
    pub fn serve_listener(self, listener: TcpListener) -> io::Result<()> {
        let limiter = ConnLimiter::new(MAX_CONNECTIONS);
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            // At capacity: drop the connection. The FD closes with `stream`.
            let Some(permit) = limiter.try_acquire() else { continue };
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
        Some(config) => crate::wss::accept_wss(stream, config)?,
        None => Box::new(stream),
    };
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
    let mut unadmitted_requests = 0usize;
    for _ in 0..MAX_REQUESTS_PER_CONN {
        if started.elapsed() > CONN_TOTAL_DEADLINE {
            break;
        }
        if !admitted && unadmitted_requests >= MAX_UNADMITTED_REQUESTS {
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
        let class_max = crate::wire::max_frame_for(&req);
        if req_bytes.len() > class_max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame too large for request class: {} > {class_max}", req_bytes.len()),
            ));
        }

        if !admitted {
            unadmitted_requests += 1;
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
                Ok(a) => WireResponse::Fetched(crate::wire::FetchPage::pack(&a.serve(now))),
                Err(FetchResponse::NeedCookie(c)) => WireResponse::NeedCookie(c),
                Err(FetchResponse::Rejected(s)) => WireResponse::Rejected(s),
                Err(FetchResponse::Fetched(seals)) => {
                    WireResponse::Fetched(crate::wire::FetchPage::pack(&seals))
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
        WireRequest::BlobStat(blob_id) => {
            // Public read, and it takes the BLOB lock — so it is taken outside the relay lock
            // too (#142): a stat stuck behind a chunk write must not also be holding up mail.
            let store = relay.read().expect("relay lock").blob_store();
            WireResponse::BlobStat(
                store.and_then(|s| s.lock().expect("blob store mutex").stat(&blob_id)),
            )
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

/// Клиентский транспорт поверх Noise-сессии. Один запрос = одно соединение +
/// один handshake (скелет). Держит Noise-pubkey relay (аутентификация при
/// handshake) и адаптер транспорта (§15): direct-TCP или SOCKS5-к-внешнему-PT.
#[derive(Clone)]
pub struct SocketTransport {
    /// Routes to the relay in priority order (§15 Path Manager). More than one = the
    /// request fails over across them; see `round_trip_sized` for the retry boundary.
    paths: Vec<Path>,
    relay_noise_pub: [u8; 32],
}

impl SocketTransport {
    /// Прямой TCP (без обфускации транспорта).
    pub fn new(addr: impl Into<Dest>, relay_noise_pub: [u8; 32]) -> Self {
        Self::with_adapter(addr.into(), relay_noise_pub, Arc::new(DirectTcpAdapter::default()))
    }

    /// Через заданный адаптер (напр. `Socks5Adapter` на локальный PT-порт).
    pub fn with_adapter(
        addr: impl Into<Dest>,
        relay_noise_pub: [u8; 32],
        adapter: Arc<dyn TransportAdapter>,
    ) -> Self {
        Self::with_paths(vec![Path::new(adapter, addr)], relay_noise_pub)
    }

    /// Over an ordered list of routes to the SAME relay identity (`relay_noise_pub`
    /// authenticates it regardless of which path carried the bytes). Each request tries
    /// them in order — see `round_trip_sized` for what may and may not be retried.
    pub fn with_paths(paths: Vec<Path>, relay_noise_pub: [u8; 32]) -> Self {
        SocketTransport { paths, relay_noise_pub }
    }

    fn round_trip(&self, req: &WireRequest) -> io::Result<WireResponse> {
        self.round_trip_sized(req, MAX_REQUEST_FRAME, MAX_RESPONSE_FRAME)
    }

    /// `round_trip` on its own isolation scope — requests with different scopes are not
    /// carried on the same circuit (see `TransportAdapter::connect_isolated`).
    fn round_trip_scoped(&self, req: &WireRequest, scope: Option<&str>) -> io::Result<WireResponse> {
        self.round_trip_scoped_sized(req, MAX_REQUEST_FRAME, MAX_RESPONSE_FRAME, scope)
    }

    /// Like `round_trip` but with explicit frame ceilings — blobs need the large one on
    /// the side that carries the chunk (request for `BlobPut`, response for `BlobGet`).
    ///
    /// **§15 failover, and its deliberate boundary.** Paths are tried in order, and a
    /// path is abandoned for the next one when its TCP connect OR its Noise handshake
    /// fails. That covers an adversary who blackholes the IP (connect times out) AND one
    /// that lets the SYN through and then interferes with the handshake — the case
    /// connect-level failover could not see.
    ///
    /// **Nothing is retried once the request has been written.** Past that line the
    /// relay may already have applied the request (a deposit is not idempotent), so
    /// retrying it on another path could duplicate it. A failure there is returned as
    /// an error — an honest failure beats a silent double-send. Connect/handshake
    /// failures are safe precisely because no request byte has left yet.
    fn round_trip_sized(
        &self,
        req: &WireRequest,
        req_max: usize,
        resp_max: usize,
    ) -> io::Result<WireResponse> {
        self.round_trip_scoped_sized(req, req_max, resp_max, None)
    }

    fn round_trip_scoped_sized(
        &self,
        req: &WireRequest,
        req_max: usize,
        resp_max: usize,
        scope: Option<&str>,
    ) -> io::Result<WireResponse> {
        let req_bytes = encode(req).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encode"))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Health order: paths out of cooldown first (in priority order), the cooling
        // ones after — so a blackholed primary stops costing a CONNECT_TIMEOUT on every
        // request, while a total outage can still recover (nothing is ever excluded).
        let (fresh, cooling): (Vec<&Path>, Vec<&Path>) =
            self.paths.iter().partition(|p| p.health.usable(now));
        let mut last_err: Option<io::Error> = None;
        for path in fresh.into_iter().chain(cooling) {
            // Pre-request phase: connect through the carrier, then Noise on top. A
            // failure of either means nothing was delivered → the next path is safe.
            let session = path
                .adapter
                .connect_isolated(&path.dest, scope)
                .and_then(|channel| Session::connect(channel, &self.relay_noise_pub));
            let mut session = match session {
                Ok(s) => s,
                Err(e) => {
                    path.health.record_failure(now);
                    last_err = Some(e);
                    continue;
                }
            };
            path.health.record_success();
            // Committed to this path: the request goes out now, no failover past here.
            session.write_msg(&req_bytes, req_max)?;
            let resp_bytes = session.read_msg(resp_max)?;
            return decode(&resp_bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decode"));
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "transport: no paths configured")
        }))
    }

    /// §7 slice 4a — earn a capability from a PUBLIC relay by solving its PoW. Two round
    /// trips on the Noise session: fetch the challenge (bucket + difficulty + relay_id), then
    /// redeem a freshly-mined solution. The capability (secret included) comes back inside the
    /// encrypted session. Store it 0600 and use it for sends. A relay that is not Public
    /// answers the challenge with a rejection (`PermissionDenied`).
    pub fn join(&self) -> io::Result<Capability> {
        let (bucket, difficulty_bits, relay_id) = match self.round_trip(&WireRequest::JoinChallenge)? {
            WireResponse::PowRequired { bucket, difficulty_bits, relay_id } => {
                (bucket, difficulty_bits, relay_id)
            }
            WireResponse::Rejected(s) => {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, s))
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "protocol: unexpected on JoinChallenge")),
        };
        // SEC-41 (#226): refuse a relay-declared difficulty above the ceiling OUTRIGHT — never
        // silently solve it (that's the unbounded-CPU theft this exists to stop) and never
        // silently skip the door (that would hand back no capability with no explanation). The
        // relay is named in the error so the caller can tell which relay to stop trusting.
        if difficulty_bits > MAX_ACCEPTED_POW_BITS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "relay {} declared PoW difficulty {difficulty_bits} bits, above the accepted ceiling of {MAX_ACCEPTED_POW_BITS} bits — refusing to solve",
                    hex::encode(relay_id)
                ),
            ));
        }
        let mut client_seed = [0u8; 32];
        OsRng.fill_bytes(&mut client_seed);
        let nonce = admission::pow::solve(&relay_id, bucket, &client_seed, difficulty_bits)
            .ok_or_else(|| io::Error::other("pow: nonce space exhausted"))?;
        match self.round_trip(&WireRequest::Join(JoinRequest { bucket, client_seed, nonce }))? {
            WireResponse::Issued(cap) => Ok(cap),
            WireResponse::Rejected(s) => Err(io::Error::new(io::ErrorKind::PermissionDenied, s)),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "protocol: unexpected on Join")),
        }
    }

    /// §12 discovery plane — ask this relay which relays it knows about (node-list). The
    /// operator-curated set (self + configured peers); a client uses it to learn of more
    /// relays than it was handed. Each descriptor self-authenticates on dial (its `noise_pub`
    /// is checked in the Noise handshake), so a wrong-key entry fails closed when used.
    pub fn get_node_list(&self) -> io::Result<Vec<RelayDescriptor>> {
        match self.round_trip(&WireRequest::GetNodeList)? {
            WireResponse::NodeList(v) => Ok(v),
            WireResponse::Rejected(s) => Err(io::Error::other(s)),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "protocol: unexpected on GetNodeList")),
        }
    }

    /// Fetch this relay's advertised policy (operator-declared — see `RelayPolicy`).
    pub fn get_policy(&self) -> io::Result<RelayPolicy> {
        match self.round_trip(&WireRequest::GetPolicy)? {
            WireResponse::Policy(p) => Ok(p),
            WireResponse::Rejected(s) => Err(io::Error::other(s)),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "protocol: unexpected on GetPolicy")),
        }
    }

    /// §12 4c — publish (or rotate) an opt-in discovery record. Returns whether the relay applied
    /// it (`false` = a failed signature check or a full directory).
    pub fn publish_discovery(&self, record: &DiscoveryRecord, write_sig: &[u8]) -> io::Result<bool> {
        match self.round_trip(&WireRequest::PublishDiscovery { record: record.clone(), write_sig: write_sig.to_vec() })? {
            WireResponse::DiscoveryAck(ok) => Ok(ok),
            WireResponse::Rejected(s) => Err(io::Error::other(s)),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "protocol: unexpected on PublishDiscovery")),
        }
    }

    /// §12 4c — delete a discovery record (turn discovery off at this relay).
    pub fn delete_discovery(&self, discovery_pub: [u8; 32], delete_sig: &[u8]) -> io::Result<bool> {
        match self.round_trip(&WireRequest::DeleteDiscovery { discovery_pub, delete_sig: delete_sig.to_vec() })? {
            WireResponse::DiscoveryAck(ok) => Ok(ok),
            WireResponse::Rejected(s) => Err(io::Error::other(s)),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "protocol: unexpected on DeleteDiscovery")),
        }
    }

    /// §12 4c — resolve a discovery `pseudonym` (hash of a contact code) to its record, or `None`
    /// if not published here / expired. The caller must re-verify the IK binding before trusting.
    pub fn lookup_discovery(&self, pseudonym: [u8; 32]) -> io::Result<Option<DiscoveryRecord>> {
        match self.round_trip(&WireRequest::LookupDiscovery(pseudonym))? {
            WireResponse::Discovery(rec) => Ok(rec),
            WireResponse::Rejected(s) => Err(io::Error::other(s)),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "protocol: unexpected on LookupDiscovery")),
        }
    }

    /// §15: upload one ciphertext chunk (large request frame, small response).
    pub fn blob_put(&self, req: &BlobPutRequest) -> BlobResponse {
        match self.round_trip_sized(&WireRequest::BlobPut(req.clone()), MAX_BLOB_FRAME, MAX_RESPONSE_FRAME) {
            Ok(WireResponse::Blob(b)) => b,
            Ok(_) => BlobResponse::Rejected("protocol: unexpected on BlobPut".into()),
            Err(e) => BlobResponse::Rejected(format!("transport: {e}")),
        }
    }

    /// §15: a blob's upload progress `(next, count, complete)` — the watermark a resumable upload
    /// continues from. `None` = the relay has no such blob yet (start at 0). Public read, no cookie.
    pub fn blob_stat(&self, blob_id: [u8; 32]) -> io::Result<Option<(u32, u32, bool)>> {
        match self.round_trip(&WireRequest::BlobStat(blob_id))? {
            WireResponse::BlobStat(s) => Ok(s),
            WireResponse::Rejected(s) => Err(io::Error::other(s)),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "protocol: unexpected on BlobStat")),
        }
    }

    /// §15: download one ciphertext chunk (small request, large response frame).
    pub fn blob_get(&self, req: &BlobGetRequest) -> BlobResponse {
        match self.round_trip_sized(&WireRequest::BlobGet(req.clone()), MAX_REQUEST_FRAME, MAX_BLOB_FRAME) {
            Ok(WireResponse::Blob(b)) => b,
            Ok(_) => BlobResponse::Rejected("protocol: unexpected on BlobGet".into()),
            Err(e) => BlobResponse::Rejected(format!("transport: {e}")),
        }
    }

    /// Open a REUSABLE session for streaming many `BlobPut`s over ONE Noise handshake (§15 / FT4).
    /// Tries paths in health order (like `round_trip`); the relay then accepts a bounded run of
    /// requests on this single connection, so a chunked upload amortizes the per-chunk TCP + Noise
    /// handshake instead of paying it every chunk. Dropping the returned session closes it.
    pub fn open_blob_session(&self) -> io::Result<BlobSession> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (fresh, cooling): (Vec<&Path>, Vec<&Path>) =
            self.paths.iter().partition(|p| p.health.usable(now));
        let mut last_err: Option<io::Error> = None;
        for path in fresh.into_iter().chain(cooling) {
            match path
                .adapter
                .connect_isolated(&path.dest, None)
                .and_then(|channel| Session::connect(channel, &self.relay_noise_pub))
            {
                Ok(session) => {
                    path.health.record_success();
                    return Ok(BlobSession { session });
                }
                Err(e) => {
                    path.health.record_failure(now);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "transport: no paths configured")))
    }
}

/// A reusable client connection for blob uploads (§15 / FT4): one Noise handshake, then many
/// `put`s over the same session. `Err` from `put` means the session is dead (the relay closed it
/// after its bounded run, or the link dropped) — the caller opens a fresh one and retries the
/// chunk, which is idempotent at the relay.
pub struct BlobSession {
    session: Session<Box<dyn Channel>>,
}

impl BlobSession {
    /// Upload one chunk over the reused session. `Ok(BlobResponse)` is the relay's answer;
    /// `Err` means the session is no longer usable.
    pub fn put(&mut self, req: &BlobPutRequest) -> io::Result<BlobResponse> {
        let req_bytes = encode(&WireRequest::BlobPut(req.clone()))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encode"))?;
        self.session.write_msg(&req_bytes, MAX_BLOB_FRAME)?;
        let resp_bytes = self.session.read_msg(MAX_RESPONSE_FRAME)?;
        match decode(&resp_bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decode"))? {
            WireResponse::Blob(b) => Ok(b),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "protocol: unexpected on BlobPut")),
        }
    }
}

impl Transport for SocketTransport {
    /// `now` — часы вызывающего, на провод НЕ уходят (сервер ставит своё).
    fn send(&self, msg: &WireMessage, now: u64) -> Response {
        self.send_isolated(msg, now, None)
    }

    fn fetch(&self, req: &FetchRequest, now: u64) -> FetchResponse {
        self.fetch_isolated(req, now, None)
    }

    fn send_isolated(&self, msg: &WireMessage, _now: u64, scope: Option<&str>) -> Response {
        match self.round_trip_scoped(&WireRequest::Send(msg.clone()), scope) {
            Ok(WireResponse::NeedCookie(c)) => Response::NeedCookie(c),
            Ok(WireResponse::Accepted) => Response::Accepted,
            Ok(WireResponse::Rejected(s)) => Response::Rejected(s),
            Ok(_) => Response::Rejected("protocol: unexpected на Send".into()),
            Err(e) => Response::Rejected(format!("transport: {e}")),
        }
    }

    fn fetch_isolated(&self, req: &FetchRequest, _now: u64, scope: Option<&str>) -> FetchResponse {
        match self.round_trip_scoped(&WireRequest::Fetch(req.clone()), scope) {
            Ok(WireResponse::NeedCookie(c)) => FetchResponse::NeedCookie(c),
            Ok(WireResponse::Fetched(page)) => match page.unpack() {
                Ok(seals) => FetchResponse::Fetched(seals),
                Err(_) => FetchResponse::Rejected("protocol: malformed fetch page".into()),
            },
            Ok(WireResponse::Rejected(s)) => FetchResponse::Rejected(s),
            Ok(WireResponse::Accepted) => FetchResponse::Rejected("protocol: Accepted на Fetch".into()),
            // Ошибку транспорта НЕ выдаём за пустой mailbox — recv их различает.
            Err(e) => FetchResponse::Rejected(format!("transport: {e}")),
            Ok(_) => FetchResponse::Rejected("protocol: unexpected на Fetch".into()),
        }
    }

    fn ack(&self, req: &AckRequest, now: u64) -> AckResponse {
        self.ack_isolated(req, now, None)
    }

    fn ack_isolated(&self, req: &AckRequest, _now: u64, scope: Option<&str>) -> AckResponse {
        match self.round_trip_scoped(&WireRequest::Ack(req.clone()), scope) {
            Ok(WireResponse::NeedCookie(c)) => AckResponse::NeedCookie(c),
            Ok(WireResponse::Acked) => AckResponse::Acked,
            Ok(WireResponse::Rejected(s)) => AckResponse::Rejected(s),
            Ok(_) => AckResponse::Rejected("protocol: unexpected на Ack".into()),
            Err(e) => AckResponse::Rejected(format!("transport: {e}")),
        }
    }

    fn publish_bundle(&self, req: &PublishRequest, _now: u64) -> PublishResponse {
        match self.round_trip(&WireRequest::PublishBundle(req.clone())) {
            Ok(WireResponse::NeedCookie(c)) => PublishResponse::NeedCookie(c),
            Ok(WireResponse::BundlePublished) => PublishResponse::Published,
            Ok(WireResponse::Rejected(s)) => PublishResponse::Rejected(s),
            Ok(_) => PublishResponse::Rejected("protocol: unexpected на Publish".into()),
            Err(e) => PublishResponse::Rejected(format!("transport: {e}")),
        }
    }

    fn fetch_bundle_opk(
        &self,
        req: &BundleOpkRequest,
        _now: u64,
    ) -> Result<BundleOpkResponse, String> {
        match self.round_trip(&WireRequest::FetchBundleOpk(req.clone())) {
            Ok(WireResponse::NeedCookie(c)) => Ok(BundleOpkResponse::NeedCookie(c)),
            Ok(WireResponse::Bundle(b)) => Ok(BundleOpkResponse::Bundle(b)),
            Ok(WireResponse::Rejected(e)) => Ok(BundleOpkResponse::Rejected(e)),
            Ok(_) => Err("protocol: unexpected на FetchBundleOpk".into()),
            Err(e) => Err(format!("transport: {e}")),
        }
    }

    fn fetch_bundle(&self, ik: &[u8; 32], _now: u64) -> Result<Option<PreKeyBundle>, String> {
        match self.round_trip(&WireRequest::FetchBundle(*ik)) {
            Ok(WireResponse::Bundle(b)) => Ok(b),
            Ok(WireResponse::Rejected(s)) => Err(s),
            Ok(_) => Err("protocol: unexpected на FetchBundle".into()),
            Err(e) => Err(format!("transport: {e}")),
        }
    }
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
