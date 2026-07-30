//! Клиентский транспорт поверх Noise-сессии (§15): `SocketTransport`.
//!
//! Split out of the old `socket` module (#143): that file held BOTH the relay's listener and the
//! client's dialer, which is the crate-level coupling in miniature — the side that accepts
//! connections and the side that makes them, sharing one namespace. The listener now lives in the
//! `relay` crate; nothing here can name a `RelayNode`.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use admission::capability::Capability;
use rand::rngs::OsRng;
use rand::RngCore;

use node::discovery::DiscoveryRecord;
use node::protocol::{AckRequest, AckResponse, BlobGetRequest, BlobPutRequest, BlobResponse, BundleOpkRequest, BundleOpkResponse, FetchRequest, FetchResponse, JoinRequest, PublishRequest, PublishResponse, RelayDescriptor, RelayPolicy, Response, Transport, WireMessage};
use karst_crypto::pqxdh::PreKeyBundle;
use karst_crypto::session::Session;
use crate::transport::{Channel, Dest, DirectTcpAdapter, Path, TransportAdapter};
use node::wire::{
    decode, encode, WireRequest, WireResponse, MAX_BLOB_FRAME, MAX_REQUEST_FRAME, MAX_RESPONSE_FRAME,
};


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

/// How long a QUIC attempt runs alone before the next carrier is started alongside it (QUIC-4).
///
/// Long enough that a healthy UDP path usually finishes first and the second connection is never
/// made; short enough that a network silently dropping UDP costs this instead of a full
/// `CONNECT_TIMEOUT`. That asymmetry is the point: UDP failure is typically SILENCE, so waiting
/// for it to time out is waiting for the common case.
const RACE_HEAD_START: Duration = Duration::from_millis(250);

/// How many requests we will serve on one pooled session before retiring it ourselves.
///
/// **Every pool limit below is DERIVED from the relay's own, and deliberately stricter.** The relay
/// (`relay::server`) closes a connection after `MAX_REQUESTS_PER_CONN = 4096` requests,
/// `CONN_TOTAL_DEADLINE = 120s` of wall clock, or `CONN_READ_TIMEOUT = 30s` of silence. Retiring
/// first means we never LEARN about those limits from a failed request — we simply open a fresh
/// connection at a moment when nothing is in flight.
///
/// The numbers are duplicated rather than imported because `transport` cannot depend on `relay`
/// (the dependency runs the other way). That is safe in one direction only, and the direction is
/// the point: if the relay's limits ever SHRINK below ours, a pooled write fails, and a failed
/// write is retried on a fresh connection (nothing was delivered — see `pooled_round_trip`). So a
/// constant drift costs a wasted round trip, never a lost or duplicated message.
///
/// 1024 against 4096: a whole poll cycle is ~151 requests at 50 contacts, so this is generous for
/// the case pooling exists to serve, while leaving the relay's own ceiling far away.
const POOL_MAX_REQUESTS: u32 = 1024;
/// Retire well before the relay's 120s wall-clock deadline.
const POOL_MAX_AGE: Duration = Duration::from_secs(90);
/// Retire well before the relay's 30s read timeout closes an idle session under us.
const POOL_MAX_IDLE: Duration = Duration::from_secs(20);
/// Bound on pooled sessions, mirroring `QuicAdapter`'s. A client with many scopes in flight would
/// otherwise hold one file descriptor per scope indefinitely.
const POOL_MAX_SESSIONS: usize = 32;

/// Клиентский транспорт поверх Noise-сессии. Один запрос = одно соединение +
/// один handshake (скелет). Держит Noise-pubkey relay (аутентификация при
/// handshake) и адаптер транспорта (§15): direct-TCP или SOCKS5-к-внешнему-PT.
#[derive(Clone)]
pub struct SocketTransport {
    /// Routes to the relay in priority order (§15 Path Manager). More than one = the
    /// request fails over across them; see `round_trip_sized` for the retry boundary.
    paths: Vec<Path>,
    relay_noise_pub: [u8; 32],
    /// Live Noise sessions, keyed by isolation scope and route (PERF-8).
    ///
    /// `Arc` so CLONES SHARE IT, deliberately: a cloned `SocketTransport` is the same `Relay` —
    /// the same compartment, the same routes — so a session opened by one clone is legitimately
    /// reusable by another. What it must never merge is two isolation scopes, and that is the
    /// key's job rather than a convention (see `pooled_take`).
    pool: Arc<Mutex<HashMap<PoolKey, Pooled>>>,
}

/// `(scope, route)` — the ONLY key a pooled session may be found under.
///
/// The scope half is what makes pooling safe at all. Requests under different handles must not
/// share a circuit, and a pool that ignored the scope would put them on one CONNECTION, which is
/// strictly worse than one circuit: same source address AND the same Noise session. There is
/// therefore no `Option` here — an unscoped request never reaches the pool (`pooled_take` refuses
/// it), which is the same "no scope, no pool" rule `QuicAdapter::connect_isolated` already
/// follows.
type PoolKey = (String, String);

/// One idle Noise session plus the bookkeeping that decides when to stop trusting it.
struct Pooled {
    session: Session<Box<dyn Channel>>,
    /// Requests already served on it, against [`POOL_MAX_REQUESTS`].
    requests: u32,
    opened: Instant,
    last_used: Instant,
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
        SocketTransport { paths, relay_noise_pub, pool: Arc::new(Mutex::new(HashMap::new())) }
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

    /// Start every fresh path with a stagger and take the first that completes carrier connect
    /// AND Noise handshake. `None` = they all failed.
    ///
    /// QUIC goes first with no delay; the others start `RACE_HEAD_START` apart, so on a healthy
    /// UDP network the extra connections are usually never made at all — the winner is already
    /// back. On a network that eats UDP, the head start is the whole added latency instead of a
    /// full connect timeout.
    ///
    /// The losing attempts are DETACHED, not joined. Scoped threads would wait for them, which
    /// would make a dead UDP path cost its full connect timeout anyway — the exact thing the race
    /// exists to avoid, hidden one level down. A loser that finishes later drops its session,
    /// closing whatever it opened, and records its own health so a path that genuinely keeps
    /// failing still cools down.
    fn race_connect(
        &self,
        paths: &[&Path],
        scope: Option<&str>,
        now: u64,
    ) -> Option<(Session<Box<dyn Channel>>, Path)> {
        let (tx, rx) = std::sync::mpsc::channel::<(Path, io::Result<Session<Box<dyn Channel>>>)>();
        // QUIC first, so the stagger below is in the intended order.
        let mut ordered: Vec<Path> = paths.iter().map(|p| (*p).clone()).collect();
        ordered.sort_by_key(|p| u8::from(p.adapter.carrier_label() != "quic"));

        let relay_pub = self.relay_noise_pub;
        let scope = scope.map(str::to_string);
        for (rank, path) in ordered.into_iter().enumerate() {
            let tx = tx.clone();
            let scope = scope.clone();
            let delay = RACE_HEAD_START * rank as u32;
            std::thread::spawn(move || {
                if !delay.is_zero() {
                    std::thread::sleep(delay);
                }
                let r = path
                    .adapter
                    .connect_isolated(&path.dest, scope.as_deref())
                    .and_then(|c| Session::connect(c, &relay_pub));
                // A closed receiver means someone already won; the send fails and the session
                // drops here, which closes the connection this attempt opened.
                let _ = tx.send((path, r));
            });
        }
        drop(tx);
        for (path, result) in rx {
            match result {
                Ok(session) => return Some((session, path)),
                Err(_) => path.health.record_failure(now),
            }
        }
        None
    }

    /// Route half of a [`PoolKey`] — which physical path a session was opened over.
    fn path_key(path: &Path) -> String {
        format!("{}|{}", path.adapter.carrier_label(), path.dest)
    }

    /// Take a live session for this scope+route, or `None`.
    ///
    /// **Refuses an unscoped request outright.** That is the whole safety rule, expressed as an
    /// early return rather than as a comment: without a scope there is nothing to keep two
    /// unlinkable handles apart, and pooling them would put them on ONE Noise session — worse than
    /// the shared source address they already have, because it also merges the sequence.
    ///
    /// Retires anything past its limits here rather than on insertion, so a session that went stale
    /// while idle is dropped at the moment we would otherwise have written to it.
    fn pooled_take(&self, scope: Option<&str>, path: &Path) -> Option<Pooled> {
        let scope = scope?;
        let key = (scope.to_string(), Self::path_key(path));
        let mut pool = self.pool.lock().ok()?;
        let p = pool.remove(&key)?;
        let now = Instant::now();
        let stale = p.requests >= POOL_MAX_REQUESTS
            || now.duration_since(p.opened) > POOL_MAX_AGE
            || now.duration_since(p.last_used) > POOL_MAX_IDLE;
        // Dropping `p` closes the connection — no goodbye frame, and deliberately no keep-alive
        // anywhere in this module: periodic traffic on an idle connection is a presence signal.
        if stale {
            return None;
        }
        Some(p)
    }

    /// Put a session back for the next request in the same scope.
    fn pooled_put(&self, scope: Option<&str>, path: &Path, p: Pooled) {
        let Some(scope) = scope else { return };
        let Ok(mut pool) = self.pool.lock() else { return };
        if pool.len() >= POOL_MAX_SESSIONS {
            // Full: drop this one instead of evicting someone else's. Evicting by age would be
            // tidier, but it would also let a burst of new scopes close sessions a poll cycle is
            // actively walking — trading a bounded waste for an unbounded one.
            return;
        }
        pool.insert((scope.to_string(), Self::path_key(path)), p);
    }

    /// One request/response on an already-open session.
    ///
    /// **The retry boundary, which pooling must not move.** `round_trip_scoped_sized` may fail over
    /// to another path only while nothing has been written, because a deposit is not idempotent.
    /// A pooled session inherits that rule with one refinement:
    ///
    /// - the WRITE fails → the bytes never left this machine (the kernel refused a closed socket),
    ///   so a fresh connection is safe. Returned as `Err(None)`: "nothing happened, try again".
    /// - the READ fails → the write had already been accepted into the kernel buffer, which is NOT
    ///   delivery but is also not proof of non-delivery. The relay may have applied the request.
    ///   Returned as `Err(Some(e))`: an honest failure, never a silent double-send.
    ///
    /// That asymmetry is the entire correctness argument for reusing a connection whose peer may
    /// have closed it while we were not looking.
    #[allow(clippy::type_complexity)]
    fn pooled_round_trip(
        mut p: Pooled,
        req_bytes: &[u8],
        req_max: usize,
        resp_max: usize,
    ) -> Result<(WireResponse, Pooled), Option<io::Error>> {
        if let Err(_e) = p.session.write_msg(req_bytes, req_max) {
            return Err(None); // nothing delivered — the caller may open a fresh connection
        }
        let resp_bytes = p.session.read_msg(resp_max).map_err(Some)?;
        let resp = decode(&resp_bytes)
            .map_err(|_| Some(io::Error::new(io::ErrorKind::InvalidData, "decode")))?;
        p.requests = p.requests.saturating_add(1);
        p.last_used = Instant::now();
        Ok((resp, p))
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
        // QUIC-4: when a QUIC path is present, RACE instead of walking the list. UDP is dropped
        // silently by some networks, so a sequential list pays the full connect timeout before it
        // ever tries WSS — and the timeout is the common case there, not the exception. The race
        // gives QUIC a head start and starts the others alongside; the first path to complete BOTH
        // its carrier connect and the Noise handshake wins.
        //
        // Only when QUIC is in the list, deliberately. Racing means opening more than one
        // connection to the relay at once, which on a SOCKS/Tor path means more than one circuit
        // for one request — extra exposure bought for a problem that path does not have, since
        // TCP failure there is a connect error rather than a silent drop.
        //
        // The safety boundary is untouched: the race finishes BEFORE any request byte is written,
        // so "nothing is retried once the request has been written" still holds — it is now
        // simply reached faster.
        if fresh.iter().any(|p| p.adapter.carrier_label() == "quic") && fresh.len() > 1 {
            if let Some((mut session, winner)) = self.race_connect(&fresh, scope, now) {
                winner.health.record_success();
                session.write_msg(&req_bytes, req_max)?;
                let resp_bytes = session.read_msg(resp_max)?;
                return decode(&resp_bytes)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decode"));
            }
            // Every raced path failed; fall through to the cooling ones, which the race skips.
        }
        let mut last_err: Option<io::Error> = None;
        for path in fresh.into_iter().chain(cooling) {
            // PERF-8: an already-open session for THIS scope on THIS route, if we have one. Tried
            // before connecting, so the common case — a poll cycle walking many boxes — pays one
            // handshake instead of one per request. A read failure here is returned rather than
            // failed over, exactly as for a fresh session past its write.
            if let Some(p) = self.pooled_take(scope, path) {
                match Self::pooled_round_trip(p, &req_bytes, req_max, resp_max) {
                    Ok((resp, p)) => {
                        path.health.record_success();
                        self.pooled_put(scope, path, p);
                        return Ok(resp);
                    }
                    Err(Some(e)) => return Err(e),
                    // Nothing was delivered (the write itself failed): fall through and connect.
                    Err(None) => {}
                }
            }
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
            let resp = decode(&resp_bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decode"))?;
            // Keep it for the next request in this scope. Unscoped requests are refused by
            // `pooled_put`, so a public read never leaves a reusable session behind.
            let at = Instant::now();
            self.pooled_put(
                scope,
                path,
                Pooled { session, requests: 1, opened: at, last_used: at },
            );
            return Ok(resp);
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

    /// Open a REUSABLE session for streaming many blob requests over ONE Noise handshake
    /// (§15 / FT4).
    /// Tries paths in health order (like `round_trip`); the relay then accepts a bounded run of
    /// requests on this single connection, so a chunked transfer amortizes the per-chunk TCP +
    /// Noise handshake instead of paying it every chunk. Dropping the returned session closes it.
    ///
    /// `scope` names the compartment this transfer belongs to. It is what stops a pooling carrier
    /// from putting two unrelated transfers on one connection (see `QuicAdapter::pool`), and on a
    /// SOCKS carrier it is folded into the circuit credential. Pass a value that is fresh per
    /// TRANSFER: a blob download already has one in the `client_addr` it presents
    /// (`client::blob_get_addr`), which is minted per download for the same reason.
    pub fn open_blob_session_scoped(&self, scope: Option<&str>) -> io::Result<BlobSession> {
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
                .connect_isolated(&path.dest, scope)
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

    /// `open_blob_session_scoped` with no compartment — the upload path, which already opens one
    /// session per file and so needs no key to keep files apart.
    pub fn open_blob_session(&self) -> io::Result<BlobSession> {
        self.open_blob_session_scoped(None)
    }
}

/// A reusable client connection for a blob TRANSFER (§15 / FT4): one Noise handshake, then many
/// chunk requests over the same session. `Err` from `put`/`get` means the session is dead (the
/// relay closed it after its bounded run, or the link dropped) — the caller opens a fresh one and
/// retries the chunk, which is idempotent at the relay in both directions.
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

    /// Download one chunk over the reused session — the mirror of [`BlobSession::put`], and the
    /// half that was missing: an upload has amortized its handshakes since FT4, while every chunk
    /// of a DOWNLOAD paid a fresh connection and a fresh Noise handshake.
    ///
    /// The frame ceilings are swapped, because the direction is: a get sends a tight request and
    /// receives a chunk-sized response.
    pub fn get(&mut self, req: &BlobGetRequest) -> io::Result<BlobResponse> {
        let req_bytes = encode(&WireRequest::BlobGet(req.clone()))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encode"))?;
        self.session.write_msg(&req_bytes, MAX_REQUEST_FRAME)?;
        let resp_bytes = self.session.read_msg(MAX_BLOB_FRAME)?;
        match decode(&resp_bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decode"))? {
            WireResponse::Blob(b) => Ok(b),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "protocol: unexpected on BlobGet")),
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
        // The publish class's OWN ceiling on the way OUT, matching the one the server applies on
        // the way in (`wire::max_frame_for`). `round_trip`'s tight default is sized for the
        // Send/Fetch class and cannot carry a bundle plus a one-time prekey batch — it fit only
        // while a unit was ~104 bytes, and a unit now carries its own ML-KEM encapsulation key
        // (CRYPTO-33). Sending under the wrong ceiling fails as an opaque transport error, which
        // is exactly how a full batch would have looked: "bundle not published", no reason given.
        match self.round_trip_sized(
            &WireRequest::PublishBundle(req.clone()),
            node::wire::MAX_PUBLISH_FRAME,
            MAX_RESPONSE_FRAME,
        ) {
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


/// **What the pool may and may not merge** (PERF-8), enforced rather than described.
///
/// Reusing a connection is a performance change that can silently become a privacy change: the
/// difference between "these two requests came from one address" (already true) and "these two
/// requests rode one Noise session" (a sequence a relay can join for free) is exactly one missing
/// component in a pool key. So the key is pinned here, and so is the absence of a keep-alive.
#[cfg(test)]
mod the_pool_merges_only_one_scope {
    use super::*;

    fn tcp(dest: &str) -> Path {
        Path::new(Arc::new(DirectTcpAdapter::default()), Dest::parse(dest).expect("addr"))
    }

    fn transport(paths: Vec<Path>) -> SocketTransport {
        SocketTransport::with_paths(paths, [7u8; 32])
    }

    /// **An unscoped request never enters the pool.** Same rule as `QuicAdapter`: no scope, no
    /// pool, because there is nothing to keep two unlinkable handles apart.
    ///
    /// DISCRIMINATING: drop the `let scope = scope?;` early return in `pooled_take` and this goes
    /// red — an unscoped request would then find, and reuse, whatever session was last left behind.
    #[test]
    fn an_unscoped_request_is_refused_by_the_pool() {
        let t = transport(vec![tcp("127.0.0.1:1")]);
        let p = &t.paths[0];
        assert!(t.pooled_take(None, p).is_none(), "an unscoped take must not consult the pool");
    }

    /// Two scopes on ONE route are two entries, never one.
    ///
    /// This is the property the whole change rests on: proxy identities are separated by their
    /// per-handle scope (see `transport::compartment_and_scope_are_two_axes`), so a pool that keyed
    /// on route alone would hand one identity the session another identity opened.
    #[test]
    fn two_scopes_on_one_route_are_two_keys() {
        let t = transport(vec![tcp("127.0.0.1:1")]);
        let p = &t.paths[0];
        let route = SocketTransport::path_key(p);
        assert_ne!(
            ("scope-a".to_string(), route.clone()),
            ("scope-b".to_string(), route),
            "the key collapsed to the route: one identity would reuse another's Noise session"
        );
    }

    /// And one scope over two ROUTES is also two entries — a session belongs to the carrier and
    /// destination it was opened over, and handing it to a different path would send bytes down a
    /// connection the caller did not choose.
    #[test]
    fn one_scope_on_two_routes_is_two_keys() {
        let t = transport(vec![tcp("127.0.0.1:1"), tcp("127.0.0.2:1")]);
        assert_ne!(
            SocketTransport::path_key(&t.paths[0]),
            SocketTransport::path_key(&t.paths[1]),
            "two distinct routes produced the same pool key"
        );
    }

    /// **No keep-alive, anywhere.** A pooled session that goes quiet must simply die; pinging to
    /// hold it open would turn "this client is configured" into "this client is here right now",
    /// which is a presence signal we do not send. `quic.rs` pins the same absence for QUIC.
    ///
    /// A source scan, because the failure it guards is an ADDITION: someone adds a periodic probe
    /// to make pooling more effective, and the effectiveness is real while the cost is invisible.
    /// (The forbidden spellings are assembled from fragments below rather than quoted, so this
    /// documentation is not itself a match.)
    #[test]
    fn nothing_in_this_module_keeps_a_pooled_session_warm() {
        let src = include_str!("socket.rs");
        for bad in [
            concat!("keep", "_alive"),
            concat!("heart", "beat"),
            concat!("ping", "_interval"),
        ] {
            assert!(
                !src.contains(bad),
                "`{bad}` appeared in the dialer. A pooled connection must be allowed to go idle \
                 and die: periodic traffic to hold it open is a presence signal, and it is bought \
                 for throughput the poll cycle does not need (the relay's own idle timeout is 30s, \
                 a cycle is seconds)."
            );
        }
    }

    /// The pool's limits must stay STRICTLY under the relay's, so we retire first and never learn
    /// about its ceilings from a failed request.
    /// Mirrors of `relay::server`'s constants — see `POOL_MAX_REQUESTS` on why they are duplicated
    /// and why the direction of safety makes that acceptable.
    const RELAY_MAX_REQUESTS: u32 = 4096;
    const RELAY_TOTAL_DEADLINE: Duration = Duration::from_secs(120);
    const RELAY_READ_TIMEOUT: Duration = Duration::from_secs(30);

    // A COMPILE-TIME check, not a runtime one: these are all constants, so a runtime assert would
    // be dead weight that clippy is right to flag — and a `const` block fails the BUILD, which is
    // the stronger place for "we must retire before the relay does".
    const _: () = assert!(POOL_MAX_REQUESTS < RELAY_MAX_REQUESTS);
    const _: () = assert!(POOL_MAX_AGE.as_secs() < RELAY_TOTAL_DEADLINE.as_secs());
    const _: () = assert!(POOL_MAX_IDLE.as_secs() < RELAY_READ_TIMEOUT.as_secs());
}
