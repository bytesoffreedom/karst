//! Клиентский транспорт поверх Noise-сессии (§15): `SocketTransport`.
//!
//! Split out of the old `socket` module (#143): that file held BOTH the relay's listener and the
//! client's dialer, which is the crate-level coupling in miniature — the side that accepts
//! connections and the side that makes them, sharing one namespace. The listener now lives in the
//! `relay` crate; nothing here can name a `RelayNode`.

use std::io;
use std::sync::Arc;

use admission::capability::Capability;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::discovery::DiscoveryRecord;
use crate::protocol::{AckRequest, AckResponse, BlobGetRequest, BlobPutRequest, BlobResponse, BundleOpkRequest, BundleOpkResponse, FetchRequest, FetchResponse, JoinRequest, PublishRequest, PublishResponse, RelayDescriptor, RelayPolicy, Response, Transport, WireMessage};
use crate::pqxdh::PreKeyBundle;
use crate::session::Session;
use crate::transport::{Channel, Dest, DirectTcpAdapter, Path, TransportAdapter};
use crate::wire::{
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
        // The publish class's OWN ceiling on the way OUT, matching the one the server applies on
        // the way in (`wire::max_frame_for`). `round_trip`'s tight default is sized for the
        // Send/Fetch class and cannot carry a bundle plus a one-time prekey batch — it fit only
        // while a unit was ~104 bytes, and a unit now carries its own ML-KEM encapsulation key
        // (CRYPTO-33). Sending under the wrong ceiling fails as an opaque transport error, which
        // is exactly how a full batch would have looked: "bundle not published", no reason given.
        match self.round_trip_sized(
            &WireRequest::PublishBundle(req.clone()),
            crate::wire::MAX_PUBLISH_FRAME,
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

