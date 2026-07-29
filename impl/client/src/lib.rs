//! KARST десктоп-клиент — ЯДРО (без stdout/args; это делает бинарь `karst`).
//!
//! Тонкая оркестрация над `node`: хранит identity + capability (`store`),
//! запечатывает и шлёт сообщения через `SocketTransport`, забирает и
//! расшифровывает входящие. Ядро отделено от CLI, чтобы позже переиспользовать
//! его из Android через JNI — **сам JNI здесь не строим**, это отдельный срез.
//!
//! Честные границы (названы, не спрятаны):
//! - **§2.1 путь** (`send_session`/`recv_session`): PQXDH sender-auth + ratchet
//!   поверх персистентных сессий (flock+atomic в `store`). Идентичность
//!   отправителя аутентифицирована, но пока не прокидывается наружу приёмом
//!   (показ «from» — отдельный срез). `send_message`/`fetch_messages` — старый
//!   skeleton-путь, оставлен для demo/тестов;
//! - **lease/ACK + plaintext-first на приёме:** `recv_session` =
//!   fetch(lease)→process→**persist history (deduped)**→save→ACK. Плейнтекст durable ДО
//!   коммита ratchet/OPK и ДО ACK, поэтому оба прежних окна потери ([OPK→session],
//!   [session→history]) закрыты; редоставленный дубликат отсекается по `payload_id`
//!   (или fail-closed на продвинутом ratchet). Остаток: dedup только для текста — файл/
//!   реакция в том же окне могут примениться повторно (отдельные срезы). Для
//!   container-backed аккаунта `Store` — лишь распакованная рабочая копия, поэтому
//!   `recv_session_multi` НЕ шлёт ACK сам: он возвращает [`DeferredAcks`], и удалить
//!   сообщения с relay можно только через `commit_then_send`, т.е. после успешного
//!   коммита авторитетного контейнера (SEC-34);
//! - **at-rest секретов нет** (см. `store`) — теперь load-bearing: на диске
//!   ratchet chain/root-ключи.

pub mod blob;
pub mod container;
pub mod content;
pub mod secretbox;
pub mod seed;
pub mod store;

// ----- What a UI is allowed to reach for (#143) -----
//
// The desktop used to depend on `node` directly, for three things: a decrypted message, a safety
// number, and an address parser. All three are client-side, and none of them needed a dependency
// that also carries the RELAY — a UI able to name `RelayNode` is a UI able to bypass this crate's
// API and drive relay internals, which is the coupling the crate split exists to remove.
//
// Re-exported here rather than left as a direct dependency so the boundary is stated in one place:
// what the UI may use is what this crate hands it. Adding to this list should feel like a
// decision, because it is one.
pub use node::peer::Received;
pub use node::safety::safety_number;
pub use karst_transport::transport::Dest;

use std::net::SocketAddr;
use std::sync::Arc;

use store::Store;

/// Честное сообщение при провале чтения секрета: нет файла (нужен init) vs
/// файл есть, но не расшифровался (неверный `KARST_PASSPHRASE`/повреждение).
fn secret_load_err(what: &str, e: std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::NotFound {
        format!("нет {what} (karst init)")
    } else {
        format!("не удалось прочитать {what} (неверный KARST_PASSPHRASE или повреждение): {e}")
    }
}

use admission::capability::{Capability, Quota, Scope};
use node::demo::{Client, Recipient};
use node::protocol::{
    BlobGetRequest, BlobPutRequest, BlobResponse, PublishResponse, Response,
    Transport,
};
use node::peer::{ForwardSecrecy, Peer, PeerState};
use node::pqxdh::Account;
use node::seal::Identity;
use karst_transport::socket::{BlobSession, SocketTransport};
use karst_transport::transport::{isolation_token, DirectTcpAdapter, Path, Socks5Adapter, TransportAdapter};
use karst_transport::wss::WssAdapter;

/// The §15 carrier `transport()` selects, given the SOCKS proxy setting and the
/// `KARST_WSS` env. Single source of truth so the UI can show what is *actually*
/// used (a user who set `KARST_WSS` wants to confirm the transport is live, and one
/// who set a proxy wants to confirm traffic really rides it — no silent fallback).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Carrier {
    /// Plain TCP to the relay.
    Direct,
    /// Through a SOCKS5 proxy (external PT: Tor/obfs4/…).
    Socks5,
    /// WebSocket-over-TLS carrier.
    Wss,
    /// wss riding through a SOCKS5 proxy (standard HTTPS transport *and* external PT).
    WssOverSocks5,
    /// The i2p network: a `*.i2p` relay reached through i2pd's SOCKS bridge. Transport-wise it
    /// IS SOCKS5 (to the local i2p router), but the router resolves the destination inside i2p —
    /// a distinct anonymity network from Tor, so it carries its own label.
    I2p,
    /// Tor: a `*.onion` relay reached through Tor's SOCKS port. Also SOCKS5 under the hood, but
    /// the `.onion` names the network, so it is reported as Tor rather than bare SOCKS5.
    Tor,
    /// A mixnet (Nym): the relay is reached through a Nym client's SOCKS port, which routes the
    /// stream through the mixnet — adding TIMING/TRAFFIC-ANALYSIS resistance on top of Tor/i2p's
    /// route anonymity. There is no address suffix (Nym's SOCKS client picks the path), so this
    /// carrier is chosen by an EXPLICIT flag, not inferred from the address.
    Mixnet,
}

impl Carrier {
    /// Fixed, technical label for the status bar (protocol identifiers, not prose —
    /// deliberately not localized: `wss`/`SOCKS5`/`i2p`/`Tor`/`mixnet` are proper names).
    pub fn label(self) -> &'static str {
        match self {
            Carrier::Direct => "direct",
            Carrier::Socks5 => "SOCKS5",
            Carrier::Wss => "wss",
            Carrier::WssOverSocks5 => "wss over SOCKS5",
            Carrier::I2p => "i2p",
            Carrier::Tor => "Tor",
            Carrier::Mixnet => "mixnet",
        }
    }

    /// The carrier an ADAPTER reports itself as (`TransportAdapter::carrier_label`) — the bridge
    /// between what actually ran and what the user is shown (A4-10, #217).
    ///
    /// Returns `None` for a label this layer does not know, and the caller falls back to the
    /// configured carrier rather than inventing one. An unknown adapter (a test spy, a carrier
    /// added below without a mapping here) must not be able to make the badge claim a protection
    /// it never provided — the whole point of the finding.
    pub fn from_label(label: &str) -> Option<Carrier> {
        match label {
            "direct" => Some(Carrier::Direct),
            "socks5" => Some(Carrier::Socks5),
            "wss" => Some(Carrier::Wss),
            "wss+socks5" => Some(Carrier::WssOverSocks5),
            _ => None,
        }
    }
}

/// Pure carrier decision from the two inputs — the exact branch `transport()` takes.
/// Kept separate so it is testable without touching process-global env.
fn carrier_from(wss: bool, has_proxy: bool) -> Carrier {
    match (wss, has_proxy) {
        (true, true) => Carrier::WssOverSocks5,
        (true, false) => Carrier::Wss,
        (false, true) => Carrier::Socks5,
        (false, false) => Carrier::Direct,
    }
}

/// The carrier that `transport()` will use for `proxy` under the current env.
pub fn active_carrier(proxy: Option<SocketAddr>) -> Carrier {
    let wss = std::env::var("KARST_WSS").map(|h| !h.is_empty()).unwrap_or(false);
    carrier_from(wss, proxy.is_some())
}

/// Carriers that preserve the protection property the user actually asked for.
///
/// The floor is an ALLOWLIST derived from intent — deliberately NOT a scalar
/// "strength" ordering: wss (anti-traffic-analysis transport) and SOCKS5 (anonymity via an
/// external PT) defend against different adversaries and are not comparable. A path
/// whose carrier is off this list is never built, so automatic switching can never
/// trade away the property the user chose, even when every allowed path is dead.
fn allowed_carriers(intent: Carrier) -> &'static [Carrier] {
    match intent {
        // Nothing was requested → nothing to preserve; any carrier is acceptable.
        Carrier::Direct => {
            &[Carrier::Direct, Carrier::Socks5, Carrier::Wss, Carrier::WssOverSocks5]
        }
        // Chose Tor/PT: the traffic MUST keep riding the external proxy. Bare wss is
        // excluded too — it rides standard HTTPS but exits from THIS host, which
        // exposes your IP, not merely weaker routing.
        Carrier::Socks5 => &[Carrier::Socks5, Carrier::WssOverSocks5],
        // Chose the wss carrier: every path must still ride standard HTTPS.
        Carrier::Wss => &[Carrier::Wss, Carrier::WssOverSocks5],
        // Asked for both properties → only the carrier that has both.
        Carrier::WssOverSocks5 => &[Carrier::WssOverSocks5],
        // Chose i2p: traffic MUST stay inside i2p (its SOCKS bridge). Never fall back to a
        // clearnet carrier — that would leave the anonymity network entirely.
        Carrier::I2p => &[Carrier::I2p],
        // Chose Tor (an onion): must stay on Tor. `wss over SOCKS5` (wss THROUGH Tor) still
        // rides Tor and is allowed; bare wss/direct would exit from this host = deanonymization.
        Carrier::Tor => &[Carrier::Tor, Carrier::WssOverSocks5],
        // Chose the mixnet: traffic MUST stay in the mixnet — any clearnet/Tor fallback would
        // drop the timing-analysis resistance the user asked for.
        Carrier::Mixnet => &[Carrier::Mixnet],
    }
}

/// A configured route before its adapter is built: which carrier, which endpoint.
/// Not `Copy`: `Dest` owns a host string (it may be a name, not an address).
#[derive(Clone, PartialEq, Eq, Debug)]
struct PathSpec {
    carrier: Carrier,
    dest: Dest,
}

/// Parse `KARST_PATHS`: comma-separated `kind@ip:port`, where kind is
/// `direct` | `socks5` | `wss` | `wss+socks5`. Order is preserved. An unknown kind or
/// an unparseable address is SKIPPED with a warning — a typo must never silently
/// become a different (weaker) route.
fn parse_path_specs(s: &str) -> Vec<PathSpec> {
    s.split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .filter_map(|e| {
            let (kind, addr) = match e.split_once('@') {
                Some(p) => p,
                None => {
                    eprintln!("KARST_PATHS: {e:?} is not kind@ip:port — skipped");
                    return None;
                }
            };
            let carrier = match kind.trim().to_ascii_lowercase().as_str() {
                "direct" => Carrier::Direct,
                "socks5" => Carrier::Socks5,
                "wss" => Carrier::Wss,
                "wss+socks5" => Carrier::WssOverSocks5,
                "i2p" => Carrier::I2p,
                "tor" => Carrier::Tor,
                "mixnet" => Carrier::Mixnet,
                other => {
                    eprintln!("KARST_PATHS: unknown carrier {other:?} — skipped");
                    return None;
                }
            };
            match Dest::parse(addr) {
                Ok(dest) => Some(PathSpec { carrier, dest }),
                Err(err) => {
                    eprintln!("routes: bad address {addr:?}: {err} — skipped");
                    None
                }
            }
        })
        .collect()
}

/// Drop every spec whose carrier `intent` does not allow (fail-closed). This is where
/// "automatic transport switching" is kept honest: a route the user never consented to
/// is not used even if it is the only one that would connect.
fn filter_allowed(specs: Vec<PathSpec>, intent: Carrier) -> Vec<PathSpec> {
    let allow = allowed_carriers(intent);
    specs
        .into_iter()
        .filter(|sp| {
            let ok = allow.contains(&sp.carrier);
            if !ok {
                eprintln!(
                    "KARST_PATHS: dropping {} path {} — not allowed by the chosen carrier {}",
                    sp.carrier.label(),
                    sp.dest,
                    intent.label()
                );
            }
            ok
        })
        .collect()
}

/// Build the adapter for ONE specific carrier. Returns `None` when the carrier's
/// prerequisite config is missing (a wss path with no `KARST_WSS` host, a socks5 path
/// with no proxy) — such a path is skipped rather than silently demoted.
fn adapter_for(
    carrier: Carrier,
    proxy: Option<SocketAddr>,
    wss_host: Option<&str>,
    isolation: &str,
) -> Option<Arc<dyn TransportAdapter>> {
    let wss = || wss_host.map(|h| wss_adapter(h.to_string()));
    // Every proxied carrier presents THIS compartment's isolation token, so Tor puts it
    // on its own circuit (IsolateSOCKSAuth). Without it two identities on one device can
    // share a circuit and are linked regardless of having different keys.
    let socks = |p| Socks5Adapter::isolated(p, isolation.to_string());
    match carrier {
        Carrier::Direct => Some(Arc::new(DirectTcpAdapter::default())),
        Carrier::Socks5 => Some(Arc::new(socks(proxy?))),
        Carrier::Wss => Some(Arc::new(wss()?)),
        Carrier::WssOverSocks5 => Some(Arc::new(wss()?.through(Arc::new(socks(proxy?))))),
        // i2p rides SOCKS5 to the local i2p router, which resolves the *.i2p destination and
        // builds the in-network tunnel; the host in the `Dest` is forwarded to it unresolved.
        Carrier::I2p => Some(Arc::new(socks(proxy?))),
        // Tor rides SOCKS5 to the Tor daemon, which resolves the .onion and builds the circuit;
        // the .onion host is forwarded to Tor unresolved (never leaked to clearnet DNS).
        Carrier::Tor => Some(Arc::new(socks(proxy?))),
        // Mixnet rides SOCKS5 to the Nym client, which carries the stream through the mixnet.
        Carrier::Mixnet => Some(Arc::new(socks(proxy?))),
    }
}

/// Everything needed to reach ONE relay: its out-of-band identity, the carrier
/// settings, and the ordered §15 path list that failover walks.
///
/// Built ONCE per session and handed to every networked call. That is what gives the
/// path list a home that outlives a single request (per-path health can live here
/// next), lets the GUI/CLI configure routes instead of the library reading process env
/// on every call, and collapses the `(relay, relay_id, proxy)` triple that used to be
/// threaded through eighteen signatures.
#[derive(Clone)]
pub struct Relay {
    /// The relay's primary address — the first path's endpoint. A `Dest`, so it can be an IP
    /// literal OR a name only a carrier resolves: notably a `<b32>.b32.i2p` address reached
    /// through i2pd's SOCKS bridge (`proxy`).
    pub addr: Dest,
    /// Out-of-band identity: Noise-pub (authenticates the relay on handshake) ‖
    /// fetch-auth-pub. The same identity is proven no matter which path carried it.
    pub id: RelayId,
    /// SOCKS5 port of an external PT (Tor/obfs4/…). `None` = no proxy.
    pub proxy: Option<SocketAddr>,
    /// Routes in priority order: the primary, then the configured alternates.
    paths: Vec<Path>,
    /// This compartment's SOCKS stream-isolation token — fresh per `Relay`, so each
    /// account's traffic rides its own Tor circuit (see `Socks5Adapter::isolation`).
    /// Two accounts sharing a circuit would be linked however different their keys are.
    isolation: String,
    /// **Per-session pseudonym** sent as `client_addr` on blob DOWNLOADS (and the durability
    /// spot check). Fresh random bytes, never persisted, never derived from an identity key.
    ///
    /// It used to be the uploader's IK on put and the downloader's IK on get — against
    /// the same `blob_id`, which handed the relay both ends of every large-file
    /// transfer: "IK_A sent a file to IK_B". Only the cookie needs this field on the get
    /// path, and a stable-per-session pseudonym satisfies a cookie just as well.
    ///
    /// It is no longer used on PUT. The blob store reads `client_addr` there as a durable
    /// owner handle (first-writer-wins), which a per-process value cannot be — see
    /// `blob::owner_token` and A4-1.
    pseudonym: [u8; 32],
    /// `proxy` is a mixnet (Nym) client's SOCKS port, not a bare SOCKS5/Tor proxy. Transport is
    /// identical (SOCKS5 to that port); this only makes the carrier read as `mixnet` and keeps
    /// the failover ladder inside the mixnet. Set with [`Relay::with_mixnet`].
    mixnet: bool,
}

impl Relay {
    /// Build with the extra routes taken from the environment (`KARST_RELAY_ALTS` +
    /// `KARST_PATHS`) — the CLI/back-compat entry point.
    pub fn new(addr: impl Into<Dest>, id: RelayId, proxy: Option<SocketAddr>) -> Self {
        Self::configured(addr, id, proxy, &routes_from_env())
    }

    /// Declare that this relay's `proxy` is a mixnet (Nym) SOCKS client, so the carrier reports
    /// `mixnet`. A no-op without a proxy — the mixnet IS the proxy.
    pub fn with_mixnet(mut self, on: bool) -> Self {
        self.mixnet = on;
        self
    }

    /// Build with EXPLICIT extra routes — what the app passes when the user types them
    /// in, so the failover layer is reachable without setting environment variables.
    /// `routes` is the unified comma-separated syntax (`ip:port` = same carrier,
    /// `kind@ip:port` = explicit carrier); see `build_paths`. Empty = single path.
    pub fn configured(
        addr: impl Into<Dest>,
        id: RelayId,
        proxy: Option<SocketAddr>,
        routes: &str,
    ) -> Self {
        let addr = addr.into();
        let isolation = isolation_token();
        let paths = build_paths(addr.clone(), proxy, routes, &isolation);
        Relay { addr, id, proxy, paths, pseudonym: blob::random32(), isolation, mixnet: false }
    }

    /// Replace the route list — TEST SEAM (A4-10, #217).
    ///
    /// Production builds paths through `build_paths`, which also applies the carrier allowlist.
    /// A test that wants to show the badge following a FAILOVER needs two paths with different
    /// carriers and a dead primary, which is a state the allowlist would narrow; constructing it
    /// directly keeps the test about the indicator rather than about route parsing.
    #[doc(hidden)]
    pub fn set_paths_for_test(&mut self, paths: Vec<Path>) {
        self.paths = paths;
    }

    /// The §15 transport over this relay's path list. `SocketTransport` retries a
    /// path's connect AND its Noise handshake, so an adversary that blackholes the IP and
    /// one that kills the handshake are both routed around.
    fn transport(&self) -> SocketTransport {
        SocketTransport::with_paths(self.paths.clone(), self.id.noise_pub)
    }

    /// The §15 carrier the status bar/CLI shows — derived from the path that ACTUALLY RAN
    /// (A4-10, #217).
    ///
    /// This used to describe the PRIMARY path only, computed from `proxy` + env. With failover
    /// that can be a lie: a message routed around a dead primary rides an alternate whose carrier
    /// may be different, while the badge kept claiming the protected one. For a privacy product a
    /// wrong indicator is worse than none — the user decides what to send based on it.
    ///
    /// The source of truth is now the same `PathHealth` the transport itself updates: whichever
    /// path recorded the most recent success. Before anything has succeeded there is nothing to
    /// report but intent, and that case falls through to the primary — honest, because no message
    /// has been carried yet.
    ///
    /// A `.onion` / `.i2p` address reached through the SOCKS bridge is still reported as Tor /
    /// i2p rather than bare SOCKS5, so the user sees which anonymity network carries them.
    pub fn carrier(&self) -> Carrier {
        // What actually ran wins over what was configured.
        if let Some(p) = self
            .paths
            .iter()
            .filter(|p| p.health.last_ok() > 0)
            .max_by_key(|p| p.health.last_ok())
        {
            if let Some(c) = Carrier::from_label(p.adapter.carrier_label()) {
                // The anonymity-network refinement applies to whatever carried us, not to the
                // configured primary: a `.onion` destination reached over SOCKS is Tor.
                if matches!(c, Carrier::Socks5) {
                    if self.mixnet {
                        return Carrier::Mixnet;
                    }
                    if is_onion_host(&p.dest.host) {
                        return Carrier::Tor;
                    }
                    if is_i2p_host(&p.dest.host) {
                        return Carrier::I2p;
                    }
                }
                return c;
            }
        }
        self.configured_carrier()
    }

    /// The carrier the CONFIGURATION implies, before anything has been carried. Split out so the
    /// "nothing has run yet" case is explicit rather than an accident of the same function.
    fn configured_carrier(&self) -> Carrier {
        if self.proxy.is_some() {
            // Mixnet is an explicit choice (no address suffix names it), so it wins first.
            if self.mixnet {
                return Carrier::Mixnet;
            }
            if is_onion_host(&self.addr.host) {
                return Carrier::Tor;
            }
            if is_i2p_host(&self.addr.host) {
                return Carrier::I2p;
            }
        }
        active_carrier(self.proxy)
    }

    /// How many routes failover may walk (1 = no alternates configured).
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }

    /// This compartment's SOCKS stream-isolation token. Every proxied path of this
    /// `Relay` presents it, so Tor keeps this account's traffic on its own circuit
    /// (`IsolateSOCKSAuth`) — two accounts sharing a circuit would be linked no matter
    /// how different their keys are.
    pub fn isolation(&self) -> &str {
        &self.isolation
    }
}

/// The extra routes configured in the environment, in the unified `routes` syntax
/// `build_paths` takes. `KARST_RELAY_ALTS` (plain `ip:port` — same carrier) and
/// `KARST_PATHS` (`kind@ip:port` — explicit carrier) are both accepted and simply
/// concatenated: the syntax distinguishes them per entry, so they are one list.
fn routes_from_env() -> String {
    let alts = std::env::var("KARST_RELAY_ALTS").unwrap_or_default();
    let paths = std::env::var("KARST_PATHS").unwrap_or_default();
    match (alts.trim().is_empty(), paths.trim().is_empty()) {
        (true, true) => String::new(),
        (false, true) => alts,
        (true, false) => paths,
        (false, false) => format!("{alts},{paths}"),
    }
}

/// Assemble the §15 path list: the primary path plus the configured extra routes.
///
/// The primary is `addr` with the carrier the user chose (`KARST_WSS` / `proxy`, see
/// `Carrier`). `routes` is a comma-separated list where each entry is either:
/// - `ip:port` — an alternate ENDPOINT on the SAME carrier (IP failover), or
/// - `kind@ip:port` (`direct`|`socks5`|`wss`|`wss+socks5`) — an explicit CARRIER
///   (automatic transport switching), filtered through `allowed_carriers` so switching
///   can never drop the protection the user asked for.
///
/// One syntax, one list: the `@` decides. Empty `routes` = a single path — exactly the
/// pre-failover behaviour.
/// An i2p eepsite / relay destination — `<b32>.b32.i2p` or any `*.i2p` name. Resolved only by
/// an i2p router (via its SOCKS bridge), never by clearnet DNS.
pub fn is_i2p_host(host: &str) -> bool {
    host.trim_end_matches('.').to_ascii_lowercase().ends_with(".i2p")
}

/// A Tor onion service address — `*.onion`. Reachable only through Tor's SOCKS port; it has no
/// clearnet IP and clearnet DNS never resolves it.
pub fn is_onion_host(host: &str) -> bool {
    host.trim_end_matches('.').to_ascii_lowercase().ends_with(".onion")
}

fn build_paths(
    addr: Dest,
    proxy: Option<SocketAddr>,
    routes: &str,
    isolation: &str,
) -> Vec<Path> {
    let intent = active_carrier(proxy);
    let host = std::env::var("KARST_WSS").ok().filter(|h| !h.is_empty());
    let adapter = carrier_adapter(proxy, isolation);

    let mut paths = vec![Path::new(adapter.clone(), addr)];
    // Same-carrier alternates need no allowlist check: they ARE the chosen carrier.
    let (specs, alts) = split_routes(routes);
    paths.extend(alts.into_iter().map(|dest| Path::new(adapter.clone(), dest)));
    for sp in filter_allowed(specs, intent) {
        match adapter_for(sp.carrier, proxy, host.as_deref(), isolation) {
            Some(a) => paths.push(Path::new(a, sp.dest)),
            None => eprintln!(
                "routes: {} path {} needs config that is not set (wss host / proxy) — skipped",
                sp.carrier.label(),
                sp.dest
            ),
        }
    }
    paths
}

/// Split the unified `routes` list into explicit-carrier specs (`kind@ip:port`) and
/// same-carrier alternate endpoints (`ip:port`), preserving order within each group.
/// Garbage is skipped with a warning by the two parsers.
fn split_routes(routes: &str) -> (Vec<PathSpec>, Vec<Dest>) {
    let (with_kind, plain): (Vec<&str>, Vec<&str>) = routes
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .partition(|e| e.contains('@'));
    (parse_path_specs(&with_kind.join(",")), parse_alt_addrs(&plain.join(",")))
}

/// Parse the plain (`host:port`) route entries — alternate ENDPOINTS that reuse the
/// primary's carrier, so this list can never downgrade it. Order is preserved; garbage
/// is skipped with a warning.
///
/// A host may be a NAME (`xyz.onion`, `abc.i2p`, a hostname). That is the whole point:
/// the relays worth reaching are often hidden-service addresses with no clearnet IP, reached through a resolving proxy.
/// A name only works through a resolving carrier — `DirectTcpAdapter` refuses one rather
/// than leaking a DNS lookup, so a name on a direct route fails loudly at connect time.
fn parse_alt_addrs(alts: &str) -> Vec<Dest> {
    alts.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|a| match Dest::parse(a) {
            Ok(dest) => Some(dest),
            Err(e) => {
                eprintln!("routes: bad address {a:?}: {e} — skipped");
                None
            }
        })
        .collect()
}

/// Split a `KARST_WSS` spec into (SNI host, co-hosting path). `example.com` → SNI
/// `example.com`, path `/`; `example.com/s3cret` → SNI `example.com`, path `/s3cret`.
///
/// The SNI must be a bare hostname (no path), so the path is split off at the first `/`.
/// This is how the operator points the client at a secret path their reverse proxy routes
/// to the relay — see `WssAdapter::path` for why there is no KARST-specific default.
fn split_wss_spec(spec: &str) -> (String, String) {
    match spec.split_once('/') {
        Some((host, rest)) => (host.to_string(), format!("/{rest}")),
        None => (spec.to_string(), "/".to_string()),
    }
}

/// The wss carrier for `spec` (SNI host, optionally `host/secret-path`), honouring
/// `KARST_WSS_ROOT_CA`: trust an extra root CA (self-hosted private CA / local testing) on
/// top of the webpki roots. On failure, warn and keep webpki-only rather than silently
/// trusting nothing extra.
fn wss_adapter(spec: String) -> WssAdapter {
    let (host, path) = split_wss_spec(&spec);
    let base = match std::env::var("KARST_WSS_ROOT_CA") {
        Ok(ca) if !ca.is_empty() => {
            match karst_transport::wss::client_config_with_extra_root_pem(std::path::Path::new(&ca)) {
                Ok(cfg) => WssAdapter::with_config(host, cfg),
                Err(e) => {
                    eprintln!("KARST_WSS_ROOT_CA: {e}; using webpki roots only");
                    WssAdapter::new(host)
                }
            }
        }
        _ => WssAdapter::new(host),
    };
    base.path(path)
}

/// Build the single carrier adapter chosen by env + `proxy` — the PRIMARY path's
/// carrier (see `Carrier`/`carrier_from`). `KARST_WSS` takes precedence: it is KARST's
/// own carrier, chosen explicitly; combined with a proxy it rides THROUGH it (looks
/// like HTTPS *and* uses an external PT — defense in depth).
fn carrier_adapter(proxy: Option<SocketAddr>, isolation: &str) -> Arc<dyn TransportAdapter> {
    let host = std::env::var("KARST_WSS").ok().filter(|h| !h.is_empty());
    let intent = carrier_from(host.is_some(), proxy.is_some());
    // `intent` is derived from exactly these two inputs, so its prerequisites are
    // present by construction. Panicking here is deliberate: falling back to another
    // carrier would be the silent downgrade this whole layer exists to prevent.
    adapter_for(intent, proxy, host.as_deref(), isolation)
        .expect("the intent carrier's prerequisites are the inputs that derived it")
}

/// Дев-capability для ЛОКАЛЬНОГО теста: секрет `[0x33;32]` ПУБЛИЧЕН и совпадает
/// с тем, что раздаёт `karst-relay`. Кто угодно может его подделать — это НЕ
/// «провижининг работает». Настоящая выдача capability (§7.2, от issuer) —
/// отдельный слой, здесь его нет.
pub fn dev_capability() -> Capability {
    Capability {
        capability_id: [0xCA; 16],
        scope: Scope::MessageDelivery,
        // Bulk transfers are inherently many small packets: MAX_PACKET_SIZE (1400) pins the chunk
        // size for traffic-shaping, so a single ~90 KiB image is ~90 one-packet requests, and a
        // multi-image post fanned to several contacts is thousands. The old 100-request / 1 MiB
        // window let barely ONE image through per 10 min (the rest backpressured into the outbox
        // for the next window — the "only the first photo arrived" bug). This is the DEV/LOCAL
        // credential (karst-relay dev mode) — make it generous; real per-capability quotas for a
        // public relay (how much one PoW buys) are a separate economic decision (§7.2/§19).
        quota: Quota { max_requests: 1_000_000, max_bytes: 1 << 30, window_secs: 600 },
        not_before: 0,
        not_after: u32::MAX,
        secret: [0x33; 32],
    }
}

/// §7 slice 4a — earn a capability from a PUBLIC relay by solving its proof-of-work
/// (`karst join`). No account or identity is involved: the capability is anonymous, so a
/// throwaway can knock without a stable identity ever touching the relationship. The caller
/// persists the returned capability (0600) and uses it for sends, exactly like an imported
/// invite. A relay that is not Public answers with a rejection.
pub fn earn_capability(relay: &Relay) -> Result<Capability, String> {
    relay
        .transport()
        .join()
        .map_err(|e| format!("join failed: {e}"))
}

/// What one backfill pass managed to do (see `earn_missing_capabilities`).
#[derive(Debug, Default)]
pub struct CapabilityBackfill {
    /// How many `(channel, relay)` pairs earned their own credential this pass.
    pub earned: usize,
    /// The pairs still without one, and why — `(proxy index, relay-id prefix, reason)`. A
    /// PRESENT list is the normal offline outcome, not an error: the channel simply cannot send
    /// through that relay yet, and the next pass will try again.
    pub still_missing: Vec<(u32, String, String)>,
}

/// Earn a per-channel admission credential wherever one is missing (A8-4).
///
/// Every live proxy needs its OWN credential at every relay, because the `capability_id` travels
/// in the clear on each deposit and one shared across channels is what lets a relay put them back
/// together — over Tor, where `Peer::scope_for` already gives every handle its own circuit, it is
/// the only thing that does. Issuance is what has to change: the store is already keyed per slot.
///
/// The price, stated rather than hidden: a Public relay's door is proof-of-work, so N channels
/// means solving it N times, and the account's total metered throughput at that relay grows N-fold
/// because the quota is per `capability_id`. Both are the cost of not being linkable; neither is
/// a reason to share one credential.
///
/// **Offline is a first-class outcome.** `earn_capability` needs a round trip, so a channel
/// created without a network gets nothing — and that must not be silent, or "this proxy cannot
/// send" reads as a bug forever. Each failure is REPORTED, and because the pass only ever fills
/// gaps it is safe to run again on every reconnect: a channel that already has its own credential
/// is skipped without a request, so a repeat pass costs nothing.
///
/// A relay whose door is invite-only has no self-serve issuance at all, so it fails here every
/// time — that is why `import-cap` writes a SHARED credential (`Store::save_shared_capability_for`)
/// and why doing so is an explicit call with its own doc about the linkage it reinstates.
pub fn earn_missing_capabilities(root: &Store, relays: &[Relay]) -> CapabilityBackfill {
    let mut out = CapabilityBackfill::default();
    for entry in root.load_proxies() {
        let p = root.as_proxy(entry.index);
        for relay in relays {
            match p.has_own_capability_for(&relay.id) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => {
                    // An unreadable credential file is loud everywhere else (see
                    // `load_capabilities`); earning over the top of it would write a fresh map and
                    // silently drop credentials the user still holds.
                    out.still_missing.push((
                        entry.index,
                        relay.id.hex()[..16].to_string(),
                        format!("credential store unreadable: {e}"),
                    ));
                    continue;
                }
            }
            match earn_capability(relay) {
                Ok(cap) => match p.save_capability_for(&relay.id, &cap) {
                    Ok(()) => out.earned += 1,
                    Err(e) => out.still_missing.push((
                        entry.index,
                        relay.id.hex()[..16].to_string(),
                        format!("earned but not stored: {e}"),
                    )),
                },
                Err(e) => {
                    out.still_missing.push((entry.index, relay.id.hex()[..16].to_string(), e))
                }
            }
        }
    }
    out
}

// ----- §12 4c: opt-in discovery (contact code) -----
//
// A user turns discovery ON to become findable by a RANDOM, rotatable, revocable contact code
// (see `node::discovery`). Nothing here is derived from the identity key, so the code can be
// rotated or dropped without touching the permanent identity. There are deliberately no chooseable
// usernames (a chooseable name is squattable); the code is unguessable random bytes.

/// The location descriptor for the relay we are talking to (relay-id + the address we dialed).
fn relay_descriptor(relay: &Relay) -> node::protocol::RelayDescriptor {
    node::protocol::RelayDescriptor {
        noise_pub: relay.id.noise_pub,
        fetch_pub: relay.id.fetch_pub,
        addrs: vec![relay.addr.to_string()],
        quic_addrs: Vec::new(),
    }
}

/// The current contact code if discovery is on, else `None`. Local only — no relay contacted.
pub fn discovery_code(store: &Store) -> Result<Option<String>, String> {
    if !store.has_discovery() {
        return Ok(None);
    }
    let secret = store.load_discovery().map_err(|e| format!("discovery key: {e}"))?;
    Ok(Some(node::discovery::encode_code(&node::discovery::public_of(&secret))))
}

/// Turn discovery ON (minting a random key on first use) and publish a record at `relay` so the
/// contact code resolves to this account's IK + location. Returns the contact code to share.
pub fn discovery_publish(store: &Store, relay: &Relay, now: u64) -> Result<String, String> {
    use node::discovery;
    let acct = store.load_account().map_err(|e| format!("account: {e}"))?;
    if !store.has_discovery() {
        store.save_discovery(&crate::blob::random32()).map_err(|e| format!("minting discovery key: {e}"))?;
    }
    let secret = store.load_discovery().map_err(|e| format!("discovery key: {e}"))?;
    let dpub = discovery::public_of(&secret);
    let location = relay_descriptor(relay);
    let expiry = now.saturating_add(discovery::DEFAULT_TTL_SECS);
    let ik_sig = node::discovery::sign_binding(&acct, &dpub, &location, expiry, false);
    let record = discovery::DiscoveryRecord {
        discovery_pub: dpub,
        ik: acct.identity_public(),
        location: location.clone(),
        expiry,
        single_use: false,
        ik_sig,
    };
    let write_sig = discovery::sign(&secret, &discovery::write_msg(&dpub, &record.ik, &location, expiry, false));
    let ok = relay
        .transport()
        .publish_discovery(&record, &write_sig)
        .map_err(|e| format!("publishing discovery record: {e}"))?;
    if !ok {
        return Err("the relay rejected the discovery record".into());
    }
    Ok(discovery::encode_code(&dpub))
}

/// TTL for an invite code — short (unlike the year-long persistent code), so an unused invite
/// lapses instead of lingering. Since the row is no longer destroyed by the first read (see
/// [`discovery_one_time`]), this TTL, together with an explicit revoke, is what bounds how long a
/// leaked invite keeps resolving — hence days, not a week.
pub const INVITE_TTL_SECS: u64 = 2 * 24 * 60 * 60;

/// Mint an INVITE code: a fresh random discovery key of its own (it does not touch, and cannot
/// rotate, the persistent contact code), published as a second discovery row at `relay`. Returns
/// the code to hand to one person.
///
/// **A10-4 — the row is retired by its OWNER, not burned on read.** This used to be published
/// `single_use`, which made the relay delete it the moment anyone resolved it: the relay is the
/// one party that cannot know whether the invitee actually finished adding the contact, so a lost
/// response, a crash, a disk error during the local commit, a retry after an ambiguous network
/// failure — or simply an eavesdropper on the code getting there first — destroyed the invite for
/// good, and the invitee's only recourse was to ask for a new one. The invite is now an ordinary
/// short-lived row, so resolving it is IDEMPOTENT by construction (there is no state at the relay
/// for a retry to consume), and the secret that owns the row is KEPT so the person who can
/// actually tell it worked — the inviter — can retire it with [`revoke_invite`].
///
/// The trade, stated plainly: a captured code now resolves until it is revoked or expires
/// (`INVITE_TTL_SECS`) instead of until its first read. Burn-on-read was never a guarantee — the
/// relay is not trusted, and a hostile one could always re-serve a consumed row — so this trades a
/// best-effort property for a real one, and the code→IK binding stays IK-signed either way: an
/// invite can never resolve to a different identity, only to this one for longer.
///
/// The relay-side answer that would restore both halves is a two-phase redeem (lookup returns a
/// ticket; a separate idempotent redeem retires the row), which needs a wire change — recorded as
/// a residual in `docs/STATUS.md`, not attempted here.
pub fn discovery_one_time(store: &Store, relay: &Relay, now: u64) -> Result<String, String> {
    use node::discovery;
    let acct = store.load_account().map_err(|e| format!("account: {e}"))?;
    let secret = crate::blob::random32();
    let dpub = discovery::public_of(&secret);
    let location = relay_descriptor(relay);
    let expiry = now.saturating_add(INVITE_TTL_SECS);
    // Persist BEFORE publishing. The failure this ordering picks is the harmless one: a stored
    // secret whose publish never landed revokes a row that does not exist (a no-op), whereas the
    // reverse order can leave a row published at the relay with nothing on disk able to retire it.
    store
        .add_invite(crate::store::InviteRecord { secret, created_at: now, expiry }, now)
        .map_err(|e| format!("recording the invite: {e}"))?;
    let ik_sig = node::discovery::sign_binding(&acct, &dpub, &location, expiry, false);
    let record = discovery::DiscoveryRecord {
        discovery_pub: dpub,
        ik: acct.identity_public(),
        location: location.clone(),
        expiry,
        single_use: false,
        ik_sig,
    };
    let write_sig = discovery::sign(&secret, &discovery::write_msg(&dpub, &record.ik, &location, expiry, false));
    let ok = relay
        .transport()
        .publish_discovery(&record, &write_sig)
        .map_err(|e| format!("publishing invite: {e}"))?;
    if !ok {
        return Err("the relay rejected the invite".into());
    }
    Ok(discovery::encode_code(&dpub))
}

/// One outstanding invite, as the UI lists them: its code, when it was minted, when it lapses.
pub struct Invite {
    pub code: String,
    pub created_at: u64,
    pub expiry: u64,
}

/// The invites minted from this identity that can still resolve, oldest first. Local only — no
/// relay is contacted. Lapsed ones are omitted (their rows are gone at the relay too); they are
/// swept from disk the next time one is minted.
pub fn invites(store: &Store, now: u64) -> Result<Vec<Invite>, String> {
    let all = store.load_invites().map_err(|e| format!("invite list: {e}"))?;
    Ok(all
        .into_iter()
        .filter(|i| i.expiry > now)
        .map(|i| Invite {
            code: node::discovery::encode_code(&node::discovery::public_of(&i.secret)),
            created_at: i.created_at,
            expiry: i.expiry,
        })
        .collect())
}

/// Retire an invite: delete its row at `relay`, then forget its secret. Returns whether the relay
/// actually removed a row now (`false` = it had none — already lapsed, or never landed).
///
/// The relay half runs FIRST and its failure is NOT swallowed, for the same reason as
/// `discovery_off`: the stored secret is the only thing that can authorise the deletion, so
/// dropping it on a failed call would leave the invite published with nothing able to retire it,
/// while telling the user it is gone.
pub fn revoke_invite(store: &Store, relay: &Relay, code: &str, now: u64) -> Result<bool, String> {
    use node::discovery;
    let dpub = discovery::decode_code(code).ok_or("that is not a valid KARST invite code")?;
    let held = store.load_invites().map_err(|e| format!("invite list: {e}"))?;
    let invite = held
        .into_iter()
        .find(|i| discovery::public_of(&i.secret) == dpub)
        .ok_or("no invite of yours matches that code")?;
    let removed = if invite.expiry > now {
        let del_sig = discovery::sign(&invite.secret, &discovery::delete_msg(&dpub));
        relay
            .transport()
            .delete_discovery(dpub, &del_sig)
            .map_err(|e| format!("revoking the invite ({e}) — it is NOT revoked; try again"))?
    } else {
        false // already lapsed: the relay drops it on the next lookup, nothing to retire
    };
    store.remove_invite(&invite.secret).map_err(|e| format!("forgetting the invite: {e}"))?;
    Ok(removed)
}

/// Delete the discovery record at `relay` (best-effort; needs the current key). Returns whether a
/// record was actually removed.
fn discovery_delete_at(store: &Store, relay: &Relay) -> Result<bool, String> {
    use node::discovery;
    let secret = store.load_discovery().map_err(|_| "discovery is off (no key)".to_string())?;
    let dpub = discovery::public_of(&secret);
    let del_sig = discovery::sign(&secret, &discovery::delete_msg(&dpub));
    relay
        .transport()
        .delete_discovery(dpub, &del_sig)
        .map_err(|e| format!("deleting discovery record: {e}"))
}

/// Turn discovery OFF: delete the record at `relay` and remove the local key. Returns whether the
/// relay actually removed the record NOW — `false` means the relay was unreachable (or already had
/// nothing), so the record lingers until it expires. The local key is always cleared regardless.
pub fn discovery_off(store: &Store, relay: &Relay) -> Result<bool, String> {
    // Retire the PUBLISHED record first, and do not swallow the failure. The local discovery key
    // is the ONLY thing that can authorise that deletion, so dropping it before the relay confirms
    // leaves the record published with nothing able to retire it — while the user is told
    // discovery is off (A6-7). On failure the key is KEPT so a retry is possible.
    let removed = if store.has_discovery() {
        discovery_delete_at(store, relay)
            .map_err(|e| format!("could not retire the published record ({e}) — discovery is NOT off; the key is kept so you can retry"))?
    } else {
        false
    };
    store.delete_discovery().map_err(|e| format!("removing discovery key: {e}"))?;
    Ok(removed)
}

/// Rotate the contact code: retire the old one (delete its record + overwrite the key) and publish
/// a fresh one. The identity (IK) is unchanged, so existing contacts are unaffected. Returns the
/// new contact code.
pub fn discovery_rotate(store: &Store, relay: &Relay, now: u64) -> Result<String, String> {
    if store.has_discovery() {
        let _ = discovery_delete_at(store, relay);
    }
    store.save_discovery(&crate::blob::random32()).map_err(|e| format!("minting discovery key: {e}"))?;
    discovery_publish(store, relay, now)
}

/// How far our clock may be BEHIND the publisher's before we call a record expired. Only ever
/// makes us more lenient: a record is refused solely when it is expired even after the allowance.
pub const DISCOVERY_CLOCK_SKEW_SECS: u64 = 5 * 60;

/// What a resolver says when every relay it could ask answered, and none of them holds the row.
const CODE_UNKNOWN: &str = "no one is published under that code (it may have expired or been turned off)";

/// One relay's verified answer for `dpub`. `Ok(None)` means THAT RELAY ANSWERED and has no such
/// row — a definite "unknown code" — while `Err` means we got no usable answer from it (it was
/// unreachable, or the row it served failed verification). Keeping the two apart is what lets a
/// multi-relay lookup report the accurate reason instead of whichever relay failed last.
fn lookup_verified(
    relay: &Relay,
    dpub: [u8; 32],
    now: u64,
) -> Result<Option<node::discovery::DiscoveryRecord>, String> {
    use node::discovery;
    let Some(rec) = relay
        .transport()
        .lookup_discovery(discovery::discovery_pseudonym(&dpub))
        .map_err(|e| format!("discovery lookup: {e}"))?
    else {
        return Ok(None);
    };
    if rec.discovery_pub != dpub {
        return Err("the relay returned a record for a different code — refusing".into());
    }
    if !discovery::verify_binding(&rec) {
        return Err("the record's identity signature is invalid — refusing".into());
    }
    // `expiry` rides INSIDE the signed binding, but the relay is not a trusted anchor: an honest
    // one drops stale records, a hostile one can replay an old — still validly signed — record
    // forever. Without this check expiry had no client-side force at all, so retiring a location,
    // limiting an invite, and revocation-by-expiry were all unenforceable (CRYPTO-21).
    if rec.expiry.saturating_add(DISCOVERY_CLOCK_SKEW_SECS) <= now {
        return Err("that contact code has expired — ask for a fresh one".into());
    }
    // A far-future expiry means the publisher (or a tampering relay) exceeded the protocol's own
    // ceiling, so the record can never be pinned open beyond `MAX_TTL_SECS`.
    if rec.expiry > now.saturating_add(discovery::MAX_TTL_SECS + DISCOVERY_CLOCK_SKEW_SECS) {
        return Err("that record claims an impossible lifetime — refusing".into());
    }
    Ok(Some(rec))
}

/// Resolve a contact code at `relay` to the IK + location it points at. Verifies the code→IK
/// binding itself (the relay never vouches), so a tampered or wrong-code record is refused, and
/// enforces the record's own `expiry` against `now`.
pub fn find_contact(
    relay: &Relay,
    code: &str,
    now: u64,
) -> Result<([u8; 32], node::protocol::RelayDescriptor), String> {
    let dpub = node::discovery::decode_code(code).ok_or("that is not a valid KARST contact code")?;
    let rec = lookup_verified(relay, dpub, now)?.ok_or_else(|| CODE_UNKNOWN.to_string())?;
    Ok((rec.ik, rec.location))
}

/// Resolve a contact code across the WHOLE relay set, not just the primary. A discovery row lives
/// at the relay its owner published it to, so a contact whose home relay is one of your BACKUPS
/// was simply unfindable while the lookup only ever asked `relays[0]` — the code was reported as
/// "no one is published under that" even though you were connected to the relay holding it.
///
/// Returns the resolved IK and the location the record itself is signed for. The first relay that
/// has it wins. Failure reporting follows what was actually learned: if ANY relay answered and had
/// no such row, the code is genuinely unknown and that is what the user is told — a second relay
/// being down must not turn "nobody is published under this code" into a network error, which
/// reads as "your connection is broken" for a code that simply does not exist. Only when no relay
/// gave a usable answer does a transport/verification error surface.
pub fn find_contact_multi(
    relays: &[Relay],
    code: &str,
    now: u64,
) -> Result<([u8; 32], node::protocol::RelayDescriptor), String> {
    // Decoded ONCE: a malformed code is not a per-relay failure, and repeating the same complaint
    // as many times as there are relays would only confuse where it came from.
    let dpub = node::discovery::decode_code(code).ok_or("that is not a valid KARST contact code")?;
    let mut answered_without_it = false;
    let mut first_err: Option<String> = None;
    for relay in relays {
        match lookup_verified(relay, dpub, now) {
            Ok(Some(rec)) => return Ok((rec.ik, rec.location)),
            Ok(None) => answered_without_it = true,
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    if answered_without_it {
        return Err(CODE_UNKNOWN.to_string());
    }
    Err(first_err.unwrap_or_else(|| "no relay configured".to_string()))
}

/// Add a contact from a contact/invite code: resolve it across the relay set and commit the whole
/// local record in ONE place — the roster row, the confirmed flag, which proxy of yours reaches
/// them, and WHERE they said they are ([`store::ContactEndpoint`]).
///
/// **A10-4 / A10-6, the local half.** This commit used to be four separate calls in the desktop
/// command, the last two with their errors dropped (`let _ = …`), so a failure past the roster
/// write left a contact that is added but not confirmed, or confirmed but untagged, and said
/// nothing. Every step here propagates, and every step is idempotent, so the honest answer to a
/// half-finished add is to run it again with the same code: resolving is now repeatable
/// (`discovery_one_time` no longer publishes a row the first read destroys), and re-committing an
/// already-committed step is a no-op. That is what makes "retry" a real recovery instead of the
/// advice that used to strand the invite.
///
/// Returns the contact's IK.
pub fn add_contact_by_code(
    store: &Store,
    relays: &[Relay],
    code: &str,
    name: &str,
    proxy: u32,
    now: u64,
) -> Result<[u8; 32], String> {
    let (ik, location) = find_contact_multi(relays, code.trim(), now)?;
    let mut cs = store.load_contacts().map_err(|e| format!("contacts: {e}"))?;
    if !cs.iter().any(|c| c.ik == ik) {
        // Empty name resolves to the peer's own profile name / a short IK at display time.
        cs.push(store::ContactRecord { name: name.trim().to_string(), ik, verified: false });
        store.save_contacts(&cs).map_err(|e| format!("saving contacts: {e}"))?;
    }
    // Looking someone up by their code is an EXPLICIT add → a confirmed contact (unlocks their
    // name/posts as they arrive), not a mere conversation.
    store.set_unconfirmed(ik, false).map_err(|e| format!("confirming the contact: {e}"))?;
    store.set_contact_proxy(ik, proxy).map_err(|e| format!("tagging the contact's channel: {e}"))?;
    // The route the CONTACT signed for themselves — see `relays_for_contact` for what uses it.
    store
        .set_contact_endpoint(ik, &store::ContactEndpoint { relay: location, discovered_at: now })
        .map_err(|e| format!("recording where they are reachable: {e}"))?;
    Ok(ik)
}

/// Order the relay set for reaching `ik`: the relay their contact code named goes FIRST, then the
/// rest in their existing order.
///
/// This is the routing half of A10-6. Their signed `location` is the only statement about where
/// they poll; without it a first contact is attempted at OUR primary, where a contact who homes
/// elsewhere has no prekey bundle and no mailbox anyone reads — the send fails for a reason that
/// looks like "the relay doesn't know them" rather than "we asked the wrong relay".
///
/// Two conditions, both load-bearing. The relay must be one we already hold: a descriptor is a
/// route candidate, not an instruction to dial an address on a peer's say-so, and adopting an
/// unknown relay is a deliberate, separate, user-driven step (auto-earning admission on discovery
/// is a stated non-goal). And we must hold a credential for it: `send_session` hard-fails without
/// one, so preferring a relay we cannot present a capability to would turn a working send into a
/// failure — the preference must only ever be able to help.
pub fn relays_for_contact(store: &Store, relays: &[Relay], ik: &[u8; 32]) -> Vec<Relay> {
    let mut out = relays.to_vec();
    let Some(ep) = store.contact_endpoint(ik) else { return out };
    let held = out.iter().position(|r| {
        r.id.noise_pub == ep.relay.noise_pub && r.id.fetch_pub == ep.relay.fetch_pub
    });
    if let Some(pos) = held {
        if pos > 0 && store.has_capability_for(&out[pos].id) {
            let theirs = out.remove(pos);
            out.insert(0, theirs);
        }
    }
    out
}

/// Ask a relay to advertise its policy (blob persistence/TTL/caps, PoW door). Operator-declared —
/// the caller decides which fields to trust and how far (see `RelayPolicy`).
pub fn relay_policy(relay: &Relay) -> Result<node::protocol::RelayPolicy, String> {
    relay.transport().get_policy().map_err(|e| format!("policy fetch failed: {e}"))
}

/// §12 discovery — ask a relay which relays it knows about (node-list). Lets a client learn of
/// more relays than it was handed. Each descriptor self-authenticates on dial (its `noise_pub`
/// is verified in the Noise handshake), so a bad entry only wastes a connection attempt.
pub fn discover_relays(relay: &Relay) -> Result<Vec<node::protocol::RelayDescriptor>, String> {
    relay
        .transport()
        .get_node_list()
        .map_err(|e| format!("node-list fetch failed: {e}"))
}

/// Dial a heard descriptor's address hint and return an address the relay declares for ITSELF.
///
/// CRYPTO-23. `relay::gossip::verify` proves that whoever answers at `hint` holds `d.noise_pub`
/// and serves a node-list containing the full relay-id — but it never asks whether `hint` is an
/// address of that relay. A transparent TCP/WebSocket proxy in front of an honest relay passes
/// both checks: the Noise handshake terminates at the real relay, so the byte stream really is
/// authenticated, while the client stores the PROXY as its route. That hands whoever put the
/// address into the node-list a permanent vantage point on the route — client IP on a direct
/// carrier, connection timing, volume, and selective delay/drop — without ever breaking Noise.
///
/// The fix is not to compare `hint` against the relay's self-descriptor: comparing addresses
/// needs canonicalization rules (host vs IP, carrier, port, path) and every rule that says "these
/// two strings are different" also refuses an honest relay reached by a different spelling. So
/// the hint is used ONLY as a place to dial, and the address that gets STORED comes out of the
/// authenticated self-descriptor. An address nobody but the gossiping peer vouches for is then
/// never adopted as a route, whatever it looks like.
///
/// Returns `None` when the dial fails, when the relay does not advertise its own full relay-id
/// (it is then undiscoverable by design — see `gossip::verify`), or when every address it
/// declares is one we may not dial (`allow_private`, the SSRF gate — the self-declared address
/// is peer-controlled data too, just controlled by a different peer).
fn verified_self_address(
    d: &node::protocol::RelayDescriptor,
    hint: &str,
    allow_private: bool,
) -> Option<String> {
    if !karst_transport::transport::addr_is_dialable(hint, allow_private) {
        return None; // never dial into private/loopback space on a peer's say-so (A3-12)
    }
    let dest = Dest::parse(hint).ok()?;
    let list = SocketTransport::new(dest, d.noise_pub).get_node_list().ok()?;
    // Noise authenticated the far end as the holder of `d.noise_pub`; among the descriptors IT
    // serves, its own entry (full relay-id: noise AND fetch key) is the only one it vouches for
    // with that key, so its addresses are the only ones this exchange can attribute to it.
    let self_entry = list.iter().find(|e| e.noise_pub == d.noise_pub && e.fetch_pub == d.fetch_pub)?;
    self_entry.addrs.iter().find(|a| karst_transport::transport::addr_is_dialable(a, allow_private)).cloned()
}

/// §12 — discover relays from a known one and IMPORT the verified ones into this account's
/// multi-homing set (secondaries). This is the client side of the STATUS "auto-dial" pin:
/// a discovered relay is added ONLY after a dial confirms it serves the claimed full relay-id —
/// so the client never multi-homes onto a relay it hasn't confirmed (no reflection, no fetch-key
/// spoof) — and the route that gets stored is the one the relay itself advertises, not the
/// address the gossiping peer supplied (`verified_self_address`, CRYPTO-23). Dedups against the
/// primary and existing secondaries. Returns how many new relays were added.
pub fn import_discovered_relays(store: &Store, from: &Relay) -> Result<usize, String> {
    let discovered = discover_relays(from)?;
    let mut extras = store.load_extra_relays().map_err(|e| format!("relay list: {e}"))?;
    // The relay we are discovering FROM is this account's primary — dedup against it. Derived
    // from `from` itself, NOT a persisted net.dat (which the CLI never writes), so
    // `karst relays --add` works without a prior set-net.
    let primary_id = node::protocol::RelayDescriptor {
        noise_pub: from.id.noise_pub,
        fetch_pub: from.id.fetch_pub,
        addrs: vec![],
        quic_addrs: Vec::new(),
    }
    .relay_id_hex();
    let mut known: std::collections::HashSet<String> = std::iter::once(primary_id).collect();
    for (_, id) in &extras {
        known.insert(id.to_lowercase());
    }
    // Optional policy preference: when set, only multi-home onto relays whose ADVERTISED policy
    // matches (e.g. keep files across a restart). The advertisement is operator-declared — for the
    // durable case a client can later PROVE it (`verify_durability`); ephemeral stays a claim.
    let prefs = store.load_relay_prefs().unwrap_or_default();
    let want_persistence = prefs.prefer_persistence;
    let want_mail = prefs.prefer_mail_durability;
    // A relay's node-list is attacker-influenceable, and importing it makes US dial the addresses
    // in it — so a hostile PUBLIC relay could otherwise walk the user's own LAN, or hit loopback
    // services, one auto-discovery at a time (A3-12, client side). Private destinations are
    // accepted only when the relay we are importing FROM is itself private/loopback: that is a
    // local or LAN deployment the user configured deliberately, so its peers being local is
    // consistent. Relays added explicitly (invite / config) are unaffected — this gates only
    // AUTO-discovery.
    let allow_private = !karst_transport::transport::addr_is_dialable(&from.addr.to_string(), false);
    let mut added = 0usize;
    for d in discovered {
        let id_hex = d.relay_id_hex();
        if known.contains(&id_hex) || d.addrs.is_empty() {
            continue;
        }
        // VERIFY-BEFORE-ADD: dial and confirm the relay serves its own full relay-id before
        // trusting it enough to route our mail through it — and take the ROUTE from what it
        // says about itself, not from the peer that told us about it (CRYPTO-23).
        let Some(addr) = verified_self_address(&d, &d.addrs[0], allow_private) else {
            continue;
        };
        // POLICY PREFERENCE: skip a verified relay whose advertised policy does not match.
        // ONE fetch covers both knobs — asking twice would double the dial cost and could even
        // straddle a policy change.
        if want_persistence.is_some() || want_mail.is_some() {
            let Ok(dest) = Dest::parse(&addr) else { continue };
            let Ok(p) = SocketTransport::new(dest, d.noise_pub).get_policy() else { continue };
            if want_persistence.is_some_and(|want| p.blob_persistence != Some(want)) {
                continue; // mismatch, disabled, or unknown → skip
            }
            if want_mail.is_some_and(|want| p.mailbox_durability != want) {
                continue; // R2-5: this account wants its queued mail to survive a restart
            }
        }
        extras.push((addr, id_hex.clone()));
        known.insert(id_hex);
        added += 1;
    }
    if added > 0 {
        store.save_extra_relays(&extras).map_err(|e| format!("saving relays: {e}"))?;
    }
    Ok(added)
}

/// Идентификатор узла вне канала: Noise-pub (аутентифицирует relay при
/// handshake) ‖ fetch-auth-pub (доказательство владения mailbox). Бинарь relay
/// печатает как один hex `relay-id`.
#[derive(Clone, Copy)]
pub struct RelayId {
    pub noise_pub: [u8; 32],
    pub fetch_pub: [u8; 32],
}

impl RelayId {
    /// Разобрать 128-hex (64 байта: noise ‖ fetch).
    pub fn parse(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("relay-id не hex: {e}"))?;
        if bytes.len() != 64 {
            return Err(format!("relay-id должен быть 64 байта (128 hex), дано {}", bytes.len()));
        }
        let mut noise_pub = [0u8; 32];
        let mut fetch_pub = [0u8; 32];
        noise_pub.copy_from_slice(&bytes[..32]);
        fetch_pub.copy_from_slice(&bytes[32..]);
        Ok(RelayId { noise_pub, fetch_pub })
    }

    /// The canonical 128-hex form (`noise_pub ‖ fetch_pub`, lowercase) — the key everything
    /// relay-scoped is stored under. Same string `RelayDescriptor::relay_id_hex` produces, so a
    /// discovered relay and a configured one land on the same key.
    pub fn hex(&self) -> String {
        node::protocol::RelayDescriptor { noise_pub: self.noise_pub, fetch_pub: self.fetch_pub, addrs: vec![], quic_addrs: Vec::new() }
            .relay_id_hex()
    }
}

/// Отправить одно сообщение получателю `to_pub` через `relay` (внутри
/// Noise-сессии). `now` — часы вызывающего, на провод не уходят.
pub fn send_message(
    relay: &Relay,
    cap: Capability,
    to_pub: &[u8; 32],
    plaintext: &[u8],
    now: u64,
) -> Response {
    let transport = relay.transport();
    // client_addr = capability_id: стабильный per-отправитель идентификатор для
    // привязки cookie (скелет; настоящий адрес — сетевой источник).
    let addr = cap.capability_id;
    let mut client = Client::new(transport, cap, &addr);
    let recipient_pub = x25519_dalek::PublicKey::from(*to_pub);
    client.send(&recipient_pub, plaintext, now)
}

/// Забрать и расшифровать входящие для нашей `identity` (внутри Noise-сессии;
/// fetch-auth поверх). `Ok(vec)` — выборка (может быть пустой; `None` = не
/// расшифровалось); `Err` — недоступен/протокол/отказ auth (отделено от «пусто»).
pub fn fetch_messages(
    relay: &Relay,
    identity: Identity,
    now: u64,
) -> Result<Vec<Option<Vec<u8>>>, String> {
    let transport = relay.transport();
    let fetch_pub = x25519_dalek::PublicKey::from(relay.id.fetch_pub);
    let mut recipient = Recipient::new(transport, identity, fetch_pub);
    recipient.receive(now)
}

/// §12: опубликовать §2.1-bundle нашего `account` у relay (чтобы другие могли
/// инициировать к нам сессию). Внутри Noise-сессии, cookie + ownership-proof.
pub fn publish_bundle(
    relay: &Relay,
    account: Account,
    cap: Capability,
    now: u64,
) -> PublishResponse {
    let transport = relay.transport();
    let fetch_pub = x25519_dalek::PublicKey::from(relay.id.fetch_pub);
    let mut peer = Peer::new(transport, account, cap, fetch_pub);
    // A plain bundle publish advertises NO one-time prekeys (fresh account has none anyway).
    peer.publish(now)
}

/// SEC-43: cap on the number of DISTINCT senders simultaneously holding an in-flight reassembly.
/// The per-sender cap (`content::MAX_CONCURRENT_TRANSFERS`) already stops ONE busy contact from
/// filling memory, but says nothing about the NUMBER of contacts — an IK is free to mint, so a
/// flood of fresh sender IKs each starting one transfer would otherwise grow this map (and the
/// worker's `HashMap<[u8; 32], Reassembler>`) without limit. 64 is generous for real use (simultaneous
/// inbound transfers from that many distinct people at once is already an unusual amount of
/// traffic for a P2P messenger) while bounding the map to a fixed size regardless of how many
/// identities an attacker mints.
pub const MAX_REASSEMBLY_SENDERS: usize = 64;
/// SEC-43: cap on TOTAL in-flight reassembly bytes across every sender combined, checked against
/// each manifest's DECLARED size (`content::manifest_declared_size`), NOT arrived chunk bytes — a
/// bare manifest carries no payload, so gating on arrived bytes would let a flood of manifests
/// with no chunks ever sent reserve every slot for free before the count ever moved. One sender's
/// worst case alone is already ~4.5 MiB (`MAX_CONCURRENT_TRANSFERS` × the largest transfer kind, a
/// gallery) — multiplying that by `MAX_REASSEMBLY_SENDERS` would still let a flood reach hundreds
/// of MiB, so the cross-sender total needs its OWN bound, independent of sender count. 8 MiB
/// comfortably covers dozens of concurrent avatar/file-sized transfers (the realistic case) while
/// keeping a flood's worst case a small, fixed amount of committed memory.
pub const MAX_REASSEMBLY_TOTAL_BYTES: usize = 8 * 1024 * 1024;

/// Reap idle partials across EVERY sender's `Reassembler`, then drop any sender entry left
/// holding nothing (`in_flight() == 0`) so the outer map's size reflects only senders that
/// actually pin RAM. Called from `offer_reassembly` on every receive, and should ALSO be called
/// on the bare poll cadence (SEC-43): the per-`Reassembler` `reap_stale` only fires when THAT
/// SAME sender's next manifest calls `start_transfer` — a sender who starts a transfer and then
/// goes silent would never trigger it again, pinning RAM until the account is switched or the
/// process exits. Driving this from the ordinary receive path instead means it self-heals within
/// `content::STALE_PARTIAL_SECS` of wall-clock time as long as the app keeps polling, with no
/// dependence on that same sender ever sending anything again. Returns how many stale partials
/// were dropped (diagnostic).
pub fn reap_reassemblers(
    reasm: &mut std::collections::HashMap<[u8; 32], content::Reassembler>,
    now: u64,
) -> usize {
    let mut evicted = 0;
    reasm.retain(|_, re| {
        evicted += re.reap_stale(now);
        re.in_flight() > 0
    });
    evicted
}

/// Sum of `Reassembler::bytes_in_flight` (ARRIVED bytes) across every sender — a diagnostic
/// figure, NOT what the admission check below bounds (see `total_declared_reassembly_bytes`).
pub fn total_reassembly_bytes(reasm: &std::collections::HashMap<[u8; 32], content::Reassembler>) -> usize {
    reasm.values().map(content::Reassembler::bytes_in_flight).sum()
}

/// Sum of `Reassembler::declared_bytes_in_flight` (the sender's COMMITTED manifest size, not
/// arrived bytes) across every sender — the quantity `MAX_REASSEMBLY_TOTAL_BYTES` actually bounds.
pub fn total_declared_reassembly_bytes(
    reasm: &std::collections::HashMap<[u8; 32], content::Reassembler>,
) -> u64 {
    reasm.values().map(|re| re.declared_bytes_in_flight() as u64).sum()
}

/// Feed one envelope into the per-sender pool, enforcing the GLOBAL bounds above before it ever
/// reaches a per-sender `Reassembler`. Only a MANIFEST (a genuinely new transfer id, checked via
/// `has_transfer` so an idempotent resend of an already-admitted manifest is never refused) is
/// admission-checked — a chunk for an already-tracked transfer, or an orphan chunk that will be
/// refused for its own reasons inside `Reassembler::offer`, never allocates a pool slot.
///
/// The byte cap gates on the manifest's DECLARED size (`manifest_declared_size`), never on what
/// has arrived: a bare manifest carries zero payload, so an arrived-bytes check would let a flood
/// of manifests with no chunks EVER sent reserve every slot for free, becoming visible only once
/// chunks started streaming in — by which point admission had already been granted to all of
/// them. Declared-size accounting closes that off: the sender's commitment is charged the moment
/// the manifest is accepted, so the running total never exceeds the cap regardless of whether any
/// chunk ever follows.
///
/// DELIBERATELY never evicts another sender's already-admitted (legitimate, in-progress)
/// transfer to make room for a new one: the two callers here are equally entitled, there is no
/// signal to prefer the newcomer, and silently destroying real progress with no error to either
/// side is exactly the "silent loss" this must not do. Instead a new transfer that would exceed
/// either cap is REFUSED (loud `Err`, mirroring the existing per-sender "too many concurrent
/// transfers" rejection) — the same category as a manifest already rejected for being over a
/// per-kind size/chunk-count limit, just enforced one level up.
pub fn offer_reassembly(
    reasm: &mut std::collections::HashMap<[u8; 32], content::Reassembler>,
    sender: [u8; 32],
    c: content::Content,
    now: u64,
) -> Result<Option<content::Assembled>, String> {
    reap_reassemblers(reasm, now);
    if let Some(id) = content::manifest_transfer_id(&c) {
        let already_tracked = reasm.get(&sender).is_some_and(|re| re.has_transfer(id));
        if !already_tracked {
            let is_new_sender = !reasm.contains_key(&sender);
            if is_new_sender && reasm.len() >= MAX_REASSEMBLY_SENDERS {
                return Err(format!(
                    "too many senders with in-flight transfers (cap {MAX_REASSEMBLY_SENDERS})"
                ));
            }
            // This runs BEFORE `Reassembler::offer`, i.e. before the per-kind size validation
            // that normally rejects an absurd declared size — so `declared_new` here is still the
            // RAW attacker-declared value (a `FileManifest` can claim `size: u64::MAX`).
            // `saturating_add` keeps the comparison meaningful instead of wrapping/panicking: any
            // honest manifest is unaffected, and an absurd one is refused here (loud Err) rather
            // than by luck once it reaches the per-kind check downstream.
            let declared_new = content::manifest_declared_size(&c).unwrap_or(0);
            let declared_total = total_declared_reassembly_bytes(reasm);
            if declared_total.saturating_add(declared_new) > MAX_REASSEMBLY_TOTAL_BYTES as u64 {
                return Err(format!(
                    "in-flight reassembly memory at capacity (cap {MAX_REASSEMBLY_TOTAL_BYTES} \
                     bytes, this manifest commits to {declared_new} more)"
                ));
            }
        }
    }
    let entry = reasm.entry(sender).or_default();
    let result = entry.offer(c, now);
    if entry.in_flight() == 0 {
        // Nothing pinned (completed, refused, or a non-manifest/non-chunk passthrough) — drop the
        // entry now rather than waiting for the next reap, so an empty slot never counts against
        // MAX_REASSEMBLY_SENDERS.
        reasm.remove(&sender);
    }
    result
}

/// Persist the in-flight inline transfers held by a set of per-sender reassemblers.
///
/// Inline chunks were reassembled ONLY in RAM while their carrier messages had already been ACKed
/// — and an acked message is one the relay may delete. So a crash mid-transfer lost the file with
/// no record and no retry: the sender saw "delivered", the receiver had nothing to show or resume.
/// The large-file (blob) path was already crash-safe via pending downloads; this gives the inline
/// path the same property. Failures are reported, never silent.
pub fn save_reassemblers(
    store: &Store,
    reasm: &std::collections::HashMap<[u8; 32], content::Reassembler>,
) {
    let mut out: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    for (sender, re) in reasm {
        if re.in_flight() == 0 {
            continue;
        }
        match re.export() {
            Ok(b) => out.push((*sender, b)),
            Err(e) => eprintln!("warning: could not encode in-flight transfers: {e}"),
        }
    }
    match postcard::to_stdvec(&out) {
        Ok(blob) => {
            if let Err(e) = store.save_partials(&blob) {
                eprintln!("warning: could not persist in-flight transfers: {e}");
            }
        }
        Err(e) => eprintln!("warning: could not encode in-flight transfers: {e}"),
    }
}

/// Restore what [`save_reassemblers`] wrote. A failure is reported and yields "none in flight" —
/// the same outcome as before this state existed, never worse.
pub fn load_reassemblers(store: &Store) -> std::collections::HashMap<[u8; 32], content::Reassembler> {
    let mut map = std::collections::HashMap::new();
    let blob = match store.load_partials() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("warning: could not read in-flight transfers: {e}");
            return map;
        }
    };
    if blob.is_empty() {
        return map;
    }
    let entries: Vec<([u8; 32], Vec<u8>)> = match postcard::from_bytes(&blob) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("warning: could not decode in-flight transfers: {e}");
            return map;
        }
    };
    for (sender, bytes) in entries {
        match content::Reassembler::restore(&bytes) {
            Ok(re) => {
                map.insert(sender, re);
            }
            Err(e) => eprintln!("warning: dropping an unreadable in-flight transfer: {e}"),
        }
    }
    map
}

/// How many unconsumed one-time prekeys to keep published. A fetch consumes one; the batch
/// is topped back up to this on each publish. Small: it bounds the relay's per-IK store and
/// the sidecar, and exhaustion falls back to the 3-DH agreement anyway.
pub const OPK_TARGET: usize = 16;

/// Publish this account's bundle WITH a topped-up batch of one-time prekeys, persisting the
/// secrets in the sidecar so `recv_session` can accept openers that used them. This is the
/// end-to-end one-time-prekey publish path (the plain `publish_bundle` advertises none).
pub fn publish_with_opks(store: &Store, relay: &Relay, now: u64) -> Result<PublishResponse, String> {
    let account = store.load_account().map_err(|e| secret_load_err("account", e))?;
    // The credential for THIS relay (CRYPTO-24): creating a bundle slot is metered on the
    // reference relay (`handle_publish`), so presenting another relay's capability here is a
    // rejection, not a harmless extra field — it is what kept an account from ever becoming
    // reachable on its backup relays.
    let cap = store
        .load_capability_for(&relay.id)
        .map_err(|e| format!("cannot publish to this relay: {e}"))?;
    let transport = relay.transport();
    let fetch_pub = x25519_dalek::PublicKey::from(relay.id.fetch_pub);
    let mut peer = Peer::new(transport, account, cap, fetch_pub);

    // Restore the unconsumed OPKs, then top up to the target by minting the DEFICIT. Advertise
    // ONLY the freshly minted keys, never the whole held set: the relay appends a publish's
    // OPKs with no dedup, so re-advertising already-published-but-unconsumed keys stockpiles
    // duplicates and later hands the SAME OPK to two first-contacts (Bug C). Trade-off: after a
    // relay restart the relay loses the batch and this client, still holding those secrets,
    // won't re-offer them until consumption drops it below the target — meanwhile first
    // contacts fall back to 3-DH. Bounded and self-healing; correctness beats that efficiency.
    // Persist BEFORE publishing: the relay must never advertise an OPK whose secret we have not
    // durably stored, or an opener using it could not be accepted.
    //
    // Under the sessions flock: the prekey secrets share the session file (CRYPTO-26), so
    // topping them up is a read-modify-write that a concurrent send/receive would otherwise
    // interleave with — one of the two writes would drop the other's half. Publish is not on a
    // hot path, and no caller of this function holds the lock already (checked: nothing between
    // `publish_all` and the desktop/CLI entry points takes it).
    let _lock = store.lock_sessions().map_err(|e| format!("session lock: {e}"))?;
    peer.load_opks(&store.load_opks().map_err(|e| format!("reading one-time prekeys: {e}"))?);
    let fresh = if peer.opk_count() < OPK_TARGET {
        peer.add_opks(OPK_TARGET - peer.opk_count())
    } else {
        Vec::new()
    };
    store.save_opks(&peer.export_opks()).map_err(|e| format!("saving one-time prekeys: {e}"))?;
    Ok(peer.publish_advertising(&fresh, now))
}

/// Publish this account's bundle to EVERY relay in the set (multi-homing): the primary
/// (`relays[0]`) with a full one-time-prekey batch, each secondary with the bundle only.
/// This is what makes a contact able to FIRST-CONTACT you through any of your relays.
///
/// OPKs go to the primary ONLY. A one-time prekey secret is burned on first use, so
/// advertising the same batch on two relays would let a second contact bind a key the first
/// already consumed (the collision confirmed in the multi-homing tests). Secondaries publish
/// from a FRESH `load_account` (empty OPK batch → advertises none); first contact through a
/// secondary falls back to the 3-DH agreement.
///
/// Returns the PRIMARY's response — it drives the connection indicator. A secondary that is
/// unreachable or rejects is logged and skipped: a dead backup relay must not fail the whole
/// publish, the same resilience the receive path has.
///
/// NOTE, corrected (CRYPTO-24): publish is NOT capability-free. Refreshing a slot you already
/// own is unmetered, but CREATING one presents a capability proof and is charged
/// (`RelayNode::handle_publish`, CRYPTO-18) — which is exactly the first publish to a new
/// secondary. So each relay's own credential is loaded here, and a relay this account has no
/// credential for is skipped with a reason rather than published to under another's.
pub fn publish_all(store: &Store, relays: &[Relay], now: u64) -> Result<PublishResponse, String> {
    let (primary, secondaries) = relays.split_first().ok_or("no relays configured")?;
    let primary_resp = publish_with_opks(store, primary, now)?;
    for relay in secondaries {
        // Each relay gets ITS OWN credential (CRYPTO-24). A relay we hold none for is SKIPPED
        // with a reason, not published to under the primary's: that would be rejected there
        // anyway (creating a slot is metered) and would hand a second operator the same
        // `capability_id`, linking two otherwise-unrelated deployments' view of this account for
        // nothing in return.
        let cap = match store.load_capability_for(&relay.id) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("not publishing to secondary relay {}: {e}", relay.addr);
                continue;
            }
        };
        // Fresh account = empty OPK batch → advertises NONE (see the OPK note above).
        let account = store.load_account().map_err(|e| secret_load_err("account", e))?;
        match publish_bundle(relay, account, cap, now) {
            PublishResponse::Published => {}
            other => eprintln!("publish to secondary relay {}: {other:?}", relay.addr),
        }
    }
    Ok(primary_resp)
}

/// Load the pending-send ledger (see `store::PendingSend`), or an empty one if it cannot be
/// read. Best-effort on purpose: a corrupt or unreadable ledger must not stop a send — it only
/// degrades attribution of a FUTURE loss to "unknown" instead of a name, which is the honest
/// residual documented on `queue_and_note`, not a reason to fail an otherwise-good send.
fn load_ledger_or_empty(store: &Store) -> Vec<store::PendingSend> {
    store.load_send_ledger().unwrap_or_else(|e| {
        eprintln!("KARST: could not read the send ledger, starting empty this call: {e}");
        Vec::new()
    })
}

/// Persist the ledger, logging (not propagating) a failure. Same reasoning as
/// `load_ledger_or_empty`: the send this call was actually doing already succeeded or failed on
/// its own merits before this runs — a ledger write hiccup is a tracking regression, not a
/// reason to report a good send as broken.
fn save_ledger_best_effort(store: &Store, ledger: &[store::PendingSend]) {
    if let Err(e) = store.save_send_ledger(ledger) {
        eprintln!("KARST: could not save the send ledger: {e}");
    }
}

/// Durably record a lost send, logging (not propagating) a failure — same best-effort reasoning
/// as `save_ledger_best_effort`.
fn note_lost(store: &Store, peer_ik: [u8; 32], plaintext: &[u8], queued_at: u64, now: u64, reason: &str) {
    if let Err(e) = store.park_stranded_send(peer_ik, plaintext, queued_at, now, reason) {
        eprintln!("KARST: could not record a stranded send ({reason}): {e}");
    }
}

/// `Peer::queue` one payload against `to_ik`, returning its id and — if queuing it evicted an
/// OLDER entry to make room (`node::peer::Peer::queue`'s outbox cap silently drops the oldest
/// queued entry when full) — the ledger entry that eviction claimed. The caller must not record
/// that victim as lost until the save that makes the eviction REAL has landed: recording it
/// earlier could survive a crash that rolls the eviction back, reporting a message lost that is
/// actually still safely queued (see the call sites; this is why this function returns the
/// victim rather than parking it itself).
///
/// The victim is identified exactly, never by guesswork: outbox ids only ever increase, and
/// neither `queue` nor `flush_outbox` reorder the entries that survive (`flush_outbox` takes the
/// whole vec, filters it, and pushes survivors back in the SAME relative order), so whichever
/// entry the cap evicts is always the ledger's SMALLEST still-open id — PROVIDED the ledger
/// tracks the same set of ids the real outbox does. It can fall behind: a crash between a
/// PREVIOUS `queue`'s save and its ledger write leaves an outbox entry the ledger never learned
/// about, and if THAT untracked entry is what the cap evicts here, the ledger's candidate is
/// innocent — still safely queued. So the candidate is confirmed with `peer.is_queued` before
/// ever being named: if it's still there, the true victim is untracked and unidentifiable, and
/// nothing is reported rather than accusing the wrong message (a false "your message was lost"
/// is worse than a gap — see `PendingSend`).
fn queue_and_note(
    peer: &mut Peer<SocketTransport>,
    ledger: &[store::PendingSend],
    to_ik: &[u8; 32],
    plaintext: &[u8],
    now: u64,
) -> Result<(u64, Option<store::PendingSend>), String> {
    let before = peer.outbox_len();
    let id = peer.queue(to_ik, plaintext, now)?;
    let victim = if peer.outbox_len() <= before {
        ledger.iter().min_by_key(|e| e.id).cloned().filter(|v| !peer.is_queued(v.id))
    } else {
        None
    };
    Ok((id, victim))
}

/// Reconcile the pending-send ledger against what a `flush_outbox` pass just did: `delivered`
/// ids are resolved and dropped; anything else no longer queued (`peer.is_queued`) is gone
/// without having been delivered. An EVICTION would already have been caught live, at its own
/// `queue_and_note` call (see there) — so anything reaching here unaccounted for aged out of
/// `flush_outbox`'s TTL window instead, and is recorded as `"expired"`. Returns the ledger with
/// only the still-in-flight entries left, ready to save.
fn reconcile_ledger(
    store: &Store,
    peer: &Peer<SocketTransport>,
    ledger: Vec<store::PendingSend>,
    delivered: &[u64],
    now: u64,
) -> Vec<store::PendingSend> {
    let mut kept = Vec::with_capacity(ledger.len());
    for entry in ledger {
        if delivered.contains(&entry.id) {
            continue; // delivered — resolved, drop it
        }
        if peer.is_queued(entry.id) {
            kept.push(entry); // still in flight
            continue;
        }
        note_lost(store, entry.peer_ik, &entry.plaintext, entry.queued_at, now, "expired");
    }
    kept
}

/// §2.1: отправить сообщение получателю `to_ik` (его §2.1-IK) по установленной/
/// новой ratchet-сессии. Всё окно — под flock на сессиях (иначе гонка процессов
/// → keystream-reuse); persist ПОСЛЕ отправки. Первый контакт забирает bundle
/// получателя у relay (§12) — он должен был сделать `publish`.
pub fn send_session(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    plaintext: &[u8],
    now: u64,
) -> Result<bool, String> {
    let account = store.load_account().map_err(|e| secret_load_err("account", e))?;
    let cap = store
        .load_capability_for(&relay.id)
        .map_err(|e| format!("cannot send through this relay: {e}"))?;
    let transport = relay.transport();
    let fetch_pub = x25519_dalek::PublicKey::from(relay.id.fetch_pub);
    let mut peer = Peer::new(transport, account, cap, fetch_pub);

    let _lock = store.lock_sessions().map_err(|e| format!("замок сессий: {e}"))?;
    peer.import_state(store.load_sessions().map_err(|e| format!("чтение сессий: {e}"))?);
    if !peer.has_session(to_ik) {
        // The return value is the FORWARD-SECRECY strength of this first contact, and it is not
        // allowed to be dropped: a relay that withholds every one-time prekey downgrades the
        // agreement to 3-DH, and that fact has to survive past this line or it never existed.
        if peer.connect(to_ik, now)? == ForwardSecrecy::NoOneTimePrekey {
            store.mark_reduced_fs(*to_ik).map_err(|e| format!("reduced-FS record: {e}"))?;
        }
    }
    // Crash-consistency: encrypt (advance the chain) and QUEUE the exact ciphertext, then
    // persist BEFORE it can reach the wire. The ratchet advance and the queued ciphertext
    // commit in one atomic `save_sessions`, so a crash cannot leave position N consumed with
    // its ciphertext lost — that gap is what dropped the message and stranded position N
    // (never reused, but gone) before the outbox existed.
    // `queue` (encrypt + enqueue) fails only on a HARD error — no session, encrypt — in which
    // case nothing was committed, so it is honest to propagate `Err`. Past this point the
    // message is durably queued and WILL be delivered (this flush or a later one), so the
    // whole call reports `Ok` even if the relay is down: skipping the caller's history record
    // on a transient outage would drop the message from the sender's own chat while the
    // outbox still delivers it to the recipient — a false "not sent". (A distinct
    // pending-vs-delivered indicator can read `flush_outbox`'s result / the queue depth; that
    // UI affordance is a follow-up, not correctness.)
    //
    // Unlike `send_session_batch`, a SINGLE send never refuses on a full outbox — the comment
    // above already commits to "durably queued ⇒ report Ok", and breaking that here would turn
    // an ordinary transient outage into a false "not sent" (R2-6 records the loss instead of
    // pretending it cannot happen; A4-8's all-or-nothing refusal is a BATCH-only guarantee,
    // because only a batch can make its own manifest the collateral damage of its own chunks).
    let mut ledger = load_ledger_or_empty(store);
    let (id, victim) = queue_and_note(&mut peer, &ledger, to_ik, plaintext, now)?;
    store.save_sessions(&peer.export_state()).map_err(|e| format!("запись сессий (pre): {e}"))?;
    // The eviction (if any) is now real — record its victim before it is forgotten everywhere.
    if let Some(v) = victim {
        ledger.retain(|e| e.id != v.id);
        note_lost(store, v.peer_ik, &v.plaintext, v.queued_at, now, "evicted");
    }
    ledger.push(store::PendingSend { id, peer_ik: *to_ik, plaintext: plaintext.to_vec(), queued_at: now });
    // Deliver the whole queue in FIFO order (this message plus any earlier ones a prior
    // transport failure left behind) — exact retransmit, never a re-encrypt.
    let delivered = peer.flush_outbox(now);
    // Post-save persists the removals (delivered) and any cleared `pending_initial`.
    store.save_sessions(&peer.export_state()).map_err(|e| format!("запись сессий (post): {e}"))?;
    let ledger = reconcile_ledger(store, &peer, ledger, &delivered, now);
    save_ledger_best_effort(store, &ledger);
    // `true` = this message reached the relay this call; `false` = the relay was down and it
    // stayed queued (durably) to retransmit on the next send/poll. Either way it is committed;
    // the caller uses this only to show a pending indicator, never as a failure.
    Ok(!peer.is_queued(id))
}

/// COVER TRAFFIC (Loopix-style, opt-in): deposit a DUMMY message to OUR OWN mailbox through the
/// EXACT real send path — same padded request frame + wire size class as a real message — so a
/// network observer cannot tell a cover deposit from a real one. It rides `send_session` verbatim
/// (no separate, tell-tale path); the recipient (us) DROPS it on receive by `sender == self`.
///
/// HONEST scope: this is ADDITIVE noise that masks the TIMING of *this* client's real sends from an
/// observer of this client. It is NOT Loopix-grade unobservability — that needs real sends slotted
/// onto the cover schedule (delayed to the next tick), which this does not do. Opt-in because it is
/// constant background bandwidth.
/// Returns whether the cover deposit reached the relay this call (the observable-on-the-wire event
/// that makes it cover); `false` = the relay was down, so nothing was emitted.
pub fn send_cover(store: &Store, relay: &Relay, now: u64) -> Result<bool, String> {
    let own = store.load_account().map_err(|e| secret_load_err("account", e))?.identity_public();
    // A realistic one-packet payload of random bytes; content is irrelevant (the seal hides it, and
    // it lands in our own outbound box which we don't re-poll) — the point is the DEPOSIT on the wire.
    let r = crate::blob::random32();
    let len = 120 + (r[0] as usize); // ~120..375 bytes, well within one MAX_PACKET_SIZE packet
    let mut pad = Vec::with_capacity(len);
    while pad.len() < len {
        pad.extend_from_slice(&crate::blob::random32());
    }
    pad.truncate(len);
    send_session(store, relay, &own, &pad, now)
}

/// SEND-SIDE MULTI-HOMING (failover): send to the primary; if it's down (the message stayed
/// durably QUEUED), try to deliver the outbox through each SECONDARY relay in turn, so a
/// blocked/unreachable primary doesn't stop you sending — the message lands on ANY relay you share,
/// and the recipient (who polls all of them + dedups) picks it up. The seal happens ONCE (in the
/// primary `send_session`, committed to the outbox); a secondary flush re-deposits that EXACT
/// ciphertext (never a re-encrypt), so no ratchet double-advance. Returns whether it reached ANY
/// relay this call; either way it's durably committed and retransmits on the next send/poll.
pub fn send_session_multi(
    store: &Store,
    relays: &[Relay],
    to_ik: &[u8; 32],
    plaintext: &[u8],
    now: u64,
) -> Result<bool, String> {
    let (primary, secondaries) = relays.split_first().ok_or("no relays configured")?;
    if send_session(store, primary, to_ik, plaintext, now)? {
        return Ok(true); // delivered via the primary
    }
    // Primary down — the message is durably queued. Try to deliver it (and any earlier queued) NOW
    // through a secondary instead of waiting for the next cycle. Best-effort: a dead backup is skipped.
    for relay in secondaries {
        if flush_outbox(store, relay, now).unwrap_or(0) > 0 {
            return Ok(true);
        }
    }
    Ok(false) // every relay was down; stays queued for the next send/poll
}

/// Send SEVERAL payloads to one peer under ONE session lock and ONE pair of state saves — instead
/// of `send_session` × N, which re-loads and re-saves (decrypt + encrypt + write) the WHOLE session
/// state TWICE per payload. The ratchet still advances per payload and each still leaves as its own
/// ≤`MAX_PACKET_SIZE` packet on the wire (the traffic-shaping discipline is unchanged — this does
/// NOT enlarge chunks), but the dominant cost, the per-payload disk I/O, collapses to once for the
/// whole batch. For BULK transfers whose chunk count is bounded well under `MAX_OUTBOX` (image /
/// avatar ≈ 90 chunks); a huge multi-thousand-chunk file must still stream so it can't overflow the
/// retransmit queue. Payloads are queued IN ORDER, so a manifest passed first still precedes its
/// chunks on the FIFO mailbox.
///
/// **All-or-nothing (#215/A4-8).** `node::peer::Peer::queue` evicts the OLDEST queued entry
/// whenever the outbox is already at its cap, one push at a time — it does not know it is in the
/// middle of a batch, so an unreserved N-payload batch could have its early pushes evict entries
/// from a completely unrelated conversation and, if the batch itself is larger than the whole
/// cap, eventually reach its own earlier chunks (or its own manifest). Reserving room is done by
/// queuing the WHOLE batch into this in-memory `peer` first and watching, after every single
/// push, whether the outbox actually grew: if it didn't, the cap had to evict something to fit
/// that push, and the batch does not fit as a whole. Nothing above this point has touched disk —
/// `peer` was built fresh and `import_state` only mutates memory — so refusing here simply means
/// letting `peer` (and the ratchet advance + every push it made) drop, unsaved. The batch is
/// therefore either accepted whole (every payload queued, nothing evicted) or refused whole (an
/// `Err`, no save, ratchet unmoved) — never a partial batch with silent collateral damage.
pub fn send_session_batch(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    payloads: &[Vec<u8>],
    now: u64,
) -> Result<(), String> {
    if payloads.is_empty() {
        return Ok(());
    }
    let account = store.load_account().map_err(|e| secret_load_err("account", e))?;
    let cap = store
        .load_capability_for(&relay.id)
        .map_err(|e| format!("cannot send through this relay: {e}"))?;
    let transport = relay.transport();
    let fetch_pub = x25519_dalek::PublicKey::from(relay.id.fetch_pub);
    let mut peer = Peer::new(transport, account, cap, fetch_pub);

    let _lock = store.lock_sessions().map_err(|e| format!("замок сессий: {e}"))?;
    peer.import_state(store.load_sessions().map_err(|e| format!("чтение сессий: {e}"))?);
    if !peer.has_session(to_ik) && peer.connect(to_ik, now)? == ForwardSecrecy::NoOneTimePrekey {
        store.mark_reduced_fs(*to_ik).map_err(|e| format!("reduced-FS record: {e}"))?;
    }
    let mut ledger = load_ledger_or_empty(store);
    // Encrypt + enqueue EVERY payload (each advances the ratchet), refusing the whole batch the
    // moment any single push would evict an entry (see the doc comment above) — before any of it
    // is persisted.
    let mut ids = Vec::with_capacity(payloads.len());
    for (i, p) in payloads.iter().enumerate() {
        let before = peer.outbox_len();
        let id = peer.queue(to_ik, p, now)?;
        if peer.outbox_len() <= before {
            return Err(format!(
                "outbox has no room for this {}-message batch (only {} of {} would fit without \
                 evicting an existing queued message); refusing the whole batch — nothing sent, \
                 ratchet not advanced",
                payloads.len(),
                i,
                payloads.len()
            ));
        }
        ids.push(id);
    }
    // The whole batch fits: commit the advanced state ONCE — same crash-consistency as
    // `send_session` (envelope N queued ⟺ ratchet ≥ N+1), but for the whole batch in one atomic
    // save.
    store.save_sessions(&peer.export_state()).map_err(|e| format!("запись сессий (pre): {e}"))?;
    // Track every payload this call durably queued, so a LATER loss (cap eviction from some
    // future send, or TTL expiry) can still be attributed to what it was (R2-6). None of THESE
    // ids could have just been evicted — the loop above refused rather than let that happen.
    for (id, p) in ids.iter().zip(payloads) {
        ledger.push(store::PendingSend { id: *id, peer_ik: *to_ik, plaintext: p.clone(), queued_at: now });
    }
    let delivered = peer.flush_outbox(now);
    store.save_sessions(&peer.export_state()).map_err(|e| format!("запись сессий (post): {e}"))?;
    let ledger = reconcile_ledger(store, &peer, ledger, &delivered, now);
    save_ledger_best_effort(store, &ledger);
    Ok(())
}

/// Retry delivery of any messages left queued by a prior transport failure — the send-side
/// analog of a poll. Loads the sessions, flushes the outbox (exact retransmit in FIFO order),
/// and persists the result. Cheap when the outbox is empty (the common case). Meant to run on
/// the poll cadence so a message stranded by a brief outage lands without waiting for the user
/// to send again. Returns how many were delivered this pass.
pub fn flush_outbox(store: &Store, relay: &Relay, now: u64) -> Result<usize, String> {
    let account = store.load_account().map_err(|e| secret_load_err("account", e))?;
    // NOT `unwrap_or(dev_capability())`. The dev capability's secret is published in this
    // repository, so falling back to it sends real mail under a credential anyone can forge —
    // while the sender believes the message passed normal admission (A8-11). A capability we
    // cannot read is a reason to stop retrying, not to downgrade silently.
    let cap = store
        .load_capability_for(&relay.id)
        .map_err(|e| format!("cannot flush through this relay: {e}"))?;
    let transport = relay.transport();
    let fetch_pub = x25519_dalek::PublicKey::from(relay.id.fetch_pub);
    let mut peer = Peer::new(transport, account, cap, fetch_pub);

    let _lock = store.lock_sessions().map_err(|e| format!("session lock: {e}"))?;
    peer.import_state(store.load_sessions().map_err(|e| format!("reading sessions: {e}"))?);
    if peer.outbox_len() == 0 {
        return Ok(0);
    }
    let delivered = peer.flush_outbox(now);
    store.save_sessions(&peer.export_state()).map_err(|e| format!("saving sessions: {e}"))?;
    // A retry-driven flush can be the pass that finds a PREVIOUSLY-queued message expired past
    // its TTL (queuing evictions are caught live elsewhere, at their own `queue_and_note` call —
    // see there — so anything left unaccounted for here is TTL, not the cap). Reconcile so that
    // loss gets a durable record too, not just the sends this process itself originated.
    let ledger = load_ledger_or_empty(store);
    let ledger = reconcile_ledger(store, &peer, ledger, &delivered, now);
    save_ledger_best_effort(store, &ledger);
    Ok(delivered.len())
}

/// How many sent messages are queued awaiting delivery (a transport failure left them). Reads
/// the persisted session state without building a `Peer` or touching the network — for a UI
/// pending-sends indicator that clears when the outbox drains.
pub fn outbox_len(store: &Store) -> Result<usize, String> {
    let _lock = store.lock_sessions().map_err(|e| format!("session lock: {e}"))?;
    let state = store.load_sessions().map_err(|e| format!("reading sessions: {e}"))?;
    Ok(state.outbox_len())
}

/// Отправить ТЕКСТ со штампом времени отправителя (`msg_ts`): оборачивает в
/// `Content::TextStamped`, чтобы получатель хранил ТОТ ЖЕ ts — сквозной идентификатор
/// сообщения (для «удалить у всех»/реакций/ответов). `now` — часы для admission.
#[allow(clippy::too_many_arguments)]
/// §15: offer a contact the extra routes you use to reach the relay you SHARE.
///
/// Explicitly addressed: the caller picks the recipient — this is never a broadcast and
/// never automatic, because handing someone your routes tells them where you connect.
/// `relay.id.noise_pub` rides along so the receiver can tell these routes are for the
/// relay they already use (the only case they can act on: Noise authenticates that
/// identity, so an offered route cannot impersonate it).
pub fn send_route_offer(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    routes: &str,
    now: u64,
) -> Result<(), String> {
    let payload = content::encode(&content::Content::RouteOffer {
        relay_noise_pub: relay.id.noise_pub,
        routes: routes.to_string(),
    });
    send_session(store, relay, to_ik, &payload, now).map(|_| ())
}

/// Returns `true` if the message reached the relay this call, `false` if the relay was down
/// and it stayed durably queued to retransmit (a pending indicator, never a failure).
pub fn send_text(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    text: &[u8],
    msg_ts: u64,
    now: u64,
) -> Result<bool, String> {
    let payload =
        content::encode(&content::Content::TextStamped { text: text.to_vec(), ts: msg_ts });
    send_session(store, relay, to_ik, &payload, now)
}

/// Отправить ПРАВКУ своего сообщения `target_msg_id`. Локально `set_edit` делает
/// вызывающий (worker) — здесь только провод.
#[allow(clippy::too_many_arguments)]
pub fn send_edit_message(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    target_msg_id: [u8; 16],
    new_text: &[u8],
    edit_ts: u64,
    now: u64,
) -> Result<(), String> {
    let payload = content::encode(&content::Content::EditMessage {
        target_msg_id,
        new_text: new_text.to_vec(),
        edit_ts,
    });
    send_session(store, relay, to_ik, &payload, now).map(|_| ())
}

/// **Guard авторизации входящей правки.** Правку сообщения `target` от `sender`
/// применяем ТОЛЬКО если `sender` — автор цели: у нас она входящая (`from_me=false`,
/// `peer_ik==sender`), и её канонический `msg_id` совпадает с `target`. Иначе
/// злонамеренный пир мог бы подменить текст ВАШЕГО (или чужого) сообщения на вашем
/// экране — та же честная граница «нельзя навязать», но здесь ещё и анти-спуфинг.
pub fn incoming_edit_allowed(
    records: &[store::HistoryRecord],
    sender: &[u8; 32],
    target: [u8; 16],
) -> bool {
    records.iter().any(|r| {
        !r.from_me && &r.peer_ik == sender && content::msg_id(sender, r.ts, &r.text) == target
    })
}

/// A Unix timestamp (seconds) as `YYYY-MM-DD HH:MM:SS UTC`. Pure and dependency-free
/// (Howard Hinnant's civil-from-days), so the export is deterministic and testable
/// without pulling a date crate.
pub fn fmt_ts(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    let secs = ts % 86_400;
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    // civil_from_days: days since 1970-01-01 -> (year, month, day).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

/// Render the conversation with `peer_ik` from the full history as plain text — the
/// user's own data, exported entirely CLIENT-SIDE (nothing leaves the device). Records
/// for other peers are excluded; append order is preserved. `from_me` becomes "Me", the
/// peer's messages "Them". Text is already the human-readable display string.
pub fn format_conversation(records: &[store::HistoryRecord], peer_ik: &[u8; 32]) -> String {
    let mut out = String::new();
    for r in records.iter().filter(|r| &r.peer_ik == peer_ik) {
        let who = if r.from_me { "Me" } else { "Them" };
        out.push_str(&format!("[{}] {}: {}\n", fmt_ts(r.ts), who, String::from_utf8_lossy(&r.text)));
    }
    out
}

/// Отправить текст-ОТВЕТ: как `send_text`, но с `reply_to` (`msg_id` цели). Локально
/// историю пишет и `set_reply` делает вызывающий (worker) — здесь только провод.
#[allow(clippy::too_many_arguments)]
pub fn send_text_reply(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    text: &[u8],
    msg_ts: u64,
    reply_to: [u8; 16],
    now: u64,
) -> Result<(), String> {
    let payload = content::encode(&content::Content::TextReply {
        text: text.to_vec(),
        ts: msg_ts,
        reply_to,
    });
    send_session(store, relay, to_ik, &payload, now).map(|_| ())
}

/// Отправить просьбу «удалить у всех» ранее посланное (`msg_ts` + `text`).
/// Кооперативно — получатель на сотрудничающем клиенте сотрёт запись.
#[allow(clippy::too_many_arguments)]
pub fn send_delete_for_everyone(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    msg_ts: u64,
    text: &[u8],
    now: u64,
) -> Result<(), String> {
    let payload =
        content::encode(&content::Content::DeleteForEveryone { ts: msg_ts, text: text.to_vec() });
    send_session(store, relay, to_ik, &payload, now).map(|_| ())
}

/// Послать реакцию (поставить/снять) на сообщение `msg_id` собеседнику `to_ik`.
/// Маленький control-конверт по §2.1-сессии; автора получатель атрибутирует по
/// расшифровавшей сессии (как обычный текст). Локальную запись `set_reaction`
/// делает вызывающий (worker) — здесь только провод.
#[allow(clippy::too_many_arguments)]
pub fn send_reaction(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    msg_id: [u8; 16],
    emoji: &str,
    add: bool,
    now: u64,
) -> Result<(), String> {
    let payload =
        content::encode(&content::Content::Reaction { msg_id, emoji: emoji.to_string(), add });
    send_session(store, relay, to_ik, &payload, now).map(|_| ())
}

/// Send our SELF-DECLARED profile (name + bio) to ONE contact over the existing
/// E2E channel. Broadcasting to "all contacts" is the caller's job (the worker sends
/// per IK). Lazy: only on an explicit change / first contact, not an auto-rebroadcast
/// on every launch (that burst is an activity-metadata signature).
#[allow(clippy::too_many_arguments)]
pub fn send_profile(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    name: &str,
    bio: &str,
    now: u64,
) -> Result<(), String> {
    let payload = content::encode(&content::Content::Profile {
        name: name.to_string(),
        bio: bio.to_string(),
    });
    send_session(store, relay, to_ik, &payload, now).map(|_| ())
}

/// Send a CONTACT REQUEST — carries our profile so the recipient sees who is asking (mutual-consent
/// add). Best-effort like any first send: queues + retransmits if the relay/bundle isn't ready yet.
pub fn send_contact_request(store: &Store, relay: &Relay, to_ik: &[u8; 32], name: &str, bio: &str, now: u64) -> Result<(), String> {
    let payload = content::encode(&content::Content::ContactRequest { name: name.to_string(), bio: bio.to_string() });
    send_session(store, relay, to_ik, &payload, now)?;
    // Record the ASK before we can be answered. Their accept writes their profile into our
    // contacts, so without a record of having invited them a stranger's unsolicited accept did
    // exactly the same thing (SEC-29). Noted AFTER the send so a failed send leaves no promise.
    store.note_outstanding_request(*to_ik).map_err(|e| format!("recording the request: {e}"))
}

/// Send a CONTACT ACCEPT — the consent handshake's second half; carries our profile so the original
/// requester now sees our name+bio.
pub fn send_contact_accept(store: &Store, relay: &Relay, to_ik: &[u8; 32], name: &str, bio: &str, now: u64) -> Result<(), String> {
    let payload = content::encode(&content::Content::ContactAccept { name: name.to_string(), bio: bio.to_string() });
    send_session(store, relay, to_ik, &payload, now).map(|_| ())
}

/// Ask a peer to delete the conversation on THEIR side too (they choose whether to comply). The
/// caller clears their own copy locally.
pub fn send_delete_conversation(store: &Store, relay: &Relay, to_ik: &[u8; 32], now: u64) -> Result<(), String> {
    let payload = content::encode(&content::Content::DeleteConversation);
    send_session(store, relay, to_ik, &payload, now).map(|_| ())
}

/// Send one PUBLICATION ("post") to a single contact. A post is broadcast by the caller
/// fanning this out to EVERY contact (like an avatar); `id`/`ts` are shared across the fan-out
/// so each recipient dedups the same post and orders it by the sender's clock. Text-only in v1
/// (bounded to one session packet by `MAX_POST_TEXT`, clamped here defensively).
pub fn send_publication(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    id: [u8; 16],
    text: &str,
    ts: u64,
    now: u64,
) -> Result<(), String> {
    // Truncate on a UTF-8 char boundary (plain String::truncate would panic mid-codepoint).
    let text = if text.len() > content::MAX_POST_TEXT {
        let mut end = content::MAX_POST_TEXT;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text[..end].to_string()
    } else {
        text.to_string()
    };
    let payload = content::encode(&content::Content::Publication { id, text, ts });
    send_session(store, relay, to_ik, &payload, now).map(|_| ())
}

/// Send a STORY: an ephemeral publication that self-destructs at `expire_at`. Same fan-out as a
/// publication; the recipient drops it if it already arrived dead. Text-only, one packet.
#[allow(clippy::too_many_arguments)]
pub fn send_story(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    id: [u8; 16],
    text: &str,
    ts: u64,
    expire_at: u64,
    now: u64,
) -> Result<(), String> {
    let text = if text.len() > content::MAX_POST_TEXT {
        let mut end = content::MAX_POST_TEXT;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text[..end].to_string()
    } else {
        text.to_string()
    };
    let payload = content::encode(&content::Content::Story { id, text, ts, expire_at });
    send_session(store, relay, to_ik, &payload, now).map(|_| ())
}

/// Send a RETRACTION ("delete for everyone") for publication `id` to a single contact; the
/// caller fans it out to the audience. The recipient drops the post from their feed.
pub fn send_retraction(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    id: [u8; 16],
    now: u64,
) -> Result<(), String> {
    let payload = content::encode(&content::Content::RetractPublication { id });
    send_session(store, relay, to_ik, &payload, now).map(|_| ())
}

/// Ask to SUBSCRIBE to `to_ik`'s posts. A channel auto-accepts; a private account queues it.
pub fn send_join_request(store: &Store, relay: &Relay, to_ik: &[u8; 32], now: u64) -> Result<(), String> {
    let payload = content::encode(&content::Content::JoinRequest);
    send_session(store, relay, to_ik, &payload, now)?;
    store.note_outstanding_request(*to_ik).map_err(|e| format!("recording the request: {e}"))
}

/// Live-pull: ask `to_ik` for their recent PUBLIC posts (visiting a profile you don't subscribe to).
/// They answer — only while online — by sending their public posts back as `Publication`s.
pub fn send_posts_request(store: &Store, relay: &Relay, to_ik: &[u8; 32], now: u64) -> Result<(), String> {
    let payload = content::encode(&content::Content::PostsRequest);
    send_session(store, relay, to_ik, &payload, now).map(|_| ())
}

/// Tell a contact to move to a new channel: send `Content::ChannelMigrate { new_ik }` over the
/// EXISTING session (call this on the OLD proxy's store, so it rides that authenticated ratchet).
/// The recipient re-points us to `new_ik`. Send only to the contacts you keep.
///
/// Returns `send_session`'s delivery bit VERBATIM (CRYPTO-27) instead of discarding it: `true` =
/// this migration ciphertext reached the relay this call; `false` = the relay was down and it is
/// durably QUEUED in the OLD proxy's outbox, not yet delivered. A migration message is the ONLY
/// authenticated proof-of-continuity between the old and new identity — burning the old proxy
/// while it is `false` would delete that queued ciphertext for good (the outbox lives in
/// `sessions.dat`, one of the files `Store::burn_proxy` removes), leaving the contact permanently
/// split: they never learn `new_ik`, and the next message from it looks like an unknown sender.
/// The caller MUST treat `false` (and `Err`) as "not migrated yet": do not re-point the local
/// contact→proxy tag, and rely on `Store::burn_proxy`'s own outbox check to refuse the burn until
/// this is `Ok(true)` (or a later flush drains the outbox).
pub fn send_channel_migrate(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    new_ik: [u8; 32],
    now: u64,
) -> Result<bool, String> {
    let payload = content::encode(&content::Content::ChannelMigrate { new_ik });
    send_session(store, relay, to_ik, &payload, now)
}

/// Tell `to_ik` their subscribe request was accepted (`is_channel` = we're a channel).
pub fn send_join_accept(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    is_channel: bool,
    now: u64,
) -> Result<(), String> {
    let payload = content::encode(&content::Content::JoinAccept { is_channel });
    send_session(store, relay, to_ik, &payload, now).map(|_| ())
}

/// Отправить ИСЧЕЗАЮЩИЙ текст: оборачивает в `Content::TextExpiring` с абсолютным
/// `expire_at = now + ttl_secs`. Таймер идёт от отправки и одинаков у обеих сторон.
/// Ничего не логируется в историю (это делает вызывающий — worker пропускает
/// append для этого варианта).
#[allow(clippy::too_many_arguments)]
pub fn send_text_expiring(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    text: &[u8],
    ttl_secs: u32,
    now: u64,
) -> Result<(), String> {
    let expire_at = now.saturating_add(ttl_secs as u64);
    let payload =
        content::encode(&content::Content::TextExpiring { text: text.to_vec(), expire_at });
    send_session(store, relay, to_ik, &payload, now).map(|_| ())
}

/// Отправить ФАЙЛ: манифест + чанки, каждый — ОТДЕЛЬНОЕ сообщение (1400-байтный
/// лимит Ступени-0 не даёт слать файл целиком). Первый срез: ≤250 чанков (~256
/// KiB, один mailbox). Частичная отправка (краш посреди) не соберётся у получателя
/// — файл не появится, но и ключ не переиспользуется (каждый чанк — своя позиция).
/// Манифест лучше слать по УЖЕ установленной сессии (как Initial он ограничен
/// ~104 Б из-за KEM-ct) — на практике файл шлют после переписки.
#[allow(clippy::too_many_arguments)]
pub fn send_file(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    name: &str,
    bytes: &[u8],
    now: u64,
) -> Result<(), String> {
    let size = bytes.len() as u64;
    // Small files ride the inline padded-mailbox path (metadata-hardened). Larger ones stream up
    // as an E2E blob + a tiny `FileRef` announcement — same split the GUI uses (`MAX_FILE_SIZE`).
    if size <= content::MAX_FILE_SIZE {
        let (manifest, chunks) = content::chunk_file(name, bytes)?;
        send_session(store, relay, to_ik, &content::encode(&manifest), now)?;
        for ch in &chunks {
            send_session(store, relay, to_ik, &content::encode(ch), now)?;
        }
        return Ok(());
    }

    // Large file → RESUMABLE blob upload. A stable `upload_id` keys a persisted record, so if the
    // send crashes mid-upload, re-running it continues from the relay's watermark instead of
    // re-sending the whole file. The record is cleared once the `FileRef` (the small pointer the
    // recipient downloads from) has been delivered. The id covers the CONTENT, so a resume can
    // only ever continue the same bytes — see `upload_id_for`.
    let upload_id = upload_id_for(to_ik, name, size, &blob::plaintext_hash(bytes));
    sweep_pending_uploads(store, now);
    let (blob_id, key) = match store.get_pending_upload(&upload_id).map_err(|e| format!("pending uploads: {e}"))? {
        Some(pu) => (pu.blob_id, pu.key),
        None => {
            let (b, k) = (blob::random32(), blob::random32());
            let _ = store.add_pending_upload(&store::PendingUpload {
                upload_id,
                blob_id: b,
                key: k,
                to_ik: *to_ik,
                name: name.to_string(),
                size,
                queued_at: now,
                path: None, // CLI re-reads via the re-run command; the GUI stores the path
            });
            (b, k)
        }
    };
    // The upload now presents a capability (CRYPTO-15): storing bytes on a relay is metered like
    // every other write, and this is the path that stores the most.
    let cap = store
        .load_capability_for(&relay.id)
        .map_err(|e| format!("no credential for the blob upload: {e}"))?;
    let (blob_id, key, hash, count) =
        blob_upload_resumable(relay, &cap, std::io::Cursor::new(bytes), size, blob_id, key)?;
    let fileref = content::Content::FileRef { blob_id, key, hash, name: name.to_string(), size, chunks: count };
    send_session(store, relay, to_ik, &content::encode(&fileref), now)?;
    let _ = store.remove_pending_upload(&upload_id);
    Ok(())
}

/// A stable id for an in-flight upload — a domain-separated hash of recipient+name+size — so a
/// re-run of the same send finds the persisted record and resumes rather than restarting. Shared
/// by the CLI (`send_file`) and the GUI (`spawn_blob_upload`) so both key the same record.
pub fn upload_id_for(to_ik: &[u8; 32], name: &str, size: u64, content: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"karst-upload-id-v2");
    h.update(to_ik);
    h.update((name.len() as u64).to_le_bytes());
    h.update(name.as_bytes());
    h.update(size.to_le_bytes());
    // The CONTENT hash, not just its name and length (CRYPTO-31). Without it, "same recipient,
    // same basename, same size" resumed a DIFFERENT file onto the stored blob_id and key: the
    // relay then held a blob spliced from two files, and (before the per-chunk salt) two
    // ciphertexts under one key+nonce. Editing a file now starts its own transfer.
    h.update(content);
    h.finalize().into()
}

/// Drop resume records whose blob the relay has certainly forgotten: a partial blob is swept at
/// `BLOB_TTL_SECS`, so past that the record points at nothing and resuming from it would re-upload
/// every chunk anyway (safe — the per-chunk salt makes reusing `K` harmless — but pointless).
///
/// This exists because the record store is BOUNDED (`MAX_PENDING_UPLOADS`) and a full one silently
/// stops recording NEW uploads, i.e. quietly turns resumability off. Cancelled and abandoned sends
/// keep their record on purpose (that is what a later resume needs), so without a sweep they
/// accumulate for the life of the account. Returns how many were dropped. `now` is passed in, never
/// read from the clock, so this is testable on counts alone.
///
/// The TTL used is our own default, not the `blob_ttl_secs` a relay advertises (a record is not
/// bound to the relay it was uploading to). Against a relay that keeps blobs LONGER, this drops a
/// record that was still resumable — the cost is one full re-upload, never a lost file.
pub fn sweep_pending_uploads(store: &Store, now: u64) -> usize {
    let Ok(pending) = store.list_pending_uploads() else { return 0 };
    let mut dropped = 0;
    for pu in pending {
        if now.saturating_sub(pu.queued_at) > node::blobstore::BLOB_TTL_SECS
            && store.remove_pending_upload(&pu.upload_id).is_ok()
        {
            dropped += 1;
        }
    }
    dropped
}

/// Send our AVATAR to one contact: manifest + chunks (same transport as a file, but
/// the receiver assembles it into their peer-profile cache, not a saved file). The
/// bytes must already be bounded, re-encoded image bytes (the GUI produces them).
#[allow(clippy::too_many_arguments)]
pub fn send_avatar(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    bytes: &[u8],
    now: u64,
) -> Result<(), String> {
    let (manifest, chunks) = content::chunk_avatar(bytes)?;
    let mut payloads = Vec::with_capacity(chunks.len() + 1);
    payloads.push(content::encode(&manifest)); // manifest FIRST (reassembler invariant)
    payloads.extend(chunks.iter().map(content::encode));
    send_session_batch(store, relay, to_ik, &payloads, now)
}

/// Send our whole profile PHOTO GALLERY to one contact as a single atomic transfer (mirrors
/// `send_avatar`). `photos` is packed with `content::pack_gallery`; an empty list sends a valid
/// "clear my gallery" transfer. The receiver replaces the peer's gallery wholesale on completion.
pub fn send_gallery(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    photos: &[Vec<u8>],
    now: u64,
) -> Result<(), String> {
    let packed = content::pack_gallery(now, photos); // stamp the sender clock for the receiver's stale-guard
    let (manifest, chunks) = content::chunk_gallery(&packed)?;
    let mut payloads = Vec::with_capacity(chunks.len() + 1);
    payloads.push(content::encode(&manifest)); // manifest FIRST (reassembler invariant)
    payloads.extend(chunks.iter().map(content::encode));
    send_session_batch(store, relay, to_ik, &payloads, now)
}

/// Send our whole profile gallery to one contact via the BLOB path (the receive side is
/// [`download_gallery`]) — used when the packed gallery is too big for one mailbox
/// (`content::gallery_fits_inline` false). Mirrors [`send_post_attachment_blob`]: the packed gallery
/// is uploaded as a fresh per-recipient E2E blob and only a tiny `GalleryRef` is deposited. An empty
/// gallery still packs to a valid 4-byte "clear" blob.
pub fn send_gallery_blob(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    photos: &[Vec<u8>],
    now: u64,
) -> Result<(), String> {
    let packed = content::pack_gallery(now, photos); // stamp the sender clock for the receiver's stale-guard
    if packed.len() > content::MAX_GALLERY_BYTES {
        return Err(format!("gallery > {} bytes", content::MAX_GALLERY_BYTES));
    }
    let (blob_id, key, hash, count) =
        blob_upload(
            relay,
            &store.load_capability_for(&relay.id).map_err(|e| format!("no credential for the blob upload: {e}"))?,
            std::io::Cursor::new(&packed),
            packed.len() as u64,
        )?;
    let refc = content::Content::GalleryRef {
        blob_id,
        key,
        hash,
        size: packed.len() as u64,
        chunks: count,
    };
    send_session_batch(store, relay, to_ik, &[content::encode(&refc)], now)
}

/// Send a publication/story IMAGE to one contact: `PostImageManifest { post_id }` + chunks (same
/// chunked transport as an avatar). The caller sends the `Publication`/`Story` text packet first,
/// then this, to every recipient — the receiver reunites them by `post_id`. Per-recipient E2E, no
/// shared relay blob. `bytes` must already be bounded, re-encoded image bytes (the GUI produces
/// them). The MANIFEST is sent first so it precedes its chunks on the FIFO mailbox (the
/// reassembler's manifest-before-chunks invariant).
pub fn send_post_image(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    post_id: [u8; 16],
    bytes: &[u8],
    now: u64,
) -> Result<(), String> {
    let (manifest, chunks) = content::chunk_post_image(post_id, bytes)?;
    let mut payloads = Vec::with_capacity(chunks.len() + 1);
    payloads.push(content::encode(&manifest)); // manifest FIRST (reassembler invariant)
    payloads.extend(chunks.iter().map(content::encode));
    send_session_batch(store, relay, to_ik, &payloads, now)
}

/// Send ONE post attachment (image or file) to one contact — the multi-attachment fan-out. `kind`
/// = 0 image / 1 file, `index` its slot in the post, `name` the file name (empty for an image).
/// Manifest-first, chunk-batched under one lock like `send_post_image`.
#[allow(clippy::too_many_arguments)]
pub fn send_post_attachment(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    post_id: [u8; 16],
    index: u32,
    kind: u8,
    name: &str,
    bytes: &[u8],
    now: u64,
) -> Result<(), String> {
    let (manifest, chunks) = content::chunk_post_attachment(post_id, index, kind, name, bytes)?;
    let mut payloads = Vec::with_capacity(chunks.len() + 1);
    payloads.push(content::encode(&manifest)); // manifest FIRST (reassembler invariant)
    payloads.extend(chunks.iter().map(content::encode));
    send_session_batch(store, relay, to_ik, &payloads, now)
}

/// Send ONE post attachment to one contact via the relay's BLOB store (the transport #98 swaps in
/// for `send_post_attachment`). Uploads the bytes as a PER-RECIPIENT blob — `blob_upload` mints a
/// fresh random `blob_id`+`key`, so no two recipients share an id (no whole-audience correlation) —
/// then deposits a single tiny `PostAttachmentRef` in the mailbox instead of ~90 inline chunks. A
/// multi-image post therefore lands a handful of pointers rather than hundreds of seals, so it never
/// overflows the 256-seal mailbox cap (the `MailboxFull` that dropped later images on the inline
/// path). An upload failure (e.g. the blob store is full) is returned to the caller — the recipient
/// simply doesn't get this attachment; the post TEXT still fans out on its own packet.
#[allow(clippy::too_many_arguments)]
pub fn send_post_attachment_blob(
    store: &Store,
    relay: &Relay,
    to_ik: &[u8; 32],
    post_id: [u8; 16],
    index: u32,
    kind: u8,
    name: &str,
    bytes: &[u8],
    now: u64,
) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > content::MAX_POST_IMAGE_BYTES {
        return Err(format!("attachment 1..{} bytes", content::MAX_POST_IMAGE_BYTES));
    }
    if name.len() > content::MAX_FILENAME {
        return Err("attachment name too long".into());
    }
    let (blob_id, key, hash, count) =
        blob_upload(
            relay,
            &store.load_capability_for(&relay.id).map_err(|e| format!("no credential for the blob upload: {e}"))?,
            std::io::Cursor::new(bytes),
            bytes.len() as u64,
        )?;
    let refc = content::Content::PostAttachmentRef {
        post_id,
        index,
        kind,
        name: name.to_string(),
        blob_id,
        key,
        hash,
        size: bytes.len() as u64,
        chunks: count,
    };
    send_session_batch(store, relay, to_ik, &[content::encode(&refc)], now)
}

/// Fetch ONE pending post-attachment blob into the `feed_attachments` sidecar (the receive side of
/// [`send_post_attachment_blob`]). Unlike [`download_blob`], the bytes are small (bounded by
/// `MAX_POST_IMAGE_BYTES`) and belong to the feed, not the files list, so this fetches in-memory and
/// writes the sidecar rather than streaming a crash-safe on-disk container. Idempotent + retry-safe:
/// keyed by `blob_id`, a failed attempt leaves the pending entry so the next poll re-fetches (the
/// blob lives on the relay until its TTL); past that horizon the entry is dropped. A swept/missing
/// blob is unrecoverable (`GaveUp`) — the post text still shows, the media just never arrives.
pub fn download_post_attachment(
    store: &Store,
    relay: &Relay,
    ppa: &store::PendingPostAttachment,
    now: u64,
) -> DownloadOutcome {
    // A TERMINAL give-up: record a failure marker (so the feed shows an error tile instead of the
    // attachment silently disappearing) AND drop the pending entry (no forever-retry). Retries stay
    // silent — only an unrecoverable end records the marker.
    let give_up = |why: String| -> DownloadOutcome {
        let _ = store.mark_post_attachment_failed(ppa.sender, ppa.post_id, ppa.index, ppa.kind, &ppa.name);
        let _ = store.remove_pending_post_attachment(&ppa.blob_id);
        DownloadOutcome::GaveUp(why)
    };
    // Past the retry horizon (blob TTL) — a swept blob must not retry forever.
    if now.saturating_sub(ppa.queued_at) > node::protocol::MAILBOX_TTL_SECS {
        return give_up("post attachment expired (blob past TTL)".into());
    }
    // Bound the pointer before allocating or touching the wire (SEC-31). The admission gate in
    // `persist_incoming_history` already rejects a bad shape, so a pending entry reaching here
    // with one means it predates that gate or the file was tampered with — either way, refuse
    // rather than start the round trips. `chunks` is what drives the loop below, and equality
    // with `chunk_count(size)` caps it at two for a 96 KiB attachment.
    if !content::blob_ref_shape_ok(ppa.size, ppa.chunks, content::MAX_POST_IMAGE_BYTES) {
        return give_up("post attachment out of limits".into());
    }
    // No "already recorded → skip" short-circuit like `download_blob` has: these are small and
    // `set_feed_attachment` overwrites the same `(post_id, index)` slot, so a redelivered ref just
    // re-fetches and overwrites idempotently (no duplicate) — not worth an extra sidecar read.
    use sha2::Digest;
    let transport = relay.transport();
    let mut cookie: Option<admission::cookie::Cookie> = None;
    let mut buf: Vec<u8> = Vec::with_capacity(ppa.size as usize);
    let mut hasher = sha2::Sha256::new();
    for index in 0..ppa.chunks {
        let ct = loop {
            let req = BlobGetRequest {
                client_addr: relay.pseudonym.to_vec(),
                carrier_id: BLOB_CARRIER.to_vec(),
                cookie,
                blob_id: ppa.blob_id,
                index,
            };
            match transport.blob_get(&req) {
                BlobResponse::NeedCookie(c) => cookie = Some(c),
                BlobResponse::Chunk(Some(ct)) => break ct,
                BlobResponse::Chunk(None) => {
                    // The relay no longer has the blob (swept) — unrecoverable.
                    return give_up(format!("post-attachment chunk {index} unavailable"));
                }
                BlobResponse::Rejected(r) => return DownloadOutcome::Retry(format!("blob rejected: {r}")),
                _ => return DownloadOutcome::Retry("post-attachment download: unexpected response".into()),
            }
        };
        let is_last = index + 1 == ppa.chunks;
        let pt = match blob::open_chunk(&ppa.key, &ppa.blob_id, index, ppa.chunks, is_last, &ct) {
            Ok(p) => p,
            Err(e) => return DownloadOutcome::Retry(format!("chunk {index}: {e}")),
        };
        if buf.len() + pt.len() > content::MAX_POST_IMAGE_BYTES {
            // A ref that lied about its size — refuse rather than grow past the cap.
            return give_up("post attachment exceeded size cap".into());
        }
        hasher.update(&pt);
        buf.extend_from_slice(&pt);
    }
    // The assembled length must be exactly what the pointer promised. The hash below already
    // pins the bytes, but only to what the SENDER hashed — `size` is what the queue and the caps
    // were admitted against, so a ref whose real payload is a different length was not the thing
    // we agreed to fetch.
    if buf.len() as u64 != ppa.size {
        return give_up("post attachment size mismatch".into());
    }
    let got: [u8; 32] = hasher.finalize().into();
    if got != ppa.hash {
        // A corrupt fetch — a terminal integrity failure, mark it and stop.
        return give_up("post attachment hash mismatch".into());
    }
    if let Err(e) = store.set_feed_attachment(
        ppa.sender,
        ppa.post_id,
        store::StoredAttachment { index: ppa.index, kind: ppa.kind, name: ppa.name.clone(), bytes: buf, failed: false },
    ) {
        return DownloadOutcome::Retry(format!("saving post attachment: {e}"));
    }
    let _ = store.remove_pending_post_attachment(&ppa.blob_id);
    DownloadOutcome::Done(String::new())
}

/// Fetch ONE pending GALLERY blob and replace the sender's `peer_profiles` photos with it (the
/// receive side of [`send_gallery_blob`]). Mirrors [`download_post_attachment`]: in-memory (bounded
/// by `MAX_GALLERY_BYTES`), idempotent + retry-safe keyed by the pending entry, TTL horizon, hash
/// verified. A swept/missing blob is unrecoverable (`GaveUp`) — the peer keeps their previous gallery.
pub fn download_gallery(
    store: &Store,
    relay: &Relay,
    pg: &store::PendingGallery,
    now: u64,
) -> DownloadOutcome {
    let give_up = |why: String| -> DownloadOutcome {
        // No failure MARKER (a gallery has no error tile) — just drop the pending entry so a swept
        // blob can't retry forever; the peer's previous gallery stays untouched.
        let _ = store.remove_pending_gallery(&pg.sender, &pg.blob_id);
        DownloadOutcome::GaveUp(why)
    };
    if now.saturating_sub(pg.queued_at) > node::protocol::MAILBOX_TTL_SECS {
        return give_up("gallery expired (blob past TTL)".into());
    }
    // SEC-31, same reasoning as `download_post_attachment`: `chunks` is the loop bound, so it must
    // equal what an honest sender would have computed, not merely be non-zero.
    if !content::blob_ref_shape_ok(pg.size, pg.chunks, content::MAX_GALLERY_BYTES) {
        return give_up("gallery out of limits".into());
    }
    use sha2::Digest;
    let transport = relay.transport();
    let mut cookie: Option<admission::cookie::Cookie> = None;
    let mut buf: Vec<u8> = Vec::with_capacity(pg.size as usize);
    let mut hasher = sha2::Sha256::new();
    for index in 0..pg.chunks {
        let ct = loop {
            let req = BlobGetRequest {
                client_addr: relay.pseudonym.to_vec(),
                carrier_id: BLOB_CARRIER.to_vec(),
                cookie,
                blob_id: pg.blob_id,
                index,
            };
            match transport.blob_get(&req) {
                BlobResponse::NeedCookie(c) => cookie = Some(c),
                BlobResponse::Chunk(Some(ct)) => break ct,
                BlobResponse::Chunk(None) => return give_up(format!("gallery chunk {index} unavailable")),
                BlobResponse::Rejected(r) => return DownloadOutcome::Retry(format!("blob rejected: {r}")),
                _ => return DownloadOutcome::Retry("gallery download: unexpected response".into()),
            }
        };
        let is_last = index + 1 == pg.chunks;
        let pt = match blob::open_chunk(&pg.key, &pg.blob_id, index, pg.chunks, is_last, &ct) {
            Ok(p) => p,
            Err(e) => return DownloadOutcome::Retry(format!("chunk {index}: {e}")),
        };
        if buf.len() + pt.len() > content::MAX_GALLERY_BYTES {
            return give_up("gallery exceeded size cap".into());
        }
        hasher.update(&pt);
        buf.extend_from_slice(&pt);
    }
    if buf.len() as u64 != pg.size {
        return give_up("gallery size mismatch".into());
    }
    let got: [u8; 32] = hasher.finalize().into();
    if got != pg.hash {
        return give_up("gallery hash mismatch".into());
    }
    let (ts, photos) = match content::unpack_gallery(&buf) {
        Ok(p) => p,
        Err(e) => return give_up(format!("gallery unpack: {e}")), // a malformed pack is terminal
    };
    if let Err(e) = store.set_peer_photos(pg.sender, photos, ts) {
        return DownloadOutcome::Retry(format!("saving gallery: {e}"));
    }
    let _ = store.remove_pending_gallery(&pg.sender, &pg.blob_id);
    DownloadOutcome::Done(String::new())
}

/// Carrier id binding the blob cookie — constant so it's consistent across a transfer's
/// chunks and cookie retries (the relay binds the cookie to `(client_addr, carrier_id)`).
const BLOB_CARRIER: &[u8] = b"karst-blob";

/// What `blob_upload` returns: `(blob_id, per-file key, plaintext SHA-256, chunk count)`
/// — the `FileRef` fields to send inline over the session.
pub type UploadedBlob = ([u8; 32], [u8; 32], [u8; 32], u32);

/// §15 streaming UPLOAD: encrypt `reader` chunk-by-chunk and park it as an E2E blob on
/// the relay. Peak RAM is O(chunk) — never the whole file. Returns the `FileRef` fields
/// (blob id, per-file key, plaintext SHA-256, chunk count) to send inline over the
/// session. `size` is the plaintext length. The relay only ever sees ciphertext.
pub fn blob_upload<R: std::io::Read>(
    relay: &Relay,
    cap: &Capability,
    reader: R,
    size: u64,
) -> Result<UploadedBlob, String> {
    // The simple path (CLI/tests): no progress, no cancellation.
    let never = std::sync::atomic::AtomicBool::new(false);
    blob_upload_with(relay, cap, reader, size, &never, |_, _| {})
}

/// Minimum byte delta between `on_progress` calls, so a long transfer does not flood
/// the UI channel with tens of thousands of events (1 GB / 60 KiB ≈ 17k chunks).
const BLOB_PROGRESS_STEP: u64 = 512 * 1024;

/// How many chunks a resumable upload keeps in flight at once. The relay accepts chunks out of
/// order, so several `blob_put`s (each its own connection) overlap their handshakes + transfers
/// instead of paying them strictly one after another. 4 hides most of the per-chunk round-trip
/// latency without opening an unreasonable number of concurrent connections.
const PIPELINE_DEPTH: usize = 4;

/// How much plaintext a resumable download writes between fsyncs. Each chunk is still sealed as its
/// own record (so a resume stays aligned), but fsync is batched at this granularity — a crash
/// re-fetches at most this much, in exchange for far fewer fsyncs than one-per-60-KiB-chunk.
const CHECKPOINT_EVERY_BYTES: u64 = 2 * 1024 * 1024;

/// Like [`blob_upload`], but with cooperative cancellation (`cancel`) and a progress
/// callback (`on_progress(done, total)` in plaintext bytes, throttled by
/// `BLOB_PROGRESS_STEP`). Cancellation is checked on a chunk boundary →
/// `Err("cancelled")`; the partially uploaded blob stays on the relay until the TTL
/// sweep removes it.
#[allow(clippy::too_many_arguments)]
pub fn blob_upload_with<R: std::io::Read>(
    relay: &Relay,
    cap: &Capability,
    reader: R,
    size: u64,
    cancel: &std::sync::atomic::AtomicBool,
    on_progress: impl FnMut(u64, u64),
) -> Result<UploadedBlob, String> {
    // Every upload runs through the resumable path with a FRESH random id+key, so the relay's
    // watermark is 0 and it uploads the whole file. A caller that persists the id+key resumes from
    // the watermark instead — same code, one function.
    blob_upload_resumable_with(relay, cap, reader, size, blob::random32(), blob::random32(), cancel, on_progress)
}

/// A blob's upload progress on `relay`: `(next, count, complete)` — how many chunks it holds. `None`
/// if it has never seen the blob (a fresh upload starts at 0). The watermark a resume continues from.
pub fn blob_stat(relay: &Relay, blob_id: [u8; 32]) -> Result<Option<(u32, u32, bool)>, String> {
    relay.transport().blob_stat(blob_id).map_err(|e| format!("blob stat: {e}"))
}

/// Like [`blob_upload`], but RESUMABLE. Given a STABLE `blob_id`+`key` (the caller persists them
/// across attempts), it asks the relay how many chunks it already holds (`blob_stat`) and uploads
/// only from there — so a crash mid-upload of a multi-GB file re-sends a few chunks, not the whole
/// file. The relay's blob index is durable (FT2), so this survives the RELAY restarting too. The
/// full-file hash is recomputed over every chunk in one read pass, so no state beyond `blob_id`+`key`
/// needs persisting. Idempotent: a completed blob re-runs to the same `FileRef` without re-uploading.
pub fn blob_upload_resumable<R: std::io::Read>(
    relay: &Relay,
    cap: &Capability,
    reader: R,
    size: u64,
    blob_id: [u8; 32],
    key: [u8; 32],
) -> Result<UploadedBlob, String> {
    let never = std::sync::atomic::AtomicBool::new(false);
    blob_upload_resumable_with(relay, cap, reader, size, blob_id, key, &never, |_, _| {})
}

/// Like [`blob_upload_resumable`], with cooperative cancellation + a progress callback (as
/// [`blob_upload_with`]). This is the base every upload runs through: [`blob_upload_with`] calls it
/// with a fresh random `blob_id`+`key` (so `next` is 0 and it uploads everything), while a resuming
/// caller passes the persisted id+key to continue from the relay's watermark.
#[allow(clippy::too_many_arguments)]
pub fn blob_upload_resumable_with<R: std::io::Read>(
    relay: &Relay,
    cap: &Capability,
    mut reader: R,
    size: u64,
    blob_id: [u8; 32],
    key: [u8; 32],
    cancel: &std::sync::atomic::AtomicBool,
    mut on_progress: impl FnMut(u64, u64),
) -> Result<UploadedBlob, String> {
    use sha2::Digest;
    use std::sync::atomic::Ordering::Relaxed;
    let transport = relay.transport();
    let count = blob::chunk_count(size);
    // Resume watermark: how many chunks the relay already holds (0 if it has never seen this blob).
    let next = transport
        .blob_stat(blob_id)
        .map_err(|e| format!("blob stat: {e}"))?
        .map(|(n, _, _)| n)
        .unwrap_or(0);
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; blob::BLOB_CHUNK];
    let initial_done = (next as u64 * blob::BLOB_CHUNK as u64).min(size);
    on_progress(initial_done, size);

    // PIPELINED upload: the relay now accepts chunks OUT OF ORDER, so up to PIPELINE_DEPTH chunks
    // can be in flight at once (each `blob_put` is its own connection). The main thread reads +
    // hashes chunks IN ORDER (the FileRef hash is order-dependent) and hands the ones that still
    // need uploading to a pool of worker threads; workers upload concurrently and count bytes.
    let done_bytes = std::sync::atomic::AtomicU64::new(initial_done);
    let uploaded = std::sync::atomic::AtomicU32::new(0);
    let err: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
    let (tx, rx) = std::sync::mpsc::sync_channel::<(u32, Vec<u8>, usize)>(PIPELINE_DEPTH);
    let rx = std::sync::Mutex::new(rx);
    let to_upload = count.saturating_sub(next);
    // A4-1: the blob store owns a blob by the `client_addr` of its FIRST chunk, so this field is a
    // storage identity, not a transport one — and `relay.pseudonym` is minted fresh per `Relay`,
    // i.e. per process. A resume after a client restart therefore arrived as a stranger and was
    // rejected forever. The handle is derived from the blob's own key instead (see
    // `blob::owner_token`), which the resume record already persists.
    //
    // What this costs, stated plainly: `sender` is also the relay's per-sender quota bucket, and a
    // per-blob handle makes `MAX_BLOBS_PER_SENDER` vacuous and collapses the per-sender byte
    // aggregate into the per-blob one for HONEST clients (a hostile one always minted a fresh
    // `client_addr` per blob at zero cost — blobstore.rs says so in its own header). What still
    // binds: the per-blob size cap, the global store cap, and `BLOB_CAP_QUOTA` — which meters by
    // `capability_id`, so it is unaffected by this change. Note the last is a RATE (bytes per
    // window), not a residency bound, so it limits how fast one credential can push bytes, not how
    // much it can have parked at once. Aggregating a client's blobs without a durable, linkable
    // per-client address needs the relay to treat ownership as a proof and meter by capability —
    // a relay-side change, not one this side can make alone.
    let owner = blob::owner_token(&key, &blob_id).to_vec();

    let hash: [u8; 32] = std::thread::scope(|scope| -> Result<[u8; 32], String> {
        for _ in 0..PIPELINE_DEPTH {
            scope.spawn(|| {
                let transport = relay.transport();
                let mut cookie: Option<admission::cookie::Cookie> = None;
                // ONE Noise session reused for ALL of this worker's chunks (§15 / FT4). The relay
                // bounds how many requests a connection may carry, so on session death we simply
                // re-open and retry the chunk (idempotent at the relay).
                let mut sess: Option<BlobSession> = None;
                while let Ok((index, ct, want)) = rx.lock().unwrap().recv() {
                    // Once anything has failed/cancelled, just drain the channel so the producer
                    // never blocks on a full queue — no upload, no double-report.
                    if err.lock().unwrap().is_some() {
                        continue;
                    }
                    if cancel.load(Relaxed) {
                        *err.lock().unwrap() = Some("cancelled".into());
                        continue;
                    }
                    let mut attempts = 0u32;
                    let stored = loop {
                        attempts += 1;
                        if attempts > 8 {
                            *err.lock().unwrap() = Some("blob upload: too many reconnects".into());
                            break false;
                        }
                        // Ensure a live session (re-open after a death or the relay's request cap).
                        if sess.is_none() {
                            match transport.open_blob_session() {
                                Ok(s) => sess = Some(s),
                                Err(e) => {
                                    *err.lock().unwrap() = Some(format!("blob upload connect: {e}"));
                                    break false;
                                }
                            }
                        }
                        // Per-chunk nonce of the required shape, so a proof minted for the
                        // message path cannot be replayed here (the scope is not folded into the
                        // MAC, so the nonce shape is what separates the classes).
                        let nonce = node::protocol::blob_put_nonce(&blob_id, index);
                        let req = BlobPutRequest {
                            request_nonce: nonce.clone(),
                            capability_proof: cap.prove(&nonce, 0),
                            // The blob's durable owner handle, NOT the session pseudonym (A4-1).
                            // The cookie is bound to whatever address asked for it, and each
                            // worker starts with `cookie: None`, so every cookie on this path is
                            // minted against this same handle — none is ever carried across two
                            // different addresses.
                            client_addr: owner.clone(),
                            carrier_id: BLOB_CARRIER.to_vec(),
                            cookie,
                            blob_id,
                            index,
                            count,
                            data: ct.clone(),
                        };
                        match sess.as_mut().unwrap().put(&req) {
                            Ok(BlobResponse::NeedCookie(c)) => cookie = Some(c),
                            Ok(BlobResponse::Stored) | Ok(BlobResponse::Complete) => break true,
                            Ok(BlobResponse::Rejected(r)) => {
                                *err.lock().unwrap() = Some(format!("blob upload rejected: {r}"));
                                break false;
                            }
                            Ok(_) => {
                                *err.lock().unwrap() = Some("blob upload: unexpected response".into());
                                break false;
                            }
                            // Session died (relay closed it after its bounded run, or the link
                            // dropped) — drop it, re-open, retry the same chunk.
                            Err(_) => sess = None,
                        }
                    };
                    if !stored {
                        continue;
                    }
                    done_bytes.fetch_add(want as u64, Relaxed);
                    uploaded.fetch_add(1, Relaxed);
                }
            });
        }

        // Producer: read + hash every chunk in order, enqueue the ones that need uploading.
        for index in 0..count {
            let want = if index + 1 == count {
                (size - index as u64 * blob::BLOB_CHUNK as u64) as usize
            } else {
                blob::BLOB_CHUNK
            };
            reader.read_exact(&mut buf[..want]).map_err(|e| format!("reading file: {e}"))?;
            hasher.update(&buf[..want]);
            if index < next {
                continue; // already on the relay — hashed for the FileRef, not re-uploaded
            }
            if err.lock().unwrap().is_some() {
                break;
            }
            let is_last = index + 1 == count;
            let ct = blob::seal_chunk(&key, &blob_id, index, count, is_last, &buf[..want]);
            // Blocks when PIPELINE_DEPTH chunks are queued (backpressure → bounded memory).
            if tx.send((index, ct, want)).is_err() {
                break;
            }
            on_progress(done_bytes.load(Relaxed), size);
        }
        drop(tx); // no more work → workers exit once the channel drains

        // Wait for the in-flight uploads to finish, reporting progress as bytes land.
        while err.lock().unwrap().is_none() && uploaded.load(Relaxed) < to_upload {
            on_progress(done_bytes.load(Relaxed), size);
            std::thread::sleep(std::time::Duration::from_millis(40));
        }
        if let Some(e) = err.lock().unwrap().take() {
            return Err(e);
        }
        on_progress(size, size);
        Ok(hasher.finalize().into())
    })?;
    if !verify_durability(relay, blob_id, key, count)? {
        return Err("the relay did not retain the upload (durability check failed)".into());
    }
    Ok((blob_id, key, hash, count))
}

/// Proof-of-retrievability spot check: fetch ONE random chunk of a parked blob and verify it
/// decrypts + authenticates at its position. `Ok(true)` proves the relay is holding that chunk
/// right now (Filecoin/Storj-style storage audit); `Ok(false)` = the relay does not have it (it
/// dropped the upload, was swept, or claimed "durable" but isn't). This is how a client turns a
/// relay's DURABLE claim into a checked fact. Note the asymmetry: the reverse ("ephemeral — I
/// forgot it") is NOT provable remotely, so only `durable` is verifiable this way.
///
/// This check runs immediately after every upload, on the SAME `blob_id` — so whatever address it
/// carries is, by construction, tied to the blob that was just put. It therefore uses the blob's
/// own owner handle rather than `relay.pseudonym`: the session pseudonym would have re-linked every
/// blob an uploader parked ("put X from T_x, get X from P; put Y from T_y, get Y from P") and
/// handed back exactly the cross-blob correlation the per-blob handle removes. Nothing is weakened:
/// the get path is cookie-gated only (bearer-by-id, never ownership-checked), the cookie is minted
/// against whatever address asks, and this caller holds `key` by definition.
pub fn verify_durability(relay: &Relay, blob_id: [u8; 32], key: [u8; 32], count: u32) -> Result<bool, String> {
    if count == 0 {
        return Ok(true);
    }
    let index = u32::from_le_bytes(blob::random32()[..4].try_into().unwrap()) % count;
    let transport = relay.transport();
    let owner = blob::owner_token(&key, &blob_id).to_vec();
    let mut cookie: Option<admission::cookie::Cookie> = None;
    loop {
        let req = BlobGetRequest {
            client_addr: owner.clone(),
            carrier_id: BLOB_CARRIER.to_vec(),
            cookie,
            blob_id,
            index,
        };
        match transport.blob_get(&req) {
            BlobResponse::NeedCookie(c) => cookie = Some(c),
            BlobResponse::Chunk(Some(ct)) => {
                let is_last = index + 1 == count;
                return Ok(blob::open_chunk(&key, &blob_id, index, count, is_last, &ct).is_ok());
            }
            BlobResponse::Chunk(None) => return Ok(false),
            BlobResponse::Rejected(r) => return Err(format!("durability check rejected: {r}")),
            _ => return Err("durability check: unexpected response".into()),
        }
    }
}

/// §15 streaming DOWNLOAD: fetch each ciphertext chunk, decrypt + verify position, and
/// append plaintext to `out` (e.g. a temp file) — peak RAM O(chunk). On success the
/// end-to-end plaintext hash is verified before `out` is returned for the caller to
/// flush/rename into place.
#[allow(clippy::too_many_arguments)]
pub fn blob_download<W: std::io::Write>(
    relay: &Relay,
    id: [u8; 32],
    key: [u8; 32],
    count: u32,
    expected_hash: [u8; 32],
    out: W,
) -> Result<W, String> {
    // The simple path (tests): no progress, no cancellation. `total` does not matter
    // here — the callback is a no-op.
    let never = std::sync::atomic::AtomicBool::new(false);
    blob_download_with(
        relay, id, key, count, expected_hash, out, 0, &never, |_, _| {},
    )
}

/// Like [`blob_download`], but with cancellation (`cancel`) and progress
/// (`on_progress(done, total)`, where `total` is the file size from `FileRef.size`).
/// Cancellation happens on a chunk boundary → `Err("cancelled")`; the caller removes
/// the temp file.
#[allow(clippy::too_many_arguments)]
pub fn blob_download_with<W: std::io::Write>(
    relay: &Relay,
    id: [u8; 32],
    key: [u8; 32],
    count: u32,
    expected_hash: [u8; 32],
    out: W,
    total: u64,
    cancel: &std::sync::atomic::AtomicBool,
    mut on_progress: impl FnMut(u64, u64),
) -> Result<W, String> {
    use std::sync::atomic::Ordering::Relaxed;
    let transport = relay.transport();
    let mut rx = blob::BlobReceiver::new(key, id, count, expected_hash, out);
    let mut cookie: Option<admission::cookie::Cookie> = None;
    let mut done: u64 = 0;
    let mut last_reported: u64 = 0;
    for index in 0..count {
        if cancel.load(Relaxed) {
            return Err("cancelled".into());
        }
        loop {
            let req = BlobGetRequest {
                client_addr: relay.pseudonym.to_vec(),
                carrier_id: BLOB_CARRIER.to_vec(),
                cookie,
                blob_id: id,
                index,
            };
            match transport.blob_get(&req) {
                BlobResponse::NeedCookie(c) => cookie = Some(c),
                BlobResponse::Chunk(Some(ct)) => {
                    rx.feed(index, &ct)?;
                    break;
                }
                BlobResponse::Chunk(None) => return Err(format!("blob chunk {index} unavailable")),
                BlobResponse::Rejected(r) => return Err(format!("blob download rejected: {r}")),
                _ => return Err("blob download: unexpected response".into()),
            }
        }
        done += (total.saturating_sub(done)).min(blob::BLOB_CHUNK as u64);
        if done - last_reported >= BLOB_PROGRESS_STEP || index + 1 == count {
            on_progress(done, total);
            last_reported = done;
        }
    }
    rx.finish()
}

/// The result of a crash-safe pending-download attempt ([`download_blob`]).
pub enum DownloadOutcome {
    /// Completed (or already-complete): the received-file container id. History + index are
    /// written and the pending entry is gone.
    Done(String),
    /// The blob is unrecoverable (relay swept it, or past the retry horizon, or the user
    /// cancelled) — the pending entry was dropped. Do not retry.
    GaveUp(String),
    /// A transient failure (transport hiccup); the pending entry stays for the next poll.
    Retry(String),
}

/// Download ONE pending large-file blob, crash-safely and idempotently. The FileRef was
/// persisted as a pending download on receive (before the ack), so this survives a crash: on
/// restart the entry is still here and this re-drives it. The blob lives on the relay until
/// its TTL, so a retry simply re-fetches.
///
/// - **Idempotent completion:** if a received-file already records this `blob_id`, it is
///   already done (a crash landed after the index write but before the pending entry was
///   dropped) — drop the entry and report `Done`, no re-download, no double record.
/// - **Restart-clean:** streams into a FRESH sealed file; a prior crash's partial is a
///   separate orphan swept by [`Store::sweep_orphan_files`], never appended to.
/// - **Give-up bound:** past the relay blob TTL, or when the relay reports the blob gone, or
///   on cancel — drop the entry so it can't retry forever (the outbox-TTL discipline).
///
/// The relay-restart limit is explicit: a relay that wiped its blob store cannot serve the
/// chunks, and no client-side retry can recover the file — it reports `GaveUp`.
pub fn download_blob(
    store: &Store,
    relay: &Relay,
    pd: &store::PendingDownload,
    now: u64,
    cancel: &std::sync::atomic::AtomicBool,
    on_progress: impl FnMut(u64, u64),
) -> DownloadOutcome {
    // Already done? (crash after record, before the pending entry was dropped.)
    if pd.blob_id != [0u8; 32] {
        if let Some(f) = store
            .list_received_files()
            .unwrap_or_default()
            .iter()
            .find(|f| f.blob_id == pd.blob_id)
        {
            let _ = store.remove_pending_download(&pd.blob_id);
            return DownloadOutcome::Done(f.id.clone());
        }
    }
    // Past the retry horizon (blob TTL) — a swept blob must not retry forever.
    if now.saturating_sub(pd.queued_at) > node::protocol::MAILBOX_TTL_SECS {
        let _ = store.remove_pending_download(&pd.blob_id);
        return DownloadOutcome::GaveUp("download expired (blob past TTL)".into());
    }
    use std::io::Write;
    use std::sync::atomic::Ordering::Relaxed;
    // Open fresh, or RESUME the partial from a prior attempt (skipping already-fetched chunks).
    let (fid, mut writer, chunks_done) =
        match store.open_or_resume_download(&pd.name, pd.container_id.as_deref()) {
            Ok(x) => x,
            Err(e) => return DownloadOutcome::Retry(format!("open received file: {e}")),
        };
    // Record which container this download streams into, so a crash resumes THIS partial.
    if pd.container_id.as_deref() != Some(fid.as_str()) {
        let _ = store.set_pending_container(&pd.blob_id, &fid);
    }

    // Hash IN-LINE as we fetch — the fresh path (chunks_done == 0) then needs no second read.
    // Only a resume seeds the hasher from the K chunks already on disk (one extra read, rare).
    use sha2::Digest;
    let mut hasher = if chunks_done > 0 {
        match store.hasher_from_partial(&fid) {
            Ok(h) => h,
            Err(e) => return DownloadOutcome::Retry(format!("seed resume hash: {e}")),
        }
    } else {
        sha2::Sha256::new()
    };

    let transport = relay.transport();
    let mut cookie: Option<admission::cookie::Cookie> = None;
    let mut on_progress = on_progress;
    let mut done = (chunks_done as u64 * blob::BLOB_CHUNK as u64).min(pd.size);
    let mut since_sync = 0u64;
    for index in chunks_done..pd.chunks {
        if cancel.load(Relaxed) {
            // Intentional cancel — stop retrying this file and clean the partial.
            let _ = store.remove_pending_download(&pd.blob_id);
            let _ = store.remove_received_file(&fid);
            return DownloadOutcome::GaveUp("cancelled".into());
        }
        let ct = loop {
            let req = BlobGetRequest {
                client_addr: relay.pseudonym.to_vec(),
                carrier_id: BLOB_CARRIER.to_vec(),
                cookie,
                blob_id: pd.blob_id,
                index,
            };
            match transport.blob_get(&req) {
                BlobResponse::NeedCookie(c) => cookie = Some(c),
                BlobResponse::Chunk(Some(ct)) => break ct,
                BlobResponse::Chunk(None) => {
                    // The relay no longer has the blob (swept) — unrecoverable.
                    let _ = store.remove_pending_download(&pd.blob_id);
                    let _ = store.remove_received_file(&fid);
                    return DownloadOutcome::GaveUp(format!("blob chunk {index} unavailable"));
                }
                BlobResponse::Rejected(r) => return DownloadOutcome::Retry(format!("blob rejected: {r}")),
                _ => return DownloadOutcome::Retry("blob download: unexpected response".into()),
            }
        };
        // Decrypt + verify the chunk at its position (AAD-bound); a tamper fails closed. Each
        // chunk is SEALED as its own record (the alignment a resume counts on), but we fsync in
        // BATCHES (~2 MiB) rather than per 60 KiB chunk: a resume tolerates a lost/torn unsynced
        // tail (it truncates + re-fetches), so batching only risks re-fetching a couple MiB after
        // a crash — for a large cut in fsync traffic on big downloads.
        let is_last = index + 1 == pd.chunks;
        let pt = match blob::open_chunk(&pd.key, &pd.blob_id, index, pd.chunks, is_last, &ct) {
            Ok(p) => p,
            Err(e) => return DownloadOutcome::Retry(format!("chunk {index}: {e}")),
        };
        if let Err(e) = writer.write_all(&pt).and_then(|()| writer.seal()) {
            return DownloadOutcome::Retry(format!("write chunk {index}: {e}"));
        }
        since_sync += pt.len() as u64;
        if since_sync >= CHECKPOINT_EVERY_BYTES {
            if let Err(e) = writer.sync() {
                return DownloadOutcome::Retry(format!("sync at chunk {index}: {e}"));
            }
            since_sync = 0;
        }
        hasher.update(&pt);
        done = (done + pt.len() as u64).min(pd.size);
        on_progress(done, pd.size);
    }
    if let Err(e) = writer.finish() {
        return DownloadOutcome::Retry(format!("finalize file: {e}"));
    }
    // End-to-end integrity check (each chunk was already AEAD-authenticated at its position;
    // this is the whole-file SHA-256, accumulated in-line above + seeded from any resumed
    // prefix). A mismatch means a bad partial — discard it and re-download from scratch.
    let got: [u8; 32] = hasher.finalize().into();
    if got == pd.hash {
        // The commit steps used to be `let _ = ...` and `Done` was returned regardless, so a
        // download could be reported COMPLETE while the file was not indexed — bytes on disk that
        // nothing points at, and a user told a file arrived that they cannot find (A8-10). The
        // three steps do not carry equal weight, so they are handled separately rather than all
        // being swallowed:
        if let Err(e) = store.record_received_file(&store::ReceivedFile {
            id: fid.clone(),
            name: pd.name.clone(),
            size: pd.size,
            sender: pd.sender,
            ts: pd.ts,
            blob_id: pd.blob_id,
        }) {
            // Load-bearing: without the record the file is unreachable. Keep the pending entry so
            // the next pass retries (the blob lives on the relay until its TTL).
            return DownloadOutcome::Retry(format!("recording the received file: {e}"));
        }
        // Not load-bearing — the file IS saved and indexed — but it must not be silent, or a
        // chat that stopped showing arrivals looks like nothing was sent.
        if let Err(e) = store.append_history(&store::HistoryRecord {
            from_me: false,
            peer_ik: pd.sender,
            text: format!("📎 {}", pd.name).into_bytes(),
            ts: pd.ts,
        }) {
            eprintln!("warning: file saved, but its history line failed: {e}");
        }
        if let Err(e) = store.remove_pending_download(&pd.blob_id) {
            // Harmless (the retry is idempotent by blob_id) but worth knowing about.
            eprintln!("warning: could not clear the pending download entry: {e}");
        }
        DownloadOutcome::Done(fid)
    } else {
        let _ = store.remove_received_file(&fid);
        let _ = store.set_pending_container(&pd.blob_id, ""); // drop the bad partial ref
        DownloadOutcome::Retry("integrity check failed — will re-download".into())
    }
}

/// How many recent incoming history records to consult for the plaintext-first dedup. A
/// redelivered duplicate only arises in the crash-before-ratchet-save window and reappears
/// on the very next poll, so its twin is among the newest records; a generous window absorbs
/// several intervening messages without loading the whole log per poll.
const HISTORY_DEDUP_WINDOW: usize = 1024;

/// Persist the plaintext of incoming TEXT messages to history — the **plaintext-first** step
/// of the receive path. Called by `recv_session`/`recv_session_multi` AFTER decrypt but
/// BEFORE the ratchet/OPK commit and the ACK, so a crash between the commit and this write
/// can no longer lose the message: the plaintext is already durable. Deduped by `payload_id`
/// so the single duplicate that window can produce — a message re-decrypted because the
/// ratchet advance was lost — is not appended twice. Errors propagate so the caller skips the
/// commit/ack and the message redelivers.
///
/// Non-text content (files, reactions, profile) is NOT persisted here — the caller keeps its
/// own richer handling and its own durability. That is a documented residual: a file or
/// reaction redelivered in the same window can still re-apply once (files → crash-safe blob
/// slice; reactions → idempotent-reaction slice).
fn persist_incoming_history(store: &Store, msgs: &[Option<Received>], now: u64) -> Result<(), String> {
    let mut seen = store
        .recent_incoming_ids(HISTORY_DEDUP_WINDOW)
        .map_err(|e| format!("reading history ids: {e}"))?;
    for m in msgs.iter().flatten() {
        if !seen.insert(m.msg_id) {
            continue; // already persisted (a redelivered duplicate, or a dup within this batch)
        }
        let (text, ts) = match content::decode(&m.plaintext) {
            Ok(content::Content::TextStamped { text, ts })
            | Ok(content::Content::TextReply { text, ts, .. }) => (text, ts),
            // Unstamped `Text` is REFUSED (#179). Nothing has produced it since messages carried
            // the sender's timestamp: accepting it meant stamping the message with our ARRIVAL
            // time, which then feeds `msg_id` — so the two sides computed different ids for one
            // message and reactions, replies and edits silently failed to line up. The variant
            // stays reserved in `Content` because postcard numbers variants positionally and the
            // §14 vectors pin those numbers; what is gone is the behaviour.
            Ok(content::Content::Text(_)) => {
                eprintln!("[karst] refused an unstamped Text message — no sender timestamp");
                continue;
            }
            // A large-file announcement: persist it as a PENDING DOWNLOAD (idempotent by
            // blob_id) so a crash mid-download can retry — the blob lives on the relay until
            // its TTL. Durable here, BEFORE the ack, for the same reason text history is: the
            // relay may drop the message once acked. The actual download is the caller's, off
            // this path; it removes the pending entry on success.
            Ok(content::Content::FileRef { blob_id, key, hash, name, size, chunks }) => {
                store
                    .add_pending_download(&store::PendingDownload {
                        blob_id,
                        key,
                        hash,
                        name,
                        size,
                        chunks,
                        sender: m.sender,
                        ts: now,
                        queued_at: now,
                        container_id: None,
                    })
                    .map_err(|e| format!("recording pending download: {e}"))?;
                continue;
            }
            // A post-attachment blob pointer: persist it as a PENDING POST ATTACHMENT (idempotent
            // by blob_id) so a crash mid-fetch retries — same before-ack durability as FileRef. The
            // fetch itself is the caller's (off this path); it drops the entry on success.
            //
            // SEC-31: admission happens HERE, before anything attacker-supplied is committed.
            // Checking only at fetch time would still let a stranger's refs occupy the whole
            // `MAX_PENDING_POST_ATTACHMENTS` queue and churn a retry on every poll — the queue
            // slot is the resource, so the gate belongs at the door.
            //
            // Two independent conditions, both previously absent:
            //  * the sender must be a FEED SOURCE — exactly the gate `Publication` itself passes
            //    through. An attachment decorates a post; a peer whose posts we would refuse has
            //    no business making us fetch their media. `GalleryRef` three arms down had its
            //    equivalent gate from the start; this variant simply never got one.
            //  * the pointer's declared shape must be one an honest sender could produce, which
            //    for the chunk count means exact equality with `blob::chunk_count(size)`.
            // Both are cheap and local. What they deliberately do NOT check is that `post_id`
            // names a post we already hold: the ref is persisted here, during `recv_session_multi`,
            // while its `Publication` is applied to the feed by the CALLER after this returns — so
            // within a single poll batch the post legitimately does not exist yet, and that gate
            // would drop honest media.
            Ok(content::Content::PostAttachmentRef {
                post_id, index, kind, name, blob_id, key, hash, size, chunks,
            }) => {
                if store.is_feed_source(&m.sender)
                    && content::blob_ref_shape_ok(size, chunks, content::MAX_POST_IMAGE_BYTES)
                    && name.len() <= content::MAX_FILENAME
                {
                    store
                        .add_pending_post_attachment(&store::PendingPostAttachment {
                            blob_id,
                            key,
                            hash,
                            post_id,
                            index,
                            kind,
                            name,
                            size,
                            chunks,
                            sender: m.sender,
                            queued_at: now,
                        })
                        .map_err(|e| format!("recording pending post attachment: {e}"))?;
                }
                continue;
            }
            // A gallery blob pointer: persist it as a PENDING GALLERY (keyed by sender, superseding an
            // older ref) so a crash mid-fetch retries. Only a CONFIRMED contact's gallery is fetched —
            // a blob download is many relay round-trips, so an unsolicited ref from a stranger is
            // dropped. The fetch itself is the caller's; it drops the entry on success.
            Ok(content::Content::GalleryRef { blob_id, key, hash, size, chunks }) => {
                // SEC-31 applies to this pointer too: being a confirmed contact earns the right to
                // send us a gallery, not the right to name an arbitrary chunk count.
                if store.is_confirmed_contact(&m.sender).unwrap_or(false)
                    && content::blob_ref_shape_ok(size, chunks, content::MAX_GALLERY_BYTES)
                {
                    store
                        .add_pending_gallery(&store::PendingGallery {
                            sender: m.sender,
                            blob_id,
                            key,
                            hash,
                            size,
                            chunks,
                            queued_at: now,
                        })
                        .map_err(|e| format!("recording pending gallery: {e}"))?;
                }
                continue;
            }
            // TextExpiring is a disappearing message: delivered to the UI in memory, NEVER
            // written to disk. Not persisted and not quarantined — for THIS type, being lost on
            // a crash is the feature, so acking it while it exists only in RAM is correct.
            Ok(content::Content::TextExpiring { .. }) => continue,
            // Everything else — profile updates, publications, contact control messages, inline
            // chunks, and any `Content` a newer build invented — is applied by the CALLER, after
            // this function returns and after the ack. That ordering was the bug (SEC-40): the
            // ack tells the relay to delete its only copy, so a crash, an account switch or a
            // full disk between the ack and the handler lost an authenticated message for good.
            //
            // Advancing the ratchet proves the ciphertext cannot be read twice. It proves nothing
            // about the application event surviving. So the plaintext is parked durably HERE,
            // before the ack is allowed — losing it now takes losing the quarantine file too.
            other => {
                let _ = other; // the decode outcome itself is not needed; the bytes are
                store
                    .quarantine_incoming(m.sender, &m.plaintext, now)
                    .map_err(|e| format!("quarantining an unapplied message: {e}"))?;
                continue;
            }
        };
        store
            .append_history_incoming(
                &store::HistoryRecord { from_me: false, peer_ik: m.sender, text, ts },
                m.msg_id,
            )
            .map_err(|e| format!("history append: {e}"))?;
    }
    Ok(())
}

/// §2.1: забрать входящие, ПЕРСИСТИТЬ плейнтекст, затем продвинуть сессии. Порядок
/// (под flock на сессиях всё время): fetch(lease) → decrypt → **persist history
/// (plaintext-first, deduped)** → save OPKs+sessions → ACK. Плейнтекст durable ДО
/// коммита ratchet/OPK и ДО ACK, поэтому краш в любом из окон `[OPK→session]` /
/// `[session→history]` больше НЕ теряет сообщение (при переобработке дубликат
/// отсекается по `payload_id`, либо fail-closed на продвинутом ratchet).
///
/// **FILE-TREE ACCOUNTS ONLY.** This acks internally, which is correct exactly while the
/// `Store` it writes to is the authority. A CONTAINER-backed account's authority is the
/// encrypted container, committed later and separately, so acking here would delete relay
/// mail that the authority has not yet recorded (SEC-34). Container-backed callers use
/// [`recv_session_multi`] + [`DeferredAcks::commit_then_send`]; the desktop, the only
/// container-backed caller, already does. Keep it that way — a container-backed caller
/// reaching for this function is the bug growing back.
pub fn recv_session(
    store: &Store,
    relay: &Relay,
    now: u64,
) -> Result<Vec<Option<Received>>, String> {
    let account = store.load_account().map_err(|e| secret_load_err("account", e))?;
    let transport = relay.transport();
    let fetch_pub = x25519_dalek::PublicKey::from(relay.id.fetch_pub);
    // capability не используется на приёме (fetch-auth = cookie + ownership-proof).
    let mut peer = Peer::new(transport, account, dev_capability(), fetch_pub);
    // Lease/ACK receive: fetch keeps the messages on the relay until we have durably saved
    // the advanced ratchet, then `ack_all` deletes them. A crash before the ACK redelivers
    // the exact ciphertext; the ratchet's transactional decrypt fails closed on the
    // already-consumed duplicate, so redelivery is effectively-once with no dedup store.

    let _lock = store.lock_sessions().map_err(|e| format!("замок сессий: {e}"))?;
    peer.import_state(store.load_sessions().map_err(|e| format!("чтение сессий: {e}"))?);
    // Load one-time prekey secrets so an opener that consumed one can be accepted; receive
    // deletes the used ones, and we persist the remainder so they are never reused.
    peer.load_opks(&store.load_opks().map_err(|e| format!("reading one-time prekeys: {e}"))?);
    let msgs = peer.receive(now)?;
    // PLAINTEXT-FIRST: persist the decrypted text to history BEFORE the state commit or the ACK,
    // so a crash between them cannot lose the message (`[save_sessions → history]`: advanced
    // ratchet, unpersisted plaintext). A crash here just redelivers; the dedup (or the ratchet's
    // fail-closed on an already-advanced session) prevents a double. The whole op runs under the
    // sessions flock, so no concurrent receive can interleave.
    persist_incoming_history(store, &msgs, now)?;
    // The burnt one-time prekey and the session derived from it commit TOGETHER (CRYPTO-26):
    // two writes here meant a crash could leave the prekey gone with no session to show for it,
    // and the redelivered opener then had nothing left to re-derive the 4th DH term from.
    store
        .save_receive_commit(&peer.export_state(), &peer.export_opks())
        .map_err(|e| format!("saving the receive commit: {e}"))?;
    // Plaintext + ratchet + OPKs durable ⇒ safe to delete the leased messages from the relay.
    peer.ack_all(now);
    Ok(msgs)
}

/// The result of a multi-homed receive.
pub struct MultiReceive {
    /// Every decrypted message (or `None` per envelope not addressed to us) across the
    /// relays that answered.
    pub messages: Vec<Option<Received>>,
    /// The ratchet state advanced through the relays that answered — persist this.
    pub state: PeerState,
    /// The remaining one-time prekey secrets — persist these.
    pub opks: Vec<node::pqxdh::OneTimeSecret>,
    /// Indices into `relays` whose fetch failed this pass (unreachable / blocked / auth
    /// rejected). Empty = every relay answered. A relay in here cost the caller nothing:
    /// the healthy relays' messages and state advance are still returned.
    pub failed: Vec<usize>,
    /// Messages that arrived from a contact we hold a session with and that our ratchet could NOT
    /// open (R2-11). Zero is the normal answer.
    ///
    /// Anything else is the locally-visible symptom of a SECOND DEVICE using this identity — or of
    /// state restored from a backup while the live copy kept moving. The box address is derived
    /// from the session's own seed, so reaching it proves the sender holds that session; our chain
    /// being unable to open the message means something else advanced it. KARST cannot merge the
    /// two (there is no device identity in `PeerState` to merge along), but the user must not be
    /// left with "messages just stop arriving" and nothing anywhere saying why.
    pub out_of_step: u64,
    /// Lease/ACK receipts to send AFTER the caller persists the advanced state, each tagged
    /// with the index of the relay it must be acked through. Collected ONLY from relays
    /// whose `receive` returned `Ok`: a failed relay's advance is rolled back, so acking its
    /// leased messages would delete mail that was never durably received (delete-without-
    /// deliver). See [`recv_session_multi`], which drains this after its single save.
    pub acks: Vec<(usize, node::peer::AckReceipt)>,
}

/// Receive across SEVERAL relays with one logical identity (multi-homing), returning every
/// message plus the advanced ratchet state, the remaining one-time prekeys, and which
/// relays were unreachable.
///
/// The ratchet with a peer is ONE conversation regardless of which relay carried it, so
/// `PeerState` is keyed by contact, not by relay. That makes the threading order load-
/// bearing: the state exported after fetching relay N must be imported before building
/// relay N+1's `Peer`. Building each relay's `Peer` from the same base state and exporting
/// them independently would let the last export CLOBBER the earlier relays' ratchet
/// advances — a message pulled from relay A would be silently un-received, and its session
/// left one step behind the sender. So we thread `state` (and the OPK set) sequentially
/// through the relays rather than fanning out in parallel.
///
/// A dead or blocked relay does NOT abort the pass — that would make multi-homing worse
/// than single-homing, defeating the whole no-single-load-bearing-carrier point. A relay
/// whose fetch errors is skipped: the threaded state and OPK set carry forward unchanged
/// (that relay contributed nothing), its index is recorded in `failed`, and the remaining
/// relays are still polled.
///
/// One-time prekeys are expected to be published to a SINGLE relay (see the publish side):
/// the secret is consumed on first use, so advertising the same OPK on two relays would let
/// a second sender bind an OPK the first already burned, and its opener could not derive the
/// 4th DH term. Relays that were not given OPKs simply see openers fall back to 3-DH.
pub fn receive_threaded<T: Transport + Clone>(
    account: Account,
    base_state: PeerState,
    opks: Vec<node::pqxdh::OneTimeSecret>,
    relays: &[(T, x25519_dalek::PublicKey)],
    now: u64,
) -> MultiReceive {
    let mut state = base_state;
    let mut opks = opks;
    let mut messages = Vec::new();
    let mut failed = Vec::new();
    let mut acks = Vec::new();
    // R2-11: summed across relays — a diverged channel is diverged everywhere, since the ratchet
    // is one conversation regardless of which relay carried it.
    let mut out_of_step = 0u64;
    for (i, (transport, relay_pub)) in relays.iter().enumerate() {
        // capability is unused on receive (fetch-auth = cookie + ownership-proof), same as
        // `recv_session`; the dev capability fills the slot.
        // TRANSACTIONAL per relay (A5-10). The snapshot is taken BEFORE this relay touches
        // anything, because "the state comes back the way it went in" was simply not true: by
        // the time a later fetch fails, `receive` may already have cleared handles, refreshed
        // cookies, minted fresh routing identities and — the one with teeth — advanced
        // `last_sweep`. Keeping that on an error deferred the next full drop-box sweep on the
        // strength of a sweep that never finished.
        //
        // Serialised rather than cloned so the rollback is the same bytes the disk would hold:
        // if a field is ever added that a clone would share rather than copy, this still
        // restores exactly what was there. The cost is one encode per relay of state that is
        // already bounded, on a path that is doing network round trips anyway.
        let before = postcard::to_stdvec(&state).map_err(|e| e.to_string());
        let mut peer = Peer::new(transport.clone(), account.clone(), dev_capability(), *relay_pub);
        peer.import_state(state);
        peer.load_opks(&opks);
        let opks_before = opks.clone();
        match peer.receive(now) {
            // Collect this relay's ACK receipts ONLY on success: a failed relay's advance is
            // rolled back, so acking its leased messages would delete mail that was never
            // durably received. Tag by relay index so `recv_session_multi` acks each through
            // the right transport after its save.
            Ok(mut got) => {
                messages.append(&mut got);
                acks.extend(peer.take_pending_acks().into_iter().map(|r| (i, r)));
                opks = peer.export_opks();
                out_of_step += peer.take_out_of_step();
                state = peer.export_state();
            }
            Err(_) => {
                failed.push(i);
                // Roll this relay back, keeping every healthy relay's advance. Messages this
                // relay did decrypt before failing are dropped WITH their state change, not
                // without it: unacked, they stay leased and redeliver, and the rolled-back
                // ratchet can still open them. Keeping the advance while dropping the messages
                // is what would have lost them for good.
                match before.as_ref().map(|b| PeerState::from_bytes(b)) {
                    Ok(Ok(restored)) => {
                        state = restored;
                        opks = opks_before;
                    }
                    // A state we serialised ourselves failed to come back: keep the peer's
                    // version rather than losing everything, and say so — silence here would
                    // hide a corruption bug behind a network error.
                    _ => {
                        eprintln!("KARST: could not roll back relay {i}'s state after a failure");
                        opks = peer.export_opks();
                        state = peer.export_state();
                    }
                }
            }
        }
    }
    MultiReceive { messages, state, opks, failed, acks, out_of_step }
}

/// The outcome of a multi-homed poll through the store: the decrypted messages, which
/// of the passed relays were unreachable this poll (indices into the SAME `relays` slice,
/// in order — the caller maps them back to drive a per-relay reachability indicator), and
/// the still-UNSENT lease receipts ([`DeferredAcks`]) the caller must commit before acking.
pub struct MultiPoll {
    pub messages: Vec<Option<Received>>,
    pub failed: Vec<usize>,
    /// See `MultiReceive::out_of_step` — messages from a known contact this vault's ratchet could
    /// not open, the local symptom of a second device on this identity (R2-11).
    pub out_of_step: u64,
    /// The leases this poll took. Nothing is deleted from any relay until these are handed
    /// to [`DeferredAcks::commit_then_send`] with a commit that succeeds — see that type.
    pub acks: DeferredAcks,
}

/// Lease receipts held back until the caller's **authoritative** store has committed.
///
/// SEC-34. `recv_session_multi` used to ack inside itself, right after `store.save_*`. For a
/// file-tree account those saves ARE the durable boundary, so that was correct. For a
/// CONTAINER-backed account they are not: the `Store` is a materialized working copy, and the
/// authority is the encrypted container, written by a separate, later `ContainerVault::save()`.
/// The ack therefore told the relay to delete its only copy while the authority still held the
/// PREVIOUS state — and a failed (or never-attempted) container save silently rolled the
/// messages back out of existence on the next unlock.
///
/// The fix is structural rather than a re-ordering: receiving no longer acks, and the ONLY way
/// to send these receipts is through [`commit_then_send`](Self::commit_then_send), which runs
/// the caller's durability barrier first and sends nothing if it fails. There is deliberately
/// no bare `send`: a caller that cannot name its barrier cannot ack. Forgetting the receipts
/// entirely is the safe failure — the messages stay leased on the relay and redeliver.
#[must_use = "receipts that are never committed leave their messages leased on the relay"]
#[derive(Default)]
pub struct DeferredAcks {
    /// Each receipt paired with the transport of the relay that leased it (handles, cookies
    /// and scope are relay-scoped). Paired rather than index-tagged so receipts from several
    /// polls — different relay sets, different proxies — can be [`merge`](Self::merge)d into
    /// one barrier without the indices meaning different things.
    pending: Vec<(SocketTransport, node::peer::AckReceipt)>,
}

impl DeferredAcks {
    /// No leases taken ⇒ nothing to commit for. A caller keying its container save off "did
    /// this poll take any leases?" (rather than off whether the UI got anything to show) uses
    /// this: control-only mail advances the ratchet and writes pending entries while producing
    /// zero UI events, and it still has to be committed before it is acked.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Fold another poll's receipts in, so one commit covers a whole drain (several pages,
    /// several proxies, several relay sets).
    pub fn merge(&mut self, other: DeferredAcks) {
        self.pending.extend(other.pending);
    }

    /// Run the caller's durability barrier and, ONLY if it succeeds, delete the leased
    /// messages from the relays that leased them.
    ///
    /// - File-tree caller: the `Store` writes already are the barrier, so `|| Ok(())` is the
    ///   honest argument — it says "my store is the authority", not "skip the check".
    /// - Container-backed caller: pass `ContainerVault::save`. On error nothing is acked, the
    ///   error propagates, and the messages stay leased: the relay redelivers them once the
    ///   lease expires, so the batch is recoverable rather than lost.
    ///
    /// Sending is best-effort per receipt (as before): a failed ack just leaves that message
    /// leased to redeliver, which the ratchet's fail-closed duplicate handling absorbs.
    pub fn commit_then_send(
        self,
        now: u64,
        commit: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        commit()?;
        for (transport, receipt) in &self.pending {
            node::peer::send_ack(transport, receipt, now);
        }
        Ok(())
    }
}

/// Receive across a SET of relays (multi-homing) with the on-disk identity, persisting the
/// advanced ratchet state and one-time prekeys once for the whole set. This is the store-
/// backed wiring over [`receive_threaded`]: load account/state/OPKs once, poll every relay
/// with the state threaded through them in order, save once.
///
/// A dead relay does NOT fail the poll — it lands in `MultiPoll::failed` and the healthy
/// relays' mail and state advance are still saved (that is the entire point of multi-homing;
/// see [`receive_threaded`]). `Err` is reserved for a real fault: no relays configured, or a
/// store I/O failure. Kept SEPARATE from [`recv_session`], which fails closed on its single
/// relay's error to drive the connection indicator — here reachability is per-relay data.
///
/// **This does NOT ack.** SEC-34: the store writes below are the durable boundary only for a
/// file-tree account; a container-backed caller's authority is written later. The leases come
/// back in `MultiPoll::acks` and are the caller's to commit — see [`DeferredAcks`].
pub fn recv_session_multi(store: &Store, relays: &[Relay], now: u64) -> Result<MultiPoll, String> {
    if relays.is_empty() {
        return Err("no relays configured".into());
    }
    let account = store.load_account().map_err(|e| secret_load_err("account", e))?;
    // One pair per relay, in the caller's order, so `failed` indices line up with `relays`.
    let pairs: Vec<(SocketTransport, x25519_dalek::PublicKey)> = relays
        .iter()
        .map(|r| (r.transport(), x25519_dalek::PublicKey::from(r.id.fetch_pub)))
        .collect();

    let _lock = store.lock_sessions().map_err(|e| format!("session lock: {e}"))?;
    let state = store.load_sessions().map_err(|e| format!("reading sessions: {e}"))?;
    // OPKs are consumed on receive; persist the remainder so they are never reused.
    let opks = store.load_opks().map_err(|e| format!("reading one-time prekeys: {e}"))?;
    let out = receive_threaded(account, state, opks, &pairs, now);
    // PLAINTEXT-FIRST (same discipline as `recv_session`, all under the sessions flock):
    // persist decrypted text to history BEFORE the state commit and BEFORE the ACKs, so a
    // crash between the commit and the plaintext write cannot lose the message. Deduped by
    // `payload_id`. The prekeys and the ratchet then commit as ONE write (CRYPTO-26) — see
    // `Store::save_receive_commit`.
    persist_incoming_history(store, &out.messages, now)?;
    store
        .save_receive_commit(&out.state, &out.opks)
        .map_err(|e| format!("saving the receive commit: {e}"))?;
    // Plaintext + state are durable IN THIS STORE — which is the whole story for a file-tree
    // account and only half of it for a container-backed one (SEC-34). So the leases are handed
    // back instead of acked here: each receipt carries the transport of the relay that leased it
    // (handles/cookies/scope are relay-scoped), and the caller names the barrier that must hold
    // before the relay is told it may forget the ciphertext.
    let acks = DeferredAcks {
        pending: out.acks.into_iter().map(|(i, r)| (pairs[i].0.clone(), r)).collect(),
    };
    Ok(MultiPoll { messages: out.messages, failed: out.failed, out_of_step: out.out_of_step, acks })
}

/// Send one loop (cover traffic) and drain any loops that came back. Returns how many
/// returned.
///
/// A loop is a message to ourselves, so it spends nobody's mailbox but our own and
/// answers the relay's standing question "is this user writing to anyone right now?" with
/// noise instead of silence. See `Peer::receive_loops` for the residual — against the
/// relay itself this is only cover once the two legs ride independent paths.
pub fn send_loop(store: &Store, relay: &Relay, now: u64) -> Result<usize, String> {
    let account = store.load_account().map_err(|e| secret_load_err("account", e))?;
    let cap = store
        .load_capability_for(&relay.id)
        .map_err(|e| format!("cannot send a loop through this relay: {e}"))?;
    let transport = relay.transport();
    let fetch_pub = x25519_dalek::PublicKey::from(relay.id.fetch_pub);
    let mut peer = Peer::new(transport, account, cap, fetch_pub);

    let _lock = store.lock_sessions().map_err(|e| format!("session lock: {e}"))?;
    peer.import_state(store.load_sessions().map_err(|e| format!("reading sessions: {e}"))?);
    let resp = peer.send_loop(now);
    // Persist BEFORE reading the reply's effect, same discipline as the real send path:
    // the handles and cookies minted here must be durable or the next process re-mints
    // them and pays the round trip again.
    store.save_sessions(&peer.export_state()).map_err(|e| format!("saving sessions: {e}"))?;
    if let Response::Rejected(r) = resp {
        return Err(format!("relay rejected loop: {r}"));
    }
    let back = peer.receive_loops(now);
    store.save_sessions(&peer.export_state()).map_err(|e| format!("saving sessions: {e}"))?;
    Ok(back)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_ts_renders_known_utc_instants() {
        // Pinned against known epochs so a bug in the civil-from-days math reddens.
        assert_eq!(fmt_ts(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(fmt_ts(1_700_000_000), "2023-11-14 22:13:20 UTC"); // a known instant
        assert_eq!(fmt_ts(951_782_400), "2000-02-29 00:00:00 UTC"); // leap day 2000
    }

    #[test]
    fn format_conversation_keeps_only_this_peer_in_order_labelled_by_direction() {
        use crate::store::HistoryRecord;
        let bob = [1u8; 32];
        let carol = [2u8; 32];
        let recs = vec![
            HistoryRecord { from_me: true, peer_ik: bob, text: b"hi bob".to_vec(), ts: 0 },
            HistoryRecord { from_me: false, peer_ik: carol, text: b"not this".to_vec(), ts: 1 },
            HistoryRecord { from_me: false, peer_ik: bob, text: b"hi back".to_vec(), ts: 2 },
        ];
        let out = format_conversation(&recs, &bob);
        // Bob's two lines, in order, direction-labelled; Carol's message excluded.
        assert!(out.contains("Me: hi bob"), "own message missing/mislabelled");
        assert!(out.contains("Them: hi back"), "peer message missing/mislabelled");
        assert!(!out.contains("not this"), "another peer's message leaked into the export");
        assert!(
            out.find("hi bob").unwrap() < out.find("hi back").unwrap(),
            "append order not preserved"
        );
    }

    fn tmp_store(tag: &str) -> (std::path::PathBuf, Store) {
        let dir = std::env::temp_dir().join(format!(
            "karst-persist-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::unlock(&dir, b"pw").unwrap();
        (dir, store)
    }

    fn rx(sender: [u8; 32], text: &[u8], ts: u64, msg_id: [u8; 32]) -> node::peer::Received {
        let plaintext = content::encode(&content::Content::TextStamped { text: text.to_vec(), ts });
        node::peer::Received { sender, plaintext, msg_id }
    }

    /// A5-10, THE carrying test. The multi-relay receive claimed a failed relay's state change
    /// was rolled back "because the state re-exported equals the state imported". It was not: a
    /// peer mints its per-relay handle and updates its bookkeeping BEFORE the transport call that
    /// fails, so the failure left that work behind — including an advanced sweep mark, which
    /// defers the next full drop-box sweep on the strength of a sweep that never finished.
    ///
    /// Discriminating and structural: the dead relay must own NO handle afterwards, while the
    /// healthy one keeps its own. It is second on purpose — it mints its per-relay handle before
    /// it discovers the transport is down, so there IS something to roll back; a test with only
    /// the dead relay would pass without any fix, because nothing would have happened yet.
    ///
    /// Compared by structure rather than by bytes: handles are freshly random per run, so two
    /// independent runs never serialise identically even when both are correct — an equality
    /// check on the bytes would fail for a reason that has nothing to do with the bug.
    #[test]
    fn a_relay_that_fails_leaves_no_trace_in_the_state() {
        use node::protocol::{AckResponse, AckRequest, FetchRequest, FetchResponse, Response, Transport, WireMessage};
        use node::peer::PeerState;

        #[derive(Clone)]
        struct Fake {
            up: bool,
        }
        impl Transport for Fake {
            fn send(&self, _m: &WireMessage, _now: u64) -> Response {
                Response::Rejected("not used".into())
            }
            fn fetch(&self, _r: &FetchRequest, _now: u64) -> FetchResponse {
                if self.up {
                    FetchResponse::Fetched(Vec::new())
                } else {
                    FetchResponse::Rejected("relay down".into())
                }
            }
            fn ack(&self, _r: &AckRequest, _now: u64) -> AckResponse {
                AckResponse::Rejected("not used".into())
            }
        }

        let account = node::pqxdh::Account::generate();
        let pub_a = x25519_dalek::PublicKey::from([7u8; 32]);
        let pub_b = x25519_dalek::PublicKey::from([9u8; 32]);

        let with_dead = receive_threaded(
            account,
            PeerState::empty(),
            Vec::new(),
            &[(Fake { up: true }, pub_a), (Fake { up: false }, pub_b)],
            1_000,
        );

        assert_eq!(with_dead.failed, vec![1], "control: the second relay really did fail");
        let owners = with_dead.state.relay_ids_for_test();
        assert_eq!(
            owners,
            vec![pub_a.to_bytes()],
            "the healthy relay must keep its handle and the dead one must keep NOTHING — a dead \
             relay mints its handle before it ever learns the transport is down, and leaving it \
             behind is the half-finished state this rollback exists to remove"
        );
    }

    /// SEC-40, THE carrying test. An ACK tells the relay to delete its ONLY copy of a message.
    /// The receive path acked everything it could decrypt, but only a few `Content` kinds were
    /// durably stored before that point — a profile update, a publication, a contact control
    /// message or a variant from a newer build was handed to the caller in memory, and a crash,
    /// an account switch or a full disk between the ack and the handler lost it for good.
    ///
    /// Discriminating both ways: a Profile (which no handler on this path applies) must be parked
    /// durably, and a TextExpiring must NOT be — for that type, vanishing on a crash is the
    /// feature, and quarantining it would be a disappearing message written to disk.
    #[test]
    fn content_no_handler_commits_is_parked_before_it_can_be_acked() {
        let (dir, store) = tmp_store("quarantine");
        let sender = [0xEE; 32];

        let profile = content::encode(&content::Content::Profile {
            name: "Alice".to_string(),
            bio: "hi".to_string(),
        });
        let expiring = content::encode(&content::Content::TextExpiring {
            text: b"burn after reading".to_vec(),
            expire_at: 1_000,
        });
        let msgs = vec![
            Some(node::peer::Received { sender, plaintext: profile.clone(), msg_id: [1u8; 32] }),
            Some(node::peer::Received { sender, plaintext: expiring.clone(), msg_id: [2u8; 32] }),
        ];

        persist_incoming_history(&store, &msgs, 100).expect("commit succeeds");

        let parked = store.load_quarantine().unwrap();
        assert_eq!(
            parked.len(),
            1,
            "exactly one message should be parked — the profile, which nothing on this path \
             commits; got {parked:?}"
        );
        assert_eq!(parked[0].plaintext, profile, "the parked message must be the profile");
        assert_eq!(parked[0].sender, sender);
        assert!(
            !parked.iter().any(|q| q.plaintext == expiring),
            "a disappearing message was written to disk — for TextExpiring, being lost on a \
             crash is the point"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Plaintext-first persist is idempotent by `payload_id`: re-running the SAME batch (the
    /// redelivery a crash-before-ratchet-save produces) appends nothing new, so the message
    /// lands in history exactly once.
    #[test]
    fn persist_incoming_history_dedups_a_redelivered_message() {
        let (dir, store) = tmp_store("dedup");
        let sender = [7u8; 32];
        let batch = vec![Some(rx(sender, b"once", 100, [1u8; 32]))];

        persist_incoming_history(&store, &batch, 100).unwrap();
        persist_incoming_history(&store, &batch, 100).unwrap(); // redelivery of the same payload
        let hist = store.load_history().unwrap();
        assert_eq!(hist.iter().filter(|r| r.text == b"once").count(), 1, "redelivery deduped");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Two DISTINCT messages with the same sender, second, and text (a double-tap) are NOT
    /// collapsed — their `payload_id`s differ, so both are delivered. This is exactly the
    /// case a content-hash dedup would silently eat; `payload_id` does not.
    #[test]
    fn persist_incoming_history_keeps_a_genuine_double_tap() {
        let (dir, store) = tmp_store("double-tap");
        let sender = [8u8; 32];
        // Same (sender, ts, text); DIFFERENT payload ids (fresh nonce/key per ciphertext).
        let batch = vec![
            Some(rx(sender, b"ok", 42, [1u8; 32])),
            Some(rx(sender, b"ok", 42, [2u8; 32])),
        ];
        persist_incoming_history(&store, &batch, 42).unwrap();
        let hist = store.load_history().unwrap();
        assert_eq!(hist.iter().filter(|r| r.text == b"ok").count(), 2, "both taps delivered");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Build a `Received` carrying a `PostAttachmentRef` with an attacker's choice of shape.
    fn attachment_ref(
        sender: [u8; 32],
        size: u64,
        chunks: u32,
        msg_id: [u8; 32],
    ) -> node::peer::Received {
        let plaintext = content::encode(&content::Content::PostAttachmentRef {
            post_id: [9u8; 16],
            index: 0,
            kind: 0,
            name: "photo.png".into(),
            blob_id: msg_id, // distinct per ref, which is what the pending queue keys on
            key: [2u8; 32],
            hash: [3u8; 32],
            size,
            chunks,
        });
        node::peer::Received { sender, plaintext, msg_id }
    }

    /// SEC-31, the AUTHORIZATION half. A `PostAttachmentRef` was written straight into the pending
    /// fetch queue for ANY sender that could establish a session — no contact status, no
    /// subscription, nothing. The sibling `GalleryRef` arm, three cases below it in the same match,
    /// always required a confirmed contact; this variant simply never got its gate. So a stranger
    /// could park work in a durable queue on a client that would not even display their posts.
    ///
    /// Discriminating in BOTH directions: the stranger's ref must be refused AND a subscribed
    /// channel's identical ref must be admitted. A one-directional test would pass with the whole
    /// feature disabled.
    #[test]
    fn a_post_attachment_ref_is_only_queued_for_a_feed_source() {
        let (dir, store) = tmp_store("ppa-gate");
        let stranger = [0x11u8; 32];
        let channel = [0x22u8; 32];
        store.set_channel_peer(channel, true).unwrap(); // we subscribed to this one

        persist_incoming_history(
            &store,
            &[Some(attachment_ref(stranger, 1000, 1, [0xA1; 32]))],
            100,
        )
        .unwrap();
        assert!(
            store.list_pending_post_attachments().unwrap().is_empty(),
            "a stranger's attachment ref must not reach the pending queue"
        );

        persist_incoming_history(
            &store,
            &[Some(attachment_ref(channel, 1000, 1, [0xB1; 32]))],
            100,
        )
        .unwrap();
        let q = store.list_pending_post_attachments().unwrap();
        assert_eq!(q.len(), 1, "a subscribed channel's attachment must still be queued");
        assert_eq!(q[0].sender, channel);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// SEC-31, the COST half. `chunks` was checked only for `!= 0`, and it is the loop bound of
    /// `download_post_attachment` — one blocking relay round trip per chunk. The relay accepts a
    /// declared count up to `blobstore::MAX_BLOB_CHUNKS` (40 000), so a pointer whose `size` sat
    /// comfortably inside the 96 KiB cap could still demand tens of thousands of fetches, and the
    /// `buf.len()` cap never fired because empty chunks add no bytes. Requiring exact equality
    /// with `blob::chunk_count(size)` — what the sender's own upload computed — bounds an honest
    /// 96 KiB attachment at two 60 KiB chunks.
    ///
    /// Discriminating in both directions again: the inflated count is refused at the door, the
    /// truthful count is admitted, and the check is asserted at the exact boundary rather than
    /// only far from it.
    #[test]
    fn a_post_attachment_ref_must_declare_the_chunk_count_its_size_implies() {
        let (dir, store) = tmp_store("ppa-chunks");
        let channel = [0x33u8; 32];
        store.set_channel_peer(channel, true).unwrap();

        // 1000 bytes is one 60 KiB blob chunk; claiming 40 000 is the attack.
        persist_incoming_history(
            &store,
            &[Some(attachment_ref(channel, 1000, 40_000, [0xC1; 32]))],
            100,
        )
        .unwrap();
        assert!(
            store.list_pending_post_attachments().unwrap().is_empty(),
            "an inflated chunk count must be refused before it becomes queued work"
        );

        // A zero-byte "attachment" is not something the send side can produce either.
        persist_incoming_history(&store, &[Some(attachment_ref(channel, 0, 1, [0xC2; 32]))], 100)
            .unwrap();
        assert!(
            store.list_pending_post_attachments().unwrap().is_empty(),
            "an empty attachment must not occupy a queue slot"
        );

        // The honest shapes: exactly one chunk under the boundary, exactly two over it.
        let one = blob::BLOB_CHUNK as u64;
        persist_incoming_history(&store, &[Some(attachment_ref(channel, one, 1, [0xD1; 32]))], 100)
            .unwrap();
        persist_incoming_history(
            &store,
            &[Some(attachment_ref(channel, one + 1, 2, [0xD2; 32]))],
            100,
        )
        .unwrap();
        assert_eq!(
            store.list_pending_post_attachments().unwrap().len(),
            2,
            "truthful refs on both sides of the chunk boundary must still be queued"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn carrier_from_covers_the_four_combinations() {
        // The status bar's label must match exactly which adapter `transport()` builds;
        // this pins the (wss, proxy) → carrier truth table that both share.
        assert_eq!(carrier_from(false, false), Carrier::Direct);
        assert_eq!(carrier_from(false, true), Carrier::Socks5);
        assert_eq!(carrier_from(true, false), Carrier::Wss);
        assert_eq!(carrier_from(true, true), Carrier::WssOverSocks5);
    }

    #[test]
    fn carrier_labels_are_distinct_and_nonempty() {
        let all = [Carrier::Direct, Carrier::Socks5, Carrier::Wss, Carrier::WssOverSocks5];
        let mut labels: Vec<&str> = all.iter().map(|c| c.label()).collect();
        assert!(labels.iter().all(|l| !l.is_empty()));
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), all.len(), "labels must be distinct");
    }

    fn spec(carrier: Carrier, port: u16) -> PathSpec {
        PathSpec { carrier, dest: Dest::new("127.0.0.1", port) }
    }

    #[test]
    fn allowlist_never_trades_away_the_property_the_user_chose() {
        // The allowlist is intent-derived, NOT a strength ordering: wss and SOCKS5
        // protect against different adversaries, so neither substitutes for the other.
        // Tor user: direct AND bare wss are both out (both exit from this host).
        let tor = allowed_carriers(Carrier::Socks5);
        assert!(!tor.contains(&Carrier::Direct), "a Tor user is never sent direct");
        assert!(!tor.contains(&Carrier::Wss), "bare wss exits from this host → deanonymizes a Tor user");
        assert!(tor.contains(&Carrier::Socks5) && tor.contains(&Carrier::WssOverSocks5));
        // wss user: every path must still look like HTTPS.
        let wss = allowed_carriers(Carrier::Wss);
        assert!(!wss.contains(&Carrier::Direct) && !wss.contains(&Carrier::Socks5));
        assert!(wss.contains(&Carrier::Wss) && wss.contains(&Carrier::WssOverSocks5));
        // Both asked for → only the carrier that has both properties.
        assert_eq!(allowed_carriers(Carrier::WssOverSocks5), &[Carrier::WssOverSocks5]);
        // Nothing asked for → nothing to preserve.
        assert_eq!(allowed_carriers(Carrier::Direct).len(), 4);
    }

    #[test]
    fn filter_allowed_drops_a_live_direct_path_for_a_wss_user() {
        // THE security discriminator for automatic transport switching: a config that
        // lists a working direct route plus a (dead) wss route must, under wss intent,
        // yield ONLY the wss route — so the connection can fail, but can NEVER silently
        // fall back to the live direct one. Neuter `filter_allowed` to the identity
        // function and this reds.
        let specs = vec![spec(Carrier::Direct, 9001), spec(Carrier::Wss, 9002)];
        let kept = filter_allowed(specs, Carrier::Wss);
        assert_eq!(kept, vec![spec(Carrier::Wss, 9002)], "the live direct path is dropped, not used");
    }

    #[test]
    fn filter_allowed_keeps_order_and_permits_everything_for_a_direct_user() {
        let specs = vec![spec(Carrier::Wss, 1), spec(Carrier::Direct, 2), spec(Carrier::Socks5, 3)];
        assert_eq!(filter_allowed(specs.clone(), Carrier::Direct), specs, "no floor → all kept, in order");
    }

    #[test]
    fn parse_path_specs_reads_kinds_in_order_and_skips_typos() {
        let got = parse_path_specs(
            "wss@10.0.0.1:443, bogus@10.0.0.2:80, direct@10.0.0.3:9000 ,, socks5@nope, wss+socks5@10.0.0.4:443, 10.0.0.5:9000",
        );
        assert_eq!(
            got,
            vec![
                PathSpec { carrier: Carrier::Wss, dest: Dest::parse("10.0.0.1:443").unwrap() },
                PathSpec { carrier: Carrier::Direct, dest: Dest::parse("10.0.0.3:9000").unwrap() },
                PathSpec { carrier: Carrier::WssOverSocks5, dest: Dest::parse("10.0.0.4:443").unwrap() },
            ],
            "known kinds in order; unknown carrier, bad address and a missing kind@ are skipped"
        );
    }

    #[test]
    fn adapter_for_skips_a_carrier_whose_config_is_missing() {
        // A wss path with no SNI host / a socks5 path with no proxy is SKIPPED, never
        // quietly demoted to something weaker.
        assert!(adapter_for(Carrier::Wss, None, None, "tok").is_none(), "wss without a host → no path");
        assert!(adapter_for(Carrier::Socks5, None, None, "tok").is_none(), "socks5 without a proxy → no path");
        assert!(adapter_for(Carrier::Direct, None, None, "tok").is_some());
    }

    #[test]
    fn wss_spec_splits_the_secret_cohost_path_off_the_sni_host() {
        // `KARST_WSS` carries the SNI host and, optionally, the secret co-hosting path the
        // reverse proxy routes to the relay. The SNI must be a bare hostname, so the path
        // is split at the FIRST slash and the rest (slashes included) is the path.
        assert_eq!(split_wss_spec("example.com"), ("example.com".into(), "/".into()));
        assert_eq!(split_wss_spec("example.com/s3cret"), ("example.com".into(), "/s3cret".into()));
        assert_eq!(split_wss_spec("example.com/a/b/c"), ("example.com".into(), "/a/b/c".into()));
        // A trailing slash with nothing after is still just the host at path `/`.
        assert_eq!(split_wss_spec("example.com/"), ("example.com".into(), "/".into()));
    }

    #[test]
    fn each_compartment_gets_its_own_circuit_token() {
        // A compartment is an identity + its own relay + its OWN CIRCUIT. Tor isolates
        // circuits by SOCKS credential, so two accounts must never present the same one:
        // sharing a circuit links them however different their keys are. Discriminating:
        // make the token a constant (or derive it from the identity) → this reds, and the
        // derived variant would also hand the proxy a stable label for the very thing we
        // are separating.
        let id = RelayId { noise_pub: [1u8; 32], fetch_pub: [2u8; 32] };
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let work = Relay::configured(addr, id, None, "");
        let private = Relay::configured(addr, id, None, "");
        assert_ne!(
            work.isolation(),
            private.isolation(),
            "two compartments must not share a Tor circuit"
        );
        assert!(work.isolation().len() >= 16, "unguessable, and not a name");
    }

    #[test]
    fn i2p_host_is_recognised_but_clearnet_is_not() {
        assert!(is_i2p_host("abcd1234.b32.i2p"));
        assert!(is_i2p_host("relay.i2p"));
        assert!(is_i2p_host("RELAY.I2P")); // case-insensitive
        assert!(is_i2p_host("relay.i2p.")); // trailing dot (FQDN form)
        assert!(!is_i2p_host("127.0.0.1"));
        assert!(!is_i2p_host("relay.example.com"));
        assert!(!is_i2p_host("evil-i2p.com")); // ".i2p" must be the suffix, not a substring
        assert_eq!(Carrier::I2p.label(), "i2p");
    }

    #[test]
    fn an_onion_relay_reads_as_tor_and_stays_on_tor() {
        // Symmetric to i2p: a `*.onion` reached through Tor's SOCKS port reports as Tor, not
        // bare SOCKS5, and never falls back to a bare-clearnet carrier (which would exit from
        // this host and deanonymize). `wss over SOCKS5` — wss THROUGH Tor — is still allowed.
        assert!(is_onion_host("abcdefghij234567.onion"));
        assert!(is_onion_host("RELAY.ONION")); // case-insensitive
        assert!(!is_onion_host("relay.onion.example.com")); // suffix, not substring
        assert!(!is_onion_host("10.0.0.1"));
        assert_eq!(Carrier::Tor.label(), "Tor");
        let id = RelayId { noise_pub: [3u8; 32], fetch_pub: [4u8; 32] };
        let tor_socks: SocketAddr = "127.0.0.1:9050".parse().unwrap();
        let addr = Dest::parse("expyuzz4wqqyqhjn.onion:9000").unwrap();
        assert!(addr.as_ip().is_none(), "an onion name is never an IP literal");
        let r = Relay::configured(addr, id, Some(tor_socks), "");
        assert_eq!(r.carrier(), Carrier::Tor);
        assert!(!allowed_carriers(Carrier::Tor).contains(&Carrier::Direct));
        // Same onion over plain TCP (no Tor) is not labelled Tor — it could not resolve anyway.
        let bare =
            Relay::configured(Dest::parse("expyuzz4wqqyqhjn.onion:9000").unwrap(), id, None, "");
        assert_ne!(bare.carrier(), Carrier::Tor);
    }

    #[test]
    fn mixnet_is_an_explicit_flag_and_stays_in_the_mixnet() {
        // A mixnet (Nym) has no address suffix — the same clearnet relay is reached through a
        // Nym SOCKS client. So it is an EXPLICIT choice: with_mixnet(true) makes the carrier read
        // mixnet; the identical relay without the flag is plain SOCKS5. Discriminating: infer
        // mixnet from the address (there is nothing to infer) or drop the flag → this reds.
        assert_eq!(Carrier::Mixnet.label(), "mixnet");
        let id = RelayId { noise_pub: [5u8; 32], fetch_pub: [6u8; 32] };
        let nym: SocketAddr = "127.0.0.1:1080".parse().unwrap(); // nym-socks5-client
        let addr: SocketAddr = "203.0.113.7:9000".parse().unwrap(); // an ordinary clearnet relay
        let m = Relay::configured(addr, id, Some(nym), "").with_mixnet(true);
        assert_eq!(m.carrier(), Carrier::Mixnet);
        // Same address + proxy, but not declared a mixnet → just SOCKS5, not mislabelled.
        let plain = Relay::configured(addr, id, Some(nym), "");
        assert_eq!(plain.carrier(), Carrier::Socks5);
        // The mixnet must never fall back to a clearnet (or even Tor) carrier.
        assert_eq!(allowed_carriers(Carrier::Mixnet), &[Carrier::Mixnet]);
        // Without a proxy the flag is a no-op — the mixnet IS the proxy.
        assert_ne!(Relay::configured(addr, id, None, "").with_mixnet(true).carrier(), Carrier::Mixnet);
    }

    #[test]
    fn an_i2p_relay_reads_as_i2p_and_stays_inside_i2p() {
        // A `*.i2p` address is not an IP; it must survive as a hostname (only the i2p router
        // resolves it) and, once a SOCKS bridge is set, the carrier is reported as i2p — not
        // bare SOCKS5 — so the user sees which anonymity network carries them. Discriminating:
        // relabel it SOCKS5 (drop the i2p arm) and this reds.
        let id = RelayId { noise_pub: [1u8; 32], fetch_pub: [2u8; 32] };
        let bridge: SocketAddr = "127.0.0.1:4447".parse().unwrap(); // i2pd SOCKS
        let addr = Dest::parse("hq7f2c.b32.i2p:9000").unwrap();
        assert_eq!(addr.host, "hq7f2c.b32.i2p");
        assert!(addr.as_ip().is_none(), "an i2p name is never an IP literal");
        let r = Relay::configured(addr, id, Some(bridge), "");
        assert_eq!(r.carrier(), Carrier::I2p);
        // i2p intent forbids any clearnet fallback — leaving the network would deanonymize.
        assert_eq!(allowed_carriers(Carrier::I2p), &[Carrier::I2p]);
        // The same address over plain TCP (no bridge) is NOT i2p — it could not resolve anyway,
        // so we do not mislabel it.
        let no_bridge = Relay::configured(Dest::parse("hq7f2c.b32.i2p:9000").unwrap(), id, None, "");
        assert_ne!(no_bridge.carrier(), Carrier::I2p);
    }

    #[test]
    fn a_hidden_service_name_survives_route_configuration() {
        // The end of "the relay IP is a fixed blockable endpoint": a relay published as
        // a Tor onion service has no IP at all, and its address must survive parsing,
        // the allowlist, and path assembly. Discriminating: parse routes as SocketAddr
        // (what we used to do) and every one of these is silently dropped.
        let onion = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443";
        let (specs, alts) = split_routes(&format!("{onion}, socks5@{onion}, abc.i2p:9000"));
        assert_eq!(alts.len(), 2, "a bare .onion / .i2p name is a valid alternate endpoint");
        assert!(alts[0].as_ip().is_none(), "it is a NAME — no clearnet IP, and none to parse");
        assert_eq!(
            specs,
            vec![PathSpec { carrier: Carrier::Socks5, dest: Dest::parse(onion).unwrap() }],
            "and it works with an explicit carrier too — which is the only way to reach it"
        );

        // It reaches the actual path list, through the allowlist, under a Tor user.
        let id = RelayId { noise_pub: [1u8; 32], fetch_pub: [2u8; 32] };
        let proxy: SocketAddr = "127.0.0.1:9050".parse().unwrap();
        let r = Relay::configured(
            "127.0.0.1:9000".parse::<SocketAddr>().unwrap(),
            id,
            Some(proxy),
            &format!("socks5@{onion}"),
        );
        assert_eq!(r.path_count(), 2, "primary + the onion route survive to the path list");
    }

    #[test]
    fn parse_alt_addrs_keeps_valid_in_order_and_skips_garbage() {
        // Guards the failover PATH ASSEMBLY (parse/order/skip). CONTRACT CHANGE: a
        // hostname used to be dropped here ("IP:port only") — that silently made every
        // hidden-service relay unreachable, so names are now first-class and only
        // genuinely malformed entries go. Order is still preserved.
        let got = parse_alt_addrs(
            "127.0.0.1:1, garbage, 10.0.0.2:9000 ,, relay.example.com:443, xyz.onion:443,127.0.0.1:3",
        );
        let dests: Vec<String> = got.iter().map(|d| d.to_string()).collect();
        assert_eq!(
            dests,
            vec![
                "127.0.0.1:1",
                "10.0.0.2:9000",
                "relay.example.com:443",
                "xyz.onion:443",
                "127.0.0.1:3"
            ],
            "addresses AND names kept in order; only junk ({:?}) and empties dropped",
            "garbage"
        );
    }

    #[test]
    fn split_routes_uses_the_at_sign_to_tell_the_two_entry_kinds_apart() {
        // One user-facing list, two meanings: `@` = explicit carrier, no `@` = an
        // alternate endpoint on the carrier already chosen. Order kept within each.
        let (specs, alts) = split_routes("10.0.0.1:9000, wss@10.0.0.2:443, 10.0.0.3:9000");
        assert_eq!(
            specs,
            vec![PathSpec { carrier: Carrier::Wss, dest: Dest::parse("10.0.0.2:443").unwrap() }],
            "kind@ entries become carrier specs"
        );
        let alt_s: Vec<String> = alts.iter().map(|a| a.to_string()).collect();
        assert_eq!(alt_s, vec!["10.0.0.1:9000", "10.0.0.3:9000"], "plain entries stay same-carrier");
    }

    #[test]
    fn configured_routes_extend_the_path_list_without_env() {
        // The app can widen the failover list by passing routes explicitly — no env.
        let id = RelayId { noise_pub: [1u8; 32], fetch_pub: [2u8; 32] };
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let solo = Relay::configured(addr, id, None, "");
        assert_eq!(solo.path_count(), 1, "no routes → just the primary");
        let many = Relay::configured(addr, id, None, "127.0.0.1:9001, direct@127.0.0.1:9002");
        assert_eq!(many.path_count(), 3, "primary + one alternate endpoint + one explicit-carrier route");
    }

    /// SEC-43, the SENDER-COUNT half. The per-sender cap (`content::MAX_CONCURRENT_TRANSFERS`)
    /// already stops one busy contact from filling memory, but nothing stopped the NUMBER of
    /// contacts — an IK is free to mint. Discriminating: fill `MAX_REASSEMBLY_SENDERS` distinct
    /// senders with an incomplete (never-completing) transfer each, then prove a genuinely new
    /// sender is refused (the cap does its job) WHILE an already-admitted sender's own transfer
    /// keeps working (the cap never touches anyone already let in).
    #[test]
    fn global_sender_cap_refuses_a_newcomer_but_never_disturbs_an_already_admitted_sender() {
        let mut reasm: std::collections::HashMap<[u8; 32], content::Reassembler> =
            std::collections::HashMap::new();
        let now = 1_000u64;
        let manifest = |tag: u8| content::Content::FileManifest {
            id: [tag; 16],
            name: "f".into(),
            size: 20,
            chunks: 2, // never sent in full below => stays in-flight forever
            hash: [0; 32],
        };
        for i in 0..MAX_REASSEMBLY_SENDERS as u8 {
            let sender = [i; 32];
            assert_eq!(
                offer_reassembly(&mut reasm, sender, manifest(i), now).unwrap(),
                None,
                "sender {i} must be admitted while under the cap"
            );
        }
        assert_eq!(reasm.len(), MAX_REASSEMBLY_SENDERS, "control: every sender holds a slot");

        // A brand-new sender: refused — every slot is held by another sender's live transfer.
        let newcomer = [0xAA; 32];
        assert!(
            offer_reassembly(&mut reasm, newcomer, manifest(0xAA), now).is_err(),
            "the sender cap must refuse a newcomer once every slot is taken"
        );
        assert!(!reasm.contains_key(&newcomer), "a refused newcomer must not consume a slot");

        // An ALREADY-ADMITTED sender's own transfer is untouched by the cap: their earlier
        // manifest still accepts its chunk (never evicted to make room for anyone else).
        let existing = [0u8; 32];
        let chunk = content::Content::FileChunk { id: [0u8; 16], index: 0, data: vec![1, 2, 3] };
        assert_eq!(
            offer_reassembly(&mut reasm, existing, chunk, now).unwrap(),
            None,
            "an existing sender's in-progress transfer must keep working at the cap"
        );
    }

    /// SEC-43, the TOTAL-RAM half — and specifically the manifest-flood adversary: a manifest
    /// carries NO payload, so if the cap only counted ARRIVED bytes, an attacker could send
    /// hundreds of bare manifests (never a single chunk) and every one would be admitted for
    /// free — the cap would only "notice" once chunks started streaming, by which point every
    /// slot was already reserved. `MAX_REASSEMBLY_SENDERS` alone would still let that flood
    /// reserve `senders × ~4.5 MiB` (one sender's worst case: `MAX_CONCURRENT_TRANSFERS` galleries)
    /// — hundreds of MiB. This test sends ONLY manifests, to 20 distinct senders (well past the
    /// ~2 that would exhaust the byte cap alone, and well under `MAX_REASSEMBLY_SENDERS` = 64), so
    /// a pass here cannot be explained by the sender cap or by any chunk ever arriving.
    ///
    /// Discriminating both ways: refused well before all 160 (20 × 8) manifests are admitted, AND
    /// a CHUNK continuing an already-admitted transfer still lands afterwards — the cap must
    /// refuse only a transfer that has not started, never kill progress already accepted.
    #[test]
    fn global_byte_cap_uses_the_manifests_declared_size_so_a_bare_manifest_flood_cannot_bypass_it() {
        let mut reasm: std::collections::HashMap<[u8; 32], content::Reassembler> =
            std::collections::HashMap::new();
        let now = 2_000u64;
        let declared = content::MAX_GALLERY_BYTES as u32; // the largest single-transfer commitment
        let mut admitted = 0usize;
        let mut first: Option<([u8; 32], [u8; 16])> = None;
        'outer: for sender_idx in 0u8..20 {
            let sender = [sender_idx; 32];
            for slot in 0u8..content::MAX_CONCURRENT_TRANSFERS as u8 {
                let id = [sender_idx.wrapping_mul(8).wrapping_add(slot); 16];
                let manifest = content::Content::GalleryManifest {
                    id,
                    size: declared,
                    chunks: declared / 1024 + 1,
                    hash: [0; 32],
                };
                match offer_reassembly(&mut reasm, sender, manifest, now) {
                    Ok(None) => {
                        first.get_or_insert((sender, id));
                        admitted += 1;
                    }
                    Err(_) => break 'outer, // the byte cap kicked in — stop, this is what we test
                    Ok(Some(_)) => panic!("a bare manifest cannot complete on its own"),
                }
                // Deliberately NO chunk is ever sent — `bytes_in_flight` (arrived) stays at 0 for
                // every one of these. Only declared-size accounting can catch this flood.
            }
        }
        assert!(
            admitted < 160,
            "the byte cap must refuse a bare manifest well before 160 (20 senders × 8 slots) are \
             admitted with NO chunk ever sent; got {admitted} admitted with none refused — a \
             manifest flood bypassed the cap"
        );
        assert_eq!(
            total_reassembly_bytes(&reasm),
            0,
            "control: confirms this really is a bare-manifest flood — zero bytes ever arrived"
        );
        assert!(
            total_declared_reassembly_bytes(&reasm) <= MAX_REASSEMBLY_TOTAL_BYTES as u64,
            "committed declared bytes must never exceed the cap, even before any chunk arrives"
        );

        // A CHUNK continuing an already-admitted transfer still lands even with the declared
        // budget fully committed — the cap only ever refuses a NEW transfer, never one in progress.
        let (sender, id) = first.expect("at least one manifest must have been admitted");
        let chunk = content::Content::AvatarChunk { id, index: 0, data: vec![7u8; 1024] };
        assert_eq!(
            offer_reassembly(&mut reasm, sender, chunk, now).unwrap(),
            None,
            "an already-admitted transfer must still be able to receive chunks at the byte cap"
        );
    }

    /// SEC-43 overflow guard: the admission check runs BEFORE `Reassembler::offer`'s own per-kind
    /// bound (`size > MAX_FILE_SIZE`, etc.) ever gets a chance to reject an absurd manifest, so
    /// `manifest_declared_size` is still the RAW attacker-declared value at that point — a
    /// `FileManifest` claiming `size: u64::MAX` must not overflow `declared_total + declared_new`.
    /// Discriminating: swap the admission check's `saturating_add` for plain `+` and this panics
    /// (debug builds trap on overflow) instead of returning a loud `Err`.
    #[test]
    fn global_byte_cap_refuses_an_absurd_declared_size_without_overflowing() {
        let mut reasm: std::collections::HashMap<[u8; 32], content::Reassembler> =
            std::collections::HashMap::new();
        let now = 5_000u64;
        // One small, honest manifest first, so `declared_total` is non-zero going into the
        // overflow attempt — the bug is in `total + huge`, not in `huge` alone.
        let sender_a = [1u8; 32];
        let small = content::Content::FileManifest {
            id: [1; 16],
            name: "f".into(),
            size: 10,
            chunks: 2,
            hash: [0; 32],
        };
        assert_eq!(offer_reassembly(&mut reasm, sender_a, small, now).unwrap(), None);

        let sender_b = [2u8; 32];
        let absurd = content::Content::FileManifest {
            id: [2; 16],
            name: "f".into(),
            size: u64::MAX, // far past any per-kind bound `Reassembler::offer` would reject
            chunks: 1,
            hash: [0; 32],
        };
        assert!(
            offer_reassembly(&mut reasm, sender_b, absurd, now).is_err(),
            "an absurd declared size must be refused by the global cap, not overflow past it"
        );
    }

    /// SEC-43, the EXPIRY half: the finding was that the 5-minute stale-partial reap was only
    /// ever triggered by a NEW manifest from the SAME sender that is stalled — a sender who starts
    /// a transfer and then goes silent forever would pin RAM until the account is switched or the
    /// process exits. Discriminating: the abandoning sender sends NOTHING further; only a
    /// DIFFERENT sender's ordinary traffic drives the receive path past the stale window, and that
    /// alone must free the abandoning sender's slot.
    #[test]
    fn reap_reassemblers_frees_an_abandoned_senders_slot_via_a_different_senders_traffic() {
        let mut reasm: std::collections::HashMap<[u8; 32], content::Reassembler> =
            std::collections::HashMap::new();
        let t0 = 1_000u64;
        let abandoning = [1u8; 32];
        let manifest = content::Content::FileManifest {
            id: [9; 16],
            name: "x".into(),
            size: 10,
            chunks: 2,
            hash: [0; 32],
        };
        assert_eq!(offer_reassembly(&mut reasm, abandoning, manifest, t0).unwrap(), None);
        assert_eq!(reasm.len(), 1, "control: the abandoning sender holds a slot");

        // Past the stale window — but the abandoning sender sends nothing more. A DIFFERENT
        // sender's manifest is the only thing driving the receive path here.
        let later = t0 + content::STALE_PARTIAL_SECS + 1;
        let other = [2u8; 32];
        let other_manifest = content::Content::FileManifest {
            id: [8; 16],
            name: "y".into(),
            size: 10,
            chunks: 2,
            hash: [0; 32],
        };
        assert_eq!(offer_reassembly(&mut reasm, other, other_manifest, later).unwrap(), None);

        assert!(
            !reasm.contains_key(&abandoning),
            "a different sender's ordinary traffic must free an abandoned sender's stale slot, \
             not only that same sender sending something new"
        );
    }
}
