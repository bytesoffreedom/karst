//! Pluggable transport (§15) — a SEAM, not transport obfuscation of our own.
//!
//! The spec is explicit: "pluggable transports — an interface, not an implementation
//! of our own". Traffic-analysis resistance comes from an EXTERNAL, vetted transport
//! (Tor/obfs4/Shadowsocks/meek); KARST only provides the wiring to it. Here: the
//! adapter contract + two adapters — direct TCP and SOCKS5 (a route through a PT
//! client's local SOCKS port) — plus connect-level path failover.
//!
//! **Transport obfuscation is NOT this code.** `Socks5Adapter` hides nothing by itself; it
//! points the outbound connection at an external transport, and THAT is the
//! obfuscation. We do not claim "obfuscated" — we claim "can route through a
//! obfuscating transport".
//!
//! **No silent fallback** (§15): an unreachable SOCKS proxy is a hard error. We NEVER
//! fall back to a direct connection — that would deanonymize a user who chose to
//! route through Tor.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};

/// Short timeout on the TCP connect of EVERY path. Critical for failover: connecting
/// to a blackholed IP otherwise blocks for tens of seconds (the OS default), and
/// `SocketTransport` would not reach the next path in reasonable time. an on-path classifier that lets
/// the SYN through and then kills the handshake is caught one layer up, by
/// `SocketTransport`'s per-path connect+handshake retry.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Read timeout on an established connection (handshake + the relay's response). It
/// is what makes handshake-level failover possible at all: a silent path errors, and
/// `SocketTransport` moves on to the next one. A
/// path that accepts TCP and then goes silent (a silent-drop on-path classifier / a hung proxy) would
/// otherwise wedge the client thread FOREVER (the server has `CONN_READ_TIMEOUT`; the
/// blocking client had nothing). Every relay response is small and fast (a fetch page,
/// one blob chunk per connection), so a generous bound never cuts legitimate traffic
/// but turns a hang into an error. NB: this is NOT handshake-level *failover* (retry
/// on the next path after connect) — that lives one layer up (roadmap).
pub const READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Where a path leads: a literal address, or a NAME the carrier resolves.
///
/// This exists because the addresses that matter most for blocking resistance are not
/// IPs at all: a relay published as a Tor onion service (`.onion`), an I2P destination
/// (`.i2p`) or a Lokinet address has **no clearnet IP** — and no DNS answer either. Only
/// the overlay itself can resolve them, which is exactly what SOCKS5's domain-name
/// address type is for. Routes used to be `SocketAddr`-only, so KARST could not dial any
/// of them: every hidden-service overlay was unreachable by construction.
///
/// A name is meaningful ONLY through a resolving carrier (a SOCKS proxy). Resolving one
/// locally would either fail (`.onion` has no DNS record) or leak the lookup to a DNS
/// server the user never chose — see `DirectTcpAdapter`, which refuses rather than doing
/// either quietly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dest {
    /// An IP literal or a hostname (`xyz.onion`, `relay.example.com`, `10.0.0.1`).
    pub host: String,
    pub port: u16,
}

impl Dest {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Dest { host: host.into(), port }
    }

    /// The IP literal, if this is one. `None` = a name only a carrier can resolve.
    pub fn as_ip(&self) -> Option<SocketAddr> {
        self.host.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, self.port))
    }

    /// Parse `host:port` — an IP literal or a name. IPv6 literals take `[::1]:9000`.
    pub fn parse(s: &str) -> Result<Dest, String> {
        let s = s.trim();
        if let Ok(sa) = s.parse::<SocketAddr>() {
            return Ok(Dest::new(sa.ip().to_string(), sa.port()));
        }
        let (host, port) = s.rsplit_once(':').ok_or_else(|| format!("{s:?} is not host:port"))?;
        let port: u16 = port.parse().map_err(|_| format!("{s:?}: bad port"))?;
        let host = host.trim_matches(|c| c == '[' || c == ']');
        if host.is_empty() {
            return Err(format!("{s:?}: empty host"));
        }
        Ok(Dest::new(host, port))
    }
}

impl std::fmt::Display for Dest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl From<SocketAddr> for Dest {
    fn from(a: SocketAddr) -> Self {
        Dest::new(a.ip().to_string(), a.port())
    }
}

/// An adapter's bidirectional stream. Blanket impl: any `Read+Write+Send` qualifies
/// (`TcpStream` included), so adapters hand back `Box<dyn Channel>` and `Session`
/// works over it unchanged (it is already generic over `Read+Write`).
pub trait Channel: Read + Write + Send {}
impl<T: Read + Write + Send> Channel for T {}

/// The adapter contract (a simplified slice of §15's `TransportAdapter`): establish a
/// connection to `dest`. Path SELECTION is not here — `SocketTransport` owns the
/// ordered `Path` list and retries connect+handshake across it. The richer
/// `probe`/`Capabilities`/`migrate` and per-path health/cooldown are roadmap.
pub trait TransportAdapter: Send + Sync {
    fn connect(&self, dest: &Dest) -> io::Result<Box<dyn Channel>>;

    /// What this carrier is, for the indicator the user reads (A4-10, #217).
    ///
    /// Required rather than defaulted on purpose. A default would silently label every future
    /// adapter — and every test spy — as whatever the default said, which is exactly the failure
    /// this exists to prevent: a privacy indicator that can be wrong is worse than none, because
    /// the user makes decisions on it. Adding a carrier now forces its author to name it.
    fn carrier_label(&self) -> &'static str;

    /// Connect with a PER-REQUEST stream-isolation scope on top of whatever the adapter
    /// already carries.
    ///
    /// The default ignores `scope`, which is correct for every carrier that has no notion
    /// of circuits: a direct TCP connection is its own source address and nothing else can
    /// be arranged. Only `Socks5Adapter` overrides it, because only a SOCKS proxy can be
    /// ASKED for a separate circuit (Tor keys them off the credential).
    ///
    /// This exists because rotating identifiers above the IP is undone below it. The
    /// drop-box handles and the loop boxes are unlinkable to the relay by construction —
    /// and then arrive over one connection from one address, which relinks them for free.
    /// The scope is what lets the caller say "this request must not share a circuit with
    /// that one".
    fn connect_isolated(&self, dest: &Dest, _scope: Option<&str>) -> io::Result<Box<dyn Channel>> {
        self.connect(dest)
    }
}

/// Direct TCP — the base adapter (no transport obfuscation).
pub struct DirectTcpAdapter {
    /// Read timeout set on the established socket (`None` = block forever).
    /// `Default` = `READ_TIMEOUT`; tests inject a short one to prove that a silent
    /// peer yields an error rather than an endless hang.
    pub read_timeout: Option<Duration>,
}

impl Default for DirectTcpAdapter {
    fn default() -> Self {
        DirectTcpAdapter { read_timeout: Some(READ_TIMEOUT) }
    }
}

impl TransportAdapter for DirectTcpAdapter {
    fn carrier_label(&self) -> &'static str {
        "direct"
    }

    /// IP literals only. A NAME is refused rather than resolved: a `.onion`/`.i2p` has
    /// no DNS answer, and quietly resolving an ordinary hostname would leak the lookup
    /// to a DNS server the user never chose. Names belong to a resolving carrier.
    fn connect(&self, dest: &Dest) -> io::Result<Box<dyn Channel>> {
        let addr = dest.as_ip().ok_or_else(|| {
            io_err(format!(
                "direct: {dest} is a name, not an address — a name needs a resolving carrier (SOCKS)"
            ))
        })?;
        let s = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
        s.set_read_timeout(self.read_timeout)?;
        Ok(Box::new(s))
    }
}

/// SOCKS5 (CONNECT, no auth, RFC 1928). Routes the outbound connection through an
/// external proxy — point it at a PT client's local SOCKS port (Tor `9050`, an
/// obfs4/Shadowsocks client, …). THAT is what provides the obfuscation.
pub struct Socks5Adapter {
    pub proxy: SocketAddr,
    /// Read timeout (`None` = forever). `Socks5Adapter::new` uses `READ_TIMEOUT`.
    pub read_timeout: Option<Duration>,
    /// **Stream-isolation credential** (RFC 1929 username/password), `None` = no-auth.
    ///
    /// Tor enables `IsolateSOCKSAuth` by default: connections presenting DIFFERENT SOCKS
    /// credentials get DIFFERENT circuits, enforced by Tor rather than hoped for by us.
    /// That is what keeps two identities on one device from sharing a circuit — the axis
    /// that would otherwise link compartments no matter how different their keys are.
    /// The value is opaque and random per compartment; it is never a name, and the proxy
    /// only ever uses it as an isolation token.
    pub isolation: Option<String>,
}

impl Socks5Adapter {
    /// Through `proxy`, no stream isolation (one shared circuit pool).
    pub fn new(proxy: SocketAddr) -> Self {
        Socks5Adapter { proxy, read_timeout: Some(READ_TIMEOUT), isolation: None }
    }

    /// Through `proxy`, isolated onto its OWN circuit by `token` (see `isolation`).
    pub fn isolated(proxy: SocketAddr, token: impl Into<String>) -> Self {
        Socks5Adapter {
            proxy,
            read_timeout: Some(READ_TIMEOUT),
            isolation: Some(token.into()),
        }
    }
}

/// A transport-layer error with a message (name-vs-address refusals, SOCKS faults).
fn io_err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

/// A fresh, opaque stream-isolation token (see `Socks5Adapter::isolation`). Random, not
/// derived from any identity: a token derived from a key would BE that key's label, and
/// the proxy would hold a stable handle on the very thing we are separating.
pub fn isolation_token() -> String {
    use chacha20poly1305::aead::rand_core::RngCore;
    let mut b = [0u8; 16];
    chacha20poly1305::aead::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn socks_err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

impl Socks5Adapter {
    /// The credential presented for a request scoped to `scope`.
    ///
    /// The compartment token and the per-request scope are COMBINED rather than one
    /// replacing the other. Both separations must hold at once: two accounts must never
    /// share a circuit (the compartment axis), and within one account two unlinkable
    /// handles must not either. Dropping the compartment token to make room for the scope
    /// would trade one guarantee for the other.
    ///
    /// Hashed rather than concatenated so the proxy is not handed the caller's actual
    /// identifiers. The scope a `Peer` passes is derived from its `client_addr` handle,
    /// and the relay sees that handle in the clear — so shipping it verbatim to the proxy
    /// would let a proxy operator and a relay operator join their logs on an exact match
    /// instead of on timing.
    fn credential(&self, scope: Option<&str>) -> Option<String> {
        match (&self.isolation, scope) {
            (None, None) => None,
            (base, sc) => {
                let mut h = Sha256::new();
                h.update(b"karst-socks-isolation-v1");
                h.update(base.as_deref().unwrap_or("").as_bytes());
                h.update([0u8]); // unambiguous boundary: ("ab", "c") must not equal ("a", "bc")
                h.update(sc.unwrap_or("").as_bytes());
                Some(h.finalize().iter().take(16).map(|x| format!("{x:02x}")).collect())
            }
        }
    }
}

impl TransportAdapter for Socks5Adapter {
    fn carrier_label(&self) -> &'static str {
        "socks5"
    }

    fn connect(&self, dest: &Dest) -> io::Result<Box<dyn Channel>> {
        self.connect_isolated(dest, None)
    }

    fn connect_isolated(&self, dest: &Dest, scope: Option<&str>) -> io::Result<Box<dyn Channel>> {
        let credential = self.credential(scope);
        // Proxy unreachable → hard error. We do NOT fall back to direct.
        let mut s = TcpStream::connect_timeout(&self.proxy, CONNECT_TIMEOUT)?;
        // The read timeout covers both the SOCKS handshake and the Noise/response that
        // follow: a silent proxy yields an error instead of wedging the client thread.
        s.set_read_timeout(self.read_timeout)?;

        // Greeting. **Fail closed on isolation.** When a token is present we offer ONLY
        // user/pass (0x02), never no-auth — so a proxy that cannot key a separate circuit
        // off the credential is REFUSED rather than silently handed the shared circuit.
        // Offering no-auth as a fallback (the old behaviour) meant isolation could fail
        // invisibly and two compartments could share a circuit while looking isolated.
        // Without a token, no-auth is correct: no isolation was asked for.
        match &credential {
            None => s.write_all(&[0x05, 0x01, 0x00])?,
            Some(_) => s.write_all(&[0x05, 0x01, 0x02])?,
        }
        let mut sel = [0u8; 2];
        s.read_exact(&mut sel)?;
        if sel[0] != 0x05 {
            return Err(socks_err("socks5: not a SOCKS5 proxy"));
        }
        match sel[1] {
            // No-auth is acceptable ONLY when we did not ask for isolation. If a token was
            // present and the proxy still selected no-auth (non-compliant — we never
            // offered it), fail closed: a shared circuit is exactly what isolation forbids.
            0x00 if credential.is_none() => {}
            0x00 => {
                return Err(socks_err(
                    "socks5: proxy would not isolate (selected no-auth) — failing closed",
                ))
            }
            0x02 => {
                let token = credential
                    .as_deref()
                    .ok_or_else(|| socks_err("socks5: proxy demanded auth we did not offer"))?;
                // RFC 1929: VER=1, ULEN, UNAME, PLEN, PASSWD. Tor keys circuit isolation
                // off this pair; the password is irrelevant, so it mirrors the token.
                let u = token.as_bytes();
                let len: u8 = u
                    .len()
                    .try_into()
                    .map_err(|_| socks_err("socks5: isolation token longer than 255 bytes"))?;
                let mut auth = vec![0x01, len];
                auth.extend_from_slice(u);
                auth.push(len);
                auth.extend_from_slice(u);
                s.write_all(&auth)?;
                let mut ok = [0u8; 2];
                s.read_exact(&mut ok)?;
                if ok[1] != 0x00 {
                    return Err(socks_err("socks5: the proxy rejected the isolation credential"));
                }
            }
            other => {
                return Err(socks_err(format!("socks5: no acceptable auth method (got {other:#04x})")))
            }
        }

        // CONNECT: VER=5, CMD=1, RSV=0, ATYP+ADDR, PORT(be).
        let mut req = vec![0x05, 0x01, 0x00];
        match dest.as_ip().map(|a| a.ip()) {
            Some(IpAddr::V4(v4)) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            Some(IpAddr::V6(v6)) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
            // ATYP=0x03: a NAME, resolved by the PROXY, not by us. This is what makes a
            // Tor `.onion` / I2P `.i2p` reachable at all — and it keeps an ordinary
            // hostname's lookup inside the tunnel instead of leaking it to local DNS.
            None => {
                let host = dest.host.as_bytes();
                let len: u8 = host
                    .len()
                    .try_into()
                    .map_err(|_| socks_err("socks5: hostname longer than 255 bytes"))?;
                if len == 0 {
                    return Err(socks_err("socks5: empty hostname"));
                }
                req.push(0x03);
                req.push(len);
                req.extend_from_slice(host);
            }
        }
        req.extend_from_slice(&dest.port.to_be_bytes());
        s.write_all(&req)?;

        // Reply: VER REP RSV ATYP BND.ADDR BND.PORT. REP=0 means success.
        let mut head = [0u8; 4];
        s.read_exact(&mut head)?;
        if head[0] != 0x05 || head[1] != 0x00 {
            return Err(socks_err(format!("socks5 CONNECT refused: rep={}", head[1])));
        }
        // Read and discard BND.ADDR (per ATYP) + the 2 port bytes.
        let addr_len = match head[3] {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l)?;
                l[0] as usize
            }
            other => return Err(socks_err(format!("socks5: unknown ATYP {other}"))),
        };
        let mut skip = vec![0u8; addr_len + 2];
        s.read_exact(&mut skip)?;

        Ok(Box::new(s))
    }
}

/// Base cooldown after a path's first failure; doubles per consecutive failure up to
/// `MAX_COOLDOWN`. Short enough that a blip does not exile a good path for long.
const BASE_COOLDOWN_SECS: u64 = 10;
/// Ceiling on the backoff — a long-dead path is still re-probed this often.
const MAX_COOLDOWN_SECS: u64 = 300;

/// Health of ONE path, shared (`Arc`) by every clone of it, so it survives the
/// per-request transports built from the same `Path` list. Without this, a blackholed
/// primary costs a full `CONNECT_TIMEOUT` on EVERY request before failover.
///
/// Interior atomics, not a `Mutex`: this is advisory scheduling state on the hot path;
/// a racy update at worst re-probes a path one extra time.
#[derive(Debug, Default)]
pub struct PathHealth {
    /// Consecutive failures (reset by a success). Drives the backoff.
    fails: std::sync::atomic::AtomicU32,
    /// Unix seconds until which the path is deprioritized. 0 = healthy.
    until: std::sync::atomic::AtomicU64,
    /// Sequence number of this path's last success, `0` = never (A4-10, #217).
    ///
    /// A COUNTER, not a timestamp: the local clock is an unauthenticated input everywhere else in
    /// this codebase, and all this needs is an ordering — which path succeeded most recently. It
    /// is written by the same `record_success` the transport already calls, so the carrier the UI
    /// reports comes from the path that actually ran rather than from a parallel guess.
    last_ok: std::sync::atomic::AtomicU64,
}

/// Monotonic source for `PathHealth::last_ok`. Process-wide because ordering only has to hold
/// within one running client, which is exactly the lifetime of the indicator it feeds.
static SUCCESS_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl PathHealth {
    /// Is the path currently out of cooldown? (Cooling paths are still tried, just
    /// LAST — see `SocketTransport`; a cooldown must never make recovery impossible.)
    pub fn usable(&self, now: u64) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        now >= self.until.load(Relaxed)
    }

    /// The path worked: clear the backoff immediately.
    pub fn record_success(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.last_ok.store(SUCCESS_SEQ.fetch_add(1, Relaxed), Relaxed);
        self.fails.store(0, Relaxed);
        self.until.store(0, Relaxed);
    }

    /// The path failed to connect/handshake: exponential backoff from
    /// `BASE_COOLDOWN_SECS`, capped at `MAX_COOLDOWN_SECS`.
    pub fn record_failure(&self, now: u64) {
        use std::sync::atomic::Ordering::Relaxed;
        let n = self.fails.fetch_add(1, Relaxed).saturating_add(1);
        let backoff = BASE_COOLDOWN_SECS
            .saturating_mul(1u64 << n.min(6).saturating_sub(1))
            .min(MAX_COOLDOWN_SECS);
        self.until.store(now.saturating_add(backoff), Relaxed);
    }
}

/// One route to the relay: HOW to connect (`adapter` — the carrier), WHERE (`dest` —
/// the endpoint), and how it has been behaving (`health`). Paths to one relay identity
/// are alternate routes (another IP and/or another carrier); Noise on top authenticates
/// the same relay regardless of which path was taken.
///
/// `Clone` shares the health (`Arc`), which is the point: a transport rebuilt per
/// request still remembers which routes are dead.
#[derive(Clone)]
pub struct Path {
    pub adapter: Arc<dyn TransportAdapter>,
    pub dest: Dest,
    pub health: Arc<PathHealth>,
}

impl PathHealth {
    /// When this path last worked, as a process-wide sequence number (`0` = never).
    pub fn last_ok(&self) -> u64 {
        self.last_ok.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Path {
    /// A route with fresh (healthy) state.
    pub fn new(adapter: Arc<dyn TransportAdapter>, dest: impl Into<Dest>) -> Self {
        Path { adapter, dest: dest.into(), health: Arc::new(PathHealth::default()) }
    }
}

// ----- Address validation, shared by both sides (#143) -----
//
// Moved out of the relay's gossip module with the crate split. It is not gossip logic: it is the
// question "may we dial this string at all", which the client asks of a peer-supplied hint for
// exactly the same reason the relay asks it of a gossiped one (A3-12: an unchecked address is an
// SSRF into loopback and private ranges).

/// Is this `host:port` safe to dial? Resolves the host and requires EVERY resolved address to be
/// globally routable, so a DNS name pointing at an internal IP is refused too. `allow_private`
/// exists for loopback tests and local development — production relays run with it off.
pub fn addr_is_dialable(addr: &str, allow_private: bool) -> bool {
    if allow_private {
        return true;
    }
    let Ok(dest) = Dest::parse(addr) else {
        return false;
    };
    match (dest.host.as_str(), dest.port).to_socket_addrs() {
        // Unresolvable ⇒ we cannot prove it is safe, so refuse rather than dial blind.
        Ok(mut addrs) => {
            let all: Vec<_> = addrs.by_ref().collect();
            !all.is_empty() && all.iter().all(|sa| ip_is_globally_routable(&sa.ip()))
        }
        Err(_) => false,
    }
}

fn ip_is_globally_routable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1]))       // 100.64.0.0/10 CGNAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)          // 192.0.0.0/24 IETF
                || (o[0] == 198 && (18..20).contains(&o[1]))        // 198.18.0.0/15 benchmarking
                || o[0] >= 240)                                     // 240.0.0.0/4 reserved
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return ip_is_globally_routable(&IpAddr::V4(mapped));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00                        // fc00::/7 unique local
                || (s[0] & 0xffc0) == 0xfe80)                       // fe80::/10 link-local
        }
    }
}

#[cfg(test)]
mod compartment_and_scope_are_two_axes {
    use super::*;

    /// **Two identities on ONE compartment token must still get different circuits.**
    ///
    /// This is the property a whole privacy model rests on, and it is easy to misread: a `Relay`
    /// is built per device configuration, so several proxy identities legitimately share the
    /// compartment token, and separation comes from the per-handle scope hashed together with it.
    /// Reading only the token axis produces the confident, wrong conclusion that the proxies share
    /// a circuit — I filed a privacy bug on exactly that misreading on 2026-07-29, and blocked a
    /// connection-pool change behind it.
    ///
    /// DISCRIMINATING: make `credential` return the compartment token alone (drop `scope` from the
    /// hash) and this goes red, which is the shape the mistaken bug report assumed.
    #[test]
    fn one_compartment_two_scopes_are_different_credentials() {
        let a = Socks5Adapter::isolated("127.0.0.1:9050".parse().unwrap(), "device-compartment");
        // Two proxy identities of the SAME device: same compartment, different handle-derived
        // scopes (handle bytes are random per proxy, in each proxy's own sessions file).
        let p1 = a.credential(Some("scope-of-proxy-1"));
        let p2 = a.credential(Some("scope-of-proxy-2"));
        assert!(p1.is_some() && p2.is_some(), "a scoped request must present a credential");
        assert_ne!(
            p1, p2,
            "two proxy identities on one device produced the SAME SOCKS credential, so Tor would \
             put them on ONE circuit and a relay would see them from one source — which links the \
             identities the proxy model exists to keep apart"
        );
    }

    /// And the other axis independently: same scope, different compartments must also differ.
    #[test]
    fn one_scope_two_compartments_are_different_credentials() {
        let x = Socks5Adapter::isolated("127.0.0.1:9050".parse().unwrap(), "compartment-x");
        let y = Socks5Adapter::isolated("127.0.0.1:9050".parse().unwrap(), "compartment-y");
        assert_ne!(
            x.credential(Some("same-scope")),
            y.credential(Some("same-scope")),
            "the compartment axis stopped separating: dropping it would trade one guarantee for \
             the other, which is exactly what `credential`'s doc refuses"
        );
    }

    /// The KNOWN residual, pinned so it is a decision rather than a surprise: an UNSCOPED request
    /// hashes the same for every identity, so the public reads share a circuit. That is the
    /// QUIC-13 position — scoping them would attach a channel label to requests that have none —
    /// and it links interests, never identities.
    #[test]
    fn unscoped_requests_deliberately_share_one_credential() {
        let a = Socks5Adapter::isolated("127.0.0.1:9050".parse().unwrap(), "device-compartment");
        assert_eq!(
            a.credential(None),
            a.credential(None),
            "unscoped requests are supposed to be indistinguishable from each other"
        );
        assert_ne!(
            a.credential(None),
            a.credential(Some("scope-of-proxy-1")),
            "an unscoped request must not land on a SCOPED identity's circuit — that would put a \
             public read on a channel's circuit and give the proxy operator the join"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn health_backs_off_on_failure_and_recovers_on_success() {
        let h = PathHealth::default();
        assert!(h.usable(1000), "fresh path is usable");

        // First failure → cooled down for the base window, usable again after it.
        h.record_failure(1000);
        assert!(!h.usable(1000 + BASE_COOLDOWN_SECS - 1), "still cooling inside the window");
        assert!(h.usable(1000 + BASE_COOLDOWN_SECS), "usable once the window passes");

        // Consecutive failures back off further (2nd = 2x base).
        h.record_failure(2000);
        assert!(!h.usable(2000 + BASE_COOLDOWN_SECS), "second failure backs off past the base window");
        assert!(h.usable(2000 + BASE_COOLDOWN_SECS * 2), "…but not past 2x base");

        // A success clears everything immediately — a recovered path is not punished
        // for its history.
        h.record_success();
        assert!(h.usable(2001), "success resets the cooldown at once");
    }

    #[test]
    fn health_backoff_is_capped() {
        // A long-dead path must still be re-probed periodically, not exiled forever.
        let h = PathHealth::default();
        for _ in 0..20 {
            h.record_failure(1000);
        }
        assert!(h.usable(1000 + MAX_COOLDOWN_SECS), "backoff never exceeds the cap");
    }

    #[test]
    fn health_is_shared_across_clones_of_a_path() {
        // The point of the Arc: a transport rebuilt per request must still see that a
        // route is dead. Discriminating: make `health` a plain field (cloned, not
        // shared) and the clone stays "usable" → reds.
        let p = Path::new(Arc::new(DirectTcpAdapter::default()), addr_of(9));
        let clone = p.clone();
        p.health.record_failure(1000);
        assert!(!clone.health.usable(1000), "a clone observes the original's failure");
    }

    fn addr_of(n: u16) -> SocketAddr {
        format!("127.0.0.1:{n}").parse().unwrap()
    }

    #[test]
    fn dest_parses_names_and_addresses() {
        assert_eq!(Dest::parse("10.0.0.1:9000").unwrap(), Dest::new("10.0.0.1", 9000));
        assert_eq!(Dest::parse("[::1]:9000").unwrap().port, 9000);
        // The case this whole type exists for: a hidden-service name has no IP.
        let onion = Dest::parse("abcdefghij234567.onion:9000").unwrap();
        assert_eq!(onion.host, "abcdefghij234567.onion");
        assert!(onion.as_ip().is_none(), "a name is not an address");
        assert!(Dest::parse("nonsense").is_err());
        assert!(Dest::parse(":9000").is_err());
    }

    #[test]
    fn socks5_sends_a_name_as_atyp_domain_so_onion_addresses_work() {
        // THE test for reaching hidden services: the proxy must be asked to resolve the
        // NAME (ATYP 0x03) — Tor/I2P are the only things that can. Discriminating: with
        // the old IPv4/IPv6-only code a name could not be expressed at all, so this
        // cannot pass by accident.
        use std::io::Read as _;
        use std::net::TcpListener;
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let paddr = proxy.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            let (mut c, _) = proxy.accept().unwrap();
            let mut greet = [0u8; 3];
            c.read_exact(&mut greet).unwrap();
            c.write_all(&[0x05, 0x00]).unwrap(); // no-auth agreed
            let mut head = [0u8; 4];
            c.read_exact(&mut head).unwrap(); // VER CMD RSV ATYP
            let mut rest = vec![0u8; 1];
            c.read_exact(&mut rest).unwrap(); // name length
            let mut name = vec![0u8; rest[0] as usize + 2]; // name + port
            c.read_exact(&mut name).unwrap();
            let mut log = seen2.lock().unwrap();
            log.extend_from_slice(&head); // VER CMD RSV ATYP
            log.extend_from_slice(&rest); // name length
            log.extend_from_slice(&name); // name + port
            std::thread::sleep(Duration::from_millis(200));
        });

        let a = Socks5Adapter { proxy: paddr, read_timeout: Some(Duration::from_millis(300)), isolation: None };
        let _ = a.connect(&Dest::new("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion", 443));

        let got = seen.lock().unwrap().clone();
        assert_eq!(got[3], 0x03, "ATYP must be 0x03 (domain name), not an IP type");
        let len = got[4] as usize;
        let name = String::from_utf8_lossy(&got[5..5 + len]).to_string();
        assert!(name.ends_with(".onion"), "the proxy is asked to resolve the name itself: {name}");
        let port = u16::from_be_bytes([got[5 + len], got[6 + len]]);
        assert_eq!(port, 443);
    }

    #[test]
    fn an_isolation_token_is_offered_to_the_proxy_as_socks_auth() {
        // Tor keys circuit isolation off the SOCKS credential (IsolateSOCKSAuth, on by
        // default), so presenting a per-compartment token is what forces Tor to give each
        // identity its OWN circuit — enforced by Tor, not hoped for by us. Without it two
        // compartments can share a circuit and are linked no matter how different their
        // keys are. Discriminating: drop the token (no-auth) and the proxy sees METHOD
        // 0x00 only — the auth exchange below never happens.
        //
        // The credential is a HASH of the token, not the token. This test used to demand
        // it verbatim, which was asserting an implementation detail as if it were the
        // property: Tor only needs credentials that DIFFER, and shipping our own
        // identifiers to the proxy is a leak, not a feature. What must hold is that
        // something is presented and that it is not the raw token — distinctness is
        // `two_compartments_get_different_isolation_tokens`' job.
        use std::io::Read as _;
        use std::net::TcpListener;
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let paddr = proxy.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            let (mut c, _) = proxy.accept().unwrap();
            let mut greet = [0u8; 3]; // VER NMETHODS + 1 method (user/pass only — fail closed)
            c.read_exact(&mut greet).unwrap();
            c.write_all(&[0x05, 0x02]).unwrap(); // demand user/pass
            let mut head = [0u8; 2]; // VER ULEN
            c.read_exact(&mut head).unwrap();
            let mut user = vec![0u8; head[1] as usize];
            c.read_exact(&mut user).unwrap();
            let mut log = seen2.lock().unwrap();
            log.extend_from_slice(&greet);
            log.extend_from_slice(&user);
            std::thread::sleep(Duration::from_millis(150));
        });

        let a = Socks5Adapter {
            proxy: paddr,
            read_timeout: Some(Duration::from_millis(300)),
            isolation: Some("compartment-7f3a".into()),
        };
        let _ = a.connect(&Dest::new("relay.example", 9000));

        let got = seen.lock().unwrap().clone();
        assert_eq!(&got[..3], &[0x05, 0x01, 0x02], "offers ONLY user/pass — fail closed on isolation");
        let presented = String::from_utf8_lossy(&got[3..]).to_string();
        assert!(!presented.is_empty(), "a credential must be presented, or Tor pools the circuit");
        assert_ne!(
            presented, "compartment-7f3a",
            "the raw compartment token reached the proxy — it must be hashed, so a proxy \
             operator cannot join logs with a relay operator on an exact match"
        );
        assert_eq!(
            presented,
            a.credential(None).unwrap(),
            "the credential must be a stable function of the token, or every connection \
             lands on a different circuit and isolation becomes churn"
        );
    }

    #[test]
    fn isolation_fails_closed_when_the_proxy_will_not_isolate() {
        // P0: a proxy that selects no-auth despite an isolation token must be REFUSED, not
        // silently used on a shared circuit. Otherwise two compartments look isolated while
        // riding one circuit — the exact link isolation exists to prevent.
        //
        // The mock plays a non-isolating proxy: it answers the greeting with no-auth
        // (0x00). The connect must return an error. Discriminating: revert the fix (accept
        // 0x00 with a token) and this connect would SUCCEED past auth → red.
        use std::io::Read as _;
        use std::net::TcpListener;
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let paddr = proxy.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut c, _) = proxy.accept().unwrap();
            let mut greet = [0u8; 3];
            let _ = c.read_exact(&mut greet);
            let _ = c.write_all(&[0x05, 0x00]); // "no-auth" — refuse to isolate
            std::thread::sleep(Duration::from_millis(100));
        });

        let a = Socks5Adapter {
            proxy: paddr,
            read_timeout: Some(Duration::from_millis(300)),
            isolation: Some("compartment-7f3a".into()),
        };
        let err = match a.connect(&Dest::new("relay.example", 9000)) {
            Ok(_) => panic!("a non-isolating proxy was accepted with an isolation token"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("failing closed") || err.to_string().contains("isolate"),
            "wrong error for a non-isolating proxy: {err}"
        );
    }

    #[test]
    fn two_compartments_get_different_isolation_tokens() {
        // The token must differ per compartment — a shared one would isolate them from
        // everyone else while keeping them on ONE circuit together, which is the failure
        // this whole axis exists to prevent.
        let a = Socks5Adapter::isolated("127.0.0.1:9050".parse().unwrap(), isolation_token());
        let b = Socks5Adapter::isolated("127.0.0.1:9050".parse().unwrap(), isolation_token());
        assert_ne!(a.isolation, b.isolation, "distinct compartments → distinct circuits");
        assert!(a.isolation.unwrap().len() >= 16, "unguessable, and never a name");
    }

    #[test]
    fn direct_refuses_a_name_instead_of_leaking_a_dns_lookup() {
        // A name on a direct route must fail LOUDLY. Resolving it would either fail
        // (.onion has no DNS record) or hand the lookup to a DNS server the user never
        // chose — a silent deanonymization. Discriminating: resolve it and this reds.
        let a = DirectTcpAdapter::default();
        let err = match a.connect(&Dest::new("example.onion", 9000)) {
            Err(e) => e,
            Ok(_) => panic!("direct must not resolve a name"),
        };
        assert!(
            err.to_string().contains("name"),
            "direct must refuse a name explicitly, got: {err}"
        );
    }

    #[test]
    fn read_timeout_turns_a_silent_peer_into_an_error_not_a_hang() {
        // A path that ACCEPTED TCP and then goes silent (a silent-drop on-path classifier / a hung
        // proxy) must yield a read error rather than wedge the client thread forever.
        // Discriminating: drop `set_read_timeout` (or pass None) and the read blocks
        // until the socket closes — is_err() turns false and this reds.
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let dest = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let _held = listener.accept(); // accept and STAY SILENT, holding it open
            std::thread::sleep(Duration::from_secs(30));
        });

        let adapter = DirectTcpAdapter { read_timeout: Some(Duration::from_millis(200)) };
        let mut ch = adapter.connect(&Dest::from(dest)).expect("the TCP connect succeeds");
        let start = std::time::Instant::now();
        let mut buf = [0u8; 8];
        assert!(ch.read(&mut buf).is_err(), "silent peer → a read timeout error");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the error came from the 200ms timeout, not from blocking"
        );
    }
}
