//! §12 discovery — node-list GOSSIP MERGE (relays converging on each other's lists).
//!
//! The foundation slice served an operator-curated list and never merged anything heard from a
//! peer, because re-serving a peer-supplied address without checking it is a reflection/DDoS
//! amplifier: a single hostile relay could gossip `{random_key, victim_ip}` and make every
//! relay (and then every client) dial the victim. This module closes that gap with
//! **verify-before-add**: a heard descriptor is dialed FIRST, and added only if the Noise
//! handshake proves that address really serves the claimed relay-id. A victim IP (not a KARST
//! relay, or the wrong key) fails the handshake and is never re-served.
//!
//! Rate limits keep the verification itself from being a weapon:
//! - **per-source**: at most `MAX_NEW_FROM_ONE_PEER` new descriptors are verified from any one
//!   peer per round (and a peer's whole list is frame-bounded on the wire anyway);
//! - **per-address**: each distinct address is dialed at most ONCE per round, so 100 junk
//!   entries all pointing at one IP cost ONE dial, not 100;
//! - **overall**: `MAX_DIALS_PER_ROUND` caps every connection attempt in a round.

use std::collections::HashSet;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};

use crate::node::{RelayDescriptor, RelayNode};
use crate::socket::SocketTransport;
use crate::transport::Dest;

/// May this IP be dialed on the public internet?
///
/// Verify-before-add stops a hostile peer's address from being RE-SERVED, but the dial itself
/// happens first — so without this an attacker could still make a public relay connect,
/// repeatedly and on a schedule, to `127.0.0.1:<port>`, `10.0.0.0/8`, or the cloud metadata
/// service at `169.254.169.254`. The Noise handshake bounds what can be exchanged, but the
/// connection attempt alone is egress SSRF and internal port probing (A3-12).
///
/// Rejects loopback, private, link-local (which covers the metadata address), CGNAT,
/// unspecified, multicast, broadcast, documentation and benchmarking ranges, plus their IPv6
/// equivalents and IPv4-mapped IPv6 forms.
pub fn ip_is_globally_routable(ip: &IpAddr) -> bool {
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

/// How often a gossip round runs (seconds).
pub const GOSSIP_INTERVAL_SECS: u64 = 300;
/// Hard cap on connection attempts (peer pulls + verifications) in one round — the overall
/// rate limit, so gossip can never be a high-volume reflector regardless of what peers say.
pub const MAX_DIALS_PER_ROUND: usize = 12;
/// Cap on newly-heard descriptors verified from a single peer per round (per-source limit).
pub const MAX_NEW_FROM_ONE_PEER: usize = 4;

/// Verify a heard descriptor before trusting it. Two checks, both from ONE dial:
/// 1. the Noise handshake to `addr` matches `d.noise_pub` — so that address genuinely serves
///    this noise key (a victim IP or wrong key fails closed → the reflection defense);
/// 2. the relay there advertises ITSELF with the SAME full relay-id (`noise_pub` AND
///    `fetch_pub`) — so a peer cannot lie about a real relay's fetch key, only about relays
///    that vouch for themselves.
///
/// (2) needs the target to self-advertise (it must, to be discoverable) and to include its
/// self-entry in the served page — self is seeded first, so it sits in the frame prefix.
pub fn verify(d: &RelayDescriptor, addr: &str, allow_private: bool) -> bool {
    verified_self_descriptor(d, addr, allow_private).is_some()
}

/// Dial `addr`, confirm the relay with `d`'s keys answers there, and return **its own** entry for
/// itself — the addresses IT declares, not the ones we were told to expect (CRYPTO-23).
///
/// This distinction is the fix. Everything `verify` checks is also true of a transparent proxy in
/// front of an honest relay: the TCP connection lands on the proxy, the Noise handshake terminates
/// at the real relay behind it, and the relay serves its own relay-id exactly as it should. So a
/// peer could hand out `victim-proxy:port → honest relay-id`, we would verify it, and then STORE
/// the proxy — handing whoever runs it a permanent view of client IPs, timing and volume, plus a
/// selective-drop switch, with the encryption completely intact.
///
/// Comparing the offered address against the self-declared one was considered and rejected (the
/// client side reached the same conclusion): it needs canonicalisation across host-vs-IP, carrier,
/// port and path, and every rule strict enough to catch the proxy also rejects an honest relay
/// reached by a different spelling of its own address. So the offered address is used only as a
/// PLACE TO DIAL, and what gets stored comes from the relay itself.
///
/// A relay that declares no address of its own is not stored: it is not discoverable by its own
/// choice, and inventing one for it is exactly the behaviour being removed.
pub fn verified_self_descriptor(
    d: &RelayDescriptor,
    addr: &str,
    allow_private: bool,
) -> Option<RelayDescriptor> {
    if !addr_is_dialable(addr, allow_private) {
        return None; // never dial into private/loopback space on a peer's say-so (A3-12)
    }
    let dest = Dest::parse(addr).ok()?;
    let list = SocketTransport::new(dest, d.noise_pub).get_node_list().ok()?;
    let mut own = list
        .into_iter()
        .find(|e| e.noise_pub == d.noise_pub && e.fetch_pub == d.fetch_pub)?;
    // Its self-declared addresses still have to pass the SSRF gate: "the relay said so" is not a
    // licence to dial someone's LAN either.
    own.addrs.retain(|a| addr_is_dialable(a, allow_private));
    if own.addrs.is_empty() {
        return None;
    }
    Some(own)
}

/// One gossip round. Pulls each known PEER's node-list and merges newly-heard descriptors that
/// pass `verify_at`, under the rate limits above. Returns how many verified relays were added.
/// Stateless and dependency-injected on the relay handle, so it is integration-tested against
/// real relays on loopback. Never gossips with self.
pub fn gossip_round(
    relay: &Arc<Mutex<RelayNode>>,
    self_noise_pub: &[u8; 32],
    allow_private: bool,
) -> usize {
    let known = relay.lock().expect("relay mutex").known_relays();
    let mut known_ids: HashSet<String> = known.iter().map(|d| d.relay_id_hex()).collect();
    let mut dialed_addrs: HashSet<String> = HashSet::new();
    let mut dials = 0usize;
    let mut added = 0usize;

    for peer in &known {
        if peer.noise_pub == *self_noise_pub {
            continue; // never gossip with yourself
        }
        if dials >= MAX_DIALS_PER_ROUND {
            break;
        }
        // Dial the peer once (counts against the budget; dedup its address for the round).
        let Some(peer_addr) = peer.addrs.iter().find(|a| !dialed_addrs.contains(*a)).cloned() else {
            continue;
        };
        dialed_addrs.insert(peer_addr.clone());
        if !addr_is_dialable(&peer_addr, allow_private) {
            continue; // a known peer's address is still an address we were told about
        }
        dials += 1;
        let heard = match Dest::parse(&peer_addr)
            .ok()
            .and_then(|dest| SocketTransport::new(dest, peer.noise_pub).get_node_list().ok())
        {
            Some(h) => h,
            None => continue, // peer unreachable / not who it claimed — skip
        };

        let mut new_from_peer = 0usize;
        for d in heard {
            if dials >= MAX_DIALS_PER_ROUND || new_from_peer >= MAX_NEW_FROM_ONE_PEER {
                break;
            }
            let id = d.relay_id_hex();
            if known_ids.contains(&id) {
                continue; // already known — no work
            }
            // Verify the first not-yet-dialed address; per-address dedup means many
            // descriptors pointing at one already-dialed victim cost no further dials.
            let Some(addr) = d.addrs.iter().find(|a| !dialed_addrs.contains(*a)).cloned() else {
                continue;
            };
            dialed_addrs.insert(addr.clone());
            dials += 1;
            new_from_peer += 1;
            // Store what the relay says about ITSELF, not what the peer said about it
            // (CRYPTO-23). The peer's address was only a place to dial.
            if let Some(own) = verified_self_descriptor(&d, &addr, allow_private) {
                relay.lock().expect("relay mutex").add_relay(own);
                known_ids.insert(id);
                added += 1;
            }
        }
    }
    added
}
