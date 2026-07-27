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
use std::sync::{Arc, Mutex};

use crate::node::{RelayDescriptor, RelayNode};
use crate::socket::SocketTransport;
use crate::transport::Dest;

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
pub fn verify(d: &RelayDescriptor, addr: &str) -> bool {
    let Ok(dest) = Dest::parse(addr) else {
        return false;
    };
    match SocketTransport::new(dest, d.noise_pub).get_node_list() {
        Ok(list) => list.iter().any(|e| e.noise_pub == d.noise_pub && e.fetch_pub == d.fetch_pub),
        Err(_) => false, // handshake failed (wrong key / not a relay) or unreachable
    }
}

/// One gossip round. Pulls each known PEER's node-list and merges newly-heard descriptors that
/// pass `verify_at`, under the rate limits above. Returns how many verified relays were added.
/// Stateless and dependency-injected on the relay handle, so it is integration-tested against
/// real relays on loopback. Never gossips with self.
pub fn gossip_round(relay: &Arc<Mutex<RelayNode>>, self_noise_pub: &[u8; 32]) -> usize {
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
            if verify(&d, &addr) {
                relay.lock().expect("relay mutex").add_relay(d.clone());
                known_ids.insert(id);
                added += 1;
            }
        }
    }
    added
}
