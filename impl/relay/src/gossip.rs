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
use std::sync::{Arc, RwLock};

use node::protocol::{RelayDescriptor, SignedDescriptor};
use crate::node::{RelayNode};
use karst_transport::socket::SocketTransport;
use karst_transport::transport::Dest;

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
/// (2) needs the target to self-advertise (it must, to be discoverable). It is asked for its own
/// signed descriptor directly, so this no longer depends on the target's served PAGE happening to
/// include its self-entry — with signed descriptors the page is a rotating window and a busy relay
/// may legitimately leave itself out of the one we received.
pub fn verify(d: &RelayDescriptor, addr: &str, allow_private: bool, now: u64) -> bool {
    verified_self_descriptor(d, addr, allow_private, now).is_some()
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
///
/// The dial did not become redundant when descriptors became signed, and it is worth saying why:
/// a signature proves AUTHORSHIP, not reachability or presence. Without the dial, a peer could
/// replay a genuine, correctly-signed descriptor for a relay that has since vanished, and we would
/// re-serve it forever. The signature answers "did this relay say this"; the dial answers "is it
/// still there, at an address we may legitimately use". Both, in that order.
pub fn verified_self_descriptor(
    d: &RelayDescriptor,
    addr: &str,
    allow_private: bool,
    now: u64,
) -> Option<SignedDescriptor> {
    if !karst_transport::transport::addr_is_dialable(addr, allow_private) {
        return None; // never dial into private/loopback space on a peer's say-so (A3-12)
    }
    let dest = Dest::parse(addr).ok()?;
    // Ask the relay for its OWN signed statement rather than scanning its node list for a
    // self-entry. Same answer, one obligation fewer: the served page is a rotating window, so a
    // relay with a full table could legitimately omit itself from the page we happened to get.
    let s = SocketTransport::new(dest, d.noise_pub).get_descriptor().ok()??;
    // It must be about the relay we dialed. Noise already authenticated `noise_pub`; the fetch key
    // is the other half of the relay-id and is what the peer's claim was keyed on.
    if s.desc.relay.noise_pub != d.noise_pub || s.desc.relay.fetch_pub != d.fetch_pub {
        return None;
    }
    // Signature and window. `add_relay` re-checks this — deliberately, since it is the invariant
    // for the whole list — but a caller that only wants the descriptor gets it checked too.
    s.verified(now)?;
    // Its self-declared addresses still have to pass the SSRF gate: "the relay said so" is not a
    // licence to dial someone's LAN either. A signature does not change that, so a descriptor
    // whose every address is one we may not dial is REFUSED rather than trimmed — trimming would
    // break the signature (see `descriptor_within_bounds`).
    if !s
        .desc
        .relay
        .addrs
        .iter()
        .any(|a| karst_transport::transport::addr_is_dialable(a, allow_private))
    {
        return None;
    }
    Some(s)
}

/// One gossip round. Pulls each known PEER's node-list and merges newly-heard descriptors that
/// pass `verify_at`, under the rate limits above. Returns how many verified relays were added.
/// Stateless and dependency-injected on the relay handle, so it is integration-tested against
/// real relays on loopback. Never gossips with self.
pub fn gossip_round(
    relay: &Arc<RwLock<RelayNode>>,
    self_noise_pub: &[u8; 32],
    allow_private: bool,
    now: u64,
) -> usize {
    let (known, hints) = {
        let r = relay.read().expect("relay lock");
        (r.known_relays(), r.relay_hints())
    };
    let mut known_ids: HashSet<String> = known.iter().map(|d| d.desc.relay.relay_id_hex()).collect();
    // Peers to PULL from = what others signed, plus the operator's hints. The hints have to be in
    // here: a relay that has just started knows nobody yet, and its configured peers are the only
    // way into the network. They are dial targets only — nothing gathered from a hint is stored
    // unless the relay at the far end signed it.
    let peers: Vec<RelayDescriptor> =
        known.iter().map(|s| s.desc.relay.clone()).chain(hints).collect();
    let mut dialed_addrs: HashSet<String> = HashSet::new();
    let mut dials = 0usize;
    let mut added = 0usize;

    for peer in &peers {
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
        if !karst_transport::transport::addr_is_dialable(&peer_addr, allow_private) {
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
            let id = d.desc.relay.relay_id_hex();
            if known_ids.contains(&id) {
                continue; // already known — no work
            }
            // Verify the first not-yet-dialed address; per-address dedup means many
            // descriptors pointing at one already-dialed victim cost no further dials.
            let Some(addr) = d.desc.relay.addrs.iter().find(|a| !dialed_addrs.contains(*a)).cloned() else {
                continue;
            };
            dialed_addrs.insert(addr.clone());
            dials += 1;
            new_from_peer += 1;
            // Store what the relay says about ITSELF, not what the peer said about it
            // (CRYPTO-23). The peer's address was only a place to dial.
            if let Some(own) = verified_self_descriptor(&d.desc.relay, &addr, allow_private, now) {
                relay.write().expect("relay lock").add_relay(own, now);
                known_ids.insert(id);
                added += 1;
            }
        }
    }
    added
}
