//! §12 node-list GOSSIP MERGE — verify-before-add, against real relays on loopback.
//!
//! Pins the security property this slice exists for: a descriptor heard from a peer is added
//! ONLY after we dial it and confirm a real relay with the claimed relay-id answers. A poisoned
//! entry (wrong key / victim address) is refused, so gossip can never turn relays into a
//! reflector aimed at a victim. Neuter `verify` (return true) and the poison test reddens.

use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use node::node::{RelayDescriptor, RelayNode};
use node::seal::Identity;
use node::socket::{generate_noise_keypair, RelayServer};

const NOW: u64 = 1_000_000;

/// Spawn a real relay on an ephemeral port with a KNOWN noise key, seeded with `others`
/// (and, if `advertise_self`, its own descriptor). Returns (addr, noise_pub, fetch_pub).
fn spawn(others: Vec<RelayDescriptor>, advertise_self: bool) -> (String, [u8; 32], [u8; 32]) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (npriv, npub) = generate_noise_keypair();
    let fetch = Identity::generate();
    let fetch_pub = fetch.public.to_bytes();
    let mut relay = RelayNode::with_identity(NOW, fetch);
    if advertise_self {
        relay.add_relay(RelayDescriptor { noise_pub: npub, fetch_pub, addrs: vec![addr.clone()] });
    }
    for d in others {
        relay.add_relay(d);
    }
    let server = RelayServer::with_noise_keypair(relay, Arc::new(move || NOW), npriv, npub);
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });
    (addr, npub, fetch_pub)
}

fn desc(noise: [u8; 32], fetch: [u8; 32], addr: &str) -> RelayDescriptor {
    RelayDescriptor { noise_pub: noise, fetch_pub: fetch, addrs: vec![addr.into()] }
}

#[test]
fn verify_accepts_real_relay_and_rejects_impostors() {
    let (addr, npub, fpub) = spawn(vec![], true);

    assert!(node::gossip::verify(&desc(npub, fpub, &addr), &addr, true), "a real self-advertising relay verifies");
    // Wrong noise key: the Noise handshake fails → the reflection defense.
    assert!(!node::gossip::verify(&desc([0xAB; 32], fpub, &addr), &addr, true), "wrong noise key must fail");
    // Right noise, WRONG fetch: the relay's self-advertisement doesn't match → refused.
    assert!(!node::gossip::verify(&desc(npub, [0xCD; 32], &addr), &addr, true), "wrong fetch key must fail");
    // Dead address: unreachable → refused (connection refused, fast).
    assert!(!node::gossip::verify(&desc(npub, fpub, "127.0.0.1:1"), "127.0.0.1:1", true), "dead addr must fail");

    // A relay that does NOT advertise itself can't be verified (no self-entry to match).
    let (a2, n2, f2) = spawn(vec![], false);
    assert!(!node::gossip::verify(&desc(n2, f2, &a2), &a2, true), "a non-self-advertising relay can't be confirmed");
}

#[test]
fn gossip_round_learns_a_verified_relay_from_a_peer() {
    // C: a real self-advertising relay.
    let (c_addr, c_np, c_fp) = spawn(vec![], true);
    let c = desc(c_np, c_fp, &c_addr);
    // A: a real relay that knows C (curated) and advertises itself.
    let (a_addr, a_np, a_fp) = spawn(vec![c.clone()], true);
    let a = desc(a_np, a_fp, &a_addr);
    // B: local relay seeded with A as a peer; we drive one gossip round.
    let (_bpriv, bpub) = generate_noise_keypair();
    let mut b = RelayNode::with_identity(NOW, Identity::generate());
    b.add_relay(a.clone());
    let b = Arc::new(Mutex::new(b));

    let added = node::gossip::gossip_round(&b, &bpub, true);
    assert!(added >= 1, "B should learn a new relay (C) from peer A");
    let ids: Vec<String> = b.lock().unwrap().known_relays().iter().map(|d| d.relay_id_hex()).collect();
    assert!(ids.contains(&c.relay_id_hex()), "B must now know C, verified via a direct dial");
}

#[test]
fn gossip_round_rejects_a_poisoned_descriptor() {
    // A real relay A gossips a POISON entry: a random relay-id pointing at a dead address (a
    // stand-in for a victim IP). B must refuse it — never re-serve an unverified address.
    let poison = desc([0x99; 32], [0x99; 32], "127.0.0.1:2");
    let (a_addr, a_np, a_fp) = spawn(vec![poison.clone()], true);
    let a = desc(a_np, a_fp, &a_addr);
    let (_bpriv, bpub) = generate_noise_keypair();
    let mut b = RelayNode::with_identity(NOW, Identity::generate());
    b.add_relay(a);
    let b = Arc::new(Mutex::new(b));

    node::gossip::gossip_round(&b, &bpub, true);
    let ids: Vec<String> = b.lock().unwrap().known_relays().iter().map(|d| d.relay_id_hex()).collect();
    assert!(
        !ids.contains(&poison.relay_id_hex()),
        "a poisoned (unverifiable) descriptor must NOT be added — the reflection defense"
    );
}

/// A3-12 — gossip must not dial into private/loopback space on a peer's say-so.
///
/// Verify-before-add stops a hostile descriptor from being RE-SERVED, but the dial happens
/// first — so without this filter a malicious known peer could make a public relay connect, on a
/// schedule, to `127.0.0.1:<port>`, an RFC1918 host, or the cloud metadata service at
/// 169.254.169.254. The Noise handshake bounds what can be exchanged, but the connection attempt
/// itself is egress SSRF and internal port probing.
#[test]
fn gossip_refuses_private_and_loopback_destinations() {
    use node::gossip::addr_is_dialable;

    for addr in [
        "127.0.0.1:9000",          // loopback
        "10.0.0.1:9000",           // RFC1918
        "192.168.1.1:9000",        // RFC1918
        "172.16.0.1:9000",         // RFC1918
        "169.254.169.254:80",      // cloud metadata (link-local)
        "100.64.0.1:9000",         // CGNAT
        "0.0.0.0:9000",            // unspecified
        "[::1]:9000",              // IPv6 loopback
        "[fe80::1]:9000",          // IPv6 link-local
        "[fc00::1]:9000",          // IPv6 unique-local
        "[::ffff:127.0.0.1]:9000", // IPv4-mapped loopback
    ] {
        assert!(!addr_is_dialable(addr, false), "{addr} must not be dialable on a public relay");
    }

    // A real public address still is — the filter must not simply refuse everything.
    assert!(addr_is_dialable("8.8.8.8:9000", true), "the local-testing escape hatch works");
    assert!(addr_is_dialable("8.8.8.8:9000", false), "a globally routable address stays dialable");
    // Local testing keeps working with the escape hatch on (that is how these tests run).
    assert!(addr_is_dialable("127.0.0.1:9000", true), "loopback allowed only in local testing");
}
