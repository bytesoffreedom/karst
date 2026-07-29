//! §12 node-list GOSSIP MERGE — verify-before-add, against real relays on loopback.
//!
//! Pins the security property this slice exists for: a descriptor heard from a peer is added
//! ONLY after we dial it and confirm a real relay with the claimed relay-id answers. A poisoned
//! entry (wrong key / victim address) is refused, so gossip can never turn relays into a
//! reflector aimed at a victim. Neuter `verify` (return true) and the poison test reddens.

use std::net::TcpListener;
use std::sync::{Arc, RwLock};
use std::thread;

use relay::node::{RelayDescriptor, RelayNode};
use node::seal::Identity;
use relay::server::{generate_noise_keypair, RelayServer};

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
        relay.add_relay(RelayDescriptor { noise_pub: npub, fetch_pub, addrs: vec![addr.clone()], quic_addrs: Vec::new() });
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
    RelayDescriptor { noise_pub: noise, fetch_pub: fetch, addrs: vec![addr.into()], quic_addrs: Vec::new() }
}

#[test]
fn verify_accepts_real_relay_and_rejects_impostors() {
    let (addr, npub, fpub) = spawn(vec![], true);

    assert!(relay::gossip::verify(&desc(npub, fpub, &addr), &addr, true), "a real self-advertising relay verifies");
    // Wrong noise key: the Noise handshake fails → the reflection defense.
    assert!(!relay::gossip::verify(&desc([0xAB; 32], fpub, &addr), &addr, true), "wrong noise key must fail");
    // Right noise, WRONG fetch: the relay's self-advertisement doesn't match → refused.
    assert!(!relay::gossip::verify(&desc(npub, [0xCD; 32], &addr), &addr, true), "wrong fetch key must fail");
    // Dead address: unreachable → refused (connection refused, fast).
    assert!(!relay::gossip::verify(&desc(npub, fpub, "127.0.0.1:1"), "127.0.0.1:1", true), "dead addr must fail");

    // A relay that does NOT advertise itself can't be verified (no self-entry to match).
    let (a2, n2, f2) = spawn(vec![], false);
    assert!(!relay::gossip::verify(&desc(n2, f2, &a2), &a2, true), "a non-self-advertising relay can't be confirmed");
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
    let b = Arc::new(RwLock::new(b));

    let added = relay::gossip::gossip_round(&b, &bpub, true);
    assert!(added >= 1, "B should learn a new relay (C) from peer A");
    let ids: Vec<String> = b.write().unwrap().known_relays().iter().map(|d| d.relay_id_hex()).collect();
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
    let b = Arc::new(RwLock::new(b));

    relay::gossip::gossip_round(&b, &bpub, true);
    let ids: Vec<String> = b.write().unwrap().known_relays().iter().map(|d| d.relay_id_hex()).collect();
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
    use node::transport::addr_is_dialable;

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

/// A3-13 — advertisement must be FAIR, and a changed address must be able to replace a stale one.
///
/// The node list used to be built from index 0 and to STOP at the first descriptor that did not
/// fit the frame, so the relays learned first propagated on every round while the tail could
/// never leave the node. Addresses were likewise append-only up to the cap, so four stale entries
/// permanently shut out a relay's new, working address.
#[test]
fn advertisement_rotates_and_a_new_address_replaces_the_oldest() {
    use relay::node::{RelayDescriptor, RelayNode};

    let mut relay = RelayNode::new(1_000_000);
    let desc = |n: u8, addr: &str| RelayDescriptor {
        noise_pub: [n; 32],
        fetch_pub: [n; 32],
        addrs: vec![addr.to_string()],
        quic_addrs: Vec::new(),
    };
    for n in 1..=6u8 {
        relay.add_relay(desc(n, &format!("198.51.100.{n}:9000")));
    }

    // Across successive pages the STARTING entry must move — otherwise the tail never propagates.
    let first: Vec<_> = relay.node_list().into_iter().map(|d| d.noise_pub[0]).collect();
    let mut seen_starts = std::collections::HashSet::new();
    for _ in 0..6 {
        let page: Vec<_> = relay.node_list().into_iter().map(|d| d.noise_pub[0]).collect();
        assert!(!page.is_empty(), "a page must never be empty");
        // index 0 is always self/seed; the rotation shows up right after it
        if page.len() > 1 {
            seen_starts.insert(page[1]);
        }
    }
    assert!(
        seen_starts.len() > 1,
        "the advertised window never rotated — the tail can never propagate (got {seen_starts:?}, first page {first:?})"
    );

    // A relay that moved: fill its address slots, then offer a NEW one.
    let id = desc(1, "x").relay_id_hex();
    for i in 0..8 {
        relay.add_relay(desc(1, &format!("198.51.100.1{i}:9000")));
    }
    relay.add_relay(desc(1, "203.0.113.77:9000"));
    let moved = relay
        .known_relays()
        .into_iter()
        .find(|d| d.relay_id_hex() == id)
        .expect("the relay is still known");
    assert!(
        moved.addrs.contains(&"203.0.113.77:9000".to_string()),
        "a newly verified address must displace an old one, not be dropped: {:?}",
        moved.addrs
    );
}

/// CRYPTO-23 (node side, #232): a peer's ADDRESS for a relay is only a place to dial — what gets
/// stored is what the relay says about itself.
///
/// Everything `verify` checks is also true through a transparent proxy in front of an honest
/// relay: the TCP lands on the proxy, Noise terminates at the real relay behind it, and the relay
/// serves its own relay-id correctly. So a peer could advertise `proxy → honest relay-id`, we
/// would verify it, and then store THE PROXY as the route — a permanent view of client IPs,
/// timing and volume for whoever runs it, plus a selective-drop switch, with the encryption
/// perfectly intact.
///
/// Here relay A advertises B at a proxy address that really does reach B. C gossips with A and
/// must end up holding B's OWN address. Store the offered descriptor instead and it reddens.
#[test]
fn gossip_stores_the_relays_own_address_not_a_peers_proxy() {
    // B: a real relay that advertises its own address.
    let (b_addr, b_np, b_fp) = spawn(vec![], true);
    // A transparent proxy in front of B — a different address that reaches the same relay.
    let proxy_addr = spawn_tcp_proxy(&b_addr);
    assert_ne!(proxy_addr, b_addr);

    // A knows B only through the proxy address, and tells C so.
    let (a_addr, a_np, a_fp) = spawn(vec![desc(b_np, b_fp, &proxy_addr)], true);

    let c = Arc::new(RwLock::new(RelayNode::with_identity(NOW, Identity::generate())));
    let (c_np, _c_pub) = generate_noise_keypair();
    c.write().unwrap().add_relay(desc(a_np, a_fp, &a_addr));

    let added = relay::gossip::gossip_round(&c, &c_np, true);
    assert_eq!(added, 1, "C should learn B from A");

    let stored = c.write().unwrap().known_relays();
    let b_entry = stored
        .iter()
        .find(|d| d.noise_pub == b_np && d.fetch_pub == b_fp)
        .expect("B is now known to C");
    assert!(
        b_entry.addrs.contains(&b_addr),
        "C must route to B's OWN address, got {:?}",
        b_entry.addrs
    );
    assert!(
        !b_entry.addrs.contains(&proxy_addr),
        "the proxy address A offered must not be stored as a route to B"
    );
}

/// A transparent TCP proxy: everything that arrives goes upstream and back, untouched. Enough to
/// stand in for an on-path relay operator's front end — the Noise session is end-to-end, so it
/// completes perfectly through this.
fn spawn_tcp_proxy(upstream: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let upstream = upstream.to_string();
    thread::spawn(move || {
        for inbound in listener.incoming() {
            let Ok(inbound) = inbound else { continue };
            let Ok(out) = std::net::TcpStream::connect(&upstream) else { continue };
            let (Ok(in2), Ok(out2)) = (inbound.try_clone(), out.try_clone()) else { continue };
            thread::spawn(move || {
                let mut a = inbound;
                let mut b = out;
                let _ = std::io::copy(&mut a, &mut b);
            });
            thread::spawn(move || {
                let mut a = out2;
                let mut b = in2;
                let _ = std::io::copy(&mut a, &mut b);
            });
        }
    });
    addr
}
