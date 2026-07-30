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
use node::protocol::{NodeDescriptor, RelayPolicy, SignedDescriptor};
use node::seal::Identity;
use relay::server::{generate_noise_keypair, RelayServer};

const NOW: u64 = 1_000_000;

/// A descriptor SIGNED by a key nobody else holds — what a hostile peer can always produce.
///
/// Worth being explicit, because it is the reason the dial survives this slice: signing is free
/// and unprivileged. Anyone can generate a keypair and sign "I am at 198.51.100.9". The signature
/// proves who said it, never that the address is theirs or that they are still there.
fn policy() -> RelayPolicy {
    RelayPolicy {
        blob_persistence: None,
        blob_ttl_secs: 0,
        max_blob_size: 0,
        pow_bits: None,
        mailbox_durability: node::protocol::MailboxDurability::Volatile,
    }
}

/// Sign `d` with `secret` — which must be the key behind `d.noise_pub`, or the result verifies
/// nowhere.
fn signed_with(secret: &[u8; 32], d: RelayDescriptor) -> SignedDescriptor {
    NodeDescriptor::signed(d, policy(), NOW, secret)
}

fn signed_by_a_stranger(addr: &str) -> SignedDescriptor {
    let (secret, public) = generate_noise_keypair();
    let relay = RelayDescriptor {
        noise_pub: public,
        fetch_pub: [0x99; 32],
        addrs: vec![addr.into()],
        quic_addrs: Vec::new(),
    };
    NodeDescriptor::signed(
        relay,
        RelayPolicy {
            blob_persistence: None,
            blob_ttl_secs: 0,
            max_blob_size: 0,
            pow_bits: None,
            mailbox_durability: node::protocol::MailboxDurability::Volatile,
        },
        NOW,
        &secret,
    )
}

/// Spawn a real relay on an ephemeral port with a KNOWN noise key, holding `others` as verified
/// signed entries (and, if `advertise_self`, signing its own). Returns the address, the relay-id
/// halves, and the signed self-descriptor a peer would learn — so one relay can be seeded with
/// another's real, verifiable statement rather than a fabricated one.
fn spawn(
    others: Vec<SignedDescriptor>,
    advertise_self: bool,
) -> (String, [u8; 32], [u8; 32], Option<SignedDescriptor>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (npriv, npub) = generate_noise_keypair();
    let fetch = Identity::generate();
    let fetch_pub = fetch.public.to_bytes();
    let mut relay = RelayNode::with_identity(NOW, fetch);
    if advertise_self {
        // Self is advertised by SIGNING a statement about itself, not by putting a copy in the
        // known-relay list: `known_relays` is what OTHER relays signed.
        relay.set_self_descriptor(RelayDescriptor {
            noise_pub: npub,
            fetch_pub,
            addrs: vec![addr.clone()],
            quic_addrs: Vec::new(),
        });
        relay.refresh_signed_descriptor(NOW, &npriv);
    }
    let signed_self = relay.signed_descriptor(NOW);
    for d in others {
        assert!(relay.add_relay(d, NOW), "the fixture must seed only verifiable entries");
    }
    let server = RelayServer::with_noise_keypair(relay, Arc::new(move || NOW), npriv, npub);
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });
    (addr, npub, fetch_pub, signed_self)
}

fn desc(noise: [u8; 32], fetch: [u8; 32], addr: &str) -> RelayDescriptor {
    RelayDescriptor { noise_pub: noise, fetch_pub: fetch, addrs: vec![addr.into()], quic_addrs: Vec::new() }
}

#[test]
fn verify_accepts_real_relay_and_rejects_impostors() {
    let (addr, npub, fpub, _) = spawn(vec![], true);

    assert!(relay::gossip::verify(&desc(npub, fpub, &addr), &addr, true, NOW), "a real self-advertising relay verifies");
    // Wrong noise key: the Noise handshake fails → the reflection defense.
    assert!(!relay::gossip::verify(&desc([0xAB; 32], fpub, &addr), &addr, true, NOW), "wrong noise key must fail");
    // Right noise, WRONG fetch: the relay's self-advertisement doesn't match → refused.
    assert!(!relay::gossip::verify(&desc(npub, [0xCD; 32], &addr), &addr, true, NOW), "wrong fetch key must fail");
    // Dead address: unreachable → refused (connection refused, fast).
    assert!(!relay::gossip::verify(&desc(npub, fpub, "127.0.0.1:1"), "127.0.0.1:1", true, NOW), "dead addr must fail");

    // A relay that does NOT advertise itself can't be verified (no self-entry to match).
    let (a2, n2, f2, _) = spawn(vec![], false);
    assert!(!relay::gossip::verify(&desc(n2, f2, &a2), &a2, true, NOW), "a non-self-advertising relay can't be confirmed");
}

#[test]
fn gossip_round_learns_a_verified_relay_from_a_peer() {
    // C: a real self-advertising relay.
    let (c_addr, c_np, c_fp, c_signed) = spawn(vec![], true);
    let c = desc(c_np, c_fp, &c_addr);
    // A: a real relay holding C's own signed statement, and advertising itself.
    let (a_addr, a_np, a_fp, _) = spawn(vec![c_signed.expect("C signs itself")], true);
    let a = desc(a_np, a_fp, &a_addr);
    // B: local relay with A as a configured HINT — the only thing a fresh relay ever has.
    let (_bpriv, bpub) = generate_noise_keypair();
    let mut b = RelayNode::with_identity(NOW, Identity::generate());
    b.add_relay_hint(a.clone());
    let b = Arc::new(RwLock::new(b));

    let added = relay::gossip::gossip_round(&b, &bpub, true, NOW);
    assert!(added >= 1, "B should learn a new relay (C) from peer A");
    let ids: Vec<String> =
        b.write().unwrap().known_relays().iter().map(|d| d.desc.relay.relay_id_hex()).collect();
    assert!(ids.contains(&c.relay_id_hex()), "B must now know C, verified via a direct dial");
}

#[test]
fn gossip_round_rejects_a_poisoned_descriptor() {
    // A relay A carries a POISON entry: a correctly SIGNED descriptor pointing at a dead address
    // (a stand-in for a victim IP). This is the shape the attack keeps after signing — anyone can
    // sign a claim about an address they do not own — so the signature does not refuse it and the
    // dial has to. B must never re-serve an address it could not confirm.
    let poison = signed_by_a_stranger("127.0.0.1:2");
    let poison_id = poison.desc.relay.relay_id_hex();
    let (a_addr, a_np, a_fp, _) = spawn(vec![poison], true);
    let a = desc(a_np, a_fp, &a_addr);
    let (_bpriv, bpub) = generate_noise_keypair();
    let mut b = RelayNode::with_identity(NOW, Identity::generate());
    b.add_relay_hint(a);
    let b = Arc::new(RwLock::new(b));

    relay::gossip::gossip_round(&b, &bpub, true, NOW);
    let ids: Vec<String> =
        b.write().unwrap().known_relays().iter().map(|d| d.desc.relay.relay_id_hex()).collect();
    assert!(
        !ids.contains(&poison_id),
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
    use karst_transport::transport::addr_is_dialable;

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
fn advertisement_rotates_so_no_relay_is_stranded_in_the_tail() {
    // A signed descriptor is roughly twice the size of the bare one it replaced, so a full table
    // no longer fits in one page and the served list is genuinely a rotating WINDOW. That makes
    // the rotation load-bearing rather than a nicety: without it the relays past the cut could
    // never leave this node.
    //
    // DISCRIMINATING: pin the cursor at 0 and the set of observed starting entries collapses to
    // one, which is the permanent centrality bias this rotation exists to remove.
    let mut relay = RelayNode::new(NOW);
    let mut ids = Vec::new();
    for i in 0..6 {
        let (secret, public) = generate_noise_keypair();
        let d = RelayDescriptor {
            noise_pub: public,
            fetch_pub: [3; 32],
            addrs: vec![format!("198.51.100.{}:9000", i + 1)],
            quic_addrs: Vec::new(),
        };
        ids.push(public);
        assert!(relay.add_relay(signed_with(&secret, d), NOW));
    }

    let mut seen_starts = std::collections::HashSet::new();
    for _ in 0..6 {
        let page = relay.node_list(NOW);
        assert!(!page.is_empty(), "a page must never be empty");
        seen_starts.insert(page[0].desc.relay.noise_pub);
    }
    assert!(
        seen_starts.len() > 1,
        "the advertised window never rotated — the tail can never propagate"
    );
}

/// A relay that MOVED is reachable at its new address on the next round: the newer signed
/// statement replaces the older one whole, rather than the new address queuing behind stale ones.
#[test]
fn a_relay_that_moved_is_reachable_at_its_new_address() {
    let (secret, public) = generate_noise_keypair();
    let mut relay = RelayNode::new(NOW);
    let at = |addr: &str| RelayDescriptor {
        noise_pub: public,
        fetch_pub: [4; 32],
        addrs: vec![addr.to_string()],
        quic_addrs: Vec::new(),
    };
    for i in 0..8 {
        relay.add_relay(
            NodeDescriptor::signed(
                at(&format!("198.51.100.1{i}:9000")),
                policy(),
                NOW + i,
                &secret,
            ),
            NOW,
        );
    }
    relay.add_relay(
        NodeDescriptor::signed(at("203.0.113.77:9000"), policy(), NOW + 100, &secret),
        NOW,
    );

    let moved = &relay.known_relays()[0].desc.relay;
    assert_eq!(
        moved.addrs,
        vec!["203.0.113.77:9000".to_string()],
        "the newest statement is the whole answer — an old address must not linger"
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
    let (b_addr, b_np, b_fp, _) = spawn(vec![], true);
    // A transparent proxy in front of B — a different address that reaches the same relay.
    let proxy_addr = spawn_tcp_proxy(&b_addr);
    assert_ne!(proxy_addr, b_addr);

    // The substitution A used to perform — B's relay-id at the PROXY's address — is no longer
    // expressible: A would have to sign as B. What A can still do is carry B's genuine statement
    // alongside its own signed claim pointing at the proxy, so both are offered to C.
    let (_b_addr2, _, _, b_signed) = (b_addr.clone(), 0u8, 0u8, {
        let t = karst_transport::socket::SocketTransport::new(
            karst_transport::transport::Dest::parse(&b_addr).unwrap(),
            b_np,
        );
        t.get_descriptor().expect("B serves its descriptor").expect("B advertises itself")
    });
    let proxy_claim = signed_by_a_stranger(&proxy_addr);
    let proxy_id = proxy_claim.desc.relay.relay_id_hex();
    let (a_addr, a_np, a_fp, _) = spawn(vec![b_signed, proxy_claim], true);

    let c = Arc::new(RwLock::new(RelayNode::with_identity(NOW, Identity::generate())));
    let (c_np, _c_pub) = generate_noise_keypair();
    c.write().unwrap().add_relay_hint(desc(a_np, a_fp, &a_addr));

    relay::gossip::gossip_round(&c, &c_np, true, NOW);

    let stored = c.write().unwrap().known_relays();
    let b_entry = stored
        .iter()
        .find(|d| d.desc.relay.noise_pub == b_np && d.desc.relay.fetch_pub == b_fp)
        .expect("B is now known to C");
    assert!(
        b_entry.desc.relay.addrs.contains(&b_addr),
        "C must route to B's OWN address, got {:?}",
        b_entry.desc.relay.addrs
    );
    assert!(
        !b_entry.desc.relay.addrs.contains(&proxy_addr),
        "the proxy address must never become a route to B"
    );
    // And the stranger's claim at the proxy is refused outright: something answers there, and the
    // Noise handshake even succeeds (the proxy splices to B) — but B does not serve the stranger's
    // relay-id, so the endpoint vouches for nobody.
    assert!(
        !stored.iter().any(|d| d.desc.relay.relay_id_hex() == proxy_id),
        "an endpoint that does not serve the claimed relay-id must not be stored"
    );
}

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
