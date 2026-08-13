//! QUIC through the REAL path, with nothing handed to the client (QUIC-14).
//!
//! Every earlier QUIC test built its path with `set_paths_for_test`, which proves the carrier
//! works and skips the wiring that decides whether anyone ever reaches it. That wiring is exactly
//! what was missing through every earlier QUIC slice: the listener was never started, the endpoint
//! was never advertised, and the client had no branch that could build a QUIC path. So this test
//! refuses the shortcut —
//! it starts a relay, lets that relay declare its own endpoint, and makes the client discover it
//! the way a real client does.
//!
//! It is the criterion for "QUIC works". Before it went green, saying so was a claim about an
//! adapter rather than about the product.

use std::net::TcpListener;
use std::sync::{Arc, RwLock};
use std::thread;

use relay::node::RelayNode;
use relay::quic_server::QuicServer;
use relay::server::RelayServer;

const NOW: u64 = 1_000_000;

/// A relay with BOTH listeners over one node, advertising the UDP endpoint it actually bound —
/// the arrangement `karst-relay` sets up for itself (QUIC-10 + QUIC-11).
fn spawn_relay_with_quic() -> (std::net::SocketAddr, client::RelayId) {
    let (noise_priv, noise_pub) = relay::server::generate_noise_keypair();
    let mut node = RelayNode::new(NOW);
    node.issue_capability(client::dev_capability());
    let fetch_pub = node.relay_public().to_bytes();

    let tcp = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
    let tcp_addr = tcp.local_addr().expect("bound");

    let shared = Arc::new(RwLock::new(node));
    let quic = QuicServer::bind(
        "127.0.0.1:0".parse().expect("valid"),
        shared.clone(),
        Arc::new(move || NOW),
        noise_priv,
    )
    .expect("bind quic");
    let quic_addr = quic.local_addr().expect("bound");

    // What the binary does once the UDP bind succeeds, and only then: record the endpoint on its
    // own descriptor so a client asking for the node list can read it back.
    {
        let desc = node::protocol::RelayDescriptor {
            noise_pub,
            fetch_pub,
            addrs: vec![tcp_addr.to_string()],
            quic_addrs: vec![quic_addr.to_string()],
        };
        let mut n = shared.write().expect("relay lock");
        // Self advertises by signing a statement about itself; `known_relays` is what OTHERS
        // signed, so a copy of our own descriptor has no business in it.
        n.set_self_descriptor(desc);
        n.refresh_signed_descriptor(NOW, &noise_priv);
    }

    thread::spawn(move || {
        let _ = quic.serve();
    });
    // `RelayServer` needs the node by value, so the TCP side gets its own handle on the same state
    // by way of the shared lock the QUIC side already holds.
    let server = RelayServer::from_shared(shared, Arc::new(move || NOW), noise_priv, noise_pub);
    thread::spawn(move || {
        let _ = server.serve_listener(tcp);
    });

    (tcp_addr, client::RelayId { noise_pub, fetch_pub })
}

/// **The whole chain, with no shortcut anywhere.**
///
/// Relay advertises → client asks the relay itself → client builds the path → the race picks QUIC
/// → a message is delivered → the carrier indicator names what actually carried it.
#[test]
fn a_message_travels_over_quic_discovered_the_way_a_real_client_discovers_it() {
    let (addr, rid) = spawn_relay_with_quic();

    // Step 1: an ordinary client, configured exactly as a user configures one — an address and a
    // relay-id, nothing about QUIC.
    let plain = client::Relay::new(addr, rid, None);
    assert!(
        !plain.carriers().contains(&"quic"),
        "a client that has not asked yet must not invent a QUIC path"
    );

    // Step 2: ask the relay what IT says its endpoints are (never a third party — CRYPTO-23).
    let learned = client::quic_endpoints(&plain).expect("the relay served its node list");
    assert!(!learned.is_empty(), "the relay did not advertise the endpoint it bound");

    // Step 3: the path list is rebuilt with that endpoint in it.
    let r = client::Relay::new(addr, rid, None).with_quic(learned);
    assert!(r.carriers().contains(&"quic"), "the learned endpoint did not become a path");

    // Step 4: a real request over that relay, and the indicator must name QUIC as the carrier that
    // ran — not merely as one that was available. That distinction is the whole of A4-10: a badge
    // that can be wrong is worse than none.
    client::relay_policy(&r).expect("the relay answered over the raced path");
    assert_eq!(
        r.carrier().label(),
        "quic",
        "the request completed, but over some other carrier — the QUIC path lost its own race"
    );
}

/// **The desktop's actual path: relay → sidecar → next unlock → QUIC.**
///
/// The test above proves the chain a caller drives in one go. The desktop does not do that. It
/// refreshes endpoints into an encrypted sidecar on one run and rebuilds its relays from that
/// sidecar on the NEXT unlock, so the round trip through `quic_endpoints.dat` is a link the
/// in-memory test never touches — and it is precisely the link the sentence "the desktop is where
/// QUIC runs" rests on. An untested link under a published claim is how `Carrier::from_label` got
/// away with reporting `direct`: everything around it was green.
///
/// DISCRIMINATING: have `refresh_quic_endpoints` skip the write, or have the sidecar round-trip
/// an empty list, and this goes red while both tests above stay green.
#[test]
fn what_the_relay_said_survives_the_sidecar_and_still_builds_a_quic_path() {
    let (addr, rid) = spawn_relay_with_quic();
    let dir = node::scratch::dir_for_test("quic-sidecar"); // #321: under the swept root

    // Run #1 — what the desktop's background thread does after unlocking.
    let relays = vec![client::Relay::new(addr, rid, None)];
    {
        let store = client::store::Store::unlock(dir.clone(), b"pw").expect("vault");
        let changed = client::refresh_quic_endpoints(&store, &relays);
        assert_eq!(changed, 1, "the refresh learned nothing worth caching from a relay that advertises");
    }

    // Run #2 — a fresh unlock, exactly as `build_relays` reconstructs its relays: read the cache,
    // apply it by relay-id, and nothing else.
    let store = client::store::Store::unlock(dir, b"pw").expect("re-unlock");
    let cached: std::collections::HashMap<String, Vec<String>> =
        store.load_quic_endpoints().expect("sidecar readable").into_iter().collect();
    let eps = cached.get(&rid.hex()).expect("the sidecar kept nothing under this relay's id").clone();
    assert!(!eps.is_empty(), "the sidecar round-tripped an EMPTY list — a cache that silently forgets");

    let r = client::Relay::new(addr, rid, None).with_quic(eps);
    assert!(r.carriers().contains(&"quic"), "the cached endpoint did not become a path");
    client::relay_policy(&r).expect("the relay answered");
    assert_eq!(
        r.carrier().label(),
        "quic",
        "the desktop's own path completed over some other carrier — the claim that the desktop is \
         where QUIC runs would be false"
    );
}

/// **CONTROL ARM: the same relay through a proxy gets no QUIC path at all.**
///
/// Not "tries QUIC and falls back" — never builds it. Tor implements no SOCKS5 `UDP ASSOCIATE`,
/// and a pooled QUIC connection would re-cluster the handles circuit isolation keeps apart. If
/// this ever passes by falling back rather than by never trying, the privacy property is gone
/// while the tests still look green.
#[test]
fn the_same_relay_through_a_proxy_never_gets_a_quic_path() {
    let (addr, rid) = spawn_relay_with_quic();
    let learned =
        client::quic_endpoints(&client::Relay::new(addr, rid, None)).expect("node list served");
    assert!(!learned.is_empty(), "the relay must be advertising for this control arm to mean anything");

    let socks: std::net::SocketAddr = "127.0.0.1:9050".parse().unwrap();
    let proxied = client::Relay::new(addr, rid, Some(socks)).with_quic(learned);
    assert!(
        !proxied.carriers().contains(&"quic"),
        "a proxied relay was given a QUIC path — Tor carries no UDP, and pooling one would relink \
         the handles per-circuit isolation separates"
    );
}
