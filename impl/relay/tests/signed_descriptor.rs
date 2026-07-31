//! **What a relay serves about itself, over a real socket** (NODE-1).
//!
//! `node/tests/descriptor.rs` pins the statement's properties in isolation. This one pins the
//! serving side, where three things can go wrong that no amount of correct signing would catch:
//! the descriptor and `GetPolicy` drifting into two different answers, a public read costing a
//! signature every time it is asked, and — the one that matters most — nothing re-signing, so a
//! perfectly healthy relay silently disappears from every node list the moment its window closes.

use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;

use karst_transport::socket::SocketTransport;
use node::protocol::{RelayDescriptor, DESCRIPTOR_REFRESH_SECS, DESCRIPTOR_TTL_SECS};
use relay::node::RelayNode;
use relay::server::{generate_noise_keypair, RelayServer};

const NOW: u64 = 1_800_000_000;

/// A relay on a real socket with a clock the test can move, and a handle on its state.
fn spawn(
    advertise: bool,
) -> (SocketTransport, Arc<AtomicU64>, Arc<RwLock<RelayNode>>, [u8; 32]) {
    let (noise_priv, noise_pub) = generate_noise_keypair();
    let mut node = RelayNode::new(NOW);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("bound");
    if advertise {
        node.set_self_descriptor(RelayDescriptor {
            noise_pub,
            fetch_pub: [5u8; 32],
            addrs: vec![addr.to_string()],
            quic_addrs: Vec::new(),
        });
    }
    let shared = Arc::new(RwLock::new(node));
    let clock = Arc::new(AtomicU64::new(NOW));
    let c = Arc::clone(&clock);
    let server = RelayServer::from_shared(
        Arc::clone(&shared),
        Arc::new(move || c.load(Ordering::Relaxed)),
        noise_priv,
        noise_pub,
    );
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });
    let t = SocketTransport::new(addr, noise_pub);
    (t, clock, shared, noise_pub)
}

#[test]
fn the_served_descriptor_verifies_against_the_relay_it_came_from() {
    let (t, _clock, _shared, noise_pub) = spawn(true);
    let signed = t.get_descriptor().expect("fetch").expect("this relay advertises");
    let d = signed.verified(NOW).expect("the relay's own signature verifies");
    assert_eq!(d.relay.noise_pub, noise_pub);
    assert_eq!(d.expires_at, NOW + DESCRIPTOR_TTL_SECS);
}

/// **A relay that advertises no routable address signs nothing.**
///
/// Not an error case — it is the honest answer. Such a relay is undiscoverable by its own choice,
/// and a signed statement about how to reach something unreachable would be advertising nothing,
/// loudly, with a signature on it.
#[test]
fn a_relay_with_no_address_has_nothing_to_say_about_itself() {
    let (t, _clock, _shared, _pub) = spawn(false);
    assert!(t.get_descriptor().expect("fetch").is_none());
}

/// **The descriptor and `GetPolicy` cannot disagree.**
///
/// DISCRIMINATING against the failure this task exists to avoid rather than create: the same facts
/// advertised from two places eventually answer differently, and a client that asked one way gets a
/// posture the other way would have denied. `RelayDescriptor`'s own doc rejects a
/// `supported_transports` field on exactly these grounds. Both answers here are built from
/// `RelayNode::policy()`, and this fails the moment one of them keeps its own copy.
#[test]
fn the_descriptor_and_get_policy_are_one_source() {
    let (t, clock, shared, _pub) = spawn(true);
    let before = t.get_descriptor().expect("fetch").expect("advertises");
    assert_eq!(before.desc.policy, t.get_policy().expect("policy"));

    // Change the configuration under the running relay, then move past the refresh cadence.
    shared.write().expect("lock").enable_pow_issue(20);
    clock.store(NOW + DESCRIPTOR_REFRESH_SECS + 1, Ordering::Relaxed);

    let after = t.get_descriptor().expect("fetch").expect("advertises");
    assert_eq!(
        after.desc.policy,
        t.get_policy().expect("policy"),
        "the signed policy and the live one diverged after a configuration change"
    );
    assert_eq!(after.desc.policy.pow_bits, Some(20), "the change never reached the descriptor");
    assert_ne!(before.desc.policy, after.desc.policy, "the fixture changed nothing — test is vacuous");
}

/// **A public read does not buy a signature per request.**
///
/// `GetDescriptor` is unauthenticated: anyone can ask, as often as they like. Signing on demand
/// would sell a scalar multiplication for the price of one cheap request, in the one place this
/// relay does work for strangers. Within the refresh window every asker gets the same cached bytes.
#[test]
fn asking_twice_does_not_make_the_relay_sign_twice() {
    let (t, clock, _shared, _pub) = spawn(true);
    let a = t.get_descriptor().expect("fetch").expect("advertises");
    clock.store(NOW + DESCRIPTOR_REFRESH_SECS - 10, Ordering::Relaxed);
    let b = t.get_descriptor().expect("fetch").expect("advertises");
    assert_eq!(a.sig, b.sig, "the relay re-signed inside its own refresh window");
}

/// **A relay is in its OWN node list, from the first request onwards.**
///
/// `node_list` puts self first, but only from the cached signature — and the cache was filled by
/// exactly one thing: somebody asking `GetDescriptor`. Nothing else signed, at boot or ever. So a
/// freshly started relay with a perfectly good advertised address served a node list WITHOUT ITSELF
/// to every peer that asked, until an unrelated request happened to warm the cache for it.
///
/// That is the whole of §12 discovery failing quietly: gossip converges on peers' node lists, so a
/// relay missing from its own list is a relay the network never learns about — while it sits there
/// answering requests and printing a routable address at startup.
///
/// The order here is the point: `get_node_list` FIRST, with no `get_descriptor` before it.
#[test]
fn a_relay_serves_itself_in_its_node_list_without_being_asked_for_its_descriptor_first() {
    let (t, _clock, _shared, noise_pub) = spawn(true);

    let list = t.get_node_list().expect("fetch node list");
    assert!(
        list.iter().any(|s| s.desc.relay.noise_pub == noise_pub),
        "the relay left ITSELF out of the node list it serves — nothing signed its own statement \
         until some other request happened to, so discovery never learns this relay exists"
    );

    // Not vacuously true through an unverifiable entry: what it serves about itself must verify.
    let mine = list.iter().find(|s| s.desc.relay.noise_pub == noise_pub).expect("self entry");
    assert!(mine.verified(NOW).is_some(), "the self entry does not verify against the relay serving it");
}

/// **…and it is still there an hour later.**
///
/// The gap this covers is not only the cold start. `signed_descriptor` stops handing out a copy at
/// `DESCRIPTOR_REFRESH_SECS`, which is a sixth of the TTL — so even a relay whose cache HAD been
/// warmed dropped out of its own node list once per hour and stayed out until the next
/// `GetDescriptor`. A per-hour disappearance from discovery is harder to notice than never
/// appearing at all, which is why it is asserted separately.
#[test]
fn the_relay_does_not_fall_out_of_its_own_node_list_once_an_hour() {
    let (t, clock, _shared, noise_pub) = spawn(true);
    let first = t.get_node_list().expect("fetch");
    let before =
        first.iter().find(|s| s.desc.relay.noise_pub == noise_pub).expect("self entry").sig.clone();

    // Past the refresh cadence — the cached signature is no longer servable.
    let later = NOW + DESCRIPTOR_REFRESH_SECS + 1;
    clock.store(later, Ordering::Relaxed);

    let second = t.get_node_list().expect("fetch");
    let mine = second.iter().find(|s| s.desc.relay.noise_pub == noise_pub).expect(
        "the relay vanished from its own node list at the refresh boundary — every hour, a healthy \
         relay stops being discoverable until something asks it for its descriptor",
    );
    assert_ne!(mine.sig, before, "same signature past the refresh window — the fixture did not age");
    assert!(mine.verified(later).is_some(), "the renewed self entry does not verify");
}

/// **The relay re-signs before its descriptor lapses.**
///
/// DISCRIMINATING for the failure an expiry introduces if nothing renews it: a running, reachable,
/// perfectly healthy relay stops being served by anyone at the TTL boundary, and the symptom is
/// "the network forgot a relay that never went anywhere". The refresh cadence is what keeps the
/// window open, so this asserts a NEW signature with a later expiry — not merely that a descriptor
/// still comes back.
#[test]
fn a_running_relay_does_not_lapse_out_of_existence() {
    let (t, clock, _shared, _pub) = spawn(true);
    let first = t.get_descriptor().expect("fetch").expect("advertises");

    // Past the refresh cadence, but still well inside the old descriptor's validity: the relay must
    // renew EARLY, not at the last moment.
    let later = NOW + DESCRIPTOR_REFRESH_SECS + 1;
    clock.store(later, Ordering::Relaxed);
    let second = t.get_descriptor().expect("fetch").expect("advertises");

    assert_ne!(first.sig, second.sig, "the relay never re-signed");
    let d = second.verified(later).expect("the renewed descriptor verifies");
    assert!(
        d.expires_at > first.desc.expires_at,
        "the renewal carried the OLD expiry forward — the window still closes on schedule, and the \
         relay disappears from every node list while sitting there answering requests"
    );

    // And the renewal is still good long after the original would have lapsed.
    let past_old_expiry = first.desc.expires_at + 60;
    assert!(second.verified(past_old_expiry).is_some());
}
