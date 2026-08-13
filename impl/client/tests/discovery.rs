//! §12 4c — opt-in discovery over the REAL socket. A client turns discovery on (publishing a
//! record under a random contact code), another resolves that code to the address, and the
//! lifecycle (rotate / off) behaves. Confirms the `PublishDiscovery`/`LookupDiscovery`/
//! `DeleteDiscovery` wire path end to end.

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use client::store::Store;
use client::{Relay, RelayId};
use relay::node::RelayNode;
use node::seal::Identity;
use relay::server::{generate_noise_keypair, RelayServer};

const NOW: u64 = 1_000_000;

fn temp_dir(tag: &str) -> PathBuf {
    // One root, swept by later runs — see `node::scratch` for why the harness gives us no
    // teardown hook and what that bounds (#321).
    node::scratch::dir_for_test(tag)
}

/// A store with a fresh account (seed), unlocked at-rest.
fn seeded_store(tag: &str) -> Store {
    let store = Store::unlock(temp_dir(tag), b"pw").unwrap();
    let m = client::seed::generate_mnemonic();
    store.save_seed(&client::seed::entropy_of(&m)).unwrap();
    store
}

/// Spawn a real relay on loopback. Returns (addr, noise_pub, fetch_pub).
fn spawn() -> (String, [u8; 32], [u8; 32]) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (npriv, npub) = generate_noise_keypair();
    let fetch = Identity::generate();
    let fpub = fetch.public.to_bytes();
    let relay = RelayNode::with_identity(NOW, fetch);
    let server = RelayServer::with_noise_keypair(relay, Arc::new(move || NOW), npriv, npub);
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });
    (addr, npub, fpub)
}

#[test]
fn publish_then_find_resolves_the_code_to_the_address() {
    let (addr, np, fp) = spawn();
    let r = Relay::new(addr.parse::<std::net::SocketAddr>().unwrap(), RelayId { noise_pub: np, fetch_pub: fp }, None);
    let store = seeded_store("find");
    let my_ik = store.load_account().unwrap().identity_public();

    // Turn discovery on: publish a record, get a shareable contact code.
    let code = client::discovery_publish(&store, &r, NOW).unwrap();
    assert!(code.starts_with("KARST-"));

    // Someone with the code resolves it to our IK + reachable relay address.
    let (found_ik, loc) = client::find_contact(&r, &code, NOW).expect("the code resolves");
    assert_eq!(found_ik, my_ik, "the code resolves to our identity");
    assert!(loc.addrs.contains(&addr), "and to the relay we published at");

    // A well-formed but unknown code resolves to nothing.
    let other = node::discovery::encode_code(&node::discovery::public_of(&[42u8; 32]));
    assert!(client::find_contact(&r, &other, NOW).is_err(), "an unpublished code finds no one");
    // Garbage is rejected before any network call.
    assert!(client::find_contact(&r, "not-a-code", NOW).is_err());
}

#[test]
fn rotate_retires_the_old_code_and_off_stops_resolving() {
    let (addr, np, fp) = spawn();
    let r = Relay::new(addr.parse::<std::net::SocketAddr>().unwrap(), RelayId { noise_pub: np, fetch_pub: fp }, None);
    let store = seeded_store("rotate");

    let code1 = client::discovery_publish(&store, &r, NOW).unwrap();
    assert!(client::find_contact(&r, &code1, NOW).is_ok());

    // Rotate → a new code; the old one no longer resolves, the new one does, same identity.
    let code2 = client::discovery_rotate(&store, &r, NOW).unwrap();
    assert_ne!(code1, code2, "rotation mints a different code");
    assert!(client::find_contact(&r, &code1, NOW).is_err(), "the retired code stops resolving");
    let (ik2, _) = client::find_contact(&r, &code2, NOW).expect("the new code resolves");
    assert_eq!(ik2, store.load_account().unwrap().identity_public(), "identity is unchanged by rotation");

    // Off → the current code stops resolving and the local key is gone.
    client::discovery_off(&store, &r).unwrap();
    assert!(client::find_contact(&r, &code2, NOW).is_err(), "turning discovery off unpublishes the code");
    assert!(client::discovery_code(&store).unwrap().is_none(), "and clears the local key");
}

/// CRYPTO-21 — a validly signed but EXPIRED record must be refused by the CLIENT.
///
/// `expiry` rides inside the signed IK binding, so an honest relay drops stale records — but the
/// relay is explicitly not a trusted anchor, and a hostile or compromised one can keep serving an
/// old, still-perfectly-signed record forever. Until this check existed, expiry had no
/// client-side force at all: a retired location, a spent one-time invite, and revocation-by-expiry
/// were all unenforceable, so a first message could be routed to a relay the owner abandoned long
/// ago. Here the relay's clock is pinned at NOW (it will happily keep serving), and only the
/// CLIENT's clock advances — exactly the replay scenario.
#[test]
fn an_expired_record_is_refused_even_when_the_relay_still_serves_it() {
    let (addr, np, fp) = spawn();
    let r = Relay::new(addr.parse::<std::net::SocketAddr>().unwrap(), RelayId { noise_pub: np, fetch_pub: fp }, None);
    let store = seeded_store("expired");

    let code = client::discovery_publish(&store, &r, NOW).unwrap();
    assert!(client::find_contact(&r, &code, NOW).is_ok(), "control: it resolves while fresh");

    // Just inside the record's life, allowing for the skew tolerance: still fine.
    let almost = NOW + node::discovery::DEFAULT_TTL_SECS - 1;
    assert!(
        client::find_contact(&r, &code, almost).is_ok(),
        "a record must stay usable right up to its expiry"
    );

    // Past expiry (and past the skew allowance) the client must refuse it, even though this relay
    // — whose clock never advanced — is still handing the record out.
    let after = NOW + node::discovery::DEFAULT_TTL_SECS + client::DISCOVERY_CLOCK_SKEW_SECS + 1;
    let err = client::find_contact(&r, &code, after).expect_err("an expired record must be refused");
    assert!(err.contains("expired"), "the refusal should say why, got: {err}");
}
