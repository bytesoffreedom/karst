//! §12 4c — opt-in discovery over the REAL socket. A client turns discovery on (publishing a
//! record under a random contact code), another resolves that code to the address, and the
//! lifecycle (rotate / off) behaves. Confirms the `PublishDiscovery`/`LookupDiscovery`/
//! `DeleteDiscovery` wire path end to end.

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use client::store::Store;
use client::{Relay, RelayId};
use node::node::RelayNode;
use node::seal::Identity;
use node::socket::{generate_noise_keypair, RelayServer};

const NOW: u64 = 1_000_000;

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("karst-disc-{tag}-{}-{nanos}", std::process::id()))
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
    let (found_ik, loc) = client::find_contact(&r, &code).expect("the code resolves");
    assert_eq!(found_ik, my_ik, "the code resolves to our identity");
    assert!(loc.addrs.contains(&addr), "and to the relay we published at");

    // A well-formed but unknown code resolves to nothing.
    let other = node::discovery::encode_code(&node::discovery::public_of(&[42u8; 32]));
    assert!(client::find_contact(&r, &other).is_err(), "an unpublished code finds no one");
    // Garbage is rejected before any network call.
    assert!(client::find_contact(&r, "not-a-code").is_err());
}

#[test]
fn rotate_retires_the_old_code_and_off_stops_resolving() {
    let (addr, np, fp) = spawn();
    let r = Relay::new(addr.parse::<std::net::SocketAddr>().unwrap(), RelayId { noise_pub: np, fetch_pub: fp }, None);
    let store = seeded_store("rotate");

    let code1 = client::discovery_publish(&store, &r, NOW).unwrap();
    assert!(client::find_contact(&r, &code1).is_ok());

    // Rotate → a new code; the old one no longer resolves, the new one does, same identity.
    let code2 = client::discovery_rotate(&store, &r, NOW).unwrap();
    assert_ne!(code1, code2, "rotation mints a different code");
    assert!(client::find_contact(&r, &code1).is_err(), "the retired code stops resolving");
    let (ik2, _) = client::find_contact(&r, &code2).expect("the new code resolves");
    assert_eq!(ik2, store.load_account().unwrap().identity_public(), "identity is unchanged by rotation");

    // Off → the current code stops resolving and the local key is gone.
    client::discovery_off(&store, &r).unwrap();
    assert!(client::find_contact(&r, &code2).is_err(), "turning discovery off unpublishes the code");
    assert!(client::discovery_code(&store).unwrap().is_none(), "and clears the local key");
}
