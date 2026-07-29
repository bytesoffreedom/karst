//! §12 — a client imports discovered relays into its multi-homing set, VERIFY-BEFORE-ADD.
//! Pins: a verified relay is imported as a secondary; a poisoned (unverifiable) descriptor is
//! refused; the primary is not re-added. Against real relays on loopback.

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use client::store::Store;
use client::{Relay, RelayId};
use node::node::{RelayDescriptor, RelayNode};
use node::seal::Identity;
use node::socket::{generate_noise_keypair, RelayServer};

const NOW: u64 = 1_000_000;

fn temp_dir(tag: &str) -> PathBuf {
    // Uniqueness must not rest on the clock alone: tests in one binary run on several threads
    // with the SAME pid, and a coarse timer hands two of them the same nanosecond — which showed
    // up as `AlreadyExists` on CI, not locally. A process-wide counter makes collision impossible
    // rather than unlikely.
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "karst-test-{tag}-{}-{nanos}-{seq}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn id_hex(noise: [u8; 32], fetch: [u8; 32]) -> String {
    RelayDescriptor { noise_pub: noise, fetch_pub: fetch, addrs: vec![] }.relay_id_hex()
}

/// Spawn a real self-advertising relay seeded with `others`. Returns (addr, noise_pub, fetch_pub).
fn spawn(others: Vec<RelayDescriptor>) -> (String, [u8; 32], [u8; 32]) {
    spawn_cfg(others, None, None)
}

/// Like `spawn`, but enables the blob store with a chosen persistence so the relay ADVERTISES it.
fn spawn_with_blobs(persist: node::node::BlobPersistence, tag: &str) -> (String, [u8; 32], [u8; 32]) {
    spawn_cfg(vec![], Some((persist, temp_dir(tag))), None)
}

/// A relay advertising a MAILBOX durability posture (R2-5, #161) — `Durable` opens a real mail
/// log, `Volatile` is the default (no log at all), so what it advertises is what it does.
fn spawn_with_mail(durability: node::node::MailboxDurability, tag: &str) -> (String, [u8; 32], [u8; 32]) {
    let dir = matches!(durability, node::node::MailboxDurability::Durable).then(|| temp_dir(tag));
    spawn_cfg(vec![], None, dir)
}

fn spawn_cfg(
    others: Vec<RelayDescriptor>,
    blobs: Option<(node::node::BlobPersistence, PathBuf)>,
    mail_dir: Option<PathBuf>,
) -> (String, [u8; 32], [u8; 32]) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (npriv, npub) = generate_noise_keypair();
    let fetch = Identity::generate();
    let fpub = fetch.public.to_bytes();
    let mut relay = RelayNode::with_identity(NOW, fetch);
    relay.add_relay(RelayDescriptor { noise_pub: npub, fetch_pub: fpub, addrs: vec![addr.clone()] });
    for d in others {
        relay.add_relay(d);
    }
    if let Some((persist, dir)) = blobs {
        relay.enable_blobs(dir, NOW, persist).unwrap();
    }
    if let Some(dir) = mail_dir {
        relay.enable_durable_mail(dir, NOW).unwrap();
    }
    let server = RelayServer::with_noise_keypair(relay, Arc::new(move || NOW), npriv, npub);
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });
    (addr, npub, fpub)
}

fn desc(addr: &str, np: [u8; 32], fp: [u8; 32]) -> RelayDescriptor {
    RelayDescriptor { noise_pub: np, fetch_pub: fp, addrs: vec![addr.to_string()] }
}

#[test]
fn import_adds_only_verified_relays() {
    // C: a real self-advertising relay the client should learn and multi-home onto.
    let (c_addr, c_np, c_fp) = spawn(vec![]);
    let c = RelayDescriptor { noise_pub: c_np, fetch_pub: c_fp, addrs: vec![c_addr.clone()] };
    // Poison: a random relay-id at a dead address (stand-in for a victim IP).
    let poison = RelayDescriptor { noise_pub: [9; 32], fetch_pub: [9; 32], addrs: vec!["127.0.0.1:2".into()] };
    // A (the client's primary): knows C + poison, self-advertises.
    let (a_addr, a_np, a_fp) = spawn(vec![c.clone(), poison.clone()]);

    // No set-net first — mirror the real CLI, where net.dat is never written and the primary
    // is simply the relay we discover FROM.
    let dir = temp_dir("verify");
    let store = Store::unlock(&dir, b"pw").unwrap();

    let relay_a = Relay::new(a_addr.parse::<std::net::SocketAddr>().unwrap(), RelayId { noise_pub: a_np, fetch_pub: a_fp }, None);
    let added = client::import_discovered_relays(&store, &relay_a).unwrap();
    assert_eq!(added, 1, "exactly one relay (C) should verify and import");

    let ids: Vec<String> = store.load_extra_relays().unwrap().into_iter().map(|(_, id)| id).collect();
    assert!(ids.contains(&id_hex(c_np, c_fp)), "verified relay C must be imported as a secondary");
    assert!(!ids.contains(&id_hex([9; 32], [9; 32])), "the poison must NOT be imported (verify-before-add)");
    assert!(!ids.contains(&id_hex(a_np, a_fp)), "the primary must not be re-added as a secondary");

    // Idempotent: importing again adds nothing new.
    assert_eq!(client::import_discovered_relays(&store, &relay_a).unwrap(), 0, "re-import is a no-op");
}

/// A transparent TCP relay-in-the-middle: accepts on a fresh loopback port and splices every
/// connection to `upstream` byte-for-byte. It sees no plaintext (Noise runs end-to-end through
/// it) — which is exactly the point: an attacker does not need to break Noise to become the
/// route. Returns its address; the threads live for the test.
fn transparent_proxy(upstream: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(down) = stream else { continue };
            let Ok(up) = std::net::TcpStream::connect(&upstream) else { continue };
            let (down_r, up_r) = (down.try_clone().unwrap(), up.try_clone().unwrap());
            thread::spawn(move || {
                let _ = std::io::copy(&mut { down_r }, &mut { up });
            });
            thread::spawn(move || {
                let _ = std::io::copy(&mut { up_r }, &mut { down });
            });
        }
    });
    addr
}

/// CRYPTO-23: a verified relay must be routed to at the address IT advertises, never at the
/// address the gossiping peer supplied.
///
/// The attack needs no key material and does not touch Noise: relay A (which the client is
/// discovering from) hands out C's real relay-id with the ATTACKER's endpoint as its address,
/// and that endpoint transparently splices to C. The Noise handshake authenticates C, and C's
/// own node-list contains C, so "dial it and check it serves its own relay-id" passes — and the
/// client used to persist the attacker's endpoint as its route to C, giving the attacker the
/// client's IP, every connection time and volume, and a selective drop switch, permanently.
#[test]
fn import_routes_to_the_relays_own_address_not_a_gossiped_proxy() {
    let (c_addr, c_np, c_fp) = spawn(vec![]);
    let proxy_addr = transparent_proxy(c_addr.clone());
    // A advertises C's REAL relay-id at the PROXY's address — the only thing the attacker lies
    // about, and the one thing verify-before-add never checked.
    let (a_addr, a_np, a_fp) = spawn(vec![desc(&proxy_addr, c_np, c_fp)]);

    let store = Store::unlock(temp_dir("proxy-hint"), b"pw").unwrap();
    let relay_a =
        Relay::new(a_addr.parse::<std::net::SocketAddr>().unwrap(), RelayId { noise_pub: a_np, fetch_pub: a_fp }, None);
    let added = client::import_discovered_relays(&store, &relay_a).unwrap();
    let _ = a_fp;

    assert_eq!(added, 1, "C is a real relay and still imports — the fix must not drop honest peers");
    let stored: Vec<(String, String)> = store.load_extra_relays().unwrap();
    let route = &stored.iter().find(|(_, id)| *id == id_hex(c_np, c_fp)).expect("C imported").0;
    assert_eq!(route, &c_addr, "the stored route must be C's OWN advertised address");
    assert_ne!(route, &proxy_addr, "the gossiped man-in-the-middle endpoint must never become the route");
}

/// The other half of CRYPTO-23: an address nobody vouches for is not adopted just because
/// SOMETHING answered there. The proxy splices to C, but the descriptor claims a relay-id whose
/// fetch key is not C's, so no self-entry matches and nothing is imported — the pre-existing
/// fetch-key-spoof defense must survive the change of where the address comes from.
#[test]
fn import_refuses_a_descriptor_whose_relay_id_the_endpoint_does_not_serve() {
    let (c_addr, c_np, c_fp) = spawn(vec![]);
    let proxy_addr = transparent_proxy(c_addr);
    let (a_addr, a_np, a_fp) = spawn(vec![desc(&proxy_addr, c_np, [7; 32])]);

    let store = Store::unlock(temp_dir("proxy-spoof"), b"pw").unwrap();
    let relay_a =
        Relay::new(a_addr.parse::<std::net::SocketAddr>().unwrap(), RelayId { noise_pub: a_np, fetch_pub: a_fp }, None);
    assert_eq!(client::import_discovered_relays(&store, &relay_a).unwrap(), 0, "spoofed fetch key must not import");
    assert!(store.load_extra_relays().unwrap().is_empty());
    let _ = c_fp;
}

#[test]
fn import_honors_a_persistence_preference() {
    // Two real relays advertising DIFFERENT blob policies.
    let (d_addr, d_np, d_fp) = spawn_with_blobs(node::node::BlobPersistence::Durable, "pref-dur");
    let (e_addr, e_np, e_fp) = spawn_with_blobs(node::node::BlobPersistence::Ephemeral, "pref-eph");
    let durable = desc(&d_addr, d_np, d_fp);
    let ephemeral = desc(&e_addr, e_np, e_fp);
    // A knows both.
    let (a_addr, a_np, a_fp) = spawn(vec![durable, ephemeral]);
    let _ = a_fp;

    let store = client::store::Store::unlock(temp_dir("pref"), b"pw").unwrap();
    store
        .save_relay_prefs(&client::store::RelayPrefs {
            prefer_persistence: Some(node::node::BlobPersistence::Durable),
            prefer_mail_durability: None,
        })
        .unwrap();

    let relay_a = Relay::new(a_addr.parse::<std::net::SocketAddr>().unwrap(), RelayId { noise_pub: a_np, fetch_pub: a_fp }, None);
    let added = client::import_discovered_relays(&store, &relay_a).unwrap();
    assert_eq!(added, 1, "only the durable-advertising relay matches the preference");
    let ids: Vec<String> = store.load_extra_relays().unwrap().into_iter().map(|(_, id)| id).collect();
    assert!(ids.contains(&id_hex(d_np, d_fp)), "the durable relay is imported");
    assert!(!ids.contains(&id_hex(e_np, e_fp)), "the ephemeral relay is skipped by the preference");
}

/// R2-5 (#161): the durability fix has to be REACHABLE by the code that needed it. `Accepted`
/// deliberately does not say whether the message was persisted, so the decision lives at relay
/// choice: an account that asks for durable mail must not silently multi-home onto a relay that
/// loses queued mail on restart. Both relays here are real and advertise what they actually do
/// (the durable one has an open mail log), so this is not a mocked policy string.
#[test]
fn import_honors_a_mail_durability_preference() {
    let (d_addr, d_np, d_fp) = spawn_with_mail(node::node::MailboxDurability::Durable, "pref-mail-dur");
    let (v_addr, v_np, v_fp) = spawn_with_mail(node::node::MailboxDurability::Volatile, "pref-mail-vol");
    let (a_addr, a_np, a_fp) = spawn(vec![desc(&d_addr, d_np, d_fp), desc(&v_addr, v_np, v_fp)]);

    let store = client::store::Store::unlock(temp_dir("pref-mail"), b"pw").unwrap();
    store
        .save_relay_prefs(&client::store::RelayPrefs {
            prefer_persistence: None,
            prefer_mail_durability: Some(node::node::MailboxDurability::Durable),
        })
        .unwrap();

    let relay_a = Relay::new(a_addr.parse::<std::net::SocketAddr>().unwrap(), RelayId { noise_pub: a_np, fetch_pub: a_fp }, None);
    let added = client::import_discovered_relays(&store, &relay_a).unwrap();
    assert_eq!(added, 1, "only the relay that actually persists queued mail matches");
    let ids: Vec<String> = store.load_extra_relays().unwrap().into_iter().map(|(_, id)| id).collect();
    assert!(ids.contains(&id_hex(d_np, d_fp)), "the durable-mail relay is imported");
    assert!(!ids.contains(&id_hex(v_np, v_fp)), "the volatile relay is skipped by the preference");
}
