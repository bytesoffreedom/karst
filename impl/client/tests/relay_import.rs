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
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("karst-import-{tag}-{}-{nanos}", std::process::id()))
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
