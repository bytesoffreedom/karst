//! §12 — a client imports discovered relays into its multi-homing set, VERIFY-BEFORE-ADD.
//! Pins: a verified relay is imported as a secondary; a poisoned (unverifiable) descriptor is
//! refused; the primary is not re-added. Against real relays on loopback.

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use client::store::Store;
use client::{Relay, RelayId};
use node::protocol::SignedDescriptor;
use relay::node::{RelayDescriptor, RelayNode};
use node::seal::Identity;
use relay::server::{generate_noise_keypair, RelayServer};

const NOW: u64 = 1_000_000;

fn temp_dir(tag: &str) -> PathBuf {
    // One root, swept by later runs — see `node::scratch` for why the harness gives us no
    // teardown hook and what that bounds (#321).
    node::scratch::dir_for_test(tag)
}

fn id_hex(noise: [u8; 32], fetch: [u8; 32]) -> String {
    RelayDescriptor { noise_pub: noise, fetch_pub: fetch, addrs: vec![], quic_addrs: Vec::new() }.relay_id_hex()
}

/// Spawn a real self-advertising relay seeded with `others`. Returns (addr, noise_pub, fetch_pub).
fn spawn(others: Vec<SignedDescriptor>) -> (String, [u8; 32], [u8; 32], SignedDescriptor) {
    spawn_cfg(others, None, None)
}

/// The signed statement a relay at `addr` with `(np, fp)` would make about itself, produced by
/// whoever holds `secret`. Signing is unprivileged — anyone can sign a claim about any address —
/// which is why the client still dials before it trusts a route.
fn signed_desc(secret: &[u8; 32], np: [u8; 32], fp: [u8; 32], addr: &str) -> SignedDescriptor {
    let relay = RelayDescriptor {
        noise_pub: np,
        fetch_pub: fp,
        addrs: vec![addr.to_string()],
        quic_addrs: Vec::new(),
    };
    node::protocol::NodeDescriptor::signed(relay, node::protocol::RelayPolicy {
        blob_persistence: None,
        blob_ttl_secs: 0,
        max_blob_size: 0,
        pow_bits: None,
        mailbox_durability: node::protocol::MailboxDurability::Volatile,
    }, NOW, secret)
}

/// A descriptor signed by a key we generate here — a stranger's claim, correctly signed.
fn stranger(addr: &str) -> (SignedDescriptor, [u8; 32], [u8; 32]) {
    let (secret, public) = generate_noise_keypair();
    let fp = [9u8; 32];
    (signed_desc(&secret, public, fp, addr), public, fp)
}

/// Like `spawn`, but enables the blob store with a chosen persistence so the relay ADVERTISES it.
fn spawn_with_blobs(
    persist: relay::node::BlobPersistence,
    tag: &str,
) -> (String, [u8; 32], [u8; 32], SignedDescriptor) {
    spawn_cfg(vec![], Some((persist, temp_dir(tag))), None)
}

/// A relay advertising a MAILBOX durability posture (R2-5, #161) — `Durable` opens a real mail
/// log, `Volatile` is the default (no log at all), so what it advertises is what it does.
fn spawn_with_mail(
    durability: relay::node::MailboxDurability,
    tag: &str,
) -> (String, [u8; 32], [u8; 32], SignedDescriptor) {
    let dir = matches!(durability, relay::node::MailboxDurability::Durable).then(|| temp_dir(tag));
    spawn_cfg(vec![], None, dir)
}

fn spawn_cfg(
    others: Vec<SignedDescriptor>,
    blobs: Option<(relay::node::BlobPersistence, PathBuf)>,
    mail_dir: Option<PathBuf>,
) -> (String, [u8; 32], [u8; 32], SignedDescriptor) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (npriv, npub) = generate_noise_keypair();
    let fetch = Identity::generate();
    let fpub = fetch.public.to_bytes();
    let mut relay = RelayNode::with_identity(NOW, fetch);
    relay.set_self_descriptor(RelayDescriptor {
        noise_pub: npub,
        fetch_pub: fpub,
        addrs: vec![addr.clone()],
        quic_addrs: Vec::new(),
    });
    for d in others {
        assert!(relay.add_relay(d, NOW), "the fixture seeds only verifiable statements");
    }
    if let Some((persist, dir)) = blobs {
        relay.enable_blobs(dir, NOW, persist).unwrap();
    }
    if let Some(dir) = mail_dir {
        relay.enable_durable_mail(dir, NOW).unwrap();
    }
    // Sign AFTER the policy is configured, never before: the descriptor is built from the live
    // `policy()`, so signing first would advertise the defaults and the statement would describe
    // a relay this one is not. (Production is safe by construction — the binary re-signs on a
    // cadence from the current policy — but the fixture has to imitate that order to be honest.)
    relay.refresh_signed_descriptor(NOW, &npriv);
    let signed_self = relay.signed_descriptor(NOW).expect("a self-advertising relay signs itself");
    let server = RelayServer::with_noise_keypair(relay, Arc::new(move || NOW), npriv, npub);
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });
    (addr, npub, fpub, signed_self)
}

#[test]
fn import_adds_only_verified_relays() {
    // C: a real self-advertising relay the client should learn and multi-home onto.
    let (_c_addr, c_np, c_fp, c_signed) = spawn(vec![]);
    // Poison: a correctly SIGNED claim by a stranger, pointing at a dead address (a stand-in for
    // a victim IP). The signature is genuine — that is the point. Anyone can sign a statement
    // about an address they do not own, so only the dial can refuse this.
    let (poison, poison_np, poison_fp) = stranger("127.0.0.1:2");
    // A (the client's primary): carries C's and the stranger's statements, and signs its own.
    let (a_addr, a_np, a_fp, _) = spawn(vec![c_signed, poison]);

    // No set-net first — mirror the real CLI, where net.dat is never written and the primary
    // is simply the relay we discover FROM.
    let dir = temp_dir("verify");
    let store = Store::unlock(&dir, b"pw").unwrap();

    let relay_a = Relay::new(a_addr.parse::<std::net::SocketAddr>().unwrap(), RelayId { noise_pub: a_np, fetch_pub: a_fp }, None);
    let added = client::import_discovered_relays(&store, &relay_a, NOW).unwrap();
    assert_eq!(added, 1, "exactly one relay (C) should verify and import");

    let ids: Vec<String> = store.load_extra_relays().unwrap().into_iter().map(|(_, id)| id).collect();
    assert!(ids.contains(&id_hex(c_np, c_fp)), "verified relay C must be imported as a secondary");
    assert!(
        !ids.contains(&id_hex(poison_np, poison_fp)),
        "the poison must NOT be imported — a valid signature is not a reachable address"
    );
    assert!(!ids.contains(&id_hex(a_np, a_fp)), "the primary must not be re-added as a secondary");

    // Idempotent: importing again adds nothing new.
    assert_eq!(client::import_discovered_relays(&store, &relay_a, NOW).unwrap(), 0, "re-import is a no-op");
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
    let (c_addr, c_np, c_fp, c_signed) = spawn(vec![]);
    let proxy_addr = transparent_proxy(c_addr.clone());
    // Substituting an address UNDER C's identity is no longer expressible: the attacker would
    // have to sign as C. What it can still do is offer its own correctly-signed descriptor
    // pointing at the proxy, alongside C's genuine one — so the route the client keeps for C must
    // come from C's own statement, and the proxy must not become that route.
    let (proxy_claim, _, _) = stranger(&proxy_addr);
    let (a_addr, a_np, a_fp, _) = spawn(vec![c_signed, proxy_claim]);

    let store = Store::unlock(temp_dir("proxy-hint"), b"pw").unwrap();
    let relay_a =
        Relay::new(a_addr.parse::<std::net::SocketAddr>().unwrap(), RelayId { noise_pub: a_np, fetch_pub: a_fp }, None);
    let added = client::import_discovered_relays(&store, &relay_a, NOW).unwrap();
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
    let (c_addr, _c_np, c_fp, _) = spawn(vec![]);
    let proxy_addr = transparent_proxy(c_addr);
    // A stranger's signed claim at the proxy address. Something DOES answer there (the proxy
    // splices to C), and the Noise handshake even succeeds against C — but C does not serve the
    // stranger's relay-id, so the endpoint vouches for nobody and nothing is imported.
    let (proxy_claim, _, _) = stranger(&proxy_addr);
    let (a_addr, a_np, a_fp, _) = spawn(vec![proxy_claim]);

    let store = Store::unlock(temp_dir("proxy-spoof"), b"pw").unwrap();
    let relay_a =
        Relay::new(a_addr.parse::<std::net::SocketAddr>().unwrap(), RelayId { noise_pub: a_np, fetch_pub: a_fp }, None);
    assert_eq!(client::import_discovered_relays(&store, &relay_a, NOW).unwrap(), 0, "spoofed fetch key must not import");
    assert!(store.load_extra_relays().unwrap().is_empty());
    let _ = c_fp;
}

#[test]
fn import_honors_a_persistence_preference() {
    // Two real relays advertising DIFFERENT blob policies.
    let (_d_addr, d_np, d_fp, durable) =
        spawn_with_blobs(relay::node::BlobPersistence::Durable, "pref-dur");
    let (_e_addr, e_np, e_fp, ephemeral) =
        spawn_with_blobs(relay::node::BlobPersistence::Ephemeral, "pref-eph");
    // A knows both.
    let (a_addr, a_np, a_fp, _) = spawn(vec![durable, ephemeral]);
    let _ = a_fp;

    let store = client::store::Store::unlock(temp_dir("pref"), b"pw").unwrap();
    store
        .save_relay_prefs(&client::store::RelayPrefs {
            prefer_persistence: Some(relay::node::BlobPersistence::Durable),
            prefer_mail_durability: None,
        })
        .unwrap();

    let relay_a = Relay::new(a_addr.parse::<std::net::SocketAddr>().unwrap(), RelayId { noise_pub: a_np, fetch_pub: a_fp }, None);
    let added = client::import_discovered_relays(&store, &relay_a, NOW).unwrap();
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
    let (_d_addr, d_np, d_fp, d_signed) = spawn_with_mail(relay::node::MailboxDurability::Durable, "pref-mail-dur");
    let (_v_addr, v_np, v_fp, v_signed) = spawn_with_mail(relay::node::MailboxDurability::Volatile, "pref-mail-vol");
    let (a_addr, a_np, a_fp, _) = spawn(vec![d_signed, v_signed]);

    let store = client::store::Store::unlock(temp_dir("pref-mail"), b"pw").unwrap();
    store
        .save_relay_prefs(&client::store::RelayPrefs {
            prefer_persistence: None,
            prefer_mail_durability: Some(relay::node::MailboxDurability::Durable),
        })
        .unwrap();

    let relay_a = Relay::new(a_addr.parse::<std::net::SocketAddr>().unwrap(), RelayId { noise_pub: a_np, fetch_pub: a_fp }, None);
    let added = client::import_discovered_relays(&store, &relay_a, NOW).unwrap();
    assert_eq!(added, 1, "only the relay that actually persists queued mail matches");
    let ids: Vec<String> = store.load_extra_relays().unwrap().into_iter().map(|(_, id)| id).collect();
    assert!(ids.contains(&id_hex(d_np, d_fp)), "the durable-mail relay is imported");
    assert!(!ids.contains(&id_hex(v_np, v_fp)), "the volatile relay is skipped by the preference");
}
