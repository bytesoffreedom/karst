//! Adding someone by a contact/invite code, over REAL relays.
//!
//! Two audit findings are pinned here, each with its neuter written next to the assert:
//!
//!   * **A10-4 — an invite must not be destroyed by reading it.** It used to be published
//!     `single_use`, so the relay deleted the row on the first lookup: whoever (or whatever) read
//!     it first consumed it, and a lost response, a crash, or a failed local write left the
//!     invitee with a code that no longer resolves. Retiring it is now the inviter's explicit act.
//!
//!   * **A10-6 — the relay a contact code names must survive into routing.** Resolving used to ask
//!     only `relays[0]` and then throw the record's signed `location` away, so a contact whose home
//!     relay is one of our BACKUPS was unfindable, and even once known, messages went to a relay
//!     they never poll.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use client::store::Store;
use relay::node::{PublishResponse, RelayNode};
use relay::server::RelayServer;

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

/// A relay on an ephemeral port with the dev capability issued and a fixed clock.
fn spawn_relay() -> (SocketAddr, client::RelayId) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(client::dev_capability());
    let fetch_pub = relay.relay_public().to_bytes();
    let server = RelayServer::new(relay, Arc::new(move || NOW));
    let noise_pub = server.noise_public();
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });
    (addr, client::RelayId { noise_pub, fetch_pub })
}

fn ctx(addr: SocketAddr, id: &client::RelayId) -> client::Relay {
    client::Relay::new(addr, *id, None)
}

/// A store with a fresh account, unlocked at rest.
fn seeded(tag: &str) -> (PathBuf, Store) {
    let dir = temp_dir(tag);
    let s = Store::unlock(&dir, b"pw").unwrap();
    s.save_seed(&client::seed::entropy_of(&client::seed::generate_mnemonic())).unwrap();
    (dir, s)
}

/// A10-4. An invite survives being resolved: the invitee can look the same code up again, which is
/// what makes a retry after a crash / lost response / failed local write a real recovery instead of
/// "ask them for a new code". Both resolves must land on the same identity.
///
/// NEUTER: publish the invite with `single_use: true` again in `client::discovery_one_time` (the
/// relay then deletes the row inside the first lookup) and the second resolve reddens with
/// "no one is published under that code" — verified, not assumed.
#[test]
fn an_invite_still_resolves_after_it_has_been_read() {
    let (addr, id) = spawn_relay();
    let r = ctx(addr, &id);
    let (dir, host) = seeded("invite-reread");
    let host_ik = host.load_account().unwrap().identity_public();

    let code = client::discovery_one_time(&host, &r, NOW).expect("mint an invite");

    let (first, _) = client::find_contact(&r, &code, NOW).expect("the invitee resolves it");
    assert_eq!(first, host_ik, "the code resolves to the inviter");
    // The half that used to be impossible: read it a second time. A first attempt whose response
    // was lost, whose local commit failed, or that a stranger with the code got to first, no
    // longer destroys the invite.
    let (again, _) = client::find_contact(&r, &code, NOW).expect("it resolves a SECOND time");
    assert_eq!(again, host_ik, "and to the same identity");

    std::fs::remove_dir_all(&dir).ok();
}

/// A10-4, the other half of the trade: because the row is no longer burned on read, retiring it is
/// an explicit act by the party who can actually tell the invite did its job. The secret that owns
/// the row is kept for exactly that, and revoking stops the code resolving.
///
/// NEUTER: drop the `add_invite` call in `client::discovery_one_time` (i.e. keep the pre-fix
/// "ephemeral — not persisted" secret) and `revoke_invite` reddens with "no invite of yours
/// matches that code" — there is then nothing on disk that can authorise the deletion.
#[test]
fn revoking_an_invite_retires_it_and_leaves_the_others_alone() {
    let (addr, id) = spawn_relay();
    let r = ctx(addr, &id);
    let (dir, host) = seeded("invite-revoke");

    let doomed = client::discovery_one_time(&host, &r, NOW).expect("mint invite 1");
    let kept = client::discovery_one_time(&host, &r, NOW).expect("mint invite 2");
    let listed: Vec<String> = client::invites(&host, NOW).unwrap().into_iter().map(|i| i.code).collect();
    assert_eq!(listed.len(), 2, "both invites are outstanding");
    assert!(listed.contains(&doomed) && listed.contains(&kept));

    assert!(client::revoke_invite(&host, &r, &doomed, NOW).unwrap(), "the relay removed the row");
    assert!(
        client::find_contact(&r, &doomed, NOW).is_err(),
        "the revoked invite must stop resolving"
    );
    // Revocation is per-invite, not "turn invites off": the other one still works, and the
    // PERSISTENT contact code is a different row entirely (its key was never touched).
    assert!(client::find_contact(&r, &kept, NOW).is_ok(), "the other invite still resolves");
    let left: Vec<String> = client::invites(&host, NOW).unwrap().into_iter().map(|i| i.code).collect();
    assert_eq!(left, vec![kept], "only the revoked one is forgotten locally");

    std::fs::remove_dir_all(&dir).ok();
}

/// A10-6, end to end. Bob homes on relay B only — his bundle and his contact code are published
/// there, and B is Alice's BACKUP, not her primary. Adding him by code must (a) find the row at
/// all, (b) remember the relay his code named, and (c) send the message to THAT relay, where he
/// polls.
///
/// NEUTER, both halves, each verified:
///   * make `add_contact_by_code` resolve at `relays[0]` only (the pre-fix `find_contact`) → the
///     add reddens with "no one is published under that code": Bob is simply unfindable.
///   * make `relays_for_contact` return the relay set unchanged (the pre-fix "`_loc` is dropped"
///     behaviour) → the send goes to relay A, where Bob has no bundle, and reddens with a failed
///     first contact; even if it had queued, his poll at B would never see it.
#[test]
fn a_contact_code_routes_the_message_to_the_relay_it_named() {
    let (addr_a, id_a) = spawn_relay(); // Alice's primary — Bob is NOT here
    let (addr_b, id_b) = spawn_relay(); // Bob's home relay, Alice's backup
    let (ra, rb) = (ctx(addr_a, &id_a), ctx(addr_b, &id_b));
    let (adir, alice) = seeded("route-alice");
    let (bdir, bob) = seeded("route-bob");
    let bob_ik = bob.load_account().unwrap().identity_public();

    // Alice holds a credential for both relays; Bob only ever talks to B.
    alice.save_capability_for(&id_a, &client::dev_capability()).unwrap();
    alice.save_capability_for(&id_b, &client::dev_capability()).unwrap();
    bob.save_capability_for(&id_b, &client::dev_capability()).unwrap();

    let pr = client::publish_bundle(&rb, bob.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "Bob's bundle lands on relay B: {pr:?}");
    let code = client::discovery_publish(&bob, &rb, NOW).expect("Bob publishes his contact code at B");

    // Alice adds him. Her relay set is [A (primary), B (backup)].
    let relays = vec![ra.clone(), rb.clone()];
    let ik = client::add_contact_by_code(&alice, &relays, &code, "bob", 0, NOW).expect("the code resolves");
    assert_eq!(ik, bob_ik, "the code resolves to Bob");

    // (b) the route his code was signed for is on disk…
    let ep = alice.contact_endpoint(&bob_ik).expect("his relay was recorded");
    assert_eq!(ep.relay.noise_pub, id_b.noise_pub, "and it is relay B, not the primary");
    assert_eq!(ep.relay.fetch_pub, id_b.fetch_pub);

    // (c) …and it is what the send actually uses.
    let route = client::relays_for_contact(&alice, &relays, &bob_ik);
    assert_eq!(route[0].id.noise_pub, id_b.noise_pub, "the send goes to HIS relay first");
    assert!(
        client::send_text(&alice, &route[0], &bob_ik, b"found you", NOW, NOW).unwrap(),
        "the message reached the relay"
    );

    // Bob polls the only relay he is on and has it.
    let got = client::recv_session(&bob, &rb, NOW).unwrap();
    let texts: Vec<Vec<u8>> = got
        .iter()
        .flatten()
        .filter_map(|m| match client::content::decode(&m.plaintext).ok()? {
            client::content::Content::Text(t) => Some(t),
            client::content::Content::TextStamped { text, .. } => Some(text),
            _ => None,
        })
        .collect();
    assert_eq!(texts, vec![b"found you".to_vec()], "delivered where he actually polls");

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// A10-6, the guard on the preference. Knowing where a contact is must never make a working send
/// fail: if their relay is one we hold no admission credential for, `send_session` would hard-fail
/// there, so the preference must not fire. Same setup as above, minus Alice's credential for B.
///
/// NEUTER: drop the `has_capability_for` condition in `relays_for_contact` and this reddens —
/// the route starts with a relay Alice cannot present a capability to.
#[test]
fn a_relay_we_hold_no_credential_for_is_not_preferred() {
    let (addr_a, id_a) = spawn_relay();
    let (addr_b, id_b) = spawn_relay();
    let (ra, rb) = (ctx(addr_a, &id_a), ctx(addr_b, &id_b));
    let (adir, alice) = seeded("route-nocap-alice");
    let (bdir, bob) = seeded("route-nocap-bob");
    let bob_ik = bob.load_account().unwrap().identity_public();

    alice.save_capability_for(&id_a, &client::dev_capability()).unwrap();
    bob.save_capability_for(&id_b, &client::dev_capability()).unwrap();
    let pr = client::publish_bundle(&rb, bob.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published));
    let code = client::discovery_publish(&bob, &rb, NOW).unwrap();

    let relays = vec![ra.clone(), rb.clone()];
    client::add_contact_by_code(&alice, &relays, &code, "bob", 0, NOW).expect("the code still resolves");
    assert!(alice.contact_endpoint(&bob_ik).is_some(), "his relay is still recorded for later");

    let route = client::relays_for_contact(&alice, &relays, &bob_ik);
    assert_eq!(
        route[0].id.noise_pub, id_a.noise_pub,
        "without a credential for his relay the primary stays first"
    );

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}
