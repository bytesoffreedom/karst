//! #215 (A4-8) + open half of #163 (R2-6).
//!
//! A4-8: `send_session_batch` used to queue a manifest and its chunks one payload at a time,
//! with no idea whether the outbox (`karst_client_core::peer`'s shared, capped `PeerState::outbox`) had room
//! for the whole batch. `Peer::queue` evicts the OLDEST queued entry — silently — whenever the
//! outbox is already at its cap, so an unreserved batch could evict entries belonging to a
//! completely different conversation, all while the ratchet kept advancing and the call reported
//! success. The fix reserves room for the WHOLE batch before persisting anything: the first push
//! that would have to evict something aborts the call, and because nothing before that point was
//! ever saved, the abort is exact — no partial batch, no ratchet drift.
//!
//! R2-6: even a single (non-batch) send can still have the cap evict an OLDER, unrelated queued
//! message to make room for it, and a message can still simply age out past its TTL in a
//! `flush_outbox` pass. Both used to vanish with no trace and a caller-facing "sent". Now both
//! land in `Store::load_stranded_sends` — see the eviction and expiry tests below.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use client::store::Store;
use relay::node::{PublishResponse, RelayNode, MAILBOX_TTL_SECS};
use relay::server::RelayServer;

const NOW: u64 = 1_000_000;

fn temp_dir(tag: &str) -> PathBuf {
    // One root, swept by later runs — see `node::scratch` for why the harness gives us no
    // teardown hook and what that bounds (#321).
    node::scratch::dir_for_test(tag)
}

/// Relay on an ephemeral port with a dev capability and fixed clock — same shape as
/// `e2e_client.rs`'s `spawn_relay` (kept separate here so this file has no cross-file
/// dependency on that one's private helpers).
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

fn seed_provision(s: &Store) -> [u8; client::seed::ENTROPY_BYTES] {
    let e = client::seed::entropy_of(&client::seed::generate_mnemonic());
    s.save_seed(&e).unwrap();
    e
}

/// A relay address nothing listens on — `SocketTransport` fails fast (connection refused, not a
/// timeout) so tests using this stay quick. Same pattern as `e2e_client.rs`'s multihoming test.
fn dead_relay(rid: client::RelayId) -> client::Relay {
    client::Relay::new("127.0.0.1:1".parse::<SocketAddr>().unwrap(), rid, None)
}

/// Provision Alice and Bob, publish Bob's bundle, and send one message over the LIVE relay so a
/// real ratchet session exists between them — every later send in these tests targets a DEAD
/// relay, and `send_session`/`send_session_batch` only skip the network round trip of `connect`
/// when a session already exists.
fn set_up() -> (Store, Store, [u8; 32], client::Relay) {
    let (addr, rid) = spawn_relay();
    let astore = Store::unlock(temp_dir("outbox-a"), b"pw").unwrap();
    let bstore = Store::unlock(temp_dir("outbox-b"), b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_capability_for(&rid, &client::dev_capability()).unwrap();
    bstore.save_capability_for(&rid, &client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let live = ctx(addr, &rid);
    assert!(matches!(
        client::publish_bundle(&live, bstore.load_account().unwrap(), client::dev_capability(), NOW),
        PublishResponse::Published
    ));
    let delivered = client::send_text(&astore, &live, &bob_ik, b"hello", NOW, NOW).unwrap();
    assert!(delivered, "the handshake message reaches the live relay");
    assert_eq!(client::outbox_len(&astore).unwrap(), 0, "handshake left nothing queued");
    (astore, bstore, bob_ik, live)
}

/// Tiny, distinct payloads — content encoding is irrelevant to outbox mechanics, so raw index
/// bytes keep the test fast and the "which one got evicted" check trivial.
fn filler(n: u32) -> Vec<Vec<u8>> {
    (0..n).map(|i| i.to_le_bytes().to_vec()).collect()
}

/// The node outbox cap (`karst_client_core::peer::MAX_OUTBOX`, private to that module) as of this writing.
/// Duplicated here because nothing on the client side can see the real constant either. If it
/// ever drifts out of sync, the failure is loud, not silent: the refusal test below fills to
/// THIS number and then expects one more payload to be refused — if the real cap is actually
/// larger, that expectation fails (a batch that still fits gets accepted, not refused), which is
/// exactly the signal that this needs updating.
const MAX_OUTBOX: u32 = 512;

/// A25 control: a batch that fits EXACTLY (empty outbox + a cap-sized batch) still goes through
/// whole — proves the reservation check isn't just refusing everything.
#[test]
fn a_batch_that_fits_the_outbox_exactly_still_goes_through() {
    let (astore, _bstore, bob_ik, live) = set_up();
    let dead = dead_relay(live.id);

    client::send_session_batch(&astore, &dead, &bob_ik, &filler(MAX_OUTBOX), NOW).unwrap();
    assert_eq!(
        client::outbox_len(&astore).unwrap(),
        MAX_OUTBOX as usize,
        "the whole cap-sized batch was queued — none of it refused"
    );
    assert!(
        astore.load_stranded_sends().unwrap().is_empty(),
        "nothing was evicted, so nothing should be recorded as lost"
    );
}

/// #215/A4-8: with the outbox already AT its cap, a batch that would need to evict something to
/// fit is refused WHOLE — not partially queued — and, discriminating: the ratchet's persisted
/// state is BYTE-IDENTICAL before and after the refused call, proving the refusal happened before
/// anything (ratchet advance, queued ciphertext) was committed, not merely that an error string
/// came back while sends still happened underneath it.
#[test]
fn a_batch_that_does_not_fit_the_full_outbox_is_refused_and_the_ratchet_does_not_move() {
    let (astore, _bstore, bob_ik, live) = set_up();
    let dead = dead_relay(live.id);

    // Fill the outbox to EXACTLY its cap first (proven to succeed by the control test above).
    client::send_session_batch(&astore, &dead, &bob_ik, &filler(MAX_OUTBOX), NOW).unwrap();
    assert_eq!(client::outbox_len(&astore).unwrap(), MAX_OUTBOX as usize);

    let before_state = {
        let _lock = astore.lock_sessions().unwrap();
        postcard::to_stdvec(&astore.load_sessions().unwrap()).unwrap()
    };

    // ANY additional batch — even a single payload — has no room without evicting something.
    let err = client::send_session_batch(&astore, &dead, &bob_ik, &filler(1), NOW)
        .expect_err("a batch that would evict a queued message must be refused, not accepted");
    assert!(!err.is_empty(), "the caller gets an actual error message, not a bare unit");

    let after_state = {
        let _lock = astore.lock_sessions().unwrap();
        postcard::to_stdvec(&astore.load_sessions().unwrap()).unwrap()
    };
    assert_eq!(
        before_state, after_state,
        "refusing the batch must not touch sessions.dat at all — ratchet unmoved, outbox unchanged"
    );
    assert_eq!(client::outbox_len(&astore).unwrap(), MAX_OUTBOX as usize, "outbox itself unchanged");
    assert!(
        astore.load_stranded_sends().unwrap().is_empty(),
        "a refused batch was never persisted, so it evicted nothing FOR REAL — no stranded record"
    );
}

/// R2-6: outside a batch, a full outbox still silently evicts the oldest queued message to admit
/// a new one — `send_session`/`send_text` deliberately keep that behavior (a single send never
/// refuses, see the comment in `lib.rs`) — but the eviction must now leave a durable, attributed
/// trace instead of just vanishing. The victim is identified EXACTLY: it's the oldest of the 512
/// filler payloads (id 0, plaintext `filler(MAX_OUTBOX)[0]`), not a generic "something was lost".
#[test]
fn an_eviction_outside_a_batch_is_recorded_with_the_right_victim() {
    let (astore, _bstore, bob_ik, live) = set_up();
    let dead = dead_relay(live.id);

    let fillers = filler(MAX_OUTBOX);
    client::send_session_batch(&astore, &dead, &bob_ik, &fillers, NOW).unwrap();
    assert_eq!(client::outbox_len(&astore).unwrap(), MAX_OUTBOX as usize);
    assert!(astore.load_stranded_sends().unwrap().is_empty(), "nothing lost yet");

    // One more send against the same full, dead-relay outbox: `send_text` reports whatever it
    // reports (the relay is down either way), but it must NOT refuse, and it must record whoever
    // it evicted to make room.
    let _ = client::send_text(&astore, &dead, &bob_ik, b"the 513th message", NOW, NOW).unwrap();
    assert_eq!(client::outbox_len(&astore).unwrap(), MAX_OUTBOX as usize, "still at the cap, not over it");

    let stranded = astore.load_stranded_sends().unwrap();
    assert_eq!(stranded.len(), 1, "exactly one victim recorded");
    assert_eq!(stranded[0].peer_ik, bob_ik, "attributed to the right conversation");
    assert_eq!(stranded[0].plaintext, fillers[0], "attributed to the right message: the OLDEST queued");
    assert_eq!(stranded[0].reason, "evicted");

    // The ledger stays bounded too — the evicted entry is gone from it, not double-counted.
    assert_eq!(astore.load_send_ledger().unwrap().len(), MAX_OUTBOX as usize);
}

/// R2-6, the other half: a message nobody could deliver (relay stays dead) ages out past
/// `karst_client_core::peer`'s outbox TTL (`relay::node::MAILBOX_TTL_SECS`) during a later `flush_outbox` pass.
/// No eviction is ever triggered here (the outbox holds one entry, nowhere near its cap) — this
/// is purely the TTL path, and it must be attributed as `"expired"`, not conflated with
/// `"evicted"`. Driven entirely by the `now` argument — no real waiting.
#[test]
fn a_message_that_ages_out_past_its_ttl_is_recorded_as_expired() {
    let (astore, _bstore, bob_ik, live) = set_up();
    let dead = dead_relay(live.id);

    let delivered = client::send_text(&astore, &dead, &bob_ik, b"stranded by ttl", NOW, NOW).unwrap();
    assert!(!delivered, "the dead relay never accepts it");
    assert_eq!(client::outbox_len(&astore).unwrap(), 1);
    assert!(astore.load_stranded_sends().unwrap().is_empty());

    // Retry well past the TTL — `flush_outbox` drops it as expired before even attempting the
    // (still-dead) relay.
    let later = NOW + MAILBOX_TTL_SECS + 1;
    client::flush_outbox(&astore, &dead, later).unwrap();
    assert_eq!(client::outbox_len(&astore).unwrap(), 0, "TTL-expired, dropped from the outbox");

    let stranded = astore.load_stranded_sends().unwrap();
    assert_eq!(stranded.len(), 1);
    assert_eq!(stranded[0].peer_ik, bob_ik);
    assert_eq!(stranded[0].reason, "expired");
    match client::content::decode(&stranded[0].plaintext).unwrap() {
        client::content::Content::TextStamped { text, .. } => assert_eq!(text, b"stranded by ttl"),
        other => panic!("expected the stranded text, got {other:?}"),
    }
    assert!(astore.load_send_ledger().unwrap().is_empty(), "resolved (lost) entries leave the ledger");
}
