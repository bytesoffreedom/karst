//! #281: the end-to-end bundled send path — seal a padded batch, put it on the wire as ONE
//! admitted request per bundle, and drop the padding before it reaches anything user-facing.
//!
//! The pieces were built first and nothing walked through them (`docs/design/bundling.md` said so
//! in its own status line). These tests walk through them against a REAL relay: real admission,
//! real quota, real mailbox, real ratchet.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use client::content::{self, Content};
use client::store::Store;
use relay::node::{PublishResponse, RelayNode};
use relay::server::RelayServer;

const NOW: u64 = 1_000_000;

fn temp_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir()
        .join(format!("karst-test-{tag}-{}-{nanos}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

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

fn seed_provision(s: &Store) {
    let e = client::seed::entropy_of(&client::seed::generate_mnemonic());
    s.save_seed(&e).unwrap();
}

/// Alice and Bob, both provisioned against one live relay, with a ratchet session already open —
/// a bundle carries ordinary ratchet envelopes, so the opener has to be out of the way first.
fn set_up() -> (Store, Store, [u8; 32], client::Relay) {
    let (addr, rid) = spawn_relay();
    let astore = Store::unlock(temp_dir("bundle-a"), b"pw").unwrap();
    let bstore = Store::unlock(temp_dir("bundle-b"), b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_capability_for(&rid, &client::dev_capability()).unwrap();
    bstore.save_capability_for(&rid, &client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let live = client::Relay::new(addr, rid, None);
    assert!(matches!(
        client::publish_bundle(&live, bstore.load_account().unwrap(), client::dev_capability(), NOW),
        PublishResponse::Published
    ));
    assert!(client::send_text(&astore, &live, &bob_ik, b"first contact", NOW, NOW).unwrap());
    let opener = client::recv_session(&bstore, &live, NOW).unwrap();
    assert_eq!(opener.iter().flatten().count(), 1, "the opener must land before the bundle");
    (astore, bstore, bob_ik, live)
}

fn text(s: &str) -> Vec<u8> {
    content::encode(&Content::TextStamped { text: s.as_bytes().to_vec(), ts: NOW })
}

fn texts_of(msgs: &[Option<client::Received>]) -> Vec<String> {
    msgs.iter()
        .flatten()
        .filter_map(|r| match content::decode(&r.plaintext) {
            Ok(Content::TextStamped { text, .. }) => Some(String::from_utf8_lossy(&text).into_owned()),
            _ => None,
        })
        .collect()
}

/// The whole path: two messages go out as one padded bundle, and the recipient sees TWO messages.
///
/// Discriminating on the padding: the bundle carries four slots, so four envelopes reach the
/// mailbox and four decrypt. If `strip_bundle_padding` were missing, this test would see four
/// received messages — two of them blank — which is exactly what a padded bundle looks like in a
/// chat when nobody drops the filler.
#[test]
fn a_padded_bundle_arrives_as_the_messages_that_were_written_and_nothing_else() {
    let (astore, bstore, bob_ik, live) = set_up();

    client::send_session_bundle(&astore, &live, &bob_ik, &[text("one"), text("two")], NOW)
        .expect("the bundle must be admitted and deposited");
    assert_eq!(client::outbox_len(&astore).unwrap(), 0, "nothing may stay queued after a bundle");

    let got = client::recv_session(&bstore, &live, NOW).unwrap();
    assert_eq!(
        got.iter().flatten().count(),
        2,
        "the recipient must see the two messages that were written — no padding, no blanks"
    );
    assert_eq!(texts_of(&got), vec!["one".to_string(), "two".to_string()], "in order");
}

/// A batch that is already a class is not padded, and it still arrives whole.
#[test]
fn a_batch_that_is_exactly_a_class_needs_no_padding() {
    let (astore, bstore, bob_ik, live) = set_up();
    let batch: Vec<Vec<u8>> = (0..4).map(|i| text(&format!("m{i}"))).collect();

    client::send_session_bundle(&astore, &live, &bob_ik, &batch, NOW).expect("bundle");
    let got = client::recv_session(&bstore, &live, NOW).unwrap();
    assert_eq!(texts_of(&got), vec!["m0", "m1", "m2", "m3"]);
}

/// Above the top rung a batch becomes several bundles, and every message still arrives exactly
/// once — the split must not drop the remainder or duplicate the full bundles.
///
/// **It takes several polls, and that is a fact about the ladder, not about this test.** Twenty
/// slots (16 + 4, padding included) do not fit one fixed-size fetch page, so the recipient drains
/// them over successive polls exactly as it drains any other backlog. Written as a loop with a
/// bound rather than a single fetch, because a single fetch would have quietly passed with a
/// smaller batch and hidden the fact — which belongs in `docs/design/bundling.md`, where the
/// unmeasured rungs are named.
#[test]
fn a_batch_past_the_top_rung_splits_and_still_delivers_every_message() {
    let (astore, bstore, bob_ik, live) = set_up();
    let batch: Vec<Vec<u8>> = (0..18).map(|i| text(&format!("m{i:02}"))).collect();

    client::send_session_bundle(&astore, &live, &bob_ik, &batch, NOW).expect("bundle");
    assert_eq!(client::outbox_len(&astore).unwrap(), 0);

    let mut seen = Vec::new();
    let mut polls = 0;
    while seen.len() < 18 && polls < 8 {
        seen.extend(texts_of(&client::recv_session(&bstore, &live, NOW).unwrap()));
        polls += 1;
    }
    // Deliberately not `polls > 1`: how many polls it takes is a property of the fetch page
    // size, which this test does not own and which may legitimately change.
    assert!(polls >= 1);
    seen.sort();
    let mut want: Vec<String> = (0..18).map(|i| format!("m{i:02}")).collect();
    want.sort();
    assert_eq!(seen, want, "18 messages split into 16 + 4 slots must all arrive, once each");
}

/// The padding never enters the pending-send ledger. A filler that was recorded there would
/// surface, on eviction or expiry, as a "message lost" for a message the user never wrote — a
/// loss report about a message that does not exist is worse than no report.
#[test]
fn padding_is_never_recorded_as_a_pending_send() {
    let (astore, _bstore, bob_ik, live) = set_up();
    let dead = client::Relay::new("127.0.0.1:1".parse::<SocketAddr>().unwrap(), live.id, None);

    // Against a dead relay nothing is delivered, so the whole bundle — real messages AND
    // padding — stays queued and the ledger keeps every entry it was given.
    client::send_session_bundle(&astore, &dead, &bob_ik, &[text("only one")], NOW)
        .expect("queuing must succeed even when the relay is down");
    assert_eq!(client::outbox_len(&astore).unwrap(), 1, "one message is one slot: no padding");

    client::send_session_bundle(&astore, &dead, &bob_ik, &[text("a"), text("b")], NOW)
        .expect("queued");
    assert_eq!(
        client::outbox_len(&astore).unwrap(),
        1 + 4,
        "two messages pad to a class of four — the cost the design note names"
    );
    // Age everything past its TTL and flush: expiry is what turns a queued entry into a loss
    // record, so this is where a filler would show up if it had been recorded as one.
    let much_later = NOW + 60 * 60 * 24 * 30;
    let _ = client::flush_outbox(&astore, &dead, much_later);
    let stranded = astore.load_stranded_sends().unwrap();
    let bodies: Vec<Vec<u8>> = stranded.iter().map(|s| s.plaintext.clone()).collect();
    assert!(
        !bodies.iter().any(|p| matches!(content::decode(p), Ok(c) if content::bundle::is_padding(&c))),
        "a padding slot was recorded as a lost message"
    );
    assert_eq!(bodies.len(), 3, "only the three real messages may be accounted for");
}
