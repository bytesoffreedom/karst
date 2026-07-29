//! §15 blob-upload admission (CRYPTO-15/#169, blob half of #194).
//!
//! `RelayNode::handle_blob_put` used to gate a chunk upload with a cookie ONLY. A cookie is a
//! stateless HMAC round-trip the requester can mint for any address it names — it proves
//! freshness, not a cost — so the path that stores the LARGEST bytes on the relay (a blob
//! upload) was the one write that never charged anyone's admission quota, while every other
//! write (message send, bundle publish) does. The blob store's own per-sender/global byte caps
//! (`blobstore.rs`) are a separate, complementary mechanism keyed to the self-declared
//! `client_addr` — a Sybil resets them for free by minting a fresh address, so they were never
//! the fix either.
//!
//! These tests pin, from the RELAY's chair:
//! - a chunk upload with no verifiable capability is rejected, and stores nothing;
//! - a capability-proof minted for the MESSAGE path (same capability, ordinary nonce) does NOT
//!   open the blob path — the nonce-shape check (`blob_put_nonce`) closes the cross-class replay
//!   the two paths would otherwise share;
//! - a legitimate multi-chunk upload with a correctly-derived proof per chunk still completes
//!   end to end (the control: this fix must not break honest large uploads);
//! - the blob quota (`BLOB_CAP_QUOTA`) is tracked SEPARATELY from the message quota
//!   (`cap_quota`) under the same capability — the reason two trackers exist at all, per
//!   `BlobQuotaTracker`'s doc comment (charging blob bytes against the message-scale
//!   `POW_CAP_QUOTA` would make an honest 2 GiB upload take on the order of 85 hours, see the
//!   arithmetic in that doc comment).

use admission::capability::{Capability, Quota, Scope};
use node::blobstore::{MAX_BLOB_CHUNKS, MAX_BLOB_SIZE};
use relay::node::{BlobPersistence, BlobPutRequest, BlobResponse, RelayNode, Response};
use relay::node::{blob_put_nonce, BLOB_CAP_QUOTA};

const NOW: u64 = 1_000_000;

/// A capability the relay has actually issued (as opposed to one only the attacker knows the
/// shape of) — the "legitimate holder" in every test below.
fn issued_cap(relay: &mut RelayNode, secret: [u8; 32], quota: Quota) -> Capability {
    let mut capability_id = [0u8; 16];
    capability_id.copy_from_slice(&secret[..16]); // distinct per fixture; content doesn't matter
    let cap = Capability {
        capability_id,
        scope: Scope::MessageDelivery,
        quota,
        not_before: 0,
        not_after: u32::MAX,
        secret,
    };
    relay.issue_capability(cap.clone());
    cap
}

fn relay_with_blobs(dir: &std::path::Path) -> RelayNode {
    let mut relay = RelayNode::new(NOW);
    relay.enable_blobs(dir.to_path_buf(), NOW, BlobPersistence::Ephemeral).expect("enable_blobs");
    relay
}

/// `handle_blob_put` requires `client_addr` to decode as exactly 32 bytes (it becomes the
/// blob-store `sender`) — a real client sends its pseudonym (see `Relay::pseudonym`); tests
/// just need any fixed 32 bytes.
fn addr32(tag: u8) -> Vec<u8> {
    let mut a = [0u8; 32];
    a[0] = tag;
    a.to_vec()
}

fn tmp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("karst-blob-admission-{name}-{:?}", std::thread::current().id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Build a `BlobPutRequest` for chunk `index` of `count`, correctly admitted: cookie already
/// fetched, `request_nonce` derived per `blob_put_nonce`'s required shape, and a capability
/// proof minted over EXACTLY that nonce (as a well-behaved client must, once one exists).
fn good_put(
    cap: &Capability,
    cookie: admission::cookie::Cookie,
    client_addr: &[u8],
    blob_id: [u8; 32],
    index: u32,
    count: u32,
    data: Vec<u8>,
) -> BlobPutRequest {
    let nonce = blob_put_nonce(&blob_id, index);
    let proof = cap.prove(&nonce, 0);
    BlobPutRequest {
        client_addr: client_addr.to_vec(),
        carrier_id: b"blob".to_vec(),
        cookie: Some(cookie),
        request_nonce: nonce,
        capability_proof: proof,
        blob_id,
        index,
        count,
        data,
    }
}

/// Generous quota for tests that are only about the admission GATE, not the arithmetic — the
/// arithmetic itself has its own dedicated test below.
fn generous_quota() -> Quota {
    Quota { max_requests: 1000, max_bytes: 1 << 20, window_secs: 600 }
}

#[test]
fn a_blob_chunk_with_no_registered_capability_is_rejected_and_stores_nothing() {
    let dir = tmp("no-cap");
    let mut relay = relay_with_blobs(&dir);
    let client_addr = addr32(0xA1);
    let cookie = relay.issue_cookie_for_test(&client_addr, b"blob", NOW);
    let blob_id = [0x11; 32];

    // A capability the relay has NEVER issued — the shape is fine (right nonce, well-formed
    // proof), it just doesn't verify against anything in the relay's table.
    let stranger = Capability {
        capability_id: [0xEE; 16],
        scope: Scope::MessageDelivery,
        quota: generous_quota(),
        not_before: 0,
        not_after: u32::MAX,
        secret: [0xEE; 32],
    };
    let req = good_put(&stranger, cookie, &client_addr, blob_id, 0, 1, vec![1, 2, 3]);

    let resp = relay.handle_blob_put(&req, NOW);
    assert!(
        matches!(resp, BlobResponse::Rejected(_)),
        "an unregistered capability must be rejected loudly, got {resp:?}"
    );
    assert_eq!(relay.blob_stat(&blob_id), None, "a rejected chunk must not be stored");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The load-bearing test for the cross-class fix: a capability-proof minted the way the
/// MESSAGE path mints one (ordinary `"req-N"` nonce, same registered capability, same
/// `Scope::MessageDelivery`) must NOT be accepted on the blob path. Before `blob_put_nonce`
/// existed, the capability MAC does not fold `scope` into itself for a stored capability (only
/// an equality check against the REQUESTED scope, which the blob path also asks for), so this
/// exact proof would have verified fine.
#[test]
fn a_capability_proof_minted_for_the_message_path_does_not_open_the_blob_path() {
    let dir = tmp("cross-class");
    let mut relay = relay_with_blobs(&dir);
    let client_addr = addr32(0xA1);
    let cookie = relay.issue_cookie_for_test(&client_addr, b"blob", NOW);
    let blob_id = [0x22; 32];
    let cap = issued_cap(&mut relay, [0x44; 32], generous_quota());

    // Exactly what a message-send would carry: an arbitrary nonce, NOT `blob_put_nonce`.
    let message_style_nonce = b"req-0".to_vec();
    let proof = cap.prove(&message_style_nonce, 0);
    let req = BlobPutRequest {
        client_addr: client_addr.clone(),
        carrier_id: b"blob".to_vec(),
        cookie: Some(cookie),
        request_nonce: message_style_nonce,
        capability_proof: proof,
        blob_id,
        index: 0,
        count: 1,
        data: vec![9, 9, 9],
    };

    let resp = relay.handle_blob_put(&req, NOW);
    assert!(
        matches!(resp, BlobResponse::Rejected(_)),
        "a message-shaped proof must be rejected on the blob path, got {resp:?}"
    );
    assert_eq!(relay.blob_stat(&blob_id), None, "nothing must be stored from the rejected chunk");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Control: a legitimate multi-chunk upload, correctly admitted per chunk, still completes.
/// This is what the fix must not break.
#[test]
fn a_legitimate_multi_chunk_upload_with_a_valid_capability_completes_end_to_end() {
    let dir = tmp("control");
    let mut relay = relay_with_blobs(&dir);
    let client_addr = addr32(0xA1);
    let blob_id = [0x33; 32];
    let cap = issued_cap(&mut relay, [0x55; 32], generous_quota());

    let chunks: Vec<Vec<u8>> = (0..5u32).map(|i| vec![i as u8; 100]).collect();
    let count = chunks.len() as u32;
    for (index, data) in chunks.into_iter().enumerate() {
        let index = index as u32;
        let cookie = relay.issue_cookie_for_test(&client_addr, b"blob", NOW);
        let req = good_put(&cap, cookie, &client_addr, blob_id, index, count, data);
        let resp = relay.handle_blob_put(&req, NOW);
        let expected_last = index + 1 == count;
        match resp {
            BlobResponse::Stored if !expected_last => {}
            BlobResponse::Complete if expected_last => {}
            other => panic!("chunk {index}/{count}: unexpected {other:?}"),
        }
    }

    let stat = relay.blob_stat(&blob_id).expect("blob must be known");
    assert_eq!(stat, (count, count, true), "upload must be complete with all chunks present");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The reason `BlobQuotaTracker` is a SEPARATE tracker from `cap_quota`: charging blob bytes
/// against the same budget a chat message uses would strangle uploads (see `BLOB_CAP_QUOTA`'s
/// doc comment for the arithmetic). Proven here from both directions under ONE capability:
/// exhausting the MESSAGE quota must not block a blob put, and exhausting the BLOB quota must
/// not block a message send.
#[test]
fn blob_quota_and_message_quota_are_independent_under_the_same_capability() {
    let dir = tmp("independent");
    let mut relay = relay_with_blobs(&dir);
    let client_addr = addr32(0xA1);
    // Message quota: exactly ONE request per window — the second send must be refused by
    // `cap_quota`, independent of anything blob-related.
    let tiny_message_quota = Quota { max_requests: 1, max_bytes: 1 << 20, window_secs: 600 };
    let cap = issued_cap(&mut relay, [0x66; 32], tiny_message_quota);

    // Spend the message quota's one allowed request.
    let bob = node::seal::Identity::generate();
    let relay_rc = std::rc::Rc::new(std::cell::RefCell::new(relay));
    let transport = relay::node::InMemoryTransport::new(relay_rc.clone());
    let mut alice = karst_client_core::demo::Client::new(transport.clone(), cap.clone(), &client_addr);
    let recipient = karst_client_core::demo::Recipient::new(transport, bob, relay_rc.borrow().relay_public());
    let bob_pub = recipient.public();
    assert!(
        matches!(alice.send(&bob_pub, b"first", NOW), Response::Accepted),
        "the capability's one allowed message must be admitted"
    );
    let resp2 = alice.send(&bob_pub, b"second", NOW);
    assert!(
        matches!(resp2, Response::Rejected(_)),
        "a second message must be refused by the exhausted MESSAGE quota, got {resp2:?}"
    );

    // Now upload several blob chunks under the SAME capability. If the trackers were shared,
    // this would already be exhausted by the message-quota spend above; it must not be.
    let blob_id = [0x77; 32];
    let chunks: Vec<Vec<u8>> = (0..5u32).map(|i| vec![i as u8; 200]).collect();
    let count = chunks.len() as u32;
    for (index, data) in chunks.into_iter().enumerate() {
        let index = index as u32;
        let cookie = relay_rc.borrow_mut().issue_cookie_for_test(&client_addr, b"blob", NOW);
        let req = good_put(&cap, cookie, &client_addr, blob_id, index, count, data);
        let resp = relay_rc.borrow_mut().handle_blob_put(&req, NOW);
        assert!(
            matches!(resp, BlobResponse::Stored | BlobResponse::Complete),
            "blob chunk {index} must be admitted despite the message quota being exhausted, got {resp:?}"
        );
    }
    let stat = relay_rc.borrow().blob_stat(&blob_id).expect("blob must be known");
    assert_eq!(stat, (count, count, true));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Pins the arithmetic conclusion against a later edit to either side: `BLOB_CAP_QUOTA` must
/// have headroom over the blob store's OWN worst case (`MAX_BLOB_SIZE`/`MAX_BLOB_CHUNKS`), or a
/// legitimate maximal upload plus retries could exceed its own admission budget mid-transfer —
/// exactly the failure mode a message-scale quota would have produced outright.
#[test]
fn blob_cap_quota_has_headroom_over_the_blob_store_caps() {
    // Both sides are `const`, so clippy (rightly) wants this evaluated at compile time rather
    // than asserted at runtime — a `const` block still runs as part of THIS test, so a violation
    // still shows up as a named test failure, not just a silent build change.
    const {
        assert!(
            BLOB_CAP_QUOTA.max_bytes > MAX_BLOB_SIZE,
            "a maximal blob plus any retry must still fit in one window"
        );
        assert!(
            BLOB_CAP_QUOTA.max_requests > MAX_BLOB_CHUNKS,
            "a maximal blob's chunk count plus any retry must still fit in one window"
        );
    }
}
