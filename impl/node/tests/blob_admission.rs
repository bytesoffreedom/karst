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
/// blob-store `sender`) — a real client sends the blob's owner handle (`blob::owner_token`); tests
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
        read_pub: [0xAB; 32],
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
        read_pub: [0xAB; 32],
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
        matches!(alice.send(&bob_pub, node::seal::SealKemKeys::generate().ek(), b"first", NOW), Response::Accepted),
        "the capability's one allowed message must be admitted"
    );
    let resp2 = alice.send(&bob_pub, node::seal::SealKemKeys::generate().ek(), b"second", NOW);
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

// ---------------------------------------------------------------------------------------------
// PRIV-7a: the read token. Downloads and progress queries stop being bearer-by-id — knowing the
// 256-bit blob id is no longer the download right; the requester must prove they hold the content
// key the recipient was actually given.
// ---------------------------------------------------------------------------------------------

/// Upload one chunk under a real content key and hand back everything a download needs.
fn uploaded_blob(relay: &mut RelayNode, key: [u8; 32]) -> ([u8; 32], Vec<u8>) {
    let client_addr = addr32(0xD1);
    let cap = issued_cap(relay, [0xD1; 32], generous_quota());
    let cookie = relay.issue_cookie_for_test(&client_addr, b"blob", NOW);
    let blob_id = [0xD5; 32];
    let mut req = good_put(&cap, cookie, &client_addr, blob_id, 0, 1, vec![4, 5, 6]);
    req.read_pub = node::blind::blob_read_keypair(&key).1;
    assert!(
        matches!(relay.handle_blob_put(&req, NOW), BlobResponse::Complete),
        "the upload itself must succeed"
    );
    (blob_id, client_addr)
}

/// The whole point of the slice: the id alone no longer buys the bytes.
#[test]
fn knowing_only_the_blob_id_no_longer_downloads_a_chunk() {
    let dir = tmp("read-token-id-alone");
    let mut relay = relay_with_blobs(&dir);
    let key = [0x77; 32];
    let (blob_id, client_addr) = uploaded_blob(&mut relay, key);

    // A bystander who learned the id — from the relay's own store, a backup, a log — but never
    // held the content key. They can obtain a cookie; that was always free.
    let cookie = relay.issue_cookie_for_test(&client_addr, b"blob", NOW);
    let req = relay::node::BlobGetRequest {
        client_addr: client_addr.clone(),
        carrier_id: b"blob".to_vec(),
        cookie: Some(cookie),
        blob_id,
        index: 0,
        read_proof: Vec::new(),
    };
    assert!(
        matches!(relay.handle_blob_get(&req, NOW), BlobResponse::Rejected(_)),
        "an id with no read proof must not serve bytes"
    );

    // And the holder of the content key still gets the chunk, over the same endpoint.
    let cookie = relay.issue_cookie_for_test(&client_addr, b"blob", NOW);
    let (secret, public) = node::blind::blob_read_keypair(&key);
    let ctx = node::blind::blob_read_context(&cookie.mac, &blob_id, 0);
    let proof = node::blind::FetchOwnershipProof::prove(&secret, &public, &ctx).expect("prove");
    let req = relay::node::BlobGetRequest {
        client_addr,
        carrier_id: b"blob".to_vec(),
        cookie: Some(cookie),
        blob_id,
        index: 0,
        read_proof: proof.to_bytes().to_vec(),
    };
    assert!(
        matches!(relay.handle_blob_get(&req, NOW), BlobResponse::Chunk(Some(_))),
        "the content-key holder must still be served"
    );
}

/// A proof is bound to its chunk index, so one captured for chunk 0 cannot pull chunk 1 — and a
/// STAT proof cannot stand in for a chunk download either (that is what `BLOB_STAT_INDEX` is for).
#[test]
fn a_read_proof_does_not_travel_between_indices_or_between_get_and_stat() {
    let dir = tmp("read-token-binding");
    let mut relay = relay_with_blobs(&dir);
    let key = [0x78; 32];
    let (blob_id, client_addr) = uploaded_blob(&mut relay, key);
    let (secret, public) = node::blind::blob_read_keypair(&key);

    let cookie = relay.issue_cookie_for_test(&client_addr, b"blob", NOW);
    let for_chunk_zero = node::blind::FetchOwnershipProof::prove(
        &secret,
        &public,
        &node::blind::blob_read_context(&cookie.mac, &blob_id, 0),
    )
    .expect("prove")
    .to_bytes()
    .to_vec();

    // Replayed at a different index.
    let req = relay::node::BlobGetRequest {
        client_addr: client_addr.clone(),
        carrier_id: b"blob".to_vec(),
        cookie: Some(cookie),
        blob_id,
        index: 1,
        read_proof: for_chunk_zero.clone(),
    };
    assert!(
        matches!(relay.handle_blob_get(&req, NOW), BlobResponse::Rejected(_)),
        "a proof minted for chunk 0 must not admit chunk 1"
    );

    // Replayed as a progress query.
    let cookie = relay.issue_cookie_for_test(&client_addr, b"blob", NOW);
    let chunk_proof = node::blind::FetchOwnershipProof::prove(
        &secret,
        &public,
        &node::blind::blob_read_context(&cookie.mac, &blob_id, 0),
    )
    .expect("prove")
    .to_bytes()
    .to_vec();
    let stat = node::protocol::BlobStatRequest {
        client_addr,
        carrier_id: b"blob".to_vec(),
        cookie: Some(cookie),
        blob_id,
        read_pub: public,
        read_proof: chunk_proof,
    };
    assert!(
        matches!(relay.admit_blob_stat(&stat, NOW), Err(BlobResponse::Rejected(_))),
        "a chunk proof must not admit a stat — the indices are disjoint by construction"
    );
}

/// A stat under the WRONG read key is answered exactly like a stat for an id the relay has never
/// seen. Otherwise the endpoint that must stay usable before a blob exists — an uploader asking
/// "how far did I get?" — would become the existence oracle the token exists to close.
#[test]
fn a_stat_under_the_wrong_key_looks_exactly_like_an_unknown_blob() {
    let dir = tmp("read-token-stat-unknown");
    let mut relay = relay_with_blobs(&dir);
    let key = [0x7A; 32];
    let (blob_id, client_addr) = uploaded_blob(&mut relay, key);

    let stat_with = |relay: &mut RelayNode, id: [u8; 32], k: [u8; 32]| {
        let cookie = relay.issue_cookie_for_test(&client_addr, b"blob", NOW);
        let (secret, public) = node::blind::blob_read_keypair(&k);
        let ctx =
            node::blind::blob_read_context(&cookie.mac, &id, node::protocol::BLOB_STAT_INDEX);
        let proof = node::blind::FetchOwnershipProof::prove(&secret, &public, &ctx).expect("prove");
        let req = node::protocol::BlobStatRequest {
            client_addr: client_addr.clone(),
            carrier_id: b"blob".to_vec(),
            cookie: Some(cookie),
            blob_id: id,
            read_pub: public,
            read_proof: proof.to_bytes().to_vec(),
        };
        relay.admit_blob_stat(&req, NOW).expect("a well-formed proof is admitted").is_some()
    };

    assert!(stat_with(&mut relay, blob_id, key), "the uploader sees their own blob");
    assert!(
        !stat_with(&mut relay, blob_id, [0x99; 32]),
        "a stranger's key must be answered as if the blob were unknown"
    );
    assert!(
        !stat_with(&mut relay, [0xEE; 32], key),
        "and an id the relay never saw is answered the same way"
    );
}

/// An unknown id and a bad proof must be refused THE SAME WAY: otherwise the endpoint answers
/// "does this blob exist?" for free, which is most of what the token was introduced to stop.
#[test]
fn an_unknown_blob_and_a_bad_proof_are_refused_identically() {
    let dir = tmp("read-token-no-oracle");
    let mut relay = relay_with_blobs(&dir);
    let key = [0x79; 32];
    let (blob_id, client_addr) = uploaded_blob(&mut relay, key);

    let refusal = |relay: &mut RelayNode, id: [u8; 32], proof: Vec<u8>| {
        let cookie = relay.issue_cookie_for_test(&client_addr, b"blob", NOW);
        let req = relay::node::BlobGetRequest {
            client_addr: client_addr.clone(),
            carrier_id: b"blob".to_vec(),
            cookie: Some(cookie),
            blob_id: id,
            index: 0,
            read_proof: proof,
        };
        match relay.handle_blob_get(&req, NOW) {
            BlobResponse::Rejected(r) => r,
            other => panic!("expected a refusal, got {other:?}"),
        }
    };

    let known_bad = refusal(&mut relay, blob_id, vec![0u8; 64]);
    let unknown = refusal(&mut relay, [0xEE; 32], vec![0u8; 64]);
    assert_eq!(known_bad, unknown, "the refusal must not reveal whether the id exists");
}


// ---------------------------------------------------------------------------------------------
// Bundled deposits (#281/#293): admitted once, charged per slot.
// ---------------------------------------------------------------------------------------------

/// A slot: a veiled envelope, which is the only thing a bundle can carry.
fn slot(n: u8) -> node::protocol::BundleSlot {
    node::protocol::BundleSlot {
        veil_nonce: [n; node::veil::NONCE_LEN],
        veiled: vec![n; 64],
    }
}

fn bundle(
    cap: &Capability,
    cookie: admission::cookie::Cookie,
    client_addr: &[u8],
    recipient: [u8; 32],
    slots: Vec<node::protocol::BundleSlot>,
) -> node::protocol::BundleRequest {
    let nonce = node::protocol::bundle_nonce(&recipient, &slots, &[0x5A; node::protocol::BUNDLE_SALT_LEN]);
    let proof = cap.prove(&nonce, 0);
    node::protocol::BundleRequest {
        client_addr: client_addr.to_vec(),
        carrier_id: b"blob".to_vec(),
        cookie: Some(cookie),
        request_nonce: nonce,
        capability_proof: proof,
        recipient,
        slots,
    }
}

/// A legal bundle is admitted once for all its slots.
#[test]
fn a_bundle_on_a_class_is_admitted() {
    let dir = tmp("bundle-ok");
    let mut relay = relay_with_blobs(&dir);
    let client_addr = addr32(0xB1);
    let cap = issued_cap(&mut relay, [0xB1; 32], generous_quota());
    let cookie = relay.issue_cookie_for_test(&client_addr, b"blob", NOW);
    let req = bundle(&cap, cookie, &client_addr, [0xC1; 32], vec![slot(1); 4]);
    assert!(relay.admit_bundle(&req, NOW).is_ok(), "a four-slot bundle must be admitted");
}

/// An off-ladder slot count is refused. Accepting it would let a client opt out of the padding
/// simply by sending a size that is not a rung — which is the whole property, declined.
#[test]
fn a_bundle_off_the_ladder_is_refused() {
    let dir = tmp("bundle-offclass");
    let mut relay = relay_with_blobs(&dir);
    let client_addr = addr32(0xB2);
    let cap = issued_cap(&mut relay, [0xB2; 32], generous_quota());
    for count in [2usize, 3, 5, 17] {
        let cookie = relay.issue_cookie_for_test(&client_addr, b"blob", NOW);
        let req = bundle(&cap, cookie, &client_addr, [0xC2; 32], vec![slot(1); count]);
        assert!(
            matches!(relay.admit_bundle(&req, NOW), Err(Response::Rejected(_))),
            "{count} slots is not a class and must be refused"
        );
    }
}

/// A proof minted for one bundle does not admit another with a slot swapped in.
#[test]
fn a_bundle_proof_does_not_travel_to_a_different_set_of_slots() {
    let dir = tmp("bundle-swap");
    let mut relay = relay_with_blobs(&dir);
    let client_addr = addr32(0xB3);
    let cap = issued_cap(&mut relay, [0xB3; 32], generous_quota());
    let cookie = relay.issue_cookie_for_test(&client_addr, b"blob", NOW);
    let mut req = bundle(&cap, cookie, &client_addr, [0xC3; 32], vec![slot(1); 4]);
    req.slots[2] = slot(9); // the nonce no longer matches
    assert!(
        matches!(relay.admit_bundle(&req, NOW), Err(Response::Rejected(_))),
        "a swapped slot was admitted under the old proof"
    );
}

/// The quota is charged PER SLOT. A capability with room for three requests must not carry a
/// four-slot bundle — otherwise bundling is sixteen messages for the price of one.
#[test]
fn a_bundle_cannot_buy_more_messages_than_the_quota_allows() {
    let dir = tmp("bundle-quota");
    let mut relay = relay_with_blobs(&dir);
    let client_addr = addr32(0xB4);
    let tight = Quota { max_requests: 3, max_bytes: 1 << 20, window_secs: 600 };
    let cap = issued_cap(&mut relay, [0xB4; 32], tight);
    let cookie = relay.issue_cookie_for_test(&client_addr, b"blob", NOW);
    let req = bundle(&cap, cookie, &client_addr, [0xC4; 32], vec![slot(1); 4]);
    assert!(
        matches!(relay.admit_bundle(&req, NOW), Err(Response::Rejected(_))),
        "four slots went through a quota with room for three"
    );
}

/// **Why the bundle nonce carries a salt.** A retransmit exists because a response can be lost:
/// the relay stored the bundle, the sender never heard, and the entries stay queued. If the nonce
/// were a pure function of the bundle's contents, that retransmit would be byte-identical — and
/// the replay filter would refuse it, forever, on the one path that exists to survive a lost
/// response. This test states both halves: the verbatim repeat IS refused (so the hazard is real,
/// not hypothetical), and a re-salted bundle of the SAME slots is admitted.
#[test]
fn an_identical_bundle_can_be_retransmitted_but_a_verbatim_replay_cannot() {
    let dir = tmp("bundle-replay");
    let mut relay = relay_with_blobs(&dir);
    let client_addr = addr32(0xB7);
    let cap = issued_cap(&mut relay, [0xB7; 32], generous_quota());
    let recipient = [0xC7; 32];
    let slots = vec![slot(1), slot(2), slot(3), slot(4)];

    let attempt = |relay: &mut RelayNode, salt: [u8; node::protocol::BUNDLE_SALT_LEN]| {
        let cookie = relay.issue_cookie_for_test(&client_addr, b"blob", NOW);
        let nonce = node::protocol::bundle_nonce(&recipient, &slots, &salt);
        node::protocol::BundleRequest {
            client_addr: client_addr.to_vec(),
            carrier_id: b"blob".to_vec(),
            cookie: Some(cookie),
            capability_proof: cap.prove(&nonce, 0),
            request_nonce: nonce,
            recipient,
            slots: slots.clone(),
        }
    };

    let first = attempt(&mut relay, [0x11; node::protocol::BUNDLE_SALT_LEN]);
    assert!(relay.admit_bundle(&first, NOW).is_ok(), "the first attempt must be admitted");

    // The hazard, demonstrated: the SAME request again is refused as a replay.
    assert!(
        matches!(relay.admit_bundle(&first, NOW), Err(Response::Rejected(_))),
        "a verbatim repeat must be refused — this is exactly what a deterministic nonce would \
         make every retransmit"
    );

    // The escape: same recipient, same slots, fresh salt.
    let retry = attempt(&mut relay, [0x22; node::protocol::BUNDLE_SALT_LEN]);
    assert!(
        relay.admit_bundle(&retry, NOW).is_ok(),
        "a re-salted retransmit of the same bundle must be admitted, or a lost response strands \
         the messages forever"
    );
}
