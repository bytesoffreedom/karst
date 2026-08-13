//! The client's load-bearing e2e: Alice sends → relay (in a thread) → Bob collects.
//! The discriminating detail is that **Bob's identity is saved and RELOADED FROM DISK** before
//! receiving. A generate-and-use-in-memory test would pass without checking persistence at all
//! (the same trap as roll_epoch/TTL). Only reload-then-decrypt proves the stored secret is intact.


use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use client::store::Store;
use relay::node::{BlobPutRequest, BlobResponse, FetchRequest, FetchResponse, Payload, PublishResponse, RelayNode, Response, SessionEnvelope, Transport, WireMessage};
use karst_client_core::peer::Peer;
use node::pqxdh::Account;
use relay::server::{RelayServer};
use karst_transport::socket::{SocketTransport};
use karst_transport::transport::{DirectTcpAdapter, Dest, Path, Socks5Adapter};
use x25519_dalek::PublicKey;

const NOW: u64 = 1_000_000;

/// A unique temporary state directory (one per invocation).
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

/// A relay on an ephemeral port with a dev capability issued and a fixed clock.
/// Returns (address, relay-id = Noise-pub ‖ fetch-auth-pub).
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

/// Like `spawn_relay`, but the relay admits exactly ONE credential of its own — what a
/// production relay actually does (a Private relay mints a random `capability_id + secret` into
/// its `capability.key`; a Public one derives a stateless secret from its own issuer key). The
/// globally-known dev capability is NOT issued here, so a credential from another relay fails
/// admission exactly as it would in production.
fn spawn_relay_admitting(cap: admission::capability::Capability) -> (SocketAddr, client::RelayId) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(cap);
    let fetch_pub = relay.relay_public().to_bytes();
    let server = RelayServer::new(relay, Arc::new(move || NOW));
    let noise_pub = server.noise_public();
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });
    (addr, client::RelayId { noise_pub, fetch_pub })
}

/// A credential with its own id and secret, shaped like the dev one (same scope/quota/validity).
fn own_capability(id: u8, secret: u8) -> admission::capability::Capability {
    let mut cap = client::dev_capability();
    cap.capability_id = [id; 16];
    cap.secret = [secret; 32];
    cap
}

/// The connection context for a spawned relay (single direct path, no proxy).
/// Ask a relay for ONE one-time prekey over the admission-gated path, driving the cookie
/// round trip by hand. The public `FetchBundle` never carries an OPK any more (R2-3), so any
/// test that wants one has to present a capability — exactly like a real sender does.
fn opk_request(
    ik: &[u8; 32],
    cookie: Option<admission::cookie::Cookie>,
    n: u64,
) -> relay::node::BundleOpkRequest {
    let cap = client::dev_capability();
    let nonce = format!("opk-probe-{n}").into_bytes();
    relay::node::BundleOpkRequest {
        ik: *ik,
        client_addr: format!("probe-{n}").into_bytes(),
        carrier_id: b"test".to_vec(),
        cookie,
        request_nonce: nonce.clone(),
        capability_proof: cap.prove(&nonce, 0),
    }
}

fn drain_one_opk(
    node: &mut RelayNode,
    ik: &[u8; 32],
    now: u64,
) -> Option<node::pqxdh::PreKeyBundle> {
    use relay::node::BundleOpkResponse;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut req = opk_request(ik, None, n);
    for _ in 0..2 {
        match node.handle_fetch_bundle_opk(&req, now) {
            BundleOpkResponse::NeedCookie(c) => req.cookie = Some(c),
            BundleOpkResponse::Bundle(b) => return b,
            BundleOpkResponse::Rejected(e) => panic!("gated bundle fetch rejected: {e}"),
        }
    }
    panic!("persistent cookie challenge");
}

fn fetch_opk_bundle(
    addr: SocketAddr,
    id: &client::RelayId,
    ik: &[u8; 32],
    now: u64,
) -> Option<node::pqxdh::PreKeyBundle> {
    use relay::node::{BundleOpkResponse, Transport};
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1_000);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let t = SocketTransport::new(addr, id.noise_pub);
    let mut req = opk_request(ik, None, n);
    for _ in 0..2 {
        match t.fetch_bundle_opk(&req, now).expect("transport") {
            BundleOpkResponse::NeedCookie(c) => req.cookie = Some(c),
            BundleOpkResponse::Bundle(b) => return b,
            BundleOpkResponse::Rejected(e) => panic!("gated bundle fetch rejected: {e}"),
        }
    }
    panic!("persistent cookie challenge");
}

fn ctx(addr: SocketAddr, id: &client::RelayId) -> client::Relay {
    client::Relay::new(addr, *id, None)
}

/// Like `spawn_relay`, but also hands back a handle to the shared relay state so a test
/// can assert what the mailbox holds AFTER the serving thread has processed requests —
/// the only way to tell a working over-the-wire ACK (drained) from a no-op (still leased).
fn spawn_relay_handle() -> (SocketAddr, client::RelayId, Arc<RwLock<RelayNode>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(client::dev_capability());
    let fetch_pub = relay.relay_public().to_bytes();
    let server = RelayServer::new(relay, Arc::new(move || NOW));
    let noise_pub = server.noise_public();
    let handle = server.relay_handle();
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });
    (addr, client::RelayId { noise_pub, fetch_pub }, handle)
}

/// Like `spawn_relay` but with the §15 blob store enabled (temp dir).
fn spawn_relay_with_blobs() -> (SocketAddr, client::RelayId) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(client::dev_capability());
    relay.enable_blobs(temp_dir("blobs"), 0, relay::node::BlobPersistence::Durable).unwrap();
    let fetch_pub = relay.relay_public().to_bytes();
    let server = RelayServer::new(relay, Arc::new(move || NOW));
    let noise_pub = server.noise_public();
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });
    (addr, client::RelayId { noise_pub, fetch_pub })
}

/// End-to-end §15 large-file path through the REAL relay socket: a multi-chunk file is
/// streamed up as an E2E blob and streamed back down byte-identical, with the plaintext
/// hash verified on the way out. Exercises multiple round-trips, the cookie challenge,
/// and the fixed-size framing — the discriminating test for the whole blob transport.
#[test]
fn blob_upload_download_roundtrips_through_relay() {
    let (addr, rid) = spawn_relay_with_blobs();
    // > 2 chunks (+ a short tail) so streaming, ordering, and is_last all matter.
    let data: Vec<u8> =
        (0..(client::blob::BLOB_CHUNK * 2 + 123)).map(|i| (i.wrapping_mul(7)) as u8).collect();

    let (id, key, hash, count) =
        client::blob_upload(&ctx(addr, &rid), &client::dev_capability(), std::io::Cursor::new(&data), data.len() as u64)
            .expect("upload");
    assert_eq!(count, 3, "two full chunks + a short tail");

    let out = client::blob_download(&ctx(addr, &rid), id, key, count, hash, Vec::new())
        .expect("download");
    assert_eq!(out, data, "blob round-trips byte-identical through the relay");

    // A wrong key must not silently produce garbage — decryption fails closed.
    let bad = client::blob::random32();
    assert!(
        client::blob_download(&ctx(addr, &rid), id, bad, count, hash, Vec::new()).is_err(),
        "wrong key → download fails, no garbage file"
    );
}

/// Proof-of-retrievability: after a real upload, `verify_durability` fetches a chunk back and
/// confirms the relay is holding the blob; against an unknown blob id it returns `false` (nothing
/// to retrieve). A wrong key means the returned bytes don't authenticate → also `false`.
#[test]
fn verify_durability_confirms_a_parked_blob_and_rejects_a_missing_one() {
    let (addr, rid) = spawn_relay_with_blobs();
    let data: Vec<u8> = (0..(client::blob::BLOB_CHUNK * 2 + 5)).map(|i| (i * 3) as u8).collect();
    let (id, key, _hash, count) =
        client::blob_upload(&ctx(addr, &rid), &client::dev_capability(), std::io::Cursor::new(&data), data.len() as u64).expect("upload");

    assert!(client::verify_durability(&ctx(addr, &rid), id, key, count).unwrap(), "the relay holds the blob");
    // An unknown blob id retrieves nothing.
    assert!(!client::verify_durability(&ctx(addr, &rid), client::blob::random32(), key, count).unwrap());
    // Right blob, wrong key: the bytes come back but don't authenticate → not proven.
    assert!(!client::verify_durability(&ctx(addr, &rid), id, client::blob::random32(), count).unwrap());
}

/// #28 resumable UPLOAD: an upload that crashed after K chunks RESUMES from the relay's watermark
/// (`blob_stat`), re-sending only K..count, and completes byte-identical. Also pins `BlobStat`.
#[test]
fn blob_upload_resumes_from_the_relay_watermark() {
    let (addr, rid) = spawn_relay_with_blobs();
    let r = ctx(addr, &rid);
    let chunk = client::blob::BLOB_CHUNK;
    let data: Vec<u8> = (0..(chunk * 3 + 9)).map(|i| (i * 5) as u8).collect(); // 4 chunks
    let size = data.len() as u64;
    let id = client::blob::random32();
    let key = client::blob::random32();

    // Fresh blob: the relay has never seen it.
    assert_eq!(client::blob_stat(&r, id, &key).unwrap(), None, "unknown blob → no watermark");

    // "Crash" after 2 chunks: a reader with only 2*chunk bytes but a size claiming 4 chunks stores
    // chunks 0,1 then errors reading chunk 2.
    let partial = std::io::Cursor::new(data[..2 * chunk].to_vec());
    assert!(
        client::blob_upload_resumable(&r, &client::dev_capability(), partial, size, id, key).is_err(),
        "the truncated attempt fails mid-upload"
    );
    assert_eq!(client::blob_stat(&r, id, &key).unwrap(), Some((2, 4, false)), "watermark parked at chunk 2");

    // Resume with the FULL file: skips 0,1 (hashes them for the FileRef), uploads only 2,3.
    let (rid2, rkey2, hash, count) =
        client::blob_upload_resumable(&r, &client::dev_capability(), std::io::Cursor::new(&data), size, id, key).expect("resume completes");
    assert_eq!((rid2, rkey2, count), (id, key, 4));
    assert_eq!(client::blob_stat(&r, id, &key).unwrap(), Some((4, 4, true)), "blob now complete");

    // The resumed upload downloads back byte-identical, hash verified.
    let out = client::blob_download(&r, id, key, count, hash, Vec::new()).expect("download");
    assert_eq!(out, data, "resumed upload is byte-identical to the original");

    // Idempotent: re-running a completed upload re-sends nothing and returns the same FileRef.
    let (_, _, hash2, _) =
        client::blob_upload_resumable(&r, &client::dev_capability(), std::io::Cursor::new(&data), size, id, key).expect("re-run is a no-op");
    assert_eq!(hash2, hash, "the hash is stable across a re-run");
}

/// PR-b resume: a download that crashed after K chunks RESUMES the same partial (skipping the
/// K already-fetched chunks) and completes byte-identical, hash-verified. Builds the partial
/// exactly as a real interrupted download would (K checkpointed records), then drives it.
#[test]
fn a_partial_download_resumes_and_completes_byte_identical() {
    use std::io::Write;
    use std::sync::atomic::AtomicBool;
    let (addr, rid) = spawn_relay_with_blobs();
    let chunk = client::blob::BLOB_CHUNK;
    let data: Vec<u8> = (0..(chunk * 3 + 200)).map(|i| (i * 5) as u8).collect(); // 4 chunks
    let (blob_id, key, hash, count) =
        client::blob_upload(&ctx(addr, &rid), &client::dev_capability(), std::io::Cursor::new(&data), data.len() as u64).unwrap();

    let dir = temp_dir("resume-dl");
    let store = Store::unlock(&dir, b"pw").unwrap();

    // Simulate a crash after 2 of the 4 chunks: write them as durable checkpointed records.
    let (partial_id, mut w) = store.received_file_writer("doc.bin").unwrap();
    for i in 0..2usize {
        w.write_all(&data[i * chunk..(i * chunk + chunk).min(data.len())]).unwrap();
        w.checkpoint().unwrap();
    }
    drop(w); // crash: records durable, file never finished

    let pd = client::store::PendingDownload {
        blob_id, key, hash, name: "doc.bin".into(), size: data.len() as u64, chunks: count,
        sender: [1u8; 32], ts: NOW, queued_at: NOW, container_id: Some(partial_id.clone()),
    };
    store.add_pending_download(&pd).unwrap();

    let never = AtomicBool::new(false);
    let fid = match client::download_blob(&store, &ctx(addr, &rid), &pd, NOW, &never, |_, _| {}) {
        client::DownloadOutcome::Done(id) => id,
        other => panic!("expected Done resuming: {}", matches!(other, client::DownloadOutcome::Done(_))),
    };
    assert_eq!(fid, partial_id, "resumed the SAME container, not a fresh one");
    assert_eq!(store.read_received_file(&fid).unwrap(), data, "resumed download is byte-identical");
    assert!(store.list_pending_downloads().unwrap().is_empty(), "pending cleared on completion");

    std::fs::remove_dir_all(&dir).ok();
}

/// A crash can leave a TORN trailing record (the writer only fsyncs whole records). Resume must
/// truncate it before appending — else the file never verifies and the download is stuck. Builds
/// K clean chunks + garbage tail, resumes, and asserts it completes correctly.
#[test]
fn resume_truncates_a_torn_trailing_record() {
    use std::io::Write;
    use std::sync::atomic::AtomicBool;
    let (addr, rid) = spawn_relay_with_blobs();
    let chunk = client::blob::BLOB_CHUNK;
    let data: Vec<u8> = (0..(chunk * 2 + 10)).map(|i| (i * 7) as u8).collect(); // 3 chunks
    let (blob_id, key, hash, count) =
        client::blob_upload(&ctx(addr, &rid), &client::dev_capability(), std::io::Cursor::new(&data), data.len() as u64).unwrap();

    let dir = temp_dir("resume-torn");
    let store = Store::unlock(&dir, b"pw").unwrap();

    let (partial_id, mut w) = store.received_file_writer("t.bin").unwrap();
    w.write_all(&data[0..chunk]).unwrap(); // one clean chunk
    w.checkpoint().unwrap();
    drop(w);
    // Append a torn/garbage trailing record (a bogus length prefix + junk).
    let mut f = std::fs::OpenOptions::new().append(true).open(dir.join("files").join(format!("{partial_id}.dat"))).unwrap();
    f.write_all(&[0xFF, 0xFF, 0xFF, 0x7F, 1, 2, 3]).unwrap();
    drop(f);

    let pd = client::store::PendingDownload {
        blob_id, key, hash, name: "t.bin".into(), size: data.len() as u64, chunks: count,
        sender: [2u8; 32], ts: NOW, queued_at: NOW, container_id: Some(partial_id.clone()),
    };
    store.add_pending_download(&pd).unwrap();

    let never = AtomicBool::new(false);
    match client::download_blob(&store, &ctx(addr, &rid), &pd, NOW, &never, |_, _| {}) {
        client::DownloadOutcome::Done(id) => {
            assert_eq!(store.read_received_file(&id).unwrap(), data, "torn tail truncated, file correct");
        }
        other => panic!("expected Done after truncating the torn tail: {}", matches!(other, client::DownloadOutcome::Done(_))),
    }

    std::fs::remove_dir_all(&dir).ok();
}

/// The load-bearing new receive behavior: a FileRef arriving through `recv_session` is
/// persisted as a pending download (BEFORE the ack), so it survives even though the relay
/// then drops the message. Sends a real FileRef E2E and asserts the recipient recorded it.
#[test]
fn recv_session_persists_a_fileref_as_a_pending_download() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("fileref-a");
    let bdir = temp_dir("fileref-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    assert!(matches!(
        client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW),
        PublishResponse::Published
    ));

    // Alice sends a FileRef (a blob pointer) as a §2.1 message.
    let fr = client::content::Content::FileRef {
        blob_id: [3u8; 32], key: [4u8; 32], hash: [5u8; 32], name: "big.bin".into(), size: 9_000, chunks: 3,
    };
    client::send_session(&astore, &r, &bob_ik, &client::content::encode(&fr), NOW).unwrap();

    assert!(bstore.list_pending_downloads().unwrap().is_empty(), "none before receive");
    let _ = client::recv_session(&bstore, &r, NOW).unwrap();
    let pend = bstore.list_pending_downloads().unwrap();
    assert_eq!(pend.len(), 1, "recv_session persisted the FileRef as a pending download");
    assert_eq!(pend[0].blob_id, [3u8; 32]);
    assert_eq!(pend[0].name, "big.bin");
    assert_eq!(pend[0].chunks, 3);

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// #28 end-to-end over the REAL socket: `send_file` on a LARGE file routes to the blob path
/// (resumable upload + a `FileRef`), the recipient's `recv_session` persists it as a pending
/// download, and driving that download reconstructs the file BYTE-IDENTICAL. The whole CLI
/// large-file send↔receive path.
#[test]
fn send_file_large_uploads_a_blob_that_the_recipient_downloads_byte_identical() {
    let (addr, rid) = spawn_relay_with_blobs();
    let astore = Store::unlock(temp_dir("sfl-a"), b"pw").unwrap();
    let bstore = Store::unlock(temp_dir("sfl-b"), b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&rid, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&rid, &client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(addr, &rid);
    assert!(matches!(
        client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW),
        PublishResponse::Published
    ));

    // A file well past the inline ceiling AND multiple blob chunks → exercises the blob path.
    assert!(client::blob::BLOB_CHUNK as u64 * 2 > client::content::MAX_FILE_SIZE);
    let data: Vec<u8> = (0..(client::blob::BLOB_CHUNK * 2 + 4321)).map(|i| (i * 11) as u8).collect();
    client::send_file(&astore, &r, &bob_ik, "big.bin", &data, NOW).expect("send a large file");
    assert!(astore.list_pending_uploads().unwrap().is_empty(), "the pending-upload record is cleared on success");

    // Bob receives the FileRef and drives the download.
    let _ = client::recv_session(&bstore, &r, NOW).unwrap();
    let pend = bstore.list_pending_downloads().unwrap();
    assert_eq!(pend.len(), 1, "the FileRef became a pending download");
    assert_eq!(pend[0].name, "big.bin");
    let never = std::sync::atomic::AtomicBool::new(false);
    let fid = match client::download_blob(&bstore, &r, &pend[0], NOW, &never, |_, _| {}) {
        client::DownloadOutcome::Done(fid) => fid,
        _ => panic!("the download did not complete"),
    };
    // Export the (sealed) received file and compare byte-for-byte.
    let out = temp_dir("sfl-out").join("got.bin");
    bstore.export_received_file(&fid, &out).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), data, "the received large file is byte-identical");
}

/// Crash-safe large-file download: a FileRef persisted as a pending download (what the
/// receive path now does before acking) survives a "crash" — a fresh `download_blob` re-drives
/// it to completion, records the file with its blob_id, and drops the pending entry. Running it
/// AGAIN is idempotent (already recorded → `Done`, no second file). This is the loss-fix: a
/// FileRef is no longer consumed-then-lost if the download didn't finish.
#[test]
fn a_pending_download_survives_a_crash_and_is_idempotent() {
    use std::sync::atomic::AtomicBool;
    let (addr, rid) = spawn_relay_with_blobs();
    let data: Vec<u8> = (0..(client::blob::BLOB_CHUNK * 2 + 45)).map(|i| (i * 3) as u8).collect();
    let (blob_id, key, hash, chunks) =
        client::blob_upload(&ctx(addr, &rid), &client::dev_capability(), std::io::Cursor::new(&data), data.len() as u64).unwrap();

    let dir = temp_dir("pending-dl");
    let store = Store::unlock(&dir, b"pw").unwrap();
    let sender = [9u8; 32];
    // Receive-side persisted this before acking; the download never ran (the "crash").
    let pd = client::store::PendingDownload {
        blob_id, key, hash, name: "photo.bin".into(), size: data.len() as u64, chunks, sender,
        ts: NOW, queued_at: NOW, container_id: None,
    };
    store.add_pending_download(&pd).unwrap();
    assert_eq!(store.list_pending_downloads().unwrap().len(), 1, "pending before retry");

    // Retry after the crash: drives to completion.
    let never = AtomicBool::new(false);
    let out = client::download_blob(&store, &ctx(addr, &rid), &pd, NOW, &never, |_, _| {});
    let fid = match out {
        client::DownloadOutcome::Done(id) => id,
        client::DownloadOutcome::GaveUp(e) | client::DownloadOutcome::Retry(e) => panic!("expected Done: {e}"),
    };
    assert!(store.list_pending_downloads().unwrap().is_empty(), "pending dropped on success");
    let files = store.list_received_files().unwrap();
    assert_eq!(files.len(), 1, "recorded once");
    assert_eq!(files[0].blob_id, blob_id, "recorded with its blob_id for idempotency");
    assert_eq!(store.read_received_file(&fid).unwrap(), data, "bytes round-trip");

    // Idempotent: a second drive (crash after record, before drop) records nothing new.
    match client::download_blob(&store, &ctx(addr, &rid), &pd, NOW, &never, |_, _| {}) {
        client::DownloadOutcome::Done(_) => {}
        other => panic!("expected idempotent Done: {}", matches!(other, client::DownloadOutcome::Done(_))),
    }
    assert_eq!(store.list_received_files().unwrap().len(), 1, "no duplicate file on the idempotent retry");

    std::fs::remove_dir_all(&dir).ok();
}

/// **Metadata audit regression.** A deposit must not carry the sender's identity key
/// anywhere the relay can read it: not in `client_addr`, not in `request_nonce`. Both
/// used to BE the IK (and IK‖counter) — the relay read the social graph straight off
/// the wire, sender next to recipient, plus a free per-identity message counter.
/// Discriminating: restore the IK in either field → this reds.
///
/// Scope, stated honestly: the transport fields are sealed for every deposit, but a
/// conversation OPENER still names the sender inside the payload — pinned by the test
/// below, because a gap nobody tests is a gap everyone forgets.
#[test]
fn a_deposit_does_not_carry_the_senders_identity_in_the_transport_fields() {
    let dir = temp_dir("meta-wire");
    let store = Store::unlock(&dir, b"pw").unwrap();
    let account = client::seed::derive(&seed_provision(&store)).account;
    let alice_ik = account.identity_public();
    let sent = Arc::new(Mutex::new(Vec::new()));
    let mut peer = Peer::new(
        RecordingTransport { sent: sent.clone() },
        account,
        client::dev_capability(),
        PublicKey::from([7u8; 32]),
    );
    let bob = client::seed::derive(&[3u8; client::seed::ENTROPY_BYTES]).account;
    let bob_ik = bob.identity_public();
    peer.connect_with_bundle(&bob.prekey_bundle()).expect("session opens");
    peer.send(&bob_ik, b"opener", NOW); // Initial
    peer.send(&bob_ik, b"hello", NOW); // Ratchet — the common case

    let msgs = sent.lock().unwrap();
    assert!(!msgs.is_empty(), "something went out");
    for m in msgs.iter() {
        assert!(
            !m.client_addr.windows(32).any(|w| w == alice_ik),
            "client_addr must not be the sender's IK — that IS the social graph, in plaintext"
        );
        assert!(
            !m.request_nonce.windows(32).any(|w| w == alice_ik),
            "request_nonce must not embed the sender's IK (it leaked a per-identity counter too)"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// **The opener no longer names the sender — proven by scanning the WHOLE envelope.**
///
/// A field-level check is what "moved the leak to another field" would pass; a byte scan
/// of everything the relay receives is what it fails. So: serialize the entire deposit
/// the relay would see and assert no 32-byte run equals the sender's identity key.
///
/// This test was the inverse until this slice landed — it used to assert the leak
/// EXISTED (`KeyAgreement.ik_a_pub` in the clear), because an untested gap is one
/// everyone assumes is closed. Its flip is the record that the work is done.
///
/// Discriminating: an opener that is not sealed cannot even be built any more (#232) — that
/// shape was removed from the wire, so this pins the sealed path itself.
///
/// Scope, stated exactly: this removes the SENDER from the opener. The recipient's
/// mailbox is still named (until rotating drop-boxes), and the fetch-names-you
/// correlation ceiling is unchanged.
#[test]
fn a_sealed_opener_carries_the_senders_identity_nowhere_on_the_wire() {
    let dir = temp_dir("sealed-opener");
    let store = Store::unlock(&dir, b"pw").unwrap();
    let account = client::seed::derive(&seed_provision(&store)).account;
    let alice_ik = account.identity_public();
    let sent = Arc::new(Mutex::new(Vec::new()));
    let mut peer = Peer::new(
        RecordingTransport { sent: sent.clone() },
        account,
        client::dev_capability(),
        PublicKey::from([7u8; 32]),
    );
    let bob = client::seed::derive(&[3u8; client::seed::ENTROPY_BYTES]).account;
    peer.connect_with_bundle(&bob.prekey_bundle()).expect("session opens");
    peer.send(&bob.identity_public(), b"opener", NOW);

    let msgs = sent.lock().unwrap();
    let opener = msgs.first().expect("the opener went out");
    // Everything the relay receives, as bytes — payload included.
    let on_wire = postcard::to_stdvec(opener).expect("encode the deposit");
    assert!(
        !on_wire.windows(32).any(|w| w == alice_ik),
        "the sender's IK must appear NOWHERE in the opener the relay sees — not in a \
         transport field, not in the payload"
    );
    // And it really is the sealed variant, not an accident of encoding.
    match &opener.payload {
        Payload::Session(SessionEnvelope::InitialSealed { .. }) => {}
        _ => panic!("a new conversation must open with a SEALED opener"),
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// **A post-quantum opener must fit the admission ceiling — with a real message in it.**
///
/// An ML-KEM-768 key agreement is ~1.1 KB on its own, so with the old 1400-byte stage-0
/// ceiling a first contact carrying a message longer than ~120 B was dropped as
/// oversize — silently, `DropNoReply`, no error to the sender. A spec mandating PQ key
/// agreement and a ceiling too small to carry one is inconsistent; sealing the opener
/// only made the gap wider and finally made it fail loudly in the suite.
///
/// This pins the property, not the constant: a MAXIMUM-length first message survives
/// first contact through a real relay. Discriminating: put `MAX_PACKET_SIZE` back to
/// 1400 → the opener is dropped and Bob receives nothing.
#[test]
fn a_post_quantum_opener_carries_a_full_length_first_message() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("opener-budget-a");
    let bdir = temp_dir("opener-budget-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    // The biggest text a message may carry, as the very FIRST thing said.
    let text = vec![b'x'; client::content::MAX_TEXT_BYTES];
    client::send_text(&astore, &r, &bob_ik, &text, NOW, NOW).expect("a full first message sends");

    let got = client::recv_session(&bstore, &r, NOW).unwrap();
    let recv = got.into_iter().flatten().next().expect("first contact arrived, not silently dropped");
    match client::content::decode(&recv.plaintext).expect("content decodes") {
        client::content::Content::TextStamped { text: t, .. } => {
            assert_eq!(t.len(), client::content::MAX_TEXT_BYTES, "the whole message survived the opener")
        }
        other => panic!("expected a stamped text: {other:?}"),
    }
    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// A route offer travels as an ordinary sealed session message and arrives as a decodable
/// `Content::RouteOffer` carrying the sender's routes and the shared relay's Noise key (so the
/// recipient can tell the offer names a relay they already use). This backs the desktop
/// migration-UX slice (#25): the offer is delivered and readable, never auto-applied.
#[test]
fn a_route_offer_round_trips_with_its_routes_and_relay_key() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("routeoffer-a");
    let bdir = temp_dir("routeoffer-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    let routes = "wss://relay.example:443 socks5://127.0.0.1:9050";
    client::send_route_offer(&astore, &r, &bob_ik, routes, NOW).expect("route offer sends");

    let got = client::recv_session(&bstore, &r, NOW).unwrap();
    let recv = got.into_iter().flatten().next().expect("the offer arrived");
    match client::content::decode(&recv.plaintext).expect("content decodes") {
        client::content::Content::RouteOffer { relay_noise_pub, routes: got_routes } => {
            assert_eq!(got_routes, routes, "the offered routes survived");
            assert_eq!(relay_noise_pub, r.id.noise_pub, "the offer names the shared relay");
        }
        other => panic!("expected a route offer: {other:?}"),
    }
    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// `recv_session` now persists incoming TEXT to history ITSELF, plaintext-first (before it
/// saves the ratchet or acks), so the caller must NOT append it again. This pins that the
/// message lands in Bob's on-disk history with a single `recv_session` call and no manual
/// append — the ownership move that closes the loss windows. Neuter `persist_incoming_history`
/// (make it a no-op) and this reddens.
#[test]
fn recv_session_persists_incoming_text_to_history() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("hist-persist-a");
    let bdir = temp_dir("hist-persist-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    assert!(bstore.load_history().unwrap().is_empty(), "history starts empty");
    client::send_text(&astore, &r, &bob_ik, b"persist me", NOW, NOW).unwrap();
    let _ = client::recv_session(&bstore, &r, NOW).unwrap();

    // recv_session persisted it — no manual append by the caller.
    let hist = bstore.load_history().unwrap();
    assert_eq!(hist.len(), 1, "exactly one record, written by recv_session");
    assert!(!hist[0].from_me, "it is an incoming record");
    assert_eq!(hist[0].peer_ik, alice_ik, "attributed to the sender");
    assert_eq!(hist[0].text, b"persist me", "the plaintext is durable");

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// PROXY-IDENTITY MODEL, two-party over the relay: a message from Alice's PROXY to Bob's PROXY
/// delivers, and the sender the recipient (and relay) sees is the PROXY identity — never the root.
/// This is the wire-level proof that the root identity stays off the network. Publish Bob's PROXY
/// bundle (not his root), send from Alice's proxy handle, and assert the received sender == Alice's
/// proxy IK and != her root IK.
#[test]
fn a_message_between_proxies_delivers_and_the_root_ik_never_appears() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("proxy-a");
    let bdir = temp_dir("proxy-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    astore.create_proxy("p0", NOW).unwrap(); // mints index 0's own random secret (#207)
    bstore.create_proxy("p0", NOW).unwrap();

    // Both parties act AS their proxy 0 — the only thing that ever touches the relay.
    let a = astore.as_proxy(0);
    let b = bstore.as_proxy(0);
    let a_root = astore.load_account().unwrap().identity_public();
    let a_proxy = a.load_account().unwrap().identity_public();
    let b_proxy = b.load_account().unwrap().identity_public();
    assert_ne!(a_proxy, a_root, "the proxy address is not the root");

    let r = ctx(relay_addr, &relay_id);
    // Bob's PROXY publishes its bundle (the root never publishes).
    let pr = client::publish_bundle(&r, b.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "proxy publish: {pr:?}");

    // Alice's proxy sends to Bob's PROXY address.
    client::send_text(&a, &r, &b_proxy, b"hi via proxy", NOW, NOW).unwrap();

    // Bob's proxy receives it, and the sender on the wire is Alice's PROXY, not her root.
    let got = client::recv_session(&b, &r, NOW).unwrap();
    let msg = got.into_iter().flatten().next().expect("delivered to the proxy mailbox");
    assert_eq!(msg.sender, a_proxy, "sender is the proxy identity");
    assert_ne!(msg.sender, a_root, "the root IK never appears on the wire");
    match client::content::decode(&msg.plaintext).unwrap() {
        client::content::Content::TextStamped { text, .. } => assert_eq!(text, b"hi via proxy"),
        other => panic!("expected text, got {other:?}"),
    }
    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// CRYPTO-04, the client half. A relay that serves NO one-time prekey downgrades first contact
/// from 4-DH to 3-DH. `Peer::connect` reports that, but a report nobody binds is not a report —
/// `peer.connect(..)?;` compiles fine and throws the value away, which is exactly what the client
/// used to do. So the fact has to land somewhere durable.
///
/// Discriminating: the SAME send, run once against a relay holding OPKs and once against a relay
/// that was never given any. Only the second may be recorded, so it cannot pass by marking
/// everything (or nothing).
#[test]
fn a_first_contact_without_a_one_time_prekey_is_recorded_as_reduced() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("redfs-a");
    let bdir = temp_dir("redfs-b");
    let cdir = temp_dir("redfs-c");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    let cstore = Store::unlock(&cdir, b"pw").unwrap();
    for st in [&astore, &bstore, &cstore] {
        seed_provision(st);
        st.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    }
    let r = ctx(relay_addr, &relay_id);

    // Bob publishes WITH one-time prekeys; Carol publishes a bundle with none at all.
    client::publish_with_opks(&bstore, &r,  NOW).unwrap();
    client::publish_bundle(
        &r,
        cstore.load_account().unwrap(),
        client::dev_capability(),
        NOW,
    );
    let b_ik = bstore.load_account().unwrap().identity_public();
    let c_ik = cstore.load_account().unwrap().identity_public();

    client::send_text(&astore, &r, &b_ik, b"full strength", NOW, NOW).unwrap();
    client::send_text(&astore, &r, &c_ik, b"reduced", NOW, NOW).unwrap();

    let reduced = astore.load_reduced_fs().unwrap();
    assert!(
        reduced.contains(&c_ik),
        "first contact with no one-time prekey must be recorded — otherwise the downgrade is \
         invisible to everything above the crypto layer"
    );
    assert!(
        !reduced.contains(&b_ik),
        "a 4-DH first contact must NOT be flagged, or the flag means nothing"
    );

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
    std::fs::remove_dir_all(&cdir).ok();
}

/// PROXY + ONE-TIME PREKEYS, the exact desktop path: Bob's proxy publishes its bundle WITH a
/// batch of OPKs (`publish_with_opks`, as `do_publish` does), Alice's proxy sends (first contact
/// consumes one of those OPKs → 4-DH opener), and Bob's proxy receives via `recv_session_multi`
/// (as the desktop `poll` does). This mirrors the live desktop where the message NEVER arrived —
/// isolating whether the proxy OPK first-contact receive is the break.
#[test]
fn a_proxy_message_via_a_published_opk_delivers() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("proxyopk-a");
    let bdir = temp_dir("proxyopk-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    astore.create_proxy("p0", NOW).unwrap(); // mints index 0's own random secret (#207)
    bstore.create_proxy("p0", NOW).unwrap();

    let a = astore.as_proxy(0);
    let b = bstore.as_proxy(0);
    let b_proxy = b.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    // Desktop path: publish the proxy bundle WITH one-time prekeys (4-DH first contact).
    client::publish_with_opks(&b, &r,  NOW).unwrap();

    // Alice's proxy sends — first contact consumes one of Bob's published OPKs.
    client::send_text(&a, &r, &b_proxy, b"hi via proxy opk", NOW, NOW).unwrap();

    // Bob's proxy receives via the multi-homed path the desktop poll uses.
    let poll = recv_multi(&b, std::slice::from_ref(&r), NOW).unwrap();
    let msg = poll
        .messages
        .into_iter()
        .flatten()
        .next()
        .expect("proxy message via a published OPK must arrive");
    match client::content::decode(&msg.plaintext).unwrap() {
        client::content::Content::TextStamped { text, .. } => assert_eq!(text, b"hi via proxy opk"),
        other => panic!("expected text, got {other:?}"),
    }
    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// BUG C — OPK republish must not stockpile duplicates. `publish_with_opks` used to advertise the
/// WHOLE unconsumed batch every call, and the relay appends a publish's OPKs with no dedup — so a
/// second publish (a keepalive republish, no consumption between) left the relay holding two copies
/// of every key. `get_bundle` pops one per fetch, so past the number of DISTINCT keys it hands a
/// key out AGAIN — and two first-contacts binding the same OPK lose whichever the recipient accepts
/// second (its OPK secret was consumed by the first accept → `accept_key_agreement` returns None).
/// Discriminating: drain every OPK the relay will hand out and require each to be DISTINCT. Neuter
/// the fix (advertise the full set again) and the (OPK_TARGET+1)-th fetch repeats a key → RED.
#[test]
fn republishing_opks_never_hands_the_same_prekey_twice() {
    let (relay_addr, relay_id, relay) = spawn_relay_handle();
    let bdir = temp_dir("opkrepub-b");
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&bstore);
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.create_proxy("p0", NOW).unwrap(); // mints index 0's own random secret (#207)
    let b = bstore.as_proxy(0);
    let b_ik = b.load_account().unwrap().identity_public();
    let r = ctx(relay_addr, &relay_id);

    // Publish a full OPK batch, then REPUBLISH it unchanged (no consumption between).
    client::publish_with_opks(&b, &r,  NOW).unwrap();
    client::publish_with_opks(&b, &r,  NOW).unwrap();

    // Drain every OPK the relay will hand out; each must be distinct, then the batch exhausts
    // (opk_pub == None → 3-DH fallback). A repeat means a republished duplicate is being served.
    let mut seen = std::collections::HashSet::new();
    let mut node = relay.write().unwrap();
    // Via the ADMISSION-GATED path: the public read never hands out a one-time prekey any more
    // (R2-3), so draining now costs a capability — which is the point.
    while let Some(bundle) = drain_one_opk(&mut node, &b_ik, NOW) {
        match bundle.opk {
            Some(opk) => assert!(
                seen.insert(opk.key),
                "the relay handed out the same OPK twice after a republish (Bug C)"
            ),
            None => break,
        }
    }
    drop(node);
    assert_eq!(
        seen.len(),
        client::OPK_TARGET,
        "one full distinct batch should be available (no duplicates, none dropped)"
    );

    std::fs::remove_dir_all(&bdir).ok();
}

/// STORY, two-party: an ephemeral publication delivers over the relay carrying its self-destruct
/// time, so the recipient can drop it when dead and show a countdown while live.
#[test]
fn a_story_delivers_with_its_expiry() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("story-a");
    let bdir = temp_dir("story-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    let id = client::store::random16();
    let expire = NOW + 86_400;
    client::send_story(&astore, &r, &bob_ik, id, "gone tomorrow", NOW, expire, NOW).unwrap();

    let got = client::recv_session(&bstore, &r, NOW).unwrap();
    let msg = got.into_iter().flatten().next().expect("the story arrived");
    match client::content::decode(&msg.plaintext).unwrap() {
        client::content::Content::Story { id: gid, text, expire_at, .. } => {
            assert_eq!(gid, id);
            assert_eq!(text, "gone tomorrow");
            assert_eq!(expire_at, expire, "carries its self-destruct time");
        }
        other => panic!("expected a story, got {other:?}"),
    }
    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// AVATAR, two-party: Alice's avatar reaches Bob, reassembles byte-identical, and — simulating
/// the desktop poll glue — lands in Bob's peer profile via `set_peer_avatar`. This covers the
/// receive path (chunks → `Reassembler` → `Assembled::Avatar` → peer-profile cache) end-to-end,
/// which was only unit-tested at the reassembler before.
#[test]
fn an_avatar_delivers_and_lands_in_the_recipients_peer_profile() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("avatar-a");
    let bdir = temp_dir("avatar-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    let avatar = vec![7u8; 5000]; // stand-in PNG bytes, multi-chunk
    client::send_avatar(&astore, &r, &bob_ik, &avatar, NOW).unwrap();

    // Receive + reassemble exactly as the desktop poll does (per-sender Reassembler).
    let got = recv_multi(&bstore, std::slice::from_ref(&r), NOW).unwrap();
    let mut re = client::content::Reassembler::new();
    let mut assembled = None;
    for m in got.messages.into_iter().flatten() {
        if let Ok(c) = client::content::decode(&m.plaintext) {
            if let Ok(Some(a)) = re.offer(c, NOW) {
                assembled = Some((m.sender, a));
            }
        }
    }
    match assembled.expect("the avatar reassembled") {
        (sender, client::content::Assembled::Avatar { bytes }) => {
            assert_eq!(bytes, avatar, "byte-identical");
            bstore.set_peer_avatar(sender, bytes).unwrap(); // the desktop glue
        }
        _ => panic!("expected an avatar"),
    }

    // Bob's peer-profile cache now holds Alice's avatar, keyed by her IK.
    let profiles = bstore.load_peer_profiles().unwrap();
    assert_eq!(profiles.get(&alice_ik).and_then(|p| p.avatar.clone()), Some(avatar), "cached under the sender's IK");
    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// CHANNEL MIGRATION, two-party: Alice moves Bob from her channel P0 to a fresh P1 by sending a
/// `ChannelMigrate` over the EXISTING (authenticated) session on P0. Bob applies it — his contact
/// for Alice re-points to P1 and drops its `verified` flag (safety number changed). An attacker who
/// only knew P0's address could not have forged this (no session key). Proves selective, continuity-
/// preserving revocation.
#[test]
fn a_channel_migration_repoints_a_contact_and_clears_verified() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("mig-a");
    let bdir = temp_dir("mig-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    astore.create_proxy("p0", NOW).unwrap(); // mints indices' own random secrets (#207)
    astore.create_proxy("p1", NOW).unwrap();
    bstore.create_proxy("p0", NOW).unwrap();

    let a0 = astore.as_proxy(0); // Alice's current (soon-compromised) channel
    let a1 = astore.as_proxy(1); // the fresh channel she moves keepers to
    let b0 = bstore.as_proxy(0);
    let a0_ik = a0.load_account().unwrap().identity_public();
    let a1_ik = a1.load_account().unwrap().identity_public();
    let b0_ik = b0.load_account().unwrap().identity_public();

    // Bob knows Alice as a VERIFIED contact at her P0 address.
    bstore
        .save_contacts(&[client::store::ContactRecord { name: "Alice".into(), ik: a0_ik, verified: true }])
        .unwrap();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, b0.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "bob proxy publish: {pr:?}");

    // Alice's P0 tells Bob to move to P1 (over the authenticated P0 session).
    client::send_channel_migrate(&a0, &r, &b0_ik, a1_ik, NOW).unwrap();

    let got = client::recv_session(&b0, &r, NOW).unwrap();
    let msg = got.into_iter().flatten().next().expect("the migration arrived");
    assert_eq!(msg.sender, a0_ik, "authenticated by arriving on the P0 session");
    match client::content::decode(&msg.plaintext).unwrap() {
        client::content::Content::ChannelMigrate { new_ik } => {
            assert_eq!(new_ik, a1_ik, "points to the new channel");
            assert!(bstore.migrate_contact_ik(msg.sender, new_ik).unwrap(), "contact migrated");
        }
        other => panic!("expected a migration, got {other:?}"),
    }
    let cs = bstore.load_contacts().unwrap();
    assert_eq!(cs.len(), 1);
    assert_eq!(cs[0].ik, a1_ik, "Alice now reached at the new channel");
    assert!(!cs[0].verified, "verified cleared — the safety number changed with the key");
    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// CRYPTO-27, end-to-end: a migration message that only reaches the relay's queue (not the relay
/// itself) must NOT be treated as delivered, and burning the proxy it is queued on must be refused
/// while it sits there — otherwise the ciphertext (the only authenticated proof of the old→new
/// identity link) is destroyed with nothing sent. Neuter either half — make `send_channel_migrate`
/// discard the bool again, or drop `burn_proxy`'s outbox check — and this reddens.
#[test]
fn a_queued_channel_migration_blocks_burn_until_it_is_actually_delivered() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("mig-queued-a");
    let bdir = temp_dir("mig-queued-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    astore.create_proxy("p0", NOW).unwrap();
    astore.create_proxy("p1", NOW).unwrap();
    bstore.create_proxy("p0", NOW).unwrap();

    let a0 = astore.as_proxy(0);
    let a1 = astore.as_proxy(1);
    let b0 = bstore.as_proxy(0);
    let a1_ik = a1.load_account().unwrap().identity_public();
    let b0_ik = b0.load_account().unwrap().identity_public();

    let live = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&live, b0.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "bob proxy publish: {pr:?}");

    // Establish a real ratchet session P0(Alice) <-> P0(Bob) over the LIVE relay first — a
    // migration send only skips the network round-trip of `connect` when a session already
    // exists, same precondition `outbox_batch.rs`'s tests rely on.
    let delivered = client::send_text(&a0, &live, &b0_ik, b"hi", NOW, NOW).unwrap();
    assert!(delivered, "handshake reaches the live relay");
    assert_eq!(client::outbox_len(&a0).unwrap(), 0, "handshake left nothing queued");
    let _ = client::recv_session(&b0, &live, NOW).unwrap(); // drain, not the point of this test

    // Now the relay Alice's P0 talks to is DEAD (nothing listening on this port).
    let dead = client::Relay::new("127.0.0.1:1".parse::<std::net::SocketAddr>().unwrap(), relay_id, None);
    let ok = client::send_channel_migrate(&a0, &dead, &b0_ik, a1_ik, NOW).unwrap();
    assert!(!ok, "the dead relay never accepts it — must report `false`, not `true`");
    assert_eq!(client::outbox_len(&a0).unwrap(), 1, "the migration ciphertext is durably queued, not lost");

    // Burning P0 now must be refused: it would delete `sessions.dat`, and with it the only
    // authenticated copy of the migration Bob never received.
    let burn_err = astore.burn_proxy(0).expect_err("burn must refuse while the migration is queued");
    assert!(
        burn_err.to_string().contains("undelivered"),
        "the refusal must say WHY, not just fail silently: {burn_err}"
    );
    // Nothing was destroyed by the refused attempt: the identity and its queued outbox survive.
    assert!(a0.load_account().is_ok(), "proxy 0's registry entry must still exist after a refused burn");
    assert_eq!(client::outbox_len(&a0).unwrap(), 1, "the queued migration must still be there after a refused burn");

    // Control: once the relay is reachable again and the queued send actually lands, the outbox
    // drains and the SAME burn call that was just refused now succeeds.
    let flushed = client::flush_outbox(&a0, &live, NOW).unwrap();
    assert_eq!(flushed, 1, "the retry delivers the previously-queued migration");
    assert_eq!(client::outbox_len(&a0).unwrap(), 0, "outbox drained");
    astore.burn_proxy(0).expect("control: an empty outbox must not block burning");

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// A PUBLICATION fanned out to a contact arrives as `Content::Publication` with its id/text/ts
/// intact, is NOT written to the recipient's chat history (it's a feed entry, not a 1:1 message),
/// and — simulating the desktop poll wiring — lands in the recipient's feed via `append_feed`.
/// This is the two-party proof that the publications fan-out (shared with avatars) works over the
/// relay; neuter the `_ => continue` history guard and the "history stays empty" assert reddens.
#[test]
fn a_publication_arrives_in_the_feed_not_the_chat_history() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("pub-a");
    let bdir = temp_dir("pub-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    let id = client::store::random16();
    client::send_publication(&astore, &r, &bob_ik, id, "shipped the feed", 4242, NOW)
        .expect("a publication sends");

    let got = client::recv_session(&bstore, &r, NOW).unwrap();
    let recv = got.into_iter().flatten().next().expect("the publication arrived");
    match client::content::decode(&recv.plaintext).expect("content decodes") {
        client::content::Content::Publication { id: gid, text, ts } => {
            assert_eq!(gid, id, "the publication id survived (dedup key)");
            assert_eq!(text, "shipped the feed", "the text survived");
            assert_eq!(ts, 4242, "the sender's timestamp survived");
            // Simulate the desktop poll wiring: store it in Bob's feed.
            bstore
                .append_feed(&client::store::FeedRecord { author: recv.sender, id: gid, text, ts, expire_at: None })
                .unwrap();
        }
        other => panic!("expected a publication: {other:?}"),
    }

    // A publication is NOT a chat message: it must never touch chat history.
    assert!(bstore.load_history().unwrap().is_empty(), "a publication did not leak into chat history");
    // It DID land in the feed, attributed to Alice.
    let feed = bstore.load_feed().unwrap();
    assert_eq!(feed.len(), 1, "exactly one publication in Bob's feed");
    assert_eq!(feed[0].author, alice_ik, "attributed to the sender");
    assert_eq!(feed[0].text, "shipped the feed");

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// A PUBLICATION IMAGE fanned out alongside its post arrives as a `PostImageManifest` + chunks,
/// reassembles byte-for-byte, and reunites with the post by `post_id` in the recipient's feed-image
/// sidecar — with NO shared relay blob (per-recipient E2E). Simulates the desktop poll wiring:
/// store the post, then attach the assembled image. Proves the honest inline-image path end-to-end.
#[test]
fn a_publication_image_delivers_and_reunites_with_its_post() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("pubimg-a");
    let bdir = temp_dir("pubimg-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    // Alice publishes a post, then its image as a separate chunked slice tied to the post id.
    let id = client::store::random16();
    let image = vec![3u8; 5000]; // stand-in JPEG bytes, multi-chunk
    client::send_publication(&astore, &r, &bob_ik, id, "with a photo", 7, NOW).expect("publication sends");
    client::send_post_image(&astore, &r, &bob_ik, id, &image, NOW).expect("post image sends");

    // Receive + route exactly as the desktop poll does: text → feed, image → reassembler → sidecar.
    let got = recv_multi(&bstore, std::slice::from_ref(&r), NOW).unwrap();
    let mut re = client::content::Reassembler::new();
    for m in got.messages.into_iter().flatten() {
        match client::content::decode(&m.plaintext) {
            Ok(client::content::Content::Publication { id: gid, text, ts }) => {
                bstore
                    .append_feed(&client::store::FeedRecord { author: m.sender, id: gid, text, ts, expire_at: None })
                    .unwrap();
            }
            Ok(c) => {
                if let Ok(Some(client::content::Assembled::PostImage { post_id, bytes })) = re.offer(c, NOW) {
                    bstore.set_feed_image(m.sender, post_id, bytes).unwrap();
                }
            }
            Err(e) => panic!("content decode: {e}"),
        }
    }

    // The image reunited with the post under (author, post_id) — no blob, no chat history.
    assert_eq!(bstore.feed_image(alice_ik, id), Some(image), "image reunited with its post byte-for-byte");
    assert!(bstore.load_history().unwrap().is_empty(), "an image post did not leak into chat history");
    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// With a reachable relay, `send_text` reports `true` (delivered this call) and leaves the
/// outbox empty — the send-side signal the UI turns into "delivered" rather than "pending".
#[test]
fn send_text_reports_delivered_when_the_relay_is_up() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("delivered-a");
    let bdir = temp_dir("delivered-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    assert!(matches!(
        client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW),
        PublishResponse::Published
    ));

    let delivered = client::send_text(&astore, &r, &bob_ik, b"hi", NOW, NOW).unwrap();
    assert!(delivered, "reached the relay this call");
    assert_eq!(client::outbox_len(&astore).unwrap(), 0, "nothing left queued");

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// The sealed opener still authenticates the sender END-TO-END: sealing hides the
/// identity from the RELAY, and must not cost the recipient the ability to know who
/// wrote. Bob opens it with his own key and gets Alice's IK back — attribution intact.
#[test]
fn a_sealed_opener_still_authenticates_the_sender_to_the_recipient() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("sealed-a");
    let bdir = temp_dir("sealed-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    client::send_text(&astore, &r, &bob_ik, b"first contact", NOW, NOW).unwrap();
    let got = client::recv_session(&bstore, &r, NOW).unwrap();
    let recv = got.into_iter().flatten().next().expect("Bob opened the sealed opener");
    assert_eq!(recv.sender, alice_ik, "the recipient still learns WHO wrote — E2E auth intact");
    // The plaintext is an encoded Content envelope, not raw bytes.
    match client::content::decode(&recv.plaintext).expect("content decodes") {
        client::content::Content::TextStamped { text, .. } => {
            assert_eq!(text, b"first contact", "…and what they wrote")
        }
        other => panic!("expected a stamped text, got a different content variant: {other:?}"),
    }

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// Lease/ACK over the REAL socket transport: after `recv_session` the relay's mailbox is
/// EMPTY — proving the ACK round-tripped over the wire (`WireRequest::Ack` →
/// `WireResponse::Acked`) and deleted the leased message. A fetch-based assertion cannot
/// show this (a leased message is hidden from fetch whether or not it was deleted), so we
/// inspect the shared relay state directly. Break `SocketTransport::ack` or the dispatch
/// and this reds while the in-memory crash tests stay green.
#[test]
fn recv_session_acks_and_drains_the_relay_over_the_wire() {
    let (relay_addr, relay_id, relay) = spawn_relay_handle();
    let adir = temp_dir("lease-ack-a");
    let bdir = temp_dir("lease-ack-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    client::send_text(&astore, &r, &bob_ik, b"ack me", NOW, NOW).unwrap();
    // Message is now queued in Bob's mailbox on the relay.
    assert!(!relay.write().unwrap().all_slots_for_test().is_empty(), "message deposited");

    let got = client::recv_session(&bstore, &r, NOW).unwrap();
    assert_eq!(got.into_iter().flatten().count(), 1, "Bob received it");
    // The ACK deleted it over the wire: nothing lingers leased on the relay.
    assert!(
        relay.write().unwrap().all_slots_for_test().is_empty(),
        "recv_session ACKed over the socket and the relay dropped the message"
    );

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// Like `spawn_relay_handle`, but the relay's clock is an atomic a test can ADVANCE — the only
/// way to observe a lease timing out, since lease visibility is decided by the RELAY's clock.
/// Advanced in units of `relay::node::LEASE_SECS`, never by sleeping: no wall-clock threshold.
fn spawn_relay_handle_clock() -> (SocketAddr, client::RelayId, Arc<RwLock<RelayNode>>, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(client::dev_capability());
    let fetch_pub = relay.relay_public().to_bytes();
    let clock = Arc::new(AtomicU64::new(NOW));
    let c = clock.clone();
    let server = RelayServer::new(relay, Arc::new(move || c.load(AtomicOrdering::SeqCst)));
    let noise_pub = server.noise_public();
    let handle = server.relay_handle();
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });
    (addr, client::RelayId { noise_pub, fetch_pub }, handle, clock)
}

/// A container-backed account, set up the way `container_create` does it: a container file, a
/// `ContainerVault` materialized into `work`, and a `Store` over that work dir. The vault comes
/// back so the test can drive `save()` — the commit that a container-backed session's ACK must
/// wait on.
fn open_container_store(
    cpath: &std::path::Path,
    work: PathBuf,
) -> (client::container::ContainerVault, Store) {
    let cv = client::container::ContainerVault::open(cpath, b"container-pw", work).unwrap();
    let store = Store::unlock(&cv.work_dir, b"pw").unwrap();
    (cv, store)
}

/// **SEC-34 — the discriminating test.** A container-backed client's `Store` is a materialized
/// working copy; the AUTHORITY is the encrypted container, written by a separate later `save()`.
/// Receiving used to ack (= tell the relay to delete its only copy) as soon as that working copy
/// was written, so a container `save()` that then failed — and the old code only *warned* about
/// it — left the message gone from BOTH sides: the next unlock restores the container's older
/// snapshot, and the relay has nothing left to redeliver.
///
/// Here the commit FAILS FOR REAL (an oversized file makes SEC-35's capacity check refuse the
/// snapshot — no injected error), and the batch must survive: unacked ⇒ still on the relay ⇒ the
/// lease expires ⇒ the reopened container, rolled back to its pre-message state, receives the
/// exact message. Then a commit that SUCCEEDS acks and drains the relay, so this also pins that
/// the barrier does not simply suppress acking forever.
///
/// Neuter check: ack before/regardless of the commit (`send` the receipts, then `cv.save()`) and
/// the "still on the relay" assertion reds immediately.
#[test]
fn a_failed_container_commit_leaves_the_batch_redeliverable() {
    let (relay_addr, relay_id, relay, clock) = spawn_relay_handle_clock();
    let adir = temp_dir("sec34-alice");
    let base = temp_dir("sec34-container");
    let cpath = base.join("container.dat");
    // 1 MiB container, main region 3/4 of it. A region holds two ping-pong copy slots, so the
    // usable payload is roughly 3/8 MiB — far more than a provisioned account, far less than the
    // oversized file planted below.
    let total = 1024 * 1024;
    client::container::Container::create(&cpath, total, b"container-pw", total / 4 * 3).unwrap();

    let (mut cv, bstore) = open_container_store(&cpath, base.join("work-1"));
    let astore = Store::unlock(&adir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    // The container now holds the PROVISIONED, pre-message account — the state a rollback lands on.
    cv.save().unwrap();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");
    client::send_text(&astore, &r, &bob_ik, b"survive the failed commit", NOW, NOW).unwrap();

    // ---- poll #1: decrypts into the WORK DIR, then the container commit fails ----
    let poll = client::recv_session_multi(&bstore, std::slice::from_ref(&r), NOW).unwrap();
    assert_eq!(poll.messages.iter().flatten().count(), 1, "decrypted into the working copy");
    assert!(!poll.acks.is_empty(), "the fetch took a lease that now needs committing");
    // A real, deterministic `save()` failure: one file larger than the compartment can ever hold.
    std::fs::write(cv.work_dir.join("oversized.bin"), vec![0u8; total as usize]).unwrap();
    let err = poll
        .acks
        .commit_then_send(NOW, || cv.save().map_err(|e| e.to_string()))
        .expect_err("the container commit must fail here");
    assert!(err.contains("budget") || err.contains("cap"), "expected a capacity refusal, got: {err}");
    // THE finding: the commit failed, so NOTHING was acked and the relay still holds the message.
    assert!(
        !relay.write().unwrap().all_slots_for_test().is_empty(),
        "a failed container commit must not have acked — the relay's copy is the only one left"
    );

    // ---- reopen: what the next unlock actually sees is the container, not the work dir ----
    std::fs::remove_file(cv.work_dir.join("oversized.bin")).unwrap();
    drop(bstore);
    drop(cv);
    let (mut cv2, bstore2) = open_container_store(&cpath, base.join("work-2"));
    assert!(
        bstore2.load_history().unwrap().is_empty(),
        "the restored container is the PRE-message state — this is the rollback the ack must not \
         have raced"
    );

    // The unacked lease expires and the exact ciphertext redelivers (relay-clock driven, no sleep).
    clock.store(NOW + relay::node::LEASE_SECS + 1, AtomicOrdering::SeqCst);
    let poll2 = client::recv_session_multi(&bstore2, std::slice::from_ref(&r), NOW).unwrap();
    assert_eq!(
        poll_texts(&poll2.messages),
        vec![b"survive the failed commit".to_vec()],
        "the message the failed commit did not lose is redelivered to the reopened container"
    );
    // …and a commit that SUCCEEDS acks, so the relay finally drops it.
    poll2.acks.commit_then_send(NOW, || cv2.save().map_err(|e| e.to_string())).unwrap();
    assert!(
        relay.write().unwrap().all_slots_for_test().is_empty(),
        "a successful container commit does ack — the barrier gates the ack, it doesn't block it"
    );

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&base).ok();
}

/// **SEC-34, second half.** The desktop used to save the container only `if !out.is_empty()` —
/// keyed on whether the poll produced anything to SHOW. Control mail (a reaction here; equally
/// `ChannelMigrate` or the `FileRef`/`GalleryRef` pointers) advances the ratchet and writes to
/// the store while producing zero UI events, so that gate acked it and never committed it.
///
/// The invariant that replaces it is pinned here: a control-only batch still comes back with a
/// NON-EMPTY `DeferredAcks`, so a caller keying its commit off the leases — as the desktop now
/// does — cannot miss it. Gate on UI output instead and `acks` is what proves you're wrong.
#[test]
fn a_control_only_batch_still_carries_a_commit_barrier() {
    let (relay_addr, relay_id, relay) = spawn_relay_handle();
    let adir = temp_dir("sec34-ctl-a");
    let bdir = temp_dir("sec34-ctl-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");
    client::send_reaction(&astore, &r, &bob_ik, [9u8; 16], "👍", true, NOW).unwrap();

    let poll = client::recv_session_multi(&bstore, std::slice::from_ref(&r), NOW).unwrap();
    // Nothing a UI would render…
    assert!(poll_texts(&poll.messages).is_empty(), "a reaction produces no UI text");
    assert!(
        matches!(
            client::content::decode(&poll.messages.iter().flatten().next().unwrap().plaintext),
            Ok(client::content::Content::Reaction { .. })
        ),
        "…but a real control message did arrive"
    );
    // …and yet the batch is leased, so it MUST be committed before it may be acked.
    assert!(!poll.acks.is_empty(), "control-only mail still holds leases that need committing");
    assert!(
        !relay.write().unwrap().all_slots_for_test().is_empty(),
        "receiving alone acked nothing — the ack is the committer's to send"
    );
    poll.acks.commit_then_send(NOW, || Ok(())).unwrap();
    assert!(relay.write().unwrap().all_slots_for_test().is_empty(), "committed ⇒ acked");

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// Drive `recv_session_multi` the way a FILE-TREE client does: the store it just wrote to IS
/// the authority, so the SEC-34 commit barrier is a genuine no-op and the leases are acked
/// immediately. Container-backed callers do NOT get this shape — see
/// `a_failed_container_commit_leaves_the_batch_redeliverable`.
fn recv_multi(store: &Store, relays: &[client::Relay], now: u64) -> Result<client::MultiPoll, String> {
    let mut poll = client::recv_session_multi(store, relays, now)?;
    std::mem::take(&mut poll.acks).commit_then_send(now, || Ok(()))?;
    Ok(poll)
}

/// Provision the root (the entropy of a fresh phrase) into the store; returns the entropy so the
/// test can derive the expected seal/account (`seed::derive`) for comparison. In the new model
/// identity and account are not independent secrets but derivations from a SINGLE root.
fn seed_provision(s: &Store) -> [u8; client::seed::ENTROPY_BYTES] {
    let e = client::seed::entropy_of(&client::seed::generate_mnemonic());
    s.save_seed(&e).unwrap();
    e
}

/// The plaintext of every decrypted §2.1 message in a poll (Text/TextStamped).
fn poll_texts(msgs: &[Option<karst_client_core::peer::Received>]) -> Vec<Vec<u8>> {
    msgs.iter()
        .flatten()
        .filter_map(|m| match client::content::decode(&m.plaintext).ok()? {
            client::content::Content::Text(t) | client::content::Content::TextStamped { text: t, .. } => Some(t),
            _ => None,
        })
        .collect()
}

/// Multi-homed receive through the store over REAL relay sockets: Bob is reachable at two
/// relays, one dead relay sits between them, and Alice's session is split across the two
/// live ones. `recv_session_multi` must deliver BOTH messages, report only the dead relay,
/// and persist so a second poll is empty. Discriminating: drop the dead relay's index
/// expectation and the reachability half reds; restore fail-fast in `receive_threaded` and
/// the whole poll returns nothing.
#[test]
fn recv_session_multi_delivers_from_live_relays_and_flags_the_dead_one() {
    let (addr1, id1) = spawn_relay();
    let (addr2, id2) = spawn_relay();
    // A closed port: bind then drop, so a connection is refused → the relay is "dead".
    let dead_addr = { TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap() };

    let adir = temp_dir("multi-a");
    let bdir = temp_dir("multi-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    // A credential per relay — this account multi-homes onto both, so it needs both (CRYPTO-24).
    for id in [&id1, &id2] {
        astore.save_shared_capability_for(id, &client::dev_capability()).unwrap();
        bstore.save_shared_capability_for(id, &client::dev_capability()).unwrap();
    }
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r1 = ctx(addr1, &id1);
    let r2 = ctx(addr2, &id2);
    let r_dead = ctx(dead_addr, &id1); // identity is irrelevant — the socket never opens
    for r in [&r1, &r2] {
        let pr = client::publish_bundle(r, bstore.load_account().unwrap(), client::dev_capability(), NOW);
        assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");
    }

    // Alice's opener goes via relay 1; her next ratchet message via relay 2 (same session,
    // persisted in her store between the two sends).
    client::send_text(&astore, &r1, &bob_ik, b"via-r1", NOW, NOW).unwrap();
    client::send_text(&astore, &r2, &bob_ik, b"via-r2", NOW, NOW).unwrap();

    // Dead relay in the MIDDLE, so a fail-fast poll would lose relay 2's message.
    let poll = recv_multi(&bstore, &[r1.clone(), r_dead, r2.clone()], NOW).unwrap();
    assert_eq!(poll.failed, vec![1], "only the dead relay is unreachable");
    let texts = poll_texts(&poll.messages);
    assert!(texts.contains(&b"via-r1".to_vec()), "relay 1's message was not delivered");
    assert!(texts.contains(&b"via-r2".to_vec()), "relay 2's message was not delivered past the dead relay");

    // The mailboxes were drained on fetch, so a re-poll of the same live relays is empty.
    // This checks DRAINAGE, not persistence — it would hold even without saving state.
    let drained = recv_multi(&bstore, &[r1.clone(), r2.clone()], NOW).unwrap();
    assert!(poll_texts(&drained.messages).is_empty(), "a message was re-delivered (mailbox not drained)");

    // Persistence proper: a NEW post-opener message lands in a session-derived drop box, so
    // it only decrypts if Bob's ratchet advance from the first multi-poll round-tripped
    // through disk. Delete `save_sessions` in `recv_session_multi` and this reds — Bob loads
    // a stale session, never learns the drop box, and the follow-up is lost.
    client::send_text(&astore, &r1, &bob_ik, b"after", NOW, NOW).unwrap();
    let follow = recv_multi(&bstore, &[r1, r2], NOW).unwrap();
    assert!(
        poll_texts(&follow.messages).contains(&b"after".to_vec()),
        "the multi-poll's ratchet advance did not round-trip through disk"
    );

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// `publish_all` puts Bob's bundle on EVERY relay he multi-homes to — so a contact can
/// first-contact him through any of them — but advertises one-time prekeys on the PRIMARY
/// ONLY (a secondary publishing the same OPK batch would recreate the PR #20 collision).
/// Discriminating: publish primary-only and the secondary fetch returns no bundle (reds the
/// `expect`); publish secondaries from the OPK-loaded account and the secondary's `opk_pub`
/// is `Some` (reds the asymmetry assert).
#[test]
fn publish_all_puts_the_bundle_on_every_relay_opks_on_the_primary_only() {
    let (addr1, id1) = spawn_relay();
    let (addr2, id2) = spawn_relay();
    let bdir = temp_dir("puball-b");
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&bstore);
    for id in [&id1, &id2] {
        bstore.save_shared_capability_for(id, &client::dev_capability()).unwrap();
    }
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let resp =
        client::publish_all(&bstore, &[ctx(addr1, &id1), ctx(addr2, &id2)],  NOW)
            .unwrap();
    assert!(matches!(resp, PublishResponse::Published), "primary publish: {resp:?}");

    // Fetch Bob's bundle straight from each relay (bundle fetch is public/unauthenticated).
    // The plain public read proves the bundle is THERE on both relays...
    assert!(
        SocketTransport::new(addr1, id1.noise_pub).fetch_bundle(&bob_ik, NOW).unwrap().is_some(),
        "the primary has Bob's bundle"
    );
    assert!(
        SocketTransport::new(addr2, id2.noise_pub).fetch_bundle(&bob_ik, NOW).unwrap().is_some(),
        "the secondary has Bob's bundle" // primary-only publish reds here
    );
    // ...and the admission-gated read proves WHERE the one-time prekeys went. A public read
    // would answer `None` on both now, which is why this half has to use the gated path.
    let b1 = fetch_opk_bundle(addr1, &id1, &bob_ik, NOW).expect("primary bundle");
    let b2 = fetch_opk_bundle(addr2, &id2, &bob_ik, NOW).expect("secondary bundle");
    assert!(b1.opk.is_some(), "the primary must advertise a one-time prekey");
    assert!(b2.opk.is_none(), "a secondary must NOT advertise a one-time prekey (reuse hazard)");

    std::fs::remove_dir_all(&bdir).ok();
}

/// Network config survives a restart AND is encrypted at rest — now PER ACCOUNT, which
/// is what makes an account a compartment rather than just another name. The encryption
/// half is the point: a lost or stolen cold disk must not reveal the relay this identity speaks
/// to or its escape routes. Discriminating: write `net.dat` in the clear → the
/// plaintext-scan reds; share one config across accounts → the isolation assert reds.
#[test]
fn net_settings_are_per_account_persistent_and_encrypted() {
    use client::store::{NetSettings, Vault};
    let dir = temp_dir("netcfg");
    let pass = b"devpw";
    let work = NetSettings {
        relay_addr: "203.0.113.7:9000".into(),
        relay_id: "ab".repeat(64),
        socks5: "127.0.0.1:9050".into(),
        routes: "198.51.100.9:9000, wss@203.0.113.8:443".into(),
            mixnet: false,
    };
    let private = NetSettings {
        relay_addr: "192.0.2.5:9000".into(),
        relay_id: "cd".repeat(64),
        ..Default::default()
    };

    let (a_id, b_id) = ("aaaa".to_string(), "bbbb".to_string());
    {
        let v = Vault::unlock(&dir, pass).unwrap();
        v.create_account_dir(&a_id).unwrap();
        v.create_account_dir(&b_id).unwrap();
        assert_eq!(v.account(&a_id).load_net().unwrap(), NetSettings::default(), "nothing saved yet");
        v.account(&a_id).save_net(&work).unwrap();
        v.account(&b_id).save_net(&private).unwrap();
    }

    // A fresh unlock (a later launch) sees each account's OWN config.
    let v = Vault::unlock(&dir, pass).unwrap();
    assert_eq!(v.account(&a_id).load_net().unwrap(), work, "config survives a restart");
    assert_eq!(
        v.account(&b_id).load_net().unwrap(),
        private,
        "the other compartment keeps its OWN relay — sharing one would put both identities \
         in the same room, linked by IP and timing whatever their keys are"
    );

    // A wrong passphrase cannot open the vault at all: multipassword routing derives the key and
    // finds no keyslot it authenticates, so `unlock` fails closed (cleaner than the old behaviour
    // of handing back a vault whose every decrypt then failed).
    assert!(
        Vault::unlock(&dir, b"wrong").is_err(),
        "a wrong passphrase must not open the vault"
    );

    // Nothing on disk in the clear: neither the relay nor the escape routes. The account now lives
    // inside its compartment (`c/<id>/accounts/<a_id>/`); find the single real compartment.
    let compartment = std::fs::read_dir(dir.join("c"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let on_disk = std::fs::read(compartment.join("accounts").join(&a_id).join("net.dat")).unwrap();
    for secret in ["203.0.113.7", "198.51.100.9", "203.0.113.8", "127.0.0.1:9050"] {
        assert!(
            !on_disk.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "{secret:?} must not sit in plaintext in net.dat"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn store_identity_roundtrip() {
    let dir = temp_dir("store");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    let e = seed_provision(&s);
    let expected = client::seed::derive(&e).seal.public.to_bytes();

    let loaded = Store::unlock(&dir, b"test-pw").unwrap().load_identity().unwrap();
    assert_eq!(
        loaded.public.to_bytes(),
        expected,
        "the reloaded seal public key must match the derivation from the root",
    );

    // create_new: a repeated save_seed must NOT overwrite the root.
    let other = client::seed::entropy_of(&client::seed::generate_mnemonic());
    assert!(s.save_seed(&other).is_err(), "must not overwrite the root");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn at_rest_wrong_passphrase_cannot_load_and_disk_is_encrypted() {
    // At-rest wiring through the Store: (1) the root does not open under a different password;
    // (2) there is no plaintext entropy on disk (the encryption is not a no-op).
    let dir = temp_dir("atrest");
    let s = Store::unlock(&dir, b"right-pass").unwrap();
    let e = seed_provision(&s);
    let acct = client::seed::derive(&e).account;

    // A wrong password fails fast at unlock (the verifier), before any read.
    assert!(Store::unlock(&dir, b"wrong-pass").is_err(), "a wrong password is refused at unlock");

    // The right password gives the same IK (derived from the root).
    let right = Store::unlock(&dir, b"right-pass").unwrap();
    assert_eq!(right.load_account().unwrap().identity_public(), acct.identity_public());

    // On disk (seed.key) there is no plaintext entropy (otherwise the encryption would be a no-op).
    let on_disk = std::fs::read(dir.join("seed.key")).unwrap();
    assert!(
        !on_disk.windows(e.len()).any(|w| w == e),
        "the plaintext root entropy must not appear in seed.key"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_pre_vault_single_account_layout_is_not_silently_adopted() {
    // The vault used to MIGRATE a legacy single-account directory (secrets straight in the base)
    // into `accounts/<ik>/` on unlock, reusing the same key so the moved files opened unchanged.
    // Format v2 killed that path outright: at-rest keys are now derived per (account, file), so
    // moving a file between scopes changes its key by design — a migration would have had to
    // re-seal everything, and this is pre-alpha with no users to migrate.
    //
    // What must NOT happen is the silent middle ground: a vault adopting the old layout and then
    // presenting an account it cannot actually read. Absent registry = no accounts, full stop.
    use client::store::{ContactRecord, Vault};
    let dir = temp_dir("prevault");
    let pass = b"devpw";
    let entropy = client::seed::entropy_of(&client::seed::generate_mnemonic());
    {
        let s = Store::unlock(&dir, pass).unwrap();
        s.save_seed(&entropy).unwrap();
        s.save_contacts(&[ContactRecord { name: "Bob".into(), ik: [9u8; 32], verified: true }])
            .unwrap();
    }

    let vault = Vault::unlock(&dir, pass).unwrap();
    assert!(
        vault.load_registry().unwrap().is_empty(),
        "a pre-vault layout must not be adopted as a vault account — it would be listed but \
         unreadable under per-account key derivation"
    );
    // The old files are left exactly where they are, for the standalone reader that wrote them.
    assert!(dir.join("seed.key").exists(), "nothing is moved or destroyed behind the user's back");
    assert_eq!(Store::unlock(&dir, pass).unwrap().load_entropy().unwrap(), entropy);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn store_contacts_roundtrip_with_verified_flag() {
    // Contacts (names plus the verified flag) survive a process restart.
    use client::store::ContactRecord;
    let dir = temp_dir("contacts");
    let contacts = vec![
        ContactRecord { name: "Alice".into(), ik: [1u8; 32], verified: true },
        ContactRecord { name: "unknown deadbeef".into(), ik: [2u8; 32], verified: false },
    ];
    Store::unlock(&dir, b"pw").unwrap().save_contacts(&contacts).unwrap();

    // A new Store (as after a restart) reads the same list.
    let loaded = Store::unlock(&dir, b"pw").unwrap().load_contacts().unwrap();
    assert_eq!(loaded, contacts, "contacts are stable across the disk, the verified flag intact");

    // On disk there is no plaintext name (the encryption is not a no-op).
    let on_disk = std::fs::read(dir.join("contacts.dat")).unwrap();
    assert!(
        !on_disk.windows(5).any(|w| w == b"Alice"),
        "a plaintext contact name must not lie in contacts.dat"
    );
    // An empty profile gives an empty list (not an error).
    let empty = temp_dir("contacts-empty");
    assert!(Store::unlock(&empty, b"pw").unwrap().load_contacts().unwrap().is_empty());

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&empty).ok();
}

#[test]
fn store_account_roundtrip() {
    // The §2.1 account survives the disk: the IK and bundle are stable (including the KEM seed) —
    // they are derived from the root deterministically.
    let dir = temp_dir("acct");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    let e = seed_provision(&s);
    let expected = client::seed::derive(&e).account;
    let ik = expected.identity_public();
    let ek = expected.prekey_bundle().kem_ek;

    let loaded = Store::unlock(&dir, b"test-pw").unwrap().load_account().unwrap();
    assert_eq!(loaded.identity_public(), ik, "the IK is stable across the disk");
    assert_eq!(loaded.prekey_bundle().kem_ek, ek, "the KEM ek is stable (the seed was restored)");

    // create_new: changing the root is refused (it would break discovery and sessions).
    let other = client::seed::entropy_of(&client::seed::generate_mnemonic());
    assert!(s.save_seed(&other).is_err(), "must not overwrite the root");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn bob_reloads_account_from_disk_and_publishes() {
    // Layer-1 e2e: Bob writes the root, FORGETS it, reloads from disk (deriving the account) and
    // publishes the bundle at the relay. Reload-then-publish proves the stored root is intact and
    // the derived bundle is consistent.
    let (relay, relay_id) = spawn_relay();
    let bob_dir = temp_dir("bob-acct");
    let bob_store = Store::unlock(&bob_dir, b"test-pw").unwrap();
    seed_provision(&bob_store); // the root goes to disk; everything below reads only the disk.

    let reloaded = bob_store.load_account().unwrap();
    let resp = client::publish_bundle(&ctx(relay, &relay_id), reloaded, client::dev_capability(), NOW);
    assert!(matches!(resp, PublishResponse::Published), "got: {:?}", resp);

    std::fs::remove_dir_all(&bob_dir).ok();
}

/// A mock transport: always `Accepted`, recording every WireMessage that left.
/// Send+Sync so it can be used from threads (a ciphertext that "left" is, in this model, gone).
#[derive(Clone)]
struct RecordingTransport {
    sent: Arc<Mutex<Vec<WireMessage>>>,
}
impl Transport for RecordingTransport {
    fn send(&self, msg: &WireMessage, _now: u64) -> Response {
        self.sent.lock().unwrap().push(msg.clone());
        Response::Accepted
    }
    fn fetch(&self, _r: &FetchRequest, _now: u64) -> FetchResponse {
        FetchResponse::Rejected("n/a".into())
    }
}

#[test]
fn concurrent_sends_under_lock_never_reuse_ratchet_position() {
    // LOAD-BEARING (persistent keystream reuse): two "processes" (threads) send over one session,
    // each doing load→send(advance)→save under the flock. The lock must serialise them so that
    // EVERY send takes its own chain position. If the lock is broken (for example on a renamed
    // inode), both load position N and encrypt DIFFERENT texts under the same mk and zero nonce.
    // We check that no (dh,n) pair repeats among the envelopes that left. Deterministic under any
    // ordering (the lock works → no duplicates; broken → duplicates).

    let dir = temp_dir("concurrent");
    let store = Store::unlock(&dir, b"test-pw").unwrap();
    let account = client::seed::derive(&seed_provision(&store)).account;
    let acct_bytes = account.to_secret_bytes();
    let relay_pub = PublicKey::from([7u8; 32]); // mock — the DH is unused in send
    let bob_ik = {
        // Establish the session and save the starting state.
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut peer = Peer::new(
            RecordingTransport { sent },
            Account::from_secret_bytes(&acct_bytes),
            client::dev_capability(),
            relay_pub,
        );
        let bob_bundle = Account::generate().prekey_bundle();
        let ik = bob_bundle.ik_pub;
        peer.connect_with_bundle(&bob_bundle).unwrap();
        let g = store.lock_sessions().unwrap();
        store.save_sessions(&peer.export_state()).unwrap();
        drop(g);
        ik
    };

    let recorded = Arc::new(Mutex::new(Vec::new()));
    const PER_THREAD: usize = 25;
    let mut handles = Vec::new();
    for t in 0..2u8 {
        let dir = dir.clone();
        let recorded = recorded.clone();
        handles.push(thread::spawn(move || {
            let store = Store::unlock(&dir, b"test-pw").unwrap();
            for i in 0..PER_THREAD {
                let g = store.lock_sessions().unwrap(); // blocking exclusive lock
                let transport = RecordingTransport { sent: recorded.clone() };
                let mut peer =
                    Peer::new(transport, Account::from_secret_bytes(&acct_bytes), client::dev_capability(), relay_pub);
                peer.import_state(store.load_sessions().unwrap());
                let msg = format!("t{t}-{i}");
                assert!(matches!(peer.send(&bob_ik, msg.as_bytes(), NOW), Response::Accepted));
                store.save_sessions(&peer.export_state()).unwrap();
                drop(g); // release the lock
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // Collect the (dh,n) of every Session envelope that left — there must be no duplicates.
    let sent = recorded.lock().unwrap();
    assert_eq!(sent.len(), 2 * PER_THREAD, "every send went through");
    let mut positions: Vec<([u8; 32], u32)> = sent
        .iter()
        .filter_map(|m| match &m.payload {
            Payload::Session(SessionEnvelope::Ratchet(msg)) => Some((msg.header.dh, msg.header.n)),
            _ => None,
        })
        .collect();
    let total = positions.len();
    positions.sort();
    positions.dedup();
    assert_eq!(positions.len(), total, "two sends must not share a chain position");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn crash_between_transmit_and_save_never_reuses_position() {
    // LOAD-BEARING (the crash axis of keystream reuse): "process 1" encrypts and transmits (ct_N
    // has already left for the relay), then CRASHES before the post-save. "Process 2" loads from
    // disk and encrypts DIFFERENT text. The order encrypt_next → pre-save → transmit guarantees
    // that position N was durable BEFORE ct_N left, so process 2 takes N+1 rather than N. Saving
    // after transmit would leave the window: disk at N → a repeated position → reuse.
    let dir = temp_dir("crash");
    let store = Store::unlock(&dir, b"test-pw").unwrap();
    let account = client::seed::derive(&seed_provision(&store)).account;
    let acct_bytes = account.to_secret_bytes();
    let relay_pub = PublicKey::from([7u8; 32]);
    let recorded = Arc::new(Mutex::new(Vec::new()));

    // Establish the session and save the starting state.
    let bob_ik = {
        let mut peer = Peer::new(
            RecordingTransport { sent: recorded.clone() },
            Account::from_secret_bytes(&acct_bytes),
            client::dev_capability(),
            relay_pub,
        );
        let b = Account::generate().prekey_bundle();
        let ik = b.ik_pub;
        peer.connect_with_bundle(&b).unwrap();
        let g = store.lock_sessions().unwrap();
        store.save_sessions(&peer.export_state()).unwrap();
        drop(g);
        ik
    };

    // Helper: one send in send_session order, with an option to "crash" before the post-save.
    let send_once = |plaintext: &[u8], crash_before_post_save: bool| {
        let g = store.lock_sessions().unwrap();
        let mut peer = Peer::new(
            RecordingTransport { sent: recorded.clone() },
            Account::from_secret_bytes(&acct_bytes),
            client::dev_capability(),
            relay_pub,
        );
        peer.import_state(store.load_sessions().unwrap());
        let env = peer.encrypt_next(&bob_ik, plaintext).unwrap();
        store.save_sessions(&peer.export_state()).unwrap(); // PRE-transmit save (the fix)
        peer.transmit_envelope(&bob_ik, env, NOW); // the ct left for the relay (recorded)
        if !crash_before_post_save {
            store.save_sessions(&peer.export_state()).unwrap(); // post (cleanup)
        }
        drop(g);
    };

    send_once(b"AAAA", true); // process 1: crashes after transmit, before the post-save
    send_once(b"BBBB", false); // process 2: loads from disk and sends different text

    let sent = recorded.lock().unwrap();
    let positions: Vec<([u8; 32], u32)> = sent
        .iter()
        .filter_map(|m| match &m.payload {
            Payload::Session(SessionEnvelope::Ratchet(msg)) => Some((msg.header.dh, msg.header.n)),
            _ => None,
        })
        .collect();
    let mut uniq = positions.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(positions.len(), uniq.len(), "a crash before the post-save must not repeat a position");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn alice_sends_bob_reloads_from_disk_and_decrypts() {
    let (relay, relay_id) = spawn_relay();

    // Bob: create the root, save it, then FORGET it and reload from disk.
    let bob_dir = temp_dir("bob");
    let bob_store = Store::unlock(&bob_dir, b"test-pw").unwrap();
    // Bob's KEM key comes from the SAME phrase as his identity, so it survives the reload below
    // and a sender can be told it out of band (PRIV-3).
    let (bob_pub, bob_kem_ek) = {
        let e = seed_provision(&bob_store);
        let d = client::seed::derive(&e);
        (d.seal.public.to_bytes(), d.account.seal_kem().ek().to_vec())
    };
    // ← the identity above went out of scope; below we work only from the disk.
    let bob_reloaded = bob_store.load_identity().unwrap();
    assert_eq!(bob_reloaded.public.to_bytes(), bob_pub);

    // Alice: a dev capability, sending to Bob's public key (inside a Noise session).
    let resp = client::send_message(
        &ctx(relay, &relay_id),
        client::dev_capability(),
        &bob_pub,
        &bob_kem_ek,
        b"hi bob",
        NOW,
    );
    assert!(matches!(resp, Response::Accepted), "got: {:?}", resp);

    // Bob: collect with the reloaded identity (Noise + fetch-auth) and decrypt.
    let bob_account = bob_store.load_account().expect("account re-derives from the stored phrase");
    let msgs = client::fetch_messages(&ctx(relay, &relay_id), bob_reloaded, &bob_account, NOW)
        .expect("fetch");
    let got: Vec<_> = msgs.into_iter().flatten().collect(); // the skeleton path: Vec<u8>
    assert_eq!(got, vec![b"hi bob".to_vec()], "Bob must decrypt with his stored identity");

    std::fs::remove_dir_all(&bob_dir).ok();
}

// ---- The encrypted append log of history ----

#[test]
fn history_append_then_reload_roundtrips_in_order() {
    use client::store::HistoryRecord;
    let dir = temp_dir("hist-roundtrip");
    let s = Store::unlock(&dir, b"test-pw").unwrap();

    let recs = [
        HistoryRecord { from_me: true, peer_ik: [7; 32], text: b"hello".to_vec(), ts: 1 },
        HistoryRecord { from_me: false, peer_ik: [7; 32], text: b"hi back".to_vec(), ts: 2 },
        HistoryRecord { from_me: true, peer_ik: [9; 32], text: b"other chat".to_vec(), ts: 3 },
    ];
    for r in &recs {
        s.append_history(r).unwrap();
    }
    // Reloading with a NEW Store (as a new process) reads from disk, not from memory.
    let loaded = Store::unlock(&dir, b"test-pw").unwrap().load_history().unwrap();
    assert_eq!(loaded, recs.to_vec(), "order and contents preserved");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn history_records_use_fresh_nonce_no_keystream_reuse() {
    use client::store::HistoryRecord;
    let dir = temp_dir("hist-nonce");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    // Two IDENTICAL records must give DIFFERENT ciphertexts on disk.
    let r = HistoryRecord { from_me: true, peer_ik: [1; 32], text: b"same".to_vec(), ts: 42 };
    s.append_history(&r).unwrap();
    s.append_history(&r).unwrap();
    let raw = std::fs::read(dir.join("history.dat")).unwrap();
    // Two records with the same length prefix; their sealed bodies must differ.
    let len = u32::from_le_bytes(raw[0..4].try_into().unwrap()) as usize;
    let first = &raw[4..4 + len];
    let second = &raw[4 + len + 4..4 + len + 4 + len];
    assert_ne!(first, second, "identical plaintext → different ciphertext (the nonce is fresh)");
    // And both are still readable.
    let loaded = s.load_history().unwrap();
    assert_eq!(loaded, vec![r.clone(), r]);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn history_torn_tail_is_truncated_and_future_appends_survive() {
    use client::store::HistoryRecord;
    use std::io::Write;
    let dir = temp_dir("hist-torn");
    let good = HistoryRecord { from_me: false, peer_ik: [3; 32], text: b"survivor".to_vec(), ts: 5 };
    {
        let s = Store::unlock(&dir, b"test-pw").unwrap();
        s.append_history(&good).unwrap();
        // Simulate a crash mid-append: write a torn tail (a length prefix for bytes that are not
        // there, plus garbage).
        let mut f =
            std::fs::OpenOptions::new().append(true).open(dir.join("history.dat")).unwrap();
        f.write_all(&999u32.to_le_bytes()).unwrap();
        f.write_all(b"\x00\x01\x02garbage").unwrap();
    }
    // load at startup: it returns only the whole record AND truncates the garbage.
    let s2 = Store::unlock(&dir, b"test-pw").unwrap();
    let loaded = s2.load_history().unwrap();
    assert_eq!(loaded, vec![good.clone()], "the torn tail is dropped, the whole record kept");
    // Critical: after truncation a future append parses again (the tail did not poison the file).
    let next = HistoryRecord { from_me: true, peer_ik: [3; 32], text: b"after".to_vec(), ts: 6 };
    s2.append_history(&next).unwrap();
    let after = Store::unlock(&dir, b"test-pw").unwrap().load_history().unwrap();
    assert_eq!(after, vec![good, next], "an append after recovery is readable");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn rewrite_history_drops_filtered_records_and_persists_atomically() {
    use client::store::HistoryRecord;
    let dir = temp_dir("hist-rewrite");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    let recs = [
        HistoryRecord { from_me: true, peer_ik: [7; 32], text: b"keep-1".to_vec(), ts: 1 },
        HistoryRecord { from_me: false, peer_ik: [9; 32], text: b"drop-a".to_vec(), ts: 2 },
        HistoryRecord { from_me: true, peer_ik: [7; 32], text: b"keep-2".to_vec(), ts: 3 },
        HistoryRecord { from_me: false, peer_ik: [9; 32], text: b"drop-b".to_vec(), ts: 4 },
    ];
    for r in &recs {
        s.append_history(r).unwrap();
    }
    // Clear the conversation with [9;32] (as in "delete chat"): keep only the others.
    let removed = s.rewrite_history(|r| r.peer_ik != [9; 32]).unwrap();
    assert_eq!(removed.len(), 2, "both records of chat [9;32] were removed");
    assert!(removed.iter().all(|r| r.peer_ik == [9; 32]), "exactly the removed records came back");
    // A NEW Store (as after a restart): the filter survived the rewrite, and so did the order.
    let loaded = Store::unlock(&dir, b"test-pw").unwrap().load_history().unwrap();
    assert_eq!(loaded, vec![recs[0].clone(), recs[2].clone()], "only the kept records, in order");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn rewrite_history_noop_when_nothing_filtered() {
    use client::store::HistoryRecord;
    let dir = temp_dir("hist-rewrite-noop");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    let r = HistoryRecord { from_me: true, peer_ik: [2; 32], text: b"x".to_vec(), ts: 1 };
    s.append_history(&r).unwrap();
    let before = std::fs::read(dir.join("history.dat")).unwrap();
    let removed = s.rewrite_history(|_| true).unwrap();
    assert!(removed.is_empty(), "keep-all removes nothing");
    // The file is untouched (same contents — no pointless rewrite).
    assert_eq!(std::fs::read(dir.join("history.dat")).unwrap(), before, "keep-all does not rewrite the file");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn rewrite_history_can_clear_all_and_file_stays_valid_for_append() {
    use client::store::HistoryRecord;
    let dir = temp_dir("hist-rewrite-clear");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    for ts in 1..=3 {
        s.append_history(&HistoryRecord { from_me: true, peer_ik: [1; 32], text: b"m".to_vec(), ts })
            .unwrap();
    }
    let removed = s.rewrite_history(|_| false).unwrap();
    assert_eq!(removed.len(), 3, "everything was removed");
    assert!(s.load_history().unwrap().is_empty(), "the history is empty after a full clear");
    // The file is valid: a later append parses (it was not poisoned by the empty rewrite).
    let next = HistoryRecord { from_me: false, peer_ik: [1; 32], text: b"after".to_vec(), ts: 4 };
    s.append_history(&next).unwrap();
    assert_eq!(Store::unlock(&dir, b"test-pw").unwrap().load_history().unwrap(), vec![next]);
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Message metadata (reactions), the at-rest sidecar meta.dat ----

#[test]
fn reactions_survive_restart_and_are_at_rest_encrypted() {
    use client::content::msg_id;
    let dir = temp_dir("meta-reactions");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    let id = msg_id(&[7; 32], 42, b"hi");
    s.set_reaction(id, "👍", [1; 32], true).unwrap();
    s.set_reaction(id, "👍", [2; 32], true).unwrap(); // a second author of the same reaction
    s.set_reaction(id, "🔥", [1; 32], true).unwrap();

    // At rest: the raw file does NOT contain the emoji in the clear.
    let raw = std::fs::read(dir.join("meta.dat")).unwrap();
    assert!(!raw.windows("👍".len()).any(|w| w == "👍".as_bytes()), "the emoji is not plaintext on disk");

    // Restart: the map survived and is correct.
    let map = Store::unlock(&dir, b"test-pw").unwrap().load_meta().unwrap();
    let mm = map.get(&id).expect("the message has metadata");
    assert_eq!(mm.reactions.get("👍").unwrap().len(), 2, "two authors of 👍");
    assert!(mm.reactions.get("🔥").unwrap().contains(&[1; 32]), "🔥 from author 1");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn reaction_toggle_add_then_remove_collapses_to_empty_and_removes_file() {
    use client::content::msg_id;
    let dir = temp_dir("meta-toggle");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    let id = msg_id(&[3; 32], 9, b"m");
    s.set_reaction(id, "❤", [1; 32], true).unwrap();
    assert!(dir.join("meta.dat").exists(), "the file appeared");
    s.set_reaction(id, "❤", [1; 32], false).unwrap(); // removing the last one
    assert!(s.load_meta().unwrap().is_empty(), "removing the last reaction leaves it empty");
    assert!(!dir.join("meta.dat").exists(), "an empty map deletes the file (no leftovers)");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn prune_meta_drops_only_named_ids() {
    use client::content::msg_id;
    let dir = temp_dir("meta-prune");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    let keep = msg_id(&[1; 32], 1, b"keep");
    let gone = msg_id(&[1; 32], 2, b"gone");
    s.set_reaction(keep, "👍", [1; 32], true).unwrap();
    s.set_reaction(gone, "👍", [1; 32], true).unwrap();
    s.prune_meta(&[gone]).unwrap();
    let map = s.load_meta().unwrap();
    assert!(map.contains_key(&keep) && !map.contains_key(&gone), "only the named id was removed");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn reaction_rejects_absurd_emoji_before_write() {
    use client::content::{msg_id, MAX_EMOJI_BYTES};
    let dir = temp_dir("meta-caps");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    let id = msg_id(&[1; 32], 1, b"m");
    assert!(s.set_reaction(id, "", [1; 32], true).is_err(), "an empty emoji is refused");
    let huge = "x".repeat(MAX_EMOJI_BYTES + 1);
    assert!(s.set_reaction(id, &huge, [1; 32], true).is_err(), "an oversized emoji is refused");
    assert!(!dir.join("meta.dat").exists(), "what was refused is NOT written to disk");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn set_reply_persists_across_restart() {
    use client::content::msg_id;
    let dir = temp_dir("meta-reply");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    let reply_msg = msg_id(&[1; 32], 5, b"my reply");
    let target = msg_id(&[2; 32], 3, b"original");
    s.set_reply(reply_msg, target).unwrap();
    let map = Store::unlock(&dir, b"test-pw").unwrap().load_meta().unwrap();
    assert_eq!(map.get(&reply_msg).unwrap().reply_to, Some(target), "reply_to survived the restart");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn set_edit_persists_across_restart() {
    use client::content::msg_id;
    let dir = temp_dir("meta-edit");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    let id = msg_id(&[1; 32], 5, b"typo");
    s.set_edit(id, 9, b"fixed").unwrap();
    let map = Store::unlock(&dir, b"test-pw").unwrap().load_meta().unwrap();
    assert_eq!(map.get(&id).unwrap().edited, Some((9, b"fixed".to_vec())), "the edit survived the restart");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn incoming_edit_allowed_only_for_messages_the_sender_authored() {
    // A GUARD against spoofing: an edit is applied ONLY if its sender is the target's author (for
    // us, an incoming message from them). Editing YOUR (or a third party's) message is refused.
    use client::content::msg_id;
    use client::store::HistoryRecord;
    let sender = [2u8; 32];
    let me = [1u8; 32];
    let recs = vec![
        // Their message (incoming from sender): from_me=false, peer=sender.
        HistoryRecord { from_me: false, peer_ik: sender, text: b"theirs".to_vec(), ts: 5 },
        // My message (outgoing to sender): from_me=true, author = me.
        HistoryRecord { from_me: true, peer_ik: sender, text: b"mine".to_vec(), ts: 6 },
    ];
    // Editing THEIR message (author = sender) is allowed.
    assert!(client::incoming_edit_allowed(&recs, &sender, msg_id(&sender, 5, b"theirs")));
    // Editing MY message from sender is REFUSED (otherwise they could rewrite my text).
    assert!(!client::incoming_edit_allowed(&recs, &sender, msg_id(&me, 6, b"mine")));
    // An unknown target is refused.
    assert!(!client::incoming_edit_allowed(&recs, &sender, [0xFF; 16]));
}

#[test]
fn blocked_set_persists_and_toggles_off_removes_file() {
    let dir = temp_dir("blocked");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    assert!(s.load_blocked().unwrap().is_empty());
    s.set_blocked([9; 32], true).unwrap();
    // It survived the restart.
    assert!(Store::unlock(&dir, b"test-pw").unwrap().load_blocked().unwrap().contains(&[9; 32]));
    // Unblock → empty → the file is deleted.
    s.set_blocked([9; 32], false).unwrap();
    assert!(s.load_blocked().unwrap().is_empty());
    assert!(!dir.join("blocked.dat").exists(), "an empty block list deletes the file");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Profile: own (profile.dat) + cache of peers' (peer_profiles.dat) ----

#[test]
fn own_profile_persists_at_rest_and_survives_restart() {
    use client::store::Profile;
    let dir = temp_dir("profile-own");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    s.save_profile(&Profile { name: "Alice".into(), bio: "secret".into(), avatar: None, photos: vec![], photos_ts: 0 })
        .unwrap();
    // At-rest: the raw file does NOT contain the name/bio in the clear.
    let raw = std::fs::read(dir.join("profile.dat")).unwrap();
    assert!(!raw.windows("secret".len()).any(|w| w == "secret".as_bytes()), "bio not in plaintext");
    // Survived a restart.
    let p = Store::unlock(&dir, b"test-pw").unwrap().load_profile().unwrap();
    assert_eq!(p.name, "Alice");
    assert_eq!(p.bio, "secret");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn peer_profile_never_touches_contacts_identity() {
    // HARD trust invariant: a received profile is only a per-IK hint; it NEVER
    // overwrites the local label / `verified` in contacts.dat. Neuter (if
    // set_peer_profile starts writing to contacts) -> red.
    use client::store::ContactRecord;
    let dir = temp_dir("profile-trust");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    let ik = [0x42; 32];
    s.save_contacts(&[ContactRecord { name: "MyLabel".into(), ik, verified: true }]).unwrap();
    // A profile arrives with a DIFFERENT self-declared name.
    s.set_peer_profile(ik, "TheirName", "their bio").unwrap();
    // The contact is untouched: label and verified unchanged.
    let c = &s.load_contacts().unwrap()[0];
    assert_eq!(c.name, "MyLabel", "local label not overwritten by profile");
    assert!(c.verified, "verified not reset by profile");
    // The hint landed in its own cache.
    let pp = s.load_peer_profiles().unwrap();
    assert_eq!(pp.get(&ik).unwrap().name, "TheirName");
    assert_eq!(pp.get(&ik).unwrap().bio, "their bio");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn peer_profile_clamps_oversize_name_and_bio_before_store() {
    use client::content::{MAX_PROFILE_BIO, MAX_PROFILE_NAME};
    let dir = temp_dir("profile-clamp");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    let ik = [1; 32];
    let long_name = "n".repeat(MAX_PROFILE_NAME * 3);
    let long_bio = "b".repeat(MAX_PROFILE_BIO * 3);
    s.set_peer_profile(ik, &long_name, &long_bio).unwrap();
    let pp = s.load_peer_profiles().unwrap();
    assert!(pp.get(&ik).unwrap().name.len() <= MAX_PROFILE_NAME, "name truncated to the cap");
    assert!(pp.get(&ik).unwrap().bio.len() <= MAX_PROFILE_BIO, "bio truncated to the cap");
    std::fs::remove_dir_all(&dir).ok();
}

// NOTE: the avatar-preservation invariant (a text update must not wipe an
// already-received avatar) is covered by a discriminating unit test in
// `store.rs` (`set_peer_profile_text_update_preserves_avatar`), which can seed a
// sealed avatar via the crate-internal key — impossible from this integration crate.

#[test]
fn corrupt_profile_files_load_as_empty_not_error() {
    let dir = temp_dir("profile-corrupt");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    std::fs::write(dir.join("profile.dat"), b"not a sealed profile").unwrap();
    std::fs::write(dir.join("peer_profiles.dat"), b"garbage").unwrap();
    assert_eq!(s.load_profile().unwrap(), client::store::Profile::default(), "corrupt profile -> empty");
    assert!(s.load_peer_profiles().unwrap().is_empty(), "corrupt cache -> empty, not an error");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn corrupt_meta_file_loads_as_empty_not_error() {
    let dir = temp_dir("meta-corrupt");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    // Garbage instead of a sealed blob — metadata is best-effort, and the history must not fall
    // over because meta.dat is corrupt.
    std::fs::write(dir.join("meta.dat"), b"not a sealed metadata blob").unwrap();
    assert!(s.load_meta().unwrap().is_empty(), "a corrupt meta.dat gives empty, not an error");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- File transfer through a relay (chunking plus reassembly) ----

/// Provision a §2.1 client: an account plus a dev capability FOR THIS relay on disk (a capability
/// is bound to a relay now — CRYPTO-24).
fn provision(tag: &str, relay: &client::RelayId) -> (PathBuf, Store, [u8; 32]) {
    let dir = temp_dir(tag);
    let store = Store::unlock(&dir, b"pw").unwrap();
    let acct = client::seed::derive(&seed_provision(&store)).account;
    let ik = acct.identity_public();
    store.save_capability_for(relay, &client::dev_capability()).unwrap();
    (dir, store, ik)
}

#[test]
fn file_transfer_roundtrips_through_relay_byte_identical() {
    use client::content::{decode, Content, Reassembler};
    let (relay, relay_id) = spawn_relay();
    let (adir, astore, _aik) = provision("file-alice", &relay_id);
    let (bdir, bstore, bob_ik) = provision("file-bob", &relay_id);

    // Bob publishes his bundle (§12) — otherwise Alice cannot initiate a session.
    let pr = client::publish_bundle(
        &ctx(relay, &relay_id),
        bstore.load_account().unwrap(),
        client::dev_capability(),
        NOW,
    );
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    // Alice: text (which establishes the session, so the manifest travels as a Ratchet), then a
    // ~5 KiB file (several 1024-byte chunks, validating the chunk size against the 1400 limit).
    client::send_text(&astore, &ctx(relay, &relay_id), &bob_ik, "hello".as_bytes(), NOW, NOW).unwrap();
    let file: Vec<u8> = (0..5000u32).map(|i| (i.wrapping_mul(7)) as u8).collect();
    client::send_file(&astore, &ctx(relay, &relay_id), &bob_ik, "report.bin", &file, NOW).unwrap();

    // Bob collects EVERYTHING in one recv (a single mailbox), decodes and reassembles.
    let msgs = client::recv_session(&bstore, &ctx(relay, &relay_id), NOW).unwrap();
    let mut re = Reassembler::new();
    let (mut got_text, mut got_file) = (None, None);
    for r in msgs.into_iter().flatten() {
        match decode(&r.plaintext).expect("the content decoded") {
            Content::Text(t) | Content::TextStamped { text: t, .. } => got_text = Some(t),
            c => {
            if let Some(f) = re.offer(c, NOW).expect("reassembly without errors") {
                    got_file = Some(f);
                }
            }
        }
    }
    assert_eq!(got_text.as_deref(), Some("hello".as_bytes()), "the text arrived");
    let f = match got_file.expect("file assembled from chunks") {
        client::content::Assembled::File(f) => f,
        other => panic!("expected a file, got {other:?}"),
    };
    assert_eq!(f.name, "report.bin");
    assert_eq!(f.bytes, file, "the file is byte for byte through a real relay");

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// Helper: a minimal (no-cookie) BlobPut — the relay answers `NeedCookie` before any
/// storage, so a `NeedCookie` proves the round-trip REACHED the relay.
fn probe_blob_put() -> BlobPutRequest {
    let nonce = relay::node::blob_put_nonce(&[7u8; 32], 0);
    BlobPutRequest {
        request_nonce: nonce.clone(),
        capability_proof: client::dev_capability().prove(&nonce, 0),
        client_addr: b"probe".to_vec(),
        carrier_id: b"karst-blob".to_vec(),
        cookie: None,
        blob_id: [7u8; 32],
        index: 0,
        count: 1,
        read_pub: client::blob_read_pub(&[7u8; 32]),
        data: vec![0u8; 16],
    }
}

/// FT4 discriminator: the relay serves MANY requests over ONE Noise session. Open a single
/// `BlobSession` and stream a whole 2-chunk blob through it — every put (including the cookie
/// handshake) rides the same connection. If the relay were still one-shot, the SECOND request on
/// the session would error; here both chunks land and the blob completes.
#[test]
fn one_session_streams_a_whole_blob() {
    let (addr, id) = spawn_relay_with_blobs();
    let t = SocketTransport::new(addr, id.noise_pub);
    let mut sess = t.open_blob_session().expect("open a reusable session");
    let blob_id = [0x5a; 32];
    let count = 2u32;
    let mut cookie = None;
    let mut requests = 0u32;
    for index in 0..count {
        loop {
            requests += 1;
            let nonce = relay::node::blob_put_nonce(&blob_id, index);
            let req = BlobPutRequest {
                request_nonce: nonce.clone(),
                capability_proof: client::dev_capability().prove(&nonce, 0),
                client_addr: vec![0x11u8; 32], // sender address is a 32-byte pseudonym
                carrier_id: b"karst-blob".to_vec(),
                cookie,
                blob_id,
                index,
                count,
                read_pub: client::blob_read_pub(&blob_id),
                data: vec![index as u8; 32],
            };
            match sess.put(&req).expect("the session stays open across requests") {
                BlobResponse::NeedCookie(c) => cookie = Some(c),
                BlobResponse::Stored | BlobResponse::Complete => break,
                BlobResponse::Rejected(r) => panic!("blob put rejected: {r}"),
                _ => panic!("unexpected blob response"),
            }
        }
    }
    assert!(requests > count, "the cookie handshake means more than {count} requests rode one session");
    assert_eq!(
        t.blob_stat(blob_id, &blob_id).unwrap(),
        Some((count, count, true)),
        "the whole blob completed over a single reused session"
    );
}

/// R2-13 (#164): admission is applied per request, INSIDE the Noise session — it cannot be
/// applied before the handshake, because the credential travels encrypted. So a peer with no
/// intention of authenticating still gets a connection slot and a handshake, and (before this
/// fix) could then sit in the request loop until `CONN_TOTAL_DEADLINE` — two minutes — issuing
/// requests that are all refused. `MAX_CONNECTIONS` such peers hold the whole handler pool
/// against everyone else, for free.
///
/// The fix cannot make admission happen sooner. It makes an UNADMITTED connection cheap to
/// hold: after `MAX_UNADMITTED_REQUESTS` requests without a single one getting past admission,
/// the relay drops it. This test drives the attack shape — a `BlobPut` that never presents the
/// cookie it is handed, so every response is `NeedCookie` — and asserts the connection dies at
/// the leash, NOT after 20 free requests. Neuter the check and the loop runs to 20 → RED.
///
/// The control below is the point: the same leash must be invisible to a legitimate upload,
/// which crosses the same threshold in request count but is admitted early.
#[test]
fn a_connection_that_never_gets_admitted_is_dropped_at_the_leash() {
    let (addr, id) = spawn_relay_with_blobs();
    let t = SocketTransport::new(addr, id.noise_pub);
    let mut sess = t.open_blob_session().expect("open a reusable session");

    let attempts = relay::server::MAX_UNADMITTED_REQUESTS + 12;
    let mut served = 0usize;
    for index in 0..attempts {
        let nonce = relay::node::blob_put_nonce(&[0x77; 32], index as u32);
        let req = BlobPutRequest {
            request_nonce: nonce.clone(),
            capability_proof: client::dev_capability().prove(&nonce, 0),
            client_addr: vec![0x22u8; 32],
            carrier_id: b"karst-blob".to_vec(),
            // Never presented, though the relay hands one back every time: this is the whole
            // attack — stay unadmitted while holding the slot.
            cookie: None,
            blob_id: [0x77; 32],
            index: index as u32,
            count: 1,
            read_pub: client::blob_read_pub(&[0x77; 32]),
            data: vec![0u8; 16],
        };
        match sess.put(&req) {
            Ok(BlobResponse::NeedCookie(_)) => served += 1,
            Ok(other) => panic!("a cookie-less put must be refused, got {other:?}"),
            Err(_) => break, // the relay closed the connection — the leash
        }
    }
    assert_eq!(
        served,
        relay::server::MAX_UNADMITTED_REQUESTS,
        "an unadmitted connection must be dropped after exactly {} refused requests, not held \
         open for {attempts}",
        relay::server::MAX_UNADMITTED_REQUESTS
    );

    // CONTROL: a legitimate upload sends MORE requests than the leash allows and must be
    // untouched by it, because its second request is admitted. Without this arm the test above
    // would also pass a fix that simply capped every connection at 8 requests — which would
    // break real uploads.
    let mut sess = t.open_blob_session().expect("open a second reusable session");
    let count = (relay::server::MAX_UNADMITTED_REQUESTS + 4) as u32;
    let blob_id = [0x78; 32];
    let mut cookie = None;
    let mut requests = 0usize;
    for index in 0..count {
        loop {
            requests += 1;
            let nonce = relay::node::blob_put_nonce(&blob_id, index);
            let req = BlobPutRequest {
                request_nonce: nonce.clone(),
                capability_proof: client::dev_capability().prove(&nonce, 0),
                client_addr: vec![0x33u8; 32],
                carrier_id: b"karst-blob".to_vec(),
                cookie,
                blob_id,
                index,
                count,
                read_pub: client::blob_read_pub(&blob_id),
                data: vec![index as u8; 32],
            };
            match sess.put(&req).expect("an ADMITTED session must survive past the leash") {
                BlobResponse::NeedCookie(c) => cookie = Some(c),
                BlobResponse::Stored | BlobResponse::Complete => break,
                other => panic!("unexpected blob response: {other:?}"),
            }
        }
    }
    assert!(
        requests > relay::server::MAX_UNADMITTED_REQUESTS,
        "the control must actually cross the leash: {requests} requests"
    );
    assert_eq!(
        t.blob_stat(blob_id, &blob_id).unwrap(),
        Some((count, count, true)),
        "the whole blob completed over one admitted session"
    );
}

/// A dead loopback address (nothing listens on these low ports).
fn dead_addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// A route through `DirectTcpAdapter` to `dest`.
fn direct_path(dest: SocketAddr) -> Path {
    Path::new(Arc::new(DirectTcpAdapter::default()), dest)
}

/// §15 FAILOVER over a dead endpoint: a primary that does not accept TCP is skipped and
/// the session completes over a live alternate — end-to-end through the real relay
/// socket. Discriminating: only real failover (not luck) gets a `NeedCookie` back;
/// make `round_trip_sized` use just the first path → this reds.
#[test]
fn failover_skips_dead_primary_and_reaches_live_relay() {
    let (real, relay_id) = spawn_relay_with_blobs();
    let dead = dead_addr(1); // nothing listens on port 1
    let transport =
        SocketTransport::with_paths(vec![direct_path(dead), direct_path(real)], relay_id.noise_pub);
    match transport.blob_put(&probe_blob_put()) {
        BlobResponse::NeedCookie(_) => {} // reached the relay over the live alternate
        other => panic!("failover should have reached the relay over the live path, got {:?}", tag(&other)),
    }
}

/// A4-10 (#217): the carrier badge names the path that ACTUALLY carried the message.
///
/// It used to be computed from the configuration — the primary path's proxy plus env — while
/// failover could route the message over an alternate with a different carrier. The badge then
/// claimed a protection that did not carry that message, which for a privacy product is worse
/// than showing nothing: the user decides what to send based on it.
///
/// Here the PRIMARY is a dead SOCKS5 route (so the configured answer would be "SOCKS5") and the
/// live alternate is direct. After a real send over the real relay, the badge must say `direct`.
///
/// Discriminating: it asserts what the badge says AFTER traffic has flowed, and the two paths
/// deliberately have DIFFERENT carriers — computing it from the configuration reddens this.
#[test]
fn the_carrier_badge_names_the_path_that_actually_carried_the_message() {
    let (real, relay_id) = spawn_relay_with_blobs();
    let dead_proxy = dead_addr(1); // nothing listens: this SOCKS5 route can never connect

    // Primary: SOCKS5 through the dead proxy. Alternate: direct to the live relay.
    //
    // The pair is built directly rather than through the route parser: in production the carrier
    // ALLOWLIST would narrow a SOCKS5 intent to {SOCKS5, wss-over-SOCKS5}, so this exact pair is
    // not one the parser would produce. The mismatch it demonstrates is not hypothetical though —
    // the same gap exists inside every allowed pair (a SOCKS5 intent failing over to
    // wss-over-SOCKS5, or a Direct intent failing over to SOCKS5), and this shape keeps the test
    // about the INDICATOR instead of about route parsing or environment variables.
    let mut relay = client::Relay::new(real, relay_id, Some(dead_proxy));
    relay.set_paths_for_test(vec![
        Path::new(Arc::new(Socks5Adapter::isolated(dead_proxy, "test-isolation")), Dest::from(real)),
        direct_path(real),
    ]);
    assert_eq!(
        relay.carrier().label(),
        "SOCKS5",
        "before anything runs the badge can only report intent — the configured primary"
    );

    // A real request over the real relay: the dead SOCKS5 primary fails, direct carries it.
    // `blob_stat` is a public read that goes through the very same path list.
    assert!(
        client::blob_stat(&relay, [0x5c; 32], &[0x5c; 32]).is_ok(),
        "the live alternate should have reached the relay"
    );

    assert_eq!(
        relay.carrier().label(),
        "direct",
        "after failover the badge must name the carrier that actually ran, not the configured one"
    );
}

/// **Handshake-level failover** — the case connect-level could not see: a path that
/// ACCEPTS the TCP connection and then never speaks Noise (a silent-drop on-path classifier, a hijacked
/// endpoint). The session must abandon it and complete over the live relay.
/// Discriminating on the retry boundary: with retry only on `connect()` this reds,
/// because the poisoned path connects fine and then stalls the handshake until
/// `READ_TIMEOUT`.
#[test]
fn failover_skips_a_path_that_accepts_tcp_then_stalls_the_handshake() {
    let (real, relay_id) = spawn_relay_with_blobs();
    // A listener that accepts and stays mute — TCP is fine, Noise never happens.
    let sink = TcpListener::bind("127.0.0.1:0").unwrap();
    let poisoned = sink.local_addr().unwrap();
    thread::spawn(move || {
        for c in sink.incoming() {
            // Hold each accepted connection open and silent; never reply.
            thread::spawn(move || {
                let _held = c;
                thread::sleep(std::time::Duration::from_secs(30));
            });
        }
    });

    // Short read timeout on the poisoned path only — same logic, fast test: the
    // handshake stalls, times out, and failover must move on.
    let stalling = Path::new(
        Arc::new(DirectTcpAdapter { read_timeout: Some(std::time::Duration::from_millis(300)) }),
        poisoned,
    );
    let transport = SocketTransport::with_paths(vec![stalling, direct_path(real)], relay_id.noise_pub);
    match transport.blob_put(&probe_blob_put()) {
        BlobResponse::NeedCookie(_) => {} // gave up on the mute path, reached the relay
        other => panic!("must fail over past the handshake-stalling path, got {:?}", tag(&other)),
    }
}

/// An adapter that counts connect attempts and always fails — stands in for a dead
/// route without needing a real blackholed IP.
struct CountingDead(Arc<std::sync::atomic::AtomicUsize>);
impl karst_transport::transport::TransportAdapter for CountingDead {
    fn carrier_label(&self) -> &'static str {
        "counting-dead"
    }

    fn connect(&self, _dest: &karst_transport::transport::Dest) -> std::io::Result<Box<dyn karst_transport::transport::Channel>> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "dead"))
    }
}

/// **Per-path health**: once a route has failed, later requests must stop paying for it.
/// Request 1 tries the dead primary (1 attempt) and completes over the live alternate;
/// request 2 must NOT touch the dead primary at all — it is in cooldown, so the healthy
/// alternate is tried first and succeeds. Discriminating: without health the counter
/// climbs on every request (that is the ~5 s-per-poll stall this fixes).
#[test]
fn health_stops_retrying_a_dead_path_on_every_request() {
    let (real, relay_id) = spawn_relay_with_blobs();
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let dead = Path::new(Arc::new(CountingDead(attempts.clone())), dead_addr(1));
    let transport = SocketTransport::with_paths(vec![dead, direct_path(real)], relay_id.noise_pub);

    assert!(matches!(transport.blob_put(&probe_blob_put()), BlobResponse::NeedCookie(_)));
    let after_first = attempts.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(after_first, 1, "the dead primary is tried once on the first request");

    assert!(matches!(transport.blob_put(&probe_blob_put()), BlobResponse::NeedCookie(_)));
    assert_eq!(
        attempts.load(std::sync::atomic::Ordering::SeqCst),
        after_first,
        "the cooled-down dead path is not retried on the next request"
    );
}

/// Security invariant: when ALL configured paths are dead, the connection FAILS —
/// failover never invents a fallback (e.g. a silent direct route), so a Tor/wss user
/// is never quietly deanonymized. Discriminating: a relay IS running, but it is NOT in
/// the path list; the only honest outcome is a transport error, never a success.
#[test]
fn failover_all_paths_dead_fails_never_silent_fallback() {
    let (_real, relay_id) = spawn_relay_with_blobs(); // reachable, but deliberately unlisted
    let transport = SocketTransport::with_paths(
        vec![
            direct_path(dead_addr(1)),
            direct_path(dead_addr(2)),
        ],
        relay_id.noise_pub,
    );
    match transport.blob_put(&probe_blob_put()) {
        BlobResponse::Rejected(s) => assert!(s.contains("transport"), "expected a transport error, got {s}"),
        other => panic!("all paths dead → must be an error, not {:?}", tag(&other)),
    }
}

/// An empty path list is an error, not a panic or a hang (defensive: a config that
/// filters every route away must fail honestly).
#[test]
fn transport_with_no_paths_errors() {
    let transport = SocketTransport::with_paths(vec![], [0u8; 32]);
    match transport.blob_put(&probe_blob_put()) {
        BlobResponse::Rejected(s) => assert!(s.contains("transport"), "expected a transport error, got {s}"),
        other => panic!("no paths → must be an error, not {:?}", tag(&other)),
    }
}

/// Short debug tag for BlobResponse (it isn't Debug) — for panic messages only.
fn tag(r: &BlobResponse) -> &'static str {
    match r {
        BlobResponse::NeedCookie(_) => "NeedCookie",
        BlobResponse::Stored => "Stored",
        BlobResponse::Complete => "Complete",
        BlobResponse::Chunk(_) => "Chunk",
        BlobResponse::Rejected(_) => "Rejected",
    }
}

/// The `client::send_loop` SEAM, through a real relay. `Peer::send_loop` is covered in
/// `node`, but the client wrapper does its own work — session lock, capability load,
/// deposit, the two persistence points, then the read-back — and none of that was
/// exercised. A seam that only ever runs in production is a seam nobody has tested.
///
/// The property: a loop must survive the round trip and come back to us, because the
/// whole drop-detection story rests on "a loop that does not return is evidence". If the
/// return path silently never worked, that signal would be a permanent, quiet lie.
#[test]
fn a_loop_survives_the_client_seam_and_comes_back() {
    let (relay_addr, relay_id) = spawn_relay();
    let dir = temp_dir("loop-seam");
    let store = Store::unlock(&dir, b"pw").unwrap();
    seed_provision(&store);
    store.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();

    let r = ctx(relay_addr, &relay_id);
    let back = client::send_loop(&store, &r, NOW).expect("a loop sends and reads back");
    assert_eq!(back, 1, "the loop did not come back through the client seam");

    // And it must be repeatable: the second loop is a fresh deposit, not a replay of the
    // first. A request nonce reused across loops would be rejected by the replay filter —
    // silently turning cover traffic off after exactly one message.
    let back = client::send_loop(&store, &r, NOW).expect("a second loop sends");
    assert_eq!(back, 1, "cover traffic stopped after the first loop");
    std::fs::remove_dir_all(&dir).ok();
}

/// Two accounts pointed at the SAME relay still ride different circuits.
///
/// This is the fact that decides what "compartments must not share a relay" can mean, and
/// the plan's answer (REFUSE) was written before per-handle isolation existed. Sharing a
/// relay ADDRESS is not sharing a circuit: `Relay::configured` mints a fresh isolation
/// token per construction and the GUI builds one `Relay` per account, so Tor
/// (`IsolateSOCKSAuth`) puts each account's traffic on its own circuit even when the
/// address, the proxy and the routes are identical. The relay therefore cannot join two
/// co-tenant accounts by source address.
///
/// What co-tenancy DOES cost is blast radius: one seizure exposes both accounts' mail. A
/// refusal is the wrong tool for that — it would break the inherit-on-AddAccount default
/// and forbid a user from deliberately trusting one relay with two lives. Disclosure is
/// the honest fix; see the compartments table in docs/ROADMAP.md.
///
/// Neuter `Relay::configured` to derive the token from the relay address (the "one relay,
/// one token" shape a REFUSE rule would imply) and this reddens.
#[test]
fn two_accounts_on_one_relay_do_not_share_a_circuit() {
    let (relay_addr, relay_id) = spawn_relay();
    let proxy: SocketAddr = "127.0.0.1:9050".parse().unwrap();
    // Same address, same relay identity, same proxy, same routes: as identical as two
    // compartments can be configured.
    let a = client::Relay::configured(relay_addr, relay_id, Some(proxy), "");
    let b = client::Relay::configured(relay_addr, relay_id, Some(proxy), "");
    assert_ne!(
        a.isolation(),
        b.isolation(),
        "two accounts on one relay share an isolation token — Tor would pool them onto ONE \
         circuit and the relay could join them by source address"
    );
    assert!(!a.isolation().is_empty(), "a compartment with no token is pooled with everyone");
}

/// One-time prekeys end-to-end through the process-per-call client: Bob publishes a batch
/// (persisted to a sidecar), two senders each open a conversation and BOTH arrive — which
/// only works if the relay handed each a DISTINCT OPK and Bob's `recv_session` reloaded the
/// persisted secret to accept each. Consumed OPKs are deleted and never reused.
#[test]
fn one_time_prekeys_work_and_persist_across_the_process_per_call_client() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("opk-a");
    let a2dir = temp_dir("opk-a2");
    let bdir = temp_dir("opk-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let a2store = Store::unlock(&a2dir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    for s in [&astore, &a2store, &bstore] {
        seed_provision(s);
        s.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    }
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(relay_addr, &relay_id);

    // Bob publishes WITH one-time prekeys (persisted). The sidecar now holds the secrets.
    let pr = client::publish_with_opks(&bstore, &r,  NOW).unwrap();
    assert!(matches!(pr, PublishResponse::Published));
    assert!(!bstore.load_opks().unwrap().is_empty(), "OPK secrets were not persisted");
    let opks_after_publish = bstore.load_opks().unwrap().len();

    // Two different senders each open a conversation with Bob.
    client::send_text(&astore, &r, &bob_ik, b"from A", NOW, NOW).unwrap();
    client::send_text(&a2store, &r, &bob_ik, b"from A2", NOW, NOW).unwrap();

    // Bob receives (fresh process each time). Both openers must decrypt — proving each used
    // a distinct OPK and Bob reloaded the secret to accept it.
    let got: Vec<Vec<u8>> = client::recv_session(&bstore, &r, NOW)
        .unwrap()
        .into_iter()
        .flatten()
        .map(|m| m.plaintext)
        .collect();
    let decoded: Vec<Vec<u8>> = got
        .iter()
        .filter_map(|p| match client::content::decode(p) {
            Ok(client::content::Content::TextStamped { text, .. }) => Some(text),
            _ => None,
        })
        .collect();
    assert!(decoded.contains(&b"from A".to_vec()), "sender A's opener was lost");
    assert!(decoded.contains(&b"from A2".to_vec()), "sender A2's opener was lost");

    // The two consumed OPKs are gone from the sidecar (never reusable).
    assert_eq!(
        bstore.load_opks().unwrap().len(),
        opks_after_publish - 2,
        "consumed one-time prekeys were not deleted from the persisted set"
    );
}

/// The desktop's `create_post` spawns a fan-out thread PER post. Posting two images quickly puts
/// two threads in flight racing the same session/ratchet, and their manifests+chunks interleave in
/// the recipient's single per-sender reassembler. A user reported one of two images vanishing —
/// this reproduces that exact shape in-process, deterministically, no relay/GUI flake.
#[test]
fn two_concurrent_image_posts_both_reunite_with_their_posts() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("twoimg-a");
    let bdir = temp_dir("twoimg-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    let id1 = client::store::random16();
    let id2 = client::store::random16();
    let img1 = vec![1u8; 5000];
    let img2 = vec![2u8; 6000];
    let h1 = {
        let (s, r, i, id) = (astore.clone(), r.clone(), img1.clone(), id1);
        std::thread::spawn(move || {
            client::send_publication(&s, &r, &bob_ik, id, "photo one", 7, NOW).unwrap();
            client::send_post_image(&s, &r, &bob_ik, id, &i, NOW).unwrap();
        })
    };
    let h2 = {
        let (s, r, i, id) = (astore.clone(), r.clone(), img2.clone(), id2);
        std::thread::spawn(move || {
            client::send_publication(&s, &r, &bob_ik, id, "photo two", 8, NOW).unwrap();
            client::send_post_image(&s, &r, &bob_ik, id, &i, NOW).unwrap();
        })
    };
    h1.join().unwrap();
    h2.join().unwrap();

    // Drain the mailbox over several polls (like the desktop), routing exactly as the poll does.
    let mut re = client::content::Reassembler::new();
    for _ in 0..10 {
        let got = recv_multi(&bstore, std::slice::from_ref(&r), NOW).unwrap();
        let msgs: Vec<_> = got.messages.into_iter().flatten().collect();
        if msgs.is_empty() {
            break;
        }
        for m in msgs {
            match client::content::decode(&m.plaintext) {
                Ok(client::content::Content::Publication { id, text, ts }) => {
                    bstore
                        .append_feed(&client::store::FeedRecord { author: m.sender, id, text, ts, expire_at: None })
                        .unwrap();
                }
                Ok(c) => {
                    if let Ok(Some(client::content::Assembled::PostImage { post_id, bytes })) = re.offer(c, NOW) {
                        bstore.set_feed_image(m.sender, post_id, bytes).unwrap();
                    }
                }
                Err(e) => panic!("content decode: {e}"),
            }
        }
    }
    assert_eq!(bstore.feed_image(alice_ik, id1), Some(img1), "FIRST post's image was lost");
    assert_eq!(bstore.feed_image(alice_ik, id2), Some(img2), "SECOND post's image was lost");
    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// User bug: A publishes a post and it stays INVISIBLE on B until B publishes back. That is the
/// simultaneous-first-contact (split-session) hazard — both sides PQXDH-initiate to each other
/// before either receives, so each ends up with two half-sessions for the same peer. This test
/// reproduces it deterministically: both publish (no prior chat), then both receive; assert both
/// feeds hold BOTH posts. (One-way first-contact-by-publication already passes elsewhere.)
#[test]
fn simultaneous_first_contact_publications_both_deliver() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("simul-a");
    let bdir = temp_dir("simul-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(relay_addr, &relay_id);
    // Both publish bundles so each is reachable; they exchange nothing else.
    client::publish_bundle(&r, astore.load_account().unwrap(), client::dev_capability(), NOW);
    client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);

    // Simultaneous first contact: each posts to the other BEFORE either has received anything.
    let ida = client::store::random16();
    let idb = client::store::random16();
    client::send_publication(&astore, &r, &bob_ik, ida, "from alice", 7, NOW).expect("A publishes");
    client::send_publication(&bstore, &r, &alice_ik, idb, "from bob", 8, NOW).expect("B publishes");

    let drain = |store: &Store| {
        for _ in 0..8 {
            let got = recv_multi(store, std::slice::from_ref(&r), NOW).unwrap();
            let msgs: Vec<_> = got.messages.into_iter().flatten().collect();
            if msgs.is_empty() {
                break;
            }
            for m in msgs {
                if let Ok(client::content::Content::Publication { id, text, ts }) =
                    client::content::decode(&m.plaintext)
                {
                    store
                        .append_feed(&client::store::FeedRecord { author: m.sender, id, text, ts, expire_at: None })
                        .unwrap();
                }
            }
        }
    };
    drain(&bstore); // B receives A's post — B never chatted/sent first (beyond its own publish)
    drain(&astore); // A receives B's post

    assert!(
        bstore.load_feed().unwrap().iter().any(|f| f.id == ida),
        "B is MISSING alice's publication — invisible-until-reverse (split-session) bug reproduced"
    );
    assert!(
        astore.load_feed().unwrap().iter().any(|f| f.id == idb),
        "A is missing bob's publication"
    );

    // The DISCRIMINATOR that a naive `replace` fix cannot pass: a SECOND publication each way.
    // After a split, `replace` leaves the two sides on different drop-boxes (A→B on one root key,
    // B→A on the other), so message #2 — a Ratchet message on the surviving session — misses the
    // box the peer fetches. Only a true two-session hold (own outbound + peer's inbound) routes it.
    let ida2 = client::store::random16();
    let idb2 = client::store::random16();
    client::send_publication(&astore, &r, &bob_ik, ida2, "alice second", 9, NOW).expect("A publishes #2");
    client::send_publication(&bstore, &r, &alice_ik, idb2, "bob second", 10, NOW).expect("B publishes #2");
    drain(&bstore);
    drain(&astore);
    assert!(
        bstore.load_feed().unwrap().iter().any(|f| f.id == ida2),
        "B is MISSING alice's SECOND publication — session split on ongoing messages (replace-fix trap)"
    );
    assert!(
        astore.load_feed().unwrap().iter().any(|f| f.id == idb2),
        "A is MISSING bob's SECOND publication — session split on ongoing messages"
    );

    // Idempotency / no re-delivery storm: an extra poll after everything is drained must simply
    // return Ok with nothing — never re-run key agreement (which consumes the OPK) and never
    // resurface an un-decryptable payload every cycle (the `chunk without a manifest` → Killed hang).
    let extra = recv_multi(&bstore, std::slice::from_ref(&r), NOW).unwrap();
    assert!(extra.messages.into_iter().flatten().count() == 0, "B re-delivered mail after a clean drain");

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// Multi-attachment post: text first, then several attachments (images + a file) fan out and
/// reassemble on the recipient, each landing in the feed_attachments sidecar by index/kind/name.
#[test]
fn post_attachments_round_trip_images_and_file() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("att-a");
    let bdir = temp_dir("att-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(relay_addr, &relay_id);
    client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);

    let post_id = client::store::random16();
    client::send_publication(&astore, &r, &bob_ik, post_id, "album", 7, NOW).unwrap();
    let img1 = vec![1u8; 2500]; // multi-chunk
    let img2 = vec![2u8; 1500];
    let file = vec![3u8; 3333];
    client::send_post_attachment(&astore, &r, &bob_ik, post_id, 0, 0, "", &img1, NOW).unwrap();
    client::send_post_attachment(&astore, &r, &bob_ik, post_id, 1, 0, "", &img2, NOW).unwrap();
    client::send_post_attachment(&astore, &r, &bob_ik, post_id, 2, 1, "notes.txt", &file, NOW).unwrap();

    let mut reasm = client::content::Reassembler::default();
    for _ in 0..40 {
        let got = recv_multi(&bstore, std::slice::from_ref(&r), NOW).unwrap();
        let msgs: Vec<_> = got.messages.into_iter().flatten().collect();
        if msgs.is_empty() {
            break;
        }
        for m in msgs {
            if let Ok(c) = client::content::decode(&m.plaintext) {
                if let Ok(Some(client::content::Assembled::PostAttachment { post_id, index, kind, name, bytes })) =
                    reasm.offer(c, NOW)
                {
                    bstore
                        .set_feed_attachment(m.sender, post_id, client::store::StoredAttachment { index, kind, name, bytes, failed: false })
                        .unwrap();
                }
            }
        }
    }
    let atts = bstore.feed_attachments(alice_ik, post_id);
    assert_eq!(atts.len(), 3, "all three attachments landed");
    assert_eq!(atts[0].kind, 0);
    assert_eq!(atts[0].bytes, img1, "image #1 byte-identical");
    assert_eq!(atts[1].bytes, img2, "image #2 byte-identical");
    assert_eq!(atts[2].kind, 1);
    assert_eq!(atts[2].name, "notes.txt");
    assert_eq!(atts[2].bytes, file, "file byte-identical");
    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// Realistic multi-attachment sizes (3 × ~85 KiB = ~230 chunks total). Proves the reassembler +
/// mailbox paging deliver ALL of them when the recipient keeps draining — isolating a "only the
/// first photo arrived" report from the client's poll cadence.
#[test]
fn three_large_attachments_all_arrive() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("bigatt-a");
    let bdir = temp_dir("bigatt-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(relay_addr, &relay_id);
    client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);

    let post_id = client::store::random16();
    client::send_publication(&astore, &r, &bob_ik, post_id, "album", 7, NOW).unwrap();
    let a0 = vec![7u8; 62073];
    let a1 = vec![8u8; 91378];
    let a2 = vec![9u8; 58593];
    client::send_post_attachment(&astore, &r, &bob_ik, post_id, 0, 0, "", &a0, NOW).unwrap();
    client::send_post_attachment(&astore, &r, &bob_ik, post_id, 1, 0, "", &a1, NOW).unwrap();
    client::send_post_attachment(&astore, &r, &bob_ik, post_id, 2, 0, "", &a2, NOW).unwrap();

    let mut reasm = client::content::Reassembler::default();
    for _ in 0..200 {
        let got = recv_multi(&bstore, std::slice::from_ref(&r), NOW).unwrap();
        let msgs: Vec<_> = got.messages.into_iter().flatten().collect();
        if msgs.is_empty() {
            break;
        }
        for m in msgs {
            if let Ok(c) = client::content::decode(&m.plaintext) {
                if let Ok(Some(client::content::Assembled::PostAttachment { post_id, index, kind, name, bytes })) =
                    reasm.offer(c, NOW)
                {
                    bstore
                        .set_feed_attachment(m.sender, post_id, client::store::StoredAttachment { index, kind, name, bytes, failed: false })
                        .unwrap();
                }
            }
        }
    }
    let atts = bstore.feed_attachments(alice_ik, post_id);
    assert_eq!(atts.len(), 3, "all three large attachments arrived");
    assert_eq!(atts[0].bytes, a0);
    assert_eq!(atts[1].bytes, a1);
    assert_eq!(atts[2].bytes, a2);
    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// Mutual-consent contact add: A's request carries A's profile so B sees who's asking; B's accept
/// carries B's profile so A sees who accepted. Profiles cross only WITH consent.
#[test]
fn contact_request_and_accept_exchange_profiles() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("creq-a");
    let bdir = temp_dir("creq-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(relay_addr, &relay_id);
    client::publish_bundle(&r, astore.load_account().unwrap(), client::dev_capability(), NOW);
    client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);

    // A → B: contact request carrying A's profile.
    client::send_contact_request(&astore, &r, &bob_ik, "Alice", "privacy first", NOW).unwrap();

    // B drains and applies the request like the desktop poll.
    let drain = |store: &Store| {
        for _ in 0..8 {
            let got = recv_multi(store, std::slice::from_ref(&r), NOW).unwrap();
            let msgs: Vec<_> = got.messages.into_iter().flatten().collect();
            if msgs.is_empty() { break; }
            for m in msgs {
                match client::content::decode(&m.plaintext) {
                    Ok(client::content::Content::ContactRequest { name, bio }) => {
                        store.set_peer_profile(m.sender, &name, &bio).unwrap();
                        store.add_contact_request(m.sender).unwrap();
                    }
                    Ok(client::content::Content::ContactAccept { name, bio }) => {
                        store.set_peer_profile(m.sender, &name, &bio).unwrap();
                    }
                    _ => {}
                }
            }
        }
    };
    drain(&bstore);
    assert_eq!(bstore.load_contact_requests(), vec![alice_ik], "B has A's pending request");
    assert_eq!(bstore.load_peer_profiles().unwrap().get(&alice_ik).map(|p| p.name.as_str()), Some("Alice"));

    // B accepts → sends its profile back; drops the request.
    client::send_contact_accept(&bstore, &r, &alice_ik, "Bob", "hi there", NOW).unwrap();
    bstore.remove_contact_request(alice_ik).unwrap();
    assert!(bstore.load_contact_requests().is_empty(), "accepted request cleared");

    drain(&astore);
    assert_eq!(astore.load_peer_profiles().unwrap().get(&bob_ik).map(|p| p.name.as_str()), Some("Bob"),
        "A now sees Bob's name — only after Bob consented");

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// #98 end-to-end over the REAL socket: a post attachment sent via `send_post_attachment_blob`
/// uploads a PER-RECIPIENT blob and deposits only a tiny `PostAttachmentRef` in the mailbox (not
/// ~90 inline chunks). The recipient's `recv_session` persists it as a PENDING POST ATTACHMENT —
/// crucially NOT as a file download (it never surfaces as a file transfer) — and
/// `download_post_attachment` fetches it BYTE-IDENTICAL into the `feed_attachments` sidecar, keyed
/// by (author, post_id, index). This is the blob-transport that fixes the multi-image post that
/// overflowed the 256-seal mailbox cap on the inline path.
#[test]
fn post_attachment_blob_round_trips_into_the_feed_sidecar() {
    let (addr, rid) = spawn_relay_with_blobs();
    let astore = Store::unlock(temp_dir("pab-a"), b"pw").unwrap();
    let bstore = Store::unlock(temp_dir("pab-b"), b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&rid, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&rid, &client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(addr, &rid);
    assert!(matches!(
        client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW),
        PublishResponse::Published
    ));

    // Bob SUBSCRIBED to Alice — the same consent the feed itself requires of a publication. SEC-31:
    // without this the refs are refused at the door, which is the point of the gate; a post
    // attachment is only ever fetched for an author whose posts we would display.
    bstore.set_channel_peer(alice_ik, true).unwrap();

    // The ACTUAL failing scenario: FOUR multi-chunk images on ONE post. On the inline path this was
    // ~360 seals into a 256-cap mailbox → the later images bounced off MailboxFull ("one of four
    // published, the rest didn't"). On the blob path it's four tiny refs + four per-recipient blobs.
    let post_id = client::store::random16();
    const N: u32 = 4;
    let images: Vec<Vec<u8>> = (0..N)
        .map(|k| {
            (0..(client::blob::BLOB_CHUNK + 2048 + k as usize))
                .map(|i| (i * 7 + k as usize) as u8)
                .collect()
        })
        .collect();
    for (k, img) in images.iter().enumerate() {
        assert!(img.len() <= client::content::MAX_POST_IMAGE_BYTES);
        client::send_post_attachment_blob(&astore, &r, &bob_ik, post_id, k as u32, 0, "", img, NOW)
            .expect("send a post attachment via the blob path");
    }

    // Bob receives the refs → pending POST ATTACHMENTS, NOT file downloads (no transfer UI). Drain
    // until no new refs arrive (a fetch page may not carry all four seals at once).
    let mut pend = Vec::new();
    for _ in 0..8 {
        let _ = client::recv_session(&bstore, &r, NOW).unwrap();
        pend = bstore.list_pending_post_attachments().unwrap();
        if pend.len() as u32 >= N {
            break;
        }
    }
    assert!(
        bstore.list_pending_downloads().unwrap().is_empty(),
        "a post attachment must never surface as a file download"
    );
    assert_eq!(pend.len() as u32, N, "all four refs became pending post attachments");
    for p in &pend {
        assert_eq!(p.post_id, post_id);
        assert_eq!(p.sender, alice_ik, "keyed to the post's author");
    }

    // Driving each fetch lands its bytes in the feed sidecar at its own index, byte-identical.
    for p in &pend {
        match client::download_post_attachment(&bstore, &r, p, NOW) {
            client::DownloadOutcome::Done(_) => {}
            _ => panic!("download_post_attachment did not complete"),
        }
    }
    assert!(
        bstore.list_pending_post_attachments().unwrap().is_empty(),
        "every pending entry is cleared on success"
    );
    let mut atts = bstore.feed_attachments(alice_ik, post_id);
    atts.sort_by_key(|a| a.index);
    assert_eq!(atts.len() as u32, N, "all four attachments landed against the one post");
    for (k, a) in atts.iter().enumerate() {
        assert_eq!(a.index, k as u32, "distinct index per attachment");
        assert_eq!(a.bytes, images[k], "attachment {k} is byte-identical in the feed sidecar");
    }

    // Idempotent: re-driving a ref just overwrites its (post_id,index) slot — no duplicate.
    let _ = client::download_post_attachment(&bstore, &r, &pend[0], NOW);
    assert_eq!(
        bstore.feed_attachments(alice_ik, post_id).len() as u32,
        N,
        "a redelivered/re-driven ref stays idempotent (no extra slot)"
    );

    // SEC-31 over the real socket: Bob unsubscribes, so Alice is no longer a feed source. The very
    // same send that worked four times above must now leave NOTHING queued — the ref is refused
    // before it can occupy a durable fetch slot, even though the session and the blob are fine.
    bstore.set_channel_peer(alice_ik, false).unwrap();
    client::send_post_attachment_blob(&astore, &r, &bob_ik, post_id, N, 0, "", &images[0], NOW)
        .expect("the SEND side is unchanged — the gate is the recipient's");
    for _ in 0..4 {
        let _ = client::recv_session(&bstore, &r, NOW).unwrap();
    }
    assert!(
        bstore.list_pending_post_attachments().unwrap().is_empty(),
        "an attachment from an author we no longer follow must not become queued work"
    );
}

/// #125 end-to-end over the REAL socket: a 6-photo gallery (too big for one mailbox) sent via
/// `send_gallery_blob` uploads a PER-RECIPIENT blob and deposits only a tiny `GalleryRef`. The
/// recipient's `recv_session` records a PENDING GALLERY (confirmed-contacts-only), NOT a file
/// download, and `download_gallery` fetches it and replaces the sender's peer photos BYTE-IDENTICAL.
/// This is the blob-transport that lifts the 2-photo inline cap.
#[test]
fn gallery_blob_round_trips_and_replaces_peer_photos() {
    let (addr, rid) = spawn_relay_with_blobs();
    let astore = Store::unlock(temp_dir("gal-a"), b"pw").unwrap();
    let bstore = Store::unlock(temp_dir("gal-b"), b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&rid, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&rid, &client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(addr, &rid);
    assert!(matches!(
        client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW),
        PublishResponse::Published
    ));
    // Bob must have Alice as a CONFIRMED contact, or her gallery ref is dropped (the gate).
    bstore
        .save_contacts(&[client::store::ContactRecord { name: "Alice".into(), ik: alice_ik, verified: false }])
        .unwrap();
    bstore.set_unconfirmed(alice_ik, false).unwrap();

    // SIX avatar-sized photos — packs to ~540 KB (~528 chunks), far past the 256-seal mailbox cap,
    // so this is exactly the case the blob path exists for.
    let photos: Vec<Vec<u8>> = (0..6u32)
        .map(|k| (0..(90_000 + k as usize)).map(|i| (i * 7 + k as usize) as u8).collect())
        .collect();
    assert!(!client::content::gallery_fits_inline(client::content::pack_gallery(NOW, &photos).len()),
        "a 6-photo gallery must NOT fit inline (this test exercises the blob path)");
    client::send_gallery_blob(&astore, &r, &bob_ik, &photos, NOW).expect("send gallery via blob path");

    // Bob receives ONE tiny ref → a pending gallery, NOT a file download.
    let mut pend = Vec::new();
    for _ in 0..8 {
        let _ = client::recv_session(&bstore, &r, NOW).unwrap();
        pend = bstore.list_pending_galleries().unwrap();
        if !pend.is_empty() {
            break;
        }
    }
    assert!(bstore.list_pending_downloads().unwrap().is_empty(), "a gallery must never surface as a file download");
    assert_eq!(pend.len(), 1, "one pending gallery, keyed by sender");
    assert_eq!(pend[0].sender, alice_ik);

    // Driving the fetch replaces Bob's peer photos for Alice, byte-identical.
    match client::download_gallery(&bstore, &r, &pend[0], NOW) {
        client::DownloadOutcome::Done(_) => {}
        _ => panic!("download_gallery did not complete"),
    }
    assert!(bstore.list_pending_galleries().unwrap().is_empty(), "pending cleared on success");
    let got = bstore.load_peer_profiles().unwrap().get(&alice_ik).cloned().unwrap_or_default().photos;
    assert_eq!(got, photos, "all six gallery photos land in the peer profile, byte-identical");

    // A stranger's gallery ref is DROPPED (not a confirmed contact) — no pending, no fetch.
    let cstore = Store::unlock(temp_dir("gal-c"), b"pw").unwrap();
    seed_provision(&cstore);
    cstore.save_shared_capability_for(&rid, &client::dev_capability()).unwrap();
    let carol_ik = cstore.load_account().unwrap().identity_public();
    let _ = carol_ik;
    // (Alice is NOT Carol's contact.) Carol receives Alice's ref → nothing pending.
    assert!(matches!(
        client::publish_bundle(&r, cstore.load_account().unwrap(), client::dev_capability(), NOW),
        PublishResponse::Published
    ));
    let carol_bob_ik = cstore.load_account().unwrap().identity_public();
    client::send_gallery_blob(&astore, &r, &carol_bob_ik, &photos, NOW).expect("send to carol");
    for _ in 0..4 { let _ = client::recv_session(&cstore, &r, NOW).unwrap(); }
    assert!(cstore.list_pending_galleries().unwrap().is_empty(),
        "an unsolicited gallery ref from a non-contact is dropped, not fetched");
}

/// #106 IDENTITY PAIRING (the "add-the-IK-that-wrote" bug): a contact request/accept must ride the
/// SAME proxy pair as the conversation. B receives A's request ON one of B's proxies and must reply
/// FROM that same proxy, so A sees the accept from the EXACT IK it wrote to — not B's DEFAULT proxy,
/// which would file B as a second, phantom contact. This is the discriminator the desktop fix targets
/// (accept/add default to `proxy_for_contact` = the pinned receiving proxy, not `default_proxy`).
#[test]
fn contact_accept_comes_from_the_proxy_that_received_the_request() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("cid-a");
    let bdir = temp_dir("cid-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    astore.create_proxy("p0", NOW).unwrap(); // mints indices' own random secrets (#207)
    bstore.create_proxy("p0", NOW).unwrap();
    bstore.create_proxy("p1", NOW).unwrap();
    // A acts as proxy 0; B is reached on proxy 1 (NOT B's default proxy 0).
    let a = astore.as_proxy(0);
    let b0 = bstore.as_proxy(0);
    let b1 = bstore.as_proxy(1);
    let a_ik = a.load_account().unwrap().identity_public();
    let b0_ik = b0.load_account().unwrap().identity_public();
    let b1_ik = b1.load_account().unwrap().identity_public();
    assert_ne!(b0_ik, b1_ik, "two distinct B proxies");
    let r = ctx(relay_addr, &relay_id);

    // A must be reachable (for B's accept) and B-proxy-1 reachable (for A's request).
    assert!(matches!(
        client::publish_bundle(&r, a.load_account().unwrap(), client::dev_capability(), NOW),
        PublishResponse::Published
    ));
    assert!(matches!(
        client::publish_bundle(&r, b1.load_account().unwrap(), client::dev_capability(), NOW),
        PublishResponse::Published
    ));

    // A sends a contact request to B-proxy-1.
    client::send_contact_request(&a, &r, &b1_ik, "A", "a bio", NOW).unwrap();
    // B receives it ON proxy 1 — the proxy the desktop pins the contact to and must reply from.
    let got = client::recv_session(&b1, &r, NOW).unwrap();
    let m = got.into_iter().flatten().next().expect("B-proxy-1 got the request");
    assert_eq!(m.sender, a_ik, "the requester is A's proxy");
    assert!(matches!(client::content::decode(&m.plaintext).unwrap(), client::content::Content::ContactRequest { .. }));
    // Sanity: B's proxy 0 (default) did NOT receive it — so replying from default would be wrong.
    assert!(client::recv_session(&b0, &r, NOW).unwrap().into_iter().flatten().next().is_none());

    // THE FIX: B replies from the SAME proxy 1 (proxy_for_contact = the pinned receiving proxy).
    client::send_contact_accept(&b1, &r, &a_ik, "B", "b bio", NOW).unwrap();

    // A receives the accept — its sender is B-proxy-1 (the IK A wrote to), NOT B-proxy-0.
    let gota = client::recv_session(&a, &r, NOW).unwrap();
    let ma = gota.into_iter().flatten().next().expect("A got the accept");
    assert_eq!(ma.sender, b1_ik, "accept comes from the SAME proxy A contacted — one identity, no phantom");
    assert_ne!(ma.sender, b0_ik, "NOT B's default proxy");
    assert!(matches!(client::content::decode(&ma.plaintext).unwrap(), client::content::Content::ContactAccept { .. }));

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// #109 live-pull wire: B sends a `PostsRequest` to A and A (the author) answers with a
/// `Publication` back to B — the request + reply both deliver + decode over the real socket. (The
/// "serve only PUBLIC posts" selection is desktop policy, tested there; this pins the transport.)
#[test]
fn posts_request_and_reply_round_trip() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("pull-a");
    let bdir = temp_dir("pull-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let a_ik = astore.load_account().unwrap().identity_public();
    let b_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(relay_addr, &relay_id);
    // Both publish so first-contact can open a session in each direction.
    assert!(matches!(client::publish_bundle(&r, astore.load_account().unwrap(), client::dev_capability(), NOW), PublishResponse::Published));
    assert!(matches!(client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW), PublishResponse::Published));

    // B visits A's profile → PostsRequest to A.
    client::send_posts_request(&bstore, &r, &a_ik, NOW).unwrap();
    let got = client::recv_session(&astore, &r, NOW).unwrap();
    let m = got.into_iter().flatten().next().expect("A received the request");
    assert_eq!(m.sender, b_ik);
    assert!(matches!(client::content::decode(&m.plaintext).unwrap(), client::content::Content::PostsRequest));

    // A answers with one public post back to B.
    let pid = client::store::random16();
    client::send_publication(&astore, &r, &b_ik, pid, "a public post", NOW, NOW).unwrap();
    let gotb = client::recv_session(&bstore, &r, NOW).unwrap();
    let mb = gotb.into_iter().flatten().next().expect("B received the reply post");
    assert_eq!(mb.sender, a_ik);
    match client::content::decode(&mb.plaintext).unwrap() {
        client::content::Content::Publication { id, text, .. } => {
            assert_eq!(id, pid);
            assert_eq!(text, "a public post");
        }
        other => panic!("expected a Publication, got {other:?}"),
    }
    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// #100 send-side multi-homing (failover): with the session already established, a send whose
/// PRIMARY relay is down still delivers — `send_session_multi` flushes the (exact, already-sealed)
/// queued ciphertext through a live SECONDARY, and the recipient polling that relay gets it. Proves
/// a blocked primary doesn't strand an ongoing conversation.
#[test]
fn send_multihoming_fails_over_to_a_secondary_relay() {
    let (addr, rid) = spawn_relay();
    let astore = Store::unlock(temp_dir("mh-a"), b"pw").unwrap();
    let bstore = Store::unlock(temp_dir("mh-b"), b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&rid, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&rid, &client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let live = ctx(addr, &rid);
    assert!(matches!(
        client::publish_bundle(&live, bstore.load_account().unwrap(), client::dev_capability(), NOW),
        PublishResponse::Published
    ));

    // Establish the session on the live relay (first contact), Bob receives it.
    client::send_text(&astore, &live, &bob_ik, b"hello", NOW, NOW).unwrap();
    assert!(!client::recv_session(&bstore, &live, NOW).unwrap().into_iter().flatten().next().is_none());

    // Now the PRIMARY is down (nothing listening on this port); the live relay is a secondary.
    let dead = client::Relay::new("127.0.0.1:1".parse::<std::net::SocketAddr>().unwrap(), rid, None);
    let relays = [dead, live.clone()];
    // A session-established send: primary deposit fails → failover flushes it through the secondary.
    let reached = client::send_session_multi(&astore, &relays, &bob_ik, &client::content::encode(
        &client::content::Content::TextStamped { text: b"failover".to_vec(), ts: NOW }), NOW).unwrap();
    assert!(reached, "delivered via the secondary despite the dead primary");

    // Bob, polling the live relay, gets the failed-over message.
    let got = client::recv_session(&bstore, &live, NOW).unwrap();
    let m = got.into_iter().flatten().next().expect("Bob got the failed-over message");
    match client::content::decode(&m.plaintext).unwrap() {
        client::content::Content::TextStamped { text, .. } => assert_eq!(text, b"failover"),
        other => panic!("expected the failover text, got {other:?}"),
    }
}

/// #101 cover traffic: `send_cover` deposits a dummy through the EXACT real send path (to our own
/// mailbox), so on the wire it's indistinguishable from a real deposit; we then fetch it back with
/// `sender == self`, which is how the client DROPS it. Proves the cover rides the real path and is
/// self-cleaning (no separate tell-tale channel).
#[test]
fn cover_traffic_deposits_via_the_real_path_and_is_self_addressed() {
    let (addr, rid) = spawn_relay();
    let astore = Store::unlock(temp_dir("cov-a"), b"pw").unwrap();
    seed_provision(&astore);
    astore.save_shared_capability_for(&rid, &client::dev_capability()).unwrap();
    let a_ik = astore.load_account().unwrap().identity_public();
    let r = ctx(addr, &rid);
    // We must have a published bundle so the self-session's first contact can fetch it.
    assert!(matches!(
        client::publish_bundle(&r, astore.load_account().unwrap(), client::dev_capability(), NOW),
        PublishResponse::Published
    ));

    let reached = client::send_cover(&astore, &r, NOW).expect("cover deposit runs");
    assert!(reached, "the cover deposit reached the relay (the observable-on-the-wire cover event)");
    // It lands in our OWN outbound box, which our normal receive does NOT poll → zero inbox clutter.
    let got = client::recv_session(&astore, &r, NOW).unwrap();
    assert!(got.into_iter().flatten().next().is_none(), "cover never clutters our inbox");
    let _ = a_ik;
}

// Coverage restored after the legacy egui worker was retired: its `worker_e2e` suite was the ONLY
// place the next three behaviours were exercised end to end, and the shipping desktop has no tests
// of its own. They are asserted here, at the `client` layer where the logic actually lives and
// which the desktop reuses verbatim.

/// A DISAPPEARING message is delivered but must never be written to disk. If it were persisted,
/// "disappearing" would be a UI illusion — the plaintext would outlive the timer in history.
#[test]
fn an_expiring_message_is_delivered_but_never_persisted() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("expiring-a");
    let bdir = temp_dir("expiring-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    client::send_text_expiring(&astore, &r, &bob_ik, b"burn after reading", 300, NOW).unwrap();
    let got = client::recv_session(&bstore, &r, NOW).unwrap();
    let texts: Vec<Vec<u8>> = got
        .into_iter()
        .flatten()
        .filter_map(|m| match client::content::decode(&m.plaintext) {
            Ok(client::content::Content::TextExpiring { text, .. }) => Some(text),
            _ => None,
        })
        .collect();
    assert_eq!(texts, vec![b"burn after reading".to_vec()], "it IS delivered to the caller");
    assert!(
        bstore.load_history().unwrap().is_empty(),
        "a disappearing message must leave nothing on disk — otherwise the timer is decoration"
    );

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// DELETE-FOR-EVERYONE must reach the recipient as a control envelope carrying the shared
/// timestamp, so the peer can find and remove the same record. The sender cannot rely on the
/// recipient's local ids — the shared `ts` is the join key.
#[test]
fn delete_for_everyone_reaches_the_peer_with_the_shared_timestamp() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("delfe-a");
    let bdir = temp_dir("delfe-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    client::send_text(&astore, &r, &bob_ik, b"regrettable", NOW, NOW).unwrap();
    let _ = client::recv_session(&bstore, &r, NOW).unwrap();
    assert_eq!(bstore.load_history().unwrap().len(), 1, "the message landed");

    client::send_delete_for_everyone(&astore, &r, &bob_ik, NOW, b"regrettable", NOW).unwrap();
    let got = client::recv_session(&bstore, &r, NOW).unwrap();
    let deletes: Vec<u64> = got
        .into_iter()
        .flatten()
        .filter_map(|m| match client::content::decode(&m.plaintext) {
            Ok(client::content::Content::DeleteForEveryone { ts, .. }) => Some(ts),
            _ => None,
        })
        .collect();
    assert_eq!(deletes, vec![NOW], "the peer receives the delete with the SHARED timestamp");

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// CLEAR CHAT must wipe the conversation from DISK, not just from a view — and it must survive a
/// reload, or "cleared" would mean "hidden until you restart".
#[test]
fn clearing_a_chat_wipes_it_from_disk_across_a_reload() {
    let (relay_addr, relay_id) = spawn_relay();
    let adir = temp_dir("clear-a");
    let bdir = temp_dir("clear-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    astore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    bstore.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), client::dev_capability(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    client::send_text(&astore, &r, &bob_ik, b"one", NOW, NOW).unwrap();
    client::send_text(&astore, &r, &bob_ik, b"two", NOW + 1, NOW + 1).unwrap();
    let _ = client::recv_session(&bstore, &r, NOW + 2).unwrap();
    assert_eq!(bstore.load_history().unwrap().len(), 2, "both landed");

    bstore.delete_conversation(alice_ik).unwrap();
    assert!(bstore.load_history().unwrap().is_empty(), "cleared in this handle");

    // Re-open the vault from disk: a view-only clear would reappear here.
    let reopened = Store::unlock(&bdir, b"pw").unwrap();
    assert!(
        reopened.load_history().unwrap().is_empty(),
        "the conversation must be gone from DISK, not merely hidden until the next start"
    );

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// Copy every file in `dir` (flat — the account's network files all live at the top level) so a
/// later `restore_files` can put chosen ones back exactly as they were.
fn snapshot_files(dir: &std::path::Path) -> Vec<(PathBuf, Vec<u8>)> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| (e.path(), std::fs::read(e.path()).unwrap()))
        .collect()
}

/// Put back exactly the named files from a snapshot — the simulation of a crash in which those
/// writes never landed while every other write did.
fn restore_files(snap: &[(PathBuf, Vec<u8>)], names: &[&str]) {
    for (path, bytes) in snap {
        if names.contains(&path.file_name().unwrap().to_str().unwrap()) {
            std::fs::write(path, bytes).unwrap();
        }
    }
}

/// CRYPTO-26 — a crash between burning a one-time prekey and saving the session it produced
/// must not strand the contact permanently.
///
/// The receive path used to write the two halves as two files and two renames: prekeys first,
/// ratchet second. Each rename was atomic alone, the PAIR was not, and a crash (or an I/O error)
/// in between left the prekey burnt with no session to show for it. Nothing was acked, so the
/// relay redelivered the exact opener — and there was no longer a prekey secret to re-derive the
/// 4th DH term with, while the sender kept ratcheting into a mailbox its contact could never
/// open again. Recovery needed a manual forget/reconnect.
///
/// The crash is simulated the only way that keeps it honest: the poll's lease receipts are
/// DROPPED (so the relay still holds the ciphertext, exactly as a crash before the ACK leaves
/// it) and the file(s) carrying the session half are restored to their pre-receive bytes. Then
/// the lease expires on the relay's own clock (driven, never slept on) and the opener comes back.
#[test]
fn a_crash_before_the_session_commit_leaves_the_prekey_to_reopen_the_contact() {
    let (relay_addr, relay_id, _handle, clock) = spawn_relay_handle_clock();
    let adir = temp_dir("crash26-a");
    let bdir = temp_dir("crash26-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    for s in [&astore, &bstore] {
        seed_provision(s);
        s.save_shared_capability_for(&relay_id, &client::dev_capability()).unwrap();
    }
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(relay_addr, &relay_id);

    // Bob publishes one-time prekeys, so Alice's first contact really consumes one (4-DH).
    client::publish_with_opks(&bstore, &r,  NOW).unwrap();
    let opks_before = bstore.load_opks().unwrap();
    assert!(!opks_before.is_empty(), "the batch must be persisted for this test to mean anything");
    client::send_text(&astore, &r, &bob_ik, b"first contact", NOW, NOW).unwrap();

    // The disk as it looked BEFORE the receive.
    let snapshot = snapshot_files(&bdir);

    // Bob receives — and crashes before acking: the receipts are dropped, never committed, so
    // the ciphertext stays leased on the relay.
    let poll = client::recv_session_multi(&bstore, std::slice::from_ref(&r), NOW).unwrap();
    assert_eq!(poll.messages.iter().flatten().count(), 1, "the opener must decrypt the first time");
    assert!(!poll.acks.is_empty(), "the poll must have taken a lease to drop");
    drop(poll);

    // The crash: the session write never reached the disk. Everything else did.
    restore_files(&snapshot, &["sessions.dat", "sessions.anchor"]);

    // The invariant the pair commit exists for: never "prekey burnt AND no session". With the
    // session rolled back, the prekey set must be rolled back with it.
    assert!(
        bstore.load_sessions().unwrap().debug_peers().0.is_empty(),
        "test setup: the session half is supposed to be rolled back here"
    );
    let (mut back, mut before) = (bstore.load_opks().unwrap(), opks_before.clone());
    back.sort_unstable();
    before.sort_unstable();
    assert_eq!(
        back, before,
        "the prekey was burnt but its session did not survive — the contact can never be reopened"
    );

    // And operationally: the lease expires, the relay redelivers the exact opener, and it still
    // opens — the state that redelivery is supposed to recover from.
    let later = NOW + relay::node::LEASE_SECS + 1;
    clock.store(later, AtomicOrdering::SeqCst);
    let again = recv_multi(&bstore, std::slice::from_ref(&r), later).unwrap();
    let texts = poll_texts(&again.messages);
    assert!(
        texts.contains(&b"first contact".to_vec()),
        "the redelivered opener no longer opens — the contact is stranded"
    );

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// CRYPTO-24 — multi-homing across relays that issued their OWN credentials.
///
/// Every other multi-homing test here runs against dev relays, which all admit the same globally
/// known dev capability — so one account-wide credential worked and the production shape of the
/// problem was invisible. In production a capability is relay-specific (a Private relay mints a
/// random id+secret, a Public one derives a stateless secret from its own issuer key), and the
/// two relays below model exactly that: each admits one credential, and neither knows the
/// other's.
///
/// Two things break when there is only one account-wide slot, and the first was NOT in the
/// finding: publishing a bundle on a second relay CREATES a slot there, which is metered
/// (`RelayNode::handle_publish`, CRYPTO-18) — so the account never becomes reachable on its
/// backup at all, which is receive-side multi-homing, not just send failover. The second is the
/// filed one: a queued ciphertext flushed to a secondary presents a proof minted for the primary
/// and is refused, so the failover that reachability under a degraded network rests on silently does nothing.
#[test]
fn multi_homing_presents_each_relay_the_credential_that_relay_issued() {
    let cap1 = own_capability(0x11, 0xA1);
    let cap2 = own_capability(0x22, 0xB2);
    let (addr1, id1) = spawn_relay_admitting(cap1.clone());
    let (addr2, id2) = spawn_relay_admitting(cap2.clone());
    let adir = temp_dir("percap-a");
    let bdir = temp_dir("percap-b");
    let astore = Store::unlock(&adir, b"pw").unwrap();
    let bstore = Store::unlock(&bdir, b"pw").unwrap();
    seed_provision(&astore);
    seed_provision(&bstore);
    for s in [&astore, &bstore] {
        s.save_capability_for(&id1, &cap1).unwrap();
        s.save_capability_for(&id2, &cap2).unwrap();
    }
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let (r1, r2) = (ctx(addr1, &id1), ctx(addr2, &id2));

    // STAGE 1 — reachability on the SECONDARY. `publish_all` must present relay 2 its own
    // credential, or the slot is never created there.
    client::publish_all(&bstore, &[r1.clone(), r2.clone()], NOW).unwrap();
    // Proven by USE, not by the publish response (which only reports the primary): Alice opens
    // the conversation through relay 2, which needs Bob's bundle to exist there.
    assert!(
        client::send_text(&astore, &r2, &bob_ik, b"via the backup", NOW, NOW).unwrap(),
        "the deposit on relay 2 did not reach it"
    );
    let got = poll_texts(&client::recv_session(&bstore, &r2, NOW).unwrap());
    assert!(got.contains(&b"via the backup".to_vec()), "Bob is not reachable on his backup relay");

    // STAGE 2 — failover. The session now exists; relay 1 is the primary and it goes down, so the
    // queued ciphertext has to be flushed through relay 2 under RELAY 2's credential.
    assert!(
        client::send_text(&astore, &r1, &bob_ik, b"through the primary", NOW, NOW).unwrap(),
        "the primary must work before we kill it"
    );
    let dead = client::Relay::new("127.0.0.1:1".parse::<std::net::SocketAddr>().unwrap(), id1, None);
    let payload = client::content::encode(&client::content::Content::TextStamped {
        text: b"failed over".to_vec(),
        ts: NOW,
    });
    assert!(
        client::send_session_multi(&astore, &[dead, r2.clone()], &bob_ik, &payload, NOW).unwrap(),
        "the failover deposit was refused — the secondary got a credential it never issued"
    );
    let after = poll_texts(&client::recv_session(&bstore, &r2, NOW).unwrap());
    assert!(after.contains(&b"failed over".to_vec()), "the failed-over message never arrived");

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

// ---------------------------------------------------------------------------
// A8-4 — per-channel admission credentials.
//
// The `capability_id` rides in the clear on every deposit. Shared across an account's channels it
// is the one field that puts them back together — and over Tor it is the ONLY one, because
// `Peer::scope_for` already gives each handle its own SOCKS stream-isolation token and therefore
// its own circuit. These tests pin the four things the fix has to be: issuance really is per
// channel, a channel never borrows a sibling's credential, a burn takes the credential with it,
// and a credential that CANNOT be split is shared only when something explicitly asks for that.
// ---------------------------------------------------------------------------

/// A relay with the PUBLIC (self-serve) door open: `karst join` earns a credential from it by
/// solving a proof-of-work. 1 bit keeps the solve instant — the door's difficulty is not what
/// these tests are about.
fn spawn_public_relay() -> (SocketAddr, client::RelayId) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut relay = RelayNode::new(NOW);
    relay.enable_pow_issue(1);
    let fetch_pub = relay.relay_public().to_bytes();
    let server = RelayServer::new(relay, Arc::new(move || NOW));
    let noise_pub = server.noise_public();
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });
    (addr, client::RelayId { noise_pub, fetch_pub })
}

/// THE test for this fix: two channels of ONE account earn from ONE relay and end up presenting
/// DIFFERENT `capability_id`s.
///
/// It is deliberately an over-the-wire earn rather than two writes into the store: the whole
/// question is whether ISSUANCE distinguishes them (the store has been keyed per relay since
/// CRYPTO-24). If `handle_join` derived the id from anything account-shaped, both channels would
/// come back with the same id, `capabilities.dat` would gain two entries, and every storage-level
/// assertion would still pass while the relay could link them exactly as before.
#[test]
fn two_channels_earn_credentials_a_relay_cannot_link() {
    let (relay_addr, relay_id) = spawn_public_relay();
    let dir = temp_dir("a84-earn");
    let store = Store::unlock(&dir, b"pw").unwrap();
    seed_provision(&store);
    let one = store.create_proxy("one", NOW).unwrap();
    let two = store.create_proxy("two", NOW).unwrap();

    let r = ctx(relay_addr, &relay_id);
    let back = client::earn_missing_capabilities(&store, std::slice::from_ref(&r));
    assert_eq!(back.earned, 2, "both channels must earn: {:?}", back.still_missing);
    assert!(back.still_missing.is_empty(), "unexpected gaps: {:?}", back.still_missing);

    let c1 = store.as_proxy(one.index).load_capability_for(&relay_id).unwrap();
    let c2 = store.as_proxy(two.index).load_capability_for(&relay_id).unwrap();
    assert_ne!(
        c1.capability_id, c2.capability_id,
        "both channels present the SAME capability_id — the relay can still cluster them into \
         one account, which is the entire finding"
    );
    assert_ne!(c1.secret, c2.secret, "two channels sharing a credential SECRET is worse still");

    // A second pass is a no-op: it fills gaps only, so reconnect-time backfill costs nothing and
    // does not churn a channel's identity at the relay.
    let again = client::earn_missing_capabilities(&store, std::slice::from_ref(&r));
    assert_eq!(again.earned, 0, "a repeat pass re-earned instead of skipping");
    assert_eq!(
        store.as_proxy(one.index).load_capability_for(&relay_id).unwrap().capability_id,
        c1.capability_id,
        "the repeat pass replaced a channel's credential"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A channel with no credential of its own does NOT quietly present a sibling's. Borrowing would
/// restore the exact linkage the fix removes, and it would do it invisibly: the send would work.
/// The failure has to be the loud `NotFound` that makes the caller skip the relay.
#[test]
fn a_channel_never_borrows_a_sibling_channels_credential() {
    let (relay_addr, relay_id) = spawn_public_relay();
    let dir = temp_dir("a84-borrow");
    let store = Store::unlock(&dir, b"pw").unwrap();
    seed_provision(&store);
    let one = store.create_proxy("one", NOW).unwrap();

    let r = ctx(relay_addr, &relay_id);
    assert_eq!(client::earn_missing_capabilities(&store, std::slice::from_ref(&r)).earned, 1);
    // Created AFTER the pass — the offline case, in miniature: a channel that exists but has not
    // been to the relay yet.
    let two = store.create_proxy("two", NOW).unwrap();

    assert!(store.as_proxy(one.index).load_capability_for(&relay_id).is_ok());
    let borrowed = store.as_proxy(two.index).load_capability_for(&relay_id);
    assert_eq!(
        borrowed.unwrap_err().kind(),
        std::io::ErrorKind::NotFound,
        "a channel with no credential of its own was handed one belonging to another channel"
    );
    // And the root's credential is not a fallback either, in the other direction.
    store.save_capability_for(&relay_id, &client::dev_capability()).unwrap();
    assert_eq!(
        store.as_proxy(two.index).load_capability_for(&relay_id).unwrap_err().kind(),
        std::io::ErrorKind::NotFound,
        "a channel fell back to the ROOT account's credential"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// Burning a channel destroys its admission credential too. Credentials are keyed per slot inside
/// one file, so the `net_file` sweep that removes a burned proxy's session state cannot reach
/// them — only the explicit cascade can, and without it a live credential naming a dead identity
/// stays on disk.
#[test]
fn burning_a_channel_destroys_its_admission_credential() {
    let (relay_addr, relay_id) = spawn_public_relay();
    let dir = temp_dir("a84-burn");
    let store = Store::unlock(&dir, b"pw").unwrap();
    seed_provision(&store);
    let doomed = store.create_proxy("doomed", NOW).unwrap();
    let keeper = store.create_proxy("keeper", NOW).unwrap();

    let r = ctx(relay_addr, &relay_id);
    assert_eq!(client::earn_missing_capabilities(&store, std::slice::from_ref(&r)).earned, 2);
    let kept_before = store.as_proxy(keeper.index).load_capability_for(&relay_id).unwrap();

    store.burn_proxy(doomed.index).unwrap();
    assert!(
        !store.as_proxy(doomed.index).has_own_capability_for(&relay_id).unwrap(),
        "the burned channel's admission credential survived the burn"
    );
    // The cascade must be surgical: the other channel is untouched, not collateral.
    assert_eq!(
        store.as_proxy(keeper.index).load_capability_for(&relay_id).unwrap().capability_id,
        kept_before.capability_id,
        "burning one channel took another channel's credential with it"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A credential that cannot be split — an operator invite — is shared by every channel, and only
/// because something asked for that in as many words. This pins the honest half of the boundary:
/// the public/PoW door issues per channel, the invite door cannot, and the difference is visible
/// in which method the caller had to reach for.
#[test]
fn an_invite_credential_is_shared_only_when_explicitly_asked_for() {
    let (_addr, relay_id) = spawn_public_relay();
    let dir = temp_dir("a84-invite");
    let store = Store::unlock(&dir, b"pw").unwrap();
    seed_provision(&store);
    let one = store.create_proxy("one", NOW).unwrap();
    let two = store.create_proxy("two", NOW).unwrap();

    let invite = own_capability(0x77, 0x88);
    store.save_shared_capability_for(&relay_id, &invite).unwrap();

    for p in [one.index, two.index] {
        assert_eq!(
            store.as_proxy(p).load_capability_for(&relay_id).unwrap().capability_id,
            invite.capability_id,
            "a shared invite must be presentable by every channel — otherwise an invite-only \
             relay is reachable by exactly one of them"
        );
        // Riding a shared credential is NOT the same as having earned one: the backfill pass must
        // still owe this channel its own, or a relay that later opens a public door would never
        // be asked for per-channel credentials.
        assert!(
            !store.as_proxy(p).has_own_capability_for(&relay_id).unwrap(),
            "a shared credential was mistaken for the channel's own"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}
