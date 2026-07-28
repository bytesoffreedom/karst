//! Несущий e2e клиента: Alice шлёт → relay(в потоке) → Bob забирает.
//! Дискриминирующая деталь — **identity Bob сохраняется и ПЕРЕЗАГРУЖАЕТСЯ с
//! диска** до приёма. Тест «сгенерил-и-использовал-в-памяти» прошёл бы, ни разу
//! не проверив персистентность (та же ловушка, что roll_epoch/TTL). Только
//! reload-then-decrypt доказывает, что сохранённый секрет цел.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use client::store::Store;
use node::node::{
    BlobPutRequest, BlobResponse, FetchRequest, FetchResponse, Payload, PublishResponse, RelayNode,
    Response, SessionEnvelope, Transport, WireMessage,
};
use node::peer::Peer;
use node::pqxdh::Account;
use node::socket::{RelayServer, SocketTransport};
use node::transport::{DirectTcpAdapter, Path};
use x25519_dalek::PublicKey;

const NOW: u64 = 1_000_000;

/// Уникальный временный каталог состояния (свой на вызов).
fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("karst-test-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Relay на эфемерном порту с выданной дев-capability и фиксированными часами.
/// Возвращает (адрес, relay-id = Noise-pub ‖ fetch-auth-pub).
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

/// The connection context for a spawned relay (single direct path, no proxy).
fn ctx(addr: SocketAddr, id: &client::RelayId) -> client::Relay {
    client::Relay::new(addr, *id, None)
}

/// Like `spawn_relay`, but also hands back a handle to the shared relay state so a test
/// can assert what the mailbox holds AFTER the serving thread has processed requests —
/// the only way to tell a working over-the-wire ACK (drained) from a no-op (still leased).
fn spawn_relay_handle() -> (SocketAddr, client::RelayId, Arc<Mutex<RelayNode>>) {
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
    relay.enable_blobs(temp_dir("blobs"), 0, node::node::BlobPersistence::Durable).unwrap();
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
        client::blob_upload(&ctx(addr, &rid), std::io::Cursor::new(&data), data.len() as u64)
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
        client::blob_upload(&ctx(addr, &rid), std::io::Cursor::new(&data), data.len() as u64).expect("upload");

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
    assert_eq!(client::blob_stat(&r, id).unwrap(), None, "unknown blob → no watermark");

    // "Crash" after 2 chunks: a reader with only 2*chunk bytes but a size claiming 4 chunks stores
    // chunks 0,1 then errors reading chunk 2.
    let partial = std::io::Cursor::new(data[..2 * chunk].to_vec());
    assert!(
        client::blob_upload_resumable(&r, partial, size, id, key).is_err(),
        "the truncated attempt fails mid-upload"
    );
    assert_eq!(client::blob_stat(&r, id).unwrap(), Some((2, 4, false)), "watermark parked at chunk 2");

    // Resume with the FULL file: skips 0,1 (hashes them for the FileRef), uploads only 2,3.
    let (rid2, rkey2, hash, count) =
        client::blob_upload_resumable(&r, std::io::Cursor::new(&data), size, id, key).expect("resume completes");
    assert_eq!((rid2, rkey2, count), (id, key, 4));
    assert_eq!(client::blob_stat(&r, id).unwrap(), Some((4, 4, true)), "blob now complete");

    // The resumed upload downloads back byte-identical, hash verified.
    let out = client::blob_download(&r, id, key, count, hash, Vec::new()).expect("download");
    assert_eq!(out, data, "resumed upload is byte-identical to the original");

    // Idempotent: re-running a completed upload re-sends nothing and returns the same FileRef.
    let (_, _, hash2, _) =
        client::blob_upload_resumable(&r, std::io::Cursor::new(&data), size, id, key).expect("re-run is a no-op");
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
        client::blob_upload(&ctx(addr, &rid), std::io::Cursor::new(&data), data.len() as u64).unwrap();

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
        client::blob_upload(&ctx(addr, &rid), std::io::Cursor::new(&data), data.len() as u64).unwrap();

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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    assert!(matches!(
        client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW),
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(addr, &rid);
    assert!(matches!(
        client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW),
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
        client::blob_upload(&ctx(addr, &rid), std::io::Cursor::new(&data), data.len() as u64).unwrap();

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
    let bob = client::seed::derive(&[3u8; 16]).account;
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
/// Discriminating: send the opener unsealed (`SessionEnvelope::Initial`) → reds.
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
    let bob = client::seed::derive(&[3u8; 16]).account;
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW);
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW);
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW);
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();

    // Both parties act AS their proxy 0 — the only thing that ever touches the relay.
    let a = astore.as_proxy(0);
    let b = bstore.as_proxy(0);
    let a_root = astore.load_account().unwrap().identity_public();
    let a_proxy = a.load_account().unwrap().identity_public();
    let b_proxy = b.load_account().unwrap().identity_public();
    assert_ne!(a_proxy, a_root, "the proxy address is not the root");

    let r = ctx(relay_addr, &relay_id);
    // Bob's PROXY publishes its bundle (the root never publishes).
    let pr = client::publish_bundle(&r, b.load_account().unwrap(), b.load_capability().unwrap(), NOW);
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
        st.save_capability(&client::dev_capability()).unwrap();
    }
    let r = ctx(relay_addr, &relay_id);

    // Bob publishes WITH one-time prekeys; Carol publishes a bundle with none at all.
    client::publish_with_opks(&bstore, &r, bstore.load_capability().unwrap(), NOW).unwrap();
    client::publish_bundle(
        &r,
        cstore.load_account().unwrap(),
        cstore.load_capability().unwrap(),
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();

    let a = astore.as_proxy(0);
    let b = bstore.as_proxy(0);
    let b_proxy = b.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    // Desktop path: publish the proxy bundle WITH one-time prekeys (4-DH first contact).
    client::publish_with_opks(&b, &r, b.load_capability().unwrap(), NOW).unwrap();

    // Alice's proxy sends — first contact consumes one of Bob's published OPKs.
    client::send_text(&a, &r, &b_proxy, b"hi via proxy opk", NOW, NOW).unwrap();

    // Bob's proxy receives via the multi-homed path the desktop poll uses.
    let poll = client::recv_session_multi(&b, std::slice::from_ref(&r), NOW).unwrap();
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
    bstore.save_capability(&client::dev_capability()).unwrap();
    let b = bstore.as_proxy(0);
    let b_ik = b.load_account().unwrap().identity_public();
    let r = ctx(relay_addr, &relay_id);

    // Publish a full OPK batch, then REPUBLISH it unchanged (no consumption between).
    client::publish_with_opks(&b, &r, b.load_capability().unwrap(), NOW).unwrap();
    client::publish_with_opks(&b, &r, b.load_capability().unwrap(), NOW).unwrap();

    // Drain every OPK the relay will hand out; each must be distinct, then the batch exhausts
    // (opk_pub == None → 3-DH fallback). A repeat means a republished duplicate is being served.
    let mut seen = std::collections::HashSet::new();
    let mut node = relay.lock().unwrap();
    while let Some(bundle) = node.get_bundle(&b_ik) {
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW);
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    let avatar = vec![7u8; 5000]; // stand-in PNG bytes, multi-chunk
    client::send_avatar(&astore, &r, &bob_ik, &avatar, NOW).unwrap();

    // Receive + reassemble exactly as the desktop poll does (per-sender Reassembler).
    let got = client::recv_session_multi(&bstore, std::slice::from_ref(&r), NOW).unwrap();
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();

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
    let pr = client::publish_bundle(&r, b0.load_account().unwrap(), b0.load_capability().unwrap(), NOW);
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW);
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    // Alice publishes a post, then its image as a separate chunked slice tied to the post id.
    let id = client::store::random16();
    let image = vec![3u8; 5000]; // stand-in JPEG bytes, multi-chunk
    client::send_publication(&astore, &r, &bob_ik, id, "with a photo", 7, NOW).expect("publication sends");
    client::send_post_image(&astore, &r, &bob_ik, id, &image, NOW).expect("post image sends");

    // Receive + route exactly as the desktop poll does: text → feed, image → reassembler → sidecar.
    let got = client::recv_session_multi(&bstore, std::slice::from_ref(&r), NOW).unwrap();
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    assert!(matches!(
        client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW),
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW);
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW);
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    client::send_text(&astore, &r, &bob_ik, b"ack me", NOW, NOW).unwrap();
    // Message is now queued in Bob's mailbox on the relay.
    assert!(!relay.lock().unwrap().all_slots_for_test().is_empty(), "message deposited");

    let got = client::recv_session(&bstore, &r, NOW).unwrap();
    assert_eq!(got.into_iter().flatten().count(), 1, "Bob received it");
    // The ACK deleted it over the wire: nothing lingers leased on the relay.
    assert!(
        relay.lock().unwrap().all_slots_for_test().is_empty(),
        "recv_session ACKed over the socket and the relay dropped the message"
    );

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// Провижининг корня (энтропии свежей фразы) в стор; возвращает энтропию, чтобы
/// тест мог вывести ожидаемые seal/account (`seed::derive`) для сверки. В новой
/// модели identity+account — не независимые секреты, а вывод из ЕДИНОГО корня.
fn seed_provision(s: &Store) -> [u8; client::seed::ENTROPY_BYTES] {
    let e = client::seed::entropy_of(&client::seed::generate_mnemonic());
    s.save_seed(&e).unwrap();
    e
}

/// The plaintext of every decrypted §2.1 message in a poll (Text/TextStamped).
fn poll_texts(msgs: &[Option<node::peer::Received>]) -> Vec<Vec<u8>> {
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
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
    let poll = client::recv_session_multi(&bstore, &[r1.clone(), r_dead, r2.clone()], NOW).unwrap();
    assert_eq!(poll.failed, vec![1], "only the dead relay is unreachable");
    let texts = poll_texts(&poll.messages);
    assert!(texts.contains(&b"via-r1".to_vec()), "relay 1's message was not delivered");
    assert!(texts.contains(&b"via-r2".to_vec()), "relay 2's message was not delivered past the dead relay");

    // The mailboxes were drained on fetch, so a re-poll of the same live relays is empty.
    // This checks DRAINAGE, not persistence — it would hold even without saving state.
    let drained = client::recv_session_multi(&bstore, &[r1.clone(), r2.clone()], NOW).unwrap();
    assert!(poll_texts(&drained.messages).is_empty(), "a message was re-delivered (mailbox not drained)");

    // Persistence proper: a NEW post-opener message lands in a session-derived drop box, so
    // it only decrypts if Bob's ratchet advance from the first multi-poll round-tripped
    // through disk. Delete `save_sessions` in `recv_session_multi` and this reds — Bob loads
    // a stale session, never learns the drop box, and the follow-up is lost.
    client::send_text(&astore, &r1, &bob_ik, b"after", NOW, NOW).unwrap();
    let follow = client::recv_session_multi(&bstore, &[r1, r2], NOW).unwrap();
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
    bstore.save_capability(&client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let resp =
        client::publish_all(&bstore, &[ctx(addr1, &id1), ctx(addr2, &id2)], client::dev_capability(), NOW)
            .unwrap();
    assert!(matches!(resp, PublishResponse::Published), "primary publish: {resp:?}");

    // Fetch Bob's bundle straight from each relay (bundle fetch is public/unauthenticated).
    let b1 = SocketTransport::new(addr1, id1.noise_pub)
        .fetch_bundle(&bob_ik, NOW)
        .unwrap()
        .expect("the primary has Bob's bundle");
    let b2 = SocketTransport::new(addr2, id2.noise_pub)
        .fetch_bundle(&bob_ik, NOW)
        .unwrap()
        .expect("the secondary has Bob's bundle"); // primary-only publish reds here
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
        "перезагруженный seal-pubkey должен совпасть с выводом из корня — корень цел"
    );

    // create_new: повторный save_seed НЕ должен перезаписывать корень.
    let other = client::seed::entropy_of(&client::seed::generate_mnemonic());
    assert!(s.save_seed(&other).is_err(), "не должно перезаписывать корень");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn at_rest_wrong_passphrase_cannot_load_and_disk_is_encrypted() {
    // Проводка at-rest через Store: (1) корень под другим паролем не читается;
    // (2) на диске нет открытой энтропии (не no-op шифрование).
    let dir = temp_dir("atrest");
    let s = Store::unlock(&dir, b"right-pass").unwrap();
    let e = seed_provision(&s);
    let acct = client::seed::derive(&e).account;

    // Неверный пароль → fail-fast на unlock (верификатор), до любого чтения.
    assert!(Store::unlock(&dir, b"wrong-pass").is_err(), "неверный пароль → отказ на unlock");

    // Верный пароль → тот же IK (выведенный из корня).
    let right = Store::unlock(&dir, b"right-pass").unwrap();
    assert_eq!(right.load_account().unwrap().identity_public(), acct.identity_public());

    // На диске (seed.key) — не открытая энтропия (иначе шифрование было бы no-op).
    let on_disk = std::fs::read(dir.join("seed.key")).unwrap();
    assert!(
        !on_disk.windows(e.len()).any(|w| w == e),
        "открытая энтропия корня не должна присутствовать в seed.key"
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
    // Контакты (имена + флаг сверки) переживают перезапуск процесса и at-rest.
    use client::store::ContactRecord;
    let dir = temp_dir("contacts");
    let contacts = vec![
        ContactRecord { name: "Alice".into(), ik: [1u8; 32], verified: true },
        ContactRecord { name: "неизв. deadbeef".into(), ik: [2u8; 32], verified: false },
    ];
    Store::unlock(&dir, b"pw").unwrap().save_contacts(&contacts).unwrap();

    // Новый Store (как после рестарта) читает тот же список.
    let loaded = Store::unlock(&dir, b"pw").unwrap().load_contacts().unwrap();
    assert_eq!(loaded, contacts, "контакты стабильны через диск, флаг сверки цел");

    // На диске — не открытое имя (шифрование не no-op).
    let on_disk = std::fs::read(dir.join("contacts.dat")).unwrap();
    assert!(
        !on_disk.windows(5).any(|w| w == b"Alice"),
        "открытое имя контакта не должно лежать в contacts.dat"
    );
    // Пустой профиль → пустой список (не ошибка).
    let empty = temp_dir("contacts-empty");
    assert!(Store::unlock(&empty, b"pw").unwrap().load_contacts().unwrap().is_empty());

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&empty).ok();
}

#[test]
fn store_account_roundtrip() {
    // §2.1-account переживает диск: IK/bundle стабильны (включая KEM-seed) —
    // выводятся из корня детерминированно.
    let dir = temp_dir("acct");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    let e = seed_provision(&s);
    let expected = client::seed::derive(&e).account;
    let ik = expected.identity_public();
    let ek = expected.prekey_bundle().kem_ek;

    let loaded = Store::unlock(&dir, b"test-pw").unwrap().load_account().unwrap();
    assert_eq!(loaded.identity_public(), ik, "IK стабилен через диск");
    assert_eq!(loaded.prekey_bundle().kem_ek, ek, "KEM ek стабилен (seed восстановлен)");

    // create_new: смена корня запрещена (сломала бы discovery/сессии).
    let other = client::seed::entropy_of(&client::seed::generate_mnemonic());
    assert!(s.save_seed(&other).is_err(), "не должно перезаписывать корень");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn bob_reloads_account_from_disk_and_publishes() {
    // Слой-1 e2e: Bob кладёт корень, ЗАБЫВАЕТ, перезагружает с диска (вывод
    // account) и публикует bundle у relay. Reload-then-publish доказывает, что
    // сохранённый корень цел и выведенный bundle согласован.
    let (relay, relay_id) = spawn_relay();
    let bob_dir = temp_dir("bob-acct");
    let bob_store = Store::unlock(&bob_dir, b"test-pw").unwrap();
    seed_provision(&bob_store); // корень на диск; ниже — только диск.

    let reloaded = bob_store.load_account().unwrap();
    let resp = client::publish_bundle(&ctx(relay, &relay_id), reloaded, client::dev_capability(), NOW);
    assert!(matches!(resp, PublishResponse::Published), "получено: {:?}", resp);

    std::fs::remove_dir_all(&bob_dir).ok();
}

/// Мок-транспорт: всегда `Accepted`, записывает каждый ушедший WireMessage.
/// Send+Sync для использования из потоков (шифртекст «ушёл» — в модели угроз).
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
    // НЕСУЩЕЕ (персистентный keystream-reuse): два «процесса» (потока) шлют по
    // одной сессии, каждый под flock делает load→send(advance)→save. Замок обязан
    // сериализовать их так, чтобы КАЖДЫЙ send занял свою позицию цепочки. Если
    // замок сломан (напр. на переименованном inode), оба загрузят позицию N и
    // зашифруют РАЗНЫЕ тексты одним mk+нулевым nonce. Проверяем отсутствие
    // повтора (dh,n) среди всех ушедших конвертов. Детерминирован при любом
    // порядке (замок работает → нет дублей; сломан → есть).
    let dir = temp_dir("concurrent");
    let store = Store::unlock(&dir, b"test-pw").unwrap();
    let account = client::seed::derive(&seed_provision(&store)).account;
    let acct_bytes = account.to_secret_bytes();
    let relay_pub = PublicKey::from([7u8; 32]); // мок — DH не используется в send
    let bob_ik = {
        // Установить сессию и сохранить стартовое состояние.
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
                let g = store.lock_sessions().unwrap(); // блокирующий эксклюзив
                let transport = RecordingTransport { sent: recorded.clone() };
                let mut peer =
                    Peer::new(transport, Account::from_secret_bytes(&acct_bytes), client::dev_capability(), relay_pub);
                peer.import_state(store.load_sessions().unwrap());
                let msg = format!("t{t}-{i}");
                assert!(matches!(peer.send(&bob_ik, msg.as_bytes(), NOW), Response::Accepted));
                store.save_sessions(&peer.export_state()).unwrap();
                drop(g); // снять замок
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // Собрать (dh,n) всех ушедших Session-конвертов — дублей быть не должно.
    let sent = recorded.lock().unwrap();
    assert_eq!(sent.len(), 2 * PER_THREAD, "все отправки прошли");
    let mut positions: Vec<([u8; 32], u32)> = sent
        .iter()
        .filter_map(|m| match &m.payload {
            Payload::Session(SessionEnvelope::Initial { msg, .. }) => Some((msg.header.dh, msg.header.n)),
            Payload::Session(SessionEnvelope::Ratchet(msg)) => Some((msg.header.dh, msg.header.n)),
            _ => None,
        })
        .collect();
    let total = positions.len();
    positions.sort();
    positions.dedup();
    assert_eq!(positions.len(), total, "две отправки не должны делить позицию цепочки (dh,n)");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn crash_between_transmit_and_save_never_reuses_position() {
    // НЕСУЩЕЕ (crash-axis keystream-reuse): «процесс 1» шифрует+передаёт (ct_N уже
    // ушёл к relay), затем ПАДАЕТ до post-save. «Процесс 2» грузит с диска и шлёт
    // ДРУГОЙ текст. Порядок encrypt_next→pre-save→transmit гарантирует, что
    // позиция N стала durable ДО ухода ct_N → процесс 2 берёт N+1, не N. Save-
    // после-transmit оставил бы окно: диск на N → повтор позиции → reuse.
    let dir = temp_dir("crash");
    let store = Store::unlock(&dir, b"test-pw").unwrap();
    let account = client::seed::derive(&seed_provision(&store)).account;
    let acct_bytes = account.to_secret_bytes();
    let relay_pub = PublicKey::from([7u8; 32]);
    let recorded = Arc::new(Mutex::new(Vec::new()));

    // Установить сессию, сохранить стартовое состояние.
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

    // Хелпер: одна отправка в порядке send_session, но с опцией «крах» до post-save.
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
        store.save_sessions(&peer.export_state()).unwrap(); // PRE-transmit save (фикс)
        peer.transmit_envelope(&bob_ik, env, NOW); // ct ушёл к relay (записан)
        if !crash_before_post_save {
            store.save_sessions(&peer.export_state()).unwrap(); // post (очистка)
        }
        drop(g);
    };

    send_once(b"AAAA", true); // процесс 1: краш после transmit, до post-save
    send_once(b"BBBB", false); // процесс 2: грузит с диска, шлёт другой текст

    let sent = recorded.lock().unwrap();
    let positions: Vec<([u8; 32], u32)> = sent
        .iter()
        .filter_map(|m| match &m.payload {
            Payload::Session(SessionEnvelope::Initial { msg, .. }) => Some((msg.header.dh, msg.header.n)),
            Payload::Session(SessionEnvelope::Ratchet(msg)) => Some((msg.header.dh, msg.header.n)),
            _ => None,
        })
        .collect();
    let mut uniq = positions.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(positions.len(), uniq.len(), "краш до post-save не должен дать повтор позиции (dh,n)");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn alice_sends_bob_reloads_from_disk_and_decrypts() {
    let (relay, relay_id) = spawn_relay();

    // Bob: создать корень, сохранить, затем ЗАБЫТЬ и перезагрузить с диска.
    let bob_dir = temp_dir("bob");
    let bob_store = Store::unlock(&bob_dir, b"test-pw").unwrap();
    let bob_pub = {
        let e = seed_provision(&bob_store);
        client::seed::derive(&e).seal.public.to_bytes()
    };
    // ← identity выше вышла из области видимости; ниже работаем только с диском.
    let bob_reloaded = bob_store.load_identity().unwrap();
    assert_eq!(bob_reloaded.public.to_bytes(), bob_pub);

    // Alice: дев-capability, шлёт на pubkey Bob (внутри Noise-сессии).
    let resp = client::send_message(&ctx(relay, &relay_id), client::dev_capability(), &bob_pub, b"hi bob", NOW);
    assert!(matches!(resp, Response::Accepted), "получено: {:?}", resp);

    // Bob: забрать перезагруженной identity (Noise + fetch-auth) → расшифровать.
    let msgs = client::fetch_messages(&ctx(relay, &relay_id), bob_reloaded, NOW).expect("fetch");
    let got: Vec<_> = msgs.into_iter().flatten().collect(); // skeleton-путь: Vec<u8>
    assert_eq!(got, vec![b"hi bob".to_vec()], "Bob должен расшифровать своим сохранённым ключом");

    std::fs::remove_dir_all(&bob_dir).ok();
}

// ---- Зашифрованный append-лог истории ----

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
    // Перезагрузка НОВЫМ Store (как новый процесс) — читает с диска, не из памяти.
    let loaded = Store::unlock(&dir, b"test-pw").unwrap().load_history().unwrap();
    assert_eq!(loaded, recs.to_vec(), "порядок и содержимое сохранены");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn history_records_use_fresh_nonce_no_keystream_reuse() {
    use client::store::HistoryRecord;
    let dir = temp_dir("hist-nonce");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    // Две ОДИНАКОВЫЕ записи → на диске должны дать РАЗНЫЕ шифртексты (свежий nonce).
    let r = HistoryRecord { from_me: true, peer_ik: [1; 32], text: b"same".to_vec(), ts: 42 };
    s.append_history(&r).unwrap();
    s.append_history(&r).unwrap();
    let raw = std::fs::read(dir.join("history.dat")).unwrap();
    // Две записи с одинаковым len-префиксом; их запечатанные тела не равны.
    let len = u32::from_le_bytes(raw[0..4].try_into().unwrap()) as usize;
    let first = &raw[4..4 + len];
    let second = &raw[4 + len + 4..4 + len + 4 + len];
    assert_ne!(first, second, "одинаковый plaintext → разный шифртекст (nonce свеж)");
    // И обе всё равно читаются.
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
        // Симулируем крах на середине append: дописываем рваный хвост (длина обещает
        // байты, которых нет + мусор).
        let mut f =
            std::fs::OpenOptions::new().append(true).open(dir.join("history.dat")).unwrap();
        f.write_all(&999u32.to_le_bytes()).unwrap();
        f.write_all(b"\x00\x01\x02garbage").unwrap();
    }
    // load на старте: отдаёт только целую запись И усекает мусор.
    let s2 = Store::unlock(&dir, b"test-pw").unwrap();
    let loaded = s2.load_history().unwrap();
    assert_eq!(loaded, vec![good.clone()], "рваный хвост отброшен, целое сохранено");
    // Критично: после усечения будущий append снова парсится (хвост не отравлен).
    let next = HistoryRecord { from_me: true, peer_ik: [3; 32], text: b"after".to_vec(), ts: 6 };
    s2.append_history(&next).unwrap();
    let after = Store::unlock(&dir, b"test-pw").unwrap().load_history().unwrap();
    assert_eq!(after, vec![good, next], "append после восстановления читается");
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
    // Очистить переписку с [9;32] (как «удалить чат»): оставить только peer != [9;32].
    let removed = s.rewrite_history(|r| r.peer_ik != [9; 32]).unwrap();
    assert_eq!(removed.len(), 2, "удалены обе записи чата [9;32]");
    assert!(removed.iter().all(|r| r.peer_ik == [9; 32]), "вернулись именно удалённые записи");
    // НОВЫЙ Store (как после рестарта): фильтр пережил перезапись, порядок сохранён.
    let loaded = Store::unlock(&dir, b"test-pw").unwrap().load_history().unwrap();
    assert_eq!(loaded, vec![recs[0].clone(), recs[2].clone()], "оставлены только keep-* по порядку");
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
    assert!(removed.is_empty(), "keep-all ничего не удаляет");
    // Файл не тронут (тот же inode/содержимое — не переписывали зря).
    assert_eq!(std::fs::read(dir.join("history.dat")).unwrap(), before, "keep-all не переписывает файл");
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
    assert_eq!(removed.len(), 3, "удалено всё");
    assert!(s.load_history().unwrap().is_empty(), "история пуста после полной очистки");
    // Файл валиден: последующий append парсится (не отравлен пустой перезаписью).
    let next = HistoryRecord { from_me: false, peer_ik: [1; 32], text: b"after".to_vec(), ts: 4 };
    s.append_history(&next).unwrap();
    assert_eq!(Store::unlock(&dir, b"test-pw").unwrap().load_history().unwrap(), vec![next]);
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Метаданные сообщений (реакции), at-rest sidecar meta.dat ----

#[test]
fn reactions_survive_restart_and_are_at_rest_encrypted() {
    use client::content::msg_id;
    let dir = temp_dir("meta-reactions");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    let id = msg_id(&[7; 32], 42, b"hi");
    s.set_reaction(id, "👍", [1; 32], true).unwrap();
    s.set_reaction(id, "👍", [2; 32], true).unwrap(); // второй автор той же реакции
    s.set_reaction(id, "🔥", [1; 32], true).unwrap();

    // At-rest: сырой файл НЕ содержит эмодзи в открытом виде.
    let raw = std::fs::read(dir.join("meta.dat")).unwrap();
    assert!(!raw.windows("👍".len()).any(|w| w == "👍".as_bytes()), "эмодзи не в plaintext на диске");

    // Рестарт: карта пережила и корректна.
    let map = Store::unlock(&dir, b"test-pw").unwrap().load_meta().unwrap();
    let mm = map.get(&id).expect("есть метаданные сообщения");
    assert_eq!(mm.reactions.get("👍").unwrap().len(), 2, "два автора 👍");
    assert!(mm.reactions.get("🔥").unwrap().contains(&[1; 32]), "🔥 от автора 1");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn reaction_toggle_add_then_remove_collapses_to_empty_and_removes_file() {
    use client::content::msg_id;
    let dir = temp_dir("meta-toggle");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    let id = msg_id(&[3; 32], 9, b"m");
    s.set_reaction(id, "❤", [1; 32], true).unwrap();
    assert!(dir.join("meta.dat").exists(), "файл появился");
    s.set_reaction(id, "❤", [1; 32], false).unwrap(); // снятие последней
    assert!(s.load_meta().unwrap().is_empty(), "снятие последней реакции → пусто");
    assert!(!dir.join("meta.dat").exists(), "пустая карта удаляет файл (не держим мусор)");
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
    assert!(map.contains_key(&keep) && !map.contains_key(&gone), "удалён только названный id");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn reaction_rejects_absurd_emoji_before_write() {
    use client::content::{msg_id, MAX_EMOJI_BYTES};
    let dir = temp_dir("meta-caps");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    let id = msg_id(&[1; 32], 1, b"m");
    assert!(s.set_reaction(id, "", [1; 32], true).is_err(), "пустой эмодзи отвергнут");
    let huge = "x".repeat(MAX_EMOJI_BYTES + 1);
    assert!(s.set_reaction(id, &huge, [1; 32], true).is_err(), "оверсайз эмодзи отвергнут");
    assert!(!dir.join("meta.dat").exists(), "отвергнутое НЕ записано на диск");
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
    assert_eq!(map.get(&reply_msg).unwrap().reply_to, Some(target), "reply_to пережил рестарт");
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
    assert_eq!(map.get(&id).unwrap().edited, Some((9, b"fixed".to_vec())), "правка пережила рестарт");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn incoming_edit_allowed_only_for_messages_the_sender_authored() {
    // GUARD против спуфинга: правку применяем ТОЛЬКО если её отправитель — автор
    // цели (у нас — входящее от него). Нельзя править ВАШЕ (или чужое) сообщение.
    use client::content::msg_id;
    use client::store::HistoryRecord;
    let sender = [2u8; 32];
    let me = [1u8; 32];
    let recs = vec![
        // Их сообщение (входящее от sender): from_me=false, peer=sender.
        HistoryRecord { from_me: false, peer_ik: sender, text: b"theirs".to_vec(), ts: 5 },
        // Моё сообщение (исходящее к sender): from_me=true, автор = me.
        HistoryRecord { from_me: true, peer_ik: sender, text: b"mine".to_vec(), ts: 6 },
    ];
    // Правка ИХ сообщения (автор = sender) — разрешена.
    assert!(client::incoming_edit_allowed(&recs, &sender, msg_id(&sender, 5, b"theirs")));
    // Правка МОЕГО сообщения от sender — ЗАПРЕЩЕНА (иначе он подменил бы мой текст).
    assert!(!client::incoming_edit_allowed(&recs, &sender, msg_id(&me, 6, b"mine")));
    // Незнакомый target — запрещён.
    assert!(!client::incoming_edit_allowed(&recs, &sender, [0xFF; 16]));
}

#[test]
fn blocked_set_persists_and_toggles_off_removes_file() {
    let dir = temp_dir("blocked");
    let s = Store::unlock(&dir, b"test-pw").unwrap();
    assert!(s.load_blocked().unwrap().is_empty());
    s.set_blocked([9; 32], true).unwrap();
    // Пережил рестарт.
    assert!(Store::unlock(&dir, b"test-pw").unwrap().load_blocked().unwrap().contains(&[9; 32]));
    // Разблокировать → пусто → файл удалён.
    s.set_blocked([9; 32], false).unwrap();
    assert!(s.load_blocked().unwrap().is_empty());
    assert!(!dir.join("blocked.dat").exists(), "пустой блок-лист удаляет файл");
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
    // Мусор вместо запечатанного blob — метаданные best-effort, история не должна
    // падать из-за битого meta.dat.
    std::fs::write(dir.join("meta.dat"), b"not a sealed metadata blob").unwrap();
    assert!(s.load_meta().unwrap().is_empty(), "битый meta.dat → пусто, не ошибка");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Передача файлов через relay (чанкинг + пересборка) ----

/// Провизия §2.1-клиента: account + дев-capability на диске.
fn provision(tag: &str) -> (PathBuf, Store, [u8; 32]) {
    let dir = temp_dir(tag);
    let store = Store::unlock(&dir, b"pw").unwrap();
    let acct = client::seed::derive(&seed_provision(&store)).account;
    let ik = acct.identity_public();
    store.save_capability(&client::dev_capability()).unwrap();
    (dir, store, ik)
}

#[test]
fn file_transfer_roundtrips_through_relay_byte_identical() {
    use client::content::{decode, Content, Reassembler};
    let (relay, relay_id) = spawn_relay();
    let (adir, astore, _aik) = provision("file-alice");
    let (bdir, bstore, bob_ik) = provision("file-bob");

    // Bob публикует bundle (§12) — иначе Alice не инициирует сессию.
    let pr = client::publish_bundle(
        &ctx(relay, &relay_id),
        bstore.load_account().unwrap(),
        bstore.load_capability().unwrap(),
        NOW,
    );
    assert!(matches!(pr, PublishResponse::Published), "publish: {pr:?}");

    // Alice: текст (устанавливает сессию → манифест поедет как Ratchet), затем файл
    // ~5 KiB (несколько чанков по 1024, валидирует chunk-размер против 1400-лимита).
    client::send_text(&astore, &ctx(relay, &relay_id), &bob_ik, "привет".as_bytes(), NOW, NOW).unwrap();
    let file: Vec<u8> = (0..5000u32).map(|i| (i.wrapping_mul(7)) as u8).collect();
    client::send_file(&astore, &ctx(relay, &relay_id), &bob_ik, "report.bin", &file, NOW).unwrap();

    // Bob забирает ВСЁ одним recv (один mailbox), декодирует, собирает.
    let msgs = client::recv_session(&bstore, &ctx(relay, &relay_id), NOW).unwrap();
    let mut re = Reassembler::new();
    let (mut got_text, mut got_file) = (None, None);
    for r in msgs.into_iter().flatten() {
        match decode(&r.plaintext).expect("контент разобран") {
            Content::Text(t) | Content::TextStamped { text: t, .. } => got_text = Some(t),
            c => {
                if let Some(f) = re.offer(c, NOW).expect("пересборка без ошибок") {
                    got_file = Some(f);
                }
            }
        }
    }
    assert_eq!(got_text.as_deref(), Some("привет".as_bytes()), "текст доехал");
    let f = match got_file.expect("file assembled from chunks") {
        client::content::Assembled::File(f) => f,
        other => panic!("expected a file, got {other:?}"),
    };
    assert_eq!(f.name, "report.bin");
    assert_eq!(f.bytes, file, "файл байт-в-байт через настоящий relay");

    std::fs::remove_dir_all(&adir).ok();
    std::fs::remove_dir_all(&bdir).ok();
}

/// Helper: a minimal (no-cookie) BlobPut — the relay answers `NeedCookie` before any
/// storage, so a `NeedCookie` proves the round-trip REACHED the relay.
fn probe_blob_put() -> BlobPutRequest {
    BlobPutRequest {
        client_addr: b"probe".to_vec(),
        carrier_id: b"karst-blob".to_vec(),
        cookie: None,
        blob_id: [7u8; 32],
        index: 0,
        count: 1,
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
            let req = BlobPutRequest {
                client_addr: vec![0x11u8; 32], // sender address is a 32-byte pseudonym
                carrier_id: b"karst-blob".to_vec(),
                cookie,
                blob_id,
                index,
                count,
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
        t.blob_stat(blob_id).unwrap(),
        Some((count, count, true)),
        "the whole blob completed over a single reused session"
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
impl node::transport::TransportAdapter for CountingDead {
    fn connect(&self, _dest: &node::transport::Dest) -> std::io::Result<Box<dyn node::transport::Channel>> {
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
    store.save_capability(&client::dev_capability()).unwrap();

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
        s.save_capability(&client::dev_capability()).unwrap();
    }
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(relay_addr, &relay_id);

    // Bob publishes WITH one-time prekeys (persisted). The sidecar now holds the secrets.
    let pr = client::publish_with_opks(&bstore, &r, client::dev_capability(), NOW).unwrap();
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW);
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
        let got = client::recv_session_multi(&bstore, std::slice::from_ref(&r), NOW).unwrap();
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(relay_addr, &relay_id);
    // Both publish bundles so each is reachable; they exchange nothing else.
    client::publish_bundle(&r, astore.load_account().unwrap(), astore.load_capability().unwrap(), NOW);
    client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW);

    // Simultaneous first contact: each posts to the other BEFORE either has received anything.
    let ida = client::store::random16();
    let idb = client::store::random16();
    client::send_publication(&astore, &r, &bob_ik, ida, "from alice", 7, NOW).expect("A publishes");
    client::send_publication(&bstore, &r, &alice_ik, idb, "from bob", 8, NOW).expect("B publishes");

    let drain = |store: &Store| {
        for _ in 0..8 {
            let got = client::recv_session_multi(store, std::slice::from_ref(&r), NOW).unwrap();
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
    // resurface an un-decryptable payload every cycle (the `чанк без манифеста` → Killed hang).
    let extra = client::recv_session_multi(&bstore, std::slice::from_ref(&r), NOW).unwrap();
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(relay_addr, &relay_id);
    client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW);

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
        let got = client::recv_session_multi(&bstore, std::slice::from_ref(&r), NOW).unwrap();
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(relay_addr, &relay_id);
    client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW);

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
        let got = client::recv_session_multi(&bstore, std::slice::from_ref(&r), NOW).unwrap();
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(relay_addr, &relay_id);
    client::publish_bundle(&r, astore.load_account().unwrap(), astore.load_capability().unwrap(), NOW);
    client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW);

    // A → B: contact request carrying A's profile.
    client::send_contact_request(&astore, &r, &bob_ik, "Alice", "privacy first", NOW).unwrap();

    // B drains and applies the request like the desktop poll.
    let drain = |store: &Store| {
        for _ in 0..8 {
            let got = client::recv_session_multi(store, std::slice::from_ref(&r), NOW).unwrap();
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(addr, &rid);
    assert!(matches!(
        client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW),
        PublishResponse::Published
    ));

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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(addr, &rid);
    assert!(matches!(
        client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW),
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
    cstore.save_capability(&client::dev_capability()).unwrap();
    let carol_ik = cstore.load_account().unwrap().identity_public();
    let _ = carol_ik;
    // (Alice is NOT Carol's contact.) Carol receives Alice's ref → nothing pending.
    assert!(matches!(
        client::publish_bundle(&r, cstore.load_account().unwrap(), cstore.load_capability().unwrap(), NOW),
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
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
        client::publish_bundle(&r, a.load_account().unwrap(), a.load_capability().unwrap(), NOW),
        PublishResponse::Published
    ));
    assert!(matches!(
        client::publish_bundle(&r, b1.load_account().unwrap(), b1.load_capability().unwrap(), NOW),
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let a_ik = astore.load_account().unwrap().identity_public();
    let b_ik = bstore.load_account().unwrap().identity_public();
    let r = ctx(relay_addr, &relay_id);
    // Both publish so first-contact can open a session in each direction.
    assert!(matches!(client::publish_bundle(&r, astore.load_account().unwrap(), astore.load_capability().unwrap(), NOW), PublishResponse::Published));
    assert!(matches!(client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW), PublishResponse::Published));

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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();
    let live = ctx(addr, &rid);
    assert!(matches!(
        client::publish_bundle(&live, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW),
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
    astore.save_capability(&client::dev_capability()).unwrap();
    let a_ik = astore.load_account().unwrap().identity_public();
    let r = ctx(addr, &rid);
    // We must have a published bundle so the self-session's first contact can fetch it.
    assert!(matches!(
        client::publish_bundle(&r, astore.load_account().unwrap(), astore.load_capability().unwrap(), NOW),
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW);
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW);
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
    astore.save_capability(&client::dev_capability()).unwrap();
    bstore.save_capability(&client::dev_capability()).unwrap();
    let alice_ik = astore.load_account().unwrap().identity_public();
    let bob_ik = bstore.load_account().unwrap().identity_public();

    let r = ctx(relay_addr, &relay_id);
    let pr = client::publish_bundle(&r, bstore.load_account().unwrap(), bstore.load_capability().unwrap(), NOW);
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
