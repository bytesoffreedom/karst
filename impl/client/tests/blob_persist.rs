//! §15 blob persistence across a restart — of the RELAY, and of the CLIENT.
//!
//! Relay side: the relay's blob index is durable, so a large upload parked on the relay survives a
//! restart instead of vanishing (the reliability gate before raising the size limit). Upload a
//! multi-chunk blob, bring up a SECOND relay node over the SAME on-disk blob directory (its index
//! is rebuilt purely from disk), download it back byte-identical.
//!
//! Client side (A4-1): the uploader's own restart is the harder half, because the relay owns a blob
//! by the `client_addr` of its first chunk, and the per-process address the client used to send did
//! not survive a restart. Both halves are exercised here against a real socket relay.

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use relay::node::RelayNode;
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

/// Bring up a relay whose blob store lives at `blob_dir`. Returns how to reach it.
fn spawn(blob_dir: &Path) -> (SocketAddr, client::RelayId) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(client::dev_capability());
    relay.enable_blobs(blob_dir.to_path_buf(), NOW, relay::node::BlobPersistence::Durable).unwrap();
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

#[test]
fn a_parked_blob_survives_a_relay_restart() {
    let blob_dir = temp_dir("survive");

    // Relay #1 accepts a multi-chunk upload (two full chunks + a short tail).
    let (addr1, rid1) = spawn(&blob_dir);
    let data: Vec<u8> =
        (0..(client::blob::BLOB_CHUNK * 2 + 123)).map(|i| (i.wrapping_mul(31)) as u8).collect();
    let (id, key, hash, count) =
        client::blob_upload(&ctx(addr1, &rid1), &client::dev_capability(), std::io::Cursor::new(&data), data.len() as u64)
            .expect("upload");
    assert_eq!(count, 3);

    // RESTART: a second relay node over the SAME blob directory. Its index is rebuilt only from
    // the on-disk metadata sidecars — nothing is shared in memory with relay #1.
    let (addr2, rid2) = spawn(&blob_dir);

    // The blob downloads back byte-identical through the restarted relay.
    let mut out = Vec::new();
    client::blob_download(&ctx(addr2, &rid2), id, key, count, hash, &mut out).expect("download after restart");
    assert_eq!(out, data, "the parked blob survived the restart byte-for-byte");
}

/// A4-1: an upload interrupted by a CLIENT restart resumes from the relay's watermark.
///
/// The restart is simulated the only way that proves anything — every piece of in-memory client
/// state is DROPPED (the `Relay`, so anything it held is gone for good, and the `Store` handle
/// with the `blob_id`/`key` it was holding), and the second attempt is rebuilt from what is on disk
/// plus the file itself: the resume record, found under an `upload_id` re-derived from
/// (recipient, name, size, content hash).
///
/// DISCRIMINATING: before the fix this test failed at the resume, not at the assertions after it.
/// The put path sent a per-`Relay` random value as `client_addr`, the relay's blob store had
/// recorded the FIRST attempt's value as the blob's owner, and the restarted client — necessarily
/// holding a new one — was rejected ("blob owned by another sender"), permanently, since every retry
/// minted another stranger. The single `Relay` reused across attempts in
/// `blob_upload_resumes_from_the_relay_watermark` is exactly what hid it. Nothing here would pass
/// under the old behaviour: the resume returns `Err` and the watermark never leaves 2.
#[test]
fn an_upload_resumes_after_the_client_itself_restarts() {
    let blob_dir = temp_dir("client-restart-blobs");
    let vault_dir = temp_dir("client-restart-vault");
    let (addr, rid) = spawn(&blob_dir);

    let chunk = client::blob::BLOB_CHUNK;
    let data: Vec<u8> = (0..(chunk * 3 + 9)).map(|i| (i.wrapping_mul(7)) as u8).collect(); // 4 chunks
    let size = data.len() as u64;
    let peer = [9u8; 32];
    let upload_id = client::upload_id_for(&peer, "big.bin", size, &client::blob::plaintext_hash(&data));

    // ---- Client process #1: records the upload, gets 2 of 4 chunks up, then dies. ----
    {
        let store = client::store::Store::unlock(vault_dir.clone(), b"pw").unwrap();
        let (blob_id, key) = (client::blob::random32(), client::blob::random32());
        store
            .add_pending_upload(&client::store::PendingUpload {
                upload_id,
                blob_id,
                key,
                to_ik: peer,
                name: "big.bin".into(),
                size,
                queued_at: NOW,
                path: None,
            })
            .unwrap();
        let r = ctx(addr, &rid);
        // A reader holding only the first two chunks: stores 0 and 1, then errors — a crash
        // mid-upload, with the same effect on the relay.
        let partial = std::io::Cursor::new(data[..2 * chunk].to_vec());
        assert!(
            client::blob_upload_resumable(&r, &client::dev_capability(), partial, size, blob_id, key).is_err(),
            "the interrupted attempt fails mid-upload"
        );
        assert_eq!(client::blob_stat(&r, blob_id).unwrap(), Some((2, 4, false)), "2 chunks parked");
    }

    // ---- Client process #2: nothing but the disk and the user's file. ----
    let store = client::store::Store::unlock(vault_dir, b"pw").unwrap();
    let pu = store
        .get_pending_upload(&upload_id)
        .unwrap()
        .expect("the resume record survived the restart");
    let r2 = ctx(addr, &rid); // a NEW Relay, holding nothing from the first, as a new process has

    let (id, key, hash, count) = client::blob_upload_resumable(
        &r2,
        &client::dev_capability(),
        std::io::Cursor::new(&data),
        size,
        pu.blob_id,
        pu.key,
    )
    .expect("the restarted client resumes its own upload");

    assert_eq!((id, key), (pu.blob_id, pu.key), "it continued the SAME blob, not a fresh one");
    assert_eq!(client::blob_stat(&r2, id).unwrap(), Some((4, 4, true)), "resumed to complete");

    // And the resumed blob is the file: the two chunks from the dead process and the two from the
    // live one decrypt into one byte-identical whole under one key.
    let mut out = Vec::new();
    client::blob_download(&r2, id, key, count, hash, &mut out).expect("download the resumed blob");
    assert_eq!(out, data, "the resumed upload is byte-identical to the original");

    store.remove_pending_upload(&upload_id).unwrap();
    assert!(store.list_pending_uploads().unwrap().is_empty(), "the record clears on completion");
}

/// The resume-record store is bounded, and a full one silently stops recording new uploads — so
/// records for blobs the relay has certainly swept must not sit there forever. `now` is passed in
/// (no wall clock), and the assertion is on which records remain, not on elapsed time.
#[test]
fn stale_resume_records_are_swept_once_their_blob_is_gone() {
    let dir = temp_dir("upload-sweep");
    let store = client::store::Store::unlock(dir, b"pw").unwrap();
    let rec = |tag: u8, queued_at: u64| client::store::PendingUpload {
        upload_id: [tag; 32],
        blob_id: [tag; 32],
        key: [tag; 32],
        to_ik: [tag; 32],
        name: "big.bin".into(),
        size: 1_000_000,
        queued_at,
        path: None,
    };
    store.add_pending_upload(&rec(1, NOW)).unwrap();
    store.add_pending_upload(&rec(2, NOW)).unwrap();

    // One second inside the relay's blob TTL: the blob may still be there, so the record stays.
    let inside = NOW + node::blobstore::BLOB_TTL_SECS;
    assert_eq!(client::sweep_pending_uploads(&store, inside), 0, "nothing swept while resumable");
    assert_eq!(store.list_pending_uploads().unwrap().len(), 2);

    // Past it, the relay has dropped the partial blob — the record can only point at nothing.
    let past = NOW + node::blobstore::BLOB_TTL_SECS + 1;
    assert_eq!(client::sweep_pending_uploads(&store, past), 2, "both stale records dropped");
    assert!(store.list_pending_uploads().unwrap().is_empty());
}

/// **A download reuses ONE connection for all its chunks** (QUIC-7).
///
/// An upload has amortized its handshakes since FT4; a download paid a fresh connect and a fresh
/// Noise handshake per chunk, so a large file cost tens of thousands of handshakes to FETCH and one
/// to send. `ChunkFetcher` closes that.
///
/// DISCRIMINATING without a handshake counter, by using the QUIC pool as the observable: the pool
/// only ever holds connections a caller SCOPED (QUIC-5, "no scope, no pool"). A download that opens
/// a scoped session leaves exactly one entry there; the old per-chunk path went through the
/// unscoped `blob_get` and would leave zero. The upload in the same test is the control — it also
/// uses one session per file, deliberately unscoped, so it must contribute nothing.
#[test]
fn every_chunk_of_a_download_rides_one_connection() {
    use karst_transport::quic::QuicAdapter;
    use karst_transport::transport::{Dest, Path as TPath};

    let blob_dir = temp_dir("one-conn");
    let (noise_priv, noise_pub) = relay::server::generate_noise_keypair();
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(client::dev_capability());
    relay.enable_blobs(blob_dir.clone(), NOW, relay::node::BlobPersistence::Durable).unwrap();
    let fetch_pub = relay.relay_public().to_bytes();
    let server = relay::quic_server::QuicServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(std::sync::RwLock::new(relay)),
        Arc::new(move || NOW),
        noise_priv,
    )
    .expect("bind quic");
    let quic_addr = server.local_addr().expect("bound");
    thread::spawn(move || {
        let _ = server.serve();
    });

    let quic = Arc::new(QuicAdapter::new().expect("client endpoint"));
    let mut r = client::Relay::new(quic_addr, client::RelayId { noise_pub, fetch_pub }, None);
    r.set_paths_for_test(vec![TPath::new(quic.clone(), Dest::from(quic_addr))]);

    // Three chunks, so "one connection" is a claim about several requests and not about one.
    let data: Vec<u8> =
        (0..(client::blob::BLOB_CHUNK * 2 + 77)).map(|i| (i.wrapping_mul(17)) as u8).collect();
    let (id, key, hash, count) = client::blob_upload(
        &r,
        &client::dev_capability(),
        std::io::Cursor::new(&data),
        data.len() as u64,
    )
    .expect("upload");
    assert_eq!(count, 3);
    assert_eq!(quic.pooled(), 0, "an upload session is deliberately unscoped and must not pool");

    let mut out = Vec::new();
    client::blob_download(&r, id, key, count, hash, &mut out).expect("download");
    assert_eq!(out, data, "the bytes must survive the reused session unchanged");
    assert_eq!(
        quic.pooled(),
        1,
        "three chunks left {} connections behind — the download did not reuse its session",
        quic.pooled()
    );
}
