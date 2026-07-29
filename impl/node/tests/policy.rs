//! Relay policy advertisement. Pins: `policy()` reflects the operator's blob-persistence choice +
//! the PoW door, disabled-blobs reads as absent, and the policy travels correctly over the socket.

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use node::blobstore::{BLOB_TTL_SECS, MAX_BLOB_SIZE};
use relay::node::{BlobPersistence, RelayNode};
use relay::server::{RelayServer};
use node::socket::{SocketTransport};

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

#[test]
fn policy_reflects_blobs_and_the_pow_door() {
    // Blobs disabled + no door → both absent.
    let bare = RelayNode::new(NOW).policy();
    assert_eq!(bare.blob_persistence, None);
    assert_eq!(bare.blob_ttl_secs, 0);
    assert_eq!(bare.max_blob_size, 0);
    assert_eq!(bare.pow_bits, None);

    // Durable blobs + a 20-bit public door → advertised.
    let mut r = RelayNode::new(NOW);
    r.enable_blobs(temp_dir("durable"), NOW, BlobPersistence::Durable).unwrap();
    r.enable_pow_issue(20);
    let p = r.policy();
    assert_eq!(p.blob_persistence, Some(BlobPersistence::Durable));
    assert_eq!(p.blob_ttl_secs, BLOB_TTL_SECS);
    assert_eq!(p.max_blob_size, MAX_BLOB_SIZE);
    assert_eq!(p.pow_bits, Some(20));

    // Ephemeral is advertised distinctly.
    let mut e = RelayNode::new(NOW);
    e.enable_blobs(temp_dir("ephemeral"), NOW, BlobPersistence::Ephemeral).unwrap();
    assert_eq!(e.policy().blob_persistence, Some(BlobPersistence::Ephemeral));
}

#[test]
fn policy_travels_over_the_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut relay = RelayNode::new(NOW);
    relay.enable_blobs(temp_dir("wire"), NOW, BlobPersistence::Ephemeral).unwrap();
    let server = RelayServer::new(relay, Arc::new(move || NOW));
    let noise_pub = server.noise_public();
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });

    let got = SocketTransport::new(addr, noise_pub).get_policy().expect("policy over the wire");
    assert_eq!(got.blob_persistence, Some(BlobPersistence::Ephemeral));
    assert_eq!(got.max_blob_size, MAX_BLOB_SIZE);
    assert_eq!(got.pow_bits, None);
}
