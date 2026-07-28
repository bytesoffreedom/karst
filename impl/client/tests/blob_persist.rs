//! §15 blob persistence across a relay restart. The relay's blob index is durable, so a large
//! upload parked on the relay survives a restart instead of vanishing (the reliability gate before
//! raising the size limit). Here: upload a multi-chunk blob to a relay, bring up a SECOND relay
//! node over the SAME on-disk blob directory (a restart — its index is rebuilt purely from disk),
//! and download the blob back byte-identical through it.

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use node::node::RelayNode;
use node::socket::RelayServer;

const NOW: u64 = 1_000_000;

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("karst-blobpersist-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Bring up a relay whose blob store lives at `blob_dir`. Returns how to reach it.
fn spawn(blob_dir: &Path) -> (SocketAddr, client::RelayId) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(client::dev_capability());
    relay.enable_blobs(blob_dir.to_path_buf(), NOW, node::node::BlobPersistence::Durable).unwrap();
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
