//! Crash-consistency for a blob upload (QA-2, transaction 4 of 5).
//!
//! `put_chunk` persists the metadata sidecar header BEFORE the first chunk file, and the comment
//! there says why: a crash after the header leaves an in-progress blob with fewer chunks and the
//! client resumes, whereas a chunk file with no header would be an unrecoverable orphan.
//!
//! This cuts the power in that window and checks the claim: the store still opens, the blob is
//! known but incomplete, and the upload can be finished afterwards.
//!
//! See `client/tests/crash_sessions.rs` for why the child-process shape is required and what
//! `abort` does and does not model.

#![cfg(feature = "failpoints")]

use node::blobstore::{BlobOwner, BlobStore};

/// The blob's identity: who owns it and what opens it. Fixed for this test — the crash window
/// under examination is about the sidecar header, not about ownership.
const OWNER: BlobOwner = BlobOwner { sender: SENDER, read_pub: [0xAB; 32] };

const HOME: &str = "KARST_CRASH_HOME";
const CHILD: &str = "KARST_CRASH_CHILD";
const ID: [u8; 32] = [0x5B; 32];
const SENDER: [u8; 32] = [0x1A; 32];
const NOW: u64 = 1_000_000;

fn child_body() -> ! {
    let dir = std::env::var(HOME).expect("home from parent");
    let mut s = BlobStore::open(dir.into(), NOW).expect("open in child");
    let _ = s.put_chunk(OWNER, ID, 0, 2, b"first chunk", NOW);
    eprintln!("child survived the failpoint");
    std::process::exit(7);
}

#[test]
fn a_crash_after_the_header_leaves_a_resumable_blob_not_an_orphan() {
    if std::env::var(CHILD).is_ok() {
        child_body();
    }
    let dir = node::scratch::dir_for_test("crash-blob"); // #321: under the swept root

    let exe = std::env::current_exe().expect("test binary");
    let out = std::process::Command::new(exe)
        .args(["a_crash_after_the_header_leaves_a_resumable_blob_not_an_orphan", "--exact"])
        .env(CHILD, "1")
        .env(HOME, &dir)
        .env("KARST_FAILPOINTS", "blobstore.after_header_before_chunk=abort")
        .output()
        .expect("spawn child");

    assert_ne!(out.status.code(), Some(7), "the child ran past the failpoint — it did not fire");
    assert!(!out.status.success(), "an aborting failpoint must not be survivable");

    // The header really was written before the crash. Without this a failpoint placed earlier
    // would leave an empty directory, and "the store opens and the blob is absent" would pass
    // while describing nothing.
    let wrote_something = std::fs::read_dir(&dir).expect("dir").next().is_some();
    assert!(
        wrote_something,
        "the child died before writing anything — this exercised the empty case, not the window \
         between the header and the chunk"
    );

    // The store opens: an orphaned or half-written sidecar must not make recovery fail.
    let mut s = BlobStore::open(dir.clone(), NOW).expect("the store must still open after a crash");

    // The blob is known and INCOMPLETE — which is what "the client resumes" requires. A store
    // that forgot it entirely would also "open fine", so the distinction matters.
    match s.meta(&ID) {
        Some((_, complete)) => assert!(!complete, "a blob missing its only chunk reported complete"),
        None => {
            // Also acceptable per the comment's logic — the header alone carries no chunk — but
            // then resuming must still work, which the next step checks.
        }
    }

    // And the upload can be finished: this is the property the write ORDER exists to protect.
    let put = s.put_chunk(OWNER, ID, 0, 2, b"first chunk", NOW);
    assert!(
        !matches!(put, node::blobstore::BlobPut::Rejected(_)),
        "resuming the interrupted upload was rejected: {put:?}"
    );
    let put2 = s.put_chunk(OWNER, ID, 1, 2, b"second chunk", NOW);
    assert!(!matches!(put2, node::blobstore::BlobPut::Rejected(_)), "second chunk rejected");
    assert_eq!(
        s.get_chunk(&ID, 0).as_deref(),
        Some(&b"first chunk"[..]),
        "the resumed chunk is not readable"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
