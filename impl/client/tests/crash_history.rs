//! Crash-consistency for the incoming-history append (QA-2, transaction 3 of 5).
//!
//! `append_history_incoming` does two things: it appends the plaintext to the history log, and it
//! records the message id in the dedup ring. Between them there is a window where the message is
//! durably stored and the ring does not know about it.
//!
//! The ring's own doc names that window as the one it exists to absorb, and states the price:
//! **losing a ring entry costs one re-appended message, never a lost one.** This cuts the power in
//! exactly that window and checks both halves of that sentence — the message is still there, and a
//! redelivery of the same id lands again rather than being dropped.
//!
//! Duplication is the ACCEPTED cost here, so the test asserts it happens rather than treating it
//! as a defect. Asserting the opposite would quietly turn a documented trade into a bug report,
//! and then someone would "fix" it by fsyncing the ring on the hot receive path — buying
//! exactly-once at the price the design deliberately refused to pay.
//!
//! See `crash_sessions.rs` for why the child-process shape is required and what `abort` does and
//! does not model.

#![cfg(feature = "failpoints")]

use client::store::{HistoryRecord, Store};

const HOME: &str = "KARST_CRASH_HOME";
const CHILD: &str = "KARST_CRASH_CHILD";

fn record() -> HistoryRecord {
    HistoryRecord { peer_ik: [0x21; 32], from_me: false, text: b"landed once".to_vec(), ts: 4242 }
}

const MSG_ID: [u8; 32] = [0x99; 32];

fn child_body() -> ! {
    let dir = std::env::var(HOME).expect("home from parent");
    let s = Store::unlock(&dir, b"pw").expect("unlock in child");
    let _ = s.append_history_incoming(&record(), MSG_ID);
    eprintln!("child survived the failpoint");
    std::process::exit(7);
}

#[test]
fn a_crash_before_the_dedup_ring_costs_a_duplicate_and_never_the_message() {
    if std::env::var(CHILD).is_ok() {
        child_body();
    }
    let dir = std::env::temp_dir().join(format!("karst-crash-hist-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    {
        let s = Store::unlock(&dir, b"pw").expect("unlock");
        assert!(s.load_history().expect("history").is_empty(), "start from nothing");
    }

    let exe = std::env::current_exe().expect("test binary");
    let out = std::process::Command::new(exe)
        .args(["a_crash_before_the_dedup_ring_costs_a_duplicate_and_never_the_message", "--exact"])
        .env(CHILD, "1")
        .env(HOME, &dir)
        .env("KARST_FAILPOINTS", "store.history.after_append_before_dedup=abort")
        .output()
        .expect("spawn child");

    // Preconditions first: the power really was cut, and the append really happened before it.
    // Without the second, a failpoint placed before the append would leave an empty log and every
    // assertion below would pass by describing a store where nothing occurred.
    assert_ne!(out.status.code(), Some(7), "the child ran past the failpoint — it did not fire");
    assert!(!out.status.success(), "an aborting failpoint must not be survivable");

    let s = Store::unlock(&dir, b"pw").expect("the account must still unlock");
    let after_crash = s.load_history().expect("history must still be readable");
    assert_eq!(
        after_crash.len(),
        1,
        "the message was not durable before the ring was updated — a crash here must cost a \
         duplicate, never the message itself"
    );
    assert_eq!(after_crash[0].text, b"landed once".to_vec());

    // THE RING LOST THE ENTRY. This is the half that makes the duplicate happen, and it is the
    // state the ring's own doc describes as the accepted cost. Checked directly rather than
    // through behaviour: `append_history_incoming` does not itself deduplicate — the receive path
    // does, by asking `recent_incoming_ids` first — so asserting on appends would have been
    // asserting about the wrong function. (The first version of this test did exactly that and
    // failed, which is how the misreading surfaced.)
    let seen = s.recent_incoming_ids(1024).expect("dedup ring");
    assert!(
        !seen.contains(&MSG_ID),
        "the ring knew the id after a crash that happened BEFORE it was written — then the \
         window this test exists for is somewhere other than where the failpoint sits"
    );

    // A completed append DOES record the id, so the ring is not simply broken. Without this the
    // assertion above would pass just as well against a build whose ring never stored anything.
    s.append_history_incoming(&record(), MSG_ID).expect("a redelivery is appended");
    assert!(
        s.recent_incoming_ids(1024).expect("dedup ring").contains(&MSG_ID),
        "a COMPLETED append did not record the id either — the ring is broken, and the assertion \
         above was describing that rather than the crash"
    );
    assert_eq!(s.load_history().expect("history").len(), 2, "the redelivery was appended");

    let _ = std::fs::remove_dir_all(&dir);
}
