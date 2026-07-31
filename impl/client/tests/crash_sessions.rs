//! Crash-consistency for the session save (QA-2, transaction 1 of 5).
//!
//! `save_sessions` writes the state file (temp → fsync → rename) and only THEN the anchor. The
//! comment there explains why that order and not the other: a crash between the two leaves the
//! state AHEAD of the anchor, which reads as fine because the state is newer, not older — whereas
//! writing the anchor first would make the identical crash look exactly like a rollback and refuse
//! to open a perfectly good account.
//!
//! That was prose. This cuts the power at that exact point and checks it.
//!
//! # Why a child process
//!
//! The failpoint's action is `abort`, chosen because a `panic` would unwind and run every `Drop` —
//! flushing files a crash would have left unflushed, which is the opposite of what is being
//! modelled. Nothing can catch an abort in-process, so the scenario runs in a CHILD (this same
//! test binary, re-entered through a marker variable) and the parent inspects what the dead child
//! left on disk.
//!
//! Runs only with `--features failpoints`; without it the whole file is a no-op, because the point
//! it depends on compiles to nothing.

#![cfg(feature = "failpoints")]

use client::store::Store;

const HOME: &str = "KARST_CRASH_HOME";
const CHILD: &str = "KARST_CRASH_CHILD";

/// The child half: open the store and save a SECOND generation, dying between the state rename
/// and the anchor write.
fn child_body() -> ! {
    let dir = std::env::var(HOME).expect("home from parent");
    let s = Store::unlock(&dir, b"pw").expect("unlock in child");
    let state = s.load_sessions().expect("load in child");
    // No mutation needed: every write bumps the generation, so simply saving again is what puts
    // the state file ahead of the anchor once the power is cut between the two.
    let _ = s.save_sessions(&state);
    // Only reached if the failpoint did NOT fire — which the parent treats as a failure, because a
    // test that silently stops cutting the power stops testing anything.
    eprintln!("child survived the failpoint");
    std::process::exit(7);
}

#[test]
fn a_crash_between_the_state_and_its_anchor_leaves_the_account_openable() {
    if std::env::var(CHILD).is_ok() {
        child_body();
    }
    let dir = std::env::temp_dir().join(format!("karst-crash-sess-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    // Parent: a store with one saved generation.
    {
        let s = Store::unlock(&dir, b"pw").expect("unlock");
        let state = s.load_sessions().expect("load");
        s.save_sessions(&state).expect("first save completes normally");
    }

    let before =
        std::fs::metadata(dir.join("sessions.dat")).expect("state file").modified().unwrap();
    // Coarse filesystem timestamps would make the comparison below meaningless if the child ran
    // within the same tick.
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let exe = std::env::current_exe().expect("test binary");
    let out = std::process::Command::new(exe)
        .args(["a_crash_between_the_state_and_its_anchor_leaves_the_account_openable", "--exact"])
        .env(CHILD, "1")
        .env(HOME, &dir)
        .env("KARST_FAILPOINTS", "store.sessions.after_rename_before_anchor=abort")
        .output()
        .expect("spawn child");

    // The power really was cut. Asserted BEFORE anything about recovery, because a child that ran
    // to completion would leave a perfectly consistent store and every assertion below would pass
    // for the wrong reason.
    assert_ne!(out.status.code(), Some(7), "the child ran past the failpoint — it did not fire");
    assert!(!out.status.success(), "an aborting failpoint must not be survivable");

    // The child got PAST the rename, not merely near it. Without this the test would pass just as
    // well against a failpoint placed BEFORE the write, where nothing interesting has happened yet
    // and recovery is trivial.
    let after = std::fs::metadata(dir.join("sessions.dat")).expect("state file").modified().unwrap();
    assert!(
        after > before,
        "the state file was not rewritten — the crash happened before the rename, so this exercised \
         the easy case rather than the one the write order exists for"
    );

    // …and the account still opens: state ahead of anchor reads as newer, not as a rollback.
    let s = Store::unlock(&dir, b"pw").expect("the account must still unlock after the crash");
    s.load_sessions().expect(
        "the account refused to open after a crash between the state write and the anchor — \
         exactly the failure the write ORDER exists to prevent",
    );

    // And it is still usable afterwards, which is what "recoverable" has to mean.
    let st = s.load_sessions().expect("load");
    s.save_sessions(&st).expect("saving after the crash must work");

    let _ = std::fs::remove_dir_all(&dir);
}
