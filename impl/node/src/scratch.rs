//! Where a test puts its working directory, and who cleans it up (#321).
//!
//! # The failure this exists to stop
//!
//! Integration tests create a `Store`/relay home under `std::env::temp_dir()` and never remove it.
//! One run leaks hundreds of directories. On a machine whose `/tmp` is a tmpfs — the common
//! systemd layout — a few weeks of runs fill it, and when a tmpfs reaches zero every process on the
//! box stops being able to write a single byte. That is not a housekeeping annoyance; it took a
//! whole session down, and the symptom (`ENOSPC` from unrelated commands) points nowhere near the
//! test suite.
//!
//! # What this actually promises, and what it does not
//!
//! **It bounds the leak; it does not remove it.** Rust's test harness offers no teardown hook that
//! runs after the last test in a binary, and a guard object would have to be threaded through
//! ~180 call sites that take a `PathBuf` today. So the deal here is: every run puts its
//! directories under ONE root, and every run sweeps what EARLIER runs left behind. A run's own
//! directories survive until the next run — which is a bounded amount of garbage instead of an
//! unbounded one, and it is the difference between "some megabytes" and "the machine stops".
//!
//! Deleting on drop is still the better answer and is worth doing when the call sites are touched
//! for another reason. This is the version that fixes the outage without rewriting every test.
//!
//! # Why it lives in `node`
//!
//! Every crate whose tests need it (`client`, `relay`, `node` itself) already depends on `node`,
//! and the alternative — a dev-only workspace member — costs a manifest, a `helper_guard`
//! classification, and a build unit, to hold thirty lines. `#[doc(hidden)]` and the `_for_test`
//! naming follow the precedent already in this codebase for test-only surface on a shipping type.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

/// Directories older than this are candidates for the sweep. Generous on purpose: a slow suite on
/// a loaded machine can legitimately keep a directory open for a long time, and deleting a LIVE
/// run's working directory turns a leak into a flaky test, which is a strictly worse bug.
const STALE_AFTER: Duration = Duration::from_secs(6 * 60 * 60);

/// The one root every test directory goes under, so a sweep has something to sweep.
fn root() -> PathBuf {
    std::env::temp_dir().join("karst-test")
}

/// A fresh working directory for a test, created and ready.
///
/// Unique without relying on the clock alone: tests in one binary run on several threads with the
/// SAME pid, and a coarse timer hands two of them the same nanosecond — which showed up as
/// `AlreadyExists` on CI and not locally. The pid separates runs, the counter separates threads.
#[doc(hidden)]
pub fn dir_for_test(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    static SWEPT: std::sync::Once = std::sync::Once::new();
    SWEPT.call_once(sweep_stale);

    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = root().join(format!("{tag}-{}-{nanos}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create the test working directory");
    dir
}

/// Remove what earlier runs left behind. Best-effort throughout: this is cleanup, and a cleanup
/// that can fail a test run is worse than the garbage it removes.
///
/// **Two conditions, both required.** A directory is swept only if it is old AND its pid is no
/// longer running. Either alone is unsafe: `cargo` runs several test binaries concurrently, and a
/// second `cargo test` in another terminal is an ordinary thing to do — sweeping on age alone
/// would delete a live run's directory out from under it, and sweeping on liveness alone would
/// race a run that has just started.
fn sweep_stale() {
    let Ok(entries) = std::fs::read_dir(root()) else {
        return; // nothing swept because nothing is there yet
    };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .map(|t| now.duration_since(t).unwrap_or_default() > STALE_AFTER)
            .unwrap_or(false);
        if old && !pid_of(&entry.file_name().to_string_lossy()).is_some_and(pid_is_live) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// The pid embedded in `{tag}-{pid}-{nanos}-{seq}`. `None` for anything not of that shape, which
/// is then left alone: an unrecognised directory is somebody else's, and deleting on a guess is
/// how a cleanup becomes a data-loss report.
fn pid_of(name: &str) -> Option<u32> {
    let parts: Vec<&str> = name.rsplitn(4, '-').collect();
    // rsplitn yields [seq, nanos, pid, tag-with-any-dashes]
    parts.get(2).and_then(|p| p.parse().ok())
}

/// Whether a process with this id currently exists. `/proc` on Linux; elsewhere this returns true,
/// which fails SAFE — an unknown platform sweeps nothing rather than sweeping something live.
fn pid_is_live(pid: u32) -> bool {
    if cfg!(target_os = "linux") {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    } else {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_calls_never_collide_even_in_the_same_nanosecond() {
        let a = dir_for_test("collide");
        let b = dir_for_test("collide");
        assert_ne!(a, b, "two directories in one process must differ");
        assert!(a.is_dir() && b.is_dir(), "both must exist, ready to use");
    }

    #[test]
    fn everything_lands_under_one_root_so_a_sweep_has_something_to_sweep() {
        let d = dir_for_test("rooted");
        assert_eq!(d.parent(), Some(root().as_path()));
    }

    /// The pid is read back out of the name — the sweep's whole safety rests on it, and a tag
    /// containing dashes (every real one does) must not shift the field.
    #[test]
    fn the_pid_survives_a_tag_with_dashes_in_it() {
        assert_eq!(pid_of("outbox-batch-a-12345-999-7"), Some(12345));
        assert_eq!(pid_of("simple-42-1-0"), Some(42));
        assert_eq!(pid_of("not-our-shape"), None, "a foreign directory must be left alone");
        assert_eq!(pid_of(""), None);
    }

    /// A live run must never be swept. This process is live by definition, so its own fresh
    /// directory is the strongest available case.
    #[test]
    fn a_sweep_does_not_touch_a_living_runs_directory() {
        let mine = dir_for_test("live");
        sweep_stale();
        assert!(mine.is_dir(), "the sweep deleted a directory belonging to a running process");
    }

    /// And the liveness check has to actually distinguish, or the test above passes for free.
    #[test]
    fn the_liveness_check_tells_a_running_process_from_a_gone_one() {
        assert!(pid_is_live(std::process::id()), "this process is running");
        if cfg!(target_os = "linux") {
            // pid 0 is never a userland process on Linux, so /proc/0 never exists.
            assert!(!pid_is_live(0), "pid 0 must not read as live");
        }
    }
}
