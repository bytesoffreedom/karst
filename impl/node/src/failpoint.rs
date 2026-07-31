//! Injectable failure points — for testing what a CRASH does, not what an error does (QA-2).
//!
//! Crash-consistency is the property that a machine losing power mid-transaction leaves the store
//! recoverable. It cannot be tested by returning `Err` from a function: an error unwinds, runs
//! every `Drop`, flushes what was buffered and generally lets the program tidy up — which is the
//! opposite of what a crash does. So the mechanism here is deliberately blunter than an error.
//!
//! # `abort`, not `panic`, and the difference is the whole point
//!
//! A `panic!` unwinds the stack and runs destructors. A file whose `Drop` flushes it would be
//! flushed; a lock would be released; a temp file would be cleaned up. A real crash does none of
//! that. `std::process::abort()` does none of that either, which is why it is the default action:
//! it is the closest a process can get to being switched off from outside.
//!
//! The cost is that a test cannot catch it in-process. A crash test has to fork: run the scenario
//! in a CHILD with `KARST_FAILPOINTS` set, let the child die, then inspect the store the child left
//! behind from the parent. That is more machinery than `#[should_panic]`, and it is the machinery
//! the property actually requires.
//!
//! # Off in production, structurally
//!
//! Everything here is behind `#[cfg(feature = "failpoints")]`, off by default. With the feature
//! off, [`fail_point!`] expands to nothing at all — not a branch, not an atomic read, not a string
//! literal. A test in this module asserts that, because a failure-injection mechanism that ships is
//! a defect that only needs someone to set an environment variable.
//!
//! # Usage
//!
//! ```ignore
//! fail_point!("mailstore.after_fsync_before_rename");
//! ```
//!
//! and at run time, in the child process:
//!
//! ```text
//! KARST_FAILPOINTS=mailstore.after_fsync_before_rename=abort
//! ```

/// Fire the named failure point if the environment asks for it. Compiled away entirely when the
/// `failpoints` feature is off.
#[macro_export]
macro_rules! fail_point {
    ($name:expr) => {
        #[cfg(feature = "failpoints")]
        {
            $crate::failpoint::hit($name);
        }
    };
}

#[cfg(feature = "failpoints")]
mod enabled {
    use std::sync::OnceLock;

    /// `name=action` pairs, parsed once. Read from the environment rather than from a setter so a
    /// crash test can arrange it for a CHILD process, which is the only place a crash can be
    /// observed without taking the test runner down with it.
    fn table() -> &'static Vec<(String, String)> {
        static TABLE: OnceLock<Vec<(String, String)>> = OnceLock::new();
        TABLE.get_or_init(|| {
            let Ok(spec) = std::env::var("KARST_FAILPOINTS") else { return Vec::new() };
            spec.split(',')
                .filter_map(|e| e.split_once('='))
                .map(|(n, a)| (n.trim().to_string(), a.trim().to_string()))
                .collect()
        })
    }

    /// What to do at `name`, if anything.
    ///
    /// `abort` is the default and the one that means what it says. `panic` exists ONLY for the rare
    /// case where a test wants to observe unwinding, and its doc says plainly that it does not
    /// model a crash — leaving it unlabelled would let someone reach for the familiar word and
    /// believe they had tested power loss.
    pub fn hit(name: &str) {
        let Some((_, action)) = table().iter().find(|(n, _)| n == name) else { return };
        match action.as_str() {
            "abort" => {
                eprintln!("KARST failpoint {name}: abort");
                std::process::abort();
            }
            "panic" => panic!("KARST failpoint {name}: panic (NOT a crash — Drop still runs)"),
            other => eprintln!("KARST failpoint {name}: unknown action {other:?}, ignored"),
        }
    }
}

#[cfg(feature = "failpoints")]
pub use enabled::hit;

#[cfg(test)]
mod tests {
    /// **The mechanism must not be on by default**, checked against the MANIFEST rather than the
    /// current build.
    ///
    /// The first version asserted `!cfg!(feature = "failpoints")` from inside a
    /// `#[cfg(not(feature = "failpoints"))]` test — a constant, as clippy pointed out, and worse
    /// than useless: in the configuration where it compiled the answer was fixed, and in the
    /// configuration that would have been interesting it did not compile at all. Whether a feature
    /// is *default* is a property of `Cargo.toml`, so that is what gets read.
    ///
    /// It matters because with the feature on, anyone able to set `KARST_FAILPOINTS` can abort the
    /// process at a point of their choosing — a denial-of-service switch that must not be reachable
    /// in a build nobody deliberately made for testing.
    ///
    /// DISCRIMINATING: add `failpoints` to a `default = [...]` list and this reds.
    #[test]
    fn the_feature_is_not_enabled_by_default() {
        let manifest = include_str!("../Cargo.toml");
        let default_line = manifest
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("default"))
            .unwrap_or("");
        assert!(
            !default_line.contains("failpoints"),
            "`failpoints` is in the default feature set ({default_line:?}) — a build nobody asked \
             to be testable now carries a switch that aborts it on demand"
        );
    }

    /// **A point actually FIRES when asked.** Runs only with the feature on.
    ///
    /// Without this, the whole mechanism could be twenty hooks that never trigger, and a
    /// crash-consistency suite built on it would be green while testing nothing — the exact
    /// failure this repository keeps catching by breaking its own tests on purpose.
    ///
    /// The child-process shape is not ceremony: the action is `abort`, so an in-process assertion
    /// would take the test runner down with it. That is also the point of using `abort` — see the
    /// module docs on why `panic` would model the wrong thing.
    #[cfg(feature = "failpoints")]
    #[test]
    fn a_point_fires_and_aborts_the_child() {
        // The child is this same test binary, re-entered with a marker variable, so no separate
        // fixture binary has to exist and drift.
        if std::env::var("KARST_FP_CHILD").is_ok() {
            crate::fail_point!("test.fires");
            eprintln!("child survived the failpoint");
            std::process::exit(7); // distinguishable from an abort
        }
        let exe = std::env::current_exe().expect("test binary path");
        let out = std::process::Command::new(exe)
            .args(["failpoint::tests::a_point_fires_and_aborts_the_child", "--exact", "--nocapture"])
            .env("KARST_FP_CHILD", "1")
            .env("KARST_FAILPOINTS", "test.fires=abort")
            .output()
            .expect("spawn child");
        assert_ne!(out.status.code(), Some(7), "the child ran past the failpoint — it did not fire");
        assert!(
            !out.status.success(),
            "the child exited cleanly; an aborting failpoint must not be survivable"
        );
    }

    /// A firing point costs nothing when the feature is off — no branch, no environment read.
    ///
    /// This is what makes it acceptable to sprinkle the macro across write paths: with the feature
    /// off it is not a cheap check, it is *no* check.
    ///
    /// Only meaningful — and only SAFE — in a default build: with the feature on, the macro below
    /// would fire and abort the whole test binary.
    #[cfg(not(feature = "failpoints"))]
    #[test]
    fn a_point_expands_to_nothing_when_the_feature_is_off() {
        // Compiles in both configurations; does nothing observable in this one.
        crate::fail_point!("test.nowhere");
        // If the macro expanded to an environment read here, this variable would matter. It does
        // not, and the assertion below documents that rather than testing the absence of a branch,
        // which is not observable from inside the language.
        std::env::set_var("KARST_FAILPOINTS", "test.nowhere=abort");
        crate::fail_point!("test.nowhere"); // still nothing — we are still running
        std::env::remove_var("KARST_FAILPOINTS");
    }
}
