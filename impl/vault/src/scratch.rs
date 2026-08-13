//! Where a test in THIS crate puts its container file, and who removes it (#321, #324).
//!
//! `vault` sits BELOW `node`, so it cannot use `node::scratch` — the dependency would run the
//! wrong way and put protocol concerns under the on-disk format. It needs its own, and it needs one
//! more than most crates do: a session test creates a container that is fully written with random
//! bytes, so every test here costs megabytes rather than kilobytes. Left alone they reached 1.3 GB.
//!
//! Same deal as `node::scratch`, and the same honest limit: this BOUNDS the leak rather than
//! removing it. The harness gives no teardown hook, so each run sweeps what earlier runs left and
//! its own directories survive until the next run.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

/// Old enough to sweep. Generous, because deleting a LIVE run's container turns a leak into a
/// flaky test — strictly the worse bug.
const STALE_AFTER: Duration = Duration::from_secs(6 * 60 * 60);

fn root() -> PathBuf {
    std::env::temp_dir().join("karst-test")
}

/// A fresh path for a container file, inside a directory this crate will sweep later.
pub fn container_path(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    static SWEPT: std::sync::Once = std::sync::Once::new();
    SWEPT.call_once(sweep_stale);

    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = root().join(format!("vault-{tag}-{}-{nanos}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir.join("container.bin")
}

/// Remove what earlier runs left. Best-effort: a cleanup that can fail a test run is worse than the
/// garbage it removes.
///
/// Both conditions required — old AND the pid no longer running — because cargo runs test binaries
/// concurrently and a second `cargo test` in another terminal is ordinary. Age alone would delete a
/// live run's container out from under it.
fn sweep_stale() {
    let Ok(entries) = std::fs::read_dir(root()) else { return };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("vault-") {
            continue; // somebody else's; deleting on a guess is how cleanup becomes data loss
        }
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .map(|t| now.duration_since(t).unwrap_or_default() > STALE_AFTER)
            .unwrap_or(false);
        if old && !pid_of(&name).is_some_and(pid_is_live) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// The pid out of `vault-{tag}-{pid}-{nanos}-{seq}`. `None` for anything else, which is left alone.
fn pid_of(name: &str) -> Option<u32> {
    let parts: Vec<&str> = name.rsplitn(4, '-').collect();
    parts.get(2).and_then(|p| p.parse().ok())
}

/// Whether that process still exists. `/proc` on Linux; elsewhere true, which fails SAFE — an
/// unknown platform sweeps nothing rather than sweeping something live.
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
    fn two_paths_never_collide_and_their_parent_exists() {
        let a = container_path("collide");
        let b = container_path("collide");
        assert_ne!(a, b);
        assert!(a.parent().expect("parent").is_dir());
    }

    #[test]
    fn the_pid_survives_a_tag_with_dashes() {
        assert_eq!(pid_of("vault-session-roundtrip-4242-99-0"), Some(4242));
        assert_eq!(pid_of("not-ours"), None);
    }

    /// A live run's directory is never swept — this process is live by definition.
    #[test]
    fn a_sweep_spares_a_living_run() {
        let mine = container_path("live");
        sweep_stale();
        assert!(mine.parent().expect("parent").is_dir(), "the sweep deleted a live run's dir");
    }
}
