//! The account's working directory: turning a directory into one blob, and back.
//!
//! The container stores an account as a single object. Above the container the app keeps operating
//! on ordinary files in a directory, so something has to move between the two — that is all this
//! module is. It came out of the old container (#319) unchanged, because it was never about that
//! container: it is about the directory, and the new one needs exactly the same two functions.
//!
//! The third function here is the one that decides where a HIDDEN account's plaintext may be
//! materialised, and it lives beside these two because it is the same question — which directory —
//! asked where the answer is a refusal rather than a path.

use std::io;
use std::path::{Path, PathBuf};

fn io_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Snapshot a whole account directory into ONE blob — the whole account state as a single
/// serialized object, which is what the container stores. An account therefore lives entirely
/// inside the container file with no external files of its own. Collects every regular file under
/// `dir`, keyed by its `/`-separated relative path.
///
/// **SEC-35 — `max_bytes` bounds the RAM this can consume.** The files under `dir` are not all
/// ours: attachments and downloads a CORRESPONDENT sent us live in this same account directory,
/// and their size is entirely their choice, not ours. The old, unbounded version `std::fs::read`
/// every file it found before ever checking whether the result could go anywhere — a correspondent
/// who hands us gigabytes of attachments turns the next ordinary save (which every account
/// mutation goes through) into an attempt to buffer all of it into one `Vec<u8>` in memory, an OOM
/// a remote peer can trigger for free. The container already refused an oversized object loudly —
/// but only AFTER this function had already finished building it, which is too late to save the
/// memory. So the running total is checked against
/// `max_bytes` via `metadata().len()` (a stat, not a read) BEFORE each file's bytes are pulled in,
/// and the walk aborts the instant the budget is blown — the offending path and both sizes are
/// named in the error, and no file that pushed the total over the line is ever read into memory.
/// This must fail LOUDLY, never truncate: a snapshot that silently dropped files partway through
/// would restore into a torn, incomplete account — a destroyed compartment that looks intact.
/// Pass the compartment's own usable write capacity (`vaultbox::VaultBox::max_snapshot_bytes`) as
/// `max_bytes`, so a snapshot that could never fit is refused before the OOM rather than after a
/// doomed multi-gigabyte read; use `usize::MAX` only where there is no container to fit (tests).
///
/// **Honest limit — `max_bytes` bounds the sum of raw file lengths, not the final postcard blob
/// size.** Serializing adds small per-entry overhead (the relative-path string, a couple of
/// varint length prefixes), so a directory that just clears this check by a handful of bytes can
/// still — rarely, and only within that narrow margin — be refused by the container's own write.
/// That is not silent: the write still refuses loudly in that case; this function's job is only to
/// stop the unbounded READ before it happens, not to be the single source of truth on what fits.
/// The write remains the authority either way. Same reasoning covers the stat-then-read gap below
/// (a file could theoretically grow between the `metadata()` check and the `std::fs::read()` a few
/// lines later) — the sole writer of an account's own work dir is this same process, so that race
/// isn't reachable in practice, and the container's own ceiling is still there to catch it loudly
/// if it ever were.
pub fn snapshot_dir(dir: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut total: usize = 0;
    fn walk(
        base: &Path,
        cur: &Path,
        out: &mut Vec<(String, Vec<u8>)>,
        total: &mut usize,
        max_bytes: usize,
    ) -> io::Result<()> {
        for entry in std::fs::read_dir(cur)? {
            let entry = entry?;
            let path = entry.path();
            let ty = entry.file_type()?;
            if ty.is_dir() {
                walk(base, &path, out, total, max_bytes)?;
            } else if ty.is_file() {
                let rel = path
                    .strip_prefix(base)
                    .map_err(io_err)?
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                // Stat first, read never — the whole point is to know a file is too big
                // without ever pulling its bytes into RAM to find out.
                let len = entry.metadata()?.len() as usize;
                let new_total = total
                    .checked_add(len)
                    .ok_or_else(|| io_err("snapshot size overflowed usize accumulating file lengths"))?;
                if new_total > max_bytes {
                    return Err(io_err(format!(
                        "snapshot exceeds this account's budget: {rel} ({len} bytes) brings the \
                         running total to {new_total} bytes, over the {max_bytes}-byte cap — \
                         refusing to buffer it rather than build a snapshot that can never be \
                         written back (this file is a correspondent-controlled attachment or \
                         download; its size is not ours to bound at the point it was saved)"
                    )));
                }
                *total = new_total;
                out.push((rel, std::fs::read(&path)?));
            }
        }
        Ok(())
    }
    if dir.exists() {
        walk(dir, dir, &mut files, &mut total, max_bytes)?;
    }
    files.sort_by(|a, b| a.0.cmp(&b.0)); // deterministic order (stable snapshots)
    postcard::to_stdvec(&files).map_err(io_err)
}

/// Rebuild an account directory from a `snapshot_dir` blob: afterwards `dir` holds EXACTLY the
/// files the snapshot names and nothing else. Rejects unsafe relative paths (absolute or `..`)
/// defensively.
///
/// **`dir` is DELETED and recreated — pass a work dir, never a vault base.** Every caller today
/// passes a subdirectory (`<vault>/work`, `/dev/shm/karst-hid-*`), which is what keeps
/// `container.dat` — the sibling this restores FROM — out of the blast radius. A caller that ever
/// handed this the vault base itself would erase the container along with the work dir.
///
/// **A3-3 — this used to OVERLAY the snapshot onto whatever was already in `dir`.** It created and
/// overwrote the snapshot's own files but never removed anything else, and every caller runs it
/// over a work dir that SURVIVES between sessions (the desktop's is `<vault>/work`). So a file the user had deleted — a contact, a settings file,
/// an attachment sidecar — came back the moment its (older, or merely different) snapshot was
/// restored over a directory that still held it, and the next `save()` snapshotted the resurrected
/// merge back INTO the container, making the resurrection permanent. Two generations of state could
/// also be mixed file-by-file with nothing anywhere reporting it. The container is the authority for
/// what an account contains, so restoring now means "make the directory equal the snapshot":
/// everything under `dir` is removed first, then the snapshot is laid down fresh.
///
/// **Ordering, deliberately: decode and validate the WHOLE blob before removing anything.** A blob
/// that fails to decode, or that names an unsafe path, must leave the work dir exactly as it was —
/// otherwise a corrupt read would destroy the one materialized copy on its way to reporting the
/// error.
///
/// **What this DISCARDS, said plainly (rule: no overclaiming).** Anything written into the work dir
/// that never made it into a `save()` is gone at the next open — it is not merged and it is not
/// recovered. For received mail that is safe and already load-bearing: `recv_session_multi` defers
/// its relay ACKs behind a successful container commit, so unsaved messages are still leased on the
/// relay and redeliver. It is NOT safe for the writers that have no relay copy — a queued
/// `flush_outbox` send and an in-progress download/attachment thread are, per `docs/STATUS.md`,
/// durable only at the next container save; a crash before that save now loses them cleanly instead
/// of leaving them behind torn. That is the intended trade (the container cannot be the authority
/// AND defer to leftovers in the directory it authorizes), not an oversight.
pub fn restore_dir(dir: &Path, blob: &[u8]) -> io::Result<()> {
    // Decode + validate FIRST: nothing below may destroy the live work dir on a blob we then
    // turn out to be unable to restore.
    let files: Vec<(String, Vec<u8>)> = if blob.is_empty() {
        Vec::new() // a freshly-created, empty compartment — it holds no files, so neither may `dir`
    } else {
        postcard::from_bytes(blob).map_err(io_err)?
    };
    for (rel, _) in &files {
        if rel.starts_with('/') || rel.split('/').any(|p| p == ".." || p.is_empty()) {
            return Err(io_err("unsafe path in snapshot"));
        }
    }
    // Clear, then lay down. A crash between the two is never OBSERVED: the container still holds
    // the authoritative blob, restore always precedes use, and it is idempotent — the next open
    // simply redoes it. That is why this needs no staging directory (which would litter the vault
    // base with a second container-shaped artifact after a crash — see the zero-external-artifacts
    // test) and no rollback.
    if dir.exists() {
        std::fs::remove_dir_all(dir)?;
    }
    std::fs::create_dir_all(dir)?;
    for (rel, bytes) in files {
        let path = dir.join(&rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &bytes)?;
    }
    Ok(())
}

/// Does `mounts` (the `/proc/mounts` format: `src mountpoint fstype …`) say `mountpoint` is
/// backed by RAM? Split out as a PURE function so the decision is testable on any machine,
/// including ones that do have `/dev/shm` (a test cannot un-mount it to check the refusal path).
pub(crate) fn mounts_say_ram_backed(mounts: &str, mountpoint: &str) -> bool {
    mounts.lines().any(|line| {
        let mut f = line.split_whitespace();
        let _src = f.next();
        let mp = f.next().unwrap_or("");
        let fstype = f.next().unwrap_or("");
        mp == mountpoint && (fstype == "tmpfs" || fstype == "ramfs")
    })
}

/// A work dir that is VERIFIED to live in RAM, for materializing a HIDDEN account — or `None`
/// when this system cannot prove one exists.
///
/// **Fail-closed (CRYPTO-02).** The old code took `/dev/shm` if the path merely *existed* and
/// otherwise silently fell back to a predictable directory on the real disk. That put a hidden
/// account's plaintext tree, filenames, sizes, and lock/temp files onto persistent storage (and
/// into journals and backups) on macOS, Windows, minimal Linux, and containers without a working
/// `/dev/shm` — disproving the "zero external artifacts" claim and breaking the deniability the
/// container exists for, with no cleanup at all after a crash. Checking existence was itself too
/// weak: a path can exist and be an ordinary disk directory, so we check the mount TYPE.
///
/// `None` means the caller must REFUSE to open a hidden account, not pick somewhere else.
pub fn ram_backed_hidden_dir(tag: &str) -> Option<PathBuf> {
    let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
    ["/dev/shm", "/run/shm"].into_iter().find_map(|cand| {
        (mounts_say_ram_backed(&mounts, cand) && Path::new(cand).is_dir())
            .then(|| Path::new(cand).join(format!("karst-hid-{tag}")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = node::scratch::dir_for_test(&format!("workdir-{tag}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("scratch");
        d
    }

    /// A directory goes in and comes back out — nested files included — and the restored tree
    /// snapshots to the identical blob, which is what makes a save idempotent.
    #[test]
    fn a_directory_round_trips_and_the_restore_holds_nothing_else() {
        let root = scratch("roundtrip");
        let src = root.join("acct");
        std::fs::create_dir_all(src.join("net")).unwrap();
        std::fs::write(src.join("contacts.dat"), b"bob and alice").unwrap();
        std::fs::write(src.join("net/sessions.dat"), vec![7u8; 500]).unwrap();

        let blob = snapshot_dir(&src, usize::MAX).unwrap();
        let dst = root.join("restored");
        // A file that is NOT in the snapshot: restoring must remove it, not merge it (A3-3).
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(dst.join("deleted-contact.dat"), b"came back from the dead").unwrap();
        restore_dir(&dst, &blob).unwrap();

        assert_eq!(std::fs::read(dst.join("contacts.dat")).unwrap(), b"bob and alice");
        assert_eq!(std::fs::read(dst.join("net/sessions.dat")).unwrap(), vec![7u8; 500]);
        assert!(!dst.join("deleted-contact.dat").exists(), "the restore merged instead of replacing");
        assert_eq!(snapshot_dir(&dst, usize::MAX).unwrap(), blob, "the round trip is not stable");
    }

    /// A blob that cannot be restored must leave the live directory untouched — the decode happens
    /// before anything is removed, or a corrupt read destroys the one materialised copy on its way
    /// to reporting the error.
    #[test]
    fn a_blob_that_does_not_decode_leaves_the_directory_alone() {
        let root = scratch("corrupt");
        let dir = root.join("acct");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("history.log"), b"years of it").unwrap();

        restore_dir(&dir, b"not a postcard blob at all").expect_err("a corrupt blob must be refused");
        assert_eq!(
            std::fs::read(dir.join("history.log")).unwrap(),
            b"years of it",
            "a refused restore destroyed the directory it refused to replace"
        );
    }

    /// SEC-35: a directory over its budget is refused LOUDLY, naming what overflowed — never
    /// truncated (a truncated snapshot is a destroyed account that looks intact) and never
    /// buffered into memory first to find out.
    #[test]
    fn a_directory_over_its_budget_is_refused_by_name() {
        let root = scratch("budget");
        let acct = root.join("acct");
        std::fs::create_dir_all(&acct).unwrap();
        std::fs::write(acct.join("small.dat"), vec![0u8; 100]).unwrap();
        assert!(!snapshot_dir(&acct, 10_000).unwrap().is_empty(), "an ordinary snapshot must work");

        // A correspondent-controlled attachment blows the budget.
        std::fs::write(acct.join("attachment.bin"), vec![0xAAu8; 5_000]).unwrap();
        let err = snapshot_dir(&acct, 1_000).expect_err("over budget must be refused");
        let msg = err.to_string();
        assert!(msg.contains("attachment.bin"), "the error must name the file that overflowed: {msg}");
        assert!(msg.contains("1000"), "the error must name the budget it exceeded: {msg}");
    }

    /// The mount check must look at the fstype, not merely at whether the path exists — a
    /// directory called `/dev/shm` on an ordinary disk must NOT qualify.
    #[test]
    fn only_a_real_tmpfs_mount_counts_as_ram_backed() {
        let mounts = "\
proc /proc proc rw,nosuid 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0
/dev/sda1 /home ext4 rw,relatime 0 0
";
        assert!(mounts_say_ram_backed(mounts, "/dev/shm"), "a real tmpfs mount qualifies");
        assert!(!mounts_say_ram_backed(mounts, "/home"), "an ext4 mount must not qualify");
        assert!(!mounts_say_ram_backed(mounts, "/run/shm"), "an absent mount must not qualify");
        assert!(
            !mounts_say_ram_backed("/dev/sdb1 /dev/shm ext4 rw 0 0\n", "/dev/shm"),
            "a disk-backed directory that merely LOOKS like /dev/shm must not qualify"
        );
    }
}
