//! The messenger's account, stored in the new container (#324).
//!
//! This is the seam. Above it the app keeps doing what it already does — a working directory that
//! `Store` and `Vault` operate on unchanged. Below it that directory is a snapshot blob living in
//! `vault`'s object store instead of in a region of the old container.
//!
//! # Why an adapter and not a rewrite
//!
//! The old `ContainerVault` has exactly one shape: open a compartment, materialise its ONE opaque
//! blob into a work dir, snapshot the dir back on save. It never asks for objects, offsets or
//! partial updates. So the whole app can move to the new container by replacing what stores that
//! blob — not by teaching every write path about objects.
//!
//! An object-native version, where the `Store`'s files ARE vault objects and a save writes only
//! what changed, uses the machinery as designed and is the better end state. It also touches every
//! write path in the app, which is exactly where a mistake silently loses somebody's account. It is
//! a later slice with its own argument; the measurement in `container-measurements.md` says this
//! one loses nothing today, because every save already rewrites everything.
//!
//! # What this deliberately does NOT hide
//!
//! The old container reported free space as a number the caller could size a snapshot by. This one
//! does not: copy-on-write means rewriting an object of B blocks needs B free blocks while B are
//! still held, so a snapshot sized by the free count fills the container on the first save and
//! cannot commit the second. `max_snapshot_bytes` answers the question the caller actually has,
//! and the authoritative answer stays the attempt itself — see `write_snapshot`.

use std::io;
use std::path::{Path, PathBuf};

use vault::session::{Passwords, Unlocked, Vault};
use vault::slot::Mode;

use crate::container::{restore_dir, snapshot_dir};

/// The object slot the account's snapshot lives in.
///
/// One object, slot 0. The catalogue can hold many, and a later slice may split the account across
/// several — but "which slot" must not depend on anything the owner chose, or the choice becomes a
/// fingerprint, so it is a constant of this adapter rather than a parameter.
const SNAPSHOT_SLOT: u64 = 0;

/// Which compartment a session opened. Mirrors the old `Role` so callers do not have to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The public space, opened by the protecting password.
    Main,
    /// The hidden space.
    Hidden,
    /// The public space, opened by the password that knows nothing of the hidden one.
    Public,
}

/// An account opened from a container: on open its snapshot is materialised into a working
/// directory the existing `Store` code operates on unchanged; on `save` the directory is
/// snapshotted back.
pub struct VaultBox {
    inner: Vault,
    pub work_dir: PathBuf,
    pub role: Role,
}

/// What a password turned out to be for.
pub enum Opened {
    Account(Box<VaultBox>),
    /// A duress password. **The container is already gone** — see `vault::session::Unlocked`.
    Wiped,
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// Create a container with all four passwords.
///
/// `size` is the file's size on disk, exactly — the container never grows, and what fits inside is
/// a property of the format rather than of a per-container knob.
pub fn create(
    path: &Path,
    size: u64,
    protecting: &[u8],
    hidden: &[u8],
    public: &[u8],
    wipe: &[u8],
) -> io::Result<()> {
    Vault::create(path, size, &Passwords { protected: protecting, hidden, public, wipe })
        .map_err(io_err)
}

/// Open whatever `password` unlocks, materialising the account into `work_dir`.
///
/// A hidden account's `work_dir` must be RAM-backed — the caller passes one, and passing a
/// disk-backed directory for a hidden account writes its plaintext to the disk the container
/// exists to keep it off. That check belongs to the caller because only the caller knows which
/// directories are which; this is stated rather than enforced here, and the old container's
/// `open_container` is where the enforcement lives today.
pub fn open(path: &Path, password: &[u8], size: u64, work_dir: PathBuf) -> io::Result<Opened> {
    let session = match Vault::unlock(path, password, size).map_err(io_err)? {
        Unlocked::Wiped => return Ok(Opened::Wiped),
        Unlocked::Session(v) => *v,
    };
    let role = match session.mode() {
        Mode::Protected => Role::Main,
        Mode::Hidden => Role::Hidden,
        Mode::Public => Role::Public,
        Mode::Wipe => unreachable!("a wipe never yields a session"),
    };
    // An empty object is a NEW account, not a damaged one: a container is created before it holds
    // anything, and the first save is what puts a snapshot there.
    let blob = session.read_object(SNAPSHOT_SLOT).map_err(io_err)?.unwrap_or_default();
    restore_dir(&work_dir, &blob)?;
    Ok(Opened::Account(Box::new(VaultBox { inner: session, work_dir, role })))
}

impl VaultBox {
    /// Snapshot the working directory back into the container.
    ///
    /// **A failed save leaves the work dir untouched**, and that is load-bearing rather than
    /// tidy: a hidden account exists nowhere but its RAM work dir between saves, so a caller that
    /// deleted the directory after a failed save would destroy everything since the last one. The
    /// old container carries that as a fixed bug (A3-6); the same rule holds here, and a failed
    /// barrier inside the commit surfaces as an ordinary `Err` for exactly this reason.
    pub fn save(&mut self) -> io::Result<()> {
        let max = self.max_snapshot_bytes();
        let blob = snapshot_dir(&self.work_dir, max)?;
        self.inner.write_object(SNAPSHOT_SLOT, &blob).map_err(io_err)
    }

    /// Save, then release the session's plaintext work dir — in that order and only that order.
    ///
    /// A hidden account's work dir is its only copy between saves, so it is removed only after the
    /// save has SUCCEEDED. A main account's work dir is its own storage and is never removed.
    pub fn save_and_release(&mut self) -> io::Result<()> {
        self.save()?;
        if self.role == Role::Hidden {
            std::fs::remove_dir_all(&self.work_dir)?;
        }
        Ok(())
    }

    /// The largest snapshot that can be written AND rewritten.
    ///
    /// Half the usable space, because copy-on-write holds the old version while the new one is
    /// written. Sizing a snapshot by free space instead fills the container on the first save and
    /// cannot commit the second — `admit` refuses it correctly and the user is told there is no
    /// space in a container that looks half empty.
    ///
    /// It is a BOUND for buffering, not a promise: the estimate is deliberately conservative, so
    /// the authoritative answer to "does this fit" stays the write itself.
    pub fn max_snapshot_bytes(&self) -> usize {
        self.inner.max_rewritable_bytes().min(usize::MAX as u64) as usize
    }

    /// The account's at-rest key — the space key, shared by the protecting and public passwords so
    /// both open the SAME account rather than two that happen to share a file.
    pub fn account_key(&self) -> vault::record::MasterKey {
        self.inner.space_key().clone()
    }

    /// Whether this session can see the ownership layer. False under the public password.
    pub fn has_layer(&self) -> bool {
        self.inner.has_layer()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZE: u64 = 32 * 1024 * 1024;

    fn scratch(tag: &str) -> PathBuf {
        let d = node::scratch::dir_for_test(&format!("vaultbox-{tag}"));
        std::fs::create_dir_all(&d).expect("scratch");
        d
    }

    fn make(dir: &Path) -> PathBuf {
        let p = dir.join("container.bin");
        create(&p, SIZE, b"protect", b"hidden-one", b"cover-story", b"burn-it").expect("create");
        p
    }

    fn account(path: &Path, password: &[u8], work: PathBuf) -> VaultBox {
        match open(path, password, SIZE, work).expect("open") {
            Opened::Account(a) => *a,
            Opened::Wiped => panic!("expected an account, got a wipe"),
        }
    }

    /// The whole seam: put files in the work dir, save, reopen, and the files are there.
    #[test]
    fn a_working_directory_survives_a_save_and_reopen() {
        let dir = scratch("roundtrip");
        let p = make(&dir);
        {
            let mut a = account(&p, b"protect", dir.join("work"));
            std::fs::write(a.work_dir.join("contacts.dat"), b"bob and alice").unwrap();
            std::fs::create_dir_all(a.work_dir.join("acct")).unwrap();
            std::fs::write(a.work_dir.join("acct/history.log"), b"hello there").unwrap();
            a.save().expect("save");
        }
        let a = account(&p, b"protect", dir.join("work2"));
        assert_eq!(std::fs::read(a.work_dir.join("contacts.dat")).unwrap(), b"bob and alice");
        assert_eq!(std::fs::read(a.work_dir.join("acct/history.log")).unwrap(), b"hello there");
    }

    /// The protecting and public passwords open the SAME account — not two that share a file.
    #[test]
    fn the_cover_password_opens_the_same_account() {
        let dir = scratch("shared");
        let p = make(&dir);
        {
            let mut a = account(&p, b"protect", dir.join("w1"));
            std::fs::write(a.work_dir.join("note.txt"), b"the main account").unwrap();
            a.save().expect("save");
        }
        let c = account(&p, b"cover-story", dir.join("w2"));
        assert_eq!(std::fs::read(c.work_dir.join("note.txt")).unwrap(), b"the main account");
        assert_eq!(c.role, Role::Public);
        assert!(!c.has_layer(), "the cover password must not see the ownership layer");
    }

    /// **The hidden account is a different account.** Writing in one must not show up in the other,
    /// in either direction — the property the whole container exists for.
    #[test]
    fn the_hidden_account_and_the_main_one_do_not_see_each_other() {
        let dir = scratch("isolation");
        let p = make(&dir);
        {
            let mut a = account(&p, b"protect", dir.join("main"));
            std::fs::write(a.work_dir.join("who.txt"), b"main").unwrap();
            a.save().expect("save main");
        }
        {
            let mut h = account(&p, b"hidden-one", dir.join("hidden"));
            assert!(!h.work_dir.join("who.txt").exists(), "the hidden account saw the main one");
            std::fs::write(h.work_dir.join("who.txt"), b"hidden").unwrap();
            h.save().expect("save hidden");
        }
        let a = account(&p, b"protect", dir.join("main2"));
        assert_eq!(
            std::fs::read(a.work_dir.join("who.txt")).unwrap(),
            b"main",
            "the hidden account's save disturbed the main one"
        );
    }

    /// Saving repeatedly does not consume the container — the old snapshot's blocks come back.
    #[test]
    fn repeated_saves_do_not_fill_the_container() {
        let dir = scratch("churn");
        let p = make(&dir);
        let mut a = account(&p, b"protect", dir.join("work"));
        std::fs::write(a.work_dir.join("f.dat"), vec![1u8; 4096]).unwrap();
        a.save().expect("first");
        let baseline = a.max_snapshot_bytes();
        for i in 0..5u8 {
            std::fs::write(a.work_dir.join("f.dat"), vec![i; 4096]).unwrap();
            a.save().expect("rewrite");
        }
        assert_eq!(a.max_snapshot_bytes(), baseline, "five saves ate into the container");
    }

    /// The duress password wipes, and reports a wipe rather than an account.
    #[test]
    fn the_duress_password_wipes_instead_of_opening() {
        let dir = scratch("wipe");
        let p = make(&dir);
        {
            let mut a = account(&p, b"protect", dir.join("work"));
            std::fs::write(a.work_dir.join("secret.txt"), b"everything").unwrap();
            a.save().expect("save");
        }
        match open(&p, b"burn-it", SIZE, dir.join("w2")).expect("the wipe password is recognised") {
            Opened::Wiped => {}
            Opened::Account(_) => panic!("the wipe password opened an account"),
        }
        assert!(open(&p, b"protect", SIZE, dir.join("w3")).is_err(), "something opened after a wipe");
    }
}
