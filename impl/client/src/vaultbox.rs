//! The messenger's account, stored in the new container (#324).
//!
//! This is the seam. Above it the app keeps doing what it already does — a working directory that
//! `Store` and `Vault` operate on unchanged. Below it that directory is a snapshot blob living in
//! `vault`'s object store instead of in a region of the old container.
//!
//! # Why an adapter and not a rewrite
//!
//! The container this replaced had exactly one shape: open a compartment, materialise its ONE
//! opaque blob into a work dir, snapshot the dir back on save. The app never asked it for objects,
//! offsets or partial updates. So the whole app could move to the new container by replacing what
//! stores that blob — not by teaching every write path about objects.
//!
//! An object-native version, where the `Store`'s files ARE vault objects and a save writes only
//! what changed, uses the machinery as designed and is the better end state. It also touches every
//! write path in the app, which is exactly where a mistake silently loses somebody's account. It is
//! a later slice with its own argument; the measurement in `container-measurements.md` says this
//! one loses nothing today, because every save already rewrites everything.
//!
//! # What this deliberately does NOT hide
//!
//! The container this replaced reported free space as a number the caller could size a snapshot by.
//! This one does not: copy-on-write means rewriting an object of B blocks needs B free blocks while B are
//! still held, so a snapshot sized by the free count fills the container on the first save and
//! cannot commit the second. `max_snapshot_bytes` answers the question the caller actually has,
//! and the authoritative answer stays the attempt itself — see `write_snapshot`.

use std::io;
use std::path::{Path, PathBuf};

use vault::medium::MediumError;
use vault::session::{Unlocked, Vault, VaultError};

/// Every password a container has. Re-exported rather than redefined: they are set as one table,
/// and a type that could carry three of them would invite a caller to try.
pub use vault::session::Passwords;
use vault::slot::Mode;

use crate::workdir::{restore_dir, snapshot_dir};

/// The object slot the account's snapshot lives in.
///
/// One object, slot 0. The catalogue can hold many, and a later slice may split the account across
/// several — but "which slot" must not depend on anything the owner chose, or the choice becomes a
/// fingerprint, so it is a constant of this adapter rather than a parameter.
const SNAPSHOT_SLOT: u64 = 0;

/// The object slot the account's AT-REST KEY lives in.
///
/// # Why the account key is stored rather than being the space key
///
/// The obvious shape is to use the compartment's own key as the key the account's files are
/// encrypted under — one key, nothing to store. It is wrong for one reason, and the reason only
/// shows up at the worst moment: a container's keys are properties of THAT container, and adding a
/// hidden compartment builds a NEW one (see `recreate_with_hidden`). The account's working
/// directory is carried across as bytes, still encrypted under the old container's key, and the new
/// container hands out a different one — so every file in the account stops opening, silently,
/// during an operation the user asked for to gain a feature.
///
/// Storing the key inside the container makes it the ACCOUNT's key rather than the container's, and
/// a migration carries it along with the files it belongs to.
const ACCOUNT_KEY_SLOT: u64 = 1;

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
    /// The key the account's files are encrypted under — read from the container, not derived from
    /// it. See `ACCOUNT_KEY_SLOT`. Held as raw bytes because it is the CLIENT's key type that the
    /// store wants, while the container knows it only as an object's contents.
    account_key: [u8; 32],
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

/// A container error as an `io::Error` that KEEPS its kind where the kind carries information.
///
/// Callers above this layer collapse failures into one opaque "wrong password", and they are right
/// to: distinguishing "wrong password" from "no such compartment" answers, for free, whether a
/// compartment exists. But two failures are not about the password at all — the file is already
/// open in another session, or it is too small to be a container — and both are properties of the
/// FILE, observable by anyone holding it, with or without a password. Telling a user with a working
/// password that their password is wrong, because a second window is open, is a bug that only shows
/// up in somebody's hands. So the kind survives for exactly those, and nothing else.
fn vault_err(e: VaultError) -> io::Error {
    let kind = match &e {
        VaultError::Storage(MediumError::Io(inner)) => inner.kind(),
        VaultError::TooSmall { .. } => io::ErrorKind::InvalidInput,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, e.to_string())
}

/// Create a container with all four passwords.
///
/// `size` is the file's size on disk, exactly — the container never grows, and what fits inside is
/// a property of the format rather than of a per-container knob.
pub fn create(path: &Path, size: u64, pw: &Passwords<'_>) -> io::Result<()> {
    Vault::create(path, size, pw).map_err(vault_err)
}

/// Open whatever `password` unlocks, materialising the account into `work_dir`.
///
/// A hidden account's `work_dir` must be RAM-backed — the caller passes one, and passing a
/// disk-backed directory for a hidden account writes its plaintext to the disk the container
/// exists to keep it off. That check belongs to the caller because only the caller knows which
/// directories are which; `open_routed` below is where that rule is enforced, and it is what the
/// app calls.
pub fn open(path: &Path, password: &[u8], size: u64, work_dir: PathBuf) -> io::Result<Opened> {
    open_with(path, password, size, |_| Ok(work_dir))
}

/// Open, and choose the working directory ONCE THE ROLE IS KNOWN.
///
/// Which directory an account may be materialised into depends on which compartment the password
/// opened, and the password is the only thing that says which one that is — so the choice cannot be
/// made before the unlock. A hidden account's plaintext must never touch the real disk, which is a
/// rule about directories, and `choose` is where a caller enforces it: returning an error there
/// refuses the open with nothing written.
pub fn open_with(
    path: &Path,
    password: &[u8],
    size: u64,
    choose: impl FnOnce(Role) -> io::Result<PathBuf>,
) -> io::Result<Opened> {
    let mut session = match Vault::unlock(path, password, size).map_err(vault_err)? {
        Unlocked::Wiped => return Ok(Opened::Wiped),
        Unlocked::Session(v) => *v,
    };
    let role = match session.mode() {
        Mode::Protected => Role::Main,
        Mode::Hidden => Role::Hidden,
        Mode::Public => Role::Public,
        Mode::Wipe => unreachable!("a wipe never yields a session"),
    };
    let work_dir = choose(role)?;
    let account_key = account_key_of(&mut session, role)?;
    // An empty object is a NEW account, not a damaged one: a container is created before it holds
    // anything, and the first save is what puts a snapshot there.
    let blob = session.read_object(SNAPSHOT_SLOT).map_err(vault_err)?.unwrap_or_default();
    restore_dir(&work_dir, &blob)?;
    Ok(Opened::Account(Box::new(VaultBox { inner: session, work_dir, role, account_key })))
}

/// The compartment's account key, minted on the first session that can write one.
///
/// A public session cannot mint: it holds no ownership-layer key and so cannot claim a block. That
/// is not a limitation to work around — a compartment with no account key has never been opened by
/// its owner, so there is no account in it to read, and inventing a key here would produce a second
/// account that looks like the first one's and shares none of its files.
fn account_key_of(session: &mut vault::session::Vault, role: Role) -> io::Result<[u8; 32]> {
    if let Some(bytes) = session.read_object(ACCOUNT_KEY_SLOT).map_err(vault_err)? {
        return bytes
            .as_slice()
            .try_into()
            .map_err(|_| io_err("the account key in this container is not 32 bytes"));
    }
    if role == Role::Public {
        return Err(io_err("this compartment holds no account yet"));
    }
    let mut key = [0u8; 32];
    {
        use chacha20poly1305::aead::rand_core::RngCore;
        chacha20poly1305::aead::OsRng.fill_bytes(&mut key);
    }
    session.write_object(ACCOUNT_KEY_SLOT, &key).map_err(vault_err)?;
    Ok(key)
}

/// Open, routing a HIDDEN account to a RAM-backed directory and refusing if there is none.
///
/// The refusal is the point. This used to fall back to a predictable path on the real disk, which
/// silently wrote a hidden account's plaintext to the very disk the container exists to keep it off
/// (CRYPTO-02). `hidden_dir` is `None` when the system cannot prove a RAM-backed store exists, and
/// then a hidden password does not open — the honest answer, since opening would be a lie about
/// where the files went.
pub fn open_routed(
    path: &Path,
    password: &[u8],
    size: u64,
    main_dir: PathBuf,
    hidden_dir: Option<PathBuf>,
) -> io::Result<Opened> {
    open_with(path, password, size, |role| match role {
        Role::Hidden => hidden_dir.ok_or_else(|| {
            io_err(
                "a hidden account needs a RAM-backed store (tmpfs); none is available on this \
                 system, and unlocking onto the real disk would defeat the container",
            )
        }),
        _ => Ok(main_dir),
    })
}

/// The container's size, read from the file itself.
///
/// There is no second source for it: the container never grows, so the file's length IS its size,
/// and a caller that opened an account does not carry the number around from whenever the file was
/// created. A truncated or padded file does not go unnoticed — the size feeds `FormatParams`, which
/// feeds `format_hash`, which rides in the aad of every record, so a wrong size means nothing
/// decrypts rather than something decrypting wrongly. Fail-closed by construction.
pub fn size_of(path: &Path) -> io::Result<u64> {
    Ok(std::fs::metadata(path)?.len())
}

/// The smallest container that can be created — a property of the format, published so a caller
/// can clamp a user's choice instead of building a file and then refusing it.
pub fn minimum_size() -> u64 {
    vault::session::minimum_size()
}

/// A password for a role the user did not set: random, never shown to anyone, discarded here.
///
/// The slot table is fixed — four slots, always, whether or not their passwords exist — and that
/// uniformity IS the deniability: a container with three slots would say, to anyone holding the
/// file, that one compartment was never set up. So an unset role is given a password nobody has,
/// including us. It is not a placeholder to be filled in later; there is no later, because
/// installing a password into an existing slot table is exactly what the format refuses (see
/// `recreate_with_hidden`).
pub fn unopenable_password() -> [u8; 32] {
    use chacha20poly1305::aead::rand_core::RngCore;
    let mut p = [0u8; 32];
    chacha20poly1305::aead::OsRng.fill_bytes(&mut p);
    p
}

/// Which compartment a password opens, materialising NOTHING.
///
/// For a caller that has to check a password before doing something drastic with the container. It
/// costs one KDF and touches no directory. `None` means the password was the duress one and the
/// container is already gone: asked anywhere, that password means the same thing, and a check that
/// quietly declined to honour it would be the one place duress fails.
pub fn role_of(path: &Path, password: &[u8], size: u64) -> io::Result<Option<Role>> {
    match Vault::unlock(path, password, size).map_err(vault_err)? {
        Unlocked::Wiped => Ok(None),
        Unlocked::Session(v) => Ok(Some(match v.mode() {
            Mode::Protected => Role::Main,
            Mode::Hidden => Role::Hidden,
            Mode::Public => Role::Public,
            Mode::Wipe => unreachable!("a wipe never yields a session"),
        })),
    }
}

/// The name a COMMITTED replacement waits under. Its presence means: the account is in here.
const PENDING: &str = "new";

/// The name a replacement is BUILT under. Its presence means: this was abandoned, throw it away.
///
/// The two names are the whole recovery story, and one name would not do. A single `.new` file
/// cannot say whether the account already reached it, so a crash while building would leave an
/// EMPTY container that the next launch renames over the good one — the account gone with no error
/// anywhere, because an empty object is a legitimate new account. The rename from `.building` to
/// `.new` is what makes the name mean "committed".
const BUILDING: &str = "building";

/// Finish a recreation that was interrupted, if one was.
///
/// Called before every open, and it is the whole of the crash recovery:
///
/// * a `.building` file is an abandoned attempt — the old container is still intact and
///   authoritative, so the attempt is deleted;
/// * a `.new` file is a COMMITTED replacement holding the account, so the recreation is finished
///   from wherever it stopped — including the wipe, if the crash landed before it. Doing nothing
///   would leave the user looking at a wiped container with their account lying next to it under a
///   name nothing opens.
pub fn finish_pending(path: &Path) -> io::Result<()> {
    let _ = std::fs::remove_file(path.with_extension(BUILDING));
    let pending = path.with_extension(PENDING);
    if !pending.exists() {
        return Ok(());
    }
    // The old file may still be here: a crash between "commit the replacement" and "destroy the
    // old one" leaves both. Renaming over it would unlink the old inode WITHOUT overwriting it,
    // leaving the previous container's bytes in free space — the leak the wipe-then-rename order
    // exists to prevent. So the wipe happens here too, not only on the un-crashed path.
    if path.exists() {
        let size = size_of(path)?;
        vault::file::FileStore::open(path, size).map_err(io_err)?.wipe().map_err(io_err)?;
    }
    std::fs::rename(&pending, path)
}

/// Recreate the container so it has a hidden compartment, carrying the main account across.
///
/// # Why this cannot be an "add a password" operation
///
/// The plan is explicit that P1 does not get `K_B` and cannot read B. So the hidden space's key
/// exists only inside the slot its own password opens, and there is nowhere to keep it that would
/// let the main password install a hidden password later — anywhere it could be kept, the main
/// password could reach it, which is the property being protected. Adding a compartment therefore
/// means a new container.
///
/// # Every password is asked for again, and that is not laziness
///
/// The cover and wipe passwords live in slots too, and this builds a NEW slot table. Carrying them
/// over is impossible for the same reason as above: their slots are opened by their own passwords,
/// not by P1. Generating fresh random ones instead would silently retire a wipe password the user
/// believes in — and they would find out at the one moment it was supposed to work.
///
/// # The order, which is the whole risk
///
/// ```text
///   build the replacement at `.building`, carry the account into it
///   rename `.building` -> `.new`          <- COMMIT POINT: the account is now in the new file
///   DESTROY the old file in place
///   rename `.new` -> the container
/// ```
///
/// Every crash window lands on a state a name describes. Before the commit point the old container
/// is untouched and the leftover is a `.building` file the next open deletes. After it, the account
/// is in `.new`, and the next open finishes the remaining steps. The name is what carries this: a
/// file called `.new` while it was still being filled would be renamed over a perfectly good
/// container by a recovery that had no way to know the account had never reached it.
///
/// Destroying before the final rename looks backwards and is not. The alternative — rename first,
/// wipe after — unlinks the old inode without overwriting it, leaving the previous container's
/// contents in free space for anyone who reads the raw device.
pub fn recreate_with_hidden(
    path: &Path,
    size: u64,
    pw: &Passwords<'_>,
    work_dir: &Path,
    account_key: &crate::secretbox::MasterKey,
) -> io::Result<()> {
    let building = path.with_extension(BUILDING);
    let pending = path.with_extension(PENDING);
    // Only an abandoned BUILD is swept here. A `.new` file is a committed replacement holding
    // somebody's account, and deleting it would be the destruction this whole ordering avoids.
    let _ = std::fs::remove_file(&building);

    create(&building, size, pw)?;
    let staging = building.with_extension("staging");
    {
        // **The new container is opened into a STAGING directory, never into the live one.**
        // Opening restores the container's contents over the work dir, and a freshly created
        // container is empty — so opening it into the live directory would erase the very account
        // this function exists to carry across, and the save that followed would store the
        // emptiness. That is not hypothetical: it is what the first version of this did, and the
        // test below is what caught it.
        let mut fresh = match open(&building, pw.protected, size, staging.clone())? {
            Opened::Account(a) => *a,
            Opened::Wiped => return Err(io_err("the new container reported a wipe")),
        };
        // The key comes across with the files. Without this the carried working directory is still
        // encrypted under the previous container's key while the new one hands out its own, and
        // every file in the account stops opening — during an operation the user asked for.
        fresh.install_account_key(account_key)?;
        let blob = snapshot_dir(work_dir, fresh.max_snapshot_bytes())?;
        restore_dir(&staging, &blob)?;
        fresh.save()?;
    }
    let _ = std::fs::remove_dir_all(&staging);
    // COMMIT POINT. The account is durable in the built file, and the rename is what says so: from
    // here on a crash is recovered by finishing, not by discarding.
    std::fs::rename(&building, &pending)?;
    // Only now may the old one be destroyed — and it is destroyed IN PLACE, before the final
    // rename, so its bytes are overwritten rather than merely unlinked.
    finish_pending(path)
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
        self.inner.write_object(SNAPSHOT_SLOT, &blob).map_err(vault_err)
    }

    /// **Nothing this session does can be persisted, and that is the format, not a fault.**
    ///
    /// A cover session holds no ownership-layer key, so it cannot claim a block — which is exactly
    /// why revealing the cover password cannot damage or detect the hidden space. Every caller that
    /// would otherwise "save before X" has to ask this first, or it fails on an operation that was
    /// never going to work: locking the app is the one that matters, because refusing to lock
    /// leaves the plaintext session open on the screen of someone who just asked to close it —
    /// under duress, the worst possible moment (found by driving the real app, not by a test).
    pub fn is_read_only(&self) -> bool {
        self.role == Role::Public
    }

    /// Save, then release the session's plaintext work dir — in that order and only that order.
    ///
    /// A hidden account's work dir is its only copy between saves, so it is removed only after the
    /// save has SUCCEEDED. A main account's work dir is its own storage and is never removed.
    pub fn save_and_release(&mut self) -> io::Result<()> {
        // A cover session has nothing to write and never had — see `is_read_only`.
        if !self.is_read_only() {
            self.save()?;
        }
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

    /// The account's at-rest key. Stored in the container rather than derived from it, so a
    /// migration can carry it along with the files it opens — see `ACCOUNT_KEY_SLOT`.
    pub fn account_key(&self) -> crate::secretbox::MasterKey {
        crate::secretbox::MasterKey::from_bytes(self.account_key)
    }

    /// Put an EXISTING account's key into this (fresh) compartment, replacing the one minted on
    /// open. Only a migration has any business calling this: the key belongs to the files being
    /// carried in, and the container it is being written into has none of them yet.
    fn install_account_key(&mut self, key: &crate::secretbox::MasterKey) -> io::Result<()> {
        let raw = key.as_bytes();
        self.inner.write_object(ACCOUNT_KEY_SLOT, &raw).map_err(vault_err)?;
        self.account_key = raw;
        Ok(())
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

    fn four<'a>(p: &'a [u8], h: &'a [u8], c: &'a [u8], w: &'a [u8]) -> Passwords<'a> {
        Passwords { protected: p, hidden: h, public: c, wipe: w }
    }

    fn make(dir: &Path) -> PathBuf {
        let p = dir.join("container.bin");
        create(&p, SIZE, &four(b"protect", b"hidden-one", b"cover-story", b"burn-it")).expect("create");
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

    /// Recreating carries the main account across and gives the container a hidden compartment
    /// that works.
    #[test]
    fn recreating_keeps_the_account_and_adds_a_hidden_compartment() {
        let dir = scratch("recreate");
        let p = make(&dir);
        let work = dir.join("work");
        {
            let mut a = account(&p, b"protect", work.clone());
            std::fs::write(a.work_dir.join("chats.dat"), b"years of history").unwrap();
            a.save().expect("save");
        }
        // Reopen so the work dir holds the live account, as the app does when the user asks.
        let live = account(&p, b"protect", work.clone());
        let key_before = live.account_key();
        drop(live);
        recreate_with_hidden(
            &p,
            SIZE,
            &four(b"protect", b"new-hidden", b"new-cover", b"new-burn"),
            &work,
            &key_before,
        )
        .expect("recreate");

        // Each open is closed before the next one: the container takes an exclusive lock, so two
        // live sessions on one file are refused by design rather than serialised.
        {
            let a = account(&p, b"protect", dir.join("after"));
            assert_eq!(
                std::fs::read(a.work_dir.join("chats.dat")).unwrap(),
                b"years of history",
                "the recreation lost the main account"
            );
            // The files came across as BYTES, still encrypted under the key the account had. A new
            // key here would leave every one of them unopenable while looking like a clean success.
            assert_eq!(
                a.account_key().as_bytes(),
                key_before.as_bytes(),
                "the account's at-rest key did not survive the recreation"
            );
        }
        let h = account(&p, b"new-hidden", dir.join("hidden"));
        assert_eq!(h.role, Role::Hidden, "the hidden password does not open the hidden space");
        assert!(!h.work_dir.join("chats.dat").exists(), "the hidden space saw the main account");
    }

    /// **A crash between destroying the old file and renaming the new one loses nothing.**
    ///
    /// That window is the reason the order is wipe-then-rename rather than the other way round,
    /// and it is the only moment where the account exists under a name nothing opens. The next
    /// open must complete the rename rather than show the user a wiped container.
    #[test]
    fn an_interrupted_recreation_is_finished_on_the_next_open() {
        let dir = scratch("interrupted");
        let p = make(&dir);
        let work = dir.join("work");
        {
            let mut a = account(&p, b"protect", work.clone());
            std::fs::write(a.work_dir.join("chats.dat"), b"must survive").unwrap();
            a.save().expect("save");
        }
        // Build the replacement and destroy the original, then stop — exactly the state a crash
        // between those two steps leaves behind.
        let pending = p.with_extension(PENDING);
        create(&pending, SIZE, &four(b"protect", b"h", b"c", b"w")).expect("create replacement");
        {
            let mut fresh = account(&pending, b"protect", dir.join("mid"));
            std::fs::write(fresh.work_dir.join("chats.dat"), b"must survive").unwrap();
            fresh.save().expect("save into the replacement");
        }
        vault::file::FileStore::open(&p, SIZE).expect("open old").wipe().expect("wipe old");
        assert!(open(&p, b"protect", SIZE, dir.join("x")).is_err(), "the old file survived the wipe");

        finish_pending(&p).expect("finish");
        let a = account(&p, b"protect", dir.join("after"));
        assert_eq!(
            std::fs::read(a.work_dir.join("chats.dat")).unwrap(),
            b"must survive",
            "the interrupted recreation lost the account"
        );
    }

    /// **A cover session cannot write, and every caller has to be able to ASK before trying.**
    ///
    /// The inability is the format working as intended — no ownership-layer key, no claimed block,
    /// which is why revealing the cover password can neither damage nor detect the hidden space. The
    /// bug it caused was one layer up: the app saved before locking, the save failed, and locking
    /// was refused — leaving a plaintext session open on the screen of someone who had just asked to
    /// close it. Found by driving the real app; pinned here so the next caller can check instead of
    /// discovering it the same way.
    #[test]
    fn a_cover_session_says_it_cannot_write_and_releasing_it_still_works() {
        let dir = scratch("readonly");
        let p = make(&dir);
        {
            let mut a = account(&p, b"protect", dir.join("work"));
            std::fs::write(a.work_dir.join("note.txt"), b"the main account").unwrap();
            a.save().expect("the protecting session can save");
            assert!(!a.is_read_only(), "the protecting session must be writable");
        }
        let mut cover = account(&p, b"cover-story", dir.join("cover"));
        assert!(cover.is_read_only(), "a cover session must declare itself read-only");
        cover.save().expect_err("a cover session cannot claim a block, so a save must fail");
        // The lock path goes through this one, and it must NOT fail: there was never anything to
        // write, so refusing here would strand the session open.
        cover.save_and_release().expect("releasing a cover session must not depend on a save");
    }

    /// **A crash while the replacement is still being BUILT must not touch the account.**
    ///
    /// This is the other window, and the dangerous one: the half-built file is a perfectly valid
    /// container that simply has nothing in it yet. A recovery that renamed it over the original
    /// would destroy the account without a single error — an empty object is a new account, not a
    /// damaged one, so nothing downstream would notice. The name is what tells the two apart.
    #[test]
    fn an_abandoned_build_is_thrown_away_not_promoted() {
        let dir = scratch("abandoned");
        let p = make(&dir);
        let work = dir.join("work");
        {
            let mut a = account(&p, b"protect", work.clone());
            std::fs::write(a.work_dir.join("chats.dat"), b"must survive").unwrap();
            a.save().expect("save");
        }
        // Exactly the state a crash between `create` and the commit rename leaves: a valid, empty
        // container under the build name, and the original still holding everything.
        let building = p.with_extension(BUILDING);
        create(&building, SIZE, &four(b"protect", b"h", b"c", b"w")).expect("create the replacement");

        finish_pending(&p).expect("finish");
        assert!(!building.exists(), "the abandoned build was left behind");
        let a = account(&p, b"protect", dir.join("after"));
        assert_eq!(
            std::fs::read(a.work_dir.join("chats.dat")).unwrap(),
            b"must survive",
            "an unfinished build was promoted over the account"
        );
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
