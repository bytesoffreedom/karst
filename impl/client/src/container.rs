//! Tier-2 deniable container — the storage heart of the hidden-ACCOUNT redesign.
//!
//! One fixed-size file (`container.dat`) of `N` bytes that is, without a password,
//! **byte-for-byte indistinguishable from random**. It holds, per compartment, a
//! whole serialized account state (format (b): one sealed blob per region, its logical
//! length not observable), plus an in-container 8-slot keyslot table so the number of
//! configured passwords never leaks. See `docs/design/duress-tier2-container.md`.
//!
//! What lives here vs not: this module is the *container mechanism* — it stores/returns
//! an opaque `Vec<u8>` per compartment (Phase 2 plugs the real `Store` snapshot into
//! that blob). The three-password policy (P1 protect / P2 hidden / P3 blind) and the
//! region geometry are enforced here; the desktop UI/network controls are later phases.
//!
//! Deniability model (proven by the tests at the bottom):
//! - No plaintext header/magic anywhere. Salt is a random-looking prefix (a salt is
//!   *supposed* to look random). Slots are raw-AEAD (`nonce‖ct`, no magic) or pure
//!   random when unused — the two are computationally indistinguishable.
//! - `open()` derives the password key once and trial-opens all 8 slots; a wrong
//!   password (or a compartment that isn't there) fails AEAD on every slot — "no such
//!   compartment" and "wrong password" are the same answer, which is the whole point.
//! - P1 (protect) and P3 (blind) wrap the SAME main region key and, since CRYPTO-10 (below),
//!   the SAME policy byte and the SAME write ceiling too — revealing P3 cannot expose P1 or P2,
//!   and can no longer be distinguished from an ordinary account by its write behaviour either.
//!
//! **CRYPTO-14 — honest limit: P3 does NOT mask hidden writes against a snapshot-diff
//! adversary, and this is not fixable at this layer.** Checked against all three things such an
//! adversary can observe:
//! - **Changed bytes:** every save touches only the bytes it actually changed (`persist_range`)
//!   — that is the entire efficiency point of the region/copy-slot design. A P3 (cover) save
//!   therefore touches the identical `(offset, length)` whether or not a hidden compartment
//!   exists (pinned by `a_p3_write_touches_the_same_range_whether_or_not_a_hidden_compartment_exists`);
//!   it does NOT "churn the tail" the way `duress-tier2-container.md` §2(b) hoped it would,
//!   because a small P3 save never reaches that far. A HIDDEN write's changed bytes,
//!   symmetrically, stay entirely inside the hidden region (pinned by
//!   `a_hidden_write_changes_only_bytes_inside_the_hidden_region`). An adversary who holds two
//!   images of the file (or one image plus a live watch) can diff them and localize every
//!   change to a region — separating "ordinary main/cover activity" from "something else wrote
//!   back here" by offset alone, no decryption needed. The only write that touches the hidden
//!   region from the main/cover side is a P3 spill big enough to exceed the protect cap — which
//!   doesn't mask the hidden write, it destroys it (masking and destruction are the same
//!   operation on one shared key here). A real fix would need every save to rewrite the WHOLE
//!   container so a diff can never localize anything — an O(N) rewrite per message, which
//!   directly defeats `persist_range`'s reason to exist. Not implemented; do not claim it works.
//! - **File size:** reveals nothing — `N` is fixed at `create()` time forever; every save is an
//!   in-place rewrite of existing bytes (`persist`/`persist_range`), never a resize.
//! - **mtime:** reveals ONLY that a save happened and roughly when — real, and already conceded
//!   in `docs/design/duress-tier2-container.md` §8 — but not WHICH compartment, since mtime is a
//!   single filesystem-wide timestamp with no per-region granularity. The changed-bytes leak
//!   above is strictly more informative than mtime and is the one that actually distinguishes
//!   compartments.
//!
//! **CRYPTO-10 — the cover password used to prove a duress setup exists; retracts
//! `docs/design/duress-multipassword.md` §"Overwrite decision (settled)"'s "we keep BOTH
//! mechanisms".** A slot used to carry a `Policy` (Protect for P1, Blind for P3) that changed
//! `write`'s ceiling: Protect refused past `region_cap / 2`, Blind was allowed the whole rest of
//! the container. That is a coercer-visible tell with nothing but the password they were handed:
//! every vanilla, never-configured-anything account has exactly ONE password and it is always
//! Protect, so it ALWAYS refuses past `region_cap / 2` — that is the universal baseline, not an
//! edge case. A cover password that keeps accepting well past that point is therefore, by itself,
//! proof a second (Blind) password was deliberately added to this account — which is exactly the
//! one fact a duress feature must never let the cover password prove. The fix (see
//! `Container::write_limits`): EVERY Main write, P1 or P3, gets the identical ceiling now — the
//! Policy byte is still recorded per slot (for anything Phase 2 may need later) but `Policy::Blind`
//! no longer exists as a value ANY code path can produce, and the one place that used to branch on
//! it does not anymore. Net effect, stated plainly because it is a real capability loss: a Blind
//! write can no longer spill into the hidden tail at all. CRYPTO-14 above already showed that
//! capability never bought any masking benefit (a spill only ever destroyed the hidden
//! compartment, it never hid anything from a snapshot-diff adversary) — so closing it costs
//! nothing it was actually providing, and a Blind save is crash-atomic for the first time (it can
//! no longer reach `write_region_at`'s non-atomic spill path via the public API at all).
//!
//! **Scope of the fix — `region_cap` (hence the ceiling) is `main_cap`, a value the user chooses
//! per container at creation (§7's A/B slider), so it remains inferable the same way `N` (total
//! container size) already is per §8 — that leak is accepted and unchanged. What CRYPTO-10 closes
//! is narrower and specific: the divergence BETWEEN P1 and P3 *within one container*. A coercer
//! who has only ever seen this ONE password can no longer learn "this password behaves
//! differently from what this container's real password would" — they learn nothing they
//! couldn't already learn from the file's size.**
//!
//! **Honest residual — management OPERATIONS still betray a second password, only READING an
//! account never does.** `add_hidden`/`add_blind_main`/`add_wipe` all require reading the
//! management directory (`read_dir`), which only the P1 key can open — that is what makes P3 safe
//! to reveal (`revealing_p3_cannot_enumerate_the_other_passwords`, pinned below). A coercer handed
//! the cover password who tries to configure ANOTHER duress password through it gets refused where
//! the real password would have succeeded, and that refusal is itself informative: it says "this
//! is not the password that manages slots," which is already evidence something else does. This
//! cannot be closed without either letting P3 read the directory (directly defeating the property
//! the directory exists for) or removing the directory (reopening A3-1, a silently-clobbered
//! second hidden account). It is a real, accepted limit, not a settled one to reopen — document
//! it in the UI as "do not attempt to add passwords from the cover session."

use crate::secretbox::MasterKey;
use std::io;
use std::path::{Path, PathBuf};

const SALT_LEN: usize = 16;
const SLOT_COUNT: usize = 8;
/// slot plaintext = role(1) ‖ policy(1) ‖ region_off(8) ‖ region_cap(8) ‖ region_key(32)
const SLOT_PLAIN: usize = 1 + 1 + 8 + 8 + 32;
/// raw-AEAD envelope adds nonce(24) + tag(16); no magic prefix (that would be a tell).
const SLOT_LEN: usize = 24 + SLOT_PLAIN + 16;
const HEADER_LEN: usize = SALT_LEN + SLOT_COUNT * SLOT_LEN;
/// Each region begins with a fixed sealed length-header: `seal_raw(region_key, u64 len)`.
/// Keeping the length INSIDE the region (under the region key) — not in the slot — keeps
/// P1 and P3 consistent, since both share the region key and thus read the same length.
/// (Still used by the append-log superblock/chunks below — the region PAYLOAD write path now
/// uses `COPY_HDR_LEN` instead, see CRYPTO-13.)
const LEN_HDR: usize = 24 + 8 + 16;
/// CRYPTO-13 — a region's payload write is `seal_raw` over the WHOLE new blob, and a plain
/// in-place overwrite is not crash-atomic: a save interrupted after only some of its bytes hit
/// disk leaves a mix of old and new bytes that fails the region's own AEAD tag, so the region —
/// not just the newest save, ALL of the compartment's history — becomes permanently unreadable.
/// No plaintext journal or "dirty" flag is allowed (that would itself be a tell that this is a
/// container), so the fix has to stay inside bytes that are already opaque: each region reserves
/// TWO independent copy slots side by side, and a write always targets whichever slot is NOT the
/// current newest, leaving the other — a complete, still-valid earlier save — untouched on disk.
/// A crash mid-write to the NEXT save's target slot (the common case: the currently-newest copy
/// is untouched by this call) can only cost the just-in-flight save; it can no longer brick the
/// compartment. The copy header carries an 8-byte generation counter alongside the length, sealed
/// together — the counter is what lets a reader pick the newer of two authenticating copies with
/// NO plaintext selector anywhere; it is exactly as opaque as the length byte it sits next to.
///
/// **Honest limit — a damaged newest copy rolls back SILENTLY, with no error.** If the copy that
/// already held the completed newest generation is the one that gets damaged (bitrot, a Blind
/// spill landing on it, a second unlucky crash), `read_region_at` has no way to know that — from
/// its perspective "one copy fails to authenticate" is indistinguishable from the routine case of
/// a freshly-created region (slot 1 is unwritten random right after `create()`'s bootstrap) or a
/// torn in-flight write to the STALE slot (the safe case above). So it silently falls back to
/// whatever older generation still authenticates and returns it as if it were current — no error,
/// no signal, just quietly older data. This can't be fixed by adding a "which copy is newest"
/// flag outside the AEAD envelope without creating a new plaintext tell, so it isn't: the
/// generation counter already lives inside the sealed header specifically to avoid that. Whoever
/// calls `Container::write`/`open` needs to know a successful open is "the newest generation this
/// region can still prove," not "the newest generation that was ever written."
const COPY_HDR_PLAIN: usize = 8 + 8; // generation(8) ‖ ciphertext-len(8)
const COPY_HDR_LEN: usize = 24 + COPY_HDR_PLAIN + 16; // nonce(24) + plaintext(16) + tag(16) = 56
/// Below this, a region cannot fit two independent copies (each header + a minimal empty AEAD
/// body) — refuse at creation rather than silently degrading to a single non-atomic copy.
const MIN_REGION_CAP: usize = 2 * (COPY_HDR_LEN + 24 + 16); // 2 * 96 = 192
/// A slot-directory (used-slot indices) sealed under the MANAGEMENT password's key (the P1
/// password `create` was given), placed right after the slots. It records which of the 8
/// slots are taken so adding P2/P3/wipe never clobbers an existing password's slot — the
/// deniability problem "you can't see occupied slots without their passwords." Sealed under
/// the management key, NOT the shared main region key, so a coercer who is given P3 cannot
/// read it and thus cannot learn how many passwords exist. Discipline (as in Tier-1): under
/// duress you reveal P3, never the management password.
const DIR_LEN: usize = 24 + SLOT_COUNT + 16;
const DIR_OFF: usize = SALT_LEN + SLOT_COUNT * SLOT_LEN;
const DATA_OFF: usize = DIR_OFF + DIR_LEN;

fn io_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Snapshot a whole account directory into ONE blob (format (b): the entire account state is a
/// single serialized object). This is the Phase-2 bridge — the blob is what `Container::write`
/// stores for a compartment, so an account lives entirely inside the container with no external
/// files. Collects every regular file under `dir`, keyed by its `/`-separated relative path.
///
/// **SEC-35 — `max_bytes` bounds the RAM this can consume.** The files under `dir` are not all
/// ours: attachments and downloads a CORRESPONDENT sent us live in this same account directory,
/// and their size is entirely their choice, not ours. The old, unbounded version `std::fs::read`
/// every file it found before ever checking whether the result could go anywhere — a correspondent
/// who hands us gigabytes of attachments turns the next ordinary save (`ContainerVault::save`,
/// which every account mutation goes through) into an attempt to buffer all of it into one
/// `Vec<u8>` in memory, an OOM a remote peer can trigger for free. `Container::write` already
/// refused an oversized payload loudly — but only AFTER this function had already finished
/// building it, which is too late to save the memory. So the running total is checked against
/// `max_bytes` via `metadata().len()` (a stat, not a read) BEFORE each file's bytes are pulled in,
/// and the walk aborts the instant the budget is blown — the offending path and both sizes are
/// named in the error, and no file that pushed the total over the line is ever read into memory.
/// This must fail LOUDLY, never truncate: a snapshot that silently dropped files partway through
/// would restore into a torn, incomplete account — a destroyed compartment that looks intact.
/// Pass the compartment's own usable write capacity (see `Container::max_payload_len`) as
/// `max_bytes` so a snapshot that could never fit its region is refused before the OOM, not after
/// a doomed multi-gigabyte read; use `usize::MAX` only where there is no container to fit (tests).
///
/// **Honest limit — `max_bytes` bounds the sum of raw file lengths, not the final postcard blob
/// size.** Serializing adds small per-entry overhead (the relative-path string, a couple of
/// varint length prefixes), so a directory that just clears this check by a handful of bytes can
/// still — rarely, and only within that narrow margin — trip `Container::write`'s own ceiling.
/// That is not silent: `write` still refuses loudly in that case, exactly as it always has; this
/// function's job is only to stop the unbounded READ before it happens, not to be the single
/// source of truth on what fits. `write`'s check remains the authority either way. Same reasoning
/// covers the stat-then-read gap below (a file could theoretically grow between the `metadata()`
/// check and the `std::fs::read()` a few lines later) — the sole writer of an account's own work
/// dir is this same process, so that race isn't reachable in practice, and `write`'s ceiling is
/// still there to catch it loudly if it ever were.
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
/// overwrote the snapshot's own files but never removed anything else, and both callers
/// (`ContainerVault::open`, `open_container`) run it over a work dir that SURVIVES between sessions
/// (the desktop's is `<vault>/work`). So a file the user had deleted — a contact, a settings file,
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// The everyday account. Carries a `Policy` (Protect = P1, Blind = P3).
    Main,
    /// The deniable hidden account.
    Hidden,
    /// Duress: entering it wipes the whole container (no region).
    Wipe,
}

/// CRYPTO-10: this used to have a THIRD value, `Blind` (P3), whose only effect was a wider write
/// ceiling than `Protect` — see the module doc. That value has been removed rather than left
/// unused: the whole point is that no code path can produce it anymore, not merely that nothing
/// currently reads it. Every Main slot (P1 and P3 alike) now seals `Protect`; the byte is kept
/// (rather than dropped) only so a Phase-2 caller has somewhere to put a future distinction that
/// does NOT reintroduce a P1/P3 behavioural difference.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Policy {
    /// Every main slot, P1 and P3 alike: confined to half the region's ping-pong geometry, same
    /// as a completely vanilla single-password account. Never writes the hidden tail.
    Protect,
    /// Non-main roles.
    None,
}

impl Role {
    fn to_byte(self) -> u8 {
        match self {
            Role::Main => 1,
            Role::Hidden => 2,
            Role::Wipe => 3,
        }
    }
    fn from_byte(b: u8) -> Option<Role> {
        match b {
            1 => Some(Role::Main),
            2 => Some(Role::Hidden),
            3 => Some(Role::Wipe),
            _ => None,
        }
    }
}
impl Policy {
    fn to_byte(self) -> u8 {
        match self {
            Policy::Protect => 1,
            Policy::None => 0,
        }
    }
    fn from_byte(b: u8) -> Policy {
        match b {
            1 => Policy::Protect,
            _ => Policy::None,
        }
    }
}

/// A decrypted slot: what a password unlocked.
#[derive(Clone)]
pub struct SlotInfo {
    pub role: Role,
    pub policy: Policy,
    pub region_off: u64,
    pub region_cap: u64,
    region_key: MasterKey,
}

/// The result of opening the container with a password.
pub enum Opened {
    /// Main/Hidden compartment: the decrypted account-state payload.
    Compartment {
        role: Role,
        policy: Policy,
        payload: Vec<u8>,
        /// The region's random key — use it as the account's at-rest key so that P1 and P3 (which
        /// share the region key but have different passwords) both decrypt the SAME account files.
        region_key: MasterKey,
    },
    /// A duress/wipe password — caller must erase the container.
    Wipe,
}

/// The largest container this implementation will create or open.
///
/// **A3-9 — the container is a whole-file-in-RAM design, so its size IS a memory budget.** `load`
/// reads the entire file into `buf` and `create` allocates and randomises all of it, while the
/// desktop's `container_create` takes a `size_mb` straight from the frontend and multiplies. A user
/// (or a buggy UI) asking for 10 GB got a 10 GB allocation and, with two windows open, two of them.
///
/// Memory-mapping or a block-oriented store would fix the `buf` term and NOT the problem, which is
/// the reason this cap is the right shape of fix rather than a band-aid over a missing rewrite:
/// format (b) stores **one sealed blob per compartment**, so a save necessarily builds the whole
/// account snapshot in RAM (`snapshot_dir` → `Vec<u8>`) and then its whole sealed ciphertext, and an
/// open necessarily decrypts the whole blob. Peak RAM is therefore about `C` (the file) + `0.375·C`
/// (the snapshot — a main compartment's usable payload is ~3/8 of the file, see `container_create`'s
/// geometry) + as much again for the ciphertext, i.e. **≈2×C, of which only the first term is what
/// mmap would remove**. A container the machine cannot hold in RAM twice over is unusable by design,
/// not by implementation, so the honest fix is to refuse it at the library boundary — where every
/// caller is covered — instead of validating `size_mb` in one UI. 1 GiB ⇒ ~2 GiB peak and ~384 MiB
/// of usable account.
pub const MAX_CONTAINER_BYTES: u64 = 1024 * 1024 * 1024;

/// The whole container file, held in memory (fixed size and bounded by [`MAX_CONTAINER_BYTES`]).
/// Every mutation is persisted by a crash-safe temp-swap that preserves untouched regions
/// byte-for-byte.
pub struct Container {
    path: PathBuf,
    buf: Vec<u8>,
    /// A held-open descriptor carrying an exclusive advisory lock on the container file (A3-8).
    /// `None` only on a platform where we cannot take one — see [`Container::lock_file`].
    /// Dropping the `Container` closes it, which releases the lock.
    lock: Option<std::fs::File>,
}

fn fill_random(dst: &mut [u8]) {
    use chacha20poly1305::aead::rand_core::RngCore;
    use chacha20poly1305::aead::OsRng;
    OsRng.fill_bytes(dst);
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    fill_random(&mut v);
    v
}

/// A fresh random region key. It is NOT password-derived — the random bytes ARE the key,
/// so there is no reason to run Argon2 over them (that would be pure expense).
fn random_key() -> MasterKey {
    let mut k = [0u8; 32];
    k.copy_from_slice(&random_bytes(32));
    MasterKey::from_bytes(k)
}

/// At-rest labels for the container's four kinds of record. Fixed strings, never paths: the
/// container is ONE opaque file whose regions must stay indistinguishable from random, so a
/// label can only name the ROLE of a record, never its offset. Distinct roles mean a length
/// header can never be opened as a payload, or a slot as a directory (CRYPTO-05).
const SLOT_LABEL: &str = "container:slot";
const DIR_LABEL: &str = "container:dir";
const LEN_LABEL: &str = "container:len";
const BODY_LABEL: &str = "container:body";

impl Container {
    fn slot_span(i: usize) -> (usize, usize) {
        let off = SALT_LEN + i * SLOT_LEN;
        (off, off + SLOT_LEN)
    }
    fn salt(&self) -> &[u8] {
        &self.buf[..SALT_LEN]
    }

    /// Take the exclusive advisory lock on an EXISTING container file, and hand back the descriptor
    /// that holds it (closing it releases the lock, so a `Container` keeps it for its whole life).
    ///
    /// **A3-8 — nothing used to stop two writers over one container, and the damage was worse than
    /// "one of them loses its changes".** Every `Container::load` takes its own full copy of the
    /// file with no lock, generation number or compare-and-swap, so: (a) both `persist` paths used
    /// the SAME `<container>.tmp` name, and two concurrent full saves could interleave their bytes
    /// into that one file before one of them renamed the mixture over `container.dat` — salt and
    /// slot table included, i.e. EVERY compartment gone, not just the losing writer's; (b) `load`
    /// unconditionally deleted `<container>.tmp`, so merely OPENING a container could unlink another
    /// process's save mid-flight; (c) a stale in-memory image persisted later silently reverted
    /// regions its holder never touched; (d) in-place `persist_range` writes from two processes
    /// could interleave inside one region. A file lock is what closes all four at once: with it, (a)
    /// and (b) cannot arise because the tmp file is provably ours while we hold the lock, and (c)
    /// and (d) cannot arise because no second image exists.
    ///
    /// `flock` is per open-file-description, so this also refuses a second `Container` in the SAME
    /// process — the "one held instance" convention the old comments relied on is now enforced
    /// rather than assumed.
    ///
    /// **Honest limits.** (1) UNIX ONLY. On other platforms this returns `None` and the container is
    /// unprotected exactly as before — stated here and in `docs/STATUS.md` rather than papered over;
    /// the desktop's only supported container platform today is Linux. (2) The lock is on the
    /// container's INODE, and `persist` replaces that inode by rename, so `persist` re-takes the lock
    /// on the new file immediately afterwards; a second process that opens the container inside that
    /// microsecond window can win it, in which case our re-lock fails LOUDLY (see `persist`) rather
    /// than letting two writers proceed. (3) It is advisory: a different program that ignores locks
    /// is not stopped by it.
    fn lock_file(path: &Path) -> io::Result<Option<std::fs::File>> {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let f = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
            // SAFETY: `f` is a live descriptor for the duration of the call.
            let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc != 0 {
                // `WouldBlock` deliberately: `LOCK_NB` returns EWOULDBLOCK, and a caller needs to
                // tell this apart from "wrong password". The desktop maps an ordinary open failure
                // to a single opaque "wrong password" — which is the point, since "no such
                // compartment" and "wrong password" must be the same answer — but doing that to a
                // LOCK conflict would report the most misleading string possible for a condition
                // that has nothing to do with the password.
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "this container is already open in another session ({}) — close it there \
                         first; two writers over one container can destroy every compartment in it",
                        io::Error::last_os_error()
                    ),
                ));
            }
            Ok(Some(f))
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Ok(None)
        }
    }

    /// Create a fresh container of exactly `total` bytes, entirely random, with the main
    /// account's P1 (protect) password installed. `main_cap` (bytes, the "A" reserve) is
    /// the protect-mode write ceiling for the main region. The tail after the main region
    /// is reserved for a future hidden compartment (indistinguishable random until then).
    pub fn create(path: &Path, total: u64, main_password: &[u8], main_cap: u64) -> io::Result<Self> {
        // A3-9: refuse BEFORE the allocation, so an absurd size costs nothing rather than OOMing
        // on the way to finding out. Checked on `u64` — casting first would wrap on 32-bit.
        if total > MAX_CONTAINER_BYTES {
            // `OutOfMemory` for the same reason the lock uses `WouldBlock`: this is not a password
            // failure and must not be reported as one.
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!(
                    "container size {total} bytes exceeds the {MAX_CONTAINER_BYTES}-byte maximum — \
                     the whole file is held in RAM and a save buffers the compartment's snapshot \
                     and ciphertext on top of it (peak ≈ 2× the container size)"
                ),
            ));
        }
        let total = total as usize;
        if total < DATA_OFF + MIN_REGION_CAP {
            return Err(io_err("container size too small"));
        }
        let main_cap = main_cap as usize;
        if main_cap < MIN_REGION_CAP || DATA_OFF + main_cap > total {
            return Err(io_err("main_cap out of range for this container size"));
        }
        let mut buf = random_bytes(total); // salt prefix + all slots + dir + all regions start random
        let main_off = DATA_OFF;
        let region_key = random_key();
        let mut c = Container {
            path: path.to_path_buf(),
            buf: std::mem::take(&mut buf),
            lock: None,
        };
        // Seal an empty payload so a fresh main region reads back as empty (not garbage).
        Self::write_region_at(&mut c.buf, main_off, main_cap, main_cap, &region_key, &[])?;
        c.seal_slot(0, Role::Main, Policy::Protect, main_password, main_off as u64, main_cap as u64, &region_key)?;
        let mgmt = c.key_for(main_password)?;
        c.write_dir(&mgmt, &[0])?; // slot 0 is the management/main slot
        // `persist` takes the lock on the file it just laid down (A3-8): there is nothing to lock
        // before that, since the file does not exist yet. Two processes racing to CREATE the same
        // path is therefore still last-writer-wins — an unavoidable window at this one call, and a
        // harmless one: neither container has any account in it yet.
        c.persist()?;
        Ok(c)
    }

    /// Load an existing container file into memory, taking the exclusive lock first (A3-8).
    pub fn load(path: &Path) -> io::Result<Self> {
        // Lock BEFORE touching anything: the stale-tmp cleanup below is only safe once we know no
        // other session is mid-save, and the read below is only meaningful if nobody can rewrite
        // the file under us afterwards.
        let lock = Self::lock_file(path)?;
        // A3-9: stat, don't read, to find out a file is too big — the point is to refuse without
        // ever allocating for it.
        let len = std::fs::metadata(path)?.len();
        if len > MAX_CONTAINER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!(
                    "container file is {len} bytes, over the {MAX_CONTAINER_BYTES}-byte maximum \
                     this build will hold in memory — refusing to read it"
                ),
            ));
        }
        // A crash mid-persist can leave a full-size `.tmp` copy (harmless — also random — but tidy
        // it so there aren't two container-shaped blobs lying around). Safe to delete only because
        // we hold the lock: without it this was deleting other processes' in-flight saves (A3-8).
        let _ = std::fs::remove_file(path.with_extension("tmp"));
        let buf = std::fs::read(path)?;
        if buf.len() < HEADER_LEN + LEN_HDR {
            return Err(io_err("not a container (too small)"));
        }
        Ok(Container {
            path: path.to_path_buf(),
            buf,
            lock,
        })
    }

    fn key_for(&self, password: &[u8]) -> io::Result<MasterKey> {
        MasterKey::derive(password, self.salt()).map_err(io_err)
    }

    /// Trial-open every slot with this password; return the first that authenticates.
    fn find_slot(&self, key: &MasterKey) -> Option<SlotInfo> {
        for i in 0..SLOT_COUNT {
            let (a, b) = Self::slot_span(i);
            let Ok(plain) = key.open_raw(SLOT_LABEL, &self.buf[a..b]) else {
                continue;
            };
            if plain.len() != SLOT_PLAIN {
                continue;
            }
            let role = Role::from_byte(plain[0])?;
            let policy = Policy::from_byte(plain[1]);
            let region_off = u64::from_le_bytes(plain[2..10].try_into().ok()?);
            let region_cap = u64::from_le_bytes(plain[10..18].try_into().ok()?);
            let region_key = MasterKey::from_bytes(plain[18..50].try_into().ok()?);
            return Some(SlotInfo {
                role,
                policy,
                region_off,
                region_cap,
                region_key,
            });
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_slot(
        &mut self,
        index: usize,
        role: Role,
        policy: Policy,
        password: &[u8],
        region_off: u64,
        region_cap: u64,
        region_key: &MasterKey,
    ) -> io::Result<()> {
        let key = self.key_for(password)?;
        let mut plain = Vec::with_capacity(SLOT_PLAIN);
        plain.push(role.to_byte());
        plain.push(policy.to_byte());
        plain.extend_from_slice(&region_off.to_le_bytes());
        plain.extend_from_slice(&region_cap.to_le_bytes());
        plain.extend_from_slice(&region_key.as_bytes());
        let sealed = key.seal_raw(SLOT_LABEL, &plain);
        debug_assert_eq!(sealed.len(), SLOT_LEN);
        let (a, b) = Self::slot_span(index);
        self.buf[a..b].copy_from_slice(&sealed);
        Ok(())
    }

    /// Marks the directory entry of the ONE hidden slot. The directory is sealed under the
    /// MANAGEMENT (P1) key — a cover password cannot read it (pinned by
    /// `p3_reveal_does_not_expose_the_slot_directory`) — so recording this does not weaken the
    /// property that revealing P3 cannot prove P1/P2 exist. It exists so `add_hidden` can refuse
    /// to clobber an existing hidden region (A3-1); the region bytes themselves stay
    /// indistinguishable from random, which is exactly why the container cannot detect it any
    /// other way.
    const HIDDEN_FLAG: u8 = 0x80;

    /// Read the used-slot list (sealed under the management key). `Err` = wrong key.
    fn read_dir(&self, mgmt_key: &MasterKey) -> io::Result<Vec<usize>> {
        Ok(self.read_dir_entries(mgmt_key)?.into_iter().map(|(idx, _)| idx).collect())
    }

    /// The used slots with their hidden marker: `(slot index, is_hidden)`.
    fn read_dir_entries(&self, mgmt_key: &MasterKey) -> io::Result<Vec<(usize, bool)>> {
        let plain = mgmt_key
            .open_raw(DIR_LABEL, &self.buf[DIR_OFF..DIR_OFF + DIR_LEN])
            .map_err(|_| io_err("wrong management password"))?;
        Ok(plain
            .iter()
            .filter(|&&b| ((b & !Self::HIDDEN_FLAG) as usize) < SLOT_COUNT)
            .map(|&b| ((b & !Self::HIDDEN_FLAG) as usize, b & Self::HIDDEN_FLAG != 0))
            .collect())
    }

    /// Which slot (if any) holds the hidden account.
    fn hidden_slot(&self, mgmt_key: &MasterKey) -> io::Result<Option<usize>> {
        Ok(self.read_dir_entries(mgmt_key)?.into_iter().find(|&(_, h)| h).map(|(idx, _)| idx))
    }

    /// Seal the used-slot list under the management key. Unused entries are 0xFF.
    /// `hidden` names the slot to tag with [`Self::HIDDEN_FLAG`], if any.
    fn write_dir_marked(
        &mut self,
        mgmt_key: &MasterKey,
        used: &[usize],
        hidden: Option<usize>,
    ) -> io::Result<()> {
        let mut plain = [0xFFu8; SLOT_COUNT];
        for (i, &idx) in used.iter().take(SLOT_COUNT).enumerate() {
            plain[i] = idx as u8 | if hidden == Some(idx) { Self::HIDDEN_FLAG } else { 0 };
        }
        let sealed = mgmt_key.seal_raw(DIR_LABEL, &plain);
        debug_assert_eq!(sealed.len(), DIR_LEN);
        self.buf[DIR_OFF..DIR_OFF + DIR_LEN].copy_from_slice(&sealed);
        Ok(())
    }

    /// Seal the used-slot list, preserving whichever slot is already tagged hidden.
    fn write_dir(&mut self, mgmt_key: &MasterKey, used: &[usize]) -> io::Result<()> {
        let hidden = self.hidden_slot(mgmt_key).unwrap_or(None);
        self.write_dir_marked(mgmt_key, used, hidden)
    }

    /// A free slot index not in the management directory. Random start → no order signal.
    fn free_slot(&self, used: &[usize]) -> Option<usize> {
        let start = (random_bytes(1)[0] as usize) % SLOT_COUNT;
        (0..SLOT_COUNT)
            .map(|k| (start + k) % SLOT_COUNT)
            .find(|i| !used.contains(i))
    }

    /// Add the P3 (cover) alias for the main account: give an existing main password to
    /// learn the shared region key, then seal a new slot with the SAME region and the SAME
    /// `region_cap` (CRYPTO-13: `region_cap` is the ping-pong GEOMETRY of the region — where its
    /// two copy slots live — and P1/P3 write the same physical bytes, so they must agree on it
    /// byte-for-byte).
    ///
    /// **CRYPTO-10 retraction.** P3 used to be sealed `Policy::Blind`, which `write_limits` gave a
    /// wider ceiling than P1's `Policy::Protect` — the ONLY purpose of the distinction. That made
    /// the write ceiling itself a coercer-visible proof that a second password existed (see the
    /// module doc). P3 is now sealed with the IDENTICAL `Policy::Protect` byte P1 gets, so it is
    /// not merely unreadable to a coercer (the mgmt-directory property below already gave us that)
    /// but behaviourally indistinguishable too. `blind_cap` is kept as a caller-checked parameter
    /// even though it no longer changes any write permission — it is what
    /// `ContainerVault::add_blind` already computes as "the rest of the container after the main
    /// region," and keeping the check catches a caller whose understanding of the region geometry
    /// has drifted, rather than silently accepting whatever it happens to compute.
    pub fn add_blind_main(&mut self, existing_main_password: &[u8], p3_password: &[u8], blind_cap: u64) -> io::Result<()> {
        let key = self.key_for(existing_main_password)?;
        let info = self.find_slot(&key).ok_or_else(|| io_err("wrong main password"))?;
        if info.role != Role::Main {
            return Err(io_err("not a main password"));
        }
        let derived_ceiling = self.buf.len() as u64 - info.region_off;
        if blind_cap != derived_ceiling {
            return Err(io_err("blind_cap must equal the remaining container space after the main region"));
        }
        let p3key = self.key_for(p3_password)?;
        if self.find_slot(&p3key).is_some() {
            return Err(io_err("that password is already in use"));
        }
        let mut used = self.read_dir(&key)?;
        let idx = self.free_slot(&used).ok_or_else(|| io_err("no free slot"))?;
        // CRYPTO-10: `Policy::Protect`, NOT a distinct `Blind` value — see the doc above.
        self.seal_slot(idx, Role::Main, Policy::Protect, p3_password, info.region_off, info.region_cap, &info.region_key)?;
        used.push(idx);
        self.write_dir(&key, &used)?;
        self.persist()
    }

    /// Install the hidden account (P2) in the tail after the main region. Fresh region
    /// key + empty payload. Refuses a password already in use (would collide a slot). Returns the
    /// hidden region's key so the caller can seal the hidden account's files under it.
    pub fn add_hidden(&mut self, main_password: &[u8], hidden_password: &[u8], hidden_cap: u64) -> io::Result<MasterKey> {
        let mkey = self.key_for(main_password)?;
        let main = self.find_slot(&mkey).ok_or_else(|| io_err("wrong main password"))?;
        let hidden_off = main.region_off + main.region_cap;
        let hidden_cap = hidden_cap as usize;
        if hidden_cap < MIN_REGION_CAP || hidden_off as usize + hidden_cap > self.buf.len() {
            return Err(io_err("hidden region does not fit after the main region"));
        }
        let hkey = self.key_for(hidden_password)?;
        if self.find_slot(&hkey).is_some() {
            return Err(io_err("that password is already in use"));
        }
        // Refuse a SECOND hidden account. `hidden_off` is fixed, so a second call used to write a
        // fresh empty region right on top of the existing one under a new key — silently and
        // irreversibly destroying the first hidden account while its slot still pointed there with
        // the now-useless old key (A3-1). The region bytes are indistinguishable from random by
        // design, so the marker in the P1-sealed directory is the only way to know.
        if self.hidden_slot(&mkey)?.is_some() {
            return Err(io_err("this container already holds a hidden account"));
        }
        let region_key = random_key();
        Self::write_region_at(&mut self.buf, hidden_off as usize, hidden_cap, hidden_cap, &region_key, &[])?;
        let mut used = self.read_dir(&mkey)?;
        let idx = self.free_slot(&used).ok_or_else(|| io_err("no free slot"))?;
        self.seal_slot(idx, Role::Hidden, Policy::None, hidden_password, hidden_off, hidden_cap as u64, &region_key)?;
        used.push(idx);
        self.write_dir_marked(&mkey, &used, Some(idx))?;
        self.persist()?;
        Ok(region_key)
    }

    /// Install a duress/wipe password (no region — entering it means "erase everything").
    pub fn add_wipe(&mut self, main_password: &[u8], wipe_password: &[u8]) -> io::Result<()> {
        let mkey = self.key_for(main_password)?;
        self.find_slot(&mkey).ok_or_else(|| io_err("wrong main password"))?;
        let wkey = self.key_for(wipe_password)?;
        if self.find_slot(&wkey).is_some() {
            return Err(io_err("that password is already in use"));
        }
        let dummy = MasterKey::from_bytes([0u8; 32]);
        let mut used = self.read_dir(&mkey)?;
        let idx = self.free_slot(&used).ok_or_else(|| io_err("no free slot"))?;
        self.seal_slot(idx, Role::Wipe, Policy::None, wipe_password, 0, 0, &dummy)?;
        used.push(idx);
        self.write_dir(&mkey, &used)?;
        self.persist()
    }

    /// Open with a password. Wrong password / absent compartment → `Err` (indistinguishable).
    pub fn open(&self, password: &[u8]) -> io::Result<Opened> {
        let key = self.key_for(password)?;
        let info = self
            .find_slot(&key)
            .ok_or_else(|| io_err("wrong password or no such compartment"))?;
        if info.role == Role::Wipe {
            return Ok(Opened::Wipe);
        }
        let payload = Self::read_region_at(&self.buf, info.region_off as usize, info.region_cap as usize, &info.region_key)?;
        Ok(Opened::Compartment {
            role: info.role,
            policy: info.policy,
            payload,
            region_key: info.region_key,
        })
    }

    /// Write the account-state payload for the compartment this password opens. Honors the
    /// slot's write ceiling: EVERY Main write — P1 or P3 alike, since CRYPTO-10 — refuses to
    /// exceed HALF its cap (CRYPTO-13 — that half is exactly the atomic ping-pong budget; a
    /// payload bigger than that has nowhere safe to land and must be refused loudly, never
    /// silently handed to the non-atomic spill path). Neither can reach the hidden tail through an
    /// ordinary write anymore.
    ///
    /// `region_cap` here is the ping-pong GEOMETRY (identical for P1 and P3, see
    /// `add_blind_main`), and — post CRYPTO-10 — it is now also the write PERMISSION for every
    /// Main slot: `write_limits` no longer branches on `Policy` at all, so `hard_cap` and
    /// `region_cap` are always equal here and `write_region_at`'s non-atomic spill branch is
    /// unreachable from this call site (it remains a general primitive, still exercised directly
    /// by tests, see CRYPTO-14's tests below). The ceiling MUST match `write_region_at`'s safe-path
    /// boundary (`region_cap / 2`) exactly — checking against the full `region_cap` instead (an
    /// earlier version of this fix did exactly that) let a completely ordinary save in the
    /// `(region_cap/2, region_cap]` band silently fall through to the spill branch: no atomicity,
    /// no error, the same brick CRYPTO-13 exists to prevent, just moved to happen only sometimes
    /// instead of always.
    pub fn write(&mut self, password: &[u8], payload: &[u8]) -> io::Result<()> {
        let key = self.key_for(password)?;
        let info = self
            .find_slot(&key)
            .ok_or_else(|| io_err("wrong password or no such compartment"))?;
        if info.role == Role::Wipe {
            return Err(io_err("wipe password cannot write"));
        }
        let need = COPY_HDR_LEN + 24 + payload.len() + 16;
        let (hard_cap, ceiling) = Self::write_limits(&info);
        if need > ceiling as usize {
            return Err(io_err("payload exceeds the write ceiling for this password"));
        }
        let off = info.region_off as usize;
        let (touched_off, touched_len) = Self::write_region_at(
            &mut self.buf,
            off,
            info.region_cap as usize,
            hard_cap as usize,
            &info.region_key,
            payload,
        )?;
        // Hot path (called on every message save): write ONLY the touched copy slot's bytes in
        // place, so a 10 GB container doesn't get fully rewritten per save. Other regions —
        // including the hidden tail, now unreachable from ANY Main write, and this region's OTHER
        // copy slot (CRYPTO-13) — are untouched on disk.
        self.persist_range(touched_off, touched_len)
    }

    /// `(hard_cap, ceiling)` for `info` — pulled out so `max_payload_len` (SEC-35, below) computes
    /// the SAME number `write` itself checks against, instead of drifting out of sync with a
    /// second copy of this arithmetic.
    ///
    /// **CRYPTO-10 — no longer branches on `Policy`.** This used to give `Policy::Blind` a wider
    /// ceiling (the whole rest of the container) than `Policy::Protect` (half the region's
    /// ping-pong geometry) — that was the ONLY behavioural difference between P1 and P3, and it
    /// was a coercer-visible one: see the module doc's CRYPTO-10 section for why a distinguishable
    /// write ceiling is itself proof a duress setup exists. Every Main slot now gets the identical
    /// ceiling unconditionally.
    fn write_limits(info: &SlotInfo) -> (u64, u64) {
        (info.region_cap, info.region_cap / 2)
    }

    /// The largest payload `write` will accept for `password`'s compartment RIGHT NOW.
    ///
    /// **SEC-35.** Exists so a caller building a payload (`ContainerVault::save`, via
    /// `snapshot_dir`) can pass this as the budget and be refused loudly BEFORE it finishes
    /// reading a doomed multi-gigabyte account tree into memory, instead of building the whole
    /// thing first and only THEN discovering `write` will reject it — by which point the memory
    /// is already spent. Uses the exact same `write_limits` arithmetic `write` itself checks
    /// against, so the two can never disagree about what fits: a value this function approves is
    /// guaranteed to pass `write`'s own check (same `need > ceiling` shape, same overhead
    /// constants), and vice versa.
    pub fn max_payload_len(&self, password: &[u8]) -> io::Result<usize> {
        let key = self.key_for(password)?;
        let info = self
            .find_slot(&key)
            .ok_or_else(|| io_err("wrong password or no such compartment"))?;
        if info.role == Role::Wipe {
            return Err(io_err("wipe password cannot write"));
        }
        let (_, ceiling) = Self::write_limits(&info);
        // Inverse of `write`'s `need = COPY_HDR_LEN + 24 + payload.len() + 16 <= ceiling`.
        let overhead = (COPY_HDR_LEN + 24 + 16) as u64;
        Ok(ceiling.saturating_sub(overhead) as usize)
    }

    // ---- region primitives (format (b): two ping-pong copy slots, length+generation hidden) ----
    //
    // CRYPTO-13: `atomic_cap` splits `[off, off+atomic_cap)` into two equal copy slots (0 at
    // `off`, 1 at `off + atomic_cap/2`); a write always targets whichever slot is NOT the current
    // newest, so the other slot — a complete earlier save — is never touched by this write and
    // survives a crash mid-write untouched. `hard_cap` (>= atomic_cap) is the parameter that widens
    // the write PERMISSION past the safe geometry, taking the non-atomic SPILL PATH below — a
    // capability this function still offers as a general primitive (and CRYPTO-14's tests below
    // still exercise it directly), but which CRYPTO-10 made unreachable from `Container::write`:
    // every caller through the public API now passes `hard_cap == atomic_cap`, because Blind no
    // longer gets a wider ceiling than Protect (see the module doc's CRYPTO-10 section for why —
    // the ceiling difference was itself a coercer-visible tell). A spill, if ever reached, writes
    // directly at `off` — genuinely NOT atomic, and stomps the whole ping-pong pair and whatever
    // comes after in the container; nothing in the live code paths can trigger that anymore.

    /// One copy slot's header: `(generation, ciphertext length)`, or `Err` if this slot doesn't
    /// authenticate (absent, torn by a crash, or plain random padding — all the same to us).
    fn read_copy_header(buf: &[u8], off: usize, region_key: &MasterKey) -> io::Result<(u64, usize)> {
        if off + COPY_HDR_LEN > buf.len() {
            return Err(io_err("copy header out of bounds"));
        }
        let plain = region_key
            .open_raw(LEN_LABEL, &buf[off..off + COPY_HDR_LEN])
            .map_err(|_| io_err("copy header corrupt / wrong key"))?;
        if plain.len() != COPY_HDR_PLAIN {
            return Err(io_err("bad copy header"));
        }
        let gen = u64::from_le_bytes(plain[0..8].try_into().unwrap());
        let ct_len = u64::from_le_bytes(plain[8..16].try_into().unwrap()) as usize;
        Ok((gen, ct_len))
    }

    /// A copy slot's header AND body, decrypted. `Err` if either half fails to authenticate.
    fn read_copy(buf: &[u8], off: usize, region_key: &MasterKey) -> io::Result<(u64, Vec<u8>)> {
        let (gen, ct_len) = Self::read_copy_header(buf, off, region_key)?;
        let start = off + COPY_HDR_LEN;
        if start + ct_len > buf.len() {
            return Err(io_err("copy payload out of bounds (corrupt?)"));
        }
        let payload = region_key
            .open_raw(BODY_LABEL, &buf[start..start + ct_len])
            .map_err(|_| io_err("copy payload corrupt / wrong key"))?;
        Ok((gen, payload))
    }

    /// Returns `(touched_off, touched_len)` — the byte range that actually changed, so the
    /// caller persists ONLY that slice (never the untouched copy — that's the whole point).
    fn write_region_at(
        buf: &mut [u8],
        off: usize,
        atomic_cap: usize,
        hard_cap: usize,
        region_key: &MasterKey,
        payload: &[u8],
    ) -> io::Result<(usize, usize)> {
        let ct = region_key.seal_raw(BODY_LABEL, payload);
        let half = atomic_cap / 2;
        if COPY_HDR_LEN + ct.len() <= half {
            // SAFE PATH: alternate copy slots, never touching whichever one is currently newest.
            let slot0 = Self::read_copy_header(buf, off, region_key).ok();
            let slot1 = if half > 0 {
                Self::read_copy_header(buf, off + half, region_key).ok()
            } else {
                None
            };
            let (target, new_gen) = match (slot0, slot1) {
                (None, None) => (0, 1), // brand-new region: bootstrap into slot 0
                (Some((g0, _)), None) => (1, g0 + 1),
                (None, Some((g1, _))) => (0, g1 + 1),
                // A tie can't legitimately happen (generations are unique), but if it ever did,
                // never pick the slot we're reading as "current" to write into itself.
                (Some((g0, _)), Some((g1, _))) => {
                    if g0 >= g1 {
                        (1, g0 + 1)
                    } else {
                        (0, g1 + 1)
                    }
                }
            };
            let toff = off + target * half;
            Self::write_copy_at(buf, toff, new_gen, region_key, &ct)?;
            Ok((toff, COPY_HDR_LEN + ct.len()))
        } else if hard_cap > atomic_cap && COPY_HDR_LEN + ct.len() <= hard_cap {
            // SPILL PATH — reachable ONLY when the caller's write permission (`hard_cap`) is
            // WIDER than the ping-pong geometry (`atomic_cap`). Since CRYPTO-10, `Container::write`
            // NEVER constructs such a call (Protect, Hidden, and now Blind too all call this with
            // `hard_cap == atomic_cap` — see `write_limits`): the whole reason Blind used to be
            // wider (a coercer-visible write-ceiling difference from Protect) was itself the
            // CRYPTO-10 tell, so that permission was removed. This branch remains a general
            // capability of the primitive (still exercised directly by CRYPTO-14's tests below,
            // which construct a wide `hard_cap` by hand to pin what a spill would do IF one ever
            // reached here) and a defensive fallback — a caller bug upstream must not silently
            // degrade into an unwitnessed non-atomic write, so an out-of-band `hard_cap` still
            // takes this explicit, still-non-atomic path rather than falling through to the
            // capacity error below. Writes directly at `off`, which — since it's bigger than one
            // copy slot — necessarily overwrites BOTH ping-pong slots and, past `atomic_cap`,
            // whatever comes after in the container.
            let gen = [Self::read_copy_header(buf, off, region_key).ok(), {
                if half > 0 {
                    Self::read_copy_header(buf, off + half, region_key).ok()
                } else {
                    None
                }
            }]
            .into_iter()
            .flatten()
            .map(|(g, _)| g)
            .max()
            .unwrap_or(0)
                + 1;
            Self::write_copy_at(buf, off, gen, region_key, &ct)?;
            Ok((off, COPY_HDR_LEN + ct.len()))
        } else {
            Err(io_err("payload exceeds region capacity"))
        }
    }

    /// Seal `(gen, ct.len())` as the copy header at `toff`, then the ciphertext right after it.
    fn write_copy_at(buf: &mut [u8], toff: usize, gen: u64, region_key: &MasterKey, ct: &[u8]) -> io::Result<()> {
        if toff + COPY_HDR_LEN + ct.len() > buf.len() {
            return Err(io_err("region write out of bounds"));
        }
        let mut hdr_plain = Vec::with_capacity(COPY_HDR_PLAIN);
        hdr_plain.extend_from_slice(&gen.to_le_bytes());
        hdr_plain.extend_from_slice(&(ct.len() as u64).to_le_bytes());
        let hdr = region_key.seal_raw(LEN_LABEL, &hdr_plain);
        debug_assert_eq!(hdr.len(), COPY_HDR_LEN);
        // The header write and the body write below are each one contiguous byte range, but
        // together they are still a single non-atomic in-place update — the crash-safety this
        // buys comes from NEVER touching the region's OTHER copy slot in the same call, not from
        // these two lines being atomic with each other.
        buf[toff..toff + COPY_HDR_LEN].copy_from_slice(&hdr);
        buf[toff + COPY_HDR_LEN..toff + COPY_HDR_LEN + ct.len()].copy_from_slice(ct);
        Ok(())
    }

    fn read_region_at(buf: &[u8], off: usize, atomic_cap: usize, region_key: &MasterKey) -> io::Result<Vec<u8>> {
        let half = atomic_cap / 2;
        let c0 = Self::read_copy(buf, off, region_key).ok();
        let c1 = if half > 0 {
            Self::read_copy(buf, off + half, region_key).ok()
        } else {
            None
        };
        match (c0, c1) {
            (None, None) => Err(io_err("region payload corrupt / wrong key")),
            (Some((_, p)), None) => Ok(p),
            (None, Some((_, p))) => Ok(p),
            (Some((g0, p0)), Some((g1, p1))) => Ok(if g0 >= g1 { p0 } else { p1 }),
        }
    }

    // ---- append-only log within a region (the "chunks" model: a new entry writes ONE small
    //      chunk + a tiny superblock, never re-encrypting older entries) ----
    //
    //   [superblock: seal(u64 high-water)][chunk0][chunk1]…[leftover random]
    //   each chunk = [seal(u64 ciphertext-len)][sealed payload]
    //
    // The high-water mark (where valid data ends) lives inside the sealed superblock, so an
    // observer sees only "sealed data up to some point, random after" — length stays hidden.

    // NOTE: the append-log primitives below are the Phase-2 storage mechanism (a region will hold
    // a small mutable core + this append-log for history). They are exercised by tests now and get
    // wired into the region model in a later Phase-2 slice, hence `dead_code` until then.
    //
    // CRYPTO-13 follow-up (NOT fixed here — this code isn't on the live path yet): the superblock
    // has the exact same single-point-of-failure as the region length header did. It is a single
    // sealed blob, re-sealed on every append; a torn write to it fails AEAD and `log_read` can't
    // get past it, losing ALL history in the log — not just the newest append. When this gets
    // wired in, it needs the same two-copy treatment as `write_region_at`/`read_region_at` above.

    /// Read the u64 sealed at `[off, off+LEN_HDR)` under `key`.
    #[allow(dead_code)]
    fn read_sealed_u64(buf: &[u8], off: usize, key: &MasterKey) -> io::Result<u64> {
        if off + LEN_HDR > buf.len() {
            return Err(io_err("sealed u64 out of bounds"));
        }
        let b = key.open_raw(LEN_LABEL, &buf[off..off + LEN_HDR]).map_err(|_| io_err("wrong key / corrupt"))?;
        if b.len() != 8 {
            return Err(io_err("bad sealed u64"));
        }
        Ok(u64::from_le_bytes(b.as_slice().try_into().unwrap()))
    }

    #[allow(dead_code)]
    fn write_sealed_u64(buf: &mut [u8], off: usize, key: &MasterKey, v: u64) {
        let sealed = key.seal_raw(LEN_LABEL, &v.to_le_bytes());
        debug_assert_eq!(sealed.len(), LEN_HDR);
        buf[off..off + LEN_HDR].copy_from_slice(&sealed);
    }

    /// Initialise an empty append-log at `off` (superblock high-water = 0).
    #[allow(dead_code)]
    fn log_init(buf: &mut [u8], off: usize, key: &MasterKey) {
        Self::write_sealed_u64(buf, off, key, 0);
    }

    /// Append one entry: seals it as a new chunk at the high-water mark and bumps the
    /// superblock. Only the new chunk bytes + the tiny superblock change — older chunks are
    /// never touched. Returns `Err` if the log region is full.
    #[allow(dead_code)]
    fn log_append(buf: &mut [u8], off: usize, cap: usize, key: &MasterKey, payload: &[u8]) -> io::Result<()> {
        let hw = Self::read_sealed_u64(buf, off, key)? as usize;
        let chunk_area = off + LEN_HDR; // superblock occupies the first LEN_HDR bytes
        let pos = chunk_area + hw;
        let ct = key.seal_raw(BODY_LABEL, payload);
        let lh = key.seal_raw(LEN_LABEL, &(ct.len() as u64).to_le_bytes());
        let end = pos + LEN_HDR + ct.len();
        if end > off + cap {
            return Err(io_err("append-log region full"));
        }
        buf[pos..pos + LEN_HDR].copy_from_slice(&lh);
        buf[pos + LEN_HDR..end].copy_from_slice(&ct);
        Self::write_sealed_u64(buf, off, key, (hw + LEN_HDR + ct.len()) as u64);
        Ok(())
    }

    /// Read every appended entry in order.
    #[allow(dead_code)]
    fn log_read(buf: &[u8], off: usize, key: &MasterKey) -> io::Result<Vec<Vec<u8>>> {
        let hw = Self::read_sealed_u64(buf, off, key)? as usize;
        let chunk_area = off + LEN_HDR;
        let mut out = Vec::new();
        let mut p = 0usize;
        while p < hw {
            let lh_off = chunk_area + p;
            let ct_len = Self::read_sealed_u64(buf, lh_off, key)? as usize;
            let cstart = lh_off + LEN_HDR;
            if cstart + ct_len > chunk_area + hw {
                return Err(io_err("append-log chunk out of bounds (corrupt?)"));
            }
            let payload = key
                .open_raw(BODY_LABEL, &buf[cstart..cstart + ct_len])
                .map_err(|_| io_err("append-log chunk corrupt / wrong key"))?;
            out.push(payload);
            p += LEN_HDR + ct_len;
        }
        Ok(out)
    }

    /// Crash-safe persist: write the whole buffer to a temp file, fsync, atomically rename.
    /// Untouched regions (e.g. the hidden tail during a Protect-mode main write) are copied
    /// byte-for-byte, so this never perturbs another compartment.
    ///
    /// **A3-8 — the rename replaces the inode our lock is on, so the lock is re-taken here.** The
    /// alternative (writing the whole buffer in place, keeping one inode and one lock forever) would
    /// hold the lock without a gap but would give up the crash-atomicity that this path exists for:
    /// `add_hidden`/`add_blind_main`/`add_wipe` change the slot table and directory, and a torn
    /// in-place write over those would corrupt bytes the ping-pong copy slots do not protect. So the
    /// swap stays, and the microsecond between `rename` and re-locking is a real, named window: if
    /// another process takes the lock inside it, the re-lock FAILS and this call reports an error
    /// even though the bytes are safely on disk — deliberately, because continuing would mean two
    /// live images of one container, which is the whole class this lock exists to kill. The caller's
    /// correct response is to reopen, not to retry the save.
    fn persist(&mut self) -> io::Result<()> {
        self.persist_bytes()?;
        // Drop the old inode's lock BEFORE asking for the new one: `flock` is per open-file
        // description, so holding both is harmless, but releasing first keeps "how many locks does
        // this Container hold" answerable as exactly one.
        self.lock = None;
        self.lock = Self::lock_file(&self.path)?;
        Ok(())
    }

    /// The bytes half of `persist`, without re-taking the lock. Split out for `wipe`, which must
    /// NOT be able to report failure after it has already succeeded: a wipe that lost the relock
    /// race would return `Err` for a container it had just crypto-erased, and the desktop renders
    /// that as "wrong password" — telling a user under duress that their wipe password did not
    /// work, when it did.
    fn persist_bytes(&self) -> io::Result<()> {
        let tmp = self.path.with_extension("tmp");
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            f.write_all(&self.buf)?;
            f.sync_all()?;
        }
        // fsync the DIRECTORY too: without it a power loss can resurrect the old container even
        // though the write reported success — which for `wipe()` means a "destroyed" container
        // comes back (CRYPTO-12).
        crate::store::rename_durable(&tmp, &self.path)
    }

    /// Persist ONLY `buf[off..off+len]` in place (seek + write), for the hot region-write path
    /// where a whole-file rewrite would be ruinous at multi-GB sizes. Honest tradeoff: this is
    /// not crash-atomic — a crash mid-write can lose that single save (the region reads corrupt
    /// until the next successful save), the same "last write didn't finish" risk any app has.
    /// Structural changes (create/add_*/wipe) mostly still go through the crash-safe whole-file
    /// swap; `wipe` is the one exception, and only for the single small range described there.
    fn persist_range(&self, off: usize, len: usize) -> io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new().write(true).open(&self.path)?;
        f.seek(SeekFrom::Start(off as u64))?;
        f.write_all(&self.buf[off..off + len])?;
        f.sync_all()
    }

    /// The wipe password's effect: destroy the salt IN PLACE on the current inode first, then
    /// replace the whole buffer with fresh random, so every region and slot becomes unopenable and
    /// no password works afterwards.
    ///
    /// **CRYPTO-12/#184 — what changed and why.** Every key in this file — every slot's opening
    /// key, and transitively every region key those slots wrap — is `Argon2id(password, salt)` or
    /// derived from a slot only reachable via that key. The salt is therefore the ONE small value
    /// this whole file's confidentiality reduces to: an adversary who has the correct password but
    /// NOT the exact original salt bytes cannot rederive the key that sealed anything, full stop.
    /// It plays exactly the "independently erasable KEK" role the design note asked for — nothing
    /// new needs to be introduced, and introducing one would fail anyway (see the residual below).
    /// The bug this fixes: the OLD `wipe` only ever randomised the salt as part of a whole-buffer
    /// `persist()`, which writes a NEW file and renames over the old name — the previous inode
    /// (old salt included) is UNLINKED, not overwritten, so its blocks can survive in free space, a
    /// filesystem journal, or a snapshot and still show the TRUE original salt to whoever recovers
    /// them. This version overwrites JUST the salt's `SALT_LEN` bytes IN PLACE on the CURRENT,
    /// still-live inode via `persist_range` — a real `seek`+`write`+`fsync` to the existing file,
    /// not a new one — BEFORE doing anything else. `persist_range`'s own doc already states the
    /// tradeoff for hot writes (not crash-atomic); here that is exactly the point: even a crash
    /// immediately after this line leaves the vault already unopenable by ANY password (every slot
    /// now needs a salt that no longer exists anywhere), which is the wipe's entire purpose — there
    /// is no partially-wiped state where recovery is easier than fully-wiped. The general
    /// randomise-and-swap below still runs afterward, to also scrub the ciphertext bytes and keep
    /// the "looks like a container.dat" file present.
    ///
    /// **What this closes.** On an ordinary, non-CoW filesystem (ext4/xfs without snapshots, a
    /// plain disk image, most VM/container overlays) an in-place `pwrite` really does land on the
    /// same physical blocks: the moment step one's `fsync` returns, the true original salt is gone
    /// from every location that filesystem will ever report — a forensic image taken any time
    /// after the wipe recovers the same random salt this call just wrote, never the original. That
    /// is a genuine crypto-erase for that class of storage, which the old whole-file-swap-only
    /// version never provided (it left the WHOLE original inode, salt included, sitting in free
    /// space).
    ///
    /// **What this does NOT close (stated plainly, not papered over).** Two residuals remain, and
    /// neither can be fixed inside this file:
    /// - **Copy-on-write filesystems, wear-levelling SSDs, and snapshots.** An "in-place" `pwrite`
    ///   there does not guarantee the same physical medium gets overwritten — CoW allocates a new
    ///   block and frees the old one (recoverable from a prior generation/snapshot); an SSD's FTL
    ///   may remap the logical write to a different NAND cell and leave the old one queued for
    ///   erase. This is the same limit `docs/design/duress-multipassword.md`'s CRYPTO-12 note
    ///   already names for the OLD scheme, and no purely-in-file overwrite defeats it — verified,
    ///   not merely asserted, by checking there is no code path here that controls block placement.
    /// - **Any copy of `container.dat` taken BEFORE the wipe** (a backup, a cloud sync, a second
    ///   disk image) still has the true original salt sitting in plain sight inside that copy —
    ///   destroying the live file's salt cannot reach bytes that were never modified because they
    ///   are not IN this file anymore. Moving the salt to a small sidecar file would not help
    ///   either: it would put the "independently erasable" secret outside `container.dat`, but
    ///   `account_snapshot_round_trips_with_zero_external_artifacts` pins that a hidden account's
    ///   directory holds ONLY `container.dat` — a second file is a tell in its own right (and would
    ///   still be inside the SAME pre-wipe backup regardless). So the erasable root cannot leave
    ///   this file, which means it cannot be made safe against a pre-wipe copy from inside this
    ///   module at all: closing that gap needs the salt (or a KEK wrapping it) to live somewhere a
    ///   backup never reaches — an OS keyring or hardware keystore, exactly what the design note
    ///   already named as the real fix and what this module cannot provide by itself.
    pub fn wipe(&mut self) -> io::Result<()> {
        let fresh_salt = random_bytes(SALT_LEN);
        self.buf[..SALT_LEN].copy_from_slice(&fresh_salt);
        self.persist_range(0, SALT_LEN)?;
        // Randomise the buffer we already hold rather than allocating a second one of the same
        // size: this used to be `self.buf = random_bytes(len)`, which peaked at TWICE the container
        // size — on the one path most likely to be run under duress, in a hurry (A3-9).
        fill_random(&mut self.buf);
        self.persist_bytes()?;
        // Release the lock instead of re-taking it (`persist_bytes`, not `persist`): there is
        // nothing left in this file to protect from a second writer, and a failed relock must never
        // turn a COMPLETED wipe into an error the caller reports as failure.
        self.lock = None;
        Ok(())
    }
}

/// An account opened FROM a container: on open, the compartment's snapshot blob is materialized
/// into a working directory that the existing `Store`/`Vault` code can operate on unchanged; on
/// `save`, the working directory is snapshotted back into the container. This is the Phase-2
/// integration seam — the live app keeps using a directory, but that directory now lives inside the
/// deniable container.
///
/// For the HIDDEN account the caller MUST pass a RAM-backed `work_dir` (tmpfs) so no plaintext
/// files touch the real disk (§5 zero-external-artifacts); for visible accounts an ordinary temp
/// dir is fine. The password is held to re-seal on save and is zeroized on drop.
pub struct ContainerVault {
    container: Container,
    password: Vec<u8>,
    region_key: MasterKey,
    pub work_dir: PathBuf,
    pub role: Role,
    pub policy: Policy,
}

impl ContainerVault {
    /// Open the compartment for `password` and materialize it into `work_dir`.
    pub fn open(container_path: &Path, password: &[u8], work_dir: PathBuf) -> io::Result<Self> {
        let container = Container::load(container_path)?;
        match container.open(password)? {
            Opened::Compartment { role, policy, payload, region_key } => {
                // `restore_dir` owns the work dir end to end now (it CLEARS it first — A3-3), so
                // creating it here would be undone a line later; it creates what it needs.
                restore_dir(&work_dir, &payload)?;
                Ok(ContainerVault { container, password: password.to_vec(), region_key, work_dir, role, policy })
            }
            Opened::Wipe => Err(io_err("wipe password — caller must erase")),
        }
    }

    /// The account's at-rest key = the compartment's region key. P1 and P3 share it, so both decrypt
    /// the SAME main account; the hidden account gets its own. Not password-derived — that would make
    /// P1 and P3 (different passwords, same account) derive different, incompatible keys.
    pub fn account_key(&self) -> MasterKey {
        self.region_key.clone()
    }

    /// Snapshot the working directory back into the container (call after account changes).
    ///
    /// SEC-35: bounds `snapshot_dir` to this compartment's own usable write capacity, computed
    /// fresh from the live container geometry — a snapshot bigger than the region it has to fit
    /// into is already doomed, so `snapshot_dir` refuses it before buffering gigabytes that
    /// `write` would reject anyway, rather than after.
    pub fn save(&mut self) -> io::Result<()> {
        let max = self.container.max_payload_len(&self.password)?;
        let blob = snapshot_dir(&self.work_dir, max)?;
        self.container.write(&self.password, &blob)
    }

    /// Save, then release the session's plaintext work dir — in that order, and ONLY in that order.
    ///
    /// A HIDDEN account exists nowhere but its RAM work dir between saves, so deleting that dir
    /// after a FAILED save destroys everything since the last successful one. The lock path used
    /// to do exactly that (`let _ = cv.save(); remove_dir_all(work_dir)`), discarding the error
    /// and then the only copy (A3-6). Here a failed save propagates and the work dir is left
    /// untouched, so the caller can report it and the user can retry with their data still there.
    ///
    /// A main (disk-backed) account's work dir is never removed — it is the account's own storage.
    /// Takes `&mut self` rather than consuming, so a FAILED save leaves the caller still holding
    /// a fully usable session to retry with. On success the work dir is gone and the vault must
    /// be dropped.
    pub fn save_and_release(&mut self) -> io::Result<()> {
        self.save()?;
        if self.role == Role::Hidden {
            std::fs::remove_dir_all(&self.work_dir)?;
        }
        Ok(())
    }

    /// The container's random salt prefix — use it to derive the account's at-rest key, so that key
    /// has a PER-CONTAINER random salt (not a fixed, precomputation-friendly one shared across installs).
    pub fn salt(&self) -> Vec<u8> {
        self.container.salt().to_vec()
    }

    /// Add a HIDDEN account to this container, from an open MAIN session. Reuses the ONE held
    /// container instance (no two-writers-over-one-file hazard): places the hidden region in all
    /// space remaining after the main region, then calls `build(&region_key, max_payload_len)` —
    /// the caller builds the empty account's files sealed under the hidden region's key (so its
    /// own password opens them) and returns the snapshot, which is written into the hidden
    /// region. The caller wipes its RAM build.
    ///
    /// **SEC-35.** `build` gets the hidden slot's own `max_payload_len` handed to it (computed
    /// AFTER `Container::add_hidden` below creates the slot, so the number is real, not guessed)
    /// specifically so the caller has no reason to invent a number — passing `usize::MAX` into
    /// its own `snapshot_dir` call would quietly reopen the unbounded-RAM hole this fix closes,
    /// just on the hidden-account creation path instead of the main one.
    pub fn add_hidden<F>(&mut self, hidden_password: &[u8], build: F) -> io::Result<()>
    where
        F: FnOnce(&MasterKey, usize) -> io::Result<Vec<u8>>,
    {
        if self.role != Role::Main {
            return Err(io_err("a hidden account is added from the main session"));
        }
        let mkey = self.container.key_for(&self.password)?;
        let main = self
            .container
            .find_slot(&mkey)
            .ok_or_else(|| io_err("main slot not found"))?;
        let main_end = (main.region_off + main.region_cap) as usize;
        let hidden_cap = self
            .container
            .buf
            .len()
            .checked_sub(main_end)
            .ok_or_else(|| io_err("no room for a hidden region"))? as u64;
        let region_key = self.container.add_hidden(&self.password, hidden_password, hidden_cap)?;
        let max_payload_len = self.container.max_payload_len(hidden_password)?;
        let snapshot = build(&region_key, max_payload_len)?;
        self.container.write(hidden_password, &snapshot)
    }

    /// Add the P3 (blind-cover) password for THIS main account — a second password that opens the
    /// SAME account, but whose key CANNOT read the management directory, so it is the password that's
    /// safe to reveal under duress (revealing the main P1 would let a coercer enumerate the slots and
    /// detect the hidden account). Its write ceiling spans the whole container (it may overwrite the
    /// hidden tail — the accepted-risk masking behaviour).
    pub fn add_blind(&mut self, p3_password: &[u8]) -> io::Result<()> {
        if self.role != Role::Main {
            return Err(io_err("the cover password is added from the main session"));
        }
        let mkey = self.container.key_for(&self.password)?;
        let main = self.container.find_slot(&mkey).ok_or_else(|| io_err("main slot not found"))?;
        let blind_cap = self.container.buf.len() as u64 - main.region_off;
        self.container.add_blind_main(&self.password, p3_password, blind_cap)
    }

    /// Add a Wipe/duress password: entering it crypto-erases the WHOLE container.
    pub fn add_wipe(&mut self, wipe_password: &[u8]) -> io::Result<()> {
        if self.role != Role::Main {
            return Err(io_err("the wipe password is added from the main session"));
        }
        self.container.add_wipe(&self.password, wipe_password)
    }
}

impl Drop for ContainerVault {
    fn drop(&mut self) {
        // Best-effort: scrub the password from memory. (Full zeroize/mlock is a later hardening slice.)
        for b in self.password.iter_mut() {
            *b = 0;
        }
    }
}

/// Outcome of opening a container with a password — routed by the slot's role.
pub enum Unlocked {
    /// A wipe/duress password: the container has already been crypto-erased.
    Wiped,
    /// A main or hidden account, materialized into its work dir. Inspect `.role`.
    Account(ContainerVault),
}

/// Open a container and route by the password's role: a Wipe password erases the whole container
/// and reports `Wiped`; a HIDDEN account is materialized into `hidden_work`; a main account into
/// `main_work`. Wrong password / no such compartment → `Err` (indistinguishable).
///
/// `hidden_work` is an `Option` on purpose: `None` = "this system has no VERIFIED RAM-backed
/// store" (see [`ram_backed_hidden_dir`]). Opening a hidden account then FAILS CLOSED rather
/// than writing its plaintext to the real disk (CRYPTO-02). A MAIN account is unaffected — it is
/// disk-backed by design — so this never breaks ordinary use on a platform without tmpfs.
pub fn open_container(
    path: &Path,
    password: &[u8],
    main_work: PathBuf,
    hidden_work: Option<PathBuf>,
) -> io::Result<Unlocked> {
    let mut container = Container::load(path)?;
    match container.open(password)? {
        Opened::Wipe => {
            container.wipe()?;
            Ok(Unlocked::Wiped)
        }
        Opened::Compartment { role, policy, payload, region_key } => {
            // Fail CLOSED before anything is written: no verified RAM store ⇒ no hidden account.
            let work_dir = if role == Role::Hidden {
                hidden_work.ok_or_else(|| {
                    io_err(
                        "a hidden account needs a RAM-backed store (tmpfs); none is available on \
                         this system — refusing to materialize it on disk",
                    )
                })?
            } else {
                main_work
            };
            // As in `ContainerVault::open`: `restore_dir` clears and recreates the work dir itself.
            restore_dir(&work_dir, &payload)?;
            Ok(Unlocked::Account(ContainerVault {
                container,
                password: password.to_vec(),
                region_key,
                work_dir,
                role,
                policy,
            }))
        }
    }
}

/// A region laid out as a small mutable CORE (contacts / sessions / index — re-sealed in place
/// on change, cheap because it's small) followed by an append-only LOG (message history — a new
/// message appends one chunk, never re-encrypting the rest). This is the per-account storage the
/// live `Store` maps onto in Phase 2: the core is "what changes in place", the log is "what only
/// grows". Both live inside one keyed region and never disturb each other's bytes.
#[allow(dead_code)]
pub(crate) struct RegionStore {
    pub off: usize,
    pub cap: usize,
    pub core_cap: usize,
}

#[allow(dead_code)]
impl RegionStore {
    fn log_off(&self) -> usize {
        self.off + self.core_cap
    }
    fn log_cap(&self) -> usize {
        self.cap - self.core_cap
    }
    /// Lay out an empty region: empty core + empty log.
    fn init(&self, buf: &mut [u8], key: &MasterKey) -> io::Result<()> {
        Container::write_region_at(buf, self.off, self.core_cap, self.core_cap, key, &[])?;
        Container::log_init(buf, self.log_off(), key);
        Ok(())
    }
    /// Replace the mutable core (re-sealed in place; refuses to exceed `core_cap`). The core has
    /// no Blind-style dual-cap concept, so `atomic_cap == hard_cap == core_cap` (CRYPTO-13).
    fn write_core(&self, buf: &mut [u8], key: &MasterKey, blob: &[u8]) -> io::Result<()> {
        Container::write_region_at(buf, self.off, self.core_cap, self.core_cap, key, blob).map(|_| ())
    }
    fn read_core(&self, buf: &[u8], key: &MasterKey) -> io::Result<Vec<u8>> {
        Container::read_region_at(buf, self.off, self.core_cap, key)
    }
    /// Append one history entry (cheap — one chunk, older history untouched).
    fn append(&self, buf: &mut [u8], key: &MasterKey, chunk: &[u8]) -> io::Result<()> {
        Container::log_append(buf, self.log_off(), self.log_cap(), key, chunk)
    }
    fn read_log(&self, buf: &[u8], key: &MasterKey) -> io::Result<Vec<Vec<u8>>> {
        Container::log_read(buf, self.log_off(), key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        // A path INSIDE the swept root (#321), not the root itself: callers here treat what this
        // returns as the container FILE, and one caller creates a directory at it instead. Either
        // works only if the path does not exist yet, so the sweep-managed directory is the PARENT.
        node::scratch::dir_for_test(&format!("cont-{tag}")).join("container")
    }

    /// The headline system-wide test: three passwords, hidden account, deniability, and the
    /// P1-protects / P3-may-corrupt semantics — all on one indistinguishable-from-random file.
    #[test]
    fn three_password_container_is_deniable_and_correct() {
        let p = tmp("main");
        let _ = std::fs::remove_file(&p);

        let total = 256 * 1024;
        let main_cap = 96 * 1024; // "A"
        let hidden_cap = 96 * 1024; // "B"
        let mut c = Container::create(&p, total, b"realpw", main_cap as u64).unwrap();
        c.add_hidden(b"realpw", b"hiddenpw", hidden_cap as u64).unwrap();
        // blind_cap must be exactly "the rest of the container after the main region" (CRYPTO-13:
        // region_cap is now shared geometry, not a caller-chosen permission — see `add_blind_main`).
        c.add_blind_main(b"realpw", b"blindpw", total - DATA_OFF as u64).unwrap();
        c.add_wipe(b"realpw", b"burnpw").unwrap();

        // 1) The whole file is high-entropy: no 32-byte all-zero window, no KARST magic.
        let raw = std::fs::read(&p).unwrap();
        assert_eq!(raw.len() as u64, total);
        assert!(!raw.windows(32).any(|w| w.iter().all(|&b| b == 0)), "no zero runs");
        assert!(!raw.windows(4).any(|w| w == crate::secretbox::MAGIC), "no magic tell anywhere");

        // 2) P1 opens main+Protect; write via P1, read back exactly.
        c.write(b"realpw", b"MAIN account state v1").unwrap();
        match c.open(b"realpw").unwrap() {
            Opened::Compartment { role, policy, payload, .. } => {
                assert_eq!(role, Role::Main);
                assert_eq!(policy, Policy::Protect);
                assert_eq!(payload, b"MAIN account state v1");
            }
            _ => panic!("realpw must open the main compartment"),
        }

        // 3) P3 opens the SAME main account (same data). CRYPTO-10: the policy byte is now
        //    IDENTICAL to P1's — a distinct `Policy::Blind` used to exist here and gave P3 a wider
        //    write ceiling, which was itself a coercer-visible proof a second password existed.
        match c.open(b"blindpw").unwrap() {
            Opened::Compartment { role, policy, payload, .. } => {
                assert_eq!(role, Role::Main);
                assert_eq!(policy, Policy::Protect, "P3 must be behaviourally identical to P1, not a distinguishable Blind policy");
                assert_eq!(payload, b"MAIN account state v1", "P3 sees the same main data as P1");
            }
            _ => panic!("blindpw must open main"),
        }

        // 4) P2 opens the hidden account (empty), independent of main.
        c.write(b"hiddenpw", b"HIDDEN account state").unwrap();
        match c.open(b"hiddenpw").unwrap() {
            Opened::Compartment { role, payload, .. } => {
                assert_eq!(role, Role::Hidden);
                assert_eq!(payload, b"HIDDEN account state");
            }
            _ => panic!("hiddenpw must open the hidden compartment"),
        }

        // 5) Deniability: a wrong password is indistinguishable from "no compartment".
        assert!(c.open(b"nope").is_err());
        // Wipe password reports Wipe.
        assert!(matches!(c.open(b"burnpw").unwrap(), Opened::Wipe));

        // 6) Structural: all 8 slots are the same fixed length → the number of real
        //    passwords is not inferable from the header.
        assert_eq!(HEADER_LEN, SALT_LEN + SLOT_COUNT * SLOT_LEN);

        let _ = std::fs::remove_file(&p);
    }

    /// CRYPTO-10 retraction, replacing the old `protect_preserves_hidden_blind_may_corrupt`: P3
    /// (blind) used to be ALLOWED to spill past the main region and destroy the hidden tail as an
    /// "accepted risk" — this test used to pin that a big enough blind write corrupted hidden. It
    /// no longer can: Blind's write ceiling collapsed to the identical `region_cap / 2` Protect has
    /// always had (see the module doc's CRYPTO-10 section for why the DIFFERENCE, not the
    /// capability itself, was the coercer-visible bug). So both P1 and P3 now refuse the exact
    /// same oversized payload, and the hidden compartment survives EITHER one.
    #[test]
    fn neither_protect_nor_blind_can_reach_the_hidden_tail_anymore() {
        let p = tmp("spill");
        let _ = std::fs::remove_file(&p);
        let total = 256 * 1024;
        let main_cap = 64 * 1024;
        let hidden_cap = 160 * 1024;
        let mut c = Container::create(&p, total, b"realpw", main_cap as u64).unwrap();
        c.add_hidden(b"realpw", b"hiddenpw", hidden_cap as u64).unwrap();
        c.add_blind_main(b"realpw", b"blindpw", total - DATA_OFF as u64).unwrap();
        c.write(b"hiddenpw", b"the launch codes").unwrap();

        // P1 write that fits within A: hidden survives.
        c.write(b"realpw", &vec![7u8; 20 * 1024]).unwrap();
        assert!(matches!(c.open(b"hiddenpw").unwrap(), Opened::Compartment { .. }), "protect kept hidden intact");

        // P1 refuses to exceed its A cap (so it can never reach the tail) — unchanged from before.
        assert!(c.write(b"realpw", &vec![7u8; main_cap]).is_err(), "protect refuses to exceed A");

        // The exact payload that USED to spill past A and destroy the entire hidden region under
        // the old Blind policy is now REFUSED under blindpw too — same ceiling as realpw.
        assert!(
            c.write(b"blindpw", &vec![9u8; main_cap + hidden_cap]).is_err(),
            "blind must refuse this payload exactly like protect does — it can no longer reach the hidden tail"
        );
        assert!(
            matches!(c.open(b"hiddenpw").unwrap(), Opened::Compartment { .. }),
            "the hidden compartment must survive an oversized blind write attempt, since it was refused, not spilled"
        );

        let _ = std::fs::remove_file(&p);
    }

    /// CRYPTO-13 — the exact boundary `Container::write` must enforce for Protect is
    /// `region_cap / 2` (the ping-pong safe-path budget), NOT the full `region_cap`. An earlier
    /// version of this fix checked against the full cap, which let a Protect payload in the
    /// `(region_cap/2, region_cap]` band silently fall through `write_region_at` to the
    /// non-atomic spill branch — no error, no atomicity, the exact brick this fix exists to
    /// prevent, just gated behind a payload-size coin flip instead of happening unconditionally.
    /// This test pins BOTH sides of that boundary so the band can never reopen unnoticed.
    #[test]
    fn protect_refuses_a_payload_over_half_its_cap_even_though_it_would_fit_the_whole_cap() {
        let p = tmp("half-cap");
        let _ = std::fs::remove_file(&p);
        let main_cap = 64 * 1024usize;
        let mut c = Container::create(&p, 200 * 1024, b"realpw", main_cap as u64).unwrap();

        // Just OVER half the cap: fits easily inside the full region_cap, but must be refused —
        // there is no safe (ping-pong) slot for it, and it must NOT be silently handed to the
        // non-atomic spill path.
        let over_half = main_cap / 2 + 1024;
        assert!(
            c.write(b"realpw", &vec![1u8; over_half]).is_err(),
            "a Protect payload just over half the cap must be refused, not silently spilled"
        );

        // Just UNDER half the cap: must succeed and round-trip normally through the safe path.
        let under_half = main_cap / 2 - 1024;
        c.write(b"realpw", &vec![2u8; under_half]).unwrap();
        match c.open(b"realpw").unwrap() {
            Opened::Compartment { payload, .. } => assert_eq!(payload, vec![2u8; under_half]),
            _ => panic!("must open the main compartment"),
        }
        let _ = std::fs::remove_file(&p);
    }

    /// Phase-2 seam + Phase-4 property: a realistic serialized account snapshot round-trips,
    /// and the hidden account leaves ZERO artifacts outside the single container file.
    #[test]
    fn account_snapshot_round_trips_with_zero_external_artifacts() {
        let dir = tmp("acct");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cpath = dir.join("container.dat");

        // Stand-in for a serialized Store snapshot (contacts + a text history line).
        let snapshot: Vec<(String, String)> = vec![
            ("bob".into(), "2d17…".into()),
            ("history".into(), "hi from the hidden account".into()),
        ];
        let bytes = postcard::to_stdvec(&snapshot).unwrap();

        let mut c = Container::create(&cpath, 128 * 1024, b"realpw", 60 * 1024).unwrap();
        c.add_hidden(b"realpw", b"hiddenpw", 60 * 1024).unwrap();
        c.write(b"hiddenpw", &bytes).unwrap();

        // Zero external artifacts: the dir holds ONLY the container file.
        let files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        assert_eq!(files, vec!["container.dat".to_string()], "hidden account must leave nothing outside the container");

        // Round-trip: same snapshot back out.
        match c.open(b"hiddenpw").unwrap() {
            Opened::Compartment { payload, .. } => {
                let back: Vec<(String, String)> = postcard::from_bytes(&payload).unwrap();
                assert_eq!(back, snapshot);
            }
            _ => panic!("hidden compartment"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The core deniability property: the P3 (blind) password you reveal under duress cannot
    /// read the management directory, so it cannot learn that P1/P2 exist or how many slots
    /// are configured. Only the P1 management password can.
    #[test]
    fn revealing_p3_cannot_enumerate_the_other_passwords() {
        let p = tmp("deny");
        let _ = std::fs::remove_file(&p);
        let mut c = Container::create(&p, 256 * 1024, b"realpw", 96 * 1024).unwrap();
        c.add_hidden(b"realpw", b"hiddenpw", 96 * 1024).unwrap();
        c.add_blind_main(b"realpw", b"blindpw", 256 * 1024 - DATA_OFF as u64).unwrap();

        // P1 (management) can read the directory; P3 and the hidden password cannot.
        assert!(c.read_dir(&c.key_for(b"realpw").unwrap()).is_ok(), "P1 manages slots");
        assert!(c.read_dir(&c.key_for(b"blindpw").unwrap()).is_err(), "P3 reveal must NOT expose the slot directory");
        assert!(c.read_dir(&c.key_for(b"hiddenpw").unwrap()).is_err(), "hidden password must NOT expose the slot directory");

        // A coercer given P3 opens main and sees nothing that proves a hidden compartment.
        assert!(matches!(c.open(b"blindpw").unwrap(), Opened::Compartment { role: Role::Main, .. }));
        let _ = std::fs::remove_file(&p);
    }

    /// CRYPTO-10 — DISCRIMINATING test for the write-ceiling fix. Compares a totally vanilla,
    /// single-password container (A) against one that also has a hidden account AND a cover
    /// password configured (B): if the cover password's write ceiling on B differs from what an
    /// ordinary account's ONLY password gets on A, that difference is — by itself, with no other
    /// information — proof B has more than one password configured. `max_payload_len` must
    /// therefore report the IDENTICAL number for both, and a payload sized just over
    /// `region_cap / 2` (comfortably inside the OLD Blind ceiling, which spanned nearly the whole
    /// container) must be refused under the cover password exactly like it would be under an
    /// ordinary Protect password.
    ///
    /// **Scope of the claim (do not overread this test).** A and B are given the IDENTICAL
    /// `total`/`main_cap` on purpose — the parity this test pins is "same policy behaviour given
    /// the same region geometry," not "the ceiling is geometry-independent." `region_cap` (hence
    /// the ceiling) is `main_cap`, a value the user picks per container at creation time (§7's A/B
    /// slider) — so the write ceiling remains a finer-grained version of the SAME leak §8 already
    /// concedes for `N` (container size): both are user-chosen, both are visible to whoever can
    /// stress-test the write path. What CRYPTO-10 closes is the divergence BETWEEN P1 and P3
    /// *within one container* (a coercer who only ever sees one password can no longer learn "this
    /// password behaves differently from what this container's real password would"), not the
    /// separate, already-accepted fact that `main_cap` itself is inferable the same way `N` is.
    ///
    /// Neutered by re-introducing the old `Policy::Blind => (wide, wide)` arm in `write_limits`:
    /// `max_payload_len` on B then reports a number far larger than A's, and the oversized write
    /// below SUCCEEDS instead of erroring — RED (verified by hand with BOTH a 2x stand-in ceiling
    /// and the true historical `buf_len - region_off` value). Restoring the collapsed ceiling
    /// turns it GREEN.
    #[test]
    fn the_cover_password_write_ceiling_is_identical_to_an_ordinary_accounts() {
        let vanilla = tmp("crypto10-vanilla");
        let with_cover = tmp("crypto10-cover");
        let _ = std::fs::remove_file(&vanilla);
        let _ = std::fs::remove_file(&with_cover);
        let total = 256 * 1024u64;
        let main_cap = 96 * 1024u64;

        // A: one password, nothing else configured — the universal non-duress baseline.
        let a = Container::create(&vanilla, total, b"onlypw", main_cap).unwrap();

        // B: main + hidden + cover — the duress setup a coercer must not be able to detect.
        let mut b = Container::create(&with_cover, total, b"realpw", main_cap).unwrap();
        b.add_hidden(b"realpw", b"hiddenpw", total - DATA_OFF as u64 - main_cap).unwrap();
        b.add_blind_main(b"realpw", b"coverpw", total - DATA_OFF as u64).unwrap();

        // The P1 and P3 slots must carry the SAME policy byte — no distinguishing value exists.
        let p1_policy = b.find_slot(&b.key_for(b"realpw").unwrap()).unwrap().policy;
        let p3_policy = b.find_slot(&b.key_for(b"coverpw").unwrap()).unwrap().policy;
        assert_eq!(p1_policy, p3_policy, "P1 and P3 must be sealed with the identical policy byte");

        // The write ceiling itself must match A's ordinary single password, byte for byte.
        let a_max = a.max_payload_len(b"onlypw").unwrap();
        let b_max = b.max_payload_len(b"coverpw").unwrap();
        assert_eq!(
            a_max, b_max,
            "the cover password's write ceiling must be identical to a vanilla account's — any \
             difference is, by itself, proof a duress setup was configured"
        );

        // A payload comfortably inside the OLD Blind ceiling (nearly the whole container) but past
        // the shared region_cap/2 boundary must now be refused under the cover password too.
        let oversized = vec![9u8; b_max + 1024];
        assert!(
            b.write(b"coverpw", &oversized).is_err(),
            "the cover password must refuse this payload exactly like an ordinary account would"
        );

        let _ = std::fs::remove_file(&vanilla);
        let _ = std::fs::remove_file(&with_cover);
    }

    /// CRYPTO-10 — the honest residual that survives the fix above: management OPERATIONS
    /// (`add_hidden`/`add_blind_main`/`add_wipe`) still require the P1 (management) key, so
    /// attempting one under the cover password still fails distinctively where the real password
    /// would have succeeded. This is NOT a bug to fix — it is the direct, unavoidable consequence
    /// of `revealing_p3_cannot_enumerate_the_other_passwords` above (P3 must NOT be able to read
    /// the directory, or it could enumerate P1/P2 itself), so this test demonstrates the asymmetry
    /// on the record rather than implying CRYPTO-10 is fully closed.
    #[test]
    fn managing_slots_under_the_cover_password_still_fails_distinctively() {
        let p = tmp("crypto10-residual");
        let _ = std::fs::remove_file(&p);
        let mut c = Container::create(&p, 256 * 1024, b"realpw", 96 * 1024).unwrap();
        c.add_blind_main(b"realpw", b"coverpw", 256 * 1024 - DATA_OFF as u64).unwrap();

        // The real (management) password can configure a new duress password...
        assert!(c.add_wipe(b"realpw", b"burnpw").is_ok(), "the management password can add a wipe slot");
        // ...but the SAME operation attempted with the cover password fails, betraying that the
        // cover password is not the one that manages this container.
        assert!(
            c.add_wipe(b"coverpw", b"anotherpw").is_err(),
            "the cover password must not be able to add slots — and this refusal is itself informative"
        );
        let _ = std::fs::remove_file(&p);
    }

    /// Phase-2 bridge end-to-end: a whole account DIRECTORY (nested files) snapshots into one
    /// blob, stores in the container, and restores byte-identical — an entire account can live
    /// inside the container and come back intact.
    #[test]
    fn account_directory_round_trips_through_the_container() {
        let root = tmp("dirbridge");
        let _ = std::fs::remove_dir_all(&root);
        let acct = root.join("acct");
        std::fs::create_dir_all(acct.join("net/proxy3")).unwrap();
        std::fs::write(acct.join("contacts.dat"), b"contacts blob").unwrap();
        std::fs::write(acct.join("feed.dat"), vec![0xABu8; 4096]).unwrap();
        std::fs::write(acct.join("net/proxy3/sessions.dat"), b"ratchet state").unwrap();

        let blob = snapshot_dir(&acct, usize::MAX).unwrap();

        let cpath = root.join("container.dat");
        let mut c = Container::create(&cpath, 128 * 1024, b"realpw", 60 * 1024).unwrap();
        c.write(b"realpw", &blob).unwrap();

        // Pull the account back out of the container into a fresh directory.
        let restored = root.join("restored");
        match c.open(b"realpw").unwrap() {
            Opened::Compartment { payload, .. } => restore_dir(&restored, &payload).unwrap(),
            _ => panic!(),
        }
        assert_eq!(std::fs::read(restored.join("contacts.dat")).unwrap(), b"contacts blob");
        assert_eq!(std::fs::read(restored.join("feed.dat")).unwrap(), vec![0xABu8; 4096]);
        assert_eq!(std::fs::read(restored.join("net/proxy3/sessions.dat")).unwrap(), b"ratchet state");
        // And a re-snapshot of the restored tree equals the original snapshot (stable).
        assert_eq!(snapshot_dir(&restored, usize::MAX).unwrap(), blob);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// SEC-35: `snapshot_dir` must refuse a directory that cannot fit its `max_bytes` budget —
    /// loudly, naming what overflowed — rather than silently truncating (a truncated container
    /// image is a destroyed compartment) or buffering the whole oversized tree into memory first
    /// and failing only later. Control case first: an ordinary small directory well under budget
    /// still round-trips exactly as before.
    #[test]
    fn snapshot_dir_refuses_a_directory_that_cannot_fit_its_byte_budget() {
        let root = tmp("budget");
        let _ = std::fs::remove_dir_all(&root);
        let acct = root.join("acct");
        std::fs::create_dir_all(&acct).unwrap();
        std::fs::write(acct.join("small.dat"), vec![0u8; 100]).unwrap();

        // Control: comfortably under budget still works, unchanged behaviour.
        let blob = snapshot_dir(&acct, 10_000).expect("an ordinary small snapshot must still round-trip");
        assert!(!blob.is_empty());

        // A correspondent-controlled attachment blows the budget.
        std::fs::write(acct.join("attachment.bin"), vec![0xAAu8; 5_000]).unwrap();
        let err = snapshot_dir(&acct, 1_000)
            .expect_err("a snapshot over its budget must be refused, not truncated or silently accepted");
        let msg = err.to_string();
        assert!(msg.contains("attachment.bin"), "the error must name the file that overflowed: {msg}");
        assert!(msg.contains("1000"), "the error must name the budget it exceeded: {msg}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// SEC-35, integration level: pins the WIRING, not the memory bound itself — that is
    /// `snapshot_dir_refuses_a_directory_that_cannot_fit_its_byte_budget`'s job, and it is the one
    /// that actually goes red if the budget check is neutered. This test just confirms
    /// `ContainerVault::save` correctly computes and threads a real budget from the live container
    /// geometry (`Container::max_payload_len`) end to end, and — regardless of which layer catches
    /// the oversized save, `snapshot_dir`'s budget or `Container::write`'s own ceiling, both are
    /// live here — that the container's previously-saved state is left completely intact and a
    /// later normal-sized save still succeeds. (Confirmed by neutering: with the budget check
    /// disabled, `write`'s ceiling alone still fails this exact save, so this test does NOT
    /// discriminate the RAM-bound fix in isolation — only the sharper unit test above does.)
    #[test]
    fn container_vault_save_refuses_a_work_dir_too_big_for_its_region_and_leaves_prior_state_intact() {
        let root = tmp("oversave");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let cpath = root.join("container.dat");
        // A small container: 8 KiB region, so anything past a few KiB cannot fit.
        Container::create(&cpath, 64 * 1024, b"realpw", 8 * 1024).unwrap();

        let mut cv = ContainerVault::open(&cpath, b"realpw", root.join("w1")).unwrap();
        std::fs::write(cv.work_dir.join("contacts.dat"), b"first save, fits fine").unwrap();
        cv.save().unwrap();

        // Now grow the work dir well past what the region can hold.
        std::fs::write(cv.work_dir.join("huge_attachment.bin"), vec![0x42u8; 64 * 1024]).unwrap();
        cv.save()
            .expect_err("a work dir too big for its region must be refused, not truncated into the container");

        // The container still opens and still holds the FIRST save's data — the refused,
        // too-big save never touched it.
        drop(cv);
        let cv2 = ContainerVault::open(&cpath, b"realpw", root.join("w2")).unwrap();
        assert_eq!(
            std::fs::read(cv2.work_dir.join("contacts.dat")).unwrap(),
            b"first save, fits fine",
            "the container's prior state survives a refused oversized save untouched"
        );
        assert!(
            !cv2.work_dir.join("huge_attachment.bin").exists(),
            "the oversized file was never actually committed into the container"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// In-place region write: a main-account save touches ONLY its own region on disk (the
    /// hidden tail's raw bytes are byte-identical before/after), and the data still reloads.
    #[test]
    fn in_place_write_does_not_touch_the_hidden_region_on_disk() {
        let p = tmp("inplace");
        let _ = std::fs::remove_file(&p);
        let main_cap = 64 * 1024usize;
        let hidden_cap = 64 * 1024usize;
        let mut c = Container::create(&p, 200 * 1024, b"realpw", main_cap as u64).unwrap();
        c.add_hidden(b"realpw", b"hiddenpw", hidden_cap as u64).unwrap();
        c.write(b"hiddenpw", b"hidden secret").unwrap();

        let hidden_off = DATA_OFF + main_cap;
        let before = std::fs::read(&p).unwrap()[hidden_off..hidden_off + hidden_cap].to_vec();

        // Several main-account saves (the hot path).
        for i in 0..5 {
            c.write(b"realpw", format!("main state v{i}").as_bytes()).unwrap();
        }
        let after = std::fs::read(&p).unwrap()[hidden_off..hidden_off + hidden_cap].to_vec();
        assert_eq!(before, after, "main writes must not alter the hidden region's bytes on disk");

        // Everything still reads back correctly after in-place writes + reload.
        drop(c); // A3-8: one writer at a time — the exclusive lock is released with the instance.
        let c = Container::load(&p).unwrap();
        match c.open(b"realpw").unwrap() {
            Opened::Compartment { payload, .. } => assert_eq!(payload, b"main state v4"),
            _ => panic!(),
        }
        match c.open(b"hiddenpw").unwrap() {
            Opened::Compartment { payload, .. } => assert_eq!(payload, b"hidden secret"),
            _ => panic!(),
        }
        let _ = std::fs::remove_file(&p);
    }

    /// Append-only log: entries read back in order, and appending a new entry does NOT touch
    /// the bytes of the older chunks (only the new chunk + the tiny superblock change).
    #[test]
    fn append_log_is_append_only_and_ordered() {
        let key = random_key();
        let cap = 8 * 1024usize;
        let mut region = random_bytes(cap);
        Container::log_init(&mut region, 0, &key);

        Container::log_append(&mut region, 0, cap, &key, b"first").unwrap();
        Container::log_append(&mut region, 0, cap, &key, b"second message").unwrap();

        // High-water after two appends → the two chunks occupy [LEN_HDR, LEN_HDR+hw2).
        let hw2 = Container::read_sealed_u64(&region, 0, &key).unwrap() as usize;
        let two_chunks = region[LEN_HDR..LEN_HDR + hw2].to_vec();

        Container::log_append(&mut region, 0, cap, &key, b"third").unwrap();
        assert_eq!(&region[LEN_HDR..LEN_HDR + hw2], &two_chunks[..], "a new append must not touch older chunks");

        let entries = Container::log_read(&region, 0, &key).unwrap();
        assert_eq!(entries, vec![b"first".to_vec(), b"second message".to_vec(), b"third".to_vec()]);

        // A full log reports it rather than corrupting.
        let mut tiny = random_bytes(200);
        Container::log_init(&mut tiny, 0, &key);
        assert!(Container::log_append(&mut tiny, 0, 200, &key, &[0u8; 500]).is_err(), "overflow is rejected");
    }

    /// Composite region: a mutable core and an append-only history log coexist in one region and
    /// never disturb each other — updating the core leaves the log's bytes identical, and
    /// appending history leaves the core's bytes identical.
    #[test]
    fn region_store_core_and_log_are_independent() {
        let key = random_key();
        let cap = 16 * 1024usize;
        let core_cap = 4 * 1024usize;
        let mut buf = random_bytes(cap);
        let rs = RegionStore { off: 0, cap, core_cap };
        rs.init(&mut buf, &key).unwrap();

        rs.write_core(&mut buf, &key, b"sessions+contacts v1").unwrap();
        rs.append(&mut buf, &key, b"msg one").unwrap();
        rs.append(&mut buf, &key, b"msg two").unwrap();

        // Updating the core must not touch the log area's bytes.
        let log_area_before = buf[core_cap..cap].to_vec();
        rs.write_core(&mut buf, &key, b"sessions+contacts v2 (grew a bit)").unwrap();
        assert_eq!(buf[core_cap..cap], log_area_before[..], "core update must not touch the log");

        // Appending history must not touch the core area's bytes.
        let core_area_before = buf[0..core_cap].to_vec();
        rs.append(&mut buf, &key, b"msg three").unwrap();
        assert_eq!(buf[0..core_cap], core_area_before[..], "append must not touch the core");

        assert_eq!(rs.read_core(&buf, &key).unwrap(), b"sessions+contacts v2 (grew a bit)");
        assert_eq!(
            rs.read_log(&buf, &key).unwrap(),
            vec![b"msg one".to_vec(), b"msg two".to_vec(), b"msg three".to_vec()]
        );
    }

    /// ContainerVault lifecycle: open an account into a working dir, change files, save back,
    /// close, reopen — the account survives round-trip inside the container.
    #[test]
    fn container_vault_materializes_and_saves_an_account() {
        let root = tmp("cvault");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let cpath = root.join("container.dat");
        Container::create(&cpath, 256 * 1024, b"realpw", 120 * 1024).unwrap();

        // Open the (empty) account into a working dir and write some account files.
        let work = root.join("work");
        {
            let mut v = ContainerVault::open(&cpath, b"realpw", work.clone()).unwrap();
            assert_eq!(v.role, Role::Main);
            std::fs::create_dir_all(v.work_dir.join("net")).unwrap();
            std::fs::write(v.work_dir.join("contacts.dat"), b"alice,bob").unwrap();
            std::fs::write(v.work_dir.join("net/sessions.dat"), b"ratchets").unwrap();
            v.save().unwrap();
        }

        // Reopen into a FRESH working dir → the account files come back from the container.
        let work2 = root.join("work2");
        let v = ContainerVault::open(&cpath, b"realpw", work2.clone()).unwrap();
        assert_eq!(std::fs::read(v.work_dir.join("contacts.dat")).unwrap(), b"alice,bob");
        assert_eq!(std::fs::read(v.work_dir.join("net/sessions.dat")).unwrap(), b"ratchets");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// End-to-end with the REAL `Store`: an actual account (its sealed profile.dat) written by
    /// `Store` into a ContainerVault work dir survives save → close → reopen inside the container.
    /// This de-risks the desktop wiring — the live account code runs unchanged on top of the seam.
    #[test]
    fn real_store_persists_through_the_container() {
        use crate::store::{Profile, Store};
        let root = tmp("realstore");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let cpath = root.join("container.dat");
        Container::create(&cpath, 256 * 1024, b"realpw", 120 * 1024).unwrap();
        let acct_key = MasterKey::derive(b"account-key", b"salt-16-bytes-xx").unwrap();

        {
            let mut v = ContainerVault::open(&cpath, b"realpw", root.join("w1")).unwrap();
            let store = Store::at(&v.work_dir, acct_key.clone());
            store.save_profile(&Profile { name: "Alice".into(), bio: "im alice".into(), avatar: None, photos: vec![], photos_ts: 0 }).unwrap();
            v.save().unwrap();
        }

        let v = ContainerVault::open(&cpath, b"realpw", root.join("w2")).unwrap();
        let store = Store::at(&v.work_dir, acct_key);
        let p = store.load_profile().unwrap();
        assert_eq!(p.name, "Alice");
        assert_eq!(p.bio, "im alice");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A full multi-account `Vault` (adopted over the container work dir, with the region key as
    /// its account key) round-trips through the container — the desktop's Vault-based session maps
    /// cleanly onto the seam, with the container replacing the vault's own keyslots.
    #[test]
    fn full_vault_over_the_container_round_trips() {
        use crate::store::{Profile, Vault};
        let root = tmp("vaultcont");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let cpath = root.join("container.dat");
        Container::create(&cpath, 256 * 1024, b"realpw", 120 * 1024).unwrap();
        let acct_key = MasterKey::derive(b"region-key", b"salt-16-bytes-xx").unwrap();

        {
            let mut cv = ContainerVault::open(&cpath, b"realpw", root.join("w1")).unwrap();
            let vault = Vault::adopt(&cv.work_dir, acct_key.clone());
            vault.create_account_dir("acc-ik-1").unwrap();
            vault.account("acc-ik-1").save_profile(&Profile { name: "Alice".into(), bio: "one".into(), avatar: None, photos: vec![], photos_ts: 0 }).unwrap();
            vault.create_account_dir("acc-ik-2").unwrap();
            vault.account("acc-ik-2").save_profile(&Profile { name: "Work".into(), bio: "two".into(), avatar: None, photos: vec![], photos_ts: 0 }).unwrap();
            cv.save().unwrap();
        }

        let cv = ContainerVault::open(&cpath, b"realpw", root.join("w2")).unwrap();
        let vault = Vault::adopt(&cv.work_dir, acct_key);
        assert_eq!(vault.account("acc-ik-1").load_profile().unwrap().name, "Alice");
        assert_eq!(vault.account("acc-ik-2").load_profile().unwrap().name, "Work");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Adding a hidden account from an open main session works without clobbering the main account:
    /// the hidden account opens with its own password, and the main account still opens intact.
    #[test]
    fn container_vault_adds_a_hidden_account() {
        let root = tmp("addhid");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let cpath = root.join("container.dat");
        Container::create(&cpath, 256 * 1024, b"realpw", 100 * 1024).unwrap();

        // Build an empty "hidden account" snapshot (a file in a temp dir), then add it from a main session.
        let hb = root.join("build");
        std::fs::create_dir_all(&hb).unwrap();
        std::fs::write(hb.join("seed.key"), b"hidden seed material").unwrap();
        let hidden_snapshot = snapshot_dir(&hb, usize::MAX).unwrap();

        {
            let mut cv = ContainerVault::open(&cpath, b"realpw", root.join("mw")).unwrap();
            std::fs::write(cv.work_dir.join("contacts.dat"), b"main contacts").unwrap();
            cv.save().unwrap();
            cv.add_hidden(b"hiddenpw", |_, _| Ok(hidden_snapshot.clone())).unwrap();
            cv.save().unwrap(); // a later MAIN flush must NOT clobber the hidden region
        }

        // The hidden password opens the hidden account.
        match open_container(&cpath, b"hiddenpw", root.join("mw2"), Some(root.join("hw"))).unwrap() {
            Unlocked::Account(cv) => {
                assert_eq!(cv.role, Role::Hidden);
                assert_eq!(std::fs::read(cv.work_dir.join("seed.key")).unwrap(), b"hidden seed material");
            }
            _ => panic!("hiddenpw → hidden account"),
        }
        // The main account still opens intact.
        match open_container(&cpath, b"realpw", root.join("mw3"), Some(root.join("hw3"))).unwrap() {
            Unlocked::Account(cv) => {
                assert_eq!(cv.role, Role::Main);
                assert_eq!(std::fs::read(cv.work_dir.join("contacts.dat")).unwrap(), b"main contacts");
            }
            _ => panic!("realpw → main account"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// ContainerVault add_blind/add_wipe from a main session: the P3 cover password opens main and is
    /// SAFE to reveal (can't read the mgmt dir → can't detect the hidden account); wipe erases.
    #[test]
    fn container_vault_adds_cover_and_wipe_passwords() {
        let root = tmp("cover");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let cpath = root.join("container.dat");
        Container::create(&cpath, 256 * 1024, b"mainpw", 100 * 1024).unwrap();
        // Build a tiny hidden account so there IS something the cover password must not expose.
        let hb = root.join("hb");
        std::fs::create_dir_all(&hb).unwrap();
        std::fs::write(hb.join("seed.key"), b"x").unwrap();
        let snap = snapshot_dir(&hb, usize::MAX).unwrap();
        {
            let mut cv = ContainerVault::open(&cpath, b"mainpw", root.join("mw")).unwrap();
            cv.add_hidden(b"hiddenpw", |_, _| Ok(snap.clone())).unwrap();
            cv.add_blind(b"coverpw").unwrap();
            cv.add_wipe(b"burnpw").unwrap();
        }
        // Cover password opens the MAIN account…
        match open_container(&cpath, b"coverpw", root.join("mw2"), Some(root.join("hw"))).unwrap() {
            Unlocked::Account(cv) => assert_eq!(cv.role, Role::Main),
            _ => panic!("coverpw → main"),
        }
        // …but its key CANNOT read the management directory (so revealing it can't detect the hidden acct).
        let c = Container::load(&cpath).unwrap();
        assert!(c.read_dir(&c.key_for(b"coverpw").unwrap()).is_err(), "cover password must not expose the slot directory");
        assert!(c.read_dir(&c.key_for(b"mainpw").unwrap()).is_ok(), "the main password manages slots");
        drop(c); // A3-8: release the exclusive lock before opening the container again.
        // Wipe erases the whole container.
        assert!(matches!(open_container(&cpath, b"burnpw", root.join("mw3"), Some(root.join("hw3"))).unwrap(), Unlocked::Wiped));
        assert!(open_container(&cpath, b"mainpw", root.join("mw4"), Some(root.join("hw4"))).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The cover-password bug the GUI caught: P1 and P3 must yield the SAME account key, so the cover
    /// password decrypts the SAME main account files (a Store profile written under P1 reads under P3).
    #[test]
    fn cover_password_opens_the_same_main_account() {
        use crate::store::{Profile, Vault};
        let root = tmp("coversame");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let cpath = root.join("container.dat");
        Container::create(&cpath, 256 * 1024, b"mainpw", 120 * 1024).unwrap();

        // Write a profile under the MAIN password, using the region key as the account key.
        let main_key;
        {
            let mut cv = ContainerVault::open(&cpath, b"mainpw", root.join("mw")).unwrap();
            main_key = cv.account_key();
            let vault = Vault::adopt(&cv.work_dir, cv.account_key());
            vault.create_account_dir("acc").unwrap();
            vault.account("acc").save_profile(&Profile { name: "Alice".into(), bio: "".into(), avatar: None, photos: vec![], photos_ts: 0 }).unwrap();
            cv.save().unwrap();
            cv.add_blind(b"coverpw").unwrap();
        }

        // Open via the COVER password → same account key, and the profile decrypts.
        match open_container(&cpath, b"coverpw", root.join("cw"), Some(root.join("hw"))).unwrap() {
            Unlocked::Account(cv) => {
                assert_eq!(cv.account_key().as_bytes(), main_key.as_bytes(), "P3 shares the main region key");
                let vault = Vault::adopt(&cv.work_dir, cv.account_key());
                assert_eq!(vault.account("acc").load_profile().unwrap().name, "Alice", "cover opens the same main account files");
            }
            _ => panic!("coverpw → main"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// open_container routes by role: main → main_work, hidden → hidden_work (tmpfs), wipe erases.
    #[test]
    fn open_container_routes_by_role() {
        let root = tmp("route");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let cpath = root.join("container.dat");
        let main_w = root.join("mw");
        let hid_w = root.join("hw");
        Container::create(&cpath, 256 * 1024, b"realpw", 96 * 1024).unwrap();
        {
            let mut c = Container::load(&cpath).unwrap();
            c.add_hidden(b"realpw", b"hiddenpw", 96 * 1024).unwrap();
            c.add_blind_main(b"realpw", b"blindpw", 256 * 1024 - DATA_OFF as u64).unwrap();
            c.add_wipe(b"realpw", b"burnpw").unwrap();
        }

        match open_container(&cpath, b"realpw", main_w.clone(), Some(hid_w.clone())).unwrap() {
            Unlocked::Account(cv) => { assert_eq!(cv.role, Role::Main); assert_eq!(cv.work_dir, main_w); }
            _ => panic!("realpw → main"),
        }
        match open_container(&cpath, b"hiddenpw", main_w.clone(), Some(hid_w.clone())).unwrap() {
            Unlocked::Account(cv) => { assert_eq!(cv.role, Role::Hidden); assert_eq!(cv.work_dir, hid_w); }
            _ => panic!("hiddenpw → hidden (tmpfs work dir)"),
        }
        match open_container(&cpath, b"blindpw", main_w.clone(), Some(hid_w.clone())).unwrap() {
            // CRYPTO-10: no separate Blind policy anymore — the cover password's slot is sealed
            // identically to the real password's, so the two are behaviourally indistinguishable.
            Unlocked::Account(cv) => { assert_eq!(cv.role, Role::Main); assert_eq!(cv.policy, Policy::Protect); }
            _ => panic!("blindpw → main/blind"),
        }
        // Wipe erases the whole container.
        assert!(matches!(open_container(&cpath, b"burnpw", main_w.clone(), Some(hid_w.clone())).unwrap(), Unlocked::Wiped));
        assert!(open_container(&cpath, b"realpw", main_w, Some(hid_w)).is_err(), "container wiped → nothing opens");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// CRYPTO-02 — with NO verified RAM-backed store, opening a hidden account must FAIL rather
    /// than materialize its plaintext onto the real disk. Discriminating on the part that
    /// actually mattered: not just "returns Err", but that **nothing was written** — the old code
    /// silently restored the whole account tree into a predictable `base/.hidden-work`, which is
    /// what disproved "zero external artifacts" and killed deniability on any system without a
    /// working `/dev/shm` (macOS, Windows, minimal containers). A MAIN account must still open,
    /// so the refusal cannot be "break the container on platforms without tmpfs".
    #[test]
    fn a_hidden_account_refuses_to_open_without_a_ram_backed_store() {
        let root = tmp("no-ramfs");
        std::fs::create_dir_all(&root).unwrap();
        let cpath = root.join("container.dat");
        let main_w = root.join("mw");
        Container::create(&cpath, 256 * 1024, b"realpw", 96 * 1024).unwrap();
        {
            let mut c = Container::load(&cpath).unwrap();
            c.add_hidden(b"realpw", b"hiddenpw", 96 * 1024).unwrap();
        }

        // `None` = this system could not prove a RAM-backed store exists.
        assert!(
            open_container(&cpath, b"hiddenpw", main_w.clone(), None).is_err(),
            "a hidden account must not open without a verified RAM-backed store"
        );
        // Nothing of the hidden account may have been written anywhere under the vault.
        let blob = snapshot_dir(&root, usize::MAX).unwrap();
        let on_disk: Vec<(String, Vec<u8>)> = postcard::from_bytes(&blob).unwrap();
        let names: Vec<&String> = on_disk.iter().map(|(rel, _)| rel).collect();
        assert!(
            names.iter().all(|rel| rel.as_str() == "container.dat"),
            "the hidden account leaked files to disk: {names:?}"
        );

        // The MAIN account is disk-backed by design and must still open on such a system.
        match open_container(&cpath, b"realpw", main_w.clone(), None).unwrap() {
            Unlocked::Account(cv) => assert_eq!(cv.role, Role::Main),
            _ => panic!("a main account must still open without tmpfs"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A3-1 — a SECOND hidden account must be refused, not silently written over the first.
    /// `hidden_off` is a fixed offset, so the old code wrote a fresh empty region on top of the
    /// existing hidden account under a NEW key, leaving the original slot pointing at bytes its
    /// key can no longer open: total, irreversible loss of a duress compartment with no warning.
    /// Discriminating on the data, not just the return value — the first hidden password must
    /// still open its account, with its contents intact, after the second attempt is refused.
    #[test]
    fn a_second_hidden_account_is_refused_without_touching_the_first() {
        let root = tmp("two-hidden");
        std::fs::create_dir_all(&root).unwrap();
        let cpath = root.join("container.dat");
        Container::create(&cpath, 512 * 1024, b"realpw", 128 * 1024).unwrap();
        let hidden_key = {
            let mut c = Container::load(&cpath).unwrap();
            c.add_hidden(b"realpw", b"hiddenpw", 128 * 1024).unwrap()
        };

        // Put something in the hidden compartment so its loss would be observable.
        {
            let mut c = Container::load(&cpath).unwrap();
            let slot = c.find_slot(&c.key_for(b"hiddenpw").unwrap()).expect("hidden slot");
            Container::write_region_at(
                &mut c.buf,
                slot.region_off as usize,
                slot.region_cap as usize,
                slot.region_cap as usize,
                &hidden_key,
                b"the hidden account payload",
            )
            .unwrap();
            c.persist().unwrap();
        }

        // A second hidden password must be REFUSED.
        {
            let mut c = Container::load(&cpath).unwrap();
            assert!(
                c.add_hidden(b"realpw", b"otherhidden", 128 * 1024).is_err(),
                "a container must hold at most one hidden account"
            );
            c.persist().unwrap();
        }

        // The original hidden account still opens AND still has its data.
        let c = Container::load(&cpath).unwrap();
        let hkey = c.key_for(b"hiddenpw").unwrap();
        let slot = c.find_slot(&hkey).expect("the first hidden slot must survive");
        let got = Container::read_region_at(&c.buf, slot.region_off as usize, slot.region_cap as usize, &hidden_key)
            .expect("the first hidden region must still decrypt");
        assert_eq!(got, b"the hidden account payload", "the first hidden account lost its data");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// CRYPTO-13 — a torn save must roll a compartment back to its last good generation, never
    /// brick it. We can't literally kill the process mid-syscall in a test, so instead of assuming
    /// a byte layout we ASK THE CODE where the next save would land — a dry run of
    /// `write_region_at` on a clone of the buffer — then simulate the crash by copying only a
    /// PREFIX of that exact range into the real buffer, leaving a torn mix that fails AEAD. This
    /// is deliberately layout-agnostic: it discriminates against ANY implementation (this one, or
    /// a future change to the alternation rule) that fails to leave the OTHER copy slot untouched,
    /// not just this specific offset arithmetic. Control: also destroying the slot that DOES hold
    /// the good generation must make the region genuinely fail to open — otherwise this test could
    /// pass by ignoring corruption everywhere.
    #[test]
    fn a_torn_save_rolls_back_to_the_previous_generation_instead_of_bricking() {
        let key = random_key();
        let cap = 4 * 1024usize;
        let mut buf = random_bytes(cap);

        Container::write_region_at(&mut buf, 0, cap, cap, &key, b"generation one").unwrap();
        Container::write_region_at(&mut buf, 0, cap, cap, &key, b"generation two").unwrap();
        assert_eq!(Container::read_region_at(&buf, 0, cap, &key).unwrap(), b"generation two");

        // Dry run: where would the NEXT save land? Applied to a CLONE, not `buf` — we want to know
        // the target without actually completing the write.
        let mut probe = buf.clone();
        let (target_off, target_len) =
            Container::write_region_at(&mut probe, 0, cap, cap, &key, b"generation three").unwrap();

        // Simulate a crash: only the first half of that write's bytes made it to disk.
        let torn_prefix = target_len / 2;
        buf[target_off..target_off + torn_prefix].copy_from_slice(&probe[target_off..target_off + torn_prefix]);

        assert_eq!(
            Container::read_region_at(&buf, 0, cap, &key).unwrap(),
            b"generation two",
            "a torn write to the OTHER copy slot must roll back to the last good save, not brick the region"
        );

        // Control: now also destroy the slot that DOES hold "generation two" (the opposite half
        // from the torn one) — with nothing left untouched, this must genuinely fail to open.
        let half = cap / 2;
        let surviving_off = half - target_off; // the other of {0, half}
        for b in buf[surviving_off..surviving_off + 24].iter_mut() {
            *b ^= 0xFF;
        }
        assert!(
            Container::read_region_at(&buf, 0, cap, &key).is_err(),
            "control: with BOTH copy slots destroyed there is nothing left to recover"
        );
    }

    /// CRYPTO-14 (part 1) — refutes the literal claim that "the cover password's own write
    /// reveals a hidden compartment": a P3 (blind) save touches the EXACT SAME `(offset, length)`
    /// whether or not a hidden compartment exists elsewhere in the container. Same total size N,
    /// same region offsets (fixed at creation, independent of `add_hidden`), same ping-pong
    /// alternation for the same sequence of main-account saves. We compare the deterministic
    /// `(offset, length)` `write_region_at` itself reports — not a before/after byte diff of the
    /// two files, which would be flaky here: ciphertext is pseudorandom, so a rewritten byte can
    /// coincidentally equal its own previous value, silently shrinking a value-diff's apparent
    /// range by a byte or two at either end with nothing to do with the code under test. The real
    /// leak is not in this write — see the next test.
    ///
    /// **Post-CRYPTO-10 note.** This test calls `write_region_at` directly with a hand-built wide
    /// `hard_cap`, deliberately bypassing `Container::write`/`write_limits` — which, since
    /// CRYPTO-10, never constructs a wide `hard_cap` for ANY password anymore (Blind's ceiling
    /// collapsed to match Protect's). The property this test pins is still true of the underlying
    /// primitive and worth keeping — if a future caller ever DOES hand `write_region_at` a wide
    /// `hard_cap` again, this is the test that would catch a regression back to
    /// offset-dependent behaviour — but nothing in today's live code path reaches this branch.
    #[test]
    fn a_p3_write_touches_the_same_range_whether_or_not_a_hidden_compartment_exists() {
        let no_hidden = tmp("p3-no-hidden");
        let with_hidden = tmp("p3-with-hidden");
        let _ = std::fs::remove_file(&no_hidden);
        let _ = std::fs::remove_file(&with_hidden);
        let total = 256 * 1024u64;
        let main_cap = 96 * 1024u64;

        let mut a = Container::create(&no_hidden, total, b"realpw", main_cap).unwrap();
        a.add_blind_main(b"realpw", b"blindpw", total - DATA_OFF as u64).unwrap();

        let mut b = Container::create(&with_hidden, total, b"realpw", main_cap).unwrap();
        b.add_hidden(b"realpw", b"hiddenpw", total - DATA_OFF as u64 - main_cap).unwrap();
        b.add_blind_main(b"realpw", b"blindpw", total - DATA_OFF as u64).unwrap();

        let payload = b"an ordinary cover-session save";
        let a_info = a.find_slot(&a.key_for(b"blindpw").unwrap()).unwrap();
        let a_hard_cap = a.buf.len() as u64 - a_info.region_off;
        let touched_a = Container::write_region_at(
            &mut a.buf,
            a_info.region_off as usize,
            a_info.region_cap as usize,
            a_hard_cap as usize,
            &a_info.region_key,
            payload,
        )
        .unwrap();

        let b_info = b.find_slot(&b.key_for(b"blindpw").unwrap()).unwrap();
        let b_hard_cap = b.buf.len() as u64 - b_info.region_off;
        let touched_b = Container::write_region_at(
            &mut b.buf,
            b_info.region_off as usize,
            b_info.region_cap as usize,
            b_hard_cap as usize,
            &b_info.region_key,
            payload,
        )
        .unwrap();

        assert!(touched_a.1 > 0, "control: the write must actually touch some bytes");
        assert_eq!(
            touched_a, touched_b,
            "a P3 write must touch the identical (offset, length) regardless of whether a hidden compartment exists"
        );
        let _ = std::fs::remove_file(&no_hidden);
        let _ = std::fs::remove_file(&with_hidden);
    }

    /// CRYPTO-14 (part 2) — the ACTUAL leak, pinned so nobody re-claims it's solved: a HIDDEN
    /// write's changed bytes localize entirely inside the hidden region, never touching the main
    /// region (the reverse of `in_place_write_does_not_touch_the_hidden_region_on_disk`, which
    /// pins the other direction). A snapshot-diff adversary holding two images of the file can
    /// therefore tell "ordinary main/cover activity" (changes confined to the small zone near the
    /// front of the file) apart from "something else wrote back here" — which is a real,
    /// structural leak, not a bug: `duress-tier2-container.md` §2(b)'s claim that main-account
    /// activity "masks" hidden writes does not hold below the point where a P3 save already
    /// SPILLS into (and destroys) the hidden region — masking and destroying are the same
    /// operation on one shared key. True masking would need every main save to rewrite the WHOLE
    /// container so a diff can never localize anything, which directly defeats `persist_range`'s
    /// whole reason to exist (an O(1)-ish save instead of an O(N) rewrite per message). NOT fixed
    /// here — there is no disk-layer fix that keeps the efficient-save design.
    #[test]
    fn a_hidden_write_changes_only_bytes_inside_the_hidden_region() {
        let p = tmp("leak");
        let _ = std::fs::remove_file(&p);
        let total = 256 * 1024u64;
        let main_cap = 96 * 1024usize;
        let hidden_cap = 96 * 1024u64;
        let mut c = Container::create(&p, total, b"realpw", main_cap as u64).unwrap();
        c.add_hidden(b"realpw", b"hiddenpw", hidden_cap).unwrap();

        let before = std::fs::read(&p).unwrap();
        c.write(b"hiddenpw", b"a message only the hidden account will ever see").unwrap();
        let after = std::fs::read(&p).unwrap();

        let main_off = DATA_OFF;
        let hidden_off = DATA_OFF + main_cap;
        let hidden_end = hidden_off + hidden_cap as usize;

        let changed: Vec<usize> = before
            .iter()
            .zip(after.iter())
            .enumerate()
            .filter(|(_, (x, y))| x != y)
            .map(|(i, _)| i)
            .collect();
        assert!(!changed.is_empty(), "control: the write must actually change some bytes");
        assert!(
            changed.iter().all(|&i| i >= hidden_off && i < hidden_end),
            "a hidden write must not touch any byte outside its own region"
        );
        assert!(
            changed.iter().all(|&i| !(i >= main_off && i < main_off + main_cap)),
            "a hidden write must never touch the main region's bytes"
        );
        let _ = std::fs::remove_file(&p);
    }

    /// A3-6 — a FAILED save must never be followed by deleting the work dir. A hidden account
    /// lives only in that (RAM) directory between saves, so the old `let _ = cv.save();
    /// remove_dir_all(work_dir)` threw away the error and then the only copy of everything since
    /// the last successful save — silent, total data loss on an ordinary lock.
    ///
    /// The container's directory is made read-only so `save` fails while writing its temp file;
    /// the WORK dir stays writable on purpose, so a deletion would genuinely succeed if the code
    /// still attempted it. That is what makes this discriminating rather than accidental.
    #[test]
    #[cfg(unix)]
    fn a_failed_save_does_not_delete_the_hidden_work_dir() {
        use std::os::unix::fs::PermissionsExt;

        let root = tmp("save-fail");
        let cdir = root.join("cdir");
        let work = root.join("work");
        std::fs::create_dir_all(&cdir).unwrap();
        let cpath = cdir.join("container.dat");
        Container::create(&cpath, 512 * 1024, b"realpw", 128 * 1024).unwrap();
        {
            let mut c = Container::load(&cpath).unwrap();
            c.add_hidden(b"realpw", b"hiddenpw", 128 * 1024).unwrap();
        }
        let cv = ContainerVault::open(&cpath, b"hiddenpw", work.clone()).expect("hidden opens");
        assert_eq!(cv.role, Role::Hidden);
        std::fs::write(work.join("unsaved.dat"), b"messages since the last save").unwrap();

        // Make the CONTAINER FILE read-only → the save fails (a hot save writes into this file
        // in place, so file permissions are what stops it, not the directory's). `work` stays
        // writable on purpose, so nothing but the fix prevents the deletion.
        let orig = std::fs::metadata(&cpath).unwrap().permissions();
        std::fs::set_permissions(&cpath, std::fs::Permissions::from_mode(0o444)).unwrap();
        let mut cv = cv;
        let outcome = cv.save_and_release();
        std::fs::set_permissions(&cpath, orig).unwrap();

        assert!(outcome.is_err(), "the save could not have succeeded here");
        assert!(work.exists(), "the work dir was deleted after a FAILED save — that is the data loss");
        assert_eq!(
            std::fs::read(work.join("unsaved.dat")).unwrap(),
            b"messages since the last save",
            "unsaved data must still be there to retry with"
        );
        let _ = std::fs::remove_dir_all(&root);
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

    /// Reload from disk round-trips; wipe destroys everything.
    #[test]
    fn reload_and_wipe() {
        let p = tmp("reload");
        let _ = std::fs::remove_file(&p);
        {
            let mut c = Container::create(&p, 128 * 1024, b"realpw", 60 * 1024).unwrap();
            c.write(b"realpw", b"persist me").unwrap();
        }
        let mut c = Container::load(&p).unwrap();
        match c.open(b"realpw").unwrap() {
            Opened::Compartment { payload, .. } => assert_eq!(payload, b"persist me"),
            _ => panic!(),
        }
        c.wipe().unwrap();
        drop(c); // A3-8: release the exclusive lock before reloading.
        let c = Container::load(&p).unwrap();
        assert!(c.open(b"realpw").is_err(), "wipe erased the real compartment");
        let _ = std::fs::remove_file(&p);
    }

    /// CRYPTO-12/#184 — DISCRIMINATING test for the crypto claim `wipe()`'s fix relies on:
    /// destroying ONLY the `SALT_LEN`-byte salt, with every other byte of the container left
    /// completely untouched, is already sufficient to make the real password open nothing. This is
    /// what makes an in-place, small-range overwrite (rather than rewriting the whole multi-KB/MB
    /// file) a meaningful fix at all — if some OTHER byte also had to change, overwriting just the
    /// salt wouldn't be enough and the "small independently erasable value" framing would be false.
    ///
    /// This test pins the CRYPTO claim only, not the write-ORDERING half of the fix (in-place
    /// before the whole-buffer swap) — that half is about which physical disk blocks a `pwrite`
    /// lands on, which is not observable by reading the file back through this same process, so no
    /// test in this suite can honestly claim to cover it; the doc comment on `wipe` states that
    /// limit rather than implying a test proves it.
    ///
    /// Neutered by skipping the salt replacement (leaving the original salt bytes in place): the
    /// real password still opens the compartment fine — RED. Restoring the replacement turns it
    /// GREEN.
    #[test]
    fn destroying_only_the_salt_bytes_makes_the_real_password_open_nothing() {
        let p = tmp("salt-erase");
        let _ = std::fs::remove_file(&p);
        let mut c = Container::create(&p, 128 * 1024, b"realpw", 60 * 1024).unwrap();
        c.write(b"realpw", b"data that must become unrecoverable").unwrap();

        // Control: before touching anything, the real password opens fine.
        assert!(c.open(b"realpw").is_ok(), "control: the real password must open before any erasure");

        // The exact operation `wipe()` performs first: overwrite JUST the salt, nothing else.
        let fresh_salt = random_bytes(SALT_LEN);
        c.buf[..SALT_LEN].copy_from_slice(&fresh_salt);

        // Every byte OTHER than the salt is still the original ciphertext — this is not a general
        // "corrupt the file" test, it isolates the salt as the one thing that changed.
        assert!(
            c.open(b"realpw").is_err(),
            "replacing ONLY the salt must already be enough to make the real password open nothing, \
             even though every slot/region byte is completely untouched"
        );
        let _ = std::fs::remove_file(&p);
    }

    /// **A3-3 — reopening a compartment must make the work dir EQUAL its snapshot, not merge into
    /// it.** The work dir survives between sessions (`<vault>/work`), so the old overlay behaviour
    /// let anything left in it outlive the snapshot that was supposed to replace it — deleted files
    /// came back and were then re-snapshotted, making the resurrection permanent.
    ///
    /// DISCRIMINATING by construction: the stray file is one the snapshot NEVER contained, so the
    /// obvious version of this test ("delete a contact, save, reopen, still gone") would pass under
    /// the overlay too — a delete removes it from the work dir, hence from the snapshot. Only a file
    /// that exists in the directory and not in the blob separates the two behaviours. Neuter by
    /// deleting the `remove_dir_all` in `restore_dir` and the stray survives → RED.
    ///
    /// The second half pins the ORDER: a blob that fails to decode must leave the work dir intact.
    /// Neuter by moving the clear above the decode and the live account is destroyed by a bad
    /// read → RED.
    #[test]
    fn reopening_a_compartment_replaces_the_work_dir_instead_of_merging_into_it() {
        let root = tmp("restore-authority");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let cpath = root.join("container.dat");
        let work = root.join("work");
        Container::create(&cpath, 256 * 1024, b"realpw", 96 * 1024).unwrap();

        {
            let mut cv = ContainerVault::open(&cpath, b"realpw", work.clone()).unwrap();
            std::fs::write(work.join("kept.txt"), b"in the snapshot").unwrap();
            std::fs::create_dir_all(work.join("sub")).unwrap();
            std::fs::write(work.join("sub/kept2.txt"), b"also in the snapshot").unwrap();
            cv.save().unwrap();
        }

        // Files that were never saved — what a crash (or a failed save) leaves behind.
        std::fs::write(work.join("stray.txt"), b"never reached the container").unwrap();
        std::fs::create_dir_all(work.join("ghost")).unwrap();
        std::fs::write(work.join("ghost/deleted-contact"), b"resurrected under the old overlay").unwrap();

        let cv = ContainerVault::open(&cpath, b"realpw", work.clone()).unwrap();
        assert_eq!(std::fs::read(work.join("kept.txt")).unwrap(), b"in the snapshot");
        assert_eq!(std::fs::read(work.join("sub/kept2.txt")).unwrap(), b"also in the snapshot");
        assert!(
            !work.join("stray.txt").exists(),
            "a file the snapshot does not contain must not survive a reopen — the container is the \
             authority for what the account holds"
        );
        assert!(!work.join("ghost").exists(), "and neither must a whole directory it does not contain");
        drop(cv);

        // Ordering: an undecodable blob must not destroy the materialized account on its way to
        // reporting the error.
        assert!(restore_dir(&work, &[0xffu8; 8]).is_err(), "a corrupt snapshot blob must be refused");
        assert_eq!(
            std::fs::read(work.join("kept.txt")).unwrap(),
            b"in the snapshot",
            "a blob that fails to decode must leave the work dir exactly as it was"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **A3-8 — one live `Container` per file, enforced rather than assumed.** Two writers over one
    /// container could interleave into the shared `<container>.tmp` and rename the mixture over
    /// `container.dat` (destroying every compartment), delete each other's in-flight saves, or
    /// silently revert regions they never touched. `flock` is per open-file-description, so this
    /// also covers two instances inside ONE process — which is what this test uses, since that is
    /// the strictly harder case and needs no second process to demonstrate.
    ///
    /// Neuter by making `lock_file` return `Ok(None)` without calling `flock` and the second load
    /// succeeds → RED.
    #[test]
    #[cfg(unix)]
    fn a_second_live_container_over_one_file_is_refused_until_the_first_is_dropped() {
        let root = tmp("one-writer");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let cpath = root.join("container.dat");
        let mut first = Container::create(&cpath, 128 * 1024, b"realpw", 60 * 1024).unwrap();
        first.write(b"realpw", b"the first session's state").unwrap();

        let err = Container::load(&cpath)
            .err()
            .expect("a second image of a container someone is already writing must be refused");
        // The KIND matters as much as the refusal: the desktop collapses an ordinary open failure
        // to an opaque "wrong password" (deliberately — see `container_unlock`), so a lock conflict
        // that is not distinguishable by kind gets reported as a password failure to a user whose
        // password is fine.
        assert_eq!(
            err.kind(),
            io::ErrorKind::WouldBlock,
            "a lock conflict must be distinguishable from a wrong password, got: {err}"
        );
        assert!(
            ContainerVault::open(&cpath, b"realpw", root.join("work")).is_err(),
            "and the vault path must be refused for the same reason, not just the raw loader"
        );

        // The lock lives exactly as long as the instance: dropping it frees the container.
        drop(first);
        let reopened = Container::load(&cpath).unwrap();
        match reopened.open(b"realpw").unwrap() {
            Opened::Compartment { payload, .. } => assert_eq!(payload, b"the first session's state"),
            _ => panic!("the main compartment must still open"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **A3-9 — a container bigger than we will hold in RAM is refused, not attempted.** The whole
    /// file lives in a `Vec<u8>`, so `size_mb` from the frontend was an unbounded allocation
    /// request; peak is about twice that again while a save buffers the snapshot and its ciphertext.
    ///
    /// Asserts the REFUSAL (a state), never a measured allocation — a memory-threshold assertion
    /// would be a wall-clock-style flake in a different costume. The create half additionally pins
    /// that the file is not left behind, which is what proves the check happens BEFORE the work.
    ///
    /// Neuter by removing either bound and the corresponding half succeeds → RED.
    #[test]
    fn a_container_over_the_ram_ceiling_is_refused_at_both_create_and_load() {
        let root = tmp("ram-ceiling");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let cpath = root.join("container.dat");

        let err = Container::create(&cpath, MAX_CONTAINER_BYTES + 1, b"realpw", 60 * 1024)
            .err()
            .expect("a container over the ceiling must be refused")
            .to_string();
        assert!(err.contains("exceeds"), "the error must name the ceiling, got: {err}");
        assert!(!cpath.exists(), "nothing may be created for a size we refuse — the check precedes the work");

        // Control: the same call at a sane size succeeds, so the refusal is about the size and not
        // about the path or arguments.
        drop(Container::create(&cpath, 128 * 1024, b"realpw", 60 * 1024).unwrap());

        // The load half: a SPARSE file (no blocks allocated) that merely reports an over-ceiling
        // length must be refused by the stat, before `read` turns its length into an allocation.
        let big = root.join("big.dat");
        std::fs::File::create(&big).unwrap().set_len(MAX_CONTAINER_BYTES + 1).unwrap();
        let err = Container::load(&big).err().expect("an over-ceiling file must be refused");
        assert_eq!(
            err.kind(),
            io::ErrorKind::OutOfMemory,
            "an over-ceiling container must not be reportable as a wrong password, got: {err}"
        );
        assert!(err.to_string().contains("maximum"), "the error must name the ceiling, got: {err}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
