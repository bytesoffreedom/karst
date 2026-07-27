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
//! - P1 (protect) and P3 (blind) wrap the SAME main region key, differing only by a
//!   policy flag + write ceiling; revealing P3 cannot expose P1 or P2.

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
const LEN_HDR: usize = 24 + 8 + 16;
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
pub fn snapshot_dir(dir: &Path) -> io::Result<Vec<u8>> {
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    fn walk(base: &Path, cur: &Path, out: &mut Vec<(String, Vec<u8>)>) -> io::Result<()> {
        for entry in std::fs::read_dir(cur)? {
            let entry = entry?;
            let path = entry.path();
            let ty = entry.file_type()?;
            if ty.is_dir() {
                walk(base, &path, out)?;
            } else if ty.is_file() {
                let rel = path
                    .strip_prefix(base)
                    .map_err(io_err)?
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push((rel, std::fs::read(&path)?));
            }
        }
        Ok(())
    }
    if dir.exists() {
        walk(dir, dir, &mut files)?;
    }
    files.sort_by(|a, b| a.0.cmp(&b.0)); // deterministic order (stable snapshots)
    postcard::to_stdvec(&files).map_err(io_err)
}

/// Rebuild an account directory from a `snapshot_dir` blob. Recreates every file (and parent
/// dirs) under `dir`. Rejects unsafe relative paths (absolute or `..`) defensively.
pub fn restore_dir(dir: &Path, blob: &[u8]) -> io::Result<()> {
    if blob.is_empty() {
        return Ok(()); // a freshly-created, empty compartment — nothing to restore
    }
    let files: Vec<(String, Vec<u8>)> = postcard::from_bytes(blob).map_err(io_err)?;
    for (rel, bytes) in files {
        if rel.starts_with('/') || rel.split('/').any(|p| p == ".." || p.is_empty()) {
            return Err(io_err("unsafe path in snapshot"));
        }
        let path = dir.join(&rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &bytes)?;
    }
    Ok(())
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Policy {
    /// P1: main confined to its A-cap; never writes the hidden tail.
    Protect,
    /// P3: main allowed the whole container; may overwrite the hidden tail (accepted risk).
    Blind,
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
            Policy::Blind => 2,
            Policy::None => 0,
        }
    }
    fn from_byte(b: u8) -> Policy {
        match b {
            1 => Policy::Protect,
            2 => Policy::Blind,
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

/// The whole container file, held in memory (fixed size, so bounded). Every mutation is
/// persisted by a crash-safe temp-swap that preserves untouched regions byte-for-byte.
pub struct Container {
    path: PathBuf,
    buf: Vec<u8>,
}

fn random_bytes(n: usize) -> Vec<u8> {
    use chacha20poly1305::aead::rand_core::RngCore;
    use chacha20poly1305::aead::OsRng;
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

/// A fresh random region key. It is NOT password-derived — the random bytes ARE the key,
/// so there is no reason to run Argon2 over them (that would be pure expense).
fn random_key() -> MasterKey {
    let mut k = [0u8; 32];
    k.copy_from_slice(&random_bytes(32));
    MasterKey::from_bytes(k)
}

impl Container {
    fn slot_span(i: usize) -> (usize, usize) {
        let off = SALT_LEN + i * SLOT_LEN;
        (off, off + SLOT_LEN)
    }
    fn salt(&self) -> &[u8] {
        &self.buf[..SALT_LEN]
    }

    /// Create a fresh container of exactly `total` bytes, entirely random, with the main
    /// account's P1 (protect) password installed. `main_cap` (bytes, the "A" reserve) is
    /// the protect-mode write ceiling for the main region. The tail after the main region
    /// is reserved for a future hidden compartment (indistinguishable random until then).
    pub fn create(path: &Path, total: u64, main_password: &[u8], main_cap: u64) -> io::Result<Self> {
        let total = total as usize;
        if total < DATA_OFF + LEN_HDR + 64 {
            return Err(io_err("container size too small"));
        }
        let main_cap = main_cap as usize;
        if main_cap < LEN_HDR + 32 || DATA_OFF + main_cap > total {
            return Err(io_err("main_cap out of range for this container size"));
        }
        let mut buf = random_bytes(total); // salt prefix + all slots + dir + all regions start random
        let main_off = DATA_OFF;
        let region_key = random_key();
        let mut c = Container {
            path: path.to_path_buf(),
            buf: std::mem::take(&mut buf),
        };
        // Seal an empty payload so a fresh main region reads back as empty (not garbage).
        Self::write_region_at(&mut c.buf, main_off, main_cap, &region_key, &[])?;
        c.seal_slot(0, Role::Main, Policy::Protect, main_password, main_off as u64, main_cap as u64, &region_key)?;
        let mgmt = c.key_for(main_password)?;
        c.write_dir(&mgmt, &[0])?; // slot 0 is the management/main slot
        c.persist()?;
        Ok(c)
    }

    /// Load an existing container file into memory.
    pub fn load(path: &Path) -> io::Result<Self> {
        // A crash mid-persist can leave a full-size `.tmp` copy (harmless — also random —
        // but tidy it so there aren't two container-shaped blobs lying around).
        let _ = std::fs::remove_file(path.with_extension("tmp"));
        let buf = std::fs::read(path)?;
        if buf.len() < HEADER_LEN + LEN_HDR {
            return Err(io_err("not a container (too small)"));
        }
        Ok(Container {
            path: path.to_path_buf(),
            buf,
        })
    }

    fn key_for(&self, password: &[u8]) -> io::Result<MasterKey> {
        MasterKey::derive(password, self.salt()).map_err(io_err)
    }

    /// Trial-open every slot with this password; return the first that authenticates.
    fn find_slot(&self, key: &MasterKey) -> Option<SlotInfo> {
        for i in 0..SLOT_COUNT {
            let (a, b) = Self::slot_span(i);
            let Ok(plain) = key.open_raw(&self.buf[a..b]) else {
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
        let sealed = key.seal_raw(&plain);
        debug_assert_eq!(sealed.len(), SLOT_LEN);
        let (a, b) = Self::slot_span(index);
        self.buf[a..b].copy_from_slice(&sealed);
        Ok(())
    }

    /// Read the used-slot list (sealed under the management key). `Err` = wrong key.
    fn read_dir(&self, mgmt_key: &MasterKey) -> io::Result<Vec<usize>> {
        let plain = mgmt_key
            .open_raw(&self.buf[DIR_OFF..DIR_OFF + DIR_LEN])
            .map_err(|_| io_err("wrong management password"))?;
        Ok(plain.iter().filter(|&&b| (b as usize) < SLOT_COUNT).map(|&b| b as usize).collect())
    }

    /// Seal the used-slot list under the management key. Unused entries are 0xFF.
    fn write_dir(&mut self, mgmt_key: &MasterKey, used: &[usize]) -> io::Result<()> {
        let mut plain = [0xFFu8; SLOT_COUNT];
        for (i, &idx) in used.iter().take(SLOT_COUNT).enumerate() {
            plain[i] = idx as u8;
        }
        let sealed = mgmt_key.seal_raw(&plain);
        debug_assert_eq!(sealed.len(), DIR_LEN);
        self.buf[DIR_OFF..DIR_OFF + DIR_LEN].copy_from_slice(&sealed);
        Ok(())
    }

    /// A free slot index not in the management directory. Random start → no order signal.
    fn free_slot(&self, used: &[usize]) -> Option<usize> {
        let start = (random_bytes(1)[0] as usize) % SLOT_COUNT;
        (0..SLOT_COUNT)
            .map(|k| (start + k) % SLOT_COUNT)
            .find(|i| !used.contains(i))
    }

    /// Add the P3 (blind) alias for the main account: give an existing main password to
    /// learn the shared region key, then seal a new slot with the SAME region but a
    /// `Blind` policy and a wider write ceiling (`blind_cap`, the "A+B" that may spill
    /// into the hidden tail).
    pub fn add_blind_main(&mut self, existing_main_password: &[u8], p3_password: &[u8], blind_cap: u64) -> io::Result<()> {
        let key = self.key_for(existing_main_password)?;
        let info = self.find_slot(&key).ok_or_else(|| io_err("wrong main password"))?;
        if info.role != Role::Main {
            return Err(io_err("not a main password"));
        }
        if blind_cap as usize > self.buf.len().saturating_sub(info.region_off as usize) {
            return Err(io_err("blind_cap exceeds container"));
        }
        let p3key = self.key_for(p3_password)?;
        if self.find_slot(&p3key).is_some() {
            return Err(io_err("that password is already in use"));
        }
        let mut used = self.read_dir(&key)?;
        let idx = self.free_slot(&used).ok_or_else(|| io_err("no free slot"))?;
        self.seal_slot(idx, Role::Main, Policy::Blind, p3_password, info.region_off, blind_cap, &info.region_key)?;
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
        if hidden_cap < LEN_HDR + 32 || hidden_off as usize + hidden_cap > self.buf.len() {
            return Err(io_err("hidden region does not fit after the main region"));
        }
        let hkey = self.key_for(hidden_password)?;
        if self.find_slot(&hkey).is_some() {
            return Err(io_err("that password is already in use"));
        }
        let region_key = random_key();
        Self::write_region_at(&mut self.buf, hidden_off as usize, hidden_cap, &region_key, &[])?;
        let mut used = self.read_dir(&mkey)?;
        let idx = self.free_slot(&used).ok_or_else(|| io_err("no free slot"))?;
        self.seal_slot(idx, Role::Hidden, Policy::None, hidden_password, hidden_off, hidden_cap as u64, &region_key)?;
        used.push(idx);
        self.write_dir(&mkey, &used)?;
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
        let payload = Self::read_region_at(&self.buf, info.region_off as usize, &info.region_key)?;
        Ok(Opened::Compartment {
            role: info.role,
            policy: info.policy,
            payload,
            region_key: info.region_key,
        })
    }

    /// Write the account-state payload for the compartment this password opens. Honors the
    /// slot's write ceiling: Protect refuses to exceed its cap; Blind may spill past the
    /// main region into the hidden tail (accepted risk — corrupts the hidden compartment).
    pub fn write(&mut self, password: &[u8], payload: &[u8]) -> io::Result<()> {
        let key = self.key_for(password)?;
        let info = self
            .find_slot(&key)
            .ok_or_else(|| io_err("wrong password or no such compartment"))?;
        if info.role == Role::Wipe {
            return Err(io_err("wipe password cannot write"));
        }
        let need = LEN_HDR + 24 + payload.len() + 16;
        if need > info.region_cap as usize {
            // Protect cap reached (or Blind exhausted the whole container).
            return Err(io_err("payload exceeds the write ceiling for this password"));
        }
        let off = info.region_off as usize;
        let n = Self::write_region_at(&mut self.buf, off, info.region_cap as usize, &info.region_key, payload)?;
        // Hot path (called on every message save): write ONLY this region's changed bytes in
        // place, so a 10 GB container doesn't get fully rewritten per save. Other regions —
        // including the hidden tail under a Protect write — are untouched on disk.
        self.persist_range(off, n)
    }

    // ---- region primitives (format (b): [len-header][one sealed blob], length hidden) ----

    /// Returns the number of bytes changed at `off` (`LEN_HDR + ciphertext`), so the caller can
    /// persist ONLY that range instead of the whole file.
    fn write_region_at(buf: &mut [u8], off: usize, cap: usize, region_key: &MasterKey, payload: &[u8]) -> io::Result<usize> {
        let ct = region_key.seal_raw(payload);
        if LEN_HDR + ct.len() > cap {
            return Err(io_err("payload exceeds region capacity"));
        }
        let len_hdr = region_key.seal_raw(&(ct.len() as u64).to_le_bytes());
        debug_assert_eq!(len_hdr.len(), LEN_HDR);
        if off + LEN_HDR + ct.len() > buf.len() {
            return Err(io_err("region write out of bounds"));
        }
        buf[off..off + LEN_HDR].copy_from_slice(&len_hdr);
        buf[off + LEN_HDR..off + LEN_HDR + ct.len()].copy_from_slice(&ct);
        // Bytes after the ciphertext are left as-is (leftover random) → logical length hidden.
        Ok(LEN_HDR + ct.len())
    }

    fn read_region_at(buf: &[u8], off: usize, region_key: &MasterKey) -> io::Result<Vec<u8>> {
        if off + LEN_HDR > buf.len() {
            return Err(io_err("region out of bounds"));
        }
        let len_bytes = region_key
            .open_raw(&buf[off..off + LEN_HDR])
            .map_err(|_| io_err("region length header corrupt / wrong key"))?;
        if len_bytes.len() != 8 {
            return Err(io_err("bad region length header"));
        }
        let ct_len = u64::from_le_bytes(len_bytes.as_slice().try_into().unwrap()) as usize;
        let start = off + LEN_HDR;
        if start + ct_len > buf.len() {
            return Err(io_err("region payload out of bounds (corrupt?)"));
        }
        region_key
            .open_raw(&buf[start..start + ct_len])
            .map_err(|_| io_err("region payload corrupt / wrong key"))
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

    /// Read the u64 sealed at `[off, off+LEN_HDR)` under `key`.
    #[allow(dead_code)]
    fn read_sealed_u64(buf: &[u8], off: usize, key: &MasterKey) -> io::Result<u64> {
        if off + LEN_HDR > buf.len() {
            return Err(io_err("sealed u64 out of bounds"));
        }
        let b = key.open_raw(&buf[off..off + LEN_HDR]).map_err(|_| io_err("wrong key / corrupt"))?;
        if b.len() != 8 {
            return Err(io_err("bad sealed u64"));
        }
        Ok(u64::from_le_bytes(b.as_slice().try_into().unwrap()))
    }

    #[allow(dead_code)]
    fn write_sealed_u64(buf: &mut [u8], off: usize, key: &MasterKey, v: u64) {
        let sealed = key.seal_raw(&v.to_le_bytes());
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
        let ct = key.seal_raw(payload);
        let lh = key.seal_raw(&(ct.len() as u64).to_le_bytes());
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
                .open_raw(&buf[cstart..cstart + ct_len])
                .map_err(|_| io_err("append-log chunk corrupt / wrong key"))?;
            out.push(payload);
            p += LEN_HDR + ct_len;
        }
        Ok(out)
    }

    /// Crash-safe persist: write the whole buffer to a temp file, fsync, atomically rename.
    /// Untouched regions (e.g. the hidden tail during a Protect-mode main write) are copied
    /// byte-for-byte, so this never perturbs another compartment.
    fn persist(&self) -> io::Result<()> {
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
        std::fs::rename(&tmp, &self.path)
    }

    /// Persist ONLY `buf[off..off+len]` in place (seek + write), for the hot region-write path
    /// where a whole-file rewrite would be ruinous at multi-GB sizes. Honest tradeoff: this is
    /// not crash-atomic — a crash mid-write can lose that single save (the region reads corrupt
    /// until the next successful save), the same "last write didn't finish" risk any app has.
    /// Structural changes (create/add_*/wipe) still go through the crash-safe whole-file swap.
    fn persist_range(&self, off: usize, len: usize) -> io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new().write(true).open(&self.path)?;
        f.seek(SeekFrom::Start(off as u64))?;
        f.write_all(&self.buf[off..off + len])?;
        f.sync_all()
    }

    /// Crypto-erase: overwrite the whole file with fresh random (destroys every region and
    /// slot at once — the wipe password's effect). After this, opening any password fails.
    pub fn wipe(&mut self) -> io::Result<()> {
        self.buf = random_bytes(self.buf.len());
        self.persist()
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
                std::fs::create_dir_all(&work_dir)?;
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
    pub fn save(&mut self) -> io::Result<()> {
        let blob = snapshot_dir(&self.work_dir)?;
        self.container.write(&self.password, &blob)
    }

    /// The container's random salt prefix — use it to derive the account's at-rest key, so that key
    /// has a PER-CONTAINER random salt (not a fixed, precomputation-friendly one shared across installs).
    pub fn salt(&self) -> Vec<u8> {
        self.container.salt().to_vec()
    }

    /// Add a HIDDEN account to this container, from an open MAIN session. Reuses the ONE held
    /// container instance (no two-writers-over-one-file hazard): places the hidden region in all
    /// space remaining after the main region, then calls `build(&region_key)` — the caller builds the
    /// empty account's files sealed under the hidden region's key (so its own password opens them) and
    /// returns the snapshot, which is written into the hidden region. The caller wipes its RAM build.
    pub fn add_hidden<F>(&mut self, hidden_password: &[u8], build: F) -> io::Result<()>
    where
        F: FnOnce(&MasterKey) -> io::Result<Vec<u8>>,
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
        let snapshot = build(&region_key)?;
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
/// and reports `Wiped`; a HIDDEN account is materialized into `hidden_work` (the caller passes a
/// RAM/tmpfs path so no plaintext hits the real disk); a main account into `main_work`. Wrong
/// password / no such compartment → `Err` (indistinguishable).
pub fn open_container(path: &Path, password: &[u8], main_work: PathBuf, hidden_work: PathBuf) -> io::Result<Unlocked> {
    let mut container = Container::load(path)?;
    match container.open(password)? {
        Opened::Wipe => {
            container.wipe()?;
            Ok(Unlocked::Wiped)
        }
        Opened::Compartment { role, policy, payload, region_key } => {
            let work_dir = if role == Role::Hidden { hidden_work } else { main_work };
            std::fs::create_dir_all(&work_dir)?;
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
        Container::write_region_at(buf, self.off, self.core_cap, key, &[])?;
        Container::log_init(buf, self.log_off(), key);
        Ok(())
    }
    /// Replace the mutable core (re-sealed in place; refuses to exceed `core_cap`).
    fn write_core(&self, buf: &mut [u8], key: &MasterKey, blob: &[u8]) -> io::Result<()> {
        Container::write_region_at(buf, self.off, self.core_cap, key, blob).map(|_| ())
    }
    fn read_core(&self, buf: &[u8], key: &MasterKey) -> io::Result<Vec<u8>> {
        Container::read_region_at(buf, self.off, key)
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
        std::env::temp_dir().join(format!("karst-cont-{}-{}", tag, std::process::id()))
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
        c.add_blind_main(b"realpw", b"blindpw", (main_cap + hidden_cap) as u64).unwrap();
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

        // 3) P3 opens the SAME main account (same data), but Blind policy.
        match c.open(b"blindpw").unwrap() {
            Opened::Compartment { role, policy, payload, .. } => {
                assert_eq!(role, Role::Main);
                assert_eq!(policy, Policy::Blind);
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

    /// P1 (protect) never corrupts the hidden tail; P3 (blind) spilling past A does.
    #[test]
    fn protect_preserves_hidden_blind_may_corrupt() {
        let p = tmp("spill");
        let _ = std::fs::remove_file(&p);
        let total = 256 * 1024;
        let main_cap = 64 * 1024;
        let hidden_cap = 160 * 1024;
        let mut c = Container::create(&p, total, b"realpw", main_cap as u64).unwrap();
        c.add_hidden(b"realpw", b"hiddenpw", hidden_cap as u64).unwrap();
        c.add_blind_main(b"realpw", b"blindpw", (main_cap + hidden_cap) as u64).unwrap();
        c.write(b"hiddenpw", b"the launch codes").unwrap();

        // P1 write that fits within A: hidden survives.
        c.write(b"realpw", &vec![7u8; 20 * 1024]).unwrap();
        assert!(matches!(c.open(b"hiddenpw").unwrap(), Opened::Compartment { .. }), "protect kept hidden intact");

        // P1 refuses to exceed its A cap (so it can never reach the tail).
        assert!(c.write(b"realpw", &vec![7u8; main_cap]).is_err(), "protect refuses to exceed A");

        // P3 blind write big enough to spill past A into the hidden region → hidden corrupts.
        c.write(b"blindpw", &vec![9u8; (main_cap + 40 * 1024)]).unwrap();
        assert!(c.open(b"hiddenpw").is_err(), "blind spill overwrote the hidden compartment");

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
        c.add_blind_main(b"realpw", b"blindpw", 192 * 1024).unwrap();

        // P1 (management) can read the directory; P3 and the hidden password cannot.
        assert!(c.read_dir(&c.key_for(b"realpw").unwrap()).is_ok(), "P1 manages slots");
        assert!(c.read_dir(&c.key_for(b"blindpw").unwrap()).is_err(), "P3 reveal must NOT expose the slot directory");
        assert!(c.read_dir(&c.key_for(b"hiddenpw").unwrap()).is_err(), "hidden password must NOT expose the slot directory");

        // A coercer given P3 opens main and sees nothing that proves a hidden compartment.
        assert!(matches!(c.open(b"blindpw").unwrap(), Opened::Compartment { role: Role::Main, .. }));
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

        let blob = snapshot_dir(&acct).unwrap();

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
        assert_eq!(snapshot_dir(&restored).unwrap(), blob);
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
        let hidden_snapshot = snapshot_dir(&hb).unwrap();

        {
            let mut cv = ContainerVault::open(&cpath, b"realpw", root.join("mw")).unwrap();
            std::fs::write(cv.work_dir.join("contacts.dat"), b"main contacts").unwrap();
            cv.save().unwrap();
            cv.add_hidden(b"hiddenpw", |_| Ok(hidden_snapshot.clone())).unwrap();
            cv.save().unwrap(); // a later MAIN flush must NOT clobber the hidden region
        }

        // The hidden password opens the hidden account.
        match open_container(&cpath, b"hiddenpw", root.join("mw2"), root.join("hw")).unwrap() {
            Unlocked::Account(cv) => {
                assert_eq!(cv.role, Role::Hidden);
                assert_eq!(std::fs::read(cv.work_dir.join("seed.key")).unwrap(), b"hidden seed material");
            }
            _ => panic!("hiddenpw → hidden account"),
        }
        // The main account still opens intact.
        match open_container(&cpath, b"realpw", root.join("mw3"), root.join("hw3")).unwrap() {
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
        let snap = snapshot_dir(&hb).unwrap();
        {
            let mut cv = ContainerVault::open(&cpath, b"mainpw", root.join("mw")).unwrap();
            cv.add_hidden(b"hiddenpw", |_| Ok(snap.clone())).unwrap();
            cv.add_blind(b"coverpw").unwrap();
            cv.add_wipe(b"burnpw").unwrap();
        }
        // Cover password opens the MAIN account…
        match open_container(&cpath, b"coverpw", root.join("mw2"), root.join("hw")).unwrap() {
            Unlocked::Account(cv) => assert_eq!(cv.role, Role::Main),
            _ => panic!("coverpw → main"),
        }
        // …but its key CANNOT read the management directory (so revealing it can't detect the hidden acct).
        let c = Container::load(&cpath).unwrap();
        assert!(c.read_dir(&c.key_for(b"coverpw").unwrap()).is_err(), "cover password must not expose the slot directory");
        assert!(c.read_dir(&c.key_for(b"mainpw").unwrap()).is_ok(), "the main password manages slots");
        // Wipe erases the whole container.
        assert!(matches!(open_container(&cpath, b"burnpw", root.join("mw3"), root.join("hw3")).unwrap(), Unlocked::Wiped));
        assert!(open_container(&cpath, b"mainpw", root.join("mw4"), root.join("hw4")).is_err());
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
        match open_container(&cpath, b"coverpw", root.join("cw"), root.join("hw")).unwrap() {
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
            c.add_blind_main(b"realpw", b"blindpw", 192 * 1024).unwrap();
            c.add_wipe(b"realpw", b"burnpw").unwrap();
        }

        match open_container(&cpath, b"realpw", main_w.clone(), hid_w.clone()).unwrap() {
            Unlocked::Account(cv) => { assert_eq!(cv.role, Role::Main); assert_eq!(cv.work_dir, main_w); }
            _ => panic!("realpw → main"),
        }
        match open_container(&cpath, b"hiddenpw", main_w.clone(), hid_w.clone()).unwrap() {
            Unlocked::Account(cv) => { assert_eq!(cv.role, Role::Hidden); assert_eq!(cv.work_dir, hid_w); }
            _ => panic!("hiddenpw → hidden (tmpfs work dir)"),
        }
        match open_container(&cpath, b"blindpw", main_w.clone(), hid_w.clone()).unwrap() {
            Unlocked::Account(cv) => { assert_eq!(cv.role, Role::Main); assert_eq!(cv.policy, Policy::Blind); }
            _ => panic!("blindpw → main/blind"),
        }
        // Wipe erases the whole container.
        assert!(matches!(open_container(&cpath, b"burnpw", main_w.clone(), hid_w.clone()).unwrap(), Unlocked::Wiped));
        assert!(open_container(&cpath, b"realpw", main_w, hid_w).is_err(), "container wiped → nothing opens");
        let _ = std::fs::remove_dir_all(&root);
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
        let c = Container::load(&p).unwrap();
        assert!(c.open(b"realpw").is_err(), "wipe erased the real compartment");
        let _ = std::fs::remove_file(&p);
    }
}
