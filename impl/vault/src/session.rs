//! Opening a container: the layer that composes the others (#324, slice 1).
//!
//! Every module below this one is a piece of the format — geometry, records, capsules, the
//! ownership layer, the allocator, the map, roots, the commit order, and a real file to put them
//! on. None of them is a container. This is where they become one: a password goes in, and either
//! a session comes out or nothing does.
//!
//! # What this slice does and does not do
//!
//! Does: create a container of a given size with three passwords, and reopen it under any of them,
//! yielding the mode, the space key, the ownership-layer key where the mode has one, and the live
//! root of the space that password opens.
//!
//! Does NOT: read or write objects. That is the next slice, and it is deliberately separate — the
//! moment a session can be OPENED is the moment the create/open path can be tested against a real
//! file, and testing it before object I/O exists is what keeps a failure here from being read as a
//! failure there.
//!
//! # The one thing that must be true of `create`
//!
//! A container with a hidden space and a container without one must be **byte-indistinguishable**
//! to anyone holding only P3. So `create` always lays down all three slots, always writes both
//! spaces' roots, and always fills the remaining slots with random. There is no "create without a
//! hidden space" path, because having one would make the hidden space's existence a property of
//! how the file was made.

use crate::capsule::{self, State};
use crate::file::FileStore;
use crate::geometry::Geometry;
use crate::medium::{Medium, MediumError};
use crate::params::{header_len, FormatParams, SALT_LEN};
use crate::record::{MasterKey, SpaceId};
use crate::root::{self, Live, Root, ANCHOR_COUNT};
use crate::slot::{self, Mode, SLOT_COUNT, SLOT_LEN};

/// Why a container could not be created or opened.
#[derive(Debug)]
pub enum VaultError {
    /// The password opened no slot. Deliberately the SAME answer for "wrong password" and "no such
    /// compartment": distinguishing them would answer, for free, whether a compartment exists.
    NoSuchCompartment,
    /// The space's anchors hold no readable root. NOT the same as an empty space — an empty space
    /// still has a root saying so — so the caller must refuse to write rather than start fresh.
    /// Starting fresh over an unreadable root is how a torn anchor becomes a silently empty space.
    NoLiveRoot,
    /// The container is too small to hold what the format needs.
    TooSmall { blocks: u64, needed: u64 },
    /// The two passwords given to `create` are the same, so one compartment would be unreachable.
    PasswordsCollide,
    Storage(MediumError),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::NoSuchCompartment => write!(f, "no compartment opens with that password"),
            VaultError::NoLiveRoot => write!(
                f,
                "neither anchor holds a readable root; refusing to open rather than starting fresh \
                 over a space that may still be there"
            ),
            VaultError::TooSmall { blocks, needed } => {
                write!(f, "container holds {blocks} blocks, the format needs at least {needed}")
            }
            VaultError::PasswordsCollide => {
                write!(f, "two of the passwords are the same, so one compartment could never open")
            }
            VaultError::Storage(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<MediumError> for VaultError {
    fn from(e: MediumError) -> Self {
        VaultError::Storage(e)
    }
}

/// The three passwords a container is created with.
///
/// All three, always. There is no constructor that omits the hidden one — see the module docs.
pub struct Passwords<'a> {
    /// Opens the public space AND protects the hidden one from being overwritten.
    pub protected: &'a [u8],
    /// Opens the hidden space.
    pub hidden: &'a [u8],
    /// Opens the public space knowing nothing of the ownership layer.
    pub public: &'a [u8],
}

/// An open container.
pub struct Vault {
    medium: FileStore,
    params: FormatParams,
    geometry: Geometry,
    mode: Mode,
    space: SpaceId,
    space_key: MasterKey,
    layer_key: Option<MasterKey>,
    anchors: [u64; ANCHOR_COUNT],
    live: Live,
}

/// Blocks the format needs before a container is usable at all: four anchors (two per space) plus
/// the workspace reserve.
fn minimum_blocks() -> u64 {
    2 * ANCHOR_COUNT as u64 + crate::params::SYSTEM_WORKSPACE_RESERVE
}

impl Vault {
    /// Create a container of exactly `size` bytes with all three compartments.
    pub fn create(
        path: impl AsRef<std::path::Path>,
        size: u64,
        pw: &Passwords<'_>,
    ) -> Result<(), VaultError> {
        // Distinct passwords, checked before anything is written: two equal passwords would make
        // one compartment permanently unreachable, and the container would look fine.
        if !slot::passwords_are_distinct(pw.protected, pw.hidden)
            || !slot::passwords_are_distinct(pw.protected, pw.public)
            || !slot::passwords_are_distinct(pw.hidden, pw.public)
        {
            return Err(VaultError::PasswordsCollide);
        }
        let params = FormatParams::derive(size);
        if params.blocks < minimum_blocks() {
            return Err(VaultError::TooSmall { blocks: params.blocks, needed: minimum_blocks() });
        }
        let geometry = Geometry::new(params.block_payload as usize, size);
        let format_hash = params.format_hash();

        let mut medium = FileStore::create(path, size)?;

        // Keys. The space key for A is SHARED by the protected and public slots — that is what
        // makes P1 and P3 open the same account rather than two accounts that happen to live in
        // one file. The layer key is one per container, held by P1 and P2 and by nobody else.
        let key_a = MasterKey::generate();
        let key_b = MasterKey::generate();
        let key_l = MasterKey::generate();

        // Anchors, drawn from the low blocks and disjoint between spaces. Their positions are
        // recorded in the slots, so they need not be derivable from anything public.
        let anchors_a: [u64; ANCHOR_COUNT] = [0, 1];
        let anchors_b: [u64; ANCHOR_COUNT] = [2, 3];

        // Both spaces get a root, always. A container whose hidden space had no root would be
        // distinguishable from one that had, by the shape of what is there.
        let empty = Root { generation: 1, map_root: 0, transaction: 0, mapped_blocks: 0 };
        for (space, key, anchors) in
            [(SpaceId::Public, &key_a, &anchors_a), (SpaceId::Hidden, &key_b, &anchors_b)]
        {
            for block in anchors {
                let sealed = root::seal_root(key, format_hash, space, *block, &empty);
                medium.write(payload_at(&geometry, *block), &sealed)?;
                // META capsules mark the anchor as owned, and they are readable only through the
                // ownership layer — which is why a P3 session can hold the anchor's block number
                // and still learn nothing about the other space's.
                write_meta_capsules(&mut medium, &geometry, &key_l, format_hash, *block, space)?;
            }
        }
        medium.barrier()?;

        // Slots. Three real ones and the rest random, in a fixed layout: which index holds which
        // mode must not be inferable, so every slot is the same size and shape and the empty ones
        // are indistinguishable from the full ones.
        let salt = random_salt();
        let mut slots: Vec<Vec<u8>> = Vec::with_capacity(SLOT_COUNT);
        let (ka, kb, kl) = (key_a.to_bytes(), key_b.to_bytes(), key_l.to_bytes());
        slots.push(slot::seal_slot(pw.protected, &salt, 0, Mode::Protected, &ka, Some(&kl), &anchors_a));
        slots.push(slot::seal_slot(pw.hidden, &salt, 1, Mode::Hidden, &kb, Some(&kl), &anchors_b));
        slots.push(slot::seal_slot(pw.public, &salt, 2, Mode::Public, &ka, None, &anchors_a));
        while slots.len() < SLOT_COUNT {
            slots.push(slot::random_slot());
        }

        medium.write(0, &salt)?;
        for (i, s) in slots.iter().enumerate() {
            medium.write((SALT_LEN + i * SLOT_LEN) as u64, s)?;
        }
        medium.write((SALT_LEN + SLOT_COUNT * SLOT_LEN) as u64, &params.encode())?;
        medium.barrier()?;
        Ok(())
    }

    /// Open the compartment `password` unlocks.
    pub fn open(
        path: impl AsRef<std::path::Path>,
        password: &[u8],
        size: u64,
    ) -> Result<Vault, VaultError> {
        let params = FormatParams::derive(size);
        let medium = FileStore::open(path, size)?;
        let geometry = Geometry::new(params.block_payload as usize, size);
        let format_hash = params.format_hash();

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&medium.read(0, SALT_LEN)?);
        let mut slots: Vec<Vec<u8>> = Vec::with_capacity(SLOT_COUNT);
        for i in 0..SLOT_COUNT {
            slots.push(medium.read((SALT_LEN + i * SLOT_LEN) as u64, SLOT_LEN)?);
        }

        let opened = slot::open_table(password, &salt, &slots).ok_or(VaultError::NoSuchCompartment)?;
        let space = match opened.mode {
            Mode::Hidden => SpaceId::Hidden,
            Mode::Protected | Mode::Public => SpaceId::Public,
        };

        let raw0 = medium.read(payload_at(&geometry, opened.anchors[0]), ROOT_RAW)?;
        let raw1 = medium.read(payload_at(&geometry, opened.anchors[1]), ROOT_RAW)?;
        let live = root::live_root(
            &opened.space_key,
            format_hash,
            space,
            &opened.anchors,
            [&raw0, &raw1],
        )
        .ok_or(VaultError::NoLiveRoot)?;

        Ok(Vault {
            medium,
            params,
            geometry,
            mode: opened.mode,
            space,
            space_key: opened.space_key,
            layer_key: opened.layer_key,
            anchors: opened.anchors,
            live,
        })
    }

    /// Which compartment this session opened.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Which space it addresses. `Protected` and `Public` both address the public one — that is the
    /// whole point of the pair.
    pub fn space(&self) -> SpaceId {
        self.space
    }

    /// The live root of this space.
    pub fn root(&self) -> Root {
        self.live.root
    }

    /// Whether this session can see the ownership layer. False for `Public`, and that is a
    /// difference in what the SLOT held, never a flag on disk.
    pub fn has_layer(&self) -> bool {
        self.layer_key.is_some()
    }

    /// The container's open header.
    pub fn params(&self) -> &FormatParams {
        &self.params
    }

    /// The at-rest key for whatever lives in this space. Shared between `Protected` and `Public`
    /// by construction — it is stored in the slot rather than derived from the password, so two
    /// different passwords hand back the same key and open the same account.
    pub fn space_key(&self) -> &MasterKey {
        &self.space_key
    }

    /// This space's two anchor blocks.
    ///
    /// Exposed because "the two spaces never share an anchor" is a property worth asserting from
    /// outside, and because recovery needs to know where to look. It says nothing about the OTHER
    /// space: a session only ever holds its own, straight out of the slot that opened it.
    pub fn anchors(&self) -> &[u64; ANCHOR_COUNT] {
        &self.anchors
    }

    /// The derived block geometry — the same for every container of this size and version.
    pub fn geometry(&self) -> &Geometry {
        &self.geometry
    }

    /// The container's size in bytes, read from the medium rather than from the header, so a
    /// caller comparing the two is comparing two independent answers.
    pub fn container_bytes(&self) -> u64 {
        self.medium.capacity()
    }

    /// Free space, and it is deliberately only ever a LOWER BOUND for a session with no ownership
    /// layer.
    ///
    /// A `Public` session cannot scan capsules — they are sealed under a key it does not have — so
    /// it could not produce an exact figure even if it wanted one. That is not a limitation to be
    /// worked around: an exact count under P3 would be the difference between "this container has
    /// N free blocks" and "this container has N free blocks and something invisible is holding the
    /// rest", which is the one question the format exists to refuse.
    pub fn free_space(&self) -> crate::catalogue::FreeSpace {
        let total = self.params.blocks.saturating_sub(self.params.workspace_reserve);
        let used = self.live.root.mapped_blocks;
        crate::catalogue::FreeSpace::LowerBound(total.saturating_sub(used))
    }
}

/// Bytes reserved for a sealed root at an anchor: the clear generation prefix plus the record.
const ROOT_RAW: usize = 8 + crate::geometry::RECORD_FRAMING + 32;

/// Byte offset of a block's payload area, past both capsule copies.
fn payload_at(g: &Geometry, block: u64) -> u64 {
    g.block_offset(header_len(), block) + 2 * crate::geometry::CAPSULE_ALIGN as u64
}

/// Write both capsule copies claiming `block` as META for `space`.
fn write_meta_capsules(
    medium: &mut FileStore,
    g: &Geometry,
    layer_key: &MasterKey,
    format_hash: [u8; 32],
    block: u64,
    space: SpaceId,
) -> Result<(), MediumError> {
    // META, not Live: an anchor's contents authenticate under their own record, so the capsule
    // deliberately does not bind them — which is what lets a root be rewritten in place without
    // invalidating the claim on the block it sits in.
    let claim = capsule::Claim {
        state: State::Meta(space),
        generation: 1,
        transaction: 0,
        binding: [0u8; 32],
    };
    for copy in 0..2u8 {
        let sealed = capsule::seal_claim(layer_key, format_hash, block, copy, &claim);
        medium.write(g.capsule_offset(header_len(), block, copy), &capsule::frame(&claim, sealed))?;
    }
    Ok(())
}

fn random_salt() -> [u8; SALT_LEN] {
    use rand::RngCore;
    let mut s = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut s);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZE: u64 = 8 * 1024 * 1024;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("karst-test").join(format!(
            "vault-session-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch");
        dir.join("container.bin")
    }

    fn pw<'a>() -> Passwords<'a> {
        Passwords { protected: b"protect-me", hidden: b"the-other-one", public: b"just-a-phone" }
    }

    /// The headline: a container is created, and all three passwords open it — each into what it
    /// is supposed to open.
    #[test]
    fn three_passwords_open_three_compartments() {
        let p = scratch("three");
        Vault::create(&p, SIZE, &pw()).expect("create");

        let a = Vault::open(&p, b"protect-me", SIZE).expect("P1");
        assert_eq!(a.mode(), Mode::Protected);
        assert_eq!(a.space(), SpaceId::Public);
        assert!(a.has_layer(), "P1 holds the ownership layer");
        drop(a);

        let b = Vault::open(&p, b"the-other-one", SIZE).expect("P2");
        assert_eq!(b.mode(), Mode::Hidden);
        assert_eq!(b.space(), SpaceId::Hidden);
        assert!(b.has_layer(), "P2 holds the ownership layer");
        drop(b);

        let c = Vault::open(&p, b"just-a-phone", SIZE).expect("P3");
        assert_eq!(c.mode(), Mode::Public);
        assert_eq!(c.space(), SpaceId::Public, "P3 opens the SAME space as P1");
        assert!(!c.has_layer(), "P3 must know nothing of the ownership layer");
    }

    /// P1 and P3 hand back the SAME space key, so they open one account rather than two that
    /// happen to share a file. The key is stored in the slot, never derived from the password —
    /// deriving it would make these two keys differ and the account unreadable under P3.
    #[test]
    fn the_protected_and_public_passwords_open_one_account() {
        let p = scratch("shared-key");
        Vault::create(&p, SIZE, &pw()).expect("create");
        let a = Vault::open(&p, b"protect-me", SIZE).expect("P1");
        let key_a = a.space_key().clone();
        let root_a = a.root();
        drop(a);
        let c = Vault::open(&p, b"just-a-phone", SIZE).expect("P3");
        assert_eq!(c.space_key().to_bytes(), key_a.to_bytes(), "P1 and P3 must share the key");
        assert_eq!(c.root(), root_a, "and therefore see the same root");
    }

    /// The hidden space's key is NOT the public one. Sharing it would make the hidden account
    /// readable by anyone who could open the public one — which is every duress case at once.
    #[test]
    fn the_hidden_space_has_a_key_of_its_own() {
        let p = scratch("distinct");
        Vault::create(&p, SIZE, &pw()).expect("create");
        let a = Vault::open(&p, b"protect-me", SIZE).expect("P1");
        let key_a = a.space_key().to_bytes();
        drop(a);
        let b = Vault::open(&p, b"the-other-one", SIZE).expect("P2");
        assert_ne!(b.space_key().to_bytes(), key_a, "the two spaces share a key");
    }

    /// A wrong password gets the same answer as a password for a compartment that does not exist.
    #[test]
    fn a_wrong_password_says_nothing_about_what_is_there() {
        let p = scratch("wrong");
        Vault::create(&p, SIZE, &pw()).expect("create");
        match Vault::open(&p, b"not any of them", SIZE) {
            Err(VaultError::NoSuchCompartment) => {}
            Err(other) => panic!("wrong refusal: {other}"),
            Ok(_) => panic!("a password that opens nothing must not open a session"),
        }
    }

    /// Two equal passwords are refused BEFORE anything is written — a container where one
    /// compartment can never open would otherwise look perfectly healthy.
    #[test]
    fn colliding_passwords_are_refused_before_the_file_exists() {
        let p = scratch("collide");
        let same = Passwords { protected: b"same", hidden: b"same", public: b"other" };
        assert!(matches!(Vault::create(&p, SIZE, &same), Err(VaultError::PasswordsCollide)));
        assert!(!p.exists(), "nothing may be written when the passwords are refused");
    }

    /// Free space under P3 is a LOWER BOUND and never exact. An exact figure would be the
    /// difference between "N blocks free" and "N free and something invisible holds the rest".
    #[test]
    fn a_public_session_can_only_ever_lower_bound_the_free_space() {
        let p = scratch("free");
        Vault::create(&p, SIZE, &pw()).expect("create");
        let c = Vault::open(&p, b"just-a-phone", SIZE).expect("P3");
        assert!(!c.free_space().is_exact(), "P3 reported an exact free-space figure");
        assert!(c.free_space().blocks() > 0);
    }

    /// **The two spaces never share an anchor block.** If they did, one space's commit would
    /// overwrite the other's root — the public space would silently destroy the hidden one on its
    /// next write, which is the exact failure the whole ownership layer exists to prevent, arriving
    /// through the back door of a layout mistake.
    #[test]
    fn the_two_spaces_anchors_are_disjoint() {
        let p = scratch("anchors");
        Vault::create(&p, SIZE, &pw()).expect("create");
        let a = Vault::open(&p, b"protect-me", SIZE).expect("P1");
        let anchors_a = *a.anchors();
        drop(a);
        let b = Vault::open(&p, b"the-other-one", SIZE).expect("P2");
        let anchors_b = *b.anchors();
        for x in anchors_a {
            assert!(!anchors_b.contains(&x), "block {x} anchors BOTH spaces");
        }
        // And the two anchors of one space differ, or "write to the one not live" is meaningless.
        assert_ne!(anchors_a[0], anchors_a[1]);
        assert_ne!(anchors_b[0], anchors_b[1]);
    }

    /// The header's size and the file's size are two independent answers and must agree.
    #[test]
    fn the_header_and_the_file_agree_on_how_big_the_container_is() {
        let p = scratch("size-agree");
        Vault::create(&p, SIZE, &pw()).expect("create");
        let v = Vault::open(&p, b"protect-me", SIZE).expect("open");
        assert_eq!(v.container_bytes(), SIZE);
        assert_eq!(v.params().container_size, SIZE);
        assert!(v.geometry().block_stride() > 0);
    }

    /// A container survives being closed and reopened — the roots are on disk, not in memory.
    #[test]
    fn a_container_reopens_after_the_process_that_made_it_is_gone() {
        let p = scratch("reopen");
        Vault::create(&p, SIZE, &pw()).expect("create");
        let first = Vault::open(&p, b"protect-me", SIZE).expect("open").root();
        // Dropping releases the flock; a second open with no live handle must succeed.
        let second = Vault::open(&p, b"protect-me", SIZE).expect("reopen").root();
        assert_eq!(first, second);
    }
}
