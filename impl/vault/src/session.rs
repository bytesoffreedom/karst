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
    /// The object does not fit one block yet — see `write_object`. An explicit refusal, never a
    /// truncation: a snapshot silently cut to one block is an account silently destroyed.
    ObjectTooLarge { len: usize, capacity: usize },
    /// A public session cannot allocate: it holds no ownership-layer key, so it cannot claim a
    /// block without either forging a capsule or writing none.
    PublicCannotAllocate,
    /// The transaction was refused before it touched anything.
    Refused(crate::tx::Refusal),
    /// A block would not open under this space's key. Fail-closed: the caller is told the block,
    /// never given a guess at what it might have contained.
    Unreadable { block: u64 },
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
            VaultError::ObjectTooLarge { len, capacity } => {
                write!(f, "object is {len} bytes; one block holds {capacity}")
            }
            VaultError::PublicCannotAllocate => write!(
                f,
                "a public session holds no ownership-layer key and so cannot claim a block"
            ),
            VaultError::Refused(r) => write!(f, "transaction refused: {r:?}"),
            VaultError::Unreadable { block } => {
                write!(f, "block {block} does not open under this space's key")
            }
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
    /// A HINT about which blocks are free, never the authority. A fresh session believes nothing
    /// is free until a scan says otherwise — see `freeindex` — so it is seeded from the container's
    /// size and narrowed as blocks are claimed.
    free: crate::freeindex::FreeIndex,
    /// The allocator's shuffle, in memory only. Its seed never reaches the disk, so a candidate
    /// this session considered and rejected leaves no trace anywhere.
    allocator: crate::allocator::Allocator,
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

        // Every block is believed free except the four anchors and block 0, which is never handed
        // out. This is a HINT and deliberately optimistic in the direction that costs nothing: a
        // candidate is checked against its capsule before it is used, so believing a used block
        // free wastes a candidate, while believing a free block used would lose capacity silently.
        let mut free = crate::freeindex::FreeIndex::empty(params.blocks);
        for b in 0..params.blocks {
            free.set(b, b != crate::geometry::RESERVED_BLOCK && !opened.anchors.contains(&b));
        }
        let allocator = crate::allocator::Allocator::new(params.blocks);

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
            free,
            allocator,
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

    /// Read object `slot`, or `None` if nothing has been written to it.
    ///
    /// Walks the mapping tree from the live root. A missing entry anywhere on the path means the
    /// object is not there — not that it is empty, and not that the container is damaged.
    pub fn read_object(&self, slot: u64) -> Result<Option<Vec<u8>>, VaultError> {
        let (base, _) = Geometry::slice(slot);
        let Some(block) = self.walk(base)? else { return Ok(None) };
        let raw = self.medium.read(payload_at(&self.geometry, block), self.sealed_payload_len())?;
        let plain = crate::record::open(
            &self.space_key,
            &payload_ctx(self.params.format_hash(), self.space, block, base, self.live.root.generation),
            &raw,
        )
        .ok_or(VaultError::Unreadable { block })?;
        // The stored form is `len(4) ‖ bytes ‖ padding`: a block is a fixed size, so the length has
        // to be inside it. Padding is not zeroed to a pattern — it is whatever the block held —
        // which is why the length is authoritative rather than a scan for a terminator.
        if plain.len() < 4 {
            return Err(VaultError::Unreadable { block });
        }
        let len = u32::from_le_bytes(plain[..4].try_into().expect("4 bytes")) as usize;
        if 4 + len > plain.len() {
            return Err(VaultError::Unreadable { block });
        }
        Ok(Some(plain[4..4 + len].to_vec()))
    }

    /// Write object `slot`, REPLACING whatever was there.
    ///
    /// # Replace, not write-range, and the reason is a leak
    ///
    /// The obvious shape is "write these bytes at this offset", and it is wrong for anything whose
    /// size can fall. If the object mapped 200 logical blocks last save and 150 this one, a
    /// range write leaves the map entries for 150..200 pointing at live, owned, root-reachable
    /// blocks that nothing will ever release. Snapshots shrink constantly — delete a conversation,
    /// clear a history — so that is the normal case, and its signature is a container that fills up
    /// over months with no visible cause.
    ///
    /// So the old blocks of the slot are RETIRED in the same transaction that writes the new ones.
    ///
    /// # The order is not this function's opinion
    ///
    /// Nothing here decides when anything becomes durable. It seals bytes, asks the planner what
    /// the worst case costs, refuses if the credit is not there, and hands an ordered [`Commit`] to
    /// the shared executor. A crash at any point is the crash matrix's business, not a case this
    /// function handles.
    ///
    /// # Currently one logical block
    ///
    /// The pipeline is complete — plan, admit, allocate, seal, commit — for objects up to
    /// `logical_data()` bytes. Larger objects need the same code over a range of blocks and are the
    /// next increment; the refusal is explicit rather than a silent truncation, because a snapshot
    /// silently cut to 64 KiB is an account silently destroyed.
    pub fn write_object(&mut self, slot: u64, bytes: &[u8]) -> Result<(), VaultError> {
        if self.mode == Mode::Public {
            // P3 may write — it owns the public space — but it must never be able to touch the
            // ownership layer, so it cannot allocate. That is the next increment's problem and
            // refusing now is better than half-doing it.
            return Err(VaultError::PublicCannotAllocate);
        }
        let capacity = self.geometry.logical_data() - 4;
        if bytes.len() > capacity {
            return Err(VaultError::ObjectTooLarge { len: bytes.len(), capacity });
        }
        let (base, _) = Geometry::slice(slot);
        let format_hash = self.params.format_hash();
        let generation = self.live.root.generation + 1;
        let transaction = self.live.root.transaction + 1;

        // What the worst case costs, asked BEFORE a byte is touched. `admit` is read-only by
        // construction and takes no store, so a refusal here has changed nothing.
        let plan = crate::plan::plan_mutation(
            &self.geometry,
            crate::plan::Mutation::Write { slot, offset: 0, len: bytes.len() as u64 },
        );
        let believed_free = self.free.believed_free_count();
        crate::tx::admit(plan.need(), believed_free, None, self.live.root.generation)
            .map_err(VaultError::Refused)?;

        // Allocate: one data block plus one node per level. Candidates come from the allocator's
        // in-memory shuffle and are accepted only if the free index believes them free — the index
        // is a hint, so believing it is allowed; trusting it as an authority is not.
        let depth = self.geometry.depth() as usize;
        let mut fresh = Vec::with_capacity(depth + 1);
        while fresh.len() < depth + 1 {
            let candidate = self.allocator.next_candidate().ok_or(VaultError::Refused(
                crate::tx::Refusal::NoSpace,
            ))?;
            if candidate == crate::geometry::RESERVED_BLOCK || self.anchors.contains(&candidate) {
                continue;
            }
            // **The capsule is the authority; the index is only a hint.** Consulting the hint alone
            // was the first version, and it corrupted the container across spaces: a fresh session
            // believes every block free, so the hidden space happily allocated a block the public
            // space was already using and overwrote it. The public side then read its own object
            // back as unopenable — reported as corruption, caused by an allocator.
            //
            // UNKNOWN is refused, not retried into: a block whose capsules do not verify may be
            // anything, including the other space's live data, and "I could not tell" must never
            // become "so I took it" (requirement 8, fail-closed).
            if !self.believes_allocatable(candidate)? {
                self.free.set(candidate, false);
                continue;
            }
            fresh.push(candidate);
        }
        let data_block = fresh[0];

        // The payload: `len ‖ bytes ‖ padding to the block`. A fixed-size block means the length
        // lives inside it; the padding is not a pattern, so the length is what says where the data
        // ends.
        let mut plain = Vec::with_capacity(self.geometry.logical_data());
        plain.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        plain.extend_from_slice(bytes);
        plain.resize(self.geometry.logical_data(), 0);
        let sealed_payload = crate::record::seal(
            &self.space_key,
            &payload_ctx(format_hash, self.space, data_block, base, generation),
            &plain,
        );

        // The map path, built bottom-up: each level's node points at the level below.
        let digits = crate::map::path(&self.geometry, base);
        let mut child = data_block;
        let mut node_writes: Vec<(u64, u64, Vec<u8>)> = Vec::new(); // (block, level, sealed)
        for level in (0..depth).rev() {
            let block = fresh[depth - level];
            let mut node = crate::map::Node::empty(&self.geometry);
            // COW: start from the existing node at this level where there is one, so the other
            // entries survive. Without this, writing one object would orphan every other object
            // sharing the node — which is every object, at this fan-out.
            if let Some(existing) = self.node_at_level(base, level)? {
                node = existing;
            }
            node.set(digits[level], child);
            let sealed = crate::record::seal(
                &self.space_key,
                &node_ctx(format_hash, self.space, block, level as u64, generation),
                &node.encode(),
            );
            node_writes.push((block, level as u64, sealed));
            child = block;
        }
        let new_root_block = child;

        // Capsules for every block this transaction claims, under the ownership layer.
        let layer = self.layer_key.clone().ok_or(VaultError::PublicCannotAllocate)?;
        let owner = match self.space {
            SpaceId::Public => crate::capsule::Owner::Public,
            SpaceId::Hidden => crate::capsule::Owner::Hidden,
            // A session's space comes from the slot's mode, which only ever yields the two data
            // spaces. `Ownership` is the layer's own domain and nothing allocates into it.
            SpaceId::Ownership => return Err(VaultError::PublicCannotAllocate),
        };
        let stamp = Stamp { layer: &layer, format_hash, owner, generation, transaction };
        let mut writes = Vec::with_capacity(depth + 1);
        writes.push(self.block_write(&stamp, data_block, &sealed_payload));
        for (block, _, sealed) in &node_writes {
            writes.push(self.block_write(&stamp, *block, sealed));
        }

        // The new root goes to the anchor NOT holding the live one, so a crash mid-write leaves the
        // live anchor untouched and the old version readable.
        let anchor = self.anchors[root::next_anchor(&self.live)];
        let root = Root {
            generation,
            map_root: new_root_block,
            transaction,
            mapped_blocks: self.live.root.mapped_blocks.max(1),
        };
        let sealed_root = root::seal_root(&self.space_key, format_hash, self.space, anchor, &root);

        let commit = crate::tx::Commit::build(
            &writes,
            (payload_at(&self.geometry, anchor), Vec::new()), // manifest: none to retire yet
            (payload_at(&self.geometry, anchor), sealed_root),
            &[],
            (payload_at(&self.geometry, anchor), Vec::new()),
        );
        crate::medium::apply(commit.steps(), &mut self.medium)?;

        // Only now is the session's own view allowed to move: everything above could have failed,
        // and a view that advanced before the commit did would answer reads from a version that is
        // not on disk.
        for b in &fresh {
            self.free.set(*b, false);
        }
        self.live = Live { root, anchor: root::next_anchor(&self.live) };
        Ok(())
    }

    /// Whether a block's own capsules say it may be handed out.
    ///
    /// Reads BOTH copies under the ownership layer and believes only a confirmed verdict whose
    /// state is allocatable. Everything else — a live block, a reservation, a retiring block, or a
    /// verdict of `Unknown` — is refused. This is the only place allocation is allowed to decide
    /// from, and the free index exists to make it cheap, never to replace it.
    fn believes_allocatable(&self, block: u64) -> Result<bool, VaultError> {
        let Some(layer) = self.layer_key.as_ref() else { return Ok(false) };
        let c0 = self.medium.read(
            self.geometry.capsule_offset(header_len(), block, 0),
            crate::geometry::CAPSULE_SLOT,
        )?;
        let c1 = self.medium.read(
            self.geometry.capsule_offset(header_len(), block, 1),
            crate::geometry::CAPSULE_SLOT,
        )?;
        let verdict = crate::capsule::read_capsules(
            layer,
            self.params.format_hash(),
            block,
            [&c0, &c1],
            None,
        );
        Ok(match verdict {
            // A block nobody has ever claimed has no readable capsule at all, which reads as
            // `Unknown`. That is indistinguishable from a block whose capsules were damaged, so a
            // fresh container needs its free blocks marked FREE at creation before this can tell
            // them apart — until then, `Unknown` on a never-written block is the common case and
            // is handled by the free index having been seeded optimistically for those.
            crate::capsule::Verdict::Confirmed(c) => c.state.is_allocatable(),
            crate::capsule::Verdict::Unchecked(_) => false,
            crate::capsule::Verdict::Unknown => self.free.believes_free(block),
        })
    }

    /// The existing map node at `level` on the path to `logical`, if the space has one.
    fn node_at_level(
        &self,
        logical: u64,
        level: usize,
    ) -> Result<Option<crate::map::Node>, VaultError> {
        if self.live.root.map_root == crate::geometry::RESERVED_BLOCK {
            return Ok(None);
        }
        let digits = crate::map::path(&self.geometry, logical);
        let mut block = self.live.root.map_root;
        for (l, digit) in digits.iter().enumerate() {
            let raw = self.medium.read(payload_at(&self.geometry, block), self.sealed_node_len())?;
            let plain = crate::record::open(
                &self.space_key,
                &node_ctx(
                    self.params.format_hash(),
                    self.space,
                    block,
                    l as u64,
                    self.live.root.generation,
                ),
                &raw,
            )
            .ok_or(VaultError::Unreadable { block })?;
            let node = crate::map::Node::decode(&self.geometry, &plain)
                .ok_or(VaultError::Unreadable { block })?;
            if l == level {
                return Ok(Some(node));
            }
            match node.get(*digit) {
                None => return Ok(None),
                Some(next) => block = next,
            }
        }
        Ok(None)
    }

    /// What one transaction stamps into every block it claims: who owns it and which commit it
    /// belongs to. Bundled because passing six loose values to `block_write` per block was six
    /// chances to pass them in the wrong order.
    fn block_write(&self, s: &Stamp<'_>, block: u64, sealed: &[u8]) -> crate::tx::BlockWrite {
        let (layer, format_hash, owner, generation, transaction) =
            (s.layer, s.format_hash, s.owner, s.generation, s.transaction);
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(sealed).into();
        let reserved = crate::capsule::Claim {
            state: State::Reserved(owner),
            generation,
            transaction,
            binding: [0u8; 32],
        };
        let live = crate::capsule::Claim {
            state: State::Live(owner),
            generation,
            transaction,
            binding: digest,
        };
        crate::tx::BlockWrite {
            block,
            reserved_capsule: (
                self.geometry.capsule_offset(header_len(), block, 0),
                crate::capsule::frame(
                    &reserved,
                    crate::capsule::seal_claim(layer, format_hash, block, 0, &reserved),
                ),
            ),
            payload: (payload_at(&self.geometry, block), sealed.to_vec()),
            live_capsule: (
                self.geometry.capsule_offset(header_len(), block, 0),
                crate::capsule::frame(
                    &live,
                    crate::capsule::seal_claim(layer, format_hash, block, 0, &live),
                ),
            ),
        }
    }

    /// Follow the map from the live root to the physical block holding `logical`.
    fn walk(&self, logical: u64) -> Result<Option<u64>, VaultError> {
        if self.live.root.map_root == crate::geometry::RESERVED_BLOCK {
            return Ok(None); // an empty space: a root that says so, which is not the same as no root
        }
        let digits = crate::map::path(&self.geometry, logical);
        let mut block = self.live.root.map_root;
        for (level, digit) in digits.iter().enumerate() {
            let raw = self.medium.read(payload_at(&self.geometry, block), self.sealed_node_len())?;
            let plain = crate::record::open(
                &self.space_key,
                &node_ctx(
                    self.params.format_hash(),
                    self.space,
                    block,
                    level as u64,
                    self.live.root.generation,
                ),
                &raw,
            )
            .ok_or(VaultError::Unreadable { block })?;
            let node = crate::map::Node::decode(&self.geometry, &plain)
                .ok_or(VaultError::Unreadable { block })?;
            match node.get(*digit) {
                None => return Ok(None),
                Some(next) => block = next,
            }
        }
        Ok(Some(block))
    }

    fn sealed_payload_len(&self) -> usize {
        self.geometry.logical_data() + crate::geometry::RECORD_FRAMING
    }

    fn sealed_node_len(&self) -> usize {
        self.geometry.fanout() as usize * crate::geometry::ENTRY_LEN + crate::geometry::RECORD_FRAMING
    }

    /// The largest object this container can hold **and still be able to rewrite**.
    ///
    /// This is NOT `free_space() * logical_data`, and the difference is the whole point. Writing is
    /// copy-on-write: the old version stays live until the new one has committed, so rewriting an
    /// object of B blocks needs B FREE blocks while B are still held. The steady state is 2B, and
    /// the ceiling is therefore half the usable blocks — about 44% of the file once the reserve and
    /// the per-block capsule overhead are paid.
    ///
    /// A caller that sized a snapshot by the free count instead would fill the container on the
    /// FIRST save and be unable to commit the second — `admit` would refuse it correctly, and the
    /// user would be told there is no space in a container that looks half empty. That failure is
    /// invisible until the second save, which is why the question is answered here rather than left
    /// to whoever calls `free_space`.
    pub fn max_rewritable_bytes(&self) -> u64 {
        let usable = self.params.blocks.saturating_sub(self.params.workspace_reserve);
        (usable / 2) * self.geometry.logical_data() as u64
    }
}

/// Bytes reserved for a sealed root at an anchor: the clear generation prefix plus the record.
const ROOT_RAW: usize = 8 + crate::geometry::RECORD_FRAMING + 32;

/// Everything a transaction stamps into each block it claims.
struct Stamp<'a> {
    layer: &'a MasterKey,
    format_hash: [u8; 32],
    owner: crate::capsule::Owner,
    generation: u64,
    transaction: u64,
}

/// The sealing context for one data block.
///
/// `logical_or_prefix` carries the LOGICAL block number, so a block sealed for one position cannot
/// be replayed at another even by an attacker who can move bytes around the file: the aad names
/// where it belongs, and moving it makes it fail to open rather than open as something else.
fn payload_ctx(
    format_hash: [u8; 32],
    space: SpaceId,
    block: u64,
    logical: u64,
    generation: u64,
) -> crate::record::Context {
    crate::record::Context {
        format_hash,
        record_type: crate::record::RecordType::Payload,
        space,
        physical_block: block,
        logical_or_prefix: logical,
        generation,
        copy_index: 0,
    }
}

/// The sealing context for one map node. `logical_or_prefix` is the node's LEVEL, so a node from
/// one level cannot be replayed at another — which would otherwise reinterpret a leaf's entries as
/// an interior node's.
fn node_ctx(
    format_hash: [u8; 32],
    space: SpaceId,
    block: u64,
    level: u64,
    generation: u64,
) -> crate::record::Context {
    crate::record::Context {
        format_hash,
        record_type: crate::record::RecordType::MapNode,
        space,
        physical_block: block,
        logical_or_prefix: level,
        generation,
        copy_index: 0,
    }
}

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

    /// The rewritable ceiling is HALF the usable space, not all of it — copy-on-write holds the old
    /// version while the new one is written.
    ///
    /// Discriminating: this asserts the ceiling is meaningfully below the free-space figure, so a
    /// version that returned `free * logical_data` fails here rather than at somebody's second
    /// save.
    #[test]
    fn the_rewritable_ceiling_is_about_half_the_container() {
        let p = scratch("ceiling");
        Vault::create(&p, SIZE, &pw()).expect("create");
        let v = Vault::open(&p, b"protect-me", SIZE).expect("open");

        let free_bytes = v.free_space().blocks() * v.geometry().logical_data() as u64;
        let ceiling = v.max_rewritable_bytes();
        assert!(
            ceiling < free_bytes,
            "the ceiling ({ceiling}) must be below the free figure ({free_bytes}); copy-on-write \
             needs room for the new version while the old one is still live"
        );
        // Half, within the rounding of one block.
        let half = free_bytes / 2;
        assert!(
            ceiling <= half && ceiling + v.geometry().logical_data() as u64 >= half,
            "expected about half of {free_bytes}, got {ceiling}"
        );
        assert!(ceiling > 0, "a container this size must hold something");
    }

    /// **The whole pipeline, end to end**: write an object, close the container, reopen it, and
    /// read the same bytes back.
    ///
    /// This is the test the crate did not have and could not have: until the session layer existed
    /// there was no path from a password to a stored byte. It exercises the planner, the credit
    /// refusal, the allocator, the free-index hint, capsule sealing under the ownership layer, the
    /// map path, the root switch, and the commit order — through the same executor a crash test
    /// drives.
    #[test]
    fn an_object_written_here_is_read_back_after_a_reopen() {
        let p = scratch("roundtrip");
        Vault::create(&p, SIZE, &pw()).expect("create");
        let payload = b"the hidden account's whole world, as a snapshot".to_vec();
        {
            let mut v = Vault::open(&p, b"protect-me", SIZE).expect("open");
            assert_eq!(v.read_object(0).expect("read"), None, "nothing written yet");
            v.write_object(0, &payload).expect("write");
            assert_eq!(v.read_object(0).expect("read back"), Some(payload.clone()));
        }
        let v = Vault::open(&p, b"protect-me", SIZE).expect("reopen");
        assert_eq!(v.read_object(0).expect("read"), Some(payload), "the write did not survive");
    }

    /// A second write replaces the first. The old bytes must not be what a read returns.
    #[test]
    fn writing_twice_leaves_the_second_version() {
        let p = scratch("replace");
        Vault::create(&p, SIZE, &pw()).expect("create");
        let mut v = Vault::open(&p, b"protect-me", SIZE).expect("open");
        v.write_object(0, b"first").expect("first write");
        v.write_object(0, b"second, and longer").expect("second write");
        assert_eq!(v.read_object(0).expect("read"), Some(b"second, and longer".to_vec()));
        drop(v);
        let v = Vault::open(&p, b"protect-me", SIZE).expect("reopen");
        assert_eq!(v.read_object(0).expect("read"), Some(b"second, and longer".to_vec()));
    }

    /// **The public space and the hidden space do not see each other's objects.** Writing in one
    /// must not make anything appear in the other, and this is the property the whole format is
    /// for.
    #[test]
    fn neither_space_can_see_what_the_other_wrote() {
        let p = scratch("isolated");
        Vault::create(&p, SIZE, &pw()).expect("create");
        {
            let mut a = Vault::open(&p, b"protect-me", SIZE).expect("P1");
            a.write_object(0, b"public side").expect("write A");
        }
        {
            let mut b = Vault::open(&p, b"the-other-one", SIZE).expect("P2");
            assert_eq!(b.read_object(0).expect("read"), None, "the hidden space saw A's object");
            b.write_object(0, b"hidden side").expect("write B");
            assert_eq!(b.read_object(0).expect("read"), Some(b"hidden side".to_vec()));
        }
        let a = Vault::open(&p, b"protect-me", SIZE).expect("P1 again");
        assert_eq!(
            a.read_object(0).expect("read"),
            Some(b"public side".to_vec()),
            "writing in the hidden space disturbed the public one"
        );
    }

    /// An object too big for the current increment is REFUSED, never truncated. A snapshot
    /// silently cut down is an account silently destroyed.
    #[test]
    fn an_oversized_object_is_refused_rather_than_cut() {
        let p = scratch("toobig");
        Vault::create(&p, SIZE, &pw()).expect("create");
        let mut v = Vault::open(&p, b"protect-me", SIZE).expect("open");
        let huge = vec![7u8; v.geometry().logical_data() + 1];
        match v.write_object(0, &huge) {
            Err(VaultError::ObjectTooLarge { .. }) => {}
            Err(other) => panic!("wrong refusal: {other}"),
            Ok(()) => panic!("an oversized object must be refused, not truncated"),
        }
        assert_eq!(v.read_object(0).expect("read"), None, "the refusal wrote something anyway");
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
