//! The open header: the only part of a container that is not ciphertext.
//!
//! # Why anything is in the clear at all
//!
//! A reader has to know how big a block is before it can find one. That cannot be inside the
//! encrypted region without a chicken-and-egg problem, so the geometry lives in a plaintext
//! header.
//!
//! # The rule that makes that safe
//!
//! **Nothing here may depend on what the owner configured.** Every field is either a constant of
//! the format version or the container's size, which is visible from the file length anyway. A
//! parameter that varied with whether a hidden space exists would be the answer to the only
//! question the format is built to refuse; a parameter that varied with the owner's choices would
//! be a fingerprint.
//!
//! That is why there is no "hidden space present" flag, no reserve size, no slot-occupancy count,
//! and no per-container tuning. Two containers of the same size and version have byte-identical
//! headers apart from the salt.
//!
//! # Why the header is hashed into everything
//!
//! `format_hash` covers the canonical encoding and rides in the aad of every record. Without it,
//! an attacker could edit the plaintext header — change the block size, say — and every sealed
//! record would still verify while being interpreted at the wrong offsets. With it, editing the
//! header invalidates the whole container rather than reinterpreting it.

use sha2::{Digest, Sha256};

use crate::geometry::Geometry;
use crate::slot::{SLOT_COUNT, SLOT_LEN};

/// Bytes of salt in the header. Not a secret; unique per container.
pub const SALT_LEN: usize = 16;

/// The format this crate writes.
pub const FORMAT_VERSION: u16 = 1;

/// Blocks held back so a copy-on-write transaction can always finish.
///
/// A transaction needs somewhere to put the new version before the old one can be released, so a
/// container with exactly one free block cannot commit a change to one block: it also needs the
/// map nodes on the path. Without a reserve the last few writes in a nearly full container fail in
/// the middle rather than at admission — the failure mode credits exist to prevent.
///
/// It is NOT a reserve for the hidden space. It is the same number in every container of this
/// version, present whether or not a hidden space was ever created, and visible in the clear.
pub const SYSTEM_WORKSPACE_RESERVE: u64 = 64;

/// The container's open header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatParams {
    pub version: u16,
    pub container_size: u64,
    pub blocks: u64,
    pub block_stride: u64,
    pub block_payload: u32,
    pub capsule_slot: u32,
    pub capsule_align: u32,
    pub slot_count: u16,
    pub slot_len: u16,
    pub argon_m_cost: u32,
    pub argon_t_cost: u32,
    pub argon_p_cost: u32,
    pub map_fanout: u64,
    pub map_depth: u32,
    pub workspace_reserve: u64,
}

impl FormatParams {
    /// Derive the header from the two things that may vary: the format version and the file size.
    ///
    /// Everything else follows. There is deliberately no way to construct a `FormatParams` with a
    /// hand-picked field — a constructor that allowed it would be the hole through which a
    /// per-container tuning knob eventually arrives.
    pub fn derive(container_size: u64) -> Self {
        let payload = crate::geometry::DEFAULT_BLOCK_PAYLOAD;
        let header = header_len();
        let stride = (2 * crate::geometry::CAPSULE_ALIGN + payload) as u64;
        let blocks = container_size.saturating_sub(header) / stride;
        let g = Geometry::new(payload, blocks);
        Self {
            version: FORMAT_VERSION,
            container_size,
            blocks,
            block_stride: stride,
            block_payload: payload as u32,
            capsule_slot: crate::geometry::CAPSULE_SLOT as u32,
            capsule_align: crate::geometry::CAPSULE_ALIGN as u32,
            slot_count: SLOT_COUNT as u16,
            slot_len: SLOT_LEN as u16,
            argon_m_cost: crate::slot::KDF_M_COST,
            argon_t_cost: crate::slot::KDF_T_COST,
            argon_p_cost: crate::slot::KDF_P_COST,
            map_fanout: g.fanout(),
            map_depth: g.depth(),
            workspace_reserve: SYSTEM_WORKSPACE_RESERVE,
        }
    }

    /// The geometry these params describe.
    pub fn geometry(&self) -> Geometry {
        Geometry::new(self.block_payload as usize, self.blocks)
    }

    /// Canonical encoding — the bytes that go in the header and into `format_hash`.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(PARAMS_LEN);
        v.extend_from_slice(&self.version.to_le_bytes());
        v.extend_from_slice(&self.container_size.to_le_bytes());
        v.extend_from_slice(&self.blocks.to_le_bytes());
        v.extend_from_slice(&self.block_stride.to_le_bytes());
        v.extend_from_slice(&self.block_payload.to_le_bytes());
        v.extend_from_slice(&self.capsule_slot.to_le_bytes());
        v.extend_from_slice(&self.capsule_align.to_le_bytes());
        v.extend_from_slice(&self.slot_count.to_le_bytes());
        v.extend_from_slice(&self.slot_len.to_le_bytes());
        v.extend_from_slice(&self.argon_m_cost.to_le_bytes());
        v.extend_from_slice(&self.argon_t_cost.to_le_bytes());
        v.extend_from_slice(&self.argon_p_cost.to_le_bytes());
        v.extend_from_slice(&self.map_fanout.to_le_bytes());
        v.extend_from_slice(&self.map_depth.to_le_bytes());
        v.extend_from_slice(&self.workspace_reserve.to_le_bytes());
        v
    }

    /// Hash of the canonical encoding — what every record's aad carries.
    pub fn format_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"karst-vault-format-v1");
        h.update(self.encode());
        h.finalize().into()
    }

    /// Refuse absurd parameters BEFORE allocating anything.
    ///
    /// The Argon2 cost is the dangerous one: it comes from an untrusted header and drives a memory
    /// allocation, so a container claiming 64 GiB of KDF memory would be a way to make opening one
    /// an out-of-memory kill. Checked against a hard ceiling here, before the allocation, rather
    /// than trusted because the file "should" be ours.
    pub fn is_acceptable(&self) -> bool {
        const MAX_M_COST: u32 = 1 << 21; // 2 GiB in KiB
        self.version == FORMAT_VERSION
            && self.blocks > self.workspace_reserve
            && self.block_payload as usize > crate::geometry::RECORD_FRAMING
            && self.argon_m_cost <= MAX_M_COST
            && self.argon_t_cost > 0
            && self.argon_p_cost > 0
            && self.geometry().is_sane()
    }
}

/// Bytes the canonical `format_params` encoding occupies.
///
/// Pinned as a constant and checked against the encoder, rather than taken from the encoder: the
/// header layout depends on it, so a field added without noticing would silently shift every block
/// offset in the container and make an existing file unreadable in a way that looks like a wrong
/// password.
pub const PARAMS_LEN: usize = 74;

/// Bytes the header occupies: salt plus the slot table plus the params.
pub fn header_len() -> u64 {
    (SALT_LEN + SLOT_COUNT * SLOT_LEN + PARAMS_LEN) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two containers of the same size and version have identical headers. If any field tracked
    /// something the owner chose, this is where it would show.
    #[test]
    fn two_containers_of_the_same_size_have_identical_params() {
        let a = FormatParams::derive(1 << 30);
        let b = FormatParams::derive(1 << 30);
        assert_eq!(a, b);
        assert_eq!(a.encode(), b.encode());
        assert_eq!(a.format_hash(), b.format_hash());
    }

    /// The tree shape does not vary with container size, so the header cannot be used to tell a
    /// large container from a small one beyond the size that is visible anyway.
    #[test]
    fn the_map_shape_is_the_same_at_every_container_size() {
        let small = FormatParams::derive(1 << 26);
        let large = FormatParams::derive(1 << 34);
        assert_eq!(small.map_depth, large.map_depth);
        assert_eq!(small.map_fanout, large.map_fanout);
    }

    /// The workspace reserve is a format constant, not a hidden-space reserve: same value in every
    /// container of this version.
    #[test]
    fn the_workspace_reserve_does_not_vary_between_containers() {
        assert_eq!(
            FormatParams::derive(1 << 28).workspace_reserve,
            FormatParams::derive(1 << 34).workspace_reserve
        );
    }

    /// Editing the header changes the hash, so every sealed record stops verifying rather than
    /// being reinterpreted at new offsets. That is the difference between a container that refuses
    /// to open and one that opens wrong.
    #[test]
    fn editing_any_field_changes_the_format_hash() {
        let base = FormatParams::derive(1 << 30);
        let mut edited = base;
        edited.block_payload += 1;
        assert_ne!(base.format_hash(), edited.format_hash());

        let mut edited = base;
        edited.workspace_reserve += 1;
        assert_ne!(base.format_hash(), edited.format_hash());
    }

    /// An absurd KDF cost from an untrusted header is refused BEFORE it can drive an allocation.
    #[test]
    fn an_absurd_kdf_cost_is_refused_before_allocating() {
        let mut p = FormatParams::derive(1 << 30);
        p.argon_m_cost = u32::MAX;
        assert!(!p.is_acceptable(), "a header could have demanded unbounded memory");
        p.argon_m_cost = 1 << 20;
        assert!(p.is_acceptable());
    }

    /// A container too small to hold its own workspace reserve is not a container.
    #[test]
    fn a_container_smaller_than_its_reserve_is_refused() {
        let p = FormatParams::derive(header_len() + 1);
        assert!(!p.is_acceptable());
    }

    /// A zero cost parameter would make Argon2 free, which a header must not be able to ask for.
    #[test]
    fn zero_kdf_costs_are_refused() {
        let mut p = FormatParams::derive(1 << 30);
        p.argon_t_cost = 0;
        assert!(!p.is_acceptable());
        let mut p = FormatParams::derive(1 << 30);
        p.argon_p_cost = 0;
        assert!(!p.is_acceptable());
    }

    /// A header from another format version is refused rather than read with this version's
    /// assumptions.
    #[test]
    fn another_format_version_is_refused() {
        let mut p = FormatParams::derive(1 << 30);
        p.version = FORMAT_VERSION + 1;
        assert!(!p.is_acceptable());
    }

    /// The encoding is stable in length whatever the field values, and matches the constant the
    /// header layout is computed from. A field added without updating that constant would shift
    /// every block offset in the container, and an existing file would fail to open in a way that
    /// looks exactly like a wrong password.
    #[test]
    fn the_encoding_length_is_fixed_and_matches_the_header_layout() {
        assert_eq!(FormatParams::derive(1 << 20).encode().len(), PARAMS_LEN);
        assert_eq!(FormatParams::derive(1 << 40).encode().len(), PARAMS_LEN);
    }
}
