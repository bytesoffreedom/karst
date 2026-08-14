//! Password slots: the only place the container's keys come from.
//!
//! # One Argon2 per attempt, not one per slot
//!
//! The obvious construction runs the password KDF against every slot, and it is both slow and
//! pointless. An attacker guessing a password pays for ONE derivation and then tries the cheap
//! part against every slot — so per-slot KDFs multiply the honest user's unlock latency by the slot
//! count while multiplying the attacker's cost by nothing. Here the expensive step runs once and
//! HKDF separates the slots.
//!
//! That is also why the slot count can be small. It was going to be 16 or 32 back when each slot
//! cost a full derivation; with this schedule a larger table buys nothing at all.
//!
//! # Every slot is tried, always
//!
//! Stopping at the first slot that opens would make unlock time depend on WHICH slot matched, and
//! the slot index is exactly what must not leak — it is the difference between the everyday
//! password and the one handed over under duress. So the loop runs to the end regardless.
//!
//! # The plaintext is a fixed length
//!
//! The public mode carries one key, the others carry two. If the sealed plaintext were sized to
//! its contents, the ciphertext length would announce the mode. So every slot's plaintext is
//! padded to the same size, and the unused room is random rather than zeros — an all-zero tail is
//! a distinguisher of exactly the kind the padding exists to remove.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

use crate::record::MasterKey;

/// Slots in the table. Every container has exactly this many, occupied or not.
pub const SLOT_COUNT: usize = 8;
/// Nonce stored in the clear at the head of each slot.
pub const SLOT_NONCE_LEN: usize = 24;
/// Fixed plaintext length. Room for the mode byte, two 32-byte keys, the anchor list, and padding.
pub const SLOT_PLAIN_LEN: usize = 256;
/// One slot on disk: nonce, ciphertext, tag.
pub const SLOT_LEN: usize = SLOT_NONCE_LEN + SLOT_PLAIN_LEN + 16;

/// Anchors recorded per space: where its roots live.
pub const ANCHOR_COUNT: usize = 2;

/// Pinned cost parameters, owned here rather than taken from the library's defaults so a
/// dependency bump cannot silently change key derivation.
pub const KDF_M_COST: u32 = 131_072; // KiB
pub const KDF_T_COST: u32 = 3;
pub const KDF_P_COST: u32 = 1;

/// Test-only escape hatch, compiled out of release builds.
///
/// A conservative KDF is expensive by construction and the suite unlocks containers many times in
/// tests that are not about the KDF. Without this, those runs are minutes of CI — which is how a
/// profile ends up quietly lowered "just for now". The branch sits behind `debug_assertions`, so a
/// release binary does not contain it and no environment variable can reach it.
#[cfg(debug_assertions)]
const FAST_KDF_ENV: &str = "KARST_INSECURE_FAST_KDF";

/// What a password opens, and how.
///
/// `Public` is deliberately not called anything alarming. A container that never had a hidden
/// space has exactly one password, and its slot is a `Public` slot — the same mode byte, the same
/// code path, the same everything as the password handed over under duress in a container that
/// does have one. If the two differed in any way a reader could see, the difference would be the
/// whole answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    /// Opens the public space and protects the hidden one from being overwritten.
    Protected = 1,
    /// Opens the hidden space.
    Hidden = 2,
    /// Opens the public space with no knowledge of the ownership layer.
    Public = 3,
    /// Destroys the container. Holds no key and opens no space.
    ///
    /// The plan describes three passwords; this is a fourth, and it is a PRODUCT feature rather
    /// than part of the deniability construction — the duress wipe the app already offers. It
    /// lives in the slot table because the slot table IS the "this password means X" mechanism:
    /// every slot is the same size and indistinguishable from random, so a wipe slot cannot be
    /// told from an unused one, and adding the mode costs one byte value.
    Wipe = 4,
}

impl Mode {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Mode::Protected),
            2 => Some(Mode::Hidden),
            3 => Some(Mode::Public),
            4 => Some(Mode::Wipe),
            _ => None,
        }
    }
}

/// What a slot yields when it opens.
pub struct Opened {
    pub mode: Mode,
    /// The space key: public for `Protected`/`Public`, hidden for `Hidden`.
    pub space_key: MasterKey,
    /// The ownership-layer key. Absent for `Public` — that is the entire difference between it and
    /// `Protected`, and it is a difference in what the slot HOLDS, never a flag on disk.
    pub layer_key: Option<MasterKey>,
    pub anchors: [u64; ANCHOR_COUNT],
}

/// Derive the per-attempt master secret. Expensive; called once per password tried.
fn argon2_master(password: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    #[cfg(debug_assertions)]
    let params = if std::env::var(FAST_KDF_ENV).as_deref() == Ok("1") {
        eprintln!("KARST: INSECURE fast KDF in use — this container is not protected");
        Params::new(Params::MIN_M_COST, Params::MIN_T_COST, Params::MIN_P_COST, Some(32))
    } else {
        Params::new(KDF_M_COST, KDF_T_COST, KDF_P_COST, Some(32))
    };
    #[cfg(not(debug_assertions))]
    let params = Params::new(KDF_M_COST, KDF_T_COST, KDF_P_COST, Some(32));

    let params = params.expect("pinned Argon2 parameters are valid");
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a.hash_password_into(password, salt, &mut out).expect("Argon2id derivation");
    out
}

/// The key slot `i` is sealed under. Cheap: the expensive step already happened.
fn slot_key(master: &[u8; 32], nonce: &[u8], i: usize) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut info = Vec::with_capacity(32 + SLOT_NONCE_LEN + 1);
    info.extend_from_slice(b"karst-vault-slot-v1");
    info.extend_from_slice(nonce);
    info.push(i as u8);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).expect("32 bytes is a valid HKDF length");
    out
}

fn encode(mode: Mode, space: &[u8; 32], layer: Option<&[u8; 32]>, anchors: &[u64; ANCHOR_COUNT]) -> Vec<u8> {
    let mut v = vec![0u8; SLOT_PLAIN_LEN];
    // Random first, then overwrite the used prefix: the unused tail ends up random rather than
    // zeroed, so a decrypted slot gives away nothing about how much of it was meaningful.
    OsRng.fill_bytes(&mut v);
    v[0] = mode as u8;
    v[1..33].copy_from_slice(space);
    // A `Public` slot carries random bytes where the others carry the layer key, so the two are
    // the same length AND the same shape once decrypted. `has_layer` is what distinguishes them,
    // and it is derived from the mode rather than stored separately.
    if let Some(l) = layer {
        v[33..65].copy_from_slice(l);
    }
    for (n, a) in anchors.iter().enumerate() {
        v[65 + n * 8..73 + n * 8].copy_from_slice(&a.to_le_bytes());
    }
    v
}

fn decode(plain: &[u8]) -> Option<Opened> {
    if plain.len() != SLOT_PLAIN_LEN {
        return None;
    }
    let mode = Mode::from_byte(plain[0])?;
    let mut space = [0u8; 32];
    space.copy_from_slice(&plain[1..33]);
    let layer_key = match mode {
        // A wipe slot carries no key at all: it names an action, not a compartment. The bytes in
        // the key fields are random padding, and reading them as a key would be reading noise.
        Mode::Public | Mode::Wipe => None,
        Mode::Protected | Mode::Hidden => {
            let mut l = [0u8; 32];
            l.copy_from_slice(&plain[33..65]);
            Some(MasterKey::from_bytes(l))
        }
    };
    let mut anchors = [0u64; ANCHOR_COUNT];
    for (n, a) in anchors.iter_mut().enumerate() {
        *a = u64::from_le_bytes(plain[65 + n * 8..73 + n * 8].try_into().expect("8 bytes"));
    }
    Some(Opened { mode, space_key: MasterKey::from_bytes(space), layer_key, anchors })
}

/// Seal one slot. The nonce is stored in the clear ahead of the ciphertext; an unoccupied slot is
/// just random bytes of the same length, and nothing distinguishes the two without a password.
pub fn seal_slot(
    password: &[u8],
    salt: &[u8; 16],
    index: usize,
    mode: Mode,
    space_key: &[u8; 32],
    layer_key: Option<&[u8; 32]>,
    anchors: &[u64; ANCHOR_COUNT],
) -> Vec<u8> {
    let master = argon2_master(password, salt);
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let cipher = XChaCha20Poly1305::new((&slot_key(&master, nonce.as_slice(), index)).into());
    let plain = encode(mode, space_key, layer_key, anchors);
    let ct = cipher
        .encrypt(&nonce, Payload { msg: &plain, aad: &[] })
        .expect("XChaCha20-Poly1305 encryption cannot fail on a valid key");
    let mut out = Vec::with_capacity(SLOT_LEN);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    out
}

/// Random bytes shaped like a slot. An unoccupied slot must be indistinguishable from an occupied
/// one, which means it cannot be zeros and cannot be a different length.
pub fn random_slot() -> Vec<u8> {
    let mut v = vec![0u8; SLOT_LEN];
    OsRng.fill_bytes(&mut v);
    v
}

/// Try `password` against the whole table.
///
/// Every slot is attempted even after one opens: stopping early would make unlock time depend on
/// which slot matched, and which slot matched is precisely what must not be observable.
pub fn open_table(password: &[u8], salt: &[u8; 16], slots: &[Vec<u8>]) -> Option<Opened> {
    let master = argon2_master(password, salt);
    let mut found = None;
    for (i, raw) in slots.iter().enumerate() {
        if raw.len() != SLOT_LEN {
            continue;
        }
        let nonce = XNonce::from_slice(&raw[..SLOT_NONCE_LEN]);
        let cipher = XChaCha20Poly1305::new((&slot_key(&master, nonce.as_slice(), i)).into());
        if let Ok(plain) =
            cipher.decrypt(nonce, Payload { msg: &raw[SLOT_NONCE_LEN..], aad: &[] })
        {
            if let Some(o) = decode(&plain) {
                if found.is_none() {
                    found = Some(o);
                }
            }
        }
    }
    found
}

/// Whether two passwords would be the same key material. Enforced when passwords are SET.
///
/// If the everyday password and the one meant to be surrendered were equal, one password would
/// open two slots — and whoever was given it would find that out. The check belongs at the moment
/// of setting, where it can be refused, not at unlock, where it would be a leak.
pub fn passwords_are_distinct(a: &[u8], b: &[u8]) -> bool {
    a != b
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; 16] = [1u8; 16];
    const ANCHORS: [u64; ANCHOR_COUNT] = [11, 22];

    fn table(entries: Vec<(usize, Vec<u8>)>) -> Vec<Vec<u8>> {
        let mut t: Vec<Vec<u8>> = (0..SLOT_COUNT).map(|_| random_slot()).collect();
        for (i, s) in entries {
            t[i] = s;
        }
        t
    }

    #[test]
    fn a_password_opens_its_own_slot_and_yields_its_keys() {
        let s = seal_slot(b"pw", &SALT, 2, Mode::Protected, &[7u8; 32], Some(&[8u8; 32]), &ANCHORS);
        let t = table(vec![(2, s)]);
        let o = open_table(b"pw", &SALT, &t).expect("the slot must open");
        assert_eq!(o.mode, Mode::Protected);
        assert!(o.layer_key.is_some(), "a protected slot must carry the ownership key");
        assert_eq!(o.anchors, ANCHORS);
    }

    /// The public mode differs from the protected one ONLY in what the slot holds. Same length,
    /// same shape, same code path — the difference is the absence of a key, not a flag.
    #[test]
    fn a_public_slot_is_the_same_shape_as_a_protected_one() {
        let pub_slot = seal_slot(b"a", &SALT, 0, Mode::Public, &[7u8; 32], None, &ANCHORS);
        let prot_slot = seal_slot(b"b", &SALT, 0, Mode::Protected, &[7u8; 32], Some(&[9u8; 32]), &ANCHORS);
        assert_eq!(pub_slot.len(), prot_slot.len(), "the modes have different sizes on disk");
        assert_eq!(pub_slot.len(), SLOT_LEN);

        let o = open_table(b"a", &SALT, &table(vec![(0, pub_slot)])).expect("opens");
        assert!(o.layer_key.is_none(), "a public slot must not carry the ownership key");
    }

    /// An unoccupied slot is random bytes of the same length. Nothing about the table says how many
    /// passwords a container has.
    #[test]
    fn an_empty_slot_is_the_same_size_as_a_full_one() {
        let full = seal_slot(b"x", &SALT, 1, Mode::Hidden, &[1u8; 32], Some(&[2u8; 32]), &ANCHORS);
        assert_eq!(random_slot().len(), full.len());
        assert_eq!(random_slot().len(), SLOT_LEN);
    }

    /// A wrong password opens nothing, and gets no hint which slot it nearly matched.
    #[test]
    fn a_wrong_password_opens_nothing() {
        let s = seal_slot(b"right", &SALT, 3, Mode::Public, &[7u8; 32], None, &ANCHORS);
        assert!(open_table(b"wrong", &SALT, &table(vec![(3, s)])).is_none());
    }

    /// A table of nothing but random slots opens for nobody, and does not panic trying.
    #[test]
    fn an_all_random_table_opens_for_nobody() {
        assert!(open_table(b"anything", &SALT, &table(vec![])).is_none());
    }

    /// The salt is part of the derivation: the same password against another container's salt is a
    /// different key, so one container's slot cannot be opened by another's password.
    #[test]
    fn the_same_password_under_another_salt_does_not_open_the_slot() {
        let s = seal_slot(b"pw", &SALT, 0, Mode::Public, &[7u8; 32], None, &ANCHORS);
        assert!(open_table(b"pw", &[2u8; 16], &table(vec![(0, s)])).is_none());
    }

    /// A slot is bound to its index: moving it elsewhere in the table does not let the same
    /// password open it, so the table cannot be reshuffled to swap which password does what.
    #[test]
    fn a_slot_does_not_open_from_another_index() {
        let s = seal_slot(b"pw", &SALT, 1, Mode::Public, &[7u8; 32], None, &ANCHORS);
        assert!(open_table(b"pw", &SALT, &table(vec![(5, s)])).is_none());
    }

    /// Two different passwords coexist, each opening only its own slot.
    #[test]
    fn two_passwords_open_their_own_slots_and_not_each_others() {
        let a = seal_slot(b"alpha", &SALT, 0, Mode::Protected, &[1u8; 32], Some(&[2u8; 32]), &ANCHORS);
        let b = seal_slot(b"beta", &SALT, 4, Mode::Hidden, &[3u8; 32], Some(&[4u8; 32]), &ANCHORS);
        let t = table(vec![(0, a), (4, b)]);
        assert_eq!(open_table(b"alpha", &SALT, &t).unwrap().mode, Mode::Protected);
        assert_eq!(open_table(b"beta", &SALT, &t).unwrap().mode, Mode::Hidden);
    }

    /// Identical passwords are refused at the point of setting. If they were allowed, one password
    /// would open two slots and whoever was handed it would discover that.
    #[test]
    fn identical_passwords_are_refused_when_set() {
        assert!(!passwords_are_distinct(b"same", b"same"));
        assert!(passwords_are_distinct(b"one", b"another"));
    }

    /// The plaintext is a fixed length whatever the mode, so a decrypted slot's size says nothing.
    #[test]
    fn the_sealed_plaintext_is_the_same_length_for_every_mode() {
        let a = encode(Mode::Public, &[0u8; 32], None, &ANCHORS);
        let b = encode(Mode::Protected, &[0u8; 32], Some(&[1u8; 32]), &ANCHORS);
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), SLOT_PLAIN_LEN);
    }

    /// The unused tail is random, not zeros. A zeroed tail would say how much of the slot was
    /// meaningful — the same class of leak the fixed length removes.
    #[test]
    fn the_unused_tail_of_a_slot_is_random_not_zeroed() {
        let a = encode(Mode::Public, &[0u8; 32], None, &ANCHORS);
        let b = encode(Mode::Public, &[0u8; 32], None, &ANCHORS);
        let tail = 65 + ANCHOR_COUNT * 8;
        assert_ne!(a[tail..], b[tail..], "the padding is deterministic");
        assert!(a[tail..].iter().any(|&x| x != 0), "the padding is zeroed");
    }
}
