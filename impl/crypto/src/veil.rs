//! **Per-relay re-randomisation of an already-encrypted envelope** (PRIV-4).
//!
//! # This provides NO security property, and that is the whole point of saying so first
//!
//! The inner payload is already a ratchet ciphertext: confidential, authenticated, and
//! indistinguishable from random. The veil adds nothing to any of that, and nothing here should ever
//! be cited as protecting content. It defeats exactly one thing — an adversary who compares BYTES.
//!
//! # The adversary it defeats
//!
//! Multi-homing exists so a message still lands when the primary relay is down. The way it lands is
//! a retransmit of the SAME queued envelope, so the same ciphertext can reach two relays. Two
//! operators who compare logs then match on equality and learn "this is one message" — with no
//! analysis, no timing, no volume study. PRIV-12 removed the same join on the box ADDRESS; this
//! removes it on the payload.
//!
//! # Why the nonce is DERIVED and not random
//!
//! A fresh random nonce per transmit looks obviously right and breaks something real: the relay
//! deduplicates a redeposited payload by hashing it (`protocol::payload_id`), so a retransmit to the
//! SAME relay would arrive as different bytes, fail to dedup, and sit in the mailbox twice. The
//! recipient would dedup it eventually, after paying for the delivery.
//!
//! So the nonce is a function of `(relay_id, inner bytes)`:
//!
//! - two relays, one message  → different nonce → different bytes  (the goal)
//! - one relay, a retransmit  → identical nonce → identical bytes  (dedup still works)
//!
//! Deriving a nonce from the data it protects would be a mistake in an AEAD; here there is nothing
//! to protect. The keystream's only job is to be different per relay, and the key is per-session, so
//! a repeat of the same message to the same relay reproducing the same output is CORRECT rather than
//! a reuse hazard.
//!
//! # Construction
//!
//! `keystream = HKDF-SHA256(salt = nonce, ikm = drop_seed).expand("karst-veil-v1", len)`, XORed over
//! the inner bytes. HKDF rather than a stream cipher so this adds no dependency, and the lengths
//! involved (~1.4 KB per envelope) are far inside HKDF's 255·32-byte output limit.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// Nonce size — 12 bytes, enough that a collision between two relays is not a consideration.
pub const NONCE_LEN: usize = 12;

/// HKDF's output ceiling is 255 · 32 bytes. Refusing anything near it turns a future oversize
/// envelope into a loud error rather than a panic inside `expand`.
const MAX_VEILED: usize = 255 * 32;

/// The nonce for this `(relay, inner)` pair. Deterministic — see the module docs on why.
fn nonce_for(relay_id: &[u8; 32], inner: &[u8]) -> [u8; NONCE_LEN] {
    let mut h = Sha256::new();
    h.update(b"karst-veil-nonce-v1");
    h.update(relay_id);
    h.update(inner);
    let digest = h.finalize();
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(&digest[..NONCE_LEN]);
    n
}

fn keystream(drop_seed: &[u8; 32], nonce: &[u8; NONCE_LEN], len: usize) -> Option<Vec<u8>> {
    if len > MAX_VEILED {
        return None;
    }
    let hk = Hkdf::<Sha256>::new(Some(nonce), drop_seed);
    let mut out = vec![0u8; len];
    hk.expand(b"karst-veil-v1", &mut out).ok()?;
    Some(out)
}

/// Veil `inner` for one relay. `None` only if `inner` is absurdly long (see [`MAX_VEILED`]).
pub fn veil(
    drop_seed: &[u8; 32],
    relay_id: &[u8; 32],
    inner: &[u8],
) -> Option<([u8; NONCE_LEN], Vec<u8>)> {
    let nonce = nonce_for(relay_id, inner);
    let ks = keystream(drop_seed, &nonce, inner.len())?;
    Some((nonce, inner.iter().zip(ks).map(|(a, b)| a ^ b).collect()))
}

/// Recover the inner bytes. The nonce arrives on the wire, so a hostile relay can corrupt it —
/// which yields garbage, which the inner ratchet AEAD then refuses. Indistinguishable in effect
/// from the relay simply dropping the message, which it can always do.
pub fn unveil(drop_seed: &[u8; 32], nonce: &[u8; NONCE_LEN], veiled: &[u8]) -> Option<Vec<u8>> {
    let ks = keystream(drop_seed, nonce, veiled.len())?;
    Some(veiled.iter().zip(ks).map(|(a, b)| a ^ b).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [4u8; 32];
    const INNER: &[u8] = b"an already-encrypted ratchet envelope, as far as this module cares";

    #[test]
    fn it_round_trips() {
        let (n, v) = veil(&SEED, &[0xA1; 32], INNER).expect("veils");
        assert_eq!(unveil(&SEED, &n, &v).expect("unveils"), INNER);
    }

    /// **THE property.** One message, two relays, different bytes.
    ///
    /// DISCRIMINATING: drop `relay_id` from `nonce_for` and this goes red — which is the state the
    /// code was in before PRIV-4, and the state in which two operators join on equality.
    #[test]
    fn the_same_message_looks_different_at_two_relays() {
        let (n1, v1) = veil(&SEED, &[0xA1; 32], INNER).expect("veils");
        let (n2, v2) = veil(&SEED, &[0xB2; 32], INNER).expect("veils");
        assert_ne!(n1, n2, "the nonce did not vary by relay");
        assert_ne!(
            v1, v2,
            "one message produced IDENTICAL bytes at two relays, so two operators comparing logs \
             match on equality and learn it is one message — no analysis required"
        );
    }

    /// **The property that keeps the relay's own deduplication working.** A retransmit to the SAME
    /// relay must be byte-identical, or `protocol::payload_id` sees a new payload and the mailbox
    /// holds the message twice.
    ///
    /// DISCRIMINATING: make the nonce random and this goes red.
    #[test]
    fn a_retransmit_to_one_relay_is_byte_identical() {
        let a = veil(&SEED, &[0xA1; 32], INNER).expect("veils");
        let b = veil(&SEED, &[0xA1; 32], INNER).expect("veils");
        assert_eq!(a, b, "a retransmit changed bytes, so the relay can no longer dedup it");
    }

    /// A different session cannot unveil it — not a security claim, just a check that the key is
    /// actually the session's and not a constant.
    #[test]
    fn another_sessions_seed_recovers_garbage() {
        let (n, v) = veil(&SEED, &[0xA1; 32], INNER).expect("veils");
        assert_ne!(unveil(&[7u8; 32], &n, &v).expect("unveils"), INNER);
    }

    #[test]
    fn an_absurd_length_is_refused_rather_than_panicking() {
        assert!(veil(&SEED, &[0xA1; 32], &vec![0u8; MAX_VEILED + 1]).is_none());
    }
}
