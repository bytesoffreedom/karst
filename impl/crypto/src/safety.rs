//! The safety number — a human-readable verification of a §2.1 IK's authenticity over an
//! OUT-OF-BAND channel (voice, an in-person meeting, video). It closes the one wall the model
//! cannot close cryptographically: the relay is NOT an identity anchor, so IK authenticity is
//! established out of band, otherwise an IK swap is a MITM.
//!
//! **What exactly is verified:** the AUTHENTICITY OF THE IK, and only that. It is sufficient
//! because IK authenticity implies session authenticity: the PQXDH `root_key` is load-bearing on
//! `DH1 = IK_A × PK_B` and binds both IKs into the transcript (see `pqxdh`) — a party without the
//! IK secret cannot agree the same key (fail-closed). A prekey or KEM substitution at the relay
//! forms no session at all (so it needs no separate detection). That is why exactly
//! `identity_public()` is hashed.
//!
//! **The construction.** It is symmetric: both sides sort the IK pair and obtain the same number.
//! `SHA-512(DOMAIN ‖ VERSION ‖ lo ‖ hi)` → the first 60 bytes → 12 groups of 5 bytes (big-endian)
//! `mod 100000` → 12×5 = **60 decimal digits** (in the spirit of Signal). An iterated KDF (Signal's
//! 5200 rounds) is not needed: at the full 60-digit width (~199 bits) a MITM looking for a matching
//! number `SN(A,M_a)==SN(B,M_b)` runs into a two-list collision at ~2^100 — iteration adds nothing
//! once the full width is displayed. The width carries the strength.
//! once the full width is displayed. The width carries the strength.

use sha2::{Digest, Sha512};

const DOMAIN: &[u8] = b"KARST-safety-number";
/// The format version — changing it breaks fingerprint compatibility deliberately.
const VERSION: u8 = 1;
/// Groups of 5 digits (as in Signal: 60 digits in total). It needs `GROUPS*5` bytes of digest.
const GROUPS: usize = 12;

/// The 60-digit fingerprint of a §2.1 IK pair, grouped in fives with spaces (`"01234 56789 …"`, 12
/// groups). Symmetric: `safety_number(a,b) == safety_number(b,a)`. Read aloud or compared visually
/// for the out-of-band check.
pub fn safety_number(ik_a: &[u8; 32], ik_b: &[u8; 32]) -> String {
    // Symmetry: a canonical order for the pair (the smaller IK first).
    let (lo, hi) = if ik_a <= ik_b { (ik_a, ik_b) } else { (ik_b, ik_a) };

    let mut h = Sha512::new();
    h.update(DOMAIN);
    h.update([VERSION]);
    h.update(lo);
    h.update(hi);
    let digest = h.finalize(); // 64 bytes ≥ GROUPS*5

    let mut out = String::with_capacity(GROUPS * 6);
    for i in 0..GROUPS {
        let start = i * 5;
        // 5 bytes big-endian → u64 → 5 decimal digits.
        let mut v: u64 = 0;
        for &b in &digest[start..start + 5] {
            v = (v << 8) | b as u64;
        }
        let chunk = v % 100_000;
        if i > 0 {
            out.push(' ');
        }
        // Zero-padding to 5 digits is MANDATORY: without it the groups drift apart and the visual
        // out-of-band comparison — the whole point of the feature — silently breaks.
        out.push_str(&format!("{chunk:05}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frozen known-answer test: it pins DOMAIN, VERSION, the sort order, the endianness, the
    /// chunk arithmetic AND the zero-padding against silent drift (like the conformance vectors).
    /// The value came from the implementation itself and is frozen.
    #[test]
    fn frozen_known_answer_vector() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[0] = 1;
        let sn = safety_number(&a, &b);
        assert_eq!(sn, "17189 06467 41496 60988 88669 01686 91612 33462 95102 33841 50843 30572");
    }

    /// Symmetry: the argument order does not matter (both sides see the same number).
    #[test]
    fn symmetric_in_arguments() {
        let a = [7u8; 32];
        let b = [9u8; 32];
        assert_eq!(safety_number(&a, &b), safety_number(&b, &a));
    }

    /// Sensitivity: flipping ONE bit of one IK gives a different number (otherwise an IK swap
    /// would go undetected — the whole point of the feature).
    #[test]
    fn one_bit_flip_changes_number() {
        let a = [0u8; 32];
        let b = [0x55u8; 32];
        let mut b2 = b;
        b2[31] ^= 0x01;
        assert_ne!(safety_number(&a, &b), safety_number(&a, &b2));
    }

    /// The format: exactly 60 digits in 12 groups of 5, separated by spaces.
    #[test]
    fn format_is_twelve_groups_of_five_digits() {
        let sn = safety_number(&[1u8; 32], &[2u8; 32]);
        let groups: Vec<&str> = sn.split(' ').collect();
        assert_eq!(groups.len(), 12, "12 groups");
        for g in groups {
            assert_eq!(g.len(), 5, "5 digits per group (zero-padded)");
            assert!(g.chars().all(|c| c.is_ascii_digit()), "digits only");
        }
    }
}
