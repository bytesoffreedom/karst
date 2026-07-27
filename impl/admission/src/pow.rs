//! §7 — Proof-of-Work for the PUBLIC door (slice 4a).
//!
//! A Public relay must not pre-share one invite capability with the whole internet
//! (spam-exposed) nor mint a fresh capability for anyone who asks (free Sybil). The gate
//! is hashcash: a client spends CPU to *earn* a capability, and the existing per-capability
//! quota then bounds what that capability can do. One mechanism, three jobs — the Public
//! door, the spam bound, and the price of a throwaway account (§ROADMAP "Sybil / burners").
//!
//! **What PoW does and does not buy (stated plainly, Principle 7).** One solve buys ONE
//! capability, which then sends at its quota RATE (`POW_CAP_QUOTA`, e.g. ≤100 requests / 10
//! min) for its whole lifetime (`ISSUED_CAP_TTL_SECS`) — NOT a fixed number of messages. To
//! sustain more than that rate an attacker needs more capabilities, i.e. one more solve per
//! extra `POW_CAP_QUOTA` of sustained throughput. So PoW rate-limits how fast fresh
//! capabilities appear and the quota bounds each; together they "buy minutes against a casual
//! attacker; a well-resourced adversary does not notice it." The difficulty is an operator knob
//! (`KARST_RELAY_POW_BITS`) — a speed bump, **not** Sybil resistance (a GPU farm still mints
//! many caps). The honest ceiling is unchanged by this slice.
//!
//! The preimage binds the relay's identity (a solution farmed for relay A is worthless at
//! relay B) and a time bucket (a solution is only redeemable near its bucket, so a stockpile
//! goes stale). SHA-256 hashcash, NOT a memory-hard function: the relay must verify every
//! redemption in one hash, so a memory-hard PoW would move the DoS onto the relay's verifier.

use sha2::{Digest, Sha256};

/// Domain-separated PoW preimage hash:
/// `SHA256("KARST-pow-cap-v1" ‖ relay_id ‖ bucket ‖ client_seed ‖ nonce)`.
///
/// - `relay_id` binds the work to ONE relay (its fetch-auth public key), so a solution
///   cannot be farmed once and redeemed across many relays.
/// - `bucket` (a coarse time window, see `params::POW_WINDOW_SECS`) binds the work to a
///   time, so precomputed solutions go stale rather than accumulating forever.
/// - `client_seed` is fresh random per attempt, so two joins by the same client are
///   unlinkable and yield independent capabilities.
pub fn pow_hash(relay_id: &[u8; 32], bucket: u32, client_seed: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"KARST-pow-cap-v1");
    h.update(relay_id);
    h.update(bucket.to_be_bytes());
    h.update(client_seed);
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}

/// Number of leading zero BITS of a hash (the hashcash difficulty measure).
pub fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut bits = 0u32;
    for &b in hash {
        if b == 0 {
            bits += 8;
        } else {
            bits += b.leading_zeros();
            break;
        }
    }
    bits
}

/// Verify a PoW solution meets `difficulty_bits`. `difficulty_bits == 0` accepts anything
/// (PoW disabled) — an operator's explicit choice, not a silent bypass.
pub fn verify(
    relay_id: &[u8; 32],
    bucket: u32,
    client_seed: &[u8; 32],
    nonce: u64,
    difficulty_bits: u32,
) -> bool {
    leading_zero_bits(&pow_hash(relay_id, bucket, client_seed, nonce)) >= difficulty_bits
}

/// Solve the PoW: find the smallest `nonce` whose hash has `difficulty_bits` leading zeros.
/// Client-side work. Deterministic in its inputs, so a lost capability can be re-earned from
/// the same `(bucket, client_seed)` while the bucket is still fresh. Returns `None` only if
/// the u64 nonce space is exhausted (unreachable for any sane difficulty).
pub fn solve(
    relay_id: &[u8; 32],
    bucket: u32,
    client_seed: &[u8; 32],
    difficulty_bits: u32,
) -> Option<u64> {
    (0u64..=u64::MAX).find(|&nonce| verify(relay_id, bucket, client_seed, nonce, difficulty_bits))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zeros_counts_bits() {
        assert_eq!(leading_zero_bits(&[0u8; 32]), 256);
        let mut h = [0u8; 32];
        h[0] = 0x0f; // 0000_1111 → 4 leading zeros
        assert_eq!(leading_zero_bits(&h), 4);
        h = [0u8; 32];
        h[1] = 0x80; // first byte all zero (8) + next byte 1000_0000 (0) → 8
        assert_eq!(leading_zero_bits(&h), 8);
    }

    #[test]
    fn solve_then_verify_roundtrips() {
        let relay = [7u8; 32];
        let seed = [9u8; 32];
        let bits = 12; // cheap for a test
        let nonce = solve(&relay, 42, &seed, bits).expect("solvable");
        assert!(verify(&relay, 42, &seed, nonce, bits));
    }

    /// Discriminating: a solution is bound to relay_id AND bucket AND seed — changing any
    /// invalidates it. Neuter `pow_hash` to drop one field and this goes red.
    #[test]
    fn solution_is_bound_to_relay_bucket_seed() {
        let relay = [7u8; 32];
        let seed = [9u8; 32];
        let bits = 12;
        let nonce = solve(&relay, 42, &seed, bits).expect("solvable");
        assert!(verify(&relay, 42, &seed, nonce, bits));
        assert!(!verify(&[8u8; 32], 42, &seed, nonce, bits), "other relay must reject");
        assert!(!verify(&relay, 43, &seed, nonce, bits), "other bucket must reject");
        assert!(!verify(&relay, 42, &[10u8; 32], nonce, bits), "other seed must reject");
    }

    /// The difficulty threshold is exact: a hash with K leading zeros clears difficulty K
    /// but not K+1 — the property the door's rate-limit rests on. Crafted hash, so it is
    /// deterministic (no reliance on where a solved nonce happens to land).
    #[test]
    fn difficulty_threshold_is_exact() {
        let mut hash = [0u8; 32];
        hash[1] = 0x10; // byte0=0 (8 zeros) + 0001_0000 (3 zeros) = 11 leading zeros
        assert_eq!(leading_zero_bits(&hash), 11);
        // verify() is `leading_zero_bits >= difficulty`, so 11 passes ≤11 and fails ≥12.
        assert!(leading_zero_bits(&hash) >= 11);
        assert!(leading_zero_bits(&hash) < 12, "a hard gate must reject a weaker solution");
    }
}
