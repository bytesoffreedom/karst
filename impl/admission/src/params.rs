//! §7.0 — protocol parameters.

/// The quota epoch duration (anonymous rate limiting, §7.4).
pub const EPOCH_DURATION_SECS: u64 = 10 * 60;
/// The lifetime of a stateless cookie (§7.1).
pub const COOKIE_TTL_SECS: u64 = 30;
/// How many epochs a previous cookie key is still accepted for.
pub const GRACE_EPOCHS: u64 = 1;
/// The maximum packet size at the entrance (§7.0) — the bounded-parse ceiling at stage 0.
/// NOT the link MTU: the live path runs over TCP inside a Noise session, which frames and
/// reassembles on its own.
///
/// Was 1400 and contradicted Principle 6: an ML-KEM-768 key agreement is ~1.1 KB by
/// itself, so a post-quantum opener carrying a first message longer than ~120 B was
/// silently dropped as oversize (`DropNoReply`). A spec mandating PQ key agreement and a
/// ceiling too small to carry one is inconsistent — the ceiling was the arbitrary part.
/// Raised a SECOND time, 2560 -> 3840, by the same argument (PRIV-3). The outer sealed opener now
/// carries its own ML-KEM-768 ciphertext so a quantum adversary cannot recover the social graph
/// from a recorded first contact. That is +1088 bytes on the one envelope in the protocol that was
/// already the largest, and the previous ceiling had no room for it: the budget comes to
///
///   1235 (sealed key agreement) + 1088 (outer KEM ciphertext)
/// + 1325 (padded plaintext + AEAD tag) + 64 (opener framing) + 128 (admission framing) = 3840
///
/// Shrinking the envelope instead was not an option: `pad::PADDED_LEN` is derived from THIS
/// constant, and taking 1088 out of it would leave ~29 bytes for a message whose largest legal
/// `Content` is 1053. The ceiling is again the arbitrary part — a design that mandates
/// post-quantum protection for the social graph and a ceiling too small to carry it are
/// inconsistent, exactly as with the first raise.
///
/// 3840 rather than the tight 3648: the extra 192 bytes go into `pad::MAX_PAYLOAD`, whose margin
/// over the largest legal `Content` was down to 60 bytes. A privacy parameter with 5% headroom is
/// one new message variant away from a silent send failure.
///
/// **What this costs, said plainly.** Every ordinary message is padded to the same block, so the
/// per-message cost rises with the ceiling: ~1.3 KB of plaintext per message instead of ~1.1 KB.
/// That is the price of a uniform size class (PRIV-1), and it is paid to hide message length rather
/// than to carry the opener's PQ ciphertext — ordinary messages do not contain one.
pub const MAX_PACKET_SIZE: usize = 3840;
/// The fixed size of the challenge reply to an unverified address (§7.1).
pub const COOKIE_CHALLENGE_SIZE: usize = 64;

/// The cookie epoch is a relay-local secret, rotated independently of the quota epoch.
pub fn cookie_epoch_id(unix_secs: u64, epoch_duration_secs: u64) -> u32 {
    (unix_secs / epoch_duration_secs) as u32
}

// ---- §7 PUBLIC-door PoW (slice 4a). See `pow.rs`. ----

/// PoW time-bucket width. A solution names the bucket it was mined for and is only
/// redeemable while that bucket is current (± `POW_BUCKET_SKEW`), so a precomputed stockpile
/// goes stale instead of accumulating. One hour: coarse enough that a client's solve time is
/// negligible against it, fine enough that stale solutions expire promptly.
pub const POW_WINDOW_SECS: u64 = 3600;

/// Buckets of clock skew tolerated on redemption: a solution for bucket `b` is accepted while
/// `now`'s bucket is in `[b - SKEW, b + SKEW]`. Covers client/relay clock drift and the time
/// spent solving without widening the stale-stockpile window meaningfully.
pub const POW_BUCKET_SKEW: u32 = 1;

/// Default PoW difficulty (leading zero bits) for a Public relay, overridable by the operator
/// via `KARST_RELAY_POW_BITS`. 20 bits ≈ ~10^6 hashes — a sub-second-to-seconds speed bump on
/// a CPU. This is a *rate* limiter on fresh capabilities, NOT Sybil resistance; the real
/// per-capability bound is `POW_CAP_QUOTA`. Named honestly in `pow.rs`.
pub const DEFAULT_POW_BITS: u32 = 20;

/// Lifetime of a PoW-earned capability. After this the client re-solves (fresh work). It sets
/// how often the CPU price is re-paid — and, since a cap sends at its quota rate for its whole
/// life, it directly scales the throughput one solve buys (a longer TTL lets more still-valid
/// caps accumulate from a fixed solve rate). 1 day is low friction for a client (a background
/// re-join) while keeping that per-solve budget from ballooning the way a multi-day TTL would.
pub const ISSUED_CAP_TTL_SECS: u64 = 24 * 3600;
