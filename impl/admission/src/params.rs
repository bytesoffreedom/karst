//! §7.0 — Параметры протокола.

/// Длительность quota-эпохи (anonymous rate limiting, §7.4).
pub const EPOCH_DURATION_SECS: u64 = 10 * 60;
/// Время жизни stateless cookie (§7.1).
pub const COOKIE_TTL_SECS: u64 = 30;
/// Число эпох, в течение которых предыдущий cookie-ключ ещё принимается (§7.1).
pub const GRACE_EPOCHS: u64 = 1;
/// Максимальный размер пакета на входе (§7.0) — потолок bounded-parse на ступени 0,
/// НЕ MTU канала: live-путь идёт TCP внутри Noise-сессии, которая сама кадрирует и
/// пересобирает.
///
/// Was 1400 and contradicted Principle 6: an ML-KEM-768 key agreement is ~1.1 KB by
/// itself, so a post-quantum opener carrying a first message longer than ~120 B was
/// silently dropped as oversize (`DropNoReply`). A spec mandating PQ key agreement and a
/// ceiling too small to carry one is inconsistent — the ceiling was the arbitrary part.
/// 2560 is sized from the real protocol: sealed ML-KEM opener (~1.2 KB) + a
/// maximum-length first message (1 KB) + framing. Ordinary messages (~1 KB) are
/// unaffected; the headroom exists only for the envelope that needs it.
pub const MAX_PACKET_SIZE: usize = 2560;
/// Фиксированный размер challenge-ответа непроверенному адресу (§7.1).
pub const COOKIE_CHALLENGE_SIZE: usize = 64;

/// cookie-эпоха — локальный секрет relay, ротируется независимо от quota-эпохи.
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
