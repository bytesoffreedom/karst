//! §7.7 — the DTN admission class (store-and-forward mesh: Bluetooth / Wi-Fi Direct).
//!
//! An admission class separate from the live one (§7.1–7.5). The threat model differs: in a mesh
//! the connection is physical and a third party cannot spoof an address; what is protected is not
//! a server but the carrying device — against a neighbour on the air who buries it in garbage,
//! draining the battery and filling the memory. Hence no epoch-based cookie or RLN, but two
//! independent mechanisms plus a separate replay filter on the way back into the network.
//!
//!
//! The only crypto here is a symmetric HMAC (as in §7.2) — nothing exotic, so this module lives in
//! the core without a feature gate.
//!
//! **Scope (honestly).** The PRIMITIVES of the DTN class are built here (the capability, the carry
//! budget and the rolling replay window), but they are NOT yet woven into `pipeline.rs`. Per §10
//! (audit round 3) Ingress branches on the credential type at Stage 4 — no separate DTN gateway is
//! introduced — so rolling replay and the DTN capability eventually attach to that branch of
//! `pipeline` rather than as a parallel gateway. Integration is the next slice.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// A placeholder parameter (§7.7): the upper bound on mesh transit TTL. It needs calibration
/// against real latency measurements — seven days is a starting point.
pub const MAX_DTN_TRANSIT_TTL_SECS: u64 = 7 * 24 * 60 * 60;
pub const SECS_PER_DAY: u64 = 24 * 60 * 60;

/// The global ceiling on a DTN capsule (§7.7/§21.1). Unlike the live class, a DTN capsule is a
/// stored object (up to the ~1 MB size bucket of §21.1) uploaded as a stream, NOT a UDP datagram
/// under the live MTU `MAX_PACKET_SIZE`. This is a cheap pre-verification gate: reject an
/// obviously huge upload BEFORE hashing it. The authoritative quota for a specific capsule comes
/// from `DtnQuota.max_bytes` (checked after the capability verifies).
/// `DtnQuota.max_bytes` (checked after the capability verifies).
pub const MAX_DTN_CAPSULE_SIZE: usize = 1 << 20; // 1 MiB

// ============================================================================
// 1. The DTN capability — a separate type, without epoch quantisation (§7.7 item 1)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtnQuota {
    pub max_bytes: u64,
    /// **An advisory field, NOT cryptographically enforced (§7.7).**
    /// Nothing binds the decrement to the real number of hops: the carrier physically owns all of
    /// the capsule's state and may simply not decrement it. The real protection is
    /// `CarryBudgetTracker` below, which governs the device's own resource. This is kept as
    /// advisory metadata for well-behaved clients.
    /// advisory metadata for well-behaved clients.
    pub max_hops: u32,
}

/// The secret record held by the issuing relay. Only the proof travels on the wire.
#[derive(Debug, Clone)]
pub struct DtnCapability {
    pub capability_id: [u8; 16],
    pub issued_at: u64, // unix seconds, unquantised
    pub not_after: u64, // issued_at plus at most MAX_DTN_TRANSIT_TTL
    pub quota: DtnQuota,
    pub secret: [u8; 32],
}

/// What travels on the wire alongside the capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtnCapabilityProof {
    pub capability_id: [u8; 16],
    pub mac: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtnCapError {
    UnknownCapability,
    /// now > not_after — the transit window has expired.
    Expired,
    /// not_after lies beyond issued_at + MAX_DTN_TRANSIT_TTL.
    TtlTooLong,
    /// The capsule size exceeds this capability's `quota.max_bytes`.
    QuotaExceeded,
    BadMac,
}

impl DtnCapability {
    /// Check the issued capability itself for correctness (the TTL invariant).
    pub fn validate_issue(&self) -> Result<(), DtnCapError> {
        if self.not_after > self.issued_at.saturating_add(MAX_DTN_TRANSIT_TTL_SECS) {
            return Err(DtnCapError::TtlTooLong);
        }
        Ok(())
    }

    /// Build the proof: mac = HMAC(secret, request_nonce).
    /// Without an epoch (unlike the live class, §7.2) — mesh delivery takes days.
    pub fn prove(&self, request_nonce: &[u8]) -> DtnCapabilityProof {
        DtnCapabilityProof {
            capability_id: self.capability_id,
            mac: compute_mac(&self.secret, request_nonce),
        }
    }
}

/// The issuing relay's local table: `capability_id → DtnCapability`.
#[derive(Default)]
pub struct DtnCapabilityTable {
    entries: HashMap<[u8; 16], DtnCapability>,
}

impl DtnCapabilityTable {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, cap: DtnCapability) {
        self.entries.insert(cap.capability_id, cap);
    }

    /// Proof verification: expiry (by our own clock), size, then MAC.
    /// `capsule_bytes` is the actual size of the presented capsule, checked against
    /// `quota.max_bytes` (§7.7). Order: the cheap checks (expiry, size) come before the MAC.
    pub fn verify(
        &self,
        proof: &DtnCapabilityProof,
        request_nonce: &[u8],
        capsule_bytes: u64,
        now: u64,
    ) -> Result<&DtnCapability, DtnCapError> {
        let cap = self
            .entries
            .get(&proof.capability_id)
            .ok_or(DtnCapError::UnknownCapability)?;
        if now > cap.not_after {
            return Err(DtnCapError::Expired);
        }
        if capsule_bytes > cap.quota.max_bytes {
            return Err(DtnCapError::QuotaExceeded);
        }
        let expected = compute_mac(&cap.secret, request_nonce);
        if expected.ct_eq(&proof.mac).into() {
            Ok(cap)
        } else {
            Err(DtnCapError::BadMac)
        }
    }
}

fn compute_mac(secret: &[u8; 32], request_nonce: &[u8]) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(request_nonce);
    let full = mac.finalize().into_bytes();
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&full[..16]);
    truncated
}

// ============================================================================
// 2. The carrier's local budget: per-peer and device-wide (§7.7 item 2)
// ============================================================================

/// A neighbour's ephemeral mesh identity (Bluetooth / Wi-Fi Direct) — a fingerprint.
pub type PeerId = [u8; 16];

#[derive(Debug, Clone, Copy)]
pub struct BudgetLimits {
    /// The sliding window (§7.7): 24 hours, for example.
    pub window_secs: u64,
    /// Bounds ONE insistent neighbour.
    pub per_peer_max_messages: u32,
    pub per_peer_max_bytes: u64,
    /// Bounds a Sybil built from many cheap identities — in aggregate across ALL peers, whatever
    /// the number of identities (§7.7: the mandatory second ceiling).
    pub device_max_messages: u32,
    pub device_max_bytes: u64,
    /// A local PoW throttle (§7.7): how many leading zero bits a peer must present for EVERY
    /// capsule. Not protection against spoofing (there is none in a mesh) but a pure rate
    /// throttle: how fast an unknown peer can flood you within one contact session. In production
    /// it adapts to the device's battery and memory; here it is a configurable constant. 0
    /// disables the PoW.
    pub pow_difficulty_bits: u32,
}

/// A neighbour's offer to have its capsule carried. The PoW is bound to `capsule_tag`, so it
/// cannot be reused across different capsules.
#[derive(Debug, Clone, Copy)]
pub struct CarryOffer<'a> {
    pub peer: PeerId,
    /// The capsule's unique tag (its hash, for example) — what the PoW is bound to.
    pub capsule_tag: &'a [u8],
    pub bytes: u64,
    /// The PoW nonce the peer found (see `solve_pow`).
    pub pow_nonce: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarryDecision {
    Accept,
    /// The PoW is of insufficient difficulty — throttled before any budget check.
    RejectPow,
    /// One peer exceeded its per-peer limit (the device budget still has room).
    RejectPerPeer,
    /// The aggregate device budget is exhausted — regardless of the number of identities.
    /// This is the rejection that catches a Sybil built from many ephemeral peers.
    RejectDevice,
}

/// The number of leading zero bits in the PoW hash of (peer ‖ capsule_tag ‖ nonce).
pub fn pow_leading_zero_bits(peer: &PeerId, capsule_tag: &[u8], nonce: u64) -> u32 {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(b"KARST-dtn-pow-v1");
    h.update(peer);
    h.update((capsule_tag.len() as u64).to_be_bytes());
    h.update(capsule_tag);
    h.update(nonce.to_be_bytes());
    let digest = h.finalize();
    let mut bits = 0u32;
    for byte in digest.iter() {
        if *byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// Find a PoW nonce of the required difficulty for (peer, capsule_tag) — the peer's work, not the
/// carrier's. Returns the first suitable nonce.
pub fn solve_pow(peer: &PeerId, capsule_tag: &[u8], difficulty_bits: u32) -> u64 {
    let mut nonce = 0u64;
    loop {
        if pow_leading_zero_bits(peer, capsule_tag, nonce) >= difficulty_bits {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// An event in the sliding window: (time, size).
type Event = (u64, u64);

/// The carrying device's local policy. Not part of the network protocol and requiring no
/// negotiation. Memory is bounded by the device budget itself: only events inside the window are
/// stored, and their number cannot exceed device_max_messages.
pub struct CarryBudgetTracker {
    limits: BudgetLimits,
    per_peer: HashMap<PeerId, VecDeque<Event>>,
    device: VecDeque<(PeerId, u64, u64)>, // (peer, ts, bytes) for the aggregate and for pruning
    device_bytes: u64,
}

impl CarryBudgetTracker {
    pub fn new(limits: BudgetLimits) -> Self {
        CarryBudgetTracker {
            limits,
            per_peer: HashMap::new(),
            device: VecDeque::new(),
            device_bytes: 0,
        }
    }

    /// Drop everything older than `now - window` from the window. Updates the device aggregate and
    /// clears emptied per-peer entries (otherwise a Sybil would inflate the map).
    fn prune(&mut self, now: u64) {
        let horizon = now.saturating_sub(self.limits.window_secs);
        while let Some(&(peer, ts, bytes)) = self.device.front() {
            if ts <= horizon {
                self.device.pop_front();
                self.device_bytes -= bytes;
                if let Some(q) = self.per_peer.get_mut(&peer) {
                    // Remove the corresponding oldest event of that peer.
                    while let Some(&(pts, _)) = q.front() {
                        if pts <= horizon {
                            q.pop_front();
                        } else {
                            break;
                        }
                    }
                    if q.is_empty() {
                        self.per_peer.remove(&peer);
                    }
                }
            } else {
                break;
            }
        }
    }

    fn peer_totals(&self, peer: &PeerId) -> (u32, u64) {
        match self.per_peer.get(peer) {
            Some(q) => (q.len() as u32, q.iter().map(|&(_, b)| b).sum()),
            None => (0, 0),
        }
    }

    /// The decision on an incoming offer to carry a capsule.
    /// Order: the PoW throttle (which makes the peer spend CPU on every attempt) → per-peer (a
    /// cheap local neighbour) → device-wide (Sybil). Only an Accept is recorded.
    pub fn offer(&mut self, offer: &CarryOffer, now: u64) -> CarryDecision {
        // The PoW throttle is bound to this specific capsule, so it cannot be reused.
        // difficulty=0 skips the check.
        if self.limits.pow_difficulty_bits > 0
            && pow_leading_zero_bits(&offer.peer, offer.capsule_tag, offer.pow_nonce)
                < self.limits.pow_difficulty_bits
        {
            return CarryDecision::RejectPow;
        }

        self.prune(now);

        let (peer_msgs, peer_bytes) = self.peer_totals(&offer.peer);
        if peer_msgs + 1 > self.limits.per_peer_max_messages
            || peer_bytes + offer.bytes > self.limits.per_peer_max_bytes
        {
            return CarryDecision::RejectPerPeer;
        }

        let device_msgs = self.device.len() as u32;
        if device_msgs + 1 > self.limits.device_max_messages
            || self.device_bytes + offer.bytes > self.limits.device_max_bytes
        {
            return CarryDecision::RejectDevice;
        }

        // Accept: record it in both windows.
        self.per_peer
            .entry(offer.peer)
            .or_default()
            .push_back((now, offer.bytes));
        self.device.push_back((offer.peer, now, offer.bytes));
        self.device_bytes += offer.bytes;
        CarryDecision::Accept
    }

    /// The current number of events in the window (for tests and introspection).
    pub fn device_message_count(&self) -> usize {
        self.device.len()
    }
}

// ============================================================================
// 3. The rolling-window replay filter on the way back into the network (§7.7 item 3)
// ============================================================================

/// A replay table separate from the live class (which swaps by epoch), for capsules carried
/// through the mesh. N daily buckets; an entry lives until its `not_after`; the oldest bucket is
/// recycled when a new day begins. Its memory is bounded not by a short window but by the low
/// volume of mesh traffic (§7.7).
pub struct RollingReplayWindow {
    buckets: Vec<std::collections::HashSet<[u8; 16]>>,
    /// Which day (unix_day) each bucket currently holds; None means empty.
    bucket_day: Vec<Option<u64>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayCheck {
    /// A fresh capsule — accepted and recorded.
    Fresh,
    /// Already seen within the window — a replay.
    Replayed,
    /// now > not_after — expired, not stored (it is discarded as expired anyway).
    Expired,
    /// not_after is further out than the N-day window from now — replay protection cannot be
    /// guaranteed that far ahead (beyond the window), so it is refused.
    BeyondWindow,
}

impl RollingReplayWindow {
    /// `days` is the window size in daily buckets (8, say, for a 7-day TTL with headroom).
    pub fn new(days: usize) -> Self {
        RollingReplayWindow {
            buckets: vec![std::collections::HashSet::new(); days],
            bucket_day: vec![None; days],
        }
    }

    fn slot(&self, unix_day: u64) -> usize {
        (unix_day % self.buckets.len() as u64) as usize
    }

    /// Classify `not_after`/`now` without regard to whether the id is present (the shared window
    /// check used by both check and insert).
    fn classify(&self, not_after: u64, now: u64) -> Result<(u64, usize), ReplayCheck> {
        if now > not_after {
            return Err(ReplayCheck::Expired);
        }
        let target_day = not_after / SECS_PER_DAY;
        let today = now / SECS_PER_DAY;
        if target_day >= today + self.buckets.len() as u64 {
            return Err(ReplayCheck::BeyondWindow);
        }
        Ok((target_day, self.slot(target_day)))
    }

    /// A cheap read-only scan across all buckets: is the id present (without knowing not_after).
    /// Needed at Stage 3 to reject an obvious replay BEFORE the expensive HMAC — the authoritative
    /// not_after is only available after looking the capability up at Stage 4.
    ///
    /// Note: the scan includes buckets that are stale but not yet recycled, so it can return
    /// `true` for an id whose bucket has gone stale without being cleared. That is safe: such a
    /// capsule is certainly past its `not_after` and would be filtered out as `Expired` at Stage 4
    /// (verify) regardless. A false "replay" here lets no attack through; it merely rejects an
    /// already-expired capsule earlier.
    pub fn contains_any(&self, id: &[u8; 16]) -> bool {
        self.buckets.iter().any(|b| b.contains(id))
    }

    /// Record a capsule (Stage 4, only AFTER successful verification).
    /// Returns `Replayed` if the id was already present (a race or a double insert).
    pub fn insert(&mut self, id: [u8; 16], not_after: u64, now: u64) -> ReplayCheck {
        let (target_day, idx) = match self.classify(not_after, now) {
            Ok(v) => v,
            Err(c) => return c,
        };
        // Recycle: if the bucket holds a different (older) day, clear it.
        if self.bucket_day[idx] != Some(target_day) {
            self.buckets[idx].clear();
            self.bucket_day[idx] = Some(target_day);
        }
        if self.buckets[idx].contains(&id) {
            ReplayCheck::Replayed
        } else {
            self.buckets[idx].insert(id);
            ReplayCheck::Fresh
        }
    }

    /// A convenient check-then-insert (for standalone use and tests).
    /// NOT used in the pipeline — there, check happens at Stage 3 and insert at Stage 4.
    pub fn check_and_insert(&mut self, id: [u8; 16], not_after: u64, now: u64) -> ReplayCheck {
        self.insert(id, not_after, now)
    }
}
