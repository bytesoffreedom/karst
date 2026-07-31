//! §7.2 — the capability (invited access).
//!
//! A relay is the issuer of its own capabilities: a symmetric HMAC scheme, no PKI needed. The
//! table `capability_id → secret/scope/quota` is local to the relay and bounded by the relay
//! itself, not by an attacker. Only the `CapabilityProof` travels on the wire — the device never
//! reveals the `secret` itself.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Scope {
    MessageDelivery,
    MailboxFetch,
}

/// A capability's quota. `window` is in seconds; the accounting (spending max_requests and
/// max_bytes) is kept by the relay in its local table — only the limits live here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Quota {
    pub max_requests: u32,
    pub max_bytes: u64,
    pub window_secs: u32,
}

impl Quota {
    /// Apply a relay-operator CEILING: the effective limits are the element-wise MIN of what the
    /// presented capability claims and the operator's policy, over the policy's window. This is why
    /// a live policy change (or a forgeable dev cap that claims a huge quota) cannot exceed what the
    /// operator allows — the relay clamps at enforcement time, not just at capability issuance.
    pub fn clamped_by(&self, ceiling: &Quota) -> Quota {
        Quota {
            max_requests: self.max_requests.min(ceiling.max_requests),
            max_bytes: self.max_bytes.min(ceiling.max_bytes),
            window_secs: ceiling.window_secs,
        }
    }
}

/// The secret record, which lives ONLY at the relay (§7.2). It never goes on the wire. The serde
/// impl is for local storage by the client (capability.json, 0600); that is NOT the wire.

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Capability {
    pub capability_id: [u8; 16],
    pub scope: Scope,
    pub quota: Quota,
    pub not_before: u32,
    pub not_after: u32,
    pub secret: [u8; 32],
}

/// What actually travels on the wire (§7.2).
///
/// `not_after` is carried for STATELESS PoW capabilities (slice 4a): a Public relay stores
/// no record of a PoW cap, so the client's proof must carry the expiry the relay recomputes
/// the secret from. It is bound into the secret, so a forged `not_after` recomputes to a
/// different secret and the MAC (made with the real one) fails. For stored (dev/invite)
/// capabilities the relay looks the entry up by id and IGNORES this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapabilityProof {
    pub capability_id: [u8; 16],
    pub epoch_id: u32,
    pub not_after: u32,
    pub mac: [u8; 16],
}

/// The result of a successful `verify`: just what the quota stage needs. Owned (not a
/// `&Capability`) because a stateless PoW capability has no stored record to borrow from.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedCapability {
    pub capability_id: [u8; 16],
    pub quota: Quota,
}

/// Quota policy for a PoW-earned capability (slice 4a). **This is the spam bound on the
/// Public door**, a deliberate security parameter (not a test knob): each earned capability
/// may spend at most this RATE (requests + bytes per window) for its lifetime. Sustaining a
/// higher rate needs more capabilities — one more PoW solve per extra `POW_CAP_QUOTA` of
/// throughput. The PoW difficulty rate-limits how fast fresh capabilities appear; this bounds
/// each one's rate. (Per-message cost is NOT `N/max_requests` solves — a cap sends at this
/// rate for `ISSUED_CAP_TTL_SECS`; see `pow.rs`.)
pub const POW_CAP_QUOTA: Quota = Quota {
    max_requests: 100,
    max_bytes: 4 * 1024 * 1024,
    window_secs: 600,
};

fn scope_byte(s: Scope) -> u8 {
    match s {
        Scope::MessageDelivery => 1,
        Scope::MailboxFetch => 2,
    }
}

/// Deterministic id of a PoW capability from its solution (slice 4a). Deterministic ⇒
/// replaying the same Join re-derives the SAME capability (same id → same secret → same
/// quota bucket), so a replayed redemption is harmless rather than minting a second cap.
pub fn pow_cap_id(
    issuer_key: &[u8; 32],
    relay_id: &[u8; 32],
    bucket: u32,
    client_seed: &[u8; 32],
    nonce: u64,
) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(issuer_key).expect("HMAC accepts any key length");
    mac.update(b"pow-cap-id");
    mac.update(relay_id);
    mac.update(&bucket.to_be_bytes());
    mac.update(client_seed);
    mac.update(&nonce.to_be_bytes());
    let full = mac.finalize().into_bytes();
    let mut id = [0u8; 16];
    id.copy_from_slice(&full[..16]);
    id
}

/// Secret of a PoW capability, recomputable by the relay from `issuer_key` ALONE — so PoW
/// caps need no stored record (they survive restart and cannot fill a table). Binds
/// `not_after` and `scope`: a client that forges either recomputes to a different secret, so
/// its MAC (made with the real secret) no longer verifies. Only the relay knows `issuer_key`,
/// so the only way to hold a verifying `(id, secret)` pair is to have been ISSUED one — which
/// requires PoW. That is what enforces the door without a record of who was let in.
pub fn pow_cap_secret(issuer_key: &[u8; 32], cap_id: &[u8; 16], not_after: u32, scope: Scope) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(issuer_key).expect("HMAC accepts any key length");
    mac.update(b"pow-cap-secret");
    mac.update(cap_id);
    mac.update(&not_after.to_be_bytes());
    mac.update(&[scope_byte(scope)]);
    let full = mac.finalize().into_bytes();
    let mut s = [0u8; 32];
    s.copy_from_slice(&full[..32]);
    s
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    /// The capability_id was not found in the relay's local table.
    UnknownCapability,
    /// `now` is outside [not_before, not_after].
    Expired,
    /// The request's scope does not match the scope the capability was issued for.
    ScopeMismatch,
    /// The MAC did not match.
    BadMac,
}

impl Capability {
    /// Build a `CapabilityProof` for this `request_nonce` and epoch.
    /// mac = HMAC-SHA256(secret, request_nonce || epoch_id)[:16].
    pub fn prove(&self, request_nonce: &[u8], epoch_id: u32) -> CapabilityProof {
        CapabilityProof {
            capability_id: self.capability_id,
            epoch_id,
            not_after: self.not_after,
            mac: compute_mac(&self.secret, request_nonce, epoch_id),
        }
    }
}

/// The relay's local table: `capability_id → Capability`.
///
/// Two kinds of capability verify through here. STORED ones (dev/invite) live in `entries`,
/// looked up by id. STATELESS PoW ones (slice 4a) are NOT stored: when a Public relay sets
/// `pow_issuer`, an id that misses the table is verified by RECOMPUTING its secret from the
/// issuer key (see `pow_cap_secret`). That is what lets the Public door survive a restart and
/// resist a table-filling DoS — there is no table to fill.
#[derive(Default)]
pub struct CapabilityTable {
    entries: std::collections::HashMap<[u8; 16], Capability>,
    /// `Some` on a Public relay: the key stateless PoW-capability secrets are recomputed
    /// from. `None` on Private/Dev — an unknown id is simply rejected.
    pow_issuer: Option<[u8; 32]>,
}

impl CapabilityTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, cap: Capability) {
        self.entries.insert(cap.capability_id, cap);
    }

    /// Remove a stored capability, so REVOKING an invite takes effect on the next request rather
    /// than at the next restart (CRYPTO-25). Returns whether anything was there — the caller
    /// reports "unknown id" rather than pretending it revoked something.
    ///
    /// Only stored credentials can be revoked this way. A PoW-earned capability is verified
    /// STATELESSLY (there is no entry to remove), which is the trade that makes the public door
    /// cheap; bounding those is the quota's job, not a revocation list's.
    pub fn remove(&mut self, capability_id: &[u8; 16]) -> bool {
        self.entries.remove(capability_id).is_some()
    }

    /// Stored capability ids, for an operator listing (`invite list`).
    pub fn ids(&self) -> Vec<[u8; 16]> {
        self.entries.keys().copied().collect()
    }

    /// Enable stateless PoW-capability verification (the Public door, slice 4a). Idempotent.
    pub fn set_pow_issuer(&mut self, issuer_key: [u8; 32]) {
        self.pow_issuer = Some(issuer_key);
    }

    /// Verify a presented proof (§7.5, Stage 4, step 1 — the cheapest crypto step).
    /// `request_nonce`/`requested_scope`/`now` come from the current request. It returns a
    /// `VerifiedCapability` rather than a `&Capability`, because a stateless PoW capability has no
    /// stored record to borrow.
    pub fn verify(
        &self,
        proof: &CapabilityProof,
        request_nonce: &[u8],
        requested_scope: Scope,
        now: u32,
    ) -> Result<VerifiedCapability, CapabilityError> {
        // Stored (dev/invite) path — semantics unchanged.
        if let Some(cap) = self.entries.get(&proof.capability_id) {
            if now < cap.not_before || now > cap.not_after {
                return Err(CapabilityError::Expired);
            }
            if cap.scope != requested_scope {
                return Err(CapabilityError::ScopeMismatch);
            }
            let expected = compute_mac(&cap.secret, request_nonce, proof.epoch_id);
            return if expected.ct_eq(&proof.mac).into() {
                Ok(VerifiedCapability { capability_id: cap.capability_id, quota: cap.quota })
            } else {
                Err(CapabilityError::BadMac)
            };
        }

        // Stateless PoW path (Public door): recompute the secret from the issuer key. The
        // secret binds `not_after` and `scope`, so a forged expiry or scope yields a
        // non-matching secret → BadMac. `not_before` is moot: a client cannot hold a
        // verifying secret before the relay issued it.
        if let Some(issuer) = self.pow_issuer {
            if now > proof.not_after {
                return Err(CapabilityError::Expired);
            }
            let secret = pow_cap_secret(&issuer, &proof.capability_id, proof.not_after, requested_scope);
            let expected = compute_mac(&secret, request_nonce, proof.epoch_id);
            return if expected.ct_eq(&proof.mac).into() {
                Ok(VerifiedCapability { capability_id: proof.capability_id, quota: POW_CAP_QUOTA })
            } else {
                Err(CapabilityError::BadMac)
            };
        }

        Err(CapabilityError::UnknownCapability)
    }
}

fn compute_mac(secret: &[u8; 32], request_nonce: &[u8], epoch_id: u32) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(request_nonce);
    mac.update(&epoch_id.to_be_bytes());
    let full = mac.finalize().into_bytes();
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&full[..16]);
    truncated
}

/// The outcome of quota accounting for one capability request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaDecision {
    /// Within quota — the request was counted.
    Ok,
    /// The same proof is already in the window (a verbatim replay) — not counted twice.
    Replay,
    /// `max_requests` or `max_bytes` exceeded within `window_secs`.
    Exceeded,
}

/// Accounting of a capability's spend by capability_id over a sliding `window_secs`.
///
/// It closes a gap: without it a valid proof is reusable once per new epoch all the way to
/// `not_after` (the epoch-scoped replay filter of §7.5 is cleared, while `verify` computes the MAC
/// over `proof.epoch_id` and does not check epoch freshness — and MUST NOT: a capability is
/// deliberately multi-epoch). The real bound is the capability's own quota (§7.2), which the relay
/// must keep locally. The same sliding-window logic as the DTN carry budget (§7.7).
/// must keep locally. The same sliding-window logic as the DTN carry budget (§7.7).
///
/// A verbatim replay is caught by `proof.mac` (a captured proof repeats unchanged, including
/// across an epoch boundary, while the entry is in the window). Memory is bounded by
/// `max_requests` itself (a window holds no more entries than that).
/// One capability's sliding window: a queue of (time, bytes, proof tag).
type QuotaWindow = std::collections::VecDeque<(u64, u64, [u8; 16])>;

#[derive(Default)]
pub struct CapabilityQuotaTracker {
    /// capability_id → its spend window.
    windows: std::collections::HashMap<[u8; 16], QuotaWindow>,
    /// capability_id → ITS `window_secs`, remembered when spending. `reap` used to apply the
    /// default value to every capability, although the window is a property of the specific one —
    /// a longer window lost its spend records early and gave back quota it should not have.
    window_of: std::collections::HashMap<[u8; 16], u64>,
}

impl CapabilityQuotaTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live per-capability windows. Grows by one per distinct `cap_id`; a Public
    /// relay must `reap` idle ones or this is an unbounded-memory DoS (a fresh PoW `cap_id`
    /// per solve). Exposed so a test can assert the reap actually runs.
    pub fn len(&self) -> usize {
        self.windows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }

    /// Count a request against the quota. Call it ONLY after successful verification (otherwise a
    /// bad MAC would burn someone else's quota). `cap_id`/`quota` come from `VerifiedCapability`
    /// (stored or a stateless PoW capability — the accounting is identical, keyed by `cap_id`);
    /// `proof_tag` is `proof.mac`; `bytes` is the request size.
    pub fn consume(
        &mut self,
        cap_id: [u8; 16],
        quota: &Quota,
        proof_tag: [u8; 16],
        bytes: u64,
        now: u64,
    ) -> QuotaDecision {
        let window = quota.window_secs as u64;
        let horizon = now.saturating_sub(window);
        self.window_of.insert(cap_id, window);
        let dq = self.windows.entry(cap_id).or_default();
        // Prune: drop everything older than the window.
        while let Some(&(ts, _, _)) = dq.front() {
            if ts <= horizon {
                dq.pop_front();
            } else {
                break;
            }
        }
        // A verbatim replay: the same proof tag is already in the window.
        if dq.iter().any(|&(_, _, tag)| tag == proof_tag) {
            return QuotaDecision::Replay;
        }
        // The quota by request count and by bytes within the window.
        let count = dq.len() as u32;
        let bytes_sum: u64 = dq.iter().map(|&(_, b, _)| b).sum();
        if count + 1 > quota.max_requests || bytes_sum + bytes > quota.max_bytes {
            return QuotaDecision::Exceeded;
        }
        dq.push_back((now, bytes, proof_tag));
        QuotaDecision::Ok
    }

    /// Periodic cleanup: drop capabilities whose windows have fully expired (untouched for longer
    /// than their own `window_secs`). `consume` does not free the record of a capability nobody
    /// asks about any more, so the relay calls `reap` occasionally. Not security-critical (the
    /// number of windows is bounded by the number of issued capabilities, not by an attacker) but
    /// memory hygiene. Returns the number of records removed.

    pub fn reap(&mut self, now: u64, default_window_secs: u64) -> usize {
        let before = self.windows.len();
        let window_of = std::mem::take(&mut self.window_of);
        self.windows.retain(|id, dq| {
            // Each capability is reaped against ITS OWN window, remembered at consume time; the
            // caller's value is only a fallback for an id we have never metered (A4-6).
            let window = window_of.get(id).copied().unwrap_or(default_window_secs);
            let horizon = now.saturating_sub(window);
            while let Some(&(ts, _, _)) = dq.front() {
                if ts <= horizon {
                    dq.pop_front();
                } else {
                    break;
                }
            }
            !dq.is_empty()
        });
        // Keep the remembered windows for the ids that survived.
        self.window_of = window_of.into_iter().filter(|(id, _)| self.windows.contains_key(id)).collect();
        before - self.windows.len()
    }
}
