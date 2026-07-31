//! §7.5 / §7.6 — the full checking order for an incoming request.
//!
//! Memory at every stage grows only in proportion to the already-verified legitimate load (§7.5).
//! The stage order is the cost order: cheap rejections come before expensive ones (§7.6).
//!
//!
//! ```text
//! Stage 0  bounded parse         — a length budget, no allocation on an unverified length
//! Stage 1  cookie                — without a valid one, exactly 64 bytes back and NO state created
//! Stage 2  credential format     — structure without crypto; rejecting garbage is free
//! Stage 3  replay/freshness      — a bounded filter, tied to the quota epoch
//! Stage 4  expensive crypto      — in rising cost order: capability HMAC → token ring sig → RLN zk
//! Stage 5  bounded session state — LRU with a hard ceiling → Mix/Mailbox/Egress (§10)
//! ```

use crate::capability::{
    CapabilityError, CapabilityProof, CapabilityQuotaTracker, CapabilityTable, Quota, QuotaDecision, Scope,
};
use crate::cookie::{Cookie, CookieError, CookieKeyring};
use crate::dtn::{
    DtnCapError, DtnCapabilityProof, DtnCapabilityTable, ReplayCheck, RollingReplayWindow,
    MAX_DTN_CAPSULE_SIZE,
};
use crate::params::COOKIE_CHALLENGE_SIZE;
use crate::token::{AdmissionToken, AdmissionTokenVerifier, IssuerRing, TokenError};

/// The credential being presented (§7.5, Stage 4). RLN is not a separate credential here but a
/// quota layer on top of admission; its zk gate is stubbed (see `rln`), so it appears in the
/// pipeline as an explicitly unreachable branch.
pub enum Credential {
    Capability(CapabilityProof),
    Token(AdmissionToken),
    /// RLN quota: the zk wrapper is not implemented (§7.4). The branch exists so the pipeline
    /// says honestly "this path does not pass yet" rather than pretending RLN is ready.

    RlnQuota,
}

pub struct Request<'a> {
    /// The raw packet length before parsing (for Stage 0).
    pub raw_len: usize,
    /// Stage-0 ceiling for THIS request's CLASS, supplied by the caller.
    ///
    /// It used to be a single hardcoded `MAX_PACKET_SIZE` for every kind of request, which forced
    /// a choice between two wrong answers wherever a class legitimately costs more: charge the
    /// real cost and have stage 0 reject every honest request, or charge a fiction and leave the
    /// difference unmetered. A bundle publish carrying a full one-time-prekey batch is ~28 KiB
    /// against a 2560-byte ceiling, so it took the second — the batch was free (A10-1).
    ///
    /// The caller declares the ceiling because only it knows the class; `wire::max_frame_for`
    /// already does exactly this one layer up, and the asymmetry between the two was the defect.
    /// Use [`crate::params::MAX_PACKET_SIZE`] for the ordinary live path.
    pub max_raw_len: usize,
    pub client_addr: &'a [u8],
    pub carrier_id: &'a [u8],
    /// The cookie, if the client already completed the first round trip; None on first contact.
    pub cookie: Option<Cookie>,
    pub request_nonce: &'a [u8],
    pub requested_scope: Scope,
    pub credential: Credential,
}

/// A request on the Ingress DTN branch (§7.7): a capsule that came back out of the mesh and is
/// being uploaded to the network by an online carrier.
///
/// **The only capsule identifier is `H(ciphertext)`** — it is also the MAC input (binding the
/// signature to the content) and the rolling-window key. Therefore:
/// - an observer inside the mesh cannot attach a valid proof to different content (change the
///   content → a different hash → a different MAC and a different replay key);
/// - `capsule_bytes` and `capsule_id` are taken FROM THE WIRE (from `ciphertext`), never from
///   client-supplied fields; `not_after`/`max_bytes` come from the authoritative capability at
///   Stage 4.
pub struct DtnRequest<'a> {
    pub raw_len: usize,
    pub client_addr: &'a [u8],
    pub carrier_id: &'a [u8],
    pub cookie: Option<Cookie>,
    /// The DTN capability proof; its MAC covers `H(ciphertext)`.
    pub proof: DtnCapabilityProof,
    /// The raw capsule ciphertext — the source of both the id and the size.
    pub ciphertext: &'a [u8],
}

/// The outcome of a pass through the pipeline.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Stage 0/2: a silent reject with no reply (garbage or oversized).
    DropNoReply(DropReason),
    /// Stage 1: no valid cookie — the reply is exactly 64 bytes and no state is created.
    Challenge([u8; COOKIE_CHALLENGE_SIZE]),
    /// Stage 3: the replay filter is full — a signal to raise the adaptive PoW. The request is not
    /// accepted, but this is overload rather than garbage (§7.5, Stage 3).
    BackpressurePow,
    /// Stage 3/4: the request was rejected for a specific reason (replay or crypto).
    Reject(RejectReason),
    /// Stage 5: admitted, handed to the session state → Mix/Mailbox/Egress.
    Admit,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DropReason {
    /// Stage 0: the length exceeds MAX_PACKET_SIZE.
    Oversize,
    /// Stage 2: the credential structure did not parse (an empty nonce and the like).
    MalformedCredential,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RejectReason {
    Cookie(CookieError),
    Capability(CapabilityError),
    Token(TokenError),
    Replay,
    /// The capability exhausted its quota (max_requests/max_bytes per window, §7.2).
    CapabilityQuota,
    /// The RLN zk wrapper is not implemented — this path cannot pass (§7.4).
    RlnNotImplemented,
    /// DTN branch (§7.7): the capability failed (expiry, size, MAC, or unknown).
    Dtn(DtnCapError),
    /// DTN branch: this capsule has been seen before (rolling-window replay).
    DtnReplay,
    /// DTN branch: the capsule expired (now > not_after).
    DtnExpired,
    /// DTN branch: not_after lies beyond the rolling window — no guarantee can be offered.
    DtnBeyondWindow,
}

/// The bounded replay/freshness filter (§7.5, Stage 3).
///
/// The spec names Bloom/cuckoo; this is a capacity-bounded `HashSet` with a hard ceiling, tied to
/// the quota epoch and cleared when it rotates. What the implementation checks is exactly the
/// bounded memory plus the backpressure signal on overflow, not any particular probabilistic
/// structure (choosing one is an optimisation, not a change of behaviour at the boundary).

pub struct ReplayFilter {
    epoch_id: u32,
    seen: std::collections::HashSet<[u8; 16]>,
    capacity: usize,
}

impl ReplayFilter {
    pub fn new(epoch_id: u32, capacity: usize) -> Self {
        ReplayFilter {
            epoch_id,
            seen: std::collections::HashSet::new(),
            capacity,
        }
    }

    /// Cleared when the quota epoch rotates (§7.5): the whole filter is zeroed.
    pub fn roll_epoch(&mut self, new_epoch: u32) {
        if new_epoch != self.epoch_id {
            self.seen.clear();
            self.epoch_id = new_epoch;
        }
    }

    /// A cheap READ-ONLY look: have we seen this tag. It occupies nothing — used at Stage 3 to
    /// reject an obvious replay BEFORE the expensive crypto, without giving an unauthenticated
    /// request a slot in the filter (R2-1).
    fn contains(&self, tag: &[u8; 16]) -> bool {
        self.seen.contains(tag)
    }

    /// Attempts to record the tag. Returns:
    /// - `Ok(true)`  — fresh, accepted;
    /// - `Ok(false)` — already seen (replay);
    /// - `Err(())`   — the filter is full (overflow → backpressure/PoW).
    ///
    /// Called ONLY after a credential verifies — otherwise a garbage proof occupies capacity and
    /// breaks sending for the whole relay (R2-1; the DTN branch always did it this way).
    fn commit(&mut self, tag: [u8; 16]) -> Result<bool, ()> {
        if self.seen.contains(&tag) {
            return Ok(false);
        }
        if self.seen.len() >= self.capacity {
            return Err(());
        }
        self.seen.insert(tag);
        Ok(true)
    }
}

/// The pipeline orchestrator. Holds references to the relay's state.
pub struct AdmissionPipeline<'r, V: AdmissionTokenVerifier> {
    pub keyring: &'r CookieKeyring,
    pub capabilities: &'r CapabilityTable,
    pub token_verifier: &'r V,
    pub issuer_ring: &'r IssuerRing,
}

impl<'r, V: AdmissionTokenVerifier> AdmissionPipeline<'r, V> {
    /// Stages 0–1, shared by the live and DTN branches of one Ingress (§10: a single entry point,
    /// branching on the credential type — not a separate gateway).
    /// `Some(outcome)` means a short circuit (drop/challenge); `None` means we passed.
    ///
    /// The cookie applies to DTN as well: a capsule returning from the mesh is uploaded by an
    /// ALREADY online carrier, and the cookie protects that online uplink against amplification
    /// (spoofing inside the mesh itself is impossible, §7.7).
    // The arguments are primitive and distinct; bundling them into a struct for the lint's sake
    // would add indirection to a private helper for nothing.
    #[allow(clippy::too_many_arguments)]
    fn precheck(
        &self,
        raw_len: usize,
        max_raw_len: usize,
        client_addr: &[u8],
        carrier_id: &[u8],
        cookie: &Option<Cookie>,
        now_secs: u64,
        challenge_bytes: [u8; COOKIE_CHALLENGE_SIZE],
    ) -> Option<Outcome> {
        // Stage 0: bounded parse. The ceiling depends on the class: the live MTU for the live
        // path, the MB-scale DTN ceiling for a stored mesh capsule.
        if raw_len > max_raw_len {
            return Some(Outcome::DropNoReply(DropReason::Oversize));
        }
        // Stage 1: cookie.
        let cookie = match cookie {
            Some(c) => c,
            None => return Some(Outcome::Challenge(challenge_bytes)),
        };
        if self
            .keyring
            .verify(cookie, client_addr, carrier_id, now_secs)
            .is_err()
        {
            return Some(Outcome::Challenge(challenge_bytes));
        }
        None
    }

    /// The live path (§7.5). `replay` is the live-class epoch filter; `cap_quota` accounts for the
    /// capability's spend within its window (§7.2) and is NOT cleared by the epoch (unlike
    /// `replay`) — otherwise a valid proof would be reusable once per epoch until `not_after`.

    pub fn process(
        &self,
        req: &Request,
        now_secs: u64,
        epoch_id: u32,
        challenge_bytes: [u8; COOKIE_CHALLENGE_SIZE],
        replay: &mut ReplayFilter,
        cap_quota: &mut CapabilityQuotaTracker,
    ) -> Outcome {
        self.process_with_policy(req, now_secs, epoch_id, challenge_bytes, replay, cap_quota, None)
    }

    /// As [`process`], but the operator's live quota `policy` clamps every capability's effective
    /// quota (`None` = no ceiling, use the capability's own quota — the historical behaviour). The
    /// relay passes its current policy so a change over the admin channel (or an "off") takes effect
    /// immediately, for already-issued capabilities too.
    #[allow(clippy::too_many_arguments)]
    pub fn process_with_policy(
        &self,
        req: &Request,
        now_secs: u64,
        epoch_id: u32,
        challenge_bytes: [u8; COOKIE_CHALLENGE_SIZE],
        replay: &mut ReplayFilter,
        cap_quota: &mut CapabilityQuotaTracker,
        quota_policy: Option<Quota>,
    ) -> Outcome {
        // --- Stages 0–1 ---
        if let Some(out) = self.precheck(
            req.raw_len,
            req.max_raw_len,
            req.client_addr,
            req.carrier_id,
            &req.cookie,
            now_secs,
            challenge_bytes,
        ) {
            return out;
        }

        // --- Stage 2: credential format (no crypto) ---
        if req.request_nonce.is_empty() {
            return Outcome::DropNoReply(DropReason::MalformedCredential);
        }

        // --- Stage 3: replay/freshness — a read-only CHECK ONLY ---
        // The order matters here and now matches the DTN branch (see `process_dtn`).
        // The capability's tag is `proof.mac`, a field FROM THE WIRE: recording it BEFORE the HMAC
        // is verified would let anyone holding an ordinary cookie flood the filter with garbage
        // MACs, and after the overflow EVERY new unique request gets BackpressurePow until the
        // epoch turns — a cheap denial of sending for the whole relay (R2-1). So only the cheap
        // look happens here (a real replay is rejected at once); the insert comes after Stage 4.
        replay.roll_epoch(epoch_id);
        let replay_tag = credential_replay_tag(&req.credential);
        if let Some(tag) = replay_tag {
            if replay.contains(&tag) {
                return Outcome::Reject(RejectReason::Replay);
            }
        }

        // --- Stage 4: expensive crypto, in rising cost order ---
        match &req.credential {
            // Step 1: capability HMAC (the cheapest).
            Credential::Capability(proof) => {
                let cap = match self.capabilities.verify(
                    proof,
                    req.request_nonce,
                    req.requested_scope,
                    now_secs as u32,
                ) {
                    Ok(c) => c,
                    Err(e) => return Outcome::Reject(RejectReason::Capability(e)),
                };
                // Quota accounting happens ONLY after the MAC verifies (otherwise a bad proof
                // would burn someone else's quota). The tag is proof.mac (stable under a verbatim
                // replay, including across an epoch boundary). cap_id/quota come from verify
                // (stored or a stateless PoW capability — the accounting is identical).
                // The operator's policy (if any) clamps the effective quota — a forgeable dev cap or
                // a stale over-generous token cannot exceed what the relay currently allows.
                let effective = match quota_policy {
                    Some(p) => cap.quota.clamped_by(&p),
                    None => cap.quota,
                };
                match cap_quota.consume(cap.capability_id, &effective, proof.mac, req.raw_len as u64, now_secs) {
                    QuotaDecision::Ok => {}
                    QuotaDecision::Replay => return Outcome::Reject(RejectReason::Replay),
                    QuotaDecision::Exceeded => {
                        return Outcome::Reject(RejectReason::CapabilityQuota)
                    }
                }
            }
            // Step 2: the admission token ring signature.
            Credential::Token(token) => {
                match self
                    .token_verifier
                    .verify(token, self.issuer_ring, epoch_id)
                {
                    Ok(()) => {}
                    Err(e) => return Outcome::Reject(RejectReason::Token(e)),
                }
            }
            // Step 3: the RLN zk proof — not implemented (§7.4); the path honestly does not pass.
            Credential::RlnQuota => {
                return Outcome::Reject(RejectReason::RlnNotImplemented)
            }
        }

        // The replay tag is recorded ONLY now, once the credential is VERIFIED (R2-1).
        // An unauthenticated request never reaches this point, so filter capacity is spent only by
        // those who really presented a valid credential (and the quota bounds them further).
        if let Some(tag) = replay_tag {
            match replay.commit(tag) {
                Ok(true) => {}
                Ok(false) => return Outcome::Reject(RejectReason::Replay), // lost the race
                Err(()) => return Outcome::BackpressurePow,
            }
        }

        // --- Stage 5: bounded session state → Mix/Mailbox/Egress ---
        Outcome::Admit
    }

    /// The DTN path (§7.7) of the same Ingress. `dtn_caps` is the DTN capability table,
    /// `dtn_replay` is a separate rolling window (not the live-class epoch filter).
    ///
    /// The order matters for DTN and DIFFERS from live: Stage 3 is a read-only CHECK only (to
    /// reject a real replay cheaply), and the insert into the rolling window happens ONLY after a
    /// successful HMAC at Stage 4. Otherwise an attacker who glimpsed a capsule id in the mesh
    /// would upload it first with a garbage proof, burn the id at Stage 3, and the genuine capsule
    /// would later be rejected as a "replay".

    pub fn process_dtn(
        &self,
        req: &DtnRequest,
        dtn_caps: &DtnCapabilityTable,
        dtn_replay: &mut RollingReplayWindow,
        now_secs: u64,
        challenge_bytes: [u8; COOKIE_CHALLENGE_SIZE],
    ) -> Outcome {
        // --- Stages 0–1 (shared) ---
        // The DTN ceiling (MB scale), NOT the live MTU: a capsule is a stored object.
        // A cheap gate before hashing the ciphertext.
        if let Some(out) = self.precheck(
            req.raw_len,
            MAX_DTN_CAPSULE_SIZE,
            req.client_addr,
            req.carrier_id,
            &req.cookie,
            now_secs,
            challenge_bytes,
        ) {
            return out;
        }

        // --- Stage 2: format (no crypto) ---
        if req.ciphertext.is_empty() {
            return Outcome::DropNoReply(DropReason::MalformedCredential);
        }

        // The only capsule identifier comes from the wire, never from client fields.
        let full_hash = capsule_hash(req.ciphertext);
        let mut replay_key = [0u8; 16];
        replay_key.copy_from_slice(&full_hash[..16]);
        let capsule_bytes = req.ciphertext.len() as u64;

        // --- Stage 3: a cheap read-only CHECK (scan, no not_after) ---
        // Rejects an obvious replay BEFORE the HMAC without burning the id (the insert happens
        // only after verification at Stage 4).
        if dtn_replay.contains_any(&replay_key) {
            return Outcome::Reject(RejectReason::DtnReplay);
        }

        // --- Stage 4: verify the DTN capability ---
        // The MAC over H(ciphertext) (binding it to the content), the expiry, and the size against
        // the authoritative quota. `not_after` comes from the capability that was found, never
        // from the client.
        let cap = match dtn_caps.verify(&req.proof, &full_hash, capsule_bytes, now_secs) {
            Ok(c) => c,
            Err(DtnCapError::Expired) => return Outcome::Reject(RejectReason::DtnExpired),
            Err(e) => return Outcome::Reject(RejectReason::Dtn(e)),
        };
        let not_after = cap.not_after;

        // Recorded in the rolling window ONLY now, after a successful HMAC.
        // (Expired cannot occur here — verify already checked the expiry; BeyondWindow is
        // meaningful, since it depends on not_after and the rolling window.)
        match dtn_replay.insert(replay_key, not_after, now_secs) {
            ReplayCheck::Fresh => {}
            ReplayCheck::Replayed => return Outcome::Reject(RejectReason::DtnReplay), // lost the race
            ReplayCheck::Expired => return Outcome::Reject(RejectReason::DtnExpired),
            ReplayCheck::BeyondWindow => return Outcome::Reject(RejectReason::DtnBeyondWindow),
        }

        // --- Stage 5 ---
        Outcome::Admit
    }
}

/// `H(ciphertext)` — the only capsule identifier (§7.7 integration).
/// Public: a DTN sender must compute the id the same way, so that its proof (a MAC over this
/// value) matches what Ingress recomputes.
pub fn capsule_hash(ciphertext: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"KARST-dtn-capsule-id");
    h.update(ciphertext);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// The tag for the replay filter: for a token it is its `t` (unique per token); for a capability
/// it is the proof's MAC (unique per (nonce, epoch)). RLN never reaches the filter in this
/// implementation (the zk gate stops it earlier on the branch — but no tag is handed out anyway).

fn credential_replay_tag(cred: &Credential) -> Option<[u8; 16]> {
    match cred {
        Credential::Capability(p) => Some(p.mac),
        Credential::Token(t) => {
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&t.t[..16]);
            Some(tag)
        }
        Credential::RlnQuota => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A discriminating test for `roll_epoch`: an epoch change CLEARS the live replay filter.
    /// Through the full pipeline this is masked by the quota tracker (for capabilities), so here
    /// the primitive is checked where the effect is directly observable. The node's epoch-scoped
    /// replay protection rests on exactly this.
    #[test]
    fn roll_epoch_clears_replay_filter() {
        let mut f = ReplayFilter::new(0, 16);
        let tag = [7u8; 16];
        assert_eq!(f.commit(tag), Ok(true)); // fresh
        assert_eq!(f.commit(tag), Ok(false)); // replay inside the same epoch
        f.roll_epoch(1); // epoch change
        assert_eq!(f.commit(tag), Ok(true), "an epoch change must clear the filter");
        // The same epoch number again is idempotent and does NOT clear it.
        f.roll_epoch(1);
        assert_eq!(f.commit(tag), Ok(false), "the same epoch_id must not reset it");
    }
}
