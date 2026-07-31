//! §7.4 — RLN-style quota: the nullifier core plus Shamir slashing.
//!
//! The spec (§7.4):
//! ```text
//! RLNProof {
//!   epoch_id
//!   external_nullifier = Hash(epoch_id || relay_scope_id)
//!   nullifier          = Poseidon(identity_secret, external_nullifier)
//!   a1                 = identity_secret + message_hash * a0   // the Shamir share
//!   zk_proof
//! }
//! ```
//! The mechanism is not a preventive block but an economic penalty: two different presentations of
//! the same `identity_secret` in one epoch, with different `message_hash`es, let anyone recover
//! `identity_secret` from the two `a1` values.
//!
//! # What is implemented and what is not (the boundary, stated honestly)
//!
//! A real finite-field core is implemented: deriving the slope and the nullifier, and the property
//! that the secret is recoverable from two shares. The field is the Curve25519 scalar field (prime
//! order `l`), which gives real modular arithmetic with inversion.

//!
//! NOT implemented (and not available off the shelf): the `zk_proof` wrapper that proves in zero
//! knowledge that (a) `identity_secret` is in the tree of admitted members, and (b) `nullifier`
//! and `a1` were derived from it correctly. That needs a circom/halo2 circuit rather than a
//! primitive from crates.io — see below.
//! `ZkProofStub`.
//!
//! # A finding the implementation exposed (invisible to a prose audit) — see the NOTE below.

use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// A field element — a Curve25519 scalar (mod the prime order `l`).
pub type Field = Scalar;

/// Hash arbitrary bytes into a field element (uniformly, by wide reduction).
/// The spec says Poseidon (SNARK-friendly); this reference core uses SHA-512 → wide reduce. The
/// substitution does NOT affect the property being checked (recovering the secret from two
/// shares) — that is purely a field property and independent of the hash; Poseidon matters only
/// so the same computation is cheap INSIDE a zk circuit, which does not exist here.
fn hash_to_field(parts: &[&[u8]]) -> Field {
    let mut h = Sha512::new();
    for p in parts {
        h.update((p.len() as u64).to_be_bytes()); // length-prefixed domain separation
        h.update(p);
    }
    let out = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&out);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// external_nullifier = Hash(epoch_id || relay_scope_id) (§7.4).
pub fn external_nullifier(epoch_id: u32, relay_scope_id: &[u8]) -> Field {
    hash_to_field(&[b"karst-rln-ext", &epoch_id.to_be_bytes(), relay_scope_id])
}

/// The identity secret (a_0 of the line in standard RLN terms — but the SPEC calls this secret
/// `identity_secret` and calls the slope `a0`; the names below follow the spec).

#[derive(Clone, Copy)]
pub struct IdentitySecret(pub Field);

impl IdentitySecret {
    /// The deterministic slope of the sharing line for a given epoch.
    ///
    /// In the spec the share equation `a1 = identity_secret + message_hash * a0` uses `a0` as the
    /// slope but does NOT define where `a0` comes from. Standard RLN derives the slope as
    /// `H(identity_secret || external_nullifier)` — adopted here; the slope must be stable per
    /// epoch (otherwise two shares do not lie on one line) and secret (otherwise see the NOTE
    /// about the nullifier below).
    pub fn slope(&self, ext_nullifier: &Field) -> Field {
        hash_to_field(&[
            b"karst-rln-slope",
            self.0.as_bytes(),
            ext_nullifier.as_bytes(),
        ])
    }

    /// The public per-epoch tag used to detect a double presentation.
    ///
    /// NOTE (a finding the implementation exposed) — a divergence from spec §7.4.
    /// The spec writes `nullifier = Poseidon(identity_secret, external_nullifier)` — exactly the
    /// same input as the slope `a0`. If the public `nullifier` EQUALS the slope, then publishing it
    /// alongside ONE share `a1` lets anyone compute `identity_secret = a1 - message_hash * a0` from
    /// a SINGLE message — which deanonymises on the very first message and breaks the property that
    /// only a repeated quota violation is penalised. The slope must stay secret; detection needs a
    /// SEPARATE tag that is not the slope. Standard RLN does exactly that:
    /// `internal_nullifier = Poseidon(slope)` (a hash of the slope, not the slope itself). The
    /// correct variant is implemented here; the spec formula needs the fix (see the §7.4 patch).
    pub fn nullifier(&self, ext_nullifier: &Field) -> Field {
        let slope = self.slope(ext_nullifier);
        hash_to_field(&[b"karst-rln-null", slope.as_bytes()])
    }
}

/// A Shamir share for one message: the point (x, y) on the line
/// `y = identity_secret + slope * x`, where x = message_hash.
/// (The spec calls `y` itself `a1`.)
#[derive(Clone, Copy)]
pub struct Share {
    /// x — the message hash (the evaluation point).
    pub message_hash: Field,
    /// y — the share value (`a1` in the spec's terms).
    pub a1: Field,
    /// The public epoch+identity tag by which a repeat is detected.
    pub nullifier: Field,
    /// The public input `external_nullifier = H(epoch_id ‖ scope)`, from which `nullifier` and
    /// `slope` were derived. The relay checks it for epoch freshness (the zk wrapper binds the
    /// nullifier to it but does NOT guarantee the epoch is current — that is a relay-side
    /// freshness check of a public input).
    pub external_nullifier: Field,
}

impl IdentitySecret {
    /// Issue a share for a specific message in a specific epoch.
    pub fn share(&self, ext_nullifier: &Field, message_hash: Field) -> Share {
        let slope = self.slope(ext_nullifier);
        let a1 = self.0 + message_hash * slope;
        Share {
            message_hash,
            a1,
            nullifier: self.nullifier(ext_nullifier),
            external_nullifier: *ext_nullifier,
        }
    }
}

/// The outcome of attempting to slash from two shares.
#[derive(Debug, PartialEq, Eq)]
pub enum SlashResult {
    /// The identity secret was recovered (quota exceeded, the violator is deanonymised).
    Recovered([u8; 32]),
    /// The shares belong to different identities or epochs (the nullifiers differ) — there is
    /// nothing to recover, and this is not a double presentation.
    DifferentNullifier,
    /// The same message_hash (not two different messages) — a degenerate case: x1 == x2, the line
    /// is not recoverable (and it is not a quota violation either: repeating an identical message
    /// is the same RLNProof).
    SameMessage,
}

/// §7.4 — recovering `identity_secret` from two shares of one epoch.
///
/// Two points (x1,y1),(x2,y2) on the line `y = s + slope*x` determine it uniquely:
/// `slope = (y2-y1)/(x2-x1)`, `s = y1 - slope*x1`. This is the "economic penalty": exceed the
/// quota (more than one share per epoch) and the secret is revealed.
pub fn slash(s1: &Share, s2: &Share) -> SlashResult {
    if s1.nullifier != s2.nullifier {
        return SlashResult::DifferentNullifier;
    }
    let dx = s2.message_hash - s1.message_hash;
    if dx == Scalar::ZERO {
        return SlashResult::SameMessage;
    }
    let slope = (s2.a1 - s1.a1) * dx.invert();
    let secret = s1.a1 - slope * s1.message_hash;
    SlashResult::Recovered(secret.to_bytes())
}

/// An explicit stub for the zk wrapper (§7.4, the `zk_proof` field).
///
/// Deliberately NOT implemented: proving in zero knowledge that `identity_secret` is a leaf of an
/// admitted Merkle tree and that `nullifier`/`a1` were derived from it correctly requires an
/// arithmetic circuit (circom/halo2) plus a trusted setup, or a transparent STARK — that is a
/// separate layer, not a primitive to take from crates.io. Without it the core above checks the
/// field mathematics of slashing but does NOT prove that whoever presented a share is really in
/// the admitted set. That is the honest boundary of a reference implementation.

#[derive(Debug, Clone, Copy)]
pub struct ZkProofStub;

impl ZkProofStub {
    /// Always returns `false`: a stub verifies nothing and must not be mistaken for a working
    /// membership check.
    pub fn verify(&self) -> bool {
        false
    }
}

// ============================================================================
// The RLN quota layer: double-presentation detection plus slashing (§7.4)
// ============================================================================

/// The outcome of the quota tracker observing a share.
#[derive(Debug, PartialEq, Eq)]
pub enum RlnOutcome {
    /// The identity's first message this epoch — within quota.
    Accepted,
    /// Exactly the same message (the same message_hash) — a repeat, not a quota violation (it is
    /// the same RLNProof).
    Duplicate,
    /// Quota exceeded: a second DIFFERENT message from the same identity in one epoch. The secret
    /// was recovered and the violator is deanonymised (an economic penalty, not a preventive
    /// block).
    QuotaViolation { recovered_secret: [u8; 32] },
    /// The share's `external_nullifier` matches neither the current epoch nor the previous (grace)
    /// one — a stale or future epoch. WITHOUT this check the limit is bypassed by cycling
    /// `epoch_id` (each epoch yields a fresh nullifier).
    WrongEpoch,
    /// The tracker is full (bounded memory) — a backpressure/PoW signal, like the live replay
    /// filter (§7.5).
    Backpressure,
}

/// The RLN quota tracker for one relay scope. Holds the nullifier state of the current and the
/// previous epoch (a grace window of `GRACE_EPOCHS = 1`, like the §7.1 cookie).
///
/// # THE BOUNDARY (honestly): what this layer guarantees and what it does not
///
/// It implements the rate limit "at most 1 message per identity per epoch" through repeated-
/// nullifier detection plus slashing (§7.4). The limit is 1 because the `Share` core is a line
/// (degree 1); limits above 1 need a polynomial of degree `limit` and recovery from `limit+1`
/// shares, which the core does not have.
///
/// **The tracker ASSUMES the shares are already zk-verified** (membership in the admitted tree
/// plus correct derivation of `nullifier`/`a1` from the secret) — that is, that something real
/// stands behind `ZkProofStub`. It is NOT implemented (circom/halo2 needed, see `ZkProofStub`).
/// Without it an attacker can submit arbitrary `(nullifier, a1)` unrelated to any real identity,
/// and slashing will recover a meaningless "secret". So this layer is NOT a complete RLN admission
/// gate but a penalty layer ON TOP of a zk check. In the pipeline (§7.5) the RLN branch stays
/// `RlnNotImplemented` until the zk part exists.
///
///
/// Epoch freshness (`external_nullifier == H(epoch ‖ scope)`) is NOT inside the zk boundary: zk
/// binds the nullifier to external_nullifier but does not confirm the epoch is current. That is a
/// relay-side freshness check, and it is implemented here.
///
pub struct RlnQuotaTracker {
    current_epoch: u32,
    scope: Vec<u8>,
    /// nullifier(bytes) → the first share of the current epoch.
    current: std::collections::HashMap<[u8; 32], Share>,
    /// The same for the previous epoch (grace) — otherwise straddling an epoch boundary bypasses
    /// slashing.
    previous: std::collections::HashMap<[u8; 32], Share>,
    /// The ceiling on the map (bounded memory).
    capacity: usize,
}

impl RlnQuotaTracker {
    pub fn new(epoch_id: u32, scope: &[u8], capacity: usize) -> Self {
        RlnQuotaTracker {
            current_epoch: epoch_id,
            scope: scope.to_vec(),
            current: std::collections::HashMap::new(),
            previous: std::collections::HashMap::new(),
            capacity,
        }
    }

    /// Advance the epoch. On +1 the current map becomes the previous one (grace retains its
    /// nullifiers); on a larger jump there is no grace window and both maps are cleared. Time does
    /// not run backwards (a no-op).
    pub fn roll_epoch(&mut self, new_epoch: u32) {
        if new_epoch <= self.current_epoch {
            return;
        }
        if new_epoch == self.current_epoch + 1 {
            std::mem::swap(&mut self.previous, &mut self.current);
            self.current.clear();
        } else {
            self.previous.clear();
            self.current.clear();
        }
        self.current_epoch = new_epoch;
    }

    /// Observe a share (assumed already zk-verified — see the boundary above).
    /// Epoch freshness is checked first through `external_nullifier`, then repeat/violation
    /// detection in the map of the corresponding epoch.
    pub fn observe(&mut self, share: &Share) -> RlnOutcome {
        // Epoch freshness: external_nullifier must match the value expected for the current or
        // (grace) previous epoch.
        let ext_cur = external_nullifier(self.current_epoch, &self.scope);
        let is_current = share.external_nullifier == ext_cur;
        let is_previous = self.current_epoch > 0
            && share.external_nullifier
                == external_nullifier(self.current_epoch - 1, &self.scope);
        if !is_current && !is_previous {
            return RlnOutcome::WrongEpoch;
        }

        let capacity = self.capacity;
        let map = if is_current {
            &mut self.current
        } else {
            &mut self.previous
        };
        let key = share.nullifier.to_bytes();
        if let Some(first) = map.get(&key) {
            match slash(first, share) {
                SlashResult::Recovered(secret) => {
                    RlnOutcome::QuotaViolation { recovered_secret: secret }
                }
                SlashResult::SameMessage => RlnOutcome::Duplicate,
                SlashResult::DifferentNullifier => {
                    // The map is keyed by the nullifier itself, so the nullifiers are equal and
                    // slash cannot return "different". If that invariant is broken it is a bug,
                    // not a silent Duplicate.
                    debug_assert!(false, "equal nullifiers reported DifferentNullifier");
                    RlnOutcome::Duplicate
                }
            }
        } else {
            if map.len() >= capacity {
                return RlnOutcome::Backpressure;
            }
            map.insert(key, *share);
            RlnOutcome::Accepted
        }
    }
}
