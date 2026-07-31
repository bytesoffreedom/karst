//! §7.3 — the Anonymous Admission Token (Privacy Pass-like).
//!
//! A token is presented WITHOUT an explicit `issuer_id`, through a **threshold ring signature**
//! (Bresson–Stern–Szydlo, CRYPTO 2002) over a set of trusted issuers: "at least t of N signed this
//! jointly", without revealing which ones. That hides which issuer issued the token — otherwise
//! the anonymity set shrinks to the users of one particular issuer (§7.3).
//!
//!
//! # Why a trait and a mock here instead of an implementation
//!
//! Bresson–Stern–Szydlo threshold ring signatures have NO ready, reviewed crate on crates.io
//! (unlike Ed25519, HMAC or the RLN field arithmetic, which are implemented for real in the
//! neighbouring modules). Writing a threshold ring signature from scratch inside a reference
//! skeleton would put unaudited crypto in the foundation; that is WORSE than an honest stub.
//!
//!
//! So this module defines `AdmissionTokenVerifier` — the trait the whole pipeline composes against
//! (§7.5, Stage 4, step 2) — and `MockRingVerifier`, a deliberately NON-cryptographic stub for
//! pipeline integration tests. This is one of the findings a prose audit structurally misses: the
//! spec named the primitive, and "named" is not "a ready implementation exists that composes with
//! the rest".
//!
//!
//! # The ecosystem survey (done before attempting an implementation)
//!
//! Checking crates.io settled the outcome as "an external dependency", not "I will implement it
//! now":
//!
//! - The Bresson–Stern–Szydlo threshold ring signature does NOT exist in Rust.
//! - Every available ring crate is 1-of-N (the Monero family: SAG/bLSAG/CLSAG/MLSAG) and does not
//!   cover "2 of 5".
//! - The FROST family gives "t of N" but NOT anonymously (the signers are known) and needs a DKG
//!   or a shared group key — a different trust model from an ad-hoc ring of N independent
//!   issuers.
//! - BSS itself is built on RSA / trapdoor permutations (RST), while the KARST stack is
//!   Curve25519/Ed25519: literal BSS does not compose. The correct replacement is a
//!   curve-friendly discrete-log threshold ring construction, which still has to be chosen and
//!   reviewed. See §7.3 of the specification.
//!
//! Implementing threshold ring crypto from scratch here is MORE DANGEROUS than leaving an honest
//! stub (happy-path tests over homemade crypto manufacture false confidence in a
//! security-critical primitive). So the stub stays as working code until a specific construction
//! is chosen and audited.

/// The token as it is presented to a relay (§7.3). `ring_sig` is the opaque bytes of a threshold
/// ring signature over `t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionToken {
    /// The threshold ring signature over `t` by the set of trusted issuer keys.
    pub ring_sig: Vec<u8>,
    /// The token's unblinded nonce (bytes[32]).
    pub t: [u8; 32],
    pub epoch_id: u32,
}

/// The public keys of the trusted issuers and the required threshold t of N.
#[derive(Debug, Clone)]
pub struct IssuerRing {
    pub issuer_pubkeys: Vec<[u8; 32]>,
    /// The threshold: how many issuers MUST sign jointly (1..=N). One primitive covers both
    /// "1 of 5" and "2 of 5" (§7.3).
    pub threshold_t: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// The threshold is outside [1, N].
    BadThreshold,
    /// The signature failed verification against the ring.
    BadRingSignature,
    /// The token was already seen this epoch (double spend) — detected by the caller through the
    /// replay filter (§7.5, Stage 3), not by the verifier itself.
    Replayed,
}

/// The contract the pipeline composes against (§7.5, Stage 4 step 2). The real verifier (a BSS
/// port) and the mock implement the same trait, so the pipeline does not change when one is
/// swapped for the other.
pub trait AdmissionTokenVerifier {
    /// Check that `token.ring_sig` is a valid threshold ring signature over `token.t` by `ring`,
    /// for the epoch `expected_epoch`.
    fn verify(
        &self,
        token: &AdmissionToken,
        ring: &IssuerRing,
        expected_epoch: u32,
    ) -> Result<(), TokenError>;
}

/// A NON-CRYPTOGRAPHIC stub for pipeline integration tests.
///
/// It checks only structural sanity (the threshold is in range, the epoch matches, the signature
/// is non-empty and its length is encoded as expected). It must NEVER be used in production — its
/// only job is to give the pipeline an object of the right type until a real BSS verifier is
/// ported.
/// Constructible only through `for_tests_only()`, whose name is the point: the private field
/// makes `MockRingVerifier` impossible to write by accident (`MockRingVerifier` as a unit value
/// no longer compiles), so any use of it has to name what it is at the call site and survive
/// review saying that out loud (#145).
pub struct MockRingVerifier {
    _not_constructible_by_accident: (),
}

impl MockRingVerifier {
    /// The only way to build one. NOT cryptography — see the type's doc comment.
    pub fn for_tests_only() -> Self {
        MockRingVerifier { _not_constructible_by_accident: () }
    }
}

/// The ABSENCE of a token verifier, expressed as a type (#145).
///
/// Refuses every admission token, always. A relay that has no audited threshold-ring verifier
/// available should be structurally incapable of accepting a token credential, rather than
/// leaning on the fact that no wire request happens to carry one today — that is the kind of
/// property a future protocol change silently revokes. `RelayNode` holds this, so wiring up a
/// real verifier is a deliberate TYPE change in the relay, not a config or feature-flag flip
/// that a mistake could make for you.
pub struct NoTokenVerifier;

impl AdmissionTokenVerifier for NoTokenVerifier {
    fn verify(
        &self,
        _token: &AdmissionToken,
        _ring: &IssuerRing,
        _expected_epoch: u32,
    ) -> Result<(), TokenError> {
        Err(TokenError::BadRingSignature)
    }
}

/// The mock "signature" format: the first byte is the claimed number of signers, followed by that
/// many 32-byte empty slots. Just enough for a pipeline test to construct a token that is
/// "structurally valid" and one that is not (below the threshold), without pretending to any
/// cryptographic strength.
pub const MOCK_SIG_SLOT: usize = 32;

impl AdmissionTokenVerifier for MockRingVerifier {
    fn verify(
        &self,
        token: &AdmissionToken,
        ring: &IssuerRing,
        expected_epoch: u32,
    ) -> Result<(), TokenError> {
        let n = ring.issuer_pubkeys.len();
        if ring.threshold_t == 0 || ring.threshold_t > n {
            return Err(TokenError::BadThreshold);
        }
        if token.epoch_id != expected_epoch {
            return Err(TokenError::BadRingSignature);
        }
        // The "number of signers" from the first byte of the mock signature.
        let claimed_signers = *token.ring_sig.first().ok_or(TokenError::BadRingSignature)? as usize;
        let expected_len = 1 + claimed_signers * MOCK_SIG_SLOT;
        if token.ring_sig.len() != expected_len {
            return Err(TokenError::BadRingSignature);
        }
        // Threshold: there must be at least t signers and no more than N.
        if claimed_signers < ring.threshold_t || claimed_signers > n {
            return Err(TokenError::BadRingSignature);
        }
        Ok(())
    }
}

impl MockRingVerifier {
    /// Build a mock token "signed" by `signers` issuers, for tests.
    pub fn mock_token(t: [u8; 32], epoch_id: u32, signers: usize) -> AdmissionToken {
        let mut ring_sig = Vec::with_capacity(1 + signers * MOCK_SIG_SLOT);
        ring_sig.push(signers as u8);
        ring_sig.resize(1 + signers * MOCK_SIG_SLOT, 0u8);
        AdmissionToken {
            ring_sig,
            t,
            epoch_id,
        }
    }
}

/// The real verifier over the §7.3 threshold ring signature (tring).
/// REFERENCE, NOT AUDITED — available only behind the `unaudited-crypto` feature flag.
///
/// This is the composition the trait exists for: the pipeline (§7.5, Stage 4 step 2) can now run
/// against real crypto rather than only against the mock.
///
/// **The boundary.** The ring signature proves "at least t issuers signed the token nonce `t`".
/// `epoch_id` is NOT part of the signature itself (in the Privacy Pass model an issuer signs a
/// token once, blindly, without knowing the future epoch) — epoch freshness comes from the
/// pipeline's separate replay filter, tied to the quota epoch (§7.5, Stage 3). All that is checked
/// here is that the token's claimed epoch matches the expected one.
#[cfg(feature = "unaudited-crypto")]
pub struct RealRingVerifier;

#[cfg(feature = "unaudited-crypto")]
impl AdmissionTokenVerifier for RealRingVerifier {
    fn verify(
        &self,
        token: &AdmissionToken,
        ring: &IssuerRing,
        expected_epoch: u32,
    ) -> Result<(), TokenError> {
        let n = ring.issuer_pubkeys.len();
        if ring.threshold_t == 0 || ring.threshold_t > n {
            return Err(TokenError::BadThreshold);
        }
        if token.epoch_id != expected_epoch {
            return Err(TokenError::BadRingSignature);
        }
        // Decode the ring's issuer keys into Ristretto points.
        let mut ring_points = Vec::with_capacity(n);
        for pk in &ring.issuer_pubkeys {
            let p = crate::tring::point_from_bytes(pk).ok_or(TokenError::BadRingSignature)?;
            ring_points.push(p);
        }
        // Parse the signature and verify it against the token nonce as the message.
        let sig = crate::tring::ThresholdRingSig::from_bytes(&token.ring_sig)
            .ok_or(TokenError::BadRingSignature)?;
        if sig.challenges.len() != n {
            return Err(TokenError::BadRingSignature);
        }
        if crate::tring::verify(&token.t, &ring_points, ring.threshold_t, &sig) {
            Ok(())
        } else {
            Err(TokenError::BadRingSignature)
        }
    }
}
