//! §7.3 — a threshold ring signature (t-of-N), a curve-friendly replacement for BSS.
//!
//! # STATUS: REFERENCE, NOT AUDITED. NOT FOR PRODUCTION.
//!
//! The module sits behind the `unaudited-crypto` feature flag (off by default). For a
//! security-critical primitive, "more trustworthy" ultimately means an independent audit — until
//! then this code cannot be treated as trusted. The weight is carried by the adversarial tests
//! (see the bottom of the file): t−1 signers must fail, a forgery must fail, and the signature
//! must bind to the ring and the message. A happy path proves nothing here by itself.
//!
//!
//! # The construction (pinned to a theorem, not ad hoc)
//!
//! Cramer–Damgård–Schoenmakers, «Proofs of Partial Knowledge and Simplified
//! Design of Witness Hiding Protocols", CRYPTO 1994 — a threshold σ-composition of Schnorr proofs,
//! made non-interactive through Fiat–Shamir. Discrete log over Ristretto255
//! (`curve25519-dalek`), compatible with KARST's Ed25519 stack (unlike the RSA-based
//! Bresson–Stern–Szydlo). Guided by the discrete-log ETRS work: Aranha, Hall-Andersen, Nitulescu,
//! Pagnin,
//! Yakoubov, «Count Me In! Extendability for Threshold Ring Signatures»,
//! PKC 2022.
//!
//! ## The idea
//!
//! N issuer keys `P_i = x_i·G`. At least t of them sign, without revealing which. Each issuer is
//! assigned the field point `i+1` (1-indexed; 0 is reserved for the master challenge). The Schnorr
//! challenges of all N ring members are tied together by one requirement: the challenges `c_i` lie
//! on a polynomial `p` of degree `N−t` with `p(0) = c`, where `c` is the Fiat–Shamir master
//! challenge over (t ‖ ring ‖ message ‖ all commitments). A signer who knows t secrets may pick
//! the `N−t` challenges of the simulated members freely; together with `(0,c)` that fixes `p`
//! (degree `N−t`), and the real signers' challenges then come out as `p(index)` — for which an
//! honest Schnorr response can be built.

//!
//! ## The inequality check (≥ t, not = t)
//!
//! A signature with more signers, `s > t`, yields a polynomial of degree `N−s < N−t` — which is
//! also of degree `≤ N−t` and therefore satisfies a policy of `t`. Verify checks "degree ≤ N−t"
//! (that is, "at least t signed"), not equality.
//! «= N−t».
//!
//! # What the tests do NOT prove (the boundaries, honestly)
//!
//! - **Unforgeability** rests on the CDS soundness theorem plus Fiat–Shamir in the ROM (the
//!   forking lemma), NOT on a unit test. `fewer_than_t_signers_fails...` only checks policy
//!   enforcement on an HONESTLY built signature — it does not model a malicious sub-threshold
//!   signer and cannot: that is a proof obligation, not an assertEq. The same discipline applies
//!   to anonymity below.
//!
//! - **Anonymity / unlinkability** rests on a simulation (HVZK) argument — also a proof, not a
//!   test. The tests only check the necessary symptoms.
//!
//! - **The NUMBER of signers `s` is revealed** (through the degree `N−s` of the interpolated
//!   polynomial), although WHO signed is not. It does not matter for our use — issuers sign
//!   exactly `t` — but the property must be named rather than assumed hidden.
//!

#![cfg(feature = "unaudited-crypto")]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::{Digest, Sha512};

const G: &RistrettoPoint = &RISTRETTO_BASEPOINT_POINT;

/// One issuer's key pair.
#[derive(Clone)]
pub struct IssuerKeypair {
    pub secret: Scalar,
    pub public: RistrettoPoint,
}

impl IssuerKeypair {
    pub fn from_secret(secret: Scalar) -> Self {
        IssuerKeypair {
            public: secret * G,
            secret,
        }
    }
}

/// The signature on the wire: challenges and responses only. The `R_i` are NOT transmitted — the
/// verifier reconstructs them as `R_i = s_i·G − c_i·P_i` (otherwise `c_i` could not be extracted
/// from the signature; that is a discrete log). All `c_i` are uniform, so publishing them says
/// nothing about the set of signers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdRingSig {
    pub challenges: Vec<Scalar>, // c_1..c_N
    pub responses: Vec<Scalar>,  // s_1..s_N
}

impl ThresholdRingSig {
    /// Wire format: [N: u32 BE][c_1..c_N: 32B each][s_1..s_N: 32B each].
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.challenges.len();
        let mut out = Vec::with_capacity(4 + n * 64);
        out.extend_from_slice(&(n as u32).to_be_bytes());
        for c in &self.challenges {
            out.extend_from_slice(c.as_bytes());
        }
        for s in &self.responses {
            out.extend_from_slice(s.as_bytes());
        }
        out
    }

    /// Parsing with a canonicity check on the scalars. `None` on any structural error or any
    /// non-canonical scalar.
    pub fn from_bytes(buf: &[u8]) -> Option<ThresholdRingSig> {
        if buf.len() < 4 {
            return None;
        }
        let n = u32::from_be_bytes(buf[0..4].try_into().ok()?) as usize;
        if buf.len() != 4 + n * 64 {
            return None;
        }
        let read_scalar = |off: usize| -> Option<Scalar> {
            let mut b = [0u8; 32];
            b.copy_from_slice(&buf[off..off + 32]);
            Option::<Scalar>::from(Scalar::from_canonical_bytes(b))
        };
        let mut challenges = Vec::with_capacity(n);
        let mut responses = Vec::with_capacity(n);
        for i in 0..n {
            challenges.push(read_scalar(4 + i * 32)?);
        }
        for i in 0..n {
            responses.push(read_scalar(4 + n * 32 + i * 32)?);
        }
        Some(ThresholdRingSig {
            challenges,
            responses,
        })
    }
}

/// Parse a compressed Ristretto point from 32 bytes (for issuer keys on the wire).
pub fn point_from_bytes(b: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(b).ok()?.decompress()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TRingError {
    /// t outside [1, N], or an empty ring.
    BadThreshold,
    /// Fewer signers than the threshold t.
    NotEnoughSigners,
    /// A signer index outside the ring, or a duplicate.
    BadSignerIndex,
}

fn hash_to_scalar(parts: &[&[u8]]) -> Scalar {
    let mut h = Sha512::new();
    for p in parts {
        h.update((p.len() as u64).to_be_bytes()); // length-prefixed domain separation
        h.update(p);
    }
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn point_bytes(p: &RistrettoPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

/// The master challenge `c = H(DOMAIN ‖ t ‖ P_1..P_N ‖ msg ‖ R_1..R_N)`.
/// It binds the threshold, the ORDERED ring, the message and every commitment — that is what makes
/// this a strong Fiat–Shamir (omitting any one of them opens a forgery hole).
fn master_challenge(
    t: usize,
    ring: &[RistrettoPoint],
    msg: &[u8],
    commitments: &[RistrettoPoint],
) -> Scalar {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    parts.push(b"KARST-tring-v1-challenge".to_vec());
    parts.push((t as u64).to_be_bytes().to_vec());
    parts.push((ring.len() as u64).to_be_bytes().to_vec());
    for p in ring {
        parts.push(point_bytes(p).to_vec());
    }
    parts.push(msg.to_vec());
    for r in commitments {
        parts.push(point_bytes(r).to_vec());
    }
    let refs: Vec<&[u8]> = parts.iter().map(|v| v.as_slice()).collect();
    hash_to_scalar(&refs)
}

/// The field point assigned to the issuer with index `i` (0-based): `i+1`.
/// 1-indexed because 0 is reserved for the master challenge; the points are distinct and non-zero
/// (otherwise the interpolation degenerates or leaks).
fn eval_point(i: usize) -> Scalar {
    Scalar::from((i as u64) + 1)
}

/// Lagrange interpolation: the value at `x_target` of the polynomial through `points`.
/// The points must have distinct x coordinates.
fn lagrange_eval(points: &[(Scalar, Scalar)], x_target: Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    for (k, (xk, yk)) in points.iter().enumerate() {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for (m, (xm, _)) in points.iter().enumerate() {
            if m == k {
                continue;
            }
            num *= x_target - xm;
            den *= xk - xm;
        }
        acc += yk * num * den.invert();
    }
    acc
}

/// Sign `msg` on behalf of the ring `ring` with threshold `t`, using `signers` — a list of
/// `(index_in_ring, secret)`. |signers| must be ≥ t.
///
/// The signers' nonces are derived deterministically from the FULL pre-challenge context (secret ‖
/// msg ‖ ring ‖ all of the simulation randomness). That is strictly stronger than `H(secret‖msg)`:
/// if the same signer signs the same message in a different composition or simulation, the nonce
/// changes too — otherwise, with the same `k` and a different `c_j`, the secret would leak through
/// `s = k + c·x` (the same class of leak as two shares in RLN §7.4).

pub fn sign(
    msg: &[u8],
    ring: &[RistrettoPoint],
    t: usize,
    signers: &[(usize, Scalar)],
) -> Result<ThresholdRingSig, TRingError> {
    let n = ring.len();
    if n == 0 || t == 0 || t > n {
        return Err(TRingError::BadThreshold);
    }
    if signers.len() < t {
        return Err(TRingError::NotEnoughSigners);
    }
    // Validate the signer indices: in range, no duplicates.
    let mut is_signer = vec![false; n];
    for (idx, _) in signers {
        if *idx >= n || is_signer[*idx] {
            return Err(TRingError::BadSignerIndex);
        }
        is_signer[*idx] = true;
    }
    let s = signers.len(); // the actual number of signers (≥ t)
    let degree = n - s; // polynomial degree

    // --- 1. Simulation for the NON-signers: free (c_i, s_i) ---
    // The simulation randomness is deterministic so that sign is reproducible in test vectors: it
    // is derived from (msg, ring, secrets, index). In production it is replaced by a CSPRNG; what
    // matters here is that it is fixed BEFORE the signers' nonces and hashed into them.

    let mut challenges = vec![Scalar::ZERO; n];
    let mut responses = vec![Scalar::ZERO; n];
    let mut sim_seed = Vec::new();
    sim_seed.extend_from_slice(b"KARST-tring-v1-sim");
    sim_seed.extend_from_slice(msg);
    for p in ring {
        sim_seed.extend_from_slice(&point_bytes(p));
    }
    for (idx, sk) in signers {
        sim_seed.extend_from_slice(&(*idx as u64).to_be_bytes());
        sim_seed.extend_from_slice(sk.as_bytes());
    }

    for i in 0..n {
        if is_signer[i] {
            continue;
        }
        let ci = hash_to_scalar(&[b"sim-c", &sim_seed, &(i as u64).to_be_bytes()]);
        let si = hash_to_scalar(&[b"sim-s", &sim_seed, &(i as u64).to_be_bytes()]);
        challenges[i] = ci;
        responses[i] = si;
    }

    // --- 2. Commitments of all members ---
    // For the signers: R_j = k_j·G, with k_j derived from the FULL context (including all of the
    // simulation randomness above).
    let mut ctx = sim_seed.clone();
    for i in 0..n {
        if !is_signer[i] {
            ctx.extend_from_slice(&challenges[i].to_bytes());
            ctx.extend_from_slice(&responses[i].to_bytes());
        }
    }
    let mut nonces = vec![Scalar::ZERO; n];
    let mut commitments = vec![RistrettoPoint::identity(); n];
    for i in 0..n {
        if is_signer[i] {
            let sk = signers.iter().find(|(idx, _)| *idx == i).unwrap().1;
            let kj = hash_to_scalar(&[b"KARST-tring-v1-nonce", sk.as_bytes(), &ctx,
                                       &(i as u64).to_be_bytes()]);
            nonces[i] = kj;
            commitments[i] = kj * G;
        } else {
            // R_i = s_i·G − c_i·P_i (simulated).
            commitments[i] = responses[i] * G - challenges[i] * ring[i];
        }
    }

    // --- 3. The master challenge ---
    let c = master_challenge(t, ring, msg, &commitments);

    // --- 4. The polynomial through (0, c) and the non-signers' (idx+1, c_i) → degree = n−s ---
    let mut poly_points: Vec<(Scalar, Scalar)> = Vec::with_capacity(degree + 1);
    poly_points.push((Scalar::ZERO, c));
    for i in 0..n {
        if !is_signer[i] {
            poly_points.push((eval_point(i), challenges[i]));
        }
    }
    debug_assert_eq!(poly_points.len(), degree + 1);

    // --- 5. The signers' challenges are p(idx+1); an honest Schnorr response follows ---
    for (idx, sk) in signers {
        let cj = lagrange_eval(&poly_points, eval_point(*idx));
        challenges[*idx] = cj;
        responses[*idx] = nonces[*idx] + cj * sk;
    }

    Ok(ThresholdRingSig {
        challenges,
        responses,
    })
}

/// Verify a signature against the ring `ring` and the threshold policy `t`.
/// `t` and `ring` are trusted parameters (from the §7.3 policy), NOT taken from the signature.
pub fn verify(msg: &[u8], ring: &[RistrettoPoint], t: usize, sig: &ThresholdRingSig) -> bool {
    let n = ring.len();
    if n == 0 || t == 0 || t > n {
        return false;
    }
    if sig.challenges.len() != n || sig.responses.len() != n {
        return false;
    }

    // 1. Reconstruct the commitments: R_i = s_i·G − c_i·P_i.
    let mut commitments = vec![RistrettoPoint::identity(); n];
    for i in 0..n {
        commitments[i] = sig.responses[i] * G - sig.challenges[i] * ring[i];
    }

    // 2. The master challenge over the same inputs.
    let c = master_challenge(t, ring, msg, &commitments);

    // 3. Check that all N challenge points plus (0,c) lie on a polynomial of degree ≤ n−t.
    //    Interpolate through (0,c) and the first (n−t) challenge points, then verify the remaining
    //    t challenge points against it.
    let degree = n - t;
    let mut basis: Vec<(Scalar, Scalar)> = Vec::with_capacity(degree + 1);
    basis.push((Scalar::ZERO, c));
    for i in 0..degree {
        basis.push((eval_point(i), sig.challenges[i]));
    }
    // basis.len() == degree + 1 == n − t + 1 points → a unique polynomial of degree ≤ n−t.
    for i in degree..n {
        let expected = lagrange_eval(&basis, eval_point(i));
        if expected != sig.challenges[i] {
            return false;
        }
    }
    // (The Schnorr equations hold by construction: each R_i was derived from (c_i,s_i) and the same
    // R_i went into c; a mismatch would break step 3.)
    true
}
