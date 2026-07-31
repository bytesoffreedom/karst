//! KARST — the reference implementation of the admission protocol (KARST_SPEC.md §7).
//!
//! Scope: the cryptographic admission path (§7.1–7.6). It is the most concretely specified and
//! most crypto-heavy part of the specification — and therefore the first place where a prose audit
//! structurally could not check that the primitives (Privacy Pass + threshold ring signature +
//! RLN) actually COMPOSE against a real crypto library. An implementation is the reviewer prose
//! cannot be.
//!
//!
//! Explicitly outside this crate's scope (and why):
//! - §7.3 threshold ring signature (Bresson–Stern–Szydlo) — no ready crate exists; defined as a
//!   trait plus a documented mock (see `token`).
//! - the §7.4 RLN zk_proof wrapper — it needs a circom/halo2 circuit, not an off-the-shelf
//!   primitive; the core is implemented (nullifier + Shamir slashing) and the zk wrapper is
//!   explicitly stubbed (see `rln`).

pub mod params;
pub mod cookie;
pub mod capability;
pub mod pow;
pub mod rln;
pub mod token;
pub mod pipeline;
pub mod dtn;

/// §7.3 threshold ring signature — REFERENCE, NOT AUDITED.
/// Available only behind the `unaudited-crypto` feature flag (off by default).
#[cfg(feature = "unaudited-crypto")]
pub mod tring;
