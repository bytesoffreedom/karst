//! KARST — a working node skeleton: the first time the pieces of §7 (admission) become a MESSAGE
//! PATH rather than isolated mechanisms.
//!
//! The skeleton carries one encrypted message Alice → relay → Bob in process, with a real
//! admission handshake (§7) and a real (though classical-only, see `seal`) E2E envelope. The relay
//! gates on the credential and does NOT see the contents. The session §2.1 path (`peer`: PQXDH
//! `pqxdh` plus the Double Ratchet `ratchet`) is the real in-process E2E of the message path;
//! `seal` still carries the socket and CLI path, while §12 discovery (`peer::publish`/`connect`)
//! and session persistence are implemented — the `karst` CLI runs entirely on §2.1. `seal` remains
//! (`Session::snapshot`/`restore`, `Peer::export_state`/`import_state`)
//! only as the demo path for `Client`/`Recipient` (tests). An Android client is the next slice.
//!
//!
//! The boundaries, honestly: `seal::SkeletonSeal` is NOT §2.1 (no forward secrecy, no ratchet, no
//! PQ) — deferred by choice, not an external wall. Details in the `seal` module docs.

/// Mailbox deposit/fetch key separation via Ristretto point-blinding — wired into the live
/// drop-box path for established sessions (reference construction; the Schnorr fetch proof is
/// unaudited, first-contact openers keep the identity mailbox + DH proof). See the module.
// Injectable failure points for crash-consistency tests (QA-2). Behind an off-by-default feature;
// with it off the macro expands to nothing at all. See the module for why `abort` and not `panic`.
pub mod failpoint;
pub mod blobstore;
pub mod discovery;
// What a helper node may SEE, as a checked invariant rather than a table someone maintains
// (NODE-2). Test-only, like `identity_guard` next door: it asserts a property about this
// workspace's own shape, so it compiles away entirely in a release build.
#[cfg(test)]
mod helper_guard;
pub mod protocol;

// The crypto primitives live in their own crate now (#247). Re-exported so every `node::seal::…`
// path in this workspace keeps working: the CUT is the dependency direction, not a rename, and
// making thirty call sites churn would bury the one change that matters.
pub use karst_crypto::{blind, pqxdh, ratchet, safety, seal, session, veil};
pub mod wire;

pub mod scratch;
