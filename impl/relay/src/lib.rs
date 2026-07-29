//! KARST relay — the UNTRUSTED half.
//!
//! Split out of `node` (#143). That crate held the relay implementation and the client's
//! end-to-end crypto in one namespace, so nothing structurally stopped a client from reaching
//! into relay internals, or a UI from bypassing the client API altogether. The two now sit on
//! either side of the dependency arrow: this crate depends on `node` for the shared protocol
//! vocabulary and the primitives; `node` does not depend on this one, and cannot.
//!
//! What lives here: the relay state machine (`node`), the durable mailbox log (`mailstore`),
//! the node-list gossip (`gossip`), and the listener (`server`).

// ── The production gate (#145) ────────────────────────────────────────────────────────────────
//
// There is no production build of KARST, and this is where that fact is enforced rather than
// asserted. `--features production` fails to COMPILE, and the message names what is missing.
//
// Why a compile error and not a runtime check: a runtime warning is something an operator scrolls
// past, and a README paragraph is something nobody reads twice. A build that refuses to exist
// cannot be shipped by accident, cannot be enabled by a config flip, and cannot drift out of date
// — when the last wall falls, the feature it requires exists and the gate opens by itself.
//
// The default build is unchanged and unaffected: it is the reference build, it says so at startup,
// and it is what every script and document here describes.
#[cfg(all(feature = "production", not(feature = "audited-token-verifier")))]
compile_error!(
    "KARST has no production build yet, and this gate exists so that fact cannot be forgotten.\n\
     \n\
     Missing: an independently AUDITED implementation of `admission::token::AdmissionTokenVerifier`.\n\
     The relay currently installs `NoTokenVerifier`, which refuses every admission token. That is \
     the safe posture, not a finished one — the threshold ring signature is a reference \
     implementation behind `--features unaudited-crypto`, and the RLN membership path returns \
     `RlnNotImplemented` because its zero-knowledge circuit is not built.\n\
     \n\
     Do not remove this gate to make a build succeed. Provide the audited verifier and enable \
     `--features audited-token-verifier`; the gate then opens on its own.\n\
     \n\
     For a reference relay, build WITHOUT `--features production` — that is the supported build, \
     and `docs/STATUS.md` says exactly what it does and does not give you."
);

pub mod gossip;
pub mod mailstore;
pub mod node;
pub mod quic_server;
pub mod server;
