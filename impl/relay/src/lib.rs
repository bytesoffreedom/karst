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

pub mod gossip;
pub mod mailstore;
pub mod node;
pub mod quic_server;
pub mod server;
