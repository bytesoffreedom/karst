//! The KARST client's session layer.
//!
//! `peer` is the §2.1 conversation — PQXDH first contact, the Double Ratchet, the blinded
//! drop-box routing and the receive loop. `drop` is the epoch arithmetic those boxes rotate on.
//! `demo` is the skeleton-seal path kept for tests.
//!
//! The last of the five crates #143 planned, and the one that states the original finding
//! plainly: NOTHING here can name a relay. The untrusted half and the end-to-end half no longer
//! share a namespace, in either direction.

pub mod demo;
pub mod drop;
pub mod pad;
pub mod peer;
