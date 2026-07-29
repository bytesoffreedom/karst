//! KARST cryptographic primitives.
//!
//! Split out of `node` (#247, following the relay split in #143). This crate sits at the BOTTOM of
//! the dependency arrow: it cannot name a request type, a transport or a relay. A change to the
//! protocol therefore cannot reach in here, and a fault here cannot be explained away as a wire
//! problem.
//!
//! The group is closed by construction — `ratchet` uses `seal` and `session`, `pqxdh` uses `blind`
//! and `seal`, and nothing reaches outside — which is what made it the cleanest of the cuts left
//! after the relay came out.

pub mod blind;
pub mod pqxdh;
pub mod ratchet;
pub mod safety;
pub mod seal;
pub mod session;
