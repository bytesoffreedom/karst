//! KARST carriers (§15) — how bytes reach a relay, and nothing about what they mean.
//!
//! Split out of `node` (#247). Direct TCP, SOCKS5 (the seam to an external pluggable transport),
//! WebSocket-over-TLS, QUIC, and the client dialer that runs a Noise session over whichever of
//! them won the race.
//!
//! The arrow points one way: this crate uses the protocol vocabulary and the Noise session, and
//! nothing in either knows which carrier is underneath. That is the property that let the QUIC
//! adapter drop in without a single change above the adapter seam — and putting it behind a crate
//! boundary is what keeps it true.

// Enforces the one-identity-mechanism rule the carriers all rest on (QUIC-9, #245).
// Test-only: it reads this crate's own source and asserts a property, so it compiles away
// entirely in a release build.
#[cfg(test)]
mod identity_guard;

pub mod quic;
pub mod socket;
pub mod transport;
pub mod wss;
