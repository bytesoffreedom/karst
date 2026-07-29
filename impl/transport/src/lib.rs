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

pub mod quic;
pub mod socket;
pub mod transport;
pub mod wss;
