//! One answer to "am I talking to the right relay" — enforced, not remembered (QUIC-9, #245).
//!
//! The decision this guards is in `docs/design/quic-transport.md` §3: relay identity is
//! established by `Noise_NK` against the pinned relay-id, **the same way on every carrier**, and
//! no carrier establishes it any other way. Direct TCP, `wss://`, SOCKS5 to Tor/I2P/a mixnet, and
//! QUIC all funnel through the same handshake, so there is one place to review and one answer.
//!
//! **Why this file exists rather than a paragraph.** The risk is not that someone deliberately
//! reverses the decision after reading it. The risk is that a second way to decide "is this the
//! right relay" appears quietly — a certificate pinned here, a fingerprint compared there —
//! because on the carrier being worked on it looks like an obvious improvement. Then the client
//! authenticates the same relay differently depending on which carrier won the race (QUIC-4), the
//! weaker mechanism becomes the security level, and an attacker chooses which one you use by
//! making the other path fail. Every defect found in this repository's own documentation has the
//! same shape: a decision recorded in prose, unenforced, drifting silently away from the code.
//!
//! **What is NOT prohibited.** The `wss` carrier verifies its TLS certificate against the webpki
//! roots. That authenticates a HOSTNAME so the tunnel is a well-formed `wss://` connection — it is
//! transport encapsulation, and the relay behind it is still authenticated by Noise. The rule is
//! about relay IDENTITY, not about whether a carrier may use TLS.

/// Source files that make up the carrier layer, and the one that may establish relay identity.
const CARRIERS: &[(&str, &str)] = &[
    ("quic", include_str!("quic.rs")),
    ("wss", include_str!("wss.rs")),
    ("transport", include_str!("transport.rs")),
];

/// The single module allowed to run the relay handshake.
const DIALER: (&str, &str) = ("socket", include_str!("socket.rs"));

/// Vocabulary that means "this code decides which relay it is talking to" — as opposed to
/// "this code sets up a tunnel". Deliberately about PINNING and COMPARING, not about TLS as
/// such, so an ordinary certificate check for encapsulation does not trip it.
const IDENTITY_VOCABULARY: &[&str] = &[
    "cert_fingerprint",
    "expected_cert",
    "pinned_cert",
    "pin_certificate",
    "fingerprint(",
    "relay_id ==",
    "noise_pub ==",
];

/// What a would-be reverser has to solve first. Printed at the moment they try, which is the only
/// moment it is useful.
const REVERSAL_CONDITIONS: &str = "\
Reversing this needs three things that do not exist yet, and all three are real work:

  1. A SIGNED relay identity in the descriptor. `RelayDescriptor` is not signed as a document
     today; discovery signs `location_id`, which is the relay-id and nothing else, and addresses
     are deliberately unsigned hints validated by DIALLING them (gossip's verify-before-add). A
     certificate fingerprint would therefore sit in the unsigned part, where an intermediary
     substitutes it — which is exactly why QUIC-1 REFUSED that field.

  2. One answer that holds on EVERY carrier. TLS exists only on QUIC and WSS. Direct TCP and
     TCP-through-SOCKS have none, and Tor carries no UDP at all. Two mechanisms means the carrier
     that wins the race (QUIC-4) decides how the relay was authenticated.

  3. A reproducible measurement of what Noise actually costs. The figure in the design document is
     an explicitly-labelled one-off; the unambiguous part is that Noise_NK is ONE round trip
     (`-> e, es` / `<- e, ee`), and after QUIC-5 and QUIC-7 it is paid once per transfer rather
     than once per chunk. Argue from a number that can be reproduced, not a remembered one.

If you have all three: update docs/design/quic-transport.md §3 FIRST, then this guard.";

#[cfg(test)]
mod tests {
    use super::*;

    /// **Exactly one place decides which relay this is**, and it is the dialer.
    ///
    /// Discriminating: adding `Session::connect` to a carrier — or any pinning/comparison
    /// vocabulary — turns this red with the reversal conditions attached.
    #[test]
    fn no_carrier_establishes_relay_identity_on_its_own() {
        // Split so this file does not match itself when it is scanned as part of the crate.
        let handshake = concat!("Session", "::connect");
        for (name, src) in CARRIERS {
            assert!(
                !src.contains(handshake),
                "carrier `{name}` runs the relay handshake itself. Relay identity is established \
                 in ONE place (the dialer in socket.rs), the same way on every carrier, so that \
                 there is one answer to \"am I talking to the right relay\" and one place to \
                 review it.\n\n{REVERSAL_CONDITIONS}"
            );
            for bad in IDENTITY_VOCABULARY {
                assert!(
                    !src.contains(bad),
                    "carrier `{name}` contains `{bad}` — that is a carrier deciding relay \
                     identity for itself. A TLS certificate check for ENCAPSULATION is fine (wss \
                     does exactly that); pinning or comparing an identity is not.\n\n\
                     {REVERSAL_CONDITIONS}"
                );
            }
        }
        let (dialer_name, dialer_src) = DIALER;
        assert!(
            dialer_src.contains(handshake),
            "the dialer `{dialer_name}` no longer runs the relay handshake — either it moved (put \
             this guard where it went) or relay identity is now established somewhere else, which \
             is the thing this guard exists to notice.\n\n{REVERSAL_CONDITIONS}"
        );
    }

    /// The QUIC certificate verifier is a deliberate NO-OP, and its name says so.
    ///
    /// If it ever starts verifying something, that is a second identity mechanism arriving under
    /// a name that says the opposite — the worst version of this failure, because the name would
    /// go on reassuring reviewers after the behaviour changed.
    #[test]
    fn the_quic_certificate_verifier_stays_a_deliberate_no_op() {
        let src = include_str!("quic.rs");
        assert!(
            src.contains("NoiseAuthenticatesTheRelay"),
            "the QUIC certificate verifier was renamed. Its name is load-bearing: it tells a \
             reader that TLS here is encapsulation and the relay is authenticated one layer up.\n\n\
             {REVERSAL_CONDITIONS}"
        );
        // The verifier's body must return the "verified" assertion unconditionally. Anything that
        // branches on the certificate is a check, and a check is an identity decision.
        let body = src
            .split("fn verify_server_cert")
            .nth(1)
            .expect("the verifier implements verify_server_cert");
        let body = &body[..body.find("fn verify_tls12_signature").unwrap_or(body.len())];
        for branch in ["if ", "match ", "==", "!="] {
            assert!(
                !body.contains(branch),
                "`verify_server_cert` now branches on `{branch}` — it is verifying something. \
                 That makes TLS a second way to decide which relay this is.\n\n{REVERSAL_CONDITIONS}"
            );
        }
    }
}
