//! The versioned wire envelope (#144): a peer speaking a different protocol version, or asking for
//! a feature this build does not implement, is REFUSED with a reason — not decoded into plausible
//! nonsense that fails somewhere far from the cause.

use node::wire::{decode, encode, WireError, PROTOCOL_VERSION};
use node::protocol::JoinRequest;

fn describe(r: &Result<JoinRequest, WireError>) -> String {
    match r {
        Ok(_) => "a successfully decoded request".to_string(),
        Err(e) => e.to_string(),
    }
}

fn sample() -> JoinRequest {
    JoinRequest { bucket: 7, client_seed: [3u8; 32], nonce: 99 }
}

#[test]
fn a_round_trip_through_the_envelope_is_lossless() {
    let bytes = encode(&sample()).unwrap();
    let back: JoinRequest = decode(&bytes).unwrap();
    assert_eq!(back.bucket, 7);
    assert_eq!(back.nonce, 99);
    assert_eq!(back.client_seed, [3u8; 32]);
}

/// The version is the FIRST field, so a peer on another version is caught before its payload is
/// interpreted at all. Discriminating: without the check, postcard decodes the byte soup that
/// follows and the failure surfaces as some unrelated field being wrong.
#[test]
fn a_peer_on_another_protocol_version_is_refused_by_name() {
    let mut bytes = encode(&sample()).unwrap();
    // postcard varint-encodes a u16; every version this codebase has used is one byte at offset 0.
    assert_eq!(bytes[0], PROTOCOL_VERSION as u8, "the version leads the frame");
    // Derived from the current version, never a literal: this test used to hardcode `2` as "some
    // other version", which quietly stopped testing anything the day the wire moved to v2 — it
    // asserted that OUR OWN version is refused, and failed for that reason rather than for the one
    // it was written to catch.
    let other = PROTOCOL_VERSION + 1;
    assert!(other < 128, "a one-byte varint no longer holds the version — this patch needs rewriting");
    bytes[0] = other as u8;
    match decode::<JoinRequest>(&bytes) {
        Err(WireError::ProtocolVersion { got, want }) => {
            assert_eq!((got, want), (other, PROTOCOL_VERSION));
        }
        other => panic!("a version mismatch must name itself, got {}", describe(&other)),
    }
}

/// Unknown feature bits fail CLOSED. A peer setting one is asking for behaviour this build does
/// not implement; proceeding would mean pretending it was honoured.
#[test]
fn an_unimplemented_feature_bit_is_refused_rather_than_ignored() {
    let mut bytes = encode(&sample()).unwrap();
    // The feature word follows the version; zero today, so flipping the low bit is one byte.
    assert_eq!(bytes[1], 0, "feature bits are reserved and sent as zero");
    bytes[1] = 1;
    match decode::<JoinRequest>(&bytes) {
        Err(WireError::UnknownFeatureBits(b)) => assert_eq!(b, 1),
        other => panic!("an unknown feature bit must be refused, got {}", describe(&other)),
    }
}
