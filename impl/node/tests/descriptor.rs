//! **A relay's statement about itself, checked away from the relay** (NODE-1).
//!
//! The point of signing a descriptor is that it survives the trip. `GetPolicy` is only meaningful
//! inside a session with the relay it describes; a signed descriptor can be handed on by an
//! intermediary that is free to drop or delay it, and the next holder can still tell whether the
//! contents are what the relay actually said.
//!
//! So these tests are all about the trip: what an intermediary can change (nothing), what it can
//! replay (nothing indefinitely), and what a hostile relay can claim about its own validity window
//! (nothing unbounded). None of them involve a network — that is the property.

use node::discovery::public_of;
use node::protocol::{
    BlobPersistence, MailboxDurability, NodeDescriptor, RelayDescriptor, RelayPolicy,
    SignedDescriptor, DESCRIPTOR_SKEW_SECS, DESCRIPTOR_TTL_SECS,
};

const NOW: u64 = 1_800_000_000;
const SECRET: [u8; 32] = [7u8; 32];

fn policy() -> RelayPolicy {
    RelayPolicy {
        blob_persistence: Some(BlobPersistence::Ephemeral),
        blob_ttl_secs: 3600,
        max_blob_size: 1 << 20,
        pow_bits: Some(18),
        mailbox_durability: MailboxDurability::Volatile,
    }
}

fn relay_of(secret: &[u8; 32]) -> RelayDescriptor {
    RelayDescriptor {
        noise_pub: public_of(secret),
        fetch_pub: [3u8; 32],
        addrs: vec!["relay.example:443".into()],
        quic_addrs: vec!["relay.example:443".into()],
    }
}

fn signed() -> SignedDescriptor {
    NodeDescriptor::signed(relay_of(&SECRET), policy(), NOW, &SECRET)
}

#[test]
fn a_relays_own_statement_verifies() {
    let d = signed();
    let ok = d.verified(NOW).expect("a relay's own signature verifies");
    assert_eq!(ok.policy, policy(), "the policy survived the round trip");
    assert_eq!(ok.expires_at, NOW + DESCRIPTOR_TTL_SECS);
}

/// **THE property.** An intermediary passing a descriptor along cannot edit the policy inside it.
///
/// DISCRIMINATING: this is the whole reason the descriptor is signed rather than merely served. A
/// relay that forwards node-list data could otherwise advertise a neighbour as `Durable` when it
/// declared `Ephemeral` — steering clients that specifically asked for one posture into the other,
/// invisibly, since the victim relay never sees the lie told about it.
#[test]
fn a_forwarded_descriptor_cannot_have_its_policy_rewritten() {
    let mut d = signed();
    d.desc.policy.blob_persistence = Some(BlobPersistence::Durable);
    assert!(
        d.verified(NOW).is_none(),
        "a rewritten policy still verified — an intermediary can advertise a neighbour's posture as \
         whatever suits it, and the relay being lied about never finds out"
    );
}

/// The same for addresses: swapping in a proxy's address must not survive the signature.
///
/// Note what this does and does not replace. `gossip::verified_self_descriptor` already defeats
/// address substitution by DIALING and asking the relay itself; this closes the same class one
/// layer earlier, for holders who have not dialed yet.
#[test]
fn a_forwarded_descriptor_cannot_have_its_address_rewritten() {
    let mut d = signed();
    d.desc.relay.addrs = vec!["attacker-proxy.example:443".into()];
    assert!(d.verified(NOW).is_none(), "a substituted address still verified");
}

#[test]
fn another_relays_signature_does_not_verify() {
    let other: [u8; 32] = [9u8; 32];
    // Correctly signed — by the wrong key. The descriptor names `SECRET`'s public key.
    let d = NodeDescriptor::signed(relay_of(&SECRET), policy(), NOW, &other);
    assert!(d.verified(NOW).is_none(), "a descriptor signed by someone else verified");
}

/// A lapsed descriptor is refused, with the skew allowance honoured on the way out.
#[test]
fn a_lapsed_descriptor_is_refused_but_not_a_minute_early() {
    let d = signed();
    let expiry = NOW + DESCRIPTOR_TTL_SECS;
    assert!(d.verified(expiry - 1).is_some(), "refused before its expiry");
    assert!(
        d.verified(expiry + DESCRIPTOR_SKEW_SECS - 1).is_some(),
        "refused inside the skew allowance — two honest machines disagree by minutes, and making \
         discovery depend on NTP is a worse failure than a few minutes of staleness"
    );
    assert!(d.verified(expiry + DESCRIPTOR_SKEW_SECS + 1).is_none(), "a lapsed descriptor verified");
}

/// **A validity window longer than the protocol allows is refused, even when the signature is
/// perfect.**
///
/// DISCRIMINATING: without the upper-bound check, `expires_at` is a promise the signer makes to
/// itself — one line of a hostile fork mints a descriptor that never lapses, and every holder keeps
/// honouring a retired relay's addresses and policy forever. The discovery plane had exactly this
/// hole (`client/tests/discovery.rs`) before its own bound existed.
#[test]
fn a_descriptor_that_never_lapses_is_refused() {
    let desc = NodeDescriptor {
        relay: relay_of(&SECRET),
        policy: policy(),
        issued_at: NOW,
        expires_at: NOW + 10 * 365 * 24 * 3600,
    };
    let sig = node::discovery::sign(&SECRET, &node::protocol::descriptor_msg(&desc));
    let d = SignedDescriptor { desc, sig };
    assert!(
        d.verified(NOW).is_none(),
        "a ten-year validity window verified. The signature is genuine — that is the point: \
         `expires_at` bounds staleness only if the VERIFIER enforces the maximum, not the signer"
    );
}

#[test]
fn a_descriptor_signed_in_the_future_is_refused() {
    let d = signed();
    assert!(
        d.verified(NOW - DESCRIPTOR_SKEW_SECS - 60).is_none(),
        "a descriptor issued well after the verifier's clock verified"
    );
}

/// The signature covers the postcard encoding, so a decode/re-encode round trip must reproduce the
/// signed bytes exactly.
///
/// DISCRIMINATING for a canonicalisation mistake: reorder a field, or make the encoding depend on
/// anything that is not the struct's own contents, and a descriptor that travelled through a decode
/// stops verifying — which on the wire looks like every peer suddenly forging.
#[test]
fn a_reencoded_descriptor_still_verifies() {
    let d = signed();
    let bytes = postcard::to_stdvec(&d).expect("encodes");
    let back: SignedDescriptor = postcard::from_bytes(&bytes).expect("decodes");
    assert_eq!(back, d, "the round trip changed the struct");
    assert!(back.verified(NOW).is_some(), "a descriptor that survived a decode failed to verify");
}
