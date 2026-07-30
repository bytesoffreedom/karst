//! §12 discovery plane — the node-list, now carrying what each relay SIGNED about itself.
//!
//! The slice that put signatures in the list changed three rules at once, and this file is where
//! they are pinned:
//!
//! 1. **Merging died, and that is the improvement.** Unioning addresses across sightings made
//!    sense while each sighting was a fragment of the truth. A signed descriptor is the relay's
//!    whole current answer, so the only question left is which answer is newer.
//! 2. **Bounds refuse instead of trim.** Truncating an over-long address list leaves a document
//!    whose signature no longer verifies; storing that would mean re-serving something nobody
//!    signed.
//! 3. **Hints and known entries are different lists.** Nothing signs a config line, so an
//!    operator-configured peer is a place to dial and is never served.

use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use karst_transport::socket::SocketTransport;
use node::protocol::{
    NodeDescriptor, RelayPolicy, SignedDescriptor, DESCRIPTOR_SKEW_SECS, DESCRIPTOR_TTL_SECS,
};

/// Comfortably past the validity window, skew included — `verified` allows clocks to disagree by
/// `DESCRIPTOR_SKEW_SECS`, so "one second past expiry" is still inside the window on purpose.
const WELL_AFTER_EXPIRY: u64 = DESCRIPTOR_TTL_SECS + DESCRIPTOR_SKEW_SECS + 1;
use relay::node::{RelayDescriptor, RelayNode, MAX_ADDRS_PER_RELAY, MAX_KNOWN_RELAYS};
use relay::server::{generate_noise_keypair, RelayServer};

const NOW: u64 = 1_000_000;

fn desc(n: u8, addr: &str) -> RelayDescriptor {
    RelayDescriptor {
        noise_pub: [n; 32],
        fetch_pub: [n; 32],
        addrs: vec![addr.into()],
        quic_addrs: Vec::new(),
    }
}

/// A relay that can sign for itself: the keypair plus a builder for its statements.
struct Signer {
    secret: [u8; 32],
    public: [u8; 32],
}

impl Signer {
    fn new() -> Self {
        let (secret, public) = generate_noise_keypair();
        Signer { secret, public }
    }

    fn say(&self, addrs: &[&str], quic: &[&str], issued_at: u64) -> SignedDescriptor {
        let relay = RelayDescriptor {
            noise_pub: self.public,
            fetch_pub: [7; 32],
            addrs: addrs.iter().map(|s| s.to_string()).collect(),
            quic_addrs: quic.iter().map(|s| s.to_string()).collect(),
        };
        NodeDescriptor::signed(relay, RelayPolicy {
        blob_persistence: None,
        blob_ttl_secs: 0,
        max_blob_size: 0,
        pow_bits: None,
        mailbox_durability: node::protocol::MailboxDurability::Volatile,
    }, issued_at, &self.secret)
    }
}

#[test]
fn a_newer_statement_replaces_the_older_one_whole() {
    // DISCRIMINATING: go back to unioning addresses and this reds — the old address survives
    // alongside the new one, which is precisely a document the relay never signed.
    let s = Signer::new();
    let mut r = RelayNode::new(NOW);
    assert!(r.add_relay(s.say(&["old.example:9000"], &[], NOW), NOW));
    assert!(r.add_relay(s.say(&["new.example:9000"], &[], NOW + 60), NOW));

    let list = r.known_relays();
    assert_eq!(list.len(), 1, "same relay-id must not duplicate");
    assert_eq!(
        list[0].desc.relay.addrs,
        vec!["new.example:9000".to_string()],
        "the newer statement replaces the older one entirely — no union, no leftovers"
    );
}

#[test]
fn an_older_statement_cannot_displace_a_newer_one() {
    // A peer replaying yesterday's genuine, correctly-signed descriptor must not roll us back to
    // an address the relay has since moved off. Ties keep what we already verified.
    let s = Signer::new();
    let mut r = RelayNode::new(NOW);
    r.add_relay(s.say(&["current.example:9000"], &[], NOW + 60), NOW);
    r.add_relay(s.say(&["stale.example:9000"], &[], NOW), NOW);
    r.add_relay(s.say(&["tie.example:9000"], &[], NOW + 60), NOW);

    assert_eq!(
        r.known_relays()[0].desc.relay.addrs,
        vec!["current.example:9000".to_string()],
        "a replayed older (or equally old) statement must not displace the current one"
    );
}

#[test]
fn a_relay_can_learn_that_a_known_peer_also_speaks_quic() {
    // The property QUIC-11 was about survives the change of mechanism: a relay you already knew
    // can acquire a QUIC endpoint. It no longer arrives by merging a field into a stored entry —
    // it arrives because the relay signed a newer statement that has it.
    let s = Signer::new();
    let mut r = RelayNode::new(NOW);
    r.add_relay(s.say(&["relay.example:9000"], &[], NOW), NOW);
    r.add_relay(s.say(&["relay.example:9000"], &["relay.example:9000"], NOW + 1), NOW);

    let e = &r.known_relays()[0].desc.relay;
    assert_eq!(e.quic_addrs, vec!["relay.example:9000".to_string()]);
    assert_eq!(e.addrs.len(), 1, "the TCP address must not be duplicated");
}

#[test]
fn an_unverifiable_or_oversized_statement_is_refused_rather_than_repaired() {
    let s = Signer::new();
    let mut r = RelayNode::new(NOW);

    // No dial hint: nothing to reach, so nothing worth a slot.
    assert!(!r.add_relay(s.say(&[], &[], NOW), NOW), "a descriptor with no address is useless");

    // Over the address cap. The old code trimmed to fit; trimming now breaks the signature, so
    // the whole statement is refused and stays refused until its signer fixes it.
    let many: Vec<String> =
        (0..MAX_ADDRS_PER_RELAY + 3).map(|i| format!("h{i}.example:9000")).collect();
    let over: Vec<&str> = many.iter().map(|s| s.as_str()).collect();
    assert!(!r.add_relay(s.say(&over, &[], NOW), NOW), "an over-long address list is refused");

    // A forged signature: the same descriptor, someone else's key.
    let mut forged = s.say(&["real.example:9000"], &[], NOW);
    forged.sig[0] ^= 0xFF;
    assert!(!r.add_relay(forged, NOW), "a broken signature is a forgery, not a warning");

    // Lapsed: still perfectly signed, no longer usable.
    let old = s.say(&["real.example:9000"], &[], NOW);
    assert!(
        !r.add_relay(old, NOW + WELL_AFTER_EXPIRY),
        "an expired statement must not enter the list"
    );

    assert!(r.known_relays().is_empty(), "nothing partially-trusted was stored");
}

/// **An operator's hint is never served.** THE security property of the hint/known split: the
/// value of the served list is that every entry is signed, and one unsigned operator-typed
/// address in it destroys that for the whole list.
///
/// DISCRIMINATING: serve `relay_hints` from `node_list` and this reds immediately.
#[test]
fn a_configured_hint_is_a_place_to_dial_and_never_something_we_serve() {
    let mut r = RelayNode::new(NOW);
    r.add_relay_hint(desc(3, "configured.example:9000"));

    assert_eq!(r.relay_hints().len(), 1, "the hint is kept — it is where we try");
    assert!(
        r.node_list(NOW).is_empty(),
        "an unsigned configured address must never reach the served list"
    );
    assert!(r.known_relays().is_empty(), "nor the set of what others signed");
}

#[test]
fn the_known_set_is_bounded() {
    let mut r = RelayNode::new(NOW);
    for i in 0..(MAX_KNOWN_RELAYS + 20) {
        let s = Signer::new();
        r.add_relay(s.say(&[&format!("h{i}.example:9000")], &[], NOW), NOW);
    }
    assert!(r.known_relays().len() <= MAX_KNOWN_RELAYS, "the stored set never exceeds the bound");
}

/// Self is always in the page, and no longer because it was seeded into slot zero: it is served
/// from the signed self-descriptor, the one statement this relay authors rather than carries. A
/// peer that cannot read it cannot verify us at all.
#[test]
fn self_is_served_first_and_survives_a_full_table() {
    let (secret, public) = generate_noise_keypair();
    let mut r = RelayNode::new(NOW);
    r.set_self_descriptor(RelayDescriptor {
        noise_pub: public,
        fetch_pub: [1; 32],
        addrs: vec!["self.example:9000".into()],
        quic_addrs: Vec::new(),
    });
    r.refresh_signed_descriptor(NOW, &secret);

    // Enough long-addressed peers to force the page trim to engage.
    for i in 0..MAX_KNOWN_RELAYS {
        let s = Signer::new();
        let long = format!("{}{i}.example:9000", "x".repeat(230));
        r.add_relay(s.say(&[&long], &[], NOW), NOW);
    }

    let served = r.node_list(NOW);
    assert!(
        served.len() < MAX_KNOWN_RELAYS,
        "the frame trim must engage for this to mean anything"
    );
    assert_eq!(
        served[0].desc.relay.noise_pub, public,
        "self must lead the page, or a peer cannot verify us"
    );
}

/// A lapsed entry is kept (it is evidence we once verified that relay) but never repeated: that
/// is how a stale address stops outliving the relay that moved away from it.
#[test]
fn an_expired_entry_is_held_but_not_passed_on() {
    let s = Signer::new();
    let mut r = RelayNode::new(NOW);
    r.add_relay(s.say(&["peer.example:9000"], &[], NOW), NOW);

    assert_eq!(r.node_list(NOW).len(), 1, "fresh entries are served");
    assert!(
        r.node_list(NOW + WELL_AFTER_EXPIRY).is_empty(),
        "a lapsed statement must not be handed on"
    );
    assert_eq!(r.known_relays().len(), 1, "…but it is still held, not silently pruned");
}

#[test]
fn get_node_list_travels_over_the_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let s = Signer::new();
    let mut relay = RelayNode::new(NOW);
    relay.add_relay(s.say(&["peer.example:9000"], &[], NOW), NOW);
    let server = RelayServer::new(relay, Arc::new(move || NOW));
    let noise_pub = server.noise_public();
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });

    let got = SocketTransport::new(addr, noise_pub)
        .get_node_list()
        .expect("node-list over the wire");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].desc.relay.addrs, vec!["peer.example:9000".to_string()]);
    // And it still verifies after the round trip: postcard is positional, so a field reordering
    // between encode and decode would break the signature rather than pass silently.
    assert!(got[0].verified(NOW).is_some(), "the signature must survive the wire unchanged");
}
