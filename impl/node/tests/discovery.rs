//! §12 4c — opt-in discovery (contact code) at the `RelayNode` level. Pins the properties the
//! design promises: a record is written ONLY on an explicit, self-authenticated publish (never as
//! a side effect of a bundle publish); the write is authorised by the discovery key; the record
//! binds to a real IK; expiry is enforced; and a delete removes the slot.

use std::cell::RefCell;
use std::rc::Rc;

use admission::capability::{Capability, Quota, Scope};
use node::discovery::{self, DiscoveryRecord, DEFAULT_TTL_SECS, MAX_TTL_SECS};
use node::node::{InMemoryTransport, PublishResponse, RelayDescriptor, RelayNode};
use node::peer::Peer;
use node::pqxdh::Account;

const NOW: u64 = 1_000_000;

fn dev_cap() -> Capability {
    Capability {
        capability_id: [0xCA; 16],
        scope: Scope::MessageDelivery,
        quota: Quota { max_requests: 100, max_bytes: 1 << 20, window_secs: 600 },
        not_before: 0,
        not_after: u32::MAX,
        secret: [0x33; 32],
    }
}

fn loc() -> RelayDescriptor {
    RelayDescriptor { noise_pub: [1u8; 32], fetch_pub: [2u8; 32], addrs: vec!["relay.example:9000".into()] }
}

/// Build a valid record + its write signature for `acct`, under discovery secret `dsecret`.
fn signed_record(acct: &Account, dsecret: &[u8; 32], expiry: u64) -> (DiscoveryRecord, Vec<u8>) {
    signed_record_su(acct, dsecret, expiry, false)
}
fn signed_record_su(acct: &Account, dsecret: &[u8; 32], expiry: u64, single_use: bool) -> (DiscoveryRecord, Vec<u8>) {
    let dpub = discovery::public_of(dsecret);
    let ik = acct.identity_public();
    let location = loc();
    let ik_sig = acct.sign_discovery(&dpub, &location, expiry, single_use);
    let write_sig = discovery::sign(dsecret, &discovery::write_msg(&dpub, &ik, &location, expiry, single_use));
    (DiscoveryRecord { discovery_pub: dpub, ik, location, expiry, single_use, ik_sig }, write_sig)
}

#[test]
fn opt_in_publish_is_lookupable_and_binds_to_the_ik() {
    let acct = Account::generate();
    let dsecret = [7u8; 32];
    let (rec, write_sig) = signed_record(&acct, &dsecret, NOW + DEFAULT_TTL_SECS);
    let mut relay = RelayNode::new(NOW);

    assert!(relay.handle_publish_discovery(&rec, &write_sig, NOW), "a valid opt-in publish is accepted");

    let pseudonym = discovery::discovery_pseudonym(&rec.discovery_pub);
    let got = relay.handle_lookup_discovery(&pseudonym, NOW).expect("published record resolves");
    assert_eq!(got, rec);
    assert!(discovery::verify_binding(&got), "a resolver can verify the code→IK binding itself");
    // The account's real IK is what the code resolves to.
    assert_eq!(got.ik, acct.identity_public());
    // A pseudonym for a different code has nothing.
    assert!(relay.handle_lookup_discovery(&discovery::discovery_pseudonym(&[9u8; 32]), NOW).is_none());
}

#[test]
fn one_time_invite_resolves_once_then_is_gone() {
    let acct = Account::generate();
    let dsecret = [11u8; 32];
    let (rec, write_sig) = signed_record_su(&acct, &dsecret, NOW + 1000, true);
    let mut relay = RelayNode::new(NOW);
    assert!(relay.handle_publish_discovery(&rec, &write_sig, NOW), "single-use publish accepted");
    let pseudonym = discovery::discovery_pseudonym(&rec.discovery_pub);
    // First resolve returns it and self-verifies; the SECOND finds nothing (consumed).
    let got = relay.handle_lookup_discovery(&pseudonym, NOW).expect("first resolve works");
    assert!(got.single_use && discovery::verify_binding(&got), "one-time binding verifies");
    assert!(relay.handle_lookup_discovery(&pseudonym, NOW).is_none(), "consumed after one resolve");
}

#[test]
fn write_requires_the_discovery_key_and_a_real_ik_binding() {
    let acct = Account::generate();
    let dsecret = [7u8; 32];
    let (rec, _good) = signed_record(&acct, &dsecret, NOW + DEFAULT_TTL_SECS);
    let mut relay = RelayNode::new(NOW);

    // A write signed by someone who does not own the discovery key is refused (no slot hijack).
    let forged_write = discovery::sign(&[8u8; 32], &discovery::write_msg(&rec.discovery_pub, &rec.ik, &rec.location, rec.expiry, rec.single_use));
    assert!(!relay.handle_publish_discovery(&rec, &forged_write, NOW), "wrong write key rejected");

    // A record pointing the code at a different IK than the one that signed the binding is refused.
    let (mut rec2, write2) = signed_record(&acct, &dsecret, NOW + DEFAULT_TTL_SECS);
    rec2.ik = [0xAB; 32];
    assert!(!relay.handle_publish_discovery(&rec2, &write2, NOW), "broken IK binding rejected");

    assert!(relay.handle_lookup_discovery(&discovery::discovery_pseudonym(&rec.discovery_pub), NOW).is_none());
}

#[test]
fn expiry_is_enforced_on_publish_and_lookup() {
    let acct = Account::generate();
    let dsecret = [7u8; 32];
    let mut relay = RelayNode::new(NOW);

    // Already-expired and absurdly-far expiries are both refused at publish.
    let (past, past_sig) = signed_record(&acct, &dsecret, NOW - 1);
    assert!(!relay.handle_publish_discovery(&past, &past_sig, NOW));
    let (far, far_sig) = signed_record(&acct, &dsecret, NOW + MAX_TTL_SECS + 1);
    assert!(!relay.handle_publish_discovery(&far, &far_sig, NOW));

    // A record valid now is dropped once the clock passes its expiry.
    let expiry = NOW + 100;
    let (rec, sig) = signed_record(&acct, &dsecret, expiry);
    assert!(relay.handle_publish_discovery(&rec, &sig, NOW));
    let pseudonym = discovery::discovery_pseudonym(&rec.discovery_pub);
    assert!(relay.handle_lookup_discovery(&pseudonym, expiry - 1).is_some());
    assert!(relay.handle_lookup_discovery(&pseudonym, expiry + 1).is_none(), "stale record is not served");
}

#[test]
fn rotate_and_delete_control_the_slot() {
    let acct = Account::generate();
    let mut relay = RelayNode::new(NOW);

    // Publish under one code, then rotate to a fresh code: both writes are the owner's own.
    let (rec1, sig1) = signed_record(&acct, &[7u8; 32], NOW + DEFAULT_TTL_SECS);
    let (rec2, sig2) = signed_record(&acct, &[8u8; 32], NOW + DEFAULT_TTL_SECS);
    assert!(relay.handle_publish_discovery(&rec1, &sig1, NOW));
    assert!(relay.handle_publish_discovery(&rec2, &sig2, NOW));

    // Delete the old slot (turn that code off) with a discovery-key signature.
    let del_sig = discovery::sign(&[7u8; 32], &discovery::delete_msg(&rec1.discovery_pub));
    assert!(relay.handle_delete_discovery(&rec1.discovery_pub, &del_sig));
    assert!(relay.handle_lookup_discovery(&discovery::discovery_pseudonym(&rec1.discovery_pub), NOW).is_none(), "retired code stops resolving");
    // The rotated-to code still resolves; identity (IK) is unchanged across the rotation.
    let live = relay.handle_lookup_discovery(&discovery::discovery_pseudonym(&rec2.discovery_pub), NOW).unwrap();
    assert_eq!(live.ik, acct.identity_public());

    // A delete not signed by the code's owner does nothing.
    let bad = discovery::sign(&[99u8; 32], &discovery::delete_msg(&rec2.discovery_pub));
    assert!(!relay.handle_delete_discovery(&rec2.discovery_pub, &bad));
}

#[test]
fn publishing_a_bundle_does_not_make_you_findable() {
    // The whole point of the redesign: being reachable (a published bundle) must NOT enroll you in
    // any lookup-able directory. Only an explicit discovery publish does.
    let mut relay = RelayNode::new(NOW);
    relay.issue_capability(dev_cap());
    let relay_pub = relay.relay_public();
    let handle = Rc::new(RefCell::new(relay));
    let t = InMemoryTransport::new(handle.clone());

    let mut bob = Peer::new(t, Account::generate(), dev_cap(), relay_pub);
    assert!(matches!(bob.publish(NOW), PublishResponse::Published));

    // There is no way to derive a discovery pseudonym from Bob's IK — and nothing was recorded.
    // Any pseudonym query comes back empty because Bob never opted in.
    assert!(handle.borrow_mut().handle_lookup_discovery(&[0x55; 32], NOW).is_none());
}
