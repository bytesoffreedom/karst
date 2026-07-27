//! §7 slice 4a — the PUBLIC door: PoW → capability issuance, end to end.
//!
//! What these pin (neuter the mechanism → the named test reddens):
//! - a PoW-earned capability actually opens the door (send is Admitted + delivered);
//! - insufficient work is refused, and a stale bucket is refused *as such* (not as bad PoW);
//! - a replayed redemption re-derives the SAME capability sharing the SAME (exhausted) quota
//!   bucket — one PoW = one quota bucket, permanently, so replay is not free Sybil;
//! - a non-public relay issues nothing;
//! - a PoW capability survives a relay RESTART (stateless — no stored record), which is the
//!   whole reason the door has no table to fill.

use std::cell::RefCell;
use std::rc::Rc;

use admission::params::{EPOCH_DURATION_SECS, POW_WINDOW_SECS};
use admission::pow;
use node::node::{
    Client, InMemoryTransport, JoinRequest, Recipient, RelayNode, Response,
};
use node::seal::Identity;

const NOW: u64 = 1_000_000;
const TEST_BITS: u32 = 8; // cheap PoW for a test (~256 hashes)

/// A Public relay (PoW door armed) with a KNOWN identity, so a "restart" can be simulated by
/// rebuilding a relay from the same key.
fn public_relay(now: u64, id: Identity) -> Rc<RefCell<RelayNode>> {
    let mut relay = RelayNode::with_identity(now, id);
    relay.enable_pow_issue(TEST_BITS);
    Rc::new(RefCell::new(relay))
}

/// Solve the relay's current PoW and redeem it for a capability. Returns the earned cap AND
/// the exact `JoinRequest` (so a test can replay it).
fn earn(relay: &Rc<RefCell<RelayNode>>, seed: [u8; 32], now: u64) -> (admission::capability::Capability, JoinRequest) {
    let (bucket, bits) = relay.borrow().pow_policy(now).expect("relay must be public");
    let relay_id = relay.borrow().relay_public().to_bytes();
    let nonce = pow::solve(&relay_id, bucket, &seed, bits).expect("solvable");
    let jr = JoinRequest { bucket, client_seed: seed, nonce };
    let cap = relay.borrow_mut().handle_join(&jr, now).expect("join should succeed");
    (cap, jr)
}

#[test]
fn a_pow_earned_capability_opens_the_door() {
    let relay = public_relay(NOW, Identity::generate());
    let (cap, _) = earn(&relay, [0x5a; 32], NOW);

    let transport = InMemoryTransport::new(relay.clone());
    let relay_pub = relay.borrow().relay_public();
    let mut alice = Client::new(transport.clone(), cap, b"alice");
    let mut bob = Recipient::new(transport, Identity::generate(), relay_pub);
    let bob_pub = bob.public();

    assert!(
        matches!(alice.send(&bob_pub, b"hi via pow", NOW), Response::Accepted),
        "an earned capability must be admitted"
    );
    let msgs = bob.receive(NOW).expect("fetch");
    assert_eq!(msgs.first().and_then(|m| m.as_deref()), Some(b"hi via pow".as_ref()));
}

#[test]
fn insufficient_proof_of_work_is_refused() {
    let relay = public_relay(NOW, Identity::generate());
    let (bucket, bits) = relay.borrow().pow_policy(NOW).unwrap();
    let relay_id = relay.borrow().relay_public().to_bytes();
    let seed = [1u8; 32];
    // A nonce that does NOT clear the difficulty.
    let bad = (0u64..)
        .find(|&n| !pow::verify(&relay_id, bucket, &seed, n, bits))
        .unwrap();
    let jr = JoinRequest { bucket, client_seed: seed, nonce: bad };
    let err = relay.borrow_mut().handle_join(&jr, NOW).unwrap_err();
    assert!(err.contains("proof-of-work"), "expected a PoW rejection, got: {err}");
}

#[test]
fn a_stale_bucket_is_refused_as_such() {
    // The solution is VALID (right difficulty) but mined for a long-past bucket, so it must
    // be rejected on freshness — not on PoW. Discriminating: if bucket freshness were not
    // checked, this stale-but-valid solution would mint a capability.
    let relay = public_relay(NOW, Identity::generate());
    let relay_id = relay.borrow().relay_public().to_bytes();
    let stale = ((NOW / POW_WINDOW_SECS) as u32).saturating_sub(10);
    let seed = [2u8; 32];
    let nonce = pow::solve(&relay_id, stale, &seed, TEST_BITS).unwrap();
    let jr = JoinRequest { bucket: stale, client_seed: seed, nonce };
    let err = relay.borrow_mut().handle_join(&jr, NOW).unwrap_err();
    assert!(err.contains("bucket"), "expected a bucket-freshness rejection, got: {err}");
}

#[test]
fn a_non_public_relay_issues_nothing() {
    let mut relay = RelayNode::new(NOW); // never enabled the PoW door
    assert!(relay.pow_policy(NOW).is_none(), "a closed relay has no PoW challenge");
    let jr = JoinRequest { bucket: 0, client_seed: [0u8; 32], nonce: 0 };
    let err = relay.handle_join(&jr, NOW).unwrap_err();
    assert!(err.contains("issuance disabled"), "got: {err}");
}

#[test]
fn a_replayed_redemption_shares_one_exhausted_quota_bucket() {
    // The property that makes the door real: one PoW solve buys ONE quota bucket, forever.
    // Redeeming the same solution again must re-derive the identical capability (same id AND
    // secret) sharing the SAME quota — not mint a fresh capability with fresh quota (which
    // would be free Sybil). Id-equality alone would pass even a fresh-quota bug, so this
    // EXHAUSTS the quota first and asserts the replayed cap is already spent.
    let relay = public_relay(NOW, Identity::generate());
    let (cap, jr) = earn(&relay, [0x11; 32], NOW);

    let transport = InMemoryTransport::new(relay.clone());
    let bob = Identity::generate();
    let bob_pub = bob.public;
    let mut alice = Client::new(transport.clone(), cap.clone(), b"alice");

    // Spend the whole per-capability quota (POW_CAP_QUOTA.max_requests).
    let mut admitted = 0u32;
    loop {
        match alice.send(&bob_pub, b"x", NOW) {
            Response::Accepted => {
                admitted += 1;
                assert!(admitted <= 1000, "quota never exhausted — is it enforced?");
            }
            Response::Rejected(r) => {
                assert!(r.contains("CapabilityQuota"), "expected quota exhaustion, got: {r}");
                break;
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
    assert_eq!(admitted, admission::capability::POW_CAP_QUOTA.max_requests);

    // Replay the SAME redemption.
    let cap2 = relay.borrow_mut().handle_join(&jr, NOW).expect("replay join");
    assert_eq!(cap2.capability_id, cap.capability_id, "replay must re-derive the same id");
    assert_eq!(cap2.secret, cap.secret, "replay must re-derive the same secret");

    // The replayed capability shares the already-spent bucket, so a send with it is REFUSED
    // (either as an over-quota `CapabilityQuota`, or — since it re-derives the same secret —
    // as a verbatim `Replay` of a proof already in that window; both mean "the shared bucket
    // rejected it"). The discriminator is Accepted-vs-not: a FRESH-quota bug would mint a new
    // id → an empty window → `Accepted`. That is the failure this guards.
    let mut mallory = Client::new(transport, cap2, b"mallory");
    match mallory.send(&bob_pub, b"y", NOW) {
        Response::Rejected(r) => assert!(
            r.contains("CapabilityQuota") || r.contains("Replay"),
            "expected the shared bucket to refuse the replayed cap, got: {r}"
        ),
        other => panic!("a replayed redemption minted fresh quota — the door leaks: {other:?}"),
    }
}

#[test]
fn idle_quota_windows_are_reaped_so_the_door_cannot_be_memory_flooded() {
    // On a Public relay every PoW solve mints a DISTINCT cap_id, so the quota map would grow
    // by one permanent entry per solve — an unbounded-memory DoS on the door — unless the
    // periodic reap runs. Mint several caps, spend one request each, then trigger an
    // epoch advance well past the quota window and assert the idle windows are gone.
    // Discriminating: remove the `cap_quota.reap(..)` call in `advance_epoch` and the final
    // assert reddens (5 windows persist forever).
    let relay = public_relay(NOW, Identity::generate());
    let transport = InMemoryTransport::new(relay.clone());
    let bob = Identity::generate();
    let bob_pub = bob.public;

    for i in 0..5u8 {
        let (cap, _) = earn(&relay, [i; 32], NOW);
        let mut c = Client::new(transport.clone(), cap, b"c");
        assert!(matches!(c.send(&bob_pub, b"x", NOW), Response::Accepted));
    }
    assert_eq!(relay.borrow().cap_quota_windows_for_test(), 5, "each cap has its own window");

    // A fetch far past the window advances the epoch → reap. Fetch is not capability-gated,
    // so it adds no new window; the 5 idle ones must be dropped.
    let relay_pub = relay.borrow().relay_public();
    let mut bobr = Recipient::new(transport, bob, relay_pub);
    let _ = bobr.receive(NOW + 2 * EPOCH_DURATION_SECS);
    assert_eq!(
        relay.borrow().cap_quota_windows_for_test(),
        0,
        "idle quota windows must be reaped (else the public door leaks memory per solve)"
    );
}

#[test]
fn the_owner_can_toggle_the_door_off_open_and_on_at_runtime() {
    // Early on there may be no spam to gate, so the owner runs the door OPEN (no PoW), then
    // turns PoW on later — or off entirely. Toggling issuance OFF must NOT break capabilities
    // already earned (the verifier stays armed). Discriminating: `set_pow_issue(None)` must
    // stop NEW issuance yet leave outstanding caps working, and `Some(0)` must issue freely.
    let relay = public_relay(NOW, Identity::generate()); // starts PoW-gated at TEST_BITS
    let (cap, _) = earn(&relay, [0xaa; 32], NOW);

    // OFF: no new caps handed out...
    relay.borrow_mut().set_pow_issue(None);
    assert!(relay.borrow().pow_policy(NOW).is_none(), "issuance off → no challenge");
    assert!(
        relay
            .borrow_mut()
            .handle_join(&JoinRequest { bucket: 0, client_seed: [0u8; 32], nonce: 0 }, NOW)
            .is_err(),
        "issuance off → handle_join refuses"
    );
    // ...but the capability earned earlier still opens the door.
    let transport = InMemoryTransport::new(relay.clone());
    let relay_pub = relay.borrow().relay_public();
    let mut alice = Client::new(transport.clone(), cap, b"alice");
    let mut bob = Recipient::new(transport.clone(), Identity::generate(), relay_pub);
    let bob_pub = bob.public();
    assert!(
        matches!(alice.send(&bob_pub, b"still works", NOW), Response::Accepted),
        "a cap earned before issuance was turned off must keep working"
    );
    assert_eq!(
        bob.receive(NOW).unwrap().into_iter().flatten().next(),
        Some(b"still works".to_vec())
    );

    // OPEN: issue without proof-of-work — a join with a trivial (zero) nonce succeeds.
    relay.borrow_mut().set_pow_issue(Some(0));
    let (bucket, bits) = relay.borrow().pow_policy(NOW).expect("open door issues");
    assert_eq!(bits, 0, "open door advertises difficulty 0");
    let open_cap = relay
        .borrow_mut()
        .handle_join(&JoinRequest { bucket, client_seed: [0xbb; 32], nonce: 0 }, NOW)
        .expect("an open door issues without real work");
    let mut carol = Client::new(transport, open_cap, b"carol");
    assert!(
        matches!(carol.send(&bob_pub, b"open door", NOW), Response::Accepted),
        "a freely-earned (open-door) cap must open the door"
    );
}

#[test]
fn a_pow_capability_survives_a_relay_restart() {
    // Stateless issuance: the relay stores NO record of a PoW capability, so a restart (a
    // fresh RelayNode from the SAME persistent key) must still honour a capability it issued
    // before. Discriminating: if PoW caps were table-stored, the restarted relay would have
    // an empty table and reject — this is the property that makes the Public door immune to
    // a table-filling DoS and to a re-solve storm on restart.
    let id = Identity::generate();
    let (cap, _) = earn(&public_relay(NOW, id.clone()), [0x77; 32], NOW);

    // Brand-new relay, same key, no shared state whatsoever.
    let relay2 = public_relay(NOW, id);
    let transport = InMemoryTransport::new(relay2.clone());
    let relay_pub = relay2.borrow().relay_public();
    let mut alice = Client::new(transport.clone(), cap, b"alice");
    let bob = Recipient::new(transport, Identity::generate(), relay_pub);
    let bob_pub = bob.public();

    assert!(
        matches!(alice.send(&bob_pub, b"after restart", NOW), Response::Accepted),
        "a PoW capability must survive a restart (stateless — no stored record)"
    );
}
