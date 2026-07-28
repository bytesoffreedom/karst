//! CRYPTO-03 — an initial opener must not change durable state until its first AEAD verifies.
//!
//! `accept_key_agreement` derives the root key and CONSUMES the one-time prekey, and `process`
//! used to insert the new `SessionState` regardless of whether the attached ratchet message
//! decrypted. Anyone can fetch a public prekey bundle, so a remote party could assemble a
//! structurally valid `KeyAgreement`, put ANY victim's identity key in `ik_a_pub`, attach a bogus
//! first ciphertext, and make the recipient (a) burn a one-time prekey and (b) persist a dead
//! session under that victim's IK. No key is learned — this is not impersonation — but with no
//! prior session the poisoned state becomes the PRIMARY outbound session, so the victim's later
//! genuine opener lands in the secondary map while replies keep going to the dead chain. It
//! survives restarts and needs an explicit forget/reconnect to clear.

use std::cell::RefCell;
use std::rc::Rc;

use admission::capability::{Capability, Quota, Scope};
use node::node::{InMemoryTransport, Payload, RelayNode, SessionEnvelope};
use node::peer::Peer;
use node::pqxdh::{initiate_key_agreement, Account};
use node::ratchet::{Header, RatchetMessage, Session};
use node::seal::Identity;
use x25519_dalek::PublicKey;

const NOW: u64 = 1_000_000;

fn dev_cap() -> Capability {
    Capability {
        capability_id: [0xCA; 16],
        scope: Scope::MessageDelivery,
        quota: Quota { max_requests: 10_000, max_bytes: 1 << 30, window_secs: 600 },
        not_before: 0,
        not_after: u32::MAX,
        secret: [0x33; 32],
    }
}

/// A `Peer` for Bob over an in-memory relay — this test never sends over the wire, it feeds
/// payloads straight into `process` (via `open_for_test`), which is exactly the code path a
/// fetched envelope takes.
fn sealed_to(recipient_ik: [u8; 32], ka: &node::pqxdh::KeyAgreement, msg: RatchetMessage) -> Payload {
    let plain = postcard::to_stdvec(ka).unwrap();
    let sealed_ka = node::seal::SkeletonSeal::seal(&PublicKey::from(recipient_ik), &plain);
    Payload::Session(SessionEnvelope::InitialSealed { sealed_ka, msg })
}

fn bob_peer() -> Peer<InMemoryTransport> {
    let relay = Rc::new(RefCell::new(RelayNode::new(NOW)));
    relay.borrow_mut().issue_capability(dev_cap());
    let relay_pub = relay.borrow().relay_public();
    Peer::new(InMemoryTransport::new(relay), Account::generate(), dev_cap(), relay_pub)
}

#[test]
fn a_forged_opener_neither_creates_a_session_nor_burns_a_one_time_prekey() {
    let mut bob = bob_peer();

    // Bob publishes a bundle carrying ONE one-time prekey.
    let opk = bob.add_opks(1)[0];
    let mut bundle = bob.bundle();
    bundle.opk_pub = Some(opk);
    assert_eq!(bob.opk_count(), 1, "control: Bob holds exactly one one-time prekey");

    // An attacker builds a well-formed agreement against that bundle, then claims to be a
    // THIRD party (the victim) and attaches a first ciphertext that cannot decrypt.
    let attacker = Identity::generate();
    let victim_ik = Identity::generate().public.to_bytes();
    let (_root, mut ka) =
        initiate_key_agreement(&attacker, &[9u8; 32], &bundle).expect("well-formed bundle");
    ka.ik_a_pub = victim_ik;
    let garbage = RatchetMessage {
        header: Header { dh: [1u8; 32], pn: 0, n: 0 },
        ciphertext: vec![7u8; 48],
    };
    // SEALED, so the refusal below is about authentication — not about the envelope form.
    let bob_ik = bob.bundle().ik_pub;
    let forged = sealed_to(bob_ik, &ka, garbage);

    assert!(bob.open_for_test(&forged).is_none(), "a bogus opener delivers nothing");
    assert!(
        !bob.has_session(&victim_ik),
        "a failed opener must not leave a session under the claimed identity"
    );
    assert_eq!(
        bob.opk_count(),
        1,
        "a failed opener must not consume the one-time prekey"
    );

    // Decisive: because the OPK survived, a GENUINE opener using that same bundle still works.
    // Before the fix the attacker's attempt had already consumed it, so this agreement could no
    // longer be accepted — the silent first-contact loss the one-time prekey exists to prevent.
    let real_sender = Identity::generate();
    let (root, ka2) =
        initiate_key_agreement(&real_sender, &[3u8; 32], &bundle).expect("well-formed bundle");
    let mut sender = Session::init_sender(root, bundle.prekey_pub);
    let msg = sender.encrypt(b"genuine first contact");
    let honest = sealed_to(bob_ik, &ka2, msg);

    let got = bob.open_for_test(&honest).expect("the genuine opener must still be acceptable");
    assert_eq!(got.plaintext, b"genuine first contact");
    assert_eq!(got.sender, real_sender.public.to_bytes(), "attributed to the real sender");
    assert_eq!(bob.opk_count(), 0, "the genuine acceptance consumes the one-time prekey");
}

/// The UNSEALED opener is refused on the wire.
///
/// `SessionEnvelope::Initial` carries the sender's identity key in the clear, so a relay can read
/// the social-graph edge straight off it — the exact leak `InitialSealed` was introduced to close.
/// The variant was kept only so an in-flight capsule from an older client would still open; with
/// no older clients that tolerance is pure downside, because ANY peer could send the legacy form
/// and silently downgrade a conversation's metadata privacy without the recipient noticing.
///
/// Discriminating: the very same agreement is accepted when SEALED, so this pins the refusal to
/// the envelope form rather than to a broken opener.
#[test]
fn an_unsealed_opener_is_refused_but_the_sealed_form_of_it_works() {
    let mut bob = bob_peer();
    let opk = bob.add_opks(1)[0];
    let mut bundle = bob.bundle();
    bundle.opk_pub = Some(opk);

    let alice = Identity::generate();
    let (root, ka) = initiate_key_agreement(&alice, &[5u8; 32], &bundle).expect("well-formed bundle");
    let mut sender = Session::init_sender(root, bundle.prekey_pub);
    let msg = sender.encrypt(b"first contact");

    // Legacy form: identical contents, unsealed → refused, and nothing is consumed.
    let legacy = Payload::Session(SessionEnvelope::Initial { ka: ka.clone(), msg: msg.clone() });
    assert!(bob.open_for_test(&legacy).is_none(), "an unsealed opener must not be accepted");
    assert_eq!(bob.opk_count(), 1, "a refused envelope must not consume the one-time prekey");

    // Sealed form of the SAME agreement: accepted.
    let sealed = sealed_to(bob.bundle().ik_pub, &ka, msg);
    let got = bob.open_for_test(&sealed).expect("the sealed form of the same opener must work");
    assert_eq!(got.plaintext, b"first contact");
    assert_eq!(got.sender, alice.public.to_bytes());
}

/// A degenerate mailbox point must not enter a session — from either direction.
///
/// The all-zero encoding is the Ristretto IDENTITY point, and `h·identity == identity` for every
/// blinding factor, so every sender would derive the SAME "drop box" and nobody could prove
/// ownership of it. It used to be the `serde(default)` for pre-mailbox bundles, which is why a
/// downstream guard had to catch it at SEND time — after it had already been stored in a session.
/// Its owner can sign it perfectly well, so the signature check does not cover this.
#[test]
fn a_degenerate_mailbox_point_is_refused_on_both_sides() {
    // ACCEPT side: an opener whose sender advertises the identity point.
    let mut bob = bob_peer();
    let bundle = bob.bundle();
    let alice = Identity::generate();
    let (root, mut ka) =
        initiate_key_agreement(&alice, &[0u8; 32], &bundle).expect("well-formed bundle");
    assert_eq!(ka.mailbox_a_pub, [0u8; 32], "the sender advertised the degenerate point");
    let mut sender = Session::init_sender(root, bundle.prekey_pub);
    let msg = sender.encrypt(b"hello");
    let sealed = sealed_to(bundle.ik_pub, &ka, msg);
    assert!(bob.open_for_test(&sealed).is_none(), "a degenerate sender mailbox must be refused");
    assert!(!bob.has_session(&alice.public.to_bytes()), "and must leave no session");

    // Control: the same opener with a real mailbox point is accepted, so the refusal is about
    // the degenerate value and not about the opener.
    let alice_m = node::blind::MailboxSecret::generate().public();
    let (root2, ka2) =
        initiate_key_agreement(&alice, &alice_m, &bundle).expect("well-formed bundle");
    ka.mailbox_a_pub = alice_m;
    let _ = &ka2;
    let mut sender2 = Session::init_sender(root2, bundle.prekey_pub);
    let msg2 = sender2.encrypt(b"hello again");
    let sealed2 = sealed_to(bundle.ik_pub, &ka2, msg2);
    assert!(bob.open_for_test(&sealed2).is_some(), "a real mailbox point still works");
}
