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
use relay::node::{InMemoryTransport, Payload, RelayNode, SessionEnvelope};
use karst_client_core::pad;
use karst_client_core::peer::Peer;
use node::pqxdh::{initiate_key_agreement, Account};
use node::ratchet::{Header, RatchetMessage, Session};
use node::seal::Identity;
use x25519_dalek::PublicKey;

const NOW: u64 = 1_000_000;

/// A ratchet plaintext the way the PRODUCT makes one: wrapped in the fixed-size block.
///
/// These tests hand-assemble openers, so they bypass `Peer::encrypt_next` — the one place that
/// pads. Without this they would exercise a plaintext shape no real sender can emit, and the three
/// that check "the genuine opener still works" would fail for a reason unrelated to what they test
/// (PRIV-1). Deliberately calls the SAME function as the product rather than reproducing the layout.
fn padded(plaintext: &[u8]) -> Vec<u8> {
    pad::pad(plaintext).expect("test plaintexts are far under one envelope")
}


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
    let bundle = bob.bundle_with_opk(opk);
    assert_eq!(bob.opk_count(), 1, "control: Bob holds exactly one one-time prekey");

    // An attacker builds a well-formed agreement against that bundle, then claims to be a
    // THIRD party (the victim) and attaches a first ciphertext that cannot decrypt.
    let attacker = Identity::generate();
    let victim_ik = Identity::generate().public.to_bytes();
    let (_root, mut ka) =
        initiate_key_agreement(&attacker, &[9u8; 32], &bundle).expect("well-formed bundle");
    ka.ik_a_pub = victim_ik;
    let garbage = RatchetMessage {
        header: Header { dh: [1u8; 32], pn: 0, n: 0, salt: [7u8; 16] },
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
    let msg = sender.encrypt(&padded(b"genuine first contact"));
    let honest = sealed_to(bob_ik, &ka2, msg);

    let got = bob.open_for_test(&honest).expect("the genuine opener must still be acceptable");
    assert_eq!(got.plaintext, b"genuine first contact");
    assert_eq!(got.sender, real_sender.public.to_bytes(), "attributed to the real sender");
    assert_eq!(bob.opk_count(), 0, "the genuine acceptance consumes the one-time prekey");
}

/// The UNSEALED opener cannot be expressed at all any more (#232 / A3-14).
///
/// It used to be `SessionEnvelope::Initial`, carrying `KeyAgreement.ik_a_pub` — the sender's
/// long-term identity — in the clear, so a relay that wanted the social graph could read every
/// edge straight off the openers. `Peer::process` refused it at runtime; the variant itself was
/// kept so an in-flight capsule from an older client would still open. With no older clients that
/// tolerance was pure downside, and a runtime refusal is a weaker thing than a shape that cannot
/// be constructed — so the variant is gone.
///
/// What is left to test is that the LEGACY BYTES do not become a session. They no longer decode
/// as an opener at all (postcard numbers variants positionally, so the old index now means
/// something else), which is fail-closed rather than a loud refusal — the honest description of
/// what removal buys. The sealed form of the very same agreement is accepted, which pins this to
/// the envelope form rather than to a broken opener.
#[test]
fn the_legacy_unsealed_opener_shape_cannot_become_a_session() {
    let mut bob = bob_peer();
    let opk = bob.add_opks(1)[0];
    let bundle = bob.bundle_with_opk(opk);

    let alice = Identity::generate();
    let (root, ka) = initiate_key_agreement(&alice, &[5u8; 32], &bundle).expect("well-formed bundle");
    let mut sender = Session::init_sender(root, bundle.prekey_pub);
    let msg = sender.encrypt(&padded(b"first contact"));

    // The old wire shape, written by hand: variant index 0 (which `Initial` used to occupy)
    // followed by the agreement and the first ratchet message.
    #[derive(serde::Serialize)]
    enum LegacyEnvelope {
        Initial { ka: node::pqxdh::KeyAgreement, msg: node::ratchet::RatchetMessage },
    }
    let legacy_bytes =
        postcard::to_stdvec(&LegacyEnvelope::Initial { ka: ka.clone(), msg: msg.clone() })
            .expect("legacy shape encodes");
    match postcard::from_bytes::<SessionEnvelope>(&legacy_bytes) {
        Err(_) => {} // refused at the wire boundary
        Ok(env) => {
            // It decoded as SOMETHING (the index now names another variant) — then it must not
            // open, and must not consume the one-time prekey.
            let payload = Payload::Session(env);
            assert!(bob.open_for_test(&payload).is_none(), "legacy opener bytes must not open a session");
        }
    }
    assert_eq!(bob.opk_count(), 1, "nothing about the legacy shape may consume the one-time prekey");

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
    let msg = sender.encrypt(&padded(b"hello"));
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
    let msg2 = sender2.encrypt(&padded(b"hello again"));
    let sealed2 = sealed_to(bundle.ik_pub, &ka2, msg2);
    assert!(bob.open_for_test(&sealed2).is_some(), "a real mailbox point still works");
}

/// CRYPTO-04, THE carrying test. A one-time prekey used to ride unsigned while everything else in
/// the bundle was covered by `prekey_sig`, so a malicious relay could hand the sender an OPK of
/// its OWN making. The sender folded `EK_A × OPK_relay` into the root key believing the fourth DH
/// bought forward secrecy against a later compromise of the long-lived prekey — while the relay
/// knew that DH all along.
///
/// Discriminating: the substituted OPK is a perfectly well-formed X25519 key, correctly signed BY
/// THE RELAY. Only the identity binding tells the two apart, so this cannot pass by rejecting
/// malformed input, and the control below proves a genuine signed OPK still works.
#[test]
fn a_relay_substituted_one_time_prekey_is_refused() {
    let mut bob = bob_peer();
    let opk = bob.add_opks(1)[0];
    let genuine = bob.bundle_with_opk(opk);

    // The relay mints its own one-time prekey and signs it with its own identity — everything a
    // relay can do on its own.
    let mut relay_account = Account::generate();
    let relay_opk = relay_account.add_opk();
    // The whole unit — X25519 half AND the one-time ML-KEM key — minted and signed by the relay,
    // which is exactly what a relay can produce on its own.
    let forged_opk = relay_account.signed_opk(&relay_opk).expect("the relay just minted it");
    let substituted = node::pqxdh::PreKeyBundle { opk: Some(forged_opk), ..genuine.clone() };

    let mut alice = bob_peer();
    assert!(
        alice.connect_with_bundle(&substituted).is_err(),
        "a one-time prekey signed by the RELAY was accepted as the recipient's — the fourth DH \
         would then be a value the relay knows, and the forward secrecy it buys is fiction"
    );

    let mut alice2 = bob_peer();
    assert!(
        alice2.connect_with_bundle(&genuine).is_ok(),
        "control: the recipient's OWN signed one-time prekey is still accepted"
    );
}

/// The other half of CRYPTO-04: a relay can still WITHHOLD every one-time prekey and claim
/// exhaustion, which no signature can distinguish from real exhaustion. Refusing to talk would
/// turn a downgrade into a lockout (and exhaustion is attacker-inducible today, #159), so the
/// agreement proceeds — but it must SAY so rather than quietly return the same `Ok(())` as a
/// full-strength one.
#[test]
fn a_bundle_with_no_one_time_prekey_reports_reduced_forward_secrecy() {
    use karst_client_core::peer::ForwardSecrecy;

    let mut bob = bob_peer();
    let opk = bob.add_opks(1)[0];

    let mut alice = bob_peer();
    assert_eq!(
        alice.connect_with_bundle(&bob.bundle_with_opk(opk)).unwrap(),
        ForwardSecrecy::Full,
        "a bundle carrying a one-time prekey is the 4-DH case"
    );

    // Same bundle, OPK stripped — exactly what a withholding relay serves.
    let mut alice2 = bob_peer();
    assert_eq!(
        alice2.connect_with_bundle(&bob.bundle()).unwrap(),
        ForwardSecrecy::NoOneTimePrekey,
        "a stripped bundle must be reported as reduced, not silently accepted as equivalent"
    );
}
