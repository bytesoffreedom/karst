//! §2.1 PQXDH — состязательные тесты СОГЛАСОВАНИЯ КЛЮЧА. Несущие свойства:
//! - **согласование**: инициатор и получатель выводят ОДИН root_key;
//! - **аутентификация отправителя**: подмена IK_A → у получателя ДРУГОЙ root_key
//!   (форжер без приватного IK Alice не согласует тот же ключ);
//! - **PQ-нога нагружена**: битый ML-KEM-ct → другой pq_shared → другой root_key;
//! - слой ортогонален: чужой получатель выводит другой root_key.
//!
//! Проверяем именно РАЗЛИЧИЕ root_key (а не decrypt-провал): шифрование ушло в
//! ratchet, pqxdh отвечает только за согласование. Несовпадение root_key →
//! первое ratchet-сообщение не расшифруется (см. состязательные тесты сессии).

use node::pqxdh::{initiate_key_agreement, Account};
use node::seal::Identity;

#[test]
fn initiator_and_recipient_agree_on_root_key() {
    let mut bob = Account::generate();
    let bundle = bob.prekey_bundle();
    let alice = Identity::generate();

    let (alice_rk, ka) = initiate_key_agreement(&alice, &[7u8; 32], &bundle).expect("well-formed bundle");
    let (bob_rk, sender) = bob.accept_key_agreement(&ka).expect("валидная длина KEM-ct");
    assert_eq!(alice_rk, bob_rk, "инициатор и получатель должны согласовать один root_key");
    assert_eq!(sender, alice.public.to_bytes(), "Bob узнаёт отправителя по заявленному IK");
}

#[test]
fn cannot_impersonate_alice_without_her_identity_key() {
    // Несущее (sender-auth): Mallory знает pubkey Alice (публичен), но НЕ её
    // приватный IK. Заявив IK Alice, она НЕ согласует тот же root_key, что
    // получил бы Bob — DH1 сделан ключом Mallory.
    let mut bob = Account::generate();
    let bundle = bob.prekey_bundle();
    let alice = Identity::generate();
    let mallory = Identity::generate();

    // Честная установка от Mallory: обе стороны согласуют ключ, Bob видит Mallory.
    let (mallory_rk, honest) =
        initiate_key_agreement(&mallory, &[7u8; 32], &bundle).expect("well-formed bundle");
    let (bob_rk, sender) = bob.accept_key_agreement(&honest).unwrap();
    assert_eq!(mallory_rk, bob_rk);
    assert_eq!(sender, mallory.public.to_bytes());

    // Подделка: заявить IK Alice, не имея её приватного ключа.
    let mut forged = honest.clone();
    forged.ik_a_pub = alice.public.to_bytes();
    let (forged_bob_rk, _) = bob.accept_key_agreement(&forged).unwrap();
    assert_ne!(
        forged_bob_rk, mallory_rk,
        "нельзя выдать себя за Alice: root_key получателя разойдётся с ключом форжера"
    );
}

#[test]
fn corrupt_kem_ciphertext_breaks_agreement() {
    // PQ-нога нагружена end-to-end: порча ML-KEM-ct → другой pq_shared у
    // получателя → root_key не совпадёт с ключом инициатора.
    let mut bob = Account::generate();
    let bundle = bob.prekey_bundle();
    let alice = Identity::generate();

    let (alice_rk, mut ka) = initiate_key_agreement(&alice, &[7u8; 32], &bundle).expect("well-formed bundle");
    ka.kem_ct[0] ^= 0x01;
    let (bob_rk, _) = bob.accept_key_agreement(&ka).expect("длина сохранена, decaps даёт значение");
    assert_ne!(alice_rk, bob_rk, "битый KEM-ct должен ломать согласование");
}

#[test]
fn malformed_kem_ciphertext_length_rejected() {
    // Структурная защита: KEM-ct неверной ДЛИНЫ отвергается (None), а не паникует.
    let mut bob = Account::generate();
    let bundle = bob.prekey_bundle();
    let alice = Identity::generate();

    let (_alice_rk, mut ka) = initiate_key_agreement(&alice, &[7u8; 32], &bundle).expect("well-formed bundle");
    ka.kem_ct.truncate(10);
    assert!(bob.accept_key_agreement(&ka).is_none(), "KEM-ct кривой длины → None");
}

/// CRYPTO-06 — a bundle advertising a small-order prekey must be REFUSED. X25519 against the
/// identity point yields an all-zero shared secret that the attacker also knows, so folding it
/// in would silently drop a whole DH leg's contribution. Note the bundle SIGNATURE says nothing
/// about a key's order, so this check is the only thing standing between a malicious contact's
/// degenerate key and the agreement.
#[test]
fn a_small_order_prekey_in_a_bundle_is_refused() {
    let bob = Account::generate();
    let alice = Identity::generate();

    let good = bob.prekey_bundle();
    assert!(
        initiate_key_agreement(&alice, &[7u8; 32], &good).is_ok(),
        "control: a healthy bundle agrees"
    );

    let mut degenerate = good.clone();
    degenerate.prekey_pub = [0u8; 32];
    assert!(
        initiate_key_agreement(&alice, &[7u8; 32], &degenerate).is_err(),
        "a small-order prekey must be refused"
    );

    // Signed BY ITS OWNER and still small-order: "signed" says nothing about group order, which
    // is exactly why the contributory check is separate from the signature check.
    let degenerate_opk = bob.prekey_bundle_with_opk([0u8; 32]);
    assert!(
        initiate_key_agreement(&alice, &[7u8; 32], &degenerate_opk).is_err(),
        "a small-order one-time prekey must be refused too"
    );
}

/// The mirror on the RECIPIENT's side: an initial agreement carrying a small-order ephemeral is
/// refused instead of deriving a root key from an all-zero DH.
#[test]
fn a_small_order_ephemeral_is_refused_on_accept() {
    let mut bob = Account::generate();
    let alice = Identity::generate();
    let (_rk, mut ka) =
        initiate_key_agreement(&alice, &[7u8; 32], &bob.prekey_bundle()).expect("well-formed bundle");
    ka.ek_a_pub = [0u8; 32];
    assert!(
        bob.accept_key_agreement(&ka).is_none(),
        "a non-contributory ephemeral must be refused on accept"
    );
}

#[test]
fn wrong_recipient_derives_different_key() {
    // Согласование адресовано bob'у (его bundle); другой аккаунт выведет другой
    // root_key — ни его prekey/IK, ни его ML-KEM-ключ не подходят.
    let mut bob = Account::generate();
    let mut eve = Account::generate();
    let bundle = bob.prekey_bundle();
    let alice = Identity::generate();

    let (alice_rk, ka) = initiate_key_agreement(&alice, &[7u8; 32], &bundle).expect("well-formed bundle");
    let (bob_rk, _) = bob.accept_key_agreement(&ka).unwrap();
    let (eve_rk, _) = eve.accept_key_agreement(&ka).unwrap();
    assert_eq!(alice_rk, bob_rk, "адресат согласует тот же ключ");
    assert_ne!(alice_rk, eve_rk, "чужой получатель выводит другой root_key");
}

/// A one-time prekey adds a fourth DH term to the agreement, both sides derive the same
/// root key with it, and the recipient CONSUMES it — a second agreement reusing the same
/// OPK fails. This is the forward-secrecy mechanism: the OPK secret is gone after one use.
#[test]
fn a_one_time_prekey_is_mixed_in_and_consumed_once() {
    let alice = node::seal::Identity::generate();
    let mut bob = Account::generate();

    // Bob mints a one-time prekey and publishes a bundle carrying it.
    let opk = bob.add_opk();
    assert_eq!(bob.opk_count(), 1);
    let bundle = bob.prekey_bundle_with_opk(opk);

    // Alice initiates against the OPK bundle; the KA records which OPK she used.
    let (alice_rk, ka) = initiate_key_agreement(&alice, &[7u8; 32], &bundle).expect("well-formed bundle");
    assert_eq!(ka.opk_pub, Some(opk), "the KA must name the OPK the sender used");

    // The root key differs from the SAME agreement without the OPK — proof the 4th DH is
    // load-bearing, not decorative.
    let (alice_rk_no_opk, _) =
        initiate_key_agreement(&alice, &[7u8; 32], &bob.prekey_bundle()).expect("well-formed bundle");
    assert_ne!(alice_rk, alice_rk_no_opk, "the one-time prekey did not affect the root key");

    // Bob accepts, derives the same key, and consumes the OPK.
    let (bob_rk, sender) = bob.accept_key_agreement(&ka).expect("agreement with OPK");
    assert_eq!(alice_rk, bob_rk, "sender and recipient disagree on the OPK root key");
    assert_eq!(sender, alice.public.to_bytes());
    assert_eq!(bob.opk_count(), 0, "the one-time prekey was not consumed");

    // Replaying the SAME KA (same OPK) must now FAIL — the OPK is gone, so it is truly
    // one-time. Neuter the `self.opks.remove(...)` consumption and this reddens.
    assert!(bob.accept_key_agreement(&ka).is_none(), "a consumed one-time prekey was reused");
}
