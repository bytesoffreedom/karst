//! §2.1 Double Ratchet — состязательные чёрноящичные тесты. Несущие свойства
//! ratchet, не happy-path ради галочки:
//! - двусторонний ping-pong с DH-шагами (обе стороны продвигают ratchet);
//! - **транзакционность**: битый пакет отвергается И следующий валидный
//!   расшифровывается (сессия не «заклинена» — критично для ratchet);
//! - **out-of-order терпимость** (skipped-keys): пропуск/reorder в цепочке и на
//!   границе цепочек догоняется, replay потреблённого — отвергается;
//! - **header-binding**: подмена dh/pn/n в заголовке ловится AEAD-AAD.
//!
//! (Дискриминирующие white-box FS-non-retention и PCS-нагруженность DH — в
//! `#[cfg(test)]` самого модуля `ratchet`, где доступны приватные поля.)

use node::ratchet::{RatchetError, RatchetMessage, Session, SessionSnapshot};
use node::seal::Identity;

/// Установить пару сессий из общего root_key (как даст PQXDH: root_key + prekey
/// Bob'а — его ratchet-ключ). Bob засевается своим prekey, Alice — его pubkey.
fn establish() -> (Session, Session) {
    let root = [42u8; 32];
    let bob_prekey = Identity::generate();
    let alice = Session::init_sender(root, bob_prekey.public.to_bytes());
    let bob = Session::init_receiver(root, bob_prekey);
    (alice, bob)
}

#[test]
fn bidirectional_ping_pong_with_dh_ratchet() {
    let (mut alice, mut bob) = establish();

    // Alice → Bob (первое сообщение запускает DH-шаг у Bob, даёт ему send-цепочку).
    let m1 = alice.encrypt(b"hi bob");
    assert_eq!(bob.decrypt(&m1).unwrap(), b"hi bob");

    // Bob → Alice (Bob теперь на новом ratchet-ключе; Alice делает DH-шаг).
    let m2 = bob.encrypt(b"hi alice");
    assert_eq!(alice.decrypt(&m2).unwrap(), b"hi alice");

    // Несколько подряд в одной цепочке.
    let a1 = alice.encrypt(b"a1");
    let a2 = alice.encrypt(b"a2");
    assert_eq!(bob.decrypt(&a1).unwrap(), b"a1");
    assert_eq!(bob.decrypt(&a2).unwrap(), b"a2");

    // Полный разворот направления снова.
    let b1 = bob.encrypt(b"b1");
    assert_eq!(alice.decrypt(&b1).unwrap(), b"b1");
}

#[test]
fn distinct_key_per_message() {
    // Базовая проверка (НЕ FS — FS это non-retention в module-тестах): каждое
    // сообщение шифруется своим ключом → шифртексты разные при одном plaintext.
    let (mut alice, mut bob) = establish();
    let m1 = alice.encrypt(b"same");
    let m2 = alice.encrypt(b"same");
    assert_ne!(m1.ciphertext, m2.ciphertext, "цепочка должна давать разный ключ на сообщение");
    assert_eq!(bob.decrypt(&m1).unwrap(), b"same");
    assert_eq!(bob.decrypt(&m2).unwrap(), b"same");
}

#[test]
fn tampered_message_rejected_and_session_survives() {
    // ТРАНЗАКЦИОННОСТЬ — ratchet-специфичный «нельзя заклинить»: битый пакет
    // отвергается, но НЕ двигает/ломает цепочку — следующий валидный проходит.
    let (mut alice, mut bob) = establish();

    let good0 = alice.encrypt(b"zero");
    assert_eq!(bob.decrypt(&good0).unwrap(), b"zero");

    let m1 = alice.encrypt(b"one");
    let mut bad = m1.clone();
    bad.ciphertext[0] ^= 0x01;
    assert_eq!(bob.decrypt(&bad), Err(RatchetError::Decrypt), "битый шифртекст отвергнут");

    // Сессия НЕ заклинена: исходный валидный m1 (n=1) всё ещё расшифровывается.
    assert_eq!(bob.decrypt(&m1).unwrap(), b"one", "битый пакет не должен ломать сессию");
}

#[test]
fn header_tampering_is_caught() {
    // Заголовок связан в AAD: подмена номера/pn/dh → AEAD не сойдётся.
    let (mut alice, mut bob) = establish();
    let m = alice.encrypt(b"payload");

    let mut tn = m.clone();
    tn.header.n ^= 0x01;
    assert!(bob.decrypt(&tn).is_err(), "подмена n в заголовке должна ловиться");

    let mut tp = m.clone();
    tp.header.pn ^= 0x01;
    assert!(bob.decrypt(&tp).is_err(), "подмена pn в заголовке должна ловиться");

    let mut td = m.clone();
    td.header.dh[0] ^= 0x01;
    assert!(bob.decrypt(&td).is_err(), "подмена ratchet-pubkey в заголовке должна ловиться");

    // Оригинал всё ещё проходит (транзакционность — отказы не сдвинули цепочку).
    assert_eq!(bob.decrypt(&m).unwrap(), b"payload");
}

#[test]
fn out_of_order_within_chain_is_tolerated() {
    // Out-of-order В ОДНОЙ цепочке ТЕРПИМ (skipped-keys): пропущенный номер
    // сохраняется, догнавшее сообщение расшифровывается. Именно то, что даёт
    // mailbox-пачка. Раньше m2 после m0 → OutOfOrder; теперь проходит.
    let (mut alice, mut bob) = establish();

    let m0 = alice.encrypt(b"m0"); // n=0
    let m1 = alice.encrypt(b"m1"); // n=1 — доставим ПОСЛЕ m2
    let m2 = alice.encrypt(b"m2"); // n=2

    assert_eq!(bob.decrypt(&m0).unwrap(), b"m0");
    assert_eq!(bob.decrypt(&m2).unwrap(), b"m2", "пропуск n=1 → ключ сохранён, m2 проходит");
    assert_eq!(bob.decrypt(&m1).unwrap(), b"m1", "догнавший m1 — из skipped-store");
    // Повтор уже ПОТРЕБЛЁННОГО пропущенного — отвергнут (ключ удалён при потреблении).
    assert!(bob.decrypt(&m1).is_err(), "replay потреблённого сообщения отвергается");
}

#[test]
fn reorder_across_ratchet_boundary_is_tolerated() {
    // Пропуск на ГРАНИЦЕ цепочек (mailbox-пачка / DTN-reorder) ТЕРПИМ: хвост
    // цепочки A сохраняется при DH-шаге и расшифровывается после сообщения из
    // цепочки B. Раньше отвергалось; теперь догоняется без потери.
    let (mut alice, mut bob) = establish();

    let m0 = alice.encrypt(b"m0"); // chain A, n=0
    let m1 = alice.encrypt(b"m1"); // chain A, n=1 — доставим ПОСЛЕ разворота
    assert_eq!(bob.decrypt(&m0).unwrap(), b"m0"); // bob.nr = 1

    // Разворот направления → Alice делает DH-шаг на следующей отправке.
    let r0 = bob.encrypt(b"r0");
    assert_eq!(alice.decrypt(&r0).unwrap(), b"r0");

    let m2 = alice.encrypt(b"m2"); // chain B, pn=2 (в A было 2), n=0
    assert_eq!(bob.decrypt(&m2).unwrap(), b"m2", "сообщение из новой цепочки проходит");
    // Догнавший хвост цепочки A — из сохранённого при DH-шаге.
    assert_eq!(bob.decrypt(&m1).unwrap(), b"m1", "непринятый хвост A догоняется, не теряется");
}

#[test]
fn replay_of_consumed_message_rejected() {
    // Повтор уже принятого ПО ПОРЯДКУ сообщения: ключ израсходован и не хранится
    // (не был пропущенным) → расшифровать нечем → отказ. Replay-защита цела.
    let (mut alice, mut bob) = establish();
    let m0 = alice.encrypt(b"m0");
    assert_eq!(bob.decrypt(&m0).unwrap(), b"m0");
    assert!(bob.decrypt(&m0).is_err(), "повтор n=0 отвергается (ключ израсходован)");
}

#[test]
fn populated_skipped_store_survives_postcard_roundtrip() {
    // Airtight-версия load-bearing: пропущенный ключ переживает ТУ ЖЕ postcard-
    // сериализацию, что клиент гоняет в save_sessions/load_sessions (не только
    // in-memory snapshot/restore). Догнавший gap-filler расшифровывается после
    // круга через байты.
    let (mut alice, mut bob) = establish();
    let m0 = alice.encrypt(b"m0");
    let m1 = alice.encrypt(b"m1"); // будет задержан → сохранён в store
    let m2 = alice.encrypt(b"m2");
    assert_eq!(bob.decrypt(&m0).unwrap(), b"m0");
    assert_eq!(bob.decrypt(&m2).unwrap(), b"m2"); // m1 в skipped-store

    // Круг через postcard (как PersistedSession у клиента).
    let bytes = postcard::to_allocvec(&bob.snapshot()).unwrap();
    let snap: SessionSnapshot = postcard::from_bytes(&bytes).unwrap();
    let mut bob2 = Session::restore(snap);

    assert_eq!(bob2.decrypt(&m1).unwrap(), b"m1", "gap-filler из store, пережившего байты");
}

/// CRYPTO-06 — a small-order ratchet key must be REFUSED, not folded into the DH step. Its
/// shared secret is all-zero, i.e. known to the attacker, so the "healing" step would inject no
/// fresh entropy and silently void post-compromise security. Discriminating on BOTH sides: the
/// poisoned header must be rejected, AND the session must be left untouched (a guard that
/// wedged the session would be its own bug), so the next genuine message still decrypts.
#[test]
fn a_small_order_ratchet_key_is_refused_without_wedging_the_session() {
    let (mut alice, mut bob) = establish();
    let m1 = alice.encrypt(b"one");
    assert_eq!(bob.decrypt(&m1).unwrap(), b"one", "control: normal traffic flows");

    // The identity point is the canonical small-order X25519 key: X25519(x, 0) == 0 for any x.
    let mut poisoned = alice.encrypt(b"two");
    poisoned.header.dh = [0u8; 32];
    assert_eq!(
        bob.decrypt(&poisoned),
        Err(RatchetError::NonContributoryDh),
        "a non-contributory ratchet key must be rejected, not ratcheted on"
    );

    // Session untouched → a later genuine message from the real chain still opens.
    let m3 = alice.encrypt(b"three");
    assert_eq!(bob.decrypt(&m3).unwrap(), b"three", "the rejection must not wedge the session");
}

#[test]
fn cross_message_serialization_roundtrip() {
    // Сообщение переживает сериализацию (пойдёт в wire/mailbox позже).
    let (mut alice, mut bob) = establish();
    let m = alice.encrypt(b"over the wire");
    let bytes = postcard::to_allocvec(&m).unwrap();
    let decoded: RatchetMessage = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(bob.decrypt(&decoded).unwrap(), b"over the wire");
}

/// A6-9 — skipped message keys must age out, not merely be capped in number.
///
/// They were bounded by `MAX_STORE` alone, so a key derived for a message that never arrived
/// could sit at rest indefinitely, widening the window in which a device compromise yields
/// plaintext. Age is counted in DH-ratchet GENERATIONS rather than wall-clock, because the local
/// clock is an unauthenticated input and "several chains ago" is the protocol's own measure of
/// staleness. Discriminating: a genuinely late message from the CURRENT era still opens.
#[test]
fn skipped_keys_expire_after_several_ratchet_generations() {
    let (mut alice, mut bob) = establish();

    // Alice sends two; Bob receives only the SECOND, so a gap-filler key is stored.
    let m1 = alice.encrypt(b"gap");
    let m2 = alice.encrypt(b"seen");
    assert_eq!(bob.decrypt(&m2).unwrap(), b"seen");

    // The still-fresh gap-filler works — the expiry must not eat live out-of-order mail.
    let mut bob_fresh = bob.clone();
    assert_eq!(bob_fresh.decrypt(&m1).unwrap(), b"gap", "a recent skipped key must still open");

    // Now run the conversation forward through several DH steps (each reply from Bob and the
    // next message from Alice advances the ratchet).
    for i in 0..6 {
        let r = bob.encrypt(format!("r{i}").as_bytes());
        assert!(alice.decrypt(&r).is_ok());
        let a = alice.encrypt(format!("a{i}").as_bytes());
        assert!(bob.decrypt(&a).is_ok());
    }

    // The ancient gap-filler is gone: it belongs to a chain many generations back.
    assert!(
        bob.decrypt(&m1).is_err(),
        "a skipped key many ratchet generations old must no longer be retained"
    );
}
