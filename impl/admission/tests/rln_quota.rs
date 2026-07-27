//! Тесты RLN quota-слоя §7.4: детекция двойного предъявления + slashing.
//!
//! Несущий тест — `second_different_message_deanonymizes_violator`: превышение
//! квоты восстанавливает секрет нарушителя (экономическое наказание, а не
//! превентивный блок). Границу (слой предполагает zk-верифицированные доли)
//! несёт документация типа, не тест.

use admission::rln::{external_nullifier, Field, IdentitySecret, RlnOutcome, RlnQuotaTracker};

fn identity(seed: u64) -> IdentitySecret {
    IdentitySecret(Field::from(seed) + Field::from(0x1000u64))
}

#[test]
fn first_message_accepted() {
    let mut t = RlnQuotaTracker::new(7, b"scope", 1024);
    let id = identity(1);
    let ext = external_nullifier(7, b"scope");
    let share = id.share(&ext, Field::from(100u64));
    assert_eq!(t.observe(&share), RlnOutcome::Accepted);
}

#[test]
fn second_different_message_deanonymizes_violator() {
    let mut t = RlnQuotaTracker::new(7, b"scope", 1024);
    let id = identity(42);
    let ext = external_nullifier(7, b"scope");

    // Первое сообщение — в пределах квоты.
    let s1 = id.share(&ext, Field::from(111u64));
    assert_eq!(t.observe(&s1), RlnOutcome::Accepted);

    // Второе РАЗНОЕ сообщение той же личности в ту же эпоху → нарушение квоты,
    // секрет восстановлен.
    let s2 = id.share(&ext, Field::from(222u64));
    match t.observe(&s2) {
        RlnOutcome::QuotaViolation { recovered_secret } => {
            assert_eq!(
                recovered_secret,
                id.0.to_bytes(),
                "восстановленный секрет должен совпасть с секретом нарушителя"
            );
        }
        other => panic!("ожидалось QuotaViolation, получено {:?}", other),
    }
}

#[test]
fn same_message_replay_is_duplicate_not_violation() {
    let mut t = RlnQuotaTracker::new(7, b"scope", 1024);
    let id = identity(5);
    let ext = external_nullifier(7, b"scope");
    let m = Field::from(333u64);
    let share = id.share(&ext, m);
    assert_eq!(t.observe(&share), RlnOutcome::Accepted);
    // Тот же самый message_hash повторно — это один RLNProof, не нарушение.
    assert_eq!(t.observe(&share), RlnOutcome::Duplicate);
}

#[test]
fn different_identities_do_not_cross_slash() {
    let mut t = RlnQuotaTracker::new(7, b"scope", 1024);
    let ext = external_nullifier(7, b"scope");
    let a = identity(1).share(&ext, Field::from(10u64));
    let b = identity(2).share(&ext, Field::from(20u64));
    assert_eq!(t.observe(&a), RlnOutcome::Accepted);
    // Другая личность → другой nullifier → отдельный учёт, не slash.
    assert_eq!(t.observe(&b), RlnOutcome::Accepted);
}

#[test]
fn epoch_rotation_resets_quota() {
    let mut t = RlnQuotaTracker::new(7, b"scope", 1024);
    let id = identity(9);

    let ext7 = external_nullifier(7, b"scope");
    let s7 = id.share(&ext7, Field::from(1u64));
    assert_eq!(t.observe(&s7), RlnOutcome::Accepted);

    // Новая эпоха → квота обнулилась; та же личность снова может отправить.
    t.roll_epoch(8);
    let ext8 = external_nullifier(8, b"scope");
    let s8 = id.share(&ext8, Field::from(1u64));
    assert_eq!(t.observe(&s8), RlnOutcome::Accepted);
}

#[test]
fn capacity_triggers_backpressure() {
    let mut t = RlnQuotaTracker::new(7, b"scope", 2); // ёмкость 2 личности
    let ext = external_nullifier(7, b"scope");
    assert_eq!(t.observe(&identity(1).share(&ext, Field::from(1u64))), RlnOutcome::Accepted);
    assert_eq!(t.observe(&identity(2).share(&ext, Field::from(1u64))), RlnOutcome::Accepted);
    // Третья НОВАЯ личность не влезает → backpressure.
    assert_eq!(t.observe(&identity(3).share(&ext, Field::from(1u64))), RlnOutcome::Backpressure);
}

// ---------- Несущие: актуальность эпохи (иначе лимит обходится) ----------

#[test]
fn stale_or_future_epoch_rejected() {
    // Трекер на эпохе 7. Доля, собранная для эпохи 5 (external_nullifier(5)),
    // не совпадает ни с текущей (7), ни с grace-предыдущей (6) → WrongEpoch.
    // Без этой проверки личность циклила бы epoch_id и слала бы без лимита.
    let mut t = RlnQuotaTracker::new(7, b"scope", 1024);
    let id = identity(1);
    let stale = id.share(&external_nullifier(5, b"scope"), Field::from(1u64));
    assert_eq!(t.observe(&stale), RlnOutcome::WrongEpoch);
    // И будущая эпоха (9) тоже.
    let future = id.share(&external_nullifier(9, b"scope"), Field::from(1u64));
    assert_eq!(t.observe(&future), RlnOutcome::WrongEpoch);
}

#[test]
fn straddle_across_epoch_boundary_still_slashes() {
    // САМЫЙ важный тест: попытка обойти slashing, «размазав» два разных
    // сообщения одной эпохи через границу ротации.
    // 1) На эпохе 7 личность шлёт сообщение A (external_nullifier(7)).
    // 2) Трекер продвигается в эпоху 8 (grace удерживает состояние эпохи 7).
    // 3) Личность шлёт ВТОРОЕ разное сообщение B, всё ещё для эпохи 7.
    // Без grace-удержания шаг 3 прошёл бы как Accepted (обход). С ним —
    // QuotaViolation: та же личность, та же эпоха, два сообщения → slash.
    let mut t = RlnQuotaTracker::new(7, b"scope", 1024);
    let id = identity(77);
    let ext7 = external_nullifier(7, b"scope");

    let a = id.share(&ext7, Field::from(1u64));
    assert_eq!(t.observe(&a), RlnOutcome::Accepted);

    t.roll_epoch(8); // граница эпохи

    let b = id.share(&ext7, Field::from(2u64)); // второе разное сообщение эпохи 7
    match t.observe(&b) {
        RlnOutcome::QuotaViolation { recovered_secret } => {
            assert_eq!(recovered_secret, id.0.to_bytes());
        }
        other => panic!("straddle через границу эпохи должен слэшить, получено {:?}", other),
    }
}

#[test]
fn beyond_grace_window_epoch_rejected() {
    // Скачок эпохи больше grace: состояние прошлого не удерживается, и доли
    // старой эпохи отвергаются как WrongEpoch.
    let mut t = RlnQuotaTracker::new(7, b"scope", 1024);
    let id = identity(1);
    let ext7 = external_nullifier(7, b"scope");
    assert_eq!(t.observe(&id.share(&ext7, Field::from(1u64))), RlnOutcome::Accepted);

    t.roll_epoch(10); // скачок > grace(1)
    // Эпоха 7 теперь ни current(10), ни previous(9) → WrongEpoch.
    assert_eq!(t.observe(&id.share(&ext7, Field::from(2u64))), RlnOutcome::WrongEpoch);
}
