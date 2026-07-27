//! Состязательные тесты пороговой кольцевой подписи §7.3 (tring).
//!
//! Весь файл под feature-флагом `unaudited-crypto`. Именно эти тесты несут
//! вес: happy-path на security-крипте ничего не доказывает — доказывает то,
//! что ДОЛЖНО провалиться и проваливается. Запуск:
//!   cargo test --features unaudited-crypto --test tring_adversarial
#![cfg(feature = "unaudited-crypto")]

use admission::tring::{sign, verify, IssuerKeypair, ThresholdRingSig};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// Детерминированный секрет issuer из seed (для воспроизводимых тестов).
fn keypair(seed: &[u8]) -> IssuerKeypair {
    let mut h = Sha512::new();
    h.update(b"tring-test-key");
    h.update(seed);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    IssuerKeypair::from_secret(Scalar::from_bytes_mod_order_wide(&wide))
}

/// Кольцо из N issuer'ов + их секреты по индексам.
fn make_ring(n: usize) -> (Vec<RistrettoPoint>, Vec<Scalar>) {
    let mut pubs = Vec::new();
    let mut secs = Vec::new();
    for i in 0..n {
        let kp = keypair(&[i as u8]);
        pubs.push(kp.public);
        secs.push(kp.secret);
    }
    (pubs, secs)
}

fn signers(secs: &[Scalar], idxs: &[usize]) -> Vec<(usize, Scalar)> {
    idxs.iter().map(|&i| (i, secs[i])).collect()
}

// ---------- Базовая корректность (необходимый минимум, не доказательство) ----------

#[test]
fn valid_t_of_n_verifies() {
    let (ring, secs) = make_ring(5);
    let sig = sign(b"admission-token-nonce", &ring, 2, &signers(&secs, &[1, 3])).unwrap();
    assert!(verify(b"admission-token-nonce", &ring, 2, &sig));
}

// ---------- Направление неравенства: ≥ t, не = t ----------

#[test]
fn more_than_t_signers_still_verifies_under_t_policy() {
    // 3 подписанта под политикой t=2 — сильнее требуемого, ДОЛЖНО проходить.
    let (ring, secs) = make_ring(5);
    let sig = sign(b"m", &ring, 2, &signers(&secs, &[0, 2, 4])).unwrap();
    assert!(verify(b"m", &ring, 2, &sig), "t+1 подписантов обязаны проходить политику t");
}

#[test]
fn fewer_than_t_signers_fails_under_t_policy() {
    // ВНИМАНИЕ: это тест enforcement ПОЛИТИКИ на ЧЕСТНО построенной подписи,
    // НЕ тест неподделываемости. Он показывает, что легитимная подпись порога
    // t=1 не засчитывается под политику t=2 (степень полинома n−1 > n−2).
    // Устойчивость к подделке злонамеренным sub-threshold-подписантом держится
    // на теореме soundness CDS + Fiat–Shamir (ROM) и unit-тестом не
    // проверяется — не путать одно с другим (см. doc модуля tring).
    let (ring, secs) = make_ring(5);
    let sig_t1 = sign(b"m", &ring, 1, &signers(&secs, &[3])).unwrap();
    assert!(verify(b"m", &ring, 1, &sig_t1), "sanity: t=1 подпись валидна под t=1");
    assert!(
        !verify(b"m", &ring, 2, &sig_t1),
        "подпись одного подписанта НЕ должна проходить политику '2 из 5'"
    );
}

#[test]
fn cannot_sign_below_threshold() {
    // API не даёт собрать подпись, имея меньше t секретов.
    let (ring, secs) = make_ring(5);
    assert!(sign(b"m", &ring, 3, &signers(&secs, &[0, 1])).is_err());
}

// ---------- Подделка: любое искажение подписи ломает проверку ----------

#[test]
fn tampering_any_challenge_fails() {
    let (ring, secs) = make_ring(5);
    let mut sig = sign(b"m", &ring, 2, &signers(&secs, &[1, 4])).unwrap();
    sig.challenges[0] += Scalar::ONE;
    assert!(!verify(b"m", &ring, 2, &sig));
}

#[test]
fn tampering_any_response_fails() {
    let (ring, secs) = make_ring(5);
    let mut sig = sign(b"m", &ring, 2, &signers(&secs, &[1, 4])).unwrap();
    sig.responses[2] += Scalar::ONE;
    assert!(!verify(b"m", &ring, 2, &sig));
}

#[test]
fn all_zero_signature_fails() {
    let (ring, _secs) = make_ring(5);
    let sig = ThresholdRingSig {
        challenges: vec![Scalar::ZERO; 5],
        responses: vec![Scalar::ZERO; 5],
    };
    assert!(!verify(b"m", &ring, 2, &sig));
}

// ---------- Сильный Fiat–Shamir: привязка к сообщению, кольцу, порогу ----------

#[test]
fn wrong_message_fails() {
    let (ring, secs) = make_ring(5);
    let sig = sign(b"message-A", &ring, 2, &signers(&secs, &[0, 1])).unwrap();
    assert!(!verify(b"message-B", &ring, 2, &sig), "подпись не привязана к сообщению");
}

#[test]
fn reordered_ring_fails() {
    let (mut ring, secs) = make_ring(5);
    let sig = sign(b"m", &ring, 2, &signers(&secs, &[0, 1])).unwrap();
    ring.swap(0, 4); // то же множество ключей, другой порядок
    assert!(!verify(b"m", &ring, 2, &sig), "подпись не привязана к порядку кольца");
}

#[test]
fn different_ring_member_fails() {
    let (mut ring, secs) = make_ring(5);
    let sig = sign(b"m", &ring, 2, &signers(&secs, &[0, 1])).unwrap();
    ring[2] = keypair(b"outsider").public; // подмена одного члена кольца
    assert!(!verify(b"m", &ring, 2, &sig));
}

#[test]
fn threshold_in_hash_binds_policy() {
    // Подпись, сделанная под t=2, проверяется по хэшу, куда t входит явно →
    // проверка под другим t считает другой мастер-challenge. (Отдельно от
    // проверки степени — здесь именно привязка t к Fiat–Shamir.)
    let (ring, secs) = make_ring(5);
    let sig = sign(b"m", &ring, 2, &signers(&secs, &[0, 1, 2])).unwrap();
    // Под t=2 проходит; под t=1 (другой мастер-challenge) — нет, хотя
    // «3 подписанта ≥ 1» по количеству. Это ловит именно привязку t в хэше.
    assert!(verify(b"m", &ring, 2, &sig));
    assert!(!verify(b"m", &ring, 1, &sig));
}

// ---------- Несвязываемость / анонимность (НЕОБХОДИМОЕ, не достаточное) ----------
// Полная анонимность держится на симуляционном (HVZK) аргументе — это
// доказательство, а не assertEq. Тесты ниже проверяют лишь необходимые
// признаки; имена честны и не заявляют «доказано, что анонимно».

#[test]
fn signatures_are_format_identical_across_signer_sets() {
    // Наблюдатель не должен отличать наборы подписантов по форме подписи.
    let (ring, secs) = make_ring(5);
    let a = sign(b"m", &ring, 2, &signers(&secs, &[0, 1])).unwrap();
    let b = sign(b"m", &ring, 2, &signers(&secs, &[2, 4])).unwrap();
    assert_eq!(a.challenges.len(), b.challenges.len());
    assert_eq!(a.responses.len(), b.responses.len());
    // Разные наборы → разные подписи (иначе набор бы утекал через равенство).
    assert_ne!(a, b);
    assert!(verify(b"m", &ring, 2, &a) && verify(b"m", &ring, 2, &b));
}

#[test]
fn deterministic_repro_but_ring_rebinds_nonce() {
    // (1) Тот же вход → та же подпись: нет двух разных c при том же k → нет
    //     утечки секрета (класс two-shares из RLN §7.4).
    let (ring, secs) = make_ring(5);
    let s1 = sign(b"m", &ring, 2, &signers(&secs, &[0, 1])).unwrap();
    let s2 = sign(b"m", &ring, 2, &signers(&secs, &[0, 1])).unwrap();
    assert_eq!(s1, s2, "детерминированная воспроизводимость нарушена");

    // (2) Тот же подписант+сообщение, но ДРУГОЕ кольцо → ответ подписанта
    //     меняется (nonce привязан к кольцу), а не остаётся при том же k.
    let (mut ring2, secs2) = make_ring(5);
    ring2[4] = keypair(b"different-5th").public;
    let mut secs2b = secs2.clone();
    secs2b[4] = keypair(b"different-5th").secret;
    let s3 = sign(b"m", &ring2, 2, &signers(&secs2b, &[0, 1])).unwrap();
    // Ответ подписанта 0 не должен совпасть с таковым из s1 (иначе k не
    // перепривязался бы к кольцу).
    assert_ne!(s1.responses[0], s3.responses[0], "nonce не перепривязан к кольцу");

    // (3) То же кольцо+сообщение, но ДРУГОЙ набор подписантов ([0,1] vs [0,2]).
    //     Это более прямой случай same-k-different-c: ответ подписанта 0
    //     обязан измениться (nonce привязан к составу через sim_seed), иначе
    //     при том же k и другом c_0 утёк бы секрет x_0.
    let s4 = sign(b"m", &ring, 2, &signers(&secs, &[0, 2])).unwrap();
    assert_ne!(
        s1.responses[0], s4.responses[0],
        "nonce не перепривязан к набору подписантов (риск утечки класса RLN)"
    );
}

// ---------- Крайние значения порога ----------

#[test]
fn threshold_one_is_plain_ring_signature() {
    let (ring, secs) = make_ring(4);
    let sig = sign(b"m", &ring, 1, &signers(&secs, &[2])).unwrap();
    assert!(verify(b"m", &ring, 1, &sig));
}

#[test]
fn threshold_equals_n_requires_all() {
    let (ring, secs) = make_ring(4);
    let all = sign(b"m", &ring, 4, &signers(&secs, &[0, 1, 2, 3])).unwrap();
    assert!(verify(b"m", &ring, 4, &all));
    // Три подписанта не могут удовлетворить t=N=4.
    let three = sign(b"m", &ring, 3, &signers(&secs, &[0, 1, 2])).unwrap();
    assert!(!verify(b"m", &ring, 4, &three));
}
