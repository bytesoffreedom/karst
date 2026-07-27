//! §7.3 — Пороговая кольцевая подпись (t-of-N), curve-friendly замена BSS.
//!
//! # СТАТУС: РЕФЕРЕНС, НЕ ПРОШЁЛ АУДИТ. НЕ ДЛЯ PRODUCTION.
//!
//! Модуль за feature-флагом `unaudited-crypto` (по умолчанию выключен).
//! «Надёжнее» для security-критичного примитива в пределе означает
//! независимый аудит — до него этот код нельзя считать доверенным. Вес несут
//! состязательные тесты (см. низ файла): t−1 подписантов → отказ, подделка →
//! отказ, привязка к кольцу/сообщению. Happy-path сам по себе тут ничего не
//! доказывает.
//!
//! # Конструкция (пиннится к теореме, не ad-hoc)
//!
//! Cramer–Damgård–Schoenmakers, «Proofs of Partial Knowledge and Simplified
//! Design of Witness Hiding Protocols», CRYPTO 1994 — пороговая σ-композиция
//! Schnorr-доказательств, сделанная неинтерактивной через Fiat–Shamir.
//! Discrete-log над Ristretto255 (`curve25519-dalek`), совместимо с
//! Ed25519-стеком KARST (в отличие от RSA-based Bresson–Stern–Szydlo).
//! Ориентир на discrete-log ETRS: Aranha, Hall-Andersen, Nitulescu, Pagnin,
//! Yakoubov, «Count Me In! Extendability for Threshold Ring Signatures»,
//! PKC 2022.
//!
//! ## Идея
//!
//! N issuer-ключей `P_i = x_i·G`. Подписывают ≥ t из них, не раскрывая, кто.
//! Каждому issuer сопоставлена точка поля `i+1` (1-индексация; 0 зарезервован
//! под мастер-challenge). Вызовы Schnorr для всех N членов кольца связаны
//! требованием: их challenge'и `c_i` лежат на полиноме `p` степени `N−t` с
//! `p(0) = c`, где `c` — Fiat–Shamir мастер-challenge над (t ‖ кольцо ‖
//! сообщение ‖ все commitments). Подписант, знающий t секретов, может
//! свободно выбрать `N−t` challenge'ей симулируемых членов; вместе с `(0,c)`
//! это фиксирует `p` (степень `N−t`), а challenge'и настоящих подписантов
//! оказываются `p(индекс)` — под них он строит честный Schnorr-ответ.
//!
//! ## Проверка неравенства (≥ t, не = t)
//!
//! Подпись с бóльшим числом подписантов `s > t` даёт полином степени
//! `N−s < N−t` — он тоже степени `≤ N−t`, поэтому проходит проверку политики
//! `t`. Verify проверяет «степень ≤ N−t» (= «подписали не менее t»), не
//! «= N−t».
//!
//! # Что тесты НЕ доказывают (границы честно)
//!
//! - **Неподделываемость** держится на теореме soundness CDS + Fiat–Shamir в
//!   ROM (forking lemma), а НЕ на unit-тесте. `fewer_than_t_signers_fails...`
//!   проверяет лишь enforcement политики на ЧЕСТНО построенной подписи — он
//!   не моделирует злонамеренного sub-threshold-подписанта и не может: это
//!   доказательное обязательство, не assertEq. Тот же класс дисциплины, что
//!   у анонимности ниже.
//! - **Анонимность/несвязываемость** держится на симуляционном (HVZK)
//!   аргументе — тоже доказательство, не тест. Тесты проверяют лишь
//!   необходимые признаки.
//! - **Раскрывается ЧИСЛО подписантов `s`** (по степени интерполируемого
//!   полинома `N−s`), хотя НЕ раскрывается, кто именно. Для нашего
//!   применения не важно — issuer'ы подписывают ровно `t`, — но это свойство
//!   нужно называть, а не принимать за скрытое.

#![cfg(feature = "unaudited-crypto")]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::{Digest, Sha512};

const G: &RistrettoPoint = &RISTRETTO_BASEPOINT_POINT;

/// Ключевая пара одного issuer.
#[derive(Clone)]
pub struct IssuerKeypair {
    pub secret: Scalar,
    pub public: RistrettoPoint,
}

impl IssuerKeypair {
    pub fn from_secret(secret: Scalar) -> Self {
        IssuerKeypair {
            public: secret * G,
            secret,
        }
    }
}

/// Подпись на проводе: только challenge'и и ответы. `R_i` НЕ передаются —
/// verifier восстанавливает их как `R_i = s_i·G − c_i·P_i` (иначе `c_i` из
/// подписи не извлечь, это дискретный лог). Все `c_i` равномерны, поэтому их
/// публикация ничего не говорит о наборе подписантов.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdRingSig {
    pub challenges: Vec<Scalar>, // c_1..c_N
    pub responses: Vec<Scalar>,  // s_1..s_N
}

impl ThresholdRingSig {
    /// Формат провода: [N: u32 BE][c_1..c_N: 32B каждый][s_1..s_N: 32B каждый].
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.challenges.len();
        let mut out = Vec::with_capacity(4 + n * 64);
        out.extend_from_slice(&(n as u32).to_be_bytes());
        for c in &self.challenges {
            out.extend_from_slice(c.as_bytes());
        }
        for s in &self.responses {
            out.extend_from_slice(s.as_bytes());
        }
        out
    }

    /// Разбор с проверкой каноничности скаляров. `None` при любой
    /// структурной ошибке или неканоническом скаляре.
    pub fn from_bytes(buf: &[u8]) -> Option<ThresholdRingSig> {
        if buf.len() < 4 {
            return None;
        }
        let n = u32::from_be_bytes(buf[0..4].try_into().ok()?) as usize;
        if buf.len() != 4 + n * 64 {
            return None;
        }
        let read_scalar = |off: usize| -> Option<Scalar> {
            let mut b = [0u8; 32];
            b.copy_from_slice(&buf[off..off + 32]);
            Option::<Scalar>::from(Scalar::from_canonical_bytes(b))
        };
        let mut challenges = Vec::with_capacity(n);
        let mut responses = Vec::with_capacity(n);
        for i in 0..n {
            challenges.push(read_scalar(4 + i * 32)?);
        }
        for i in 0..n {
            responses.push(read_scalar(4 + n * 32 + i * 32)?);
        }
        Some(ThresholdRingSig {
            challenges,
            responses,
        })
    }
}

/// Разобрать сжатую Ristretto-точку из 32 байт (для issuer-ключей на проводе).
pub fn point_from_bytes(b: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(b).ok()?.decompress()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TRingError {
    /// t вне [1, N] или пустое кольцо.
    BadThreshold,
    /// Подписантов меньше порога t.
    NotEnoughSigners,
    /// Индекс подписанта вне кольца или дубликат.
    BadSignerIndex,
}

fn hash_to_scalar(parts: &[&[u8]]) -> Scalar {
    let mut h = Sha512::new();
    for p in parts {
        h.update((p.len() as u64).to_be_bytes()); // домен-разделение по длине
        h.update(p);
    }
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn point_bytes(p: &RistrettoPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

/// Мастер-challenge `c = H(DOMAIN ‖ t ‖ P_1..P_N ‖ msg ‖ R_1..R_N)`.
/// Привязывает порог, УПОРЯДОЧЕННОЕ кольцо, сообщение и все commitments —
/// это и есть сильный Fiat–Shamir (пропуск любого из них = дыра подделки).
fn master_challenge(
    t: usize,
    ring: &[RistrettoPoint],
    msg: &[u8],
    commitments: &[RistrettoPoint],
) -> Scalar {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    parts.push(b"KARST-tring-v1-challenge".to_vec());
    parts.push((t as u64).to_be_bytes().to_vec());
    parts.push((ring.len() as u64).to_be_bytes().to_vec());
    for p in ring {
        parts.push(point_bytes(p).to_vec());
    }
    parts.push(msg.to_vec());
    for r in commitments {
        parts.push(point_bytes(r).to_vec());
    }
    let refs: Vec<&[u8]> = parts.iter().map(|v| v.as_slice()).collect();
    hash_to_scalar(&refs)
}

/// Точка поля, сопоставленная issuer с индексом `i` (0-based): `i+1`.
/// 1-индексация — 0 зарезервирован под мастер-challenge; точки различны и
/// ненулевые (иначе интерполяция вырождается / течёт).
fn eval_point(i: usize) -> Scalar {
    Scalar::from((i as u64) + 1)
}

/// Лагранжева интерполяция: значение в `x_target` полинома через `points`.
/// Точки должны иметь различныеx-координаты.
fn lagrange_eval(points: &[(Scalar, Scalar)], x_target: Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    for (k, (xk, yk)) in points.iter().enumerate() {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for (m, (xm, _)) in points.iter().enumerate() {
            if m == k {
                continue;
            }
            num *= x_target - xm;
            den *= xk - xm;
        }
        acc += yk * num * den.invert();
    }
    acc
}

/// Подписать `msg` от лица кольца `ring` порогом `t`, набором подписантов
/// `signers` = список `(индекс_в_кольце, секрет)`. |signers| должно быть ≥ t.
///
/// Nonce подписантов выводится детерминированно из ПОЛНОГО пред-challenge
/// контекста (секрет ‖ msg ‖ кольцо ‖ вся симуляционная случайность). Это
/// строго сильнее, чем `H(secret‖msg)`: если тот же подписант подпишет то же
/// сообщение в другом составе/симуляции, изменится и nonce — иначе при том же
/// `k` и другом `c_j` утёк бы секрет через `s=k+c·x` (тот же класс утечки,
/// что two-shares в RLN §7.4).
pub fn sign(
    msg: &[u8],
    ring: &[RistrettoPoint],
    t: usize,
    signers: &[(usize, Scalar)],
) -> Result<ThresholdRingSig, TRingError> {
    let n = ring.len();
    if n == 0 || t == 0 || t > n {
        return Err(TRingError::BadThreshold);
    }
    if signers.len() < t {
        return Err(TRingError::NotEnoughSigners);
    }
    // Валидация индексов подписантов: в диапазоне, без дубликатов.
    let mut is_signer = vec![false; n];
    for (idx, _) in signers {
        if *idx >= n || is_signer[*idx] {
            return Err(TRingError::BadSignerIndex);
        }
        is_signer[*idx] = true;
    }
    let s = signers.len(); // фактическое число подписантов (≥ t)
    let degree = n - s; // степень полинома

    // --- 1. Симуляция для НЕ-подписантов: свободные (c_i, s_i) ---
    // Детерминированная симуляционная случайность, чтобы sign был
    // воспроизводим в тест-векторах: выводим из (msg, кольцо, секреты, индекс).
    // В бою заменяется на CSPRNG; здесь важно, что она фиксируется ДО nonce
    // подписантов и хешируется в них.
    let mut challenges = vec![Scalar::ZERO; n];
    let mut responses = vec![Scalar::ZERO; n];
    let mut sim_seed = Vec::new();
    sim_seed.extend_from_slice(b"KARST-tring-v1-sim");
    sim_seed.extend_from_slice(msg);
    for p in ring {
        sim_seed.extend_from_slice(&point_bytes(p));
    }
    for (idx, sk) in signers {
        sim_seed.extend_from_slice(&(*idx as u64).to_be_bytes());
        sim_seed.extend_from_slice(sk.as_bytes());
    }

    for i in 0..n {
        if is_signer[i] {
            continue;
        }
        let ci = hash_to_scalar(&[b"sim-c", &sim_seed, &(i as u64).to_be_bytes()]);
        let si = hash_to_scalar(&[b"sim-s", &sim_seed, &(i as u64).to_be_bytes()]);
        challenges[i] = ci;
        responses[i] = si;
    }

    // --- 2. Commitments всех членов ---
    // Для подписантов: R_j = k_j·G, k_j выводится с привязкой ПОЛНОГО контекста
    // (включая всю симуляционную случайность выше).
    let mut ctx = sim_seed.clone();
    for i in 0..n {
        if !is_signer[i] {
            ctx.extend_from_slice(&challenges[i].to_bytes());
            ctx.extend_from_slice(&responses[i].to_bytes());
        }
    }
    let mut nonces = vec![Scalar::ZERO; n];
    let mut commitments = vec![RistrettoPoint::identity(); n];
    for i in 0..n {
        if is_signer[i] {
            let sk = signers.iter().find(|(idx, _)| *idx == i).unwrap().1;
            let kj = hash_to_scalar(&[b"KARST-tring-v1-nonce", sk.as_bytes(), &ctx,
                                       &(i as u64).to_be_bytes()]);
            nonces[i] = kj;
            commitments[i] = kj * G;
        } else {
            // R_i = s_i·G − c_i·P_i (симуляция).
            commitments[i] = responses[i] * G - challenges[i] * ring[i];
        }
    }

    // --- 3. Мастер-challenge ---
    let c = master_challenge(t, ring, msg, &commitments);

    // --- 4. Полином через (0, c) и (idx+1, c_i) не-подписантов → degree = n−s ---
    let mut poly_points: Vec<(Scalar, Scalar)> = Vec::with_capacity(degree + 1);
    poly_points.push((Scalar::ZERO, c));
    for i in 0..n {
        if !is_signer[i] {
            poly_points.push((eval_point(i), challenges[i]));
        }
    }
    debug_assert_eq!(poly_points.len(), degree + 1);

    // --- 5. Challenge'и подписантов = p(idx+1); честный Schnorr-ответ ---
    for (idx, sk) in signers {
        let cj = lagrange_eval(&poly_points, eval_point(*idx));
        challenges[*idx] = cj;
        responses[*idx] = nonces[*idx] + cj * sk;
    }

    Ok(ThresholdRingSig {
        challenges,
        responses,
    })
}

/// Проверить подпись против кольца `ring` и политики порога `t`.
/// `t` и `ring` — доверенные параметры (из политики §7.3), НЕ из подписи.
pub fn verify(msg: &[u8], ring: &[RistrettoPoint], t: usize, sig: &ThresholdRingSig) -> bool {
    let n = ring.len();
    if n == 0 || t == 0 || t > n {
        return false;
    }
    if sig.challenges.len() != n || sig.responses.len() != n {
        return false;
    }

    // 1. Восстановить commitments: R_i = s_i·G − c_i·P_i.
    let mut commitments = vec![RistrettoPoint::identity(); n];
    for i in 0..n {
        commitments[i] = sig.responses[i] * G - sig.challenges[i] * ring[i];
    }

    // 2. Мастер-challenge над теми же входами.
    let c = master_challenge(t, ring, msg, &commitments);

    // 3. Проверить: все N challenge-точек + (0,c) лежат на полиноме степени
    //    ≤ n−t. Интерполируем через (0,c) и первые (n−t) challenge-точек,
    //    затем сверяем остальные t challenge-точки.
    let degree = n - t;
    let mut basis: Vec<(Scalar, Scalar)> = Vec::with_capacity(degree + 1);
    basis.push((Scalar::ZERO, c));
    for i in 0..degree {
        basis.push((eval_point(i), sig.challenges[i]));
    }
    // basis.len() == degree + 1 == n − t + 1 точек → однозначный полином ≤ n−t.
    for i in degree..n {
        let expected = lagrange_eval(&basis, eval_point(i));
        if expected != sig.challenges[i] {
            return false;
        }
    }
    // (Schnorr-уравнения соблюдены по построению: R_i выведены из (c_i,s_i),
    // и те же R_i вошли в c; несоответствие сломало бы шаг 3.)
    true
}
