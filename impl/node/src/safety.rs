//! Safety number (отпечаток безопасности) — человекочитаемая сверка подлинности
//! §2.1-IK по ВНЕПОЛОСНОМУ каналу (голос/личная встреча/видео). Закрывает
//! единственную крипто-НЕобеспечиваемую стену модели: relay — НЕ якорь личности,
//! подлинность IK устанавливается OOB, иначе IK-swap = MITM.
//!
//! **Что именно верифицируется:** ПОДЛИННОСТЬ IK, и только её. Это полно, потому
//! что IK-подлинность ⟹ подлинность сессии: `root_key` PQXDH нагружает
//! `DH1 = IK_A × PK_B` и связывает оба IK в транскрипт (см. `pqxdh`) — сторона
//! без секрета IK не согласует тот же ключ (fail-closed). Подмена prekey/KEM у
//! relay сессию НЕ образует (не нужно отдельно детектить). Поэтому хэшируем
//! ровно `identity_public()`.
//!
//! **Конструкция.** Симметрична: обе стороны сортируют пару IK и получают ОДНО
//! число. `SHA-512(DOMAIN ‖ VERSION ‖ lo ‖ hi)` → первые 60 байт → 12 групп по
//! 5 байт (big-endian) `mod 100000` → 12×5 = **60 десятичных цифр** (формат в духе
//! Signal). Итерированный KDF (Signal 5200×) НЕ нужен: при полной 60-значной
//! ширине (~199 бит) MITM, ищущий совпадающее число `SN(A,M_a)==SN(B,M_b)`,
//! упирается в двухсписочную коллизию ~2^100 — итерация ничего не добавляет,
//! когда показана вся ширина. Ширина несёт стойкость.

use sha2::{Digest, Sha512};

const DOMAIN: &[u8] = b"KARST-safety-number";
/// Версия формата — смена ломает совместимость отпечатков осознанно.
const VERSION: u8 = 1;
/// Групп по 5 цифр (как Signal: 60 цифр всего). Нужно `GROUPS*5` байт дайджеста.
const GROUPS: usize = 12;

/// 60-значный отпечаток пары §2.1-IK, сгруппированный по 5 цифр через пробел
/// (`"01234 56789 …"`, 12 групп). Симметричен: `safety_number(a,b) ==
/// safety_number(b,a)`. Для OOB-сверки читается вслух/сравнивается визуально.
pub fn safety_number(ik_a: &[u8; 32], ik_b: &[u8; 32]) -> String {
    // Симметрия: канонический порядок пары (меньший IK первым).
    let (lo, hi) = if ik_a <= ik_b { (ik_a, ik_b) } else { (ik_b, ik_a) };

    let mut h = Sha512::new();
    h.update(DOMAIN);
    h.update([VERSION]);
    h.update(lo);
    h.update(hi);
    let digest = h.finalize(); // 64 байта ≥ GROUPS*5

    let mut out = String::with_capacity(GROUPS * 6);
    for i in 0..GROUPS {
        let start = i * 5;
        // 5 байт big-endian → u64 → 5 десятичных цифр.
        let mut v: u64 = 0;
        for &b in &digest[start..start + 5] {
            v = (v << 8) | b as u64;
        }
        let chunk = v % 100_000;
        if i > 0 {
            out.push(' ');
        }
        // ОБЯЗАТЕЛЬНО zero-pad до 5 цифр: иначе группы разъезжаются и визуальная
        // OOB-сверка (ради чего фича и существует) молча ломается.
        out.push_str(&format!("{chunk:05}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Замороженный known-answer: пиннит DOMAIN, VERSION, порядок сортировки,
    /// endianness, chunk-математику И zero-pad против тихого дрейфа (как
    /// conformance-вектора). Значение получено из самой реализации и заморожено.
    #[test]
    fn frozen_known_answer_vector() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[0] = 1;
        let sn = safety_number(&a, &b);
        assert_eq!(sn, "17189 06467 41496 60988 88669 01686 91612 33462 95102 33841 50843 30572");
    }

    /// Симметрия: порядок аргументов не влияет (обе стороны видят одно число).
    #[test]
    fn symmetric_in_arguments() {
        let a = [7u8; 32];
        let b = [9u8; 32];
        assert_eq!(safety_number(&a, &b), safety_number(&b, &a));
    }

    /// Чувствительность: флип ОДНОГО бита одного IK → другое число (иначе подмена
    /// IK не детектилась бы — суть фичи).
    #[test]
    fn one_bit_flip_changes_number() {
        let a = [0u8; 32];
        let b = [0x55u8; 32];
        let mut b2 = b;
        b2[31] ^= 0x01;
        assert_ne!(safety_number(&a, &b), safety_number(&a, &b2));
    }

    /// Формат: ровно 60 цифр в 12 группах по 5, разделённых пробелом.
    #[test]
    fn format_is_twelve_groups_of_five_digits() {
        let sn = safety_number(&[1u8; 32], &[2u8; 32]);
        let groups: Vec<&str> = sn.split(' ').collect();
        assert_eq!(groups.len(), 12, "12 групп");
        for g in groups {
            assert_eq!(g.len(), 5, "5 цифр в группе (zero-pad)");
            assert!(g.chars().all(|c| c.is_ascii_digit()), "только цифры");
        }
    }
}
