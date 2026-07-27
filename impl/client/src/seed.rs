//! Мнемоническая фраза (BIP39) как **единый корень личности** KARST.
//!
//! Одна 12-словная фраза — это ВСЁ, что нужно, чтобы восстановить личность на
//! любом устройстве. Из неё детерминированно выводятся ОБА секрета:
//! - `seal` — relay-facing X25519 (владение mailbox, §7 fetch-auth);
//! - `account` — §2.1 PQXDH (ik‖prekey‖ML-KEM-seed); его `ik` — адрес mailbox.
//!
//! Одна и та же фраза → тот же IK (адрес) и то же владение mailbox на любой
//! машине. Пароль (`Store::unlock`) шифрует корень НА ЭТОМ диске; фраза
//! восстанавливает его ГДЕ УГОДНО. Это разные вещи: потеря пароля ≠ потеря
//! личности (перевосстановишь по фразе), потеря фразы = потеря личности НАВСЕГДА
//! (бэкдора нет — см. `docs/STATUS.md`).
//!
//! # Дисциплина крипты. Контур вывода (`derive`) — **ЗАМОРОЖЕН НАВСЕГДА**:
//! момент, когда человек записал 12 слов, `mnemonic → IK` зафиксирован. Любое
//! изменение домена/порядка/seed-функции осиротит все записанные фразы. Пинится
//! `frozen_derivation_vector`. Схема НЕ совместима с кошельками (KARST-свой
//! HKDF поверх BIP39-seed), reference-код, независимо НЕ аудирован.

use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

use node::pqxdh::Account;
use node::seal::Identity;

/// Домен HKDF-Expand — **ЗАМОРОЖЕН НАВСЕГДА** (см. заголовок модуля).
const HKDF_INFO: &[u8] = b"KARST-identity-derive-v1";

/// 16 байт энтропии = 12 слов (как в крипто-кошельках).
pub const ENTROPY_BYTES: usize = 16;

/// Выведенные из фразы секреты. Оба детерминированы от одной энтропии.
pub struct DerivedIdentity {
    pub seal: Identity,
    pub account: Account,
}

/// Три РАЗЛИЧНЫЕ позиции слов (0-based, в 0..12) для сверки резервной копии при
/// создании аккаунта. Случайные (не фиксированные) — чтобы человек действительно
/// сверялся с записью, а не заучивал ответ. Чекбокс «я записал» — театр, тут
/// требуется ввести конкретные слова (см. UX создания).
pub fn confirm_positions() -> [usize; 3] {
    let mut rng = OsRng;
    loop {
        let p = [
            (rng.next_u32() % 12) as usize,
            (rng.next_u32() % 12) as usize,
            (rng.next_u32() % 12) as usize,
        ];
        if p[0] != p[1] && p[1] != p[2] && p[0] != p[2] {
            return p;
        }
    }
}

/// Свежая 12-словная фраза из ОС-CSPRNG (`OsRng`).
pub fn generate_mnemonic() -> Mnemonic {
    let mut entropy = [0u8; ENTROPY_BYTES];
    OsRng.fill_bytes(&mut entropy);
    Mnemonic::from_entropy(&entropy).expect("16 байт энтропии → валидные 12 слов")
}

/// Разобрать введённую пользователем фразу (английский словарь) СО СВЕРКОЙ
/// контрольной суммы: опечатка или переставленное слово будут отвергнуты, а не
/// молча приняты как чужая личность. Пробелы по краям срезаются.
pub fn parse_mnemonic(phrase: &str) -> Result<Mnemonic, String> {
    // Нормализация ДО разбора: схлопнуть любые пробелы/переносы (multiline-поле,
    // вставка с разбивкой на строки) и привести к нижнему регистру (BIP39-слова
    // нижним регистром; «Abandon» с автозаглавной иначе не распознался бы). Без
    // этого верная фраза отвергалась из-за форматирования — реальный провал
    // восстановления.
    let normalized =
        phrase.split_whitespace().map(|w| w.to_lowercase()).collect::<Vec<_>>().join(" ");
    let m = Mnemonic::parse_in(Language::English, &normalized)
        .map_err(|e| format!("неверная фраза восстановления: {e}"))?;
    if m.word_count() != 12 {
        return Err(format!("ожидается 12 слов, а не {}", m.word_count()));
    }
    Ok(m)
}

/// Энтропия фразы (16 байт) — корень, который кладётся на диск.
pub fn entropy_of(m: &Mnemonic) -> [u8; ENTROPY_BYTES] {
    let (arr, len) = m.to_entropy_array();
    debug_assert_eq!(len, ENTROPY_BYTES, "12 слов → 16 байт энтропии");
    arr[..ENTROPY_BYTES].try_into().expect("16 байт")
}

/// Восстановить фразу из энтропии (для экрана «показать фразу восстановления»).
pub fn mnemonic_of_entropy(entropy: &[u8; ENTROPY_BYTES]) -> Mnemonic {
    Mnemonic::from_entropy(entropy).expect("16 байт → валидные 12 слов")
}

/// **ЗАМОРОЖЕННЫЙ** вывод обоих секретов из энтропии фразы.
///
/// ```text
/// bip39_seed = BIP39 to_seed(passphrase="")   // PBKDF2-HMAC-SHA512, 2048 итер, 64 Б
/// PRK        = HKDF-Extract(SHA-256, salt=∅, ikm=bip39_seed)
/// okm[160]   = HKDF-Expand(PRK, info="KARST-identity-derive-v1")
/// seal(32)   = okm[0..32]
/// account    = okm[32..160] = ik(32)‖prekey(32)‖ML-KEM-seed(64)
/// ```
pub fn derive(entropy: &[u8; ENTROPY_BYTES]) -> DerivedIdentity {
    let m = mnemonic_of_entropy(entropy);
    let seed = m.to_seed(""); // BIP39 PBKDF2, ПУСТАЯ passphrase — часть контракта
    let hk = Hkdf::<Sha256>::new(None, &seed); // salt=None (пустой)
    let mut okm = [0u8; 160];
    hk.expand(HKDF_INFO, &mut okm).expect("160 ≤ 255*32");
    let seal = Identity::from_secret_bytes(okm[0..32].try_into().expect("32"));
    let account = Account::from_secret_bytes(okm[32..160].try_into().expect("128"));
    DerivedIdentity { seal, account }
}

/// HKDF-домен вывода ПРОКСИ-личностей — **ОТДЕЛЬНЫЙ замороженный контракт** от `derive`.
/// Прокси — детерминированные HD-потомки той же фразы (одноразовые каналы связи, см.
/// `docs/design/proxy-identity.md`): корень адреса не имеет, наружу ходят только прокси.
const HKDF_PROXY_INFO: &[u8] = b"KARST-proxy-derive-v1";

/// Вывести ПРОКСИ-личность номер `index` из энтропии фразы. Полностью независим от `derive`
/// (корневая личность): другой HKDF-`info` (`HKDF_PROXY_INFO ‖ le32(index)`), поэтому прокси
/// никогда не сталкиваются с корнем, а замороженный корневой контракт не тронут. Раскладка
/// та же (seal ‖ account), что у `derive` — прокси это полноценная сетевая личность.
///
/// **ЗАМОРОЖЕН, как только создан первый реальный прокси:** смена `info`/кодировки индекса
/// осиротит все розданные прокси-коды. Пинится `frozen_proxy_derivation_vector`.
pub fn derive_proxy(entropy: &[u8; ENTROPY_BYTES], index: u32) -> DerivedIdentity {
    let m = mnemonic_of_entropy(entropy);
    let seed = m.to_seed(""); // тот же BIP39-контракт, что и в `derive`
    let hk = Hkdf::<Sha256>::new(None, &seed);
    let mut info = Vec::with_capacity(HKDF_PROXY_INFO.len() + 4);
    info.extend_from_slice(HKDF_PROXY_INFO);
    info.extend_from_slice(&index.to_le_bytes()); // little-endian индекс — часть замороженного контракта
    let mut okm = [0u8; 160];
    hk.expand(&info, &mut okm).expect("160 ≤ 255*32");
    let seal = Identity::from_secret_bytes(okm[0..32].try_into().expect("32"));
    let account = Account::from_secret_bytes(okm[32..160].try_into().expect("128"));
    DerivedIdentity { seal, account }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Контракт совместимости — НЕ МЕНЯТЬ значения.** Фиксирует
    /// `известная фраза → точный IK`. Если этот тест покраснел не потому, что вы
    /// осознанно ввели НОВЫЙ формат, — вы сломали восстановление у всех, кто уже
    /// записал фразу. (Как `conformance_vectors_match_frozen` в крипто-ядре.)
    #[test]
    fn frozen_derivation_vector() {
        // Стандартная BIP39-тест-фраза (энтропия = 16 нулевых байт).
        let phrase = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon about";
        let m = parse_mnemonic(phrase).expect("валидная тест-фраза");
        assert_eq!(entropy_of(&m), [0u8; 16], "тест-фраза = нулевая энтропия");

        let d = derive(&entropy_of(&m));
        let ik = hex::encode(d.account.identity_public());
        let seal_pub = hex::encode(d.seal.public.to_bytes());
        assert_eq!(
            ik, "7934ff0bdeccabfe8ea251ec9c44b453d285de4f957f663e91a5f5c9b8fcca1b",
            "IK-вектор изменился — восстановление сломано для существующих фраз"
        );
        assert_eq!(
            seal_pub, "a9059cc02337df3c91c6811031478984c052f7eefb8ab44fb3d56d63b9a54507",
            "seal-вектор изменился — владение mailbox сломано"
        );
    }

    /// **Контракт совместимости прокси — НЕ МЕНЯТЬ значения** (как `frozen_derivation_vector`).
    /// Фиксирует `известная фраза + индекс → точный IK прокси`. Как только кто-то создал прокси
    /// и раздал его код, эти значения заморожены навсегда — иначе прокси осиротеют. Также пинит,
    /// что прокси отличаются друг от друга и от корня (разные HKDF-домены/индексы).
    #[test]
    fn frozen_proxy_derivation_vector() {
        let entropy = [0u8; 16]; // та же нулевая тест-энтропия
        let p0 = derive_proxy(&entropy, 0);
        let p1 = derive_proxy(&entropy, 1);
        let ik0 = hex::encode(p0.account.identity_public());
        let ik1 = hex::encode(p1.account.identity_public());
        let seal0 = hex::encode(p0.seal.public.to_bytes());

        // Прокси ≠ корень (отдельный домен) и ≠ друг другу (разные индексы).
        let root = derive(&entropy);
        assert_ne!(ik0, hex::encode(root.account.identity_public()), "прокси != корень");
        assert_ne!(ik0, ik1, "разные индексы → разные личности");

        // ЗАМОРОЖЕНО — эти значения не должны меняться никогда.
        assert_eq!(
            ik0, "e1c1c0f0317a31ee6171335758114701954c1230f330eec82be32bc3b3469939",
            "прокси-IK[0] изменился — розданные прокси-коды сломаны"
        );
        assert_eq!(
            ik1, "2e2e1f0b84c8de2c6057169f7426fe0741d574806721adf0c508de03a6f7c736",
            "прокси-IK[1] изменился — розданные прокси-коды сломаны"
        );
        let _ = seal0;
    }

    #[test]
    fn same_phrase_same_identity_different_phrase_different() {
        let a = generate_mnemonic();
        let b = generate_mnemonic();
        assert_ne!(entropy_of(&a), entropy_of(&b), "две генерации различны");

        // Восстановление: та же энтропия → тот же IK и тот же seal.
        let d1 = derive(&entropy_of(&a));
        let d2 = derive(&entropy_of(&a));
        assert_eq!(d1.account.identity_public(), d2.account.identity_public());
        assert_eq!(d1.seal.public.to_bytes(), d2.seal.public.to_bytes());

        // Разные фразы → разные личности.
        let e = derive(&entropy_of(&b));
        assert_ne!(d1.account.identity_public(), e.account.identity_public());
    }

    #[test]
    fn corrupted_phrase_rejected_not_silently_accepted() {
        // Валидная фраза с ОДНИМ переставленным словом → контрольная сумма не
        // сойдётся → parse ДОЛЖЕН отвергнуть (иначе человек «восстановит» чужую
        // или пустую личность вместо ошибки).
        let bad = "abandon abandon abandon abandon abandon abandon \
                   abandon abandon abandon abandon about abandon";
        assert!(parse_mnemonic(bad).is_err(), "битая контрольная сумма должна отвергаться");
        // Мусор — тоже.
        assert!(parse_mnemonic("не мнемоника вовсе").is_err());
        // Правильная — принимается.
        let good = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon about";
        assert!(parse_mnemonic(good).is_ok());
    }

    #[test]
    fn phrase_normalized_over_case_and_whitespace() {
        // Верная фраза с ЗАГЛАВНЫМИ буквами, переносами строк и двойными пробелами
        // (как из вставки в multiline-поле) должна дать ТУ ЖЕ энтропию, что канон.
        let canon = "abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon about";
        let messy = "Abandon  ABANDON\nabandon\tabandon abandon abandon \
                     abandon abandon abandon abandon abandon About";
        let a = entropy_of(&parse_mnemonic(canon).expect("канон"));
        let b = entropy_of(&parse_mnemonic(messy).expect("грязная валидная фраза принимается"));
        assert_eq!(a, b, "регистр/пробелы/переносы нормализованы к той же личности");
    }

    #[test]
    fn roundtrip_entropy_mnemonic() {
        let m = generate_mnemonic();
        let e = entropy_of(&m);
        let m2 = mnemonic_of_entropy(&e);
        assert_eq!(m.to_string(), m2.to_string(), "энтропия ↔ фраза обратимы");
    }
}
