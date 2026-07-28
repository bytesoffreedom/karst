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

/// HKDF-домен вывода ПРОКСИ-личности ИЗ ЕЁ СОБСТВЕННОГО секрета — НЕ из фразы (#207, A6-4).
///
/// История: раньше здесь стоял `derive_proxy(entropy, index)` — прокси были HD-потомками той
/// же фразы по индексу, а «сжигание» прокси (`Store::set_proxy_active`) только гасило флаг
/// `active` в реестре. Ключи прокси оставались выводимы из фразы НАВСЕГДА: тот, у кого есть
/// 12 слов, мог заново вычислить закрытый ключ ЛЮБОГО прошлого индекса, сверить его с историей
/// relay-логов, перечислить ещё не созданные прокси наперёд и связать личности, которые UI
/// показывал как независимо уничтоженные. «Сжигание» было эксплуатационной пометкой, а не
/// уничтожением — то есть ничем не отличалось от простого «перестать пользоваться».
///
/// Фикс: у каждого прокси — свой случайный 32-байтный секрет, который минтится
/// (`OsRng`) при создании и живёт ТОЛЬКО в запечатанном реестре (`Store::create_proxy`,
/// `store.rs`), никогда не выводится из фразы. Сжигание удаляет запись и секрет из
/// реестра целиком — после этого личность не восстановит НИКТО, включая владельца фразы,
/// потому что взять её неоткуда. Отсюда честное следствие: фраза восстанавливает КОРЕНЬ
/// (`derive`, выше), но НЕ прокси — «recoverable» и «destroyable» это один и тот же вопрос,
/// и это дизайн, не баг (см. `docs/design/proxy-identity.md`).
const HKDF_PROXY_SECRET_INFO: &[u8] = b"KARST-proxy-secret-derive-v1";

/// Вывести прокси-личность из её собственного случайного секрета (см. `HKDF_PROXY_SECRET_INFO`
/// выше). Раскладка та же (seal ‖ account), что у `derive` — прокси остаётся полноценной сетевой
/// личностью, — но домен HKDF свой, отдельный и от корневого `derive`, и от старого (удалённого)
/// `derive_proxy(entropy, index)`, так что вывод прокси никогда не совпадёт ни с корнем, ни со
/// значением, которое давал прежний HD-контракт.
///
/// НЕ заморожен как контракт совместимости, в отличие от `derive`: секрет — сам по себе
/// единственная резервная копия (он живёт только в сожжённом виде в `proxies.dat`), никто не
/// записывает его на бумаге вручную, поэтому смена этой функции в будущем осиротит только те
/// секреты, которые ещё не были подставлены сюда — не миллион розданных фраз.
pub fn derive_proxy_from_secret(secret: &[u8; 32]) -> DerivedIdentity {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut okm = [0u8; 160];
    hk.expand(HKDF_PROXY_SECRET_INFO, &mut okm).expect("160 ≤ 255*32");
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

    /// Прокси-личность зависит ТОЛЬКО от её случайного секрета, не от фразы: тот же секрет (даже
    /// под другим корнем) → тот же IK/seal, разные секреты → разные личности, и ни один прокси не
    /// совпадает с корневой личностью, выведенной из этой же фразы. Это ровно то поведение, на
    /// котором держится #207 — если бы вывод прокси хоть как-то зависел от `entropy`, секрет можно
    /// было бы восстановить по фразе, и сжигание перестало бы что-либо уничтожать.
    #[test]
    fn proxy_identity_depends_only_on_its_own_secret_not_on_the_phrase() {
        let secret_a = [11u8; 32];
        let secret_b = [22u8; 32];

        let a1 = derive_proxy_from_secret(&secret_a);
        let a2 = derive_proxy_from_secret(&secret_a);
        assert_eq!(
            a1.account.identity_public(),
            a2.account.identity_public(),
            "тот же секрет → та же личность (иначе прокси нельзя было бы переоткрыть)"
        );
        assert_eq!(a1.seal.public.to_bytes(), a2.seal.public.to_bytes());

        let b = derive_proxy_from_secret(&secret_b);
        assert_ne!(
            a1.account.identity_public(),
            b.account.identity_public(),
            "разные секреты → разные личности"
        );

        // Корень, выведенный из фразы (ЛЮБОЙ фразы), никогда не совпадает с прокси: секрет
        // прокси не зависит от энтропии фразы вообще, домены полностью разделены.
        let root = derive(&[0u8; 16]);
        assert_ne!(
            a1.account.identity_public(),
            root.account.identity_public(),
            "прокси != корень, даже случайно"
        );
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
