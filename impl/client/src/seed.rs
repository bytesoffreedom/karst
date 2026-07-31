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
//! moment a person writes down the 24 words, `mnemonic → IK` is fixed. Any
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

/// 32 bytes of entropy = 24 words.
///
/// CRYPTO-32: this used to be 16 bytes (12 words). Everything derived from the phrase is capped
/// by the phrase's entropy — including ML-KEM-768, which claims Category 3 (~192 bits). A
/// 128-bit root made that claim untrue: there is no reason to break a lattice when the seed can
/// be searched instead. The PQ leg exists to defeat "record now, decrypt later", which is
/// exactly where the mismatch hurts — traffic captured today stays captured until the root falls.
///
/// The cost is 24 words on paper instead of 12. That is the standard choice for a serious
/// wallet, and it is taken now, while there are no users and changing the format is free.
pub const ENTROPY_BYTES: usize = 32;

/// Words in a phrase — a function of the entropy width (BIP-39: 32 bytes → 24 words).
pub const PHRASE_WORDS: usize = 24;

/// The all-`abandon` phrase for demo seeders and visual-verification tools — **one copy, so it
/// cannot rot in several places at once**.
///
/// It already did. `PHRASE_WORDS` moved 12 → 24 when the root widened to 256 bits, and two
/// examples kept their 12-word literal and panicked on every run — including the one the GUI
/// notes recommend as the FAST path for visual checks. Nothing failed: examples compile without
/// being executed, so a runtime-only break in one is invisible to `cargo test` and to CI.
///
/// Keeping the phrase here, with the test below, means the next width change breaks a unit test
/// in this file instead of two tools nobody runs until they need them.
///
/// NOT a product constant and never a default: it is the canonical BIP-39 all-zero-entropy
/// phrase, public in every wordlist, and anything derived from it is public by construction.
pub const DEMO_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon abandon abandon abandon abandon art";

/// CRYPTO-32, enforced at COMPILE time: the root must not be weaker than the strongest primitive
/// derived from it. ML-KEM-768 claims Category 3 (~192 bits); everything here is deterministic in
/// the phrase, so a narrower root would silently make that claim false. Narrowing `ENTROPY_BYTES`
/// therefore fails the BUILD rather than a test somebody could ignore.
const ROOT_COVERS_ML_KEM_768: () = assert!(ENTROPY_BYTES * 8 >= 192);
const _: () = ROOT_COVERS_ML_KEM_768;

/// Выведенные из фразы секреты. Оба детерминированы от одной энтропии.
pub struct DerivedIdentity {
    pub seal: Identity,
    pub account: Account,
}

/// Three DISTINCT word positions (0-based, in 0..PHRASE_WORDS) to check a backup against during
/// account creation. Random rather than fixed, so a person actually consults what they wrote down
/// instead of memorising the answer. An "I wrote it down" checkbox is theatre; this asks for the
/// specific words (see the creation UX).
pub fn confirm_positions() -> [usize; 3] {
    let mut rng = OsRng;
    loop {
        let p = [
            (rng.next_u32() as usize) % PHRASE_WORDS,
            (rng.next_u32() as usize) % PHRASE_WORDS,
            (rng.next_u32() as usize) % PHRASE_WORDS,
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
    Mnemonic::from_entropy(&entropy).expect("32 bytes of entropy → a valid 24-word phrase")
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
        .map_err(|e| format!("invalid recovery phrase: {e}"))?;
    if m.word_count() != PHRASE_WORDS {
        return Err(format!("expected {PHRASE_WORDS} words, not {}", m.word_count()));
    }
    Ok(m)
}

/// Энтропия фразы (16 байт) — корень, который кладётся на диск.
pub fn entropy_of(m: &Mnemonic) -> [u8; ENTROPY_BYTES] {
    let (arr, len) = m.to_entropy_array();
    debug_assert_eq!(len, ENTROPY_BYTES, "24 words → 32 bytes of entropy");
    arr[..ENTROPY_BYTES].try_into().expect("16 bytes")
}

/// Восстановить фразу из энтропии (для экрана «показать фразу восстановления»).
pub fn mnemonic_of_entropy(entropy: &[u8; ENTROPY_BYTES]) -> Mnemonic {
    Mnemonic::from_entropy(entropy).expect("32 bytes → a valid 24-word phrase")
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
    // The BIP39 seed and the HKDF output are the whole identity in raw form — both are wiped
    // when this function returns rather than left in freed stack/heap (CRYPTO-09).
    let seed = zeroize::Zeroizing::new(m.to_seed("")); // BIP39 PBKDF2, EMPTY passphrase — part of the contract
    let hk = Hkdf::<Sha256>::new(None, seed.as_ref()); // salt=None (empty)
    let mut okm = zeroize::Zeroizing::new([0u8; 160]);
    hk.expand(HKDF_INFO, okm.as_mut()).expect("160 ≤ 255*32");
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
    let mut okm = zeroize::Zeroizing::new([0u8; 160]);
    hk.expand(HKDF_PROXY_SECRET_INFO, okm.as_mut()).expect("160 ≤ 255*32");
    let seal = Identity::from_secret_bytes(okm[0..32].try_into().expect("32"));
    let account = Account::from_secret_bytes(okm[32..160].try_into().expect("128"));
    DerivedIdentity { seal, account }
}

#[cfg(test)]
mod tests {

    /// The demo phrase parses at the CURRENT width.
    ///
    /// DISCRIMINATING: change `PHRASE_WORDS` (or trim a word from `DEMO_PHRASE`) and this reds
    /// here, in a test that runs, instead of at the moment somebody reaches for a seeding tool
    /// during a visual check and finds it has been broken for weeks.
    #[test]
    fn the_demo_phrase_still_parses_at_the_current_width() {
        let m = parse_mnemonic(DEMO_PHRASE).expect("the demo phrase must parse");
        assert_eq!(
            DEMO_PHRASE.split_whitespace().count(),
            PHRASE_WORDS,
            "the demo phrase drifted from PHRASE_WORDS"
        );
        // And it derives a usable identity, not merely a well-formed word list.
        let _ = derive(&entropy_of(&m)).account.identity_public();
    }

    use super::*;

    /// **Контракт совместимости — НЕ МЕНЯТЬ значения.**
    ///
    /// The vector was regenerated ONCE, deliberately (CRYPTO-32, #193): the root widened from 16
    /// bytes (12 words) to 32 (24 words), so both the test phrase and everything derived from it
    /// are different. No users means no written-down phrases, so nothing was broken. From here
    /// the vector is frozen again.
    ///
    /// Фиксирует
    /// `известная фраза → точный IK`. Если этот тест покраснел не потому, что вы
    /// осознанно ввели НОВЫЙ формат, — вы сломали восстановление у всех, кто уже
    /// записал фразу. (Как `conformance_vectors_match_frozen` в крипто-ядре.)
    #[test]
    fn frozen_derivation_vector() {
        // The standard 24-word BIP39 test phrase (entropy = 32 zero bytes).
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon art";
        let m = parse_mnemonic(phrase).expect("a valid test phrase");
        // Independent of the hex below: the phrase must REALLY carry all-zero entropy of the
        // current width. Regenerating the vector by copying the code's own output would make the
        // hex circular — this arm is what keeps it evidence. A wrong checksum word or a
        // wrong-length phrase fails here, not two asserts later with a confusing diff.
        assert_eq!(entropy_of(&m), [0u8; ENTROPY_BYTES], "the test phrase carries zero entropy");
        let by_entropy = derive(&[0u8; ENTROPY_BYTES]);
        let d = derive(&entropy_of(&m));
        assert_eq!(
            d.account.identity_public(),
            by_entropy.account.identity_public(),
            "the phrase and the raw entropy must derive the same identity"
        );
        let ik = hex::encode(d.account.identity_public());
        let seal_pub = hex::encode(d.seal.public.to_bytes());
        assert_eq!(
            ik, "3d1b5e4595d2999a3aa4497ec42f26516f29eb92adc96f98d590df9610707e57",
            "the IK vector changed — restore is broken for existing phrases"
        );
        assert_eq!(
            seal_pub, "c4007067a2a65902f9070746433dacf0d4a5365d33f0f8cb04affefea52f0b67",
            "the seal vector changed — mailbox ownership is broken"
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
            "the same secret yields the same identity (otherwise a proxy could not be reopened)"
        );
        assert_eq!(a1.seal.public.to_bytes(), a2.seal.public.to_bytes());

        let b = derive_proxy_from_secret(&secret_b);
        assert_ne!(
            a1.account.identity_public(),
            b.account.identity_public(),
            "different secrets yield different identities"
        );

        // Корень, выведенный из фразы (ЛЮБОЙ фразы), никогда не совпадает с прокси: секрет
        // прокси не зависит от энтропии фразы вообще, домены полностью разделены.
        let root = derive(&[0u8; ENTROPY_BYTES]);
        assert_ne!(
            a1.account.identity_public(),
            root.account.identity_public(),
            "a proxy is never the root, not even by accident"
        );
    }

    #[test]
    fn same_phrase_same_identity_different_phrase_different() {
        let a = generate_mnemonic();
        let b = generate_mnemonic();
        assert_ne!(entropy_of(&a), entropy_of(&b), "two generations differ");

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
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon \
                   abandon abandon abandon abandon abandon abandon abandon abandon \
                   abandon abandon abandon abandon abandon abandon art abandon";
        assert!(parse_mnemonic(bad).is_err(), "a broken checksum must be refused");
        // Мусор — тоже.
        assert!(parse_mnemonic("not a mnemonic at all").is_err());
        // Правильная — принимается.
        let good = "abandon abandon abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon abandon art";
        assert!(parse_mnemonic(good).is_ok());
    }

    #[test]
    fn phrase_normalized_over_case_and_whitespace() {
        // Верная фраза с ЗАГЛАВНЫМИ буквами, переносами строк и двойными пробелами
        // (как из вставки в multiline-поле) должна дать ТУ ЖЕ энтропию, что канон.
        let canon = "abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon art";
        let messy = "ABANDON abandon abandon ABANDON abandon abandon ABANDON abandon \
                     abandon ABANDON abandon abandon ABANDON abandon abandon ABANDON \
                     abandon abandon ABANDON abandon abandon ABANDON abandon art";
        let a = entropy_of(&parse_mnemonic(canon).expect("canonical"));
        let b = entropy_of(&parse_mnemonic(messy).expect("a messy but valid phrase is accepted"));
        assert_eq!(a, b, "case, spaces and newlines normalise to the same identity");
    }

    /// CRYPTO-32 (#193): the phrase must not be weaker than the strongest thing derived from it.
    ///
    /// IK, seal and ML-KEM-768 are all deterministic in the phrase's entropy, so its width IS the
    /// strength ceiling. ML-KEM-768 claims Category 3 (~192 bits); a 128-bit root made that claim
    /// false, and it hurts most on the PQ leg, which exists precisely for "record now, decrypt
    /// later".
    ///
    /// Discriminating on the ENTROPY WIDTH rather than the word count: 24 words carrying 16 bytes
    /// (someone widening only the display) would still fail here.
    #[test]
    fn the_root_seed_is_not_weaker_than_ml_kem_768() {
        // The width itself is checked at COMPILE time (see `ROOT_COVERS_ML_KEM_768` next to the
        // constant) — narrowing the root does not fail a test, it fails the build. What is left
        // to check at runtime is that a real phrase carries that entropy, rather than showing
        // more words over the same root.
        let m = generate_mnemonic();
        assert_eq!(m.word_count(), PHRASE_WORDS);
        assert_eq!(entropy_of(&m).len(), ENTROPY_BYTES);
    }

    /// Recovery end to end: whatever `generate` produces must parse back and derive the same
    /// identity. Catches exactly the class the frozen vector exists for — "the phrase was written
    /// down and will not go back in" — but on a FRESH phrase rather than one hard-coded one.
    #[test]
    fn a_generated_phrase_restores_to_the_same_identity() {
        let m = generate_mnemonic();
        assert_eq!(m.word_count(), PHRASE_WORDS);
        let phrase = m.to_string();
        let parsed = parse_mnemonic(&phrase).expect("a freshly generated phrase must parse");
        let a = derive(&entropy_of(&m));
        let b = derive(&entropy_of(&parsed));
        assert_eq!(a.account.identity_public(), b.account.identity_public(), "the IK came back");
        assert_eq!(a.seal.public.to_bytes(), b.seal.public.to_bytes(), "the seal key came back");
    }

    #[test]
    fn roundtrip_entropy_mnemonic() {
        let m = generate_mnemonic();
        let e = entropy_of(&m);
        let m2 = mnemonic_of_entropy(&e);
        assert_eq!(m.to_string(), m2.to_string(), "entropy and phrase round-trip");
    }
}
