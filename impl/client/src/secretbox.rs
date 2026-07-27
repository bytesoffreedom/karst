//! At-rest шифрование client-секретов.
//!
//! `Argon2id(passphrase, salt)` → мастер-ключ (выводится ОДИН раз на процесс),
//! `XChaCha20-Poly1305` со СВЕЖИМ random 24-байтным nonce на КАЖДУЮ запись.
//! 192-битный nonce делает случайную свежесть безопасной без счётчика — критично,
//! т.к. `sessions.dat` перезаписывается на каждую отправку/приём под ФИКСИРОВАННЫМ
//! ключом (повтор nonce = катастрофа keystream-reuse).
//!
//! # Что это защищает — и что НЕТ (честно):
//! Защищает **ХОЛОДНЫЙ диск**: украденный ноутбук, бэкап, синхронизированный
//! `~/.config`. НЕ защищает работающий процесс: пароль из env читаем из
//! `/proc/<pid>/environ` живого хоста → дыру «живая принимающая цепочка на диске»
//! при ГОРЯЧЕЙ компрометации это НЕ закрывает. Заявляем только cold-disk.
//!
//! Формат blob: `MAGIC(4) ‖ nonce(24) ‖ AEAD-ciphertext`. Версионный magic: файл
//! без него → явная ошибка «нужен re-init» (без тихой авто-миграции).

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// Версионный префикс: меняем при смене формата/AEAD. `MSC1` = v1.
pub(crate) const MAGIC: &[u8; 4] = b"KRS1";
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 4 + NONCE_LEN;

/// Свежая 16-байтная соль (не секрет; уникальна на установку, пишется plaintext).
pub fn random_salt() -> [u8; 16] {
    use chacha20poly1305::aead::rand_core::RngCore;
    let mut s = [0u8; 16];
    OsRng.fill_bytes(&mut s);
    s
}

/// Мастер-ключ, выведенный из пароля. Держите ОДИН на процесс (Argon2id дорог) и
/// переиспользуйте для всех secret-файлов. `Clone` дёшев (32 байта) — один
/// vault-ключ раздаётся всем аккаунтам (`Vault::account`), переключение бесплатно.
#[derive(Clone)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    /// `Argon2id(passphrase, salt)`. `salt` НЕ секрет (лежит рядом plaintext), но
    /// должен быть уникален на установку (≥ 8 байт). Дорогой вызов — один раз.
    pub fn derive(passphrase: &[u8], salt: &[u8]) -> Result<Self, String> {
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(passphrase, salt, &mut key)
            .map_err(|e| format!("argon2: {e}"))?;
        Ok(MasterKey(key))
    }

    /// Wrap raw 32 bytes as a key (for keys carried INSIDE a sealed slot, e.g. the Tier-2
    /// container's per-region keys). Not derived from a password — the bytes are the key.
    pub(crate) fn from_bytes(k: [u8; 32]) -> Self {
        MasterKey(k)
    }

    /// The raw 32 key bytes (only for sealing a region key into a slot; never persisted plaintext).
    pub(crate) fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Зашифровать секрет. СВЕЖИЙ random 24-байтный nonce на каждый вызов.
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); // 192-бит, свежий
        let ct = cipher.encrypt(&nonce, plaintext).expect("XChaCha20-Poly1305 encryption");
        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        out
    }

    /// RAW seal for an OPAQUE fixed-size region (the Tier-2 hidden volume): `nonce(24) ‖ ct`, with NO
    /// magic prefix — so the whole blob is indistinguishable from random (a random nonce + an AEAD
    /// ciphertext is computationally random). The caller pads the plaintext to a FIXED length so the
    /// output size never varies, and treats an `open_raw` failure as "no such volume".
    pub(crate) fn seal_raw(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher.encrypt(&nonce, plaintext).expect("XChaCha20-Poly1305 encryption");
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        out
    }

    /// Open a `seal_raw` blob. `Err` = wrong key OR this region holds no hidden volume (just random) —
    /// the two are indistinguishable, which is the whole point.
    pub(crate) fn open_raw(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        if blob.len() < NONCE_LEN + 16 {
            return Err("no hidden volume".into());
        }
        let nonce = XNonce::from_slice(&blob[..NONCE_LEN]);
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        cipher
            .decrypt(nonce, &blob[NONCE_LEN..])
            .map_err(|_| "no hidden volume / wrong key".to_string())
    }

    /// Расшифровать. `Err` — не наш формат (нужен re-init) ИЛИ неверный пароль/
    /// повреждение (AEAD не сошёлся). Оба различимы по тексту.
    pub fn open(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        if blob.len() < HEADER_LEN || &blob[..4] != MAGIC {
            return Err("не KARST-шифр at-rest (несовместимый формат — нужен re-init?)".into());
        }
        let nonce = XNonce::from_slice(&blob[4..HEADER_LEN]);
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        cipher
            .decrypt(nonce, &blob[HEADER_LEN..])
            .map_err(|_| "неверный пароль или повреждённый файл".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"unique-install-salt";

    #[test]
    fn roundtrip_with_correct_passphrase() {
        let k = MasterKey::derive(b"correct horse", SALT).unwrap();
        let blob = k.seal(b"secret key material");
        assert_eq!(k.open(&blob).unwrap(), b"secret key material");
    }

    /// Несущее: неверный пароль → AEAD-ОТКАЗ, не тихий мусор.
    #[test]
    fn wrong_passphrase_fails_not_garbage() {
        let good = MasterKey::derive(b"correct horse", SALT).unwrap();
        let bad = MasterKey::derive(b"wrong horse", SALT).unwrap();
        let blob = good.seal(b"secret key material");
        assert!(bad.open(&blob).is_err(), "неверный пароль должен ОТКАЗАТЬ, не вернуть мусор");
    }

    /// Несущее (не no-op): на диске нет открытых байтов секрета. Та же форма, что
    /// wire_bytes_are_ciphertext для Noise — ловит «случайно записали plaintext».
    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let k = MasterKey::derive(b"pw", SALT).unwrap();
        let secret = b"BOBS-PRIVATE-RATCHET-KEY-32bytes";
        let blob = k.seal(secret);
        assert!(
            !blob.windows(secret.len()).any(|w| w == secret),
            "открытый секрет не должен присутствовать в blob"
        );
    }

    /// Ветка НЕ-нашего формата (нет magic) → ошибка «re-init», отдельная от
    /// AEAD-провала. Пиннит поведение версионного magic (миграция pre-at-rest).
    #[test]
    fn missing_magic_is_reinit_error_not_aead() {
        let k = MasterKey::derive(b"pw", SALT).unwrap();
        let plaintext_era = b"raw pre-at-rest secret bytes with no MSC1 header";
        let err = k.open(plaintext_era).unwrap_err();
        assert!(err.contains("re-init"), "чужой формат → явная ошибка re-init, дано: {err}");
    }

    /// Несущее: два seal ОДИНАКОВОГО текста → РАЗНЫЕ nonce/ciphertext. Пиннит
    /// свежий-nonce-на-запись (фикс.ключ + повтор nonce = keystream-reuse).
    #[test]
    fn identical_plaintext_yields_fresh_nonce() {
        let k = MasterKey::derive(b"pw", SALT).unwrap();
        let a = k.seal(b"same session state");
        let b = k.seal(b"same session state");
        assert_ne!(&a[4..HEADER_LEN], &b[4..HEADER_LEN], "nonce должен быть свежим на каждую запись");
        assert_ne!(a, b, "шифртекст не должен повторяться при одинаковом plaintext");
    }
}
