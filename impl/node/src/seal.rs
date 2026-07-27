//! Classical-only E2E-конверт для СКЕЛЕТА.
//!
//! # ЭТО НЕ §2.1. Явно и громко:
//!
//! `SkeletonSeal` — sealed-box (эфемерный X25519 → статический ключ получателя,
//! HKDF-SHA256 → ChaCha20-Poly1305). У него **НЕТ**:
//! - **аутентификации отправителя.** Sealed-box даёт Бобу конфиденциальность,
//!   но НЕ говорит, что сообщение от Alice — запечатать Бобу может кто угодно,
//!   кто дотянулся до relay. Настоящий §2.1 (X3DH/PQXDH) аутентифицирует
//!   отправителя её долговременным ключом; здесь sender-auth ноль.
//!   Следствие: admission (§7) аутентифицирует Alice ПЕРЕД RELAY, а не перед
//!   Бобом — это разные стороны; уверенность получателя может дать только
//!   E2E-слой, которого тут (пока) нет;
//! - forward secrecy и Double Ratchet (ключ выводится из статического ключа
//!   получателя — компрометация его секрета раскрывает все прошлые сообщения);
//! - постквантовой защиты — а §2.1 существует ИМЕННО ради harvest-now-decrypt-
//!   later: пассивный противник пишет шифртекст сегодня и ломает X25519
//!   квантовым компьютером потом. Этот конверт этой угрозе НЕ противостоит.
//!
//! Назначение — только доказать, что путь сообщения (admission §7 ↔ E2E)
//! компонуется. Настоящий слой — PQXDH (X25519 + ML-KEM) + Double Ratchet.
//!
//! **Отложено по выбору, это НЕ внешняя стена.** В отличие от threshold-ring
//! аудита и RLN-zk-контура, постквантовый KEM в Rust ДОСТУПЕН сегодня
//! (`ml-kem`, FIPS 203) вместе с `x25519-dalek` — PQXDH реализуем без внешних
//! блокеров, просто не в этом срезе. KDF ниже уже оформлен со слотом под
//! `pq_shared`, чтобы добавление ML-KEM было заполнением слота, не переписью.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// Статический идентификатор получателя (для скелета — долгоживущий X25519).
/// Настоящий §2.1 заменит на prekey-bundle.
#[derive(Clone)]
pub struct Identity {
    secret: StaticSecret,
    pub public: PublicKey,
}

impl Identity {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Identity { secret, public }
    }

    /// Сериализовать секрет для хранения. **ВНИМАНИЕ:** это приватный ключ в
    /// ОТКРЫТОМ виде. Вызывающий обязан писать его под 0600; at-rest шифрование
    /// (парольный KDF) — отложенная защита, здесь не реализована.
    pub fn to_secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Восстановить identity из сохранённого секрета.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Identity { secret, public }
    }

    /// Static-static Diffie–Hellman с чужим публичным ключом. Основа
    /// fetch-auth (§7-владение mailbox): `X25519(id_sec, peer)` симметрично
    /// `X25519(peer_sec, id_pub)`, поэтому обе стороны получают общий секрет.
    /// НЕ раскрывает секрет — отдаёт только общий DH. Второе применение
    /// identity-ключа в DH (первое — эфемерно-статический seal); домены
    /// разделены на уровне KDF (`fetch_auth` vs `seal`).
    pub fn dh(&self, peer: &PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(peer).to_bytes()
    }

    /// Key for issuing STATELESS PoW capabilities (slice 4a, the Public door). A
    /// domain-separated hash of the node's static secret, so it is PERSISTENT with the node
    /// key (a PoW cap survives a relay restart) yet never exposes the raw secret. Third use
    /// of the identity key, domain-separated from `seal`/`fetch_auth` by the label.
    pub fn issuer_key(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"KARST-cap-issuer-v1");
        h.update(self.secret.to_bytes());
        h.finalize().into()
    }
}

/// Запечатанное сообщение на проводе.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SkeletonSeal {
    /// Эфемерный публичный ключ отправителя.
    pub ephemeral_pub: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Вывести ключ AEAD из общего секрета. Слот `pq_shared` пуст (classical-only);
/// добавление ML-KEM = передать сюда непустой срез. Оба публичных ключа
/// (получателя и эфемерный отправителя) связываются в `info` — иначе конверт
/// перепривязываем (тот же урок «связать весь транскрипт», что в Fiat–Shamir).
fn derive_key(
    classical_dh: &[u8; 32],
    pq_shared: &[u8],
    recipient_pub: &[u8; 32],
    ephemeral_pub: &[u8; 32],
) -> Key {
    let mut ikm = Vec::with_capacity(32 + pq_shared.len());
    ikm.extend_from_slice(classical_dh);
    ikm.extend_from_slice(pq_shared); // пусто сейчас; слот под ML-KEM
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut info = Vec::new();
    info.extend_from_slice(b"KARST-skeleton-seal-v1");
    info.extend_from_slice(recipient_pub);
    info.extend_from_slice(ephemeral_pub);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("32 within HKDF output limit");
    *Key::from_slice(&okm)
}

/// Дополнительные аутентифицируемые данные — те же связывающие ключи.
fn aad(recipient_pub: &[u8; 32], ephemeral_pub: &[u8; 32]) -> Vec<u8> {
    let mut a = Vec::with_capacity(64);
    a.extend_from_slice(recipient_pub);
    a.extend_from_slice(ephemeral_pub);
    a
}

impl SkeletonSeal {
    /// Запечатать `plaintext` для получателя с публичным ключом `recipient_pub`.
    pub fn seal(recipient_pub: &PublicKey, plaintext: &[u8]) -> SkeletonSeal {
        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_pub = PublicKey::from(&ephemeral);
        let classical_dh = ephemeral.diffie_hellman(recipient_pub);

        let rp = recipient_pub.to_bytes();
        let ep = ephemeral_pub.to_bytes();
        let key = derive_key(classical_dh.as_bytes(), &[], &rp, &ep);
        let cipher = ChaCha20Poly1305::new(&key);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload { msg: plaintext, aad: &aad(&rp, &ep) },
            )
            .expect("AEAD encryption");

        SkeletonSeal { ephemeral_pub: ep, nonce: nonce_bytes, ciphertext: ct }
    }

    /// Расшифровать своим статическим секретом. `None` — если AEAD не сошёлся
    /// (подмена/повреждение — ровно то, что ловит тест разделения слоёв).
    pub fn open(&self, recipient: &Identity) -> Option<Vec<u8>> {
        let eph = PublicKey::from(self.ephemeral_pub);
        let classical_dh = recipient.secret.diffie_hellman(&eph);
        let rp = recipient.public.to_bytes();
        let key = derive_key(classical_dh.as_bytes(), &[], &rp, &self.ephemeral_pub);
        let cipher = ChaCha20Poly1305::new(&key);
        cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload { msg: &self.ciphertext, aad: &aad(&rp, &self.ephemeral_pub) },
            )
            .ok()
    }
}
