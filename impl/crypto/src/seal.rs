//! Гибридный (X25519 + ML-KEM-768) sealed-box для СКЕЛЕТА.
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
//! - forward secrecy и Double Ratchet (ключ выводится из СТАТИЧЕСКИХ ключей
//!   получателя — компрометация его секретов раскрывает все прошлые конверты).
//!
//! # Постквантовая защита ЕСТЬ (PRIV-3), и границу надо назвать точно
//!
//! Ключ AEAD выводится из ДВУХ секретов: эфемерный X25519 против статического
//! `ik` получателя И ML-KEM-768 против его долгоживущего `kem_ek`. Слот
//! `pq_shared` в `derive_key` был оставлен заранее именно под это — добавление
//! оказалось заполнением слота, а не переписью.
//!
//! Что это ЗАКРЫЛО: harvest-now-decrypt-later против социального графа.
//! Противник, записавший opener сегодня, больше не восстановит «кто первым
//! написал кому», сломав один X25519 квантовым компьютером — оба секрета нужны
//! одновременно, а ML-KEM-768 квантовому перебору не поддаётся.
//!
//! Что это НЕ закрыло, и это не мелкая оговорка: **forward secrecy тут по-
//! прежнему нет.** Оба ключа получателя долгоживущие (одноразовый KEM-ключ
//! использовать нельзя — какой юнит взят, записано ВНУТРИ запечатанного
//! конверта, см. поле `kem_ct`), поэтому кто позже получит секретный материал
//! аккаунта, расшифрует записанные openers. Стало не хуже: классическая
//! половина всегда обладала этим свойством. Изменилось то, что одного
//! квантового компьютера без компрометации больше не хватает.
//!
//! Sender-auth по-прежнему ноль, и это НЕ дефект: именно отсутствие подписи
//! отправителя делает конверт анонимным для реле. Кто написал на самом деле,
//! говорит только внутренний PQXDH.
//!
//! Назначение остальной части — доказать, что путь сообщения (admission §7 ↔
//! E2E) компонуется. Настоящий E2E-слой — PQXDH + Double Ratchet.

use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport, Kem, TryKeyInit};
use ml_kem::{Ciphertext, DecapsulationKey, EncapsulationKey, MlKem768};

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

    /// Static-static DH that REJECTS a non-contributory result — i.e. a peer point of small
    /// order, for which the shared secret is all-zero and therefore KNOWN to everyone. This is
    /// the guard `node::mailbox_owner_ok` already applies to the fetch proof, lifted into one
    /// place so every PROTOCOL DH can use it (CRYPTO-06).
    ///
    /// Why it matters most in the ratchet: an active adversary who knows the current state can
    /// offer a small-order ratchet key so the DH step contributes NOTHING, stripping the fresh
    /// entropy that gives post-compromise security (healing). In PQXDH the ML-KEM leg and the
    /// other DH legs blunt a single zero leg, but a zero leg is never legitimate — reject it.
    ///
    /// `None` = non-contributory (constant-time check via `was_contributory`).
    pub fn dh_checked(&self, peer: &PublicKey) -> Option<[u8; 32]> {
        let shared = self.secret.diffie_hellman(peer);
        shared.was_contributory().then(|| shared.to_bytes())
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
    /// **ML-KEM-768 ciphertext to the recipient's LONG-LIVED encapsulation key** (PRIV-3).
    ///
    /// Long-lived and not the one-time KEM key, and that is forced rather than chosen: which
    /// one-time unit a sender used is recorded in `opk_pub` INSIDE the sealed key agreement, so a
    /// recipient cannot know which one-time secret to decapsulate with until it has already opened
    /// the seal. The inner handshake has no such problem (it reads the transcript after opening) and
    /// does use the one-time key — see `pqxdh::initiate_key_agreement`, CRYPTO-33.
    ///
    /// The honest consequence, stated where the field is: this layer is NOT forward-secret. Someone
    /// who later obtains the account's long-lived KEM secret can decapsulate recorded openers and
    /// recover who first wrote to whom. That is the same exposure the classical half already had
    /// (an ephemeral X25519 against a STATIC identity key), so nothing got weaker — what changed is
    /// that a quantum adversary with no secret at all no longer suffices, which is precisely the
    /// harvest-now-decrypt-later threat this envelope hides the social graph from.
    pub kem_ct: Vec<u8>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Вывести ключ AEAD из общего секрета — гибрид X25519 + ML-KEM-768.
///
/// `pq_shared` больше НЕ пуст: слот, оставленный под ML-KEM, заполнен (PRIV-3). Порядок в `ikm`
/// фиксирован (classical, затем PQ) и является частью формата: перестановка даёт другой ключ и
/// молча ломает совместимость, поэтому она обязана быть сломом версии, а не правкой.
///
/// Оба публичных ключа (получателя и эфемерный отправителя) связываются в `info` — иначе конверт
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

/// Дополнительные аутентифицируемые данные — связывающие ключи И PQ-шифртекст.
///
/// `kem_ct` входит сюда намеренно: без этого он остаётся неаутентифицированным полем на проводе.
/// Подменённый `kem_ct` дал бы другой `pq_shared`, то есть другой AEAD-ключ, и конверт просто не
/// открылся бы — но «не открылся» и «отвергнут как подделанный» это разные вещи для того, кто
/// потом читает лог. Связав его, мы получаем ровно одну причину отказа.
fn aad(recipient_pub: &[u8; 32], ephemeral_pub: &[u8; 32], kem_ct: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(64 + kem_ct.len());
    a.extend_from_slice(recipient_pub);
    a.extend_from_slice(ephemeral_pub);
    a.extend_from_slice(kem_ct);
    a
}

/// A recipient's ML-KEM half for the hybrid seal, kept OPAQUE (PRIV-3).
///
/// Exists so callers outside this crate never have to name an `ml_kem` type. That is not tidiness:
/// the moment `DecapsulationKey<MlKem768>` appears in another crate's struct field, that crate needs
/// its own `ml-kem` dependency pinned to a matching version, and a KEM upgrade turns into a
/// multi-crate change instead of a change here. The real account path uses `pqxdh::Account`'s own
/// key; this is for the skeleton path, which has no bundle to publish one in.
pub struct SealKemKeys {
    dk: DecapsulationKey<MlKem768>,
    ek: Vec<u8>,
}

impl SealKemKeys {
    /// Wrap an EXISTING decapsulation key — for a recipient whose KEM key is derived, not minted.
    ///
    /// The skeleton path needs this: its recipient identity comes from the recovery phrase, so its
    /// KEM key has to come from the same seed. A freshly generated one cannot work at all — the
    /// sender would have no way to learn it, and the envelope would authenticate and never open.
    pub fn from_dk(dk: DecapsulationKey<MlKem768>) -> Self {
        let ek = dk.encapsulation_key().to_bytes().as_slice().to_vec();
        SealKemKeys { dk, ek }
    }

    pub fn generate() -> Self {
        let (dk, _ek) = <MlKem768 as Kem>::generate_keypair();
        let ek = dk.encapsulation_key().to_bytes().as_slice().to_vec();
        SealKemKeys { dk, ek }
    }

    /// The encapsulation key a sender needs — the public half.
    pub fn ek(&self) -> &[u8] {
        &self.ek
    }

    /// Open a seal addressed to `identity` and these KEM keys.
    pub fn open(&self, seal: &SkeletonSeal, identity: &Identity) -> Option<Vec<u8>> {
        seal.open(identity, &self.dk)
    }
}

impl SkeletonSeal {
    /// Запечатать `plaintext` для получателя: X25519 `recipient_pub` + ML-KEM `recipient_kem_ek`.
    ///
    /// `recipient_kem_ek` — долгоживущий `kem_ek` из bundle получателя (см. поле `kem_ct` о том,
    /// почему именно долгоживущий, а не одноразовый). Возвращает `Err`, а не паникует, потому что
    /// это ключ С ПРОВОДА: подпись bundle покрывает его, но подпись ничего не говорит о том, что
    /// байты разбираются как ML-KEM-ключ — тот же урок, что CRYPTO-08.
    pub fn seal(
        recipient_pub: &PublicKey,
        recipient_kem_ek: &[u8],
        plaintext: &[u8],
    ) -> Result<SkeletonSeal, String> {
        let ek = <EncapsulationKey<MlKem768> as TryKeyInit>::new_from_slice(recipient_kem_ek)
            .map_err(|_| "recipient KEM key is malformed".to_string())?;
        let (kem_ct_arr, pq_shared) = ek.encapsulate();
        let kem_ct = kem_ct_arr.as_slice().to_vec();

        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_pub = PublicKey::from(&ephemeral);
        let classical_dh = ephemeral.diffie_hellman(recipient_pub);

        let rp = recipient_pub.to_bytes();
        let ep = ephemeral_pub.to_bytes();
        let key = derive_key(classical_dh.as_bytes(), pq_shared.as_slice(), &rp, &ep);
        let cipher = ChaCha20Poly1305::new(&key);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload { msg: plaintext, aad: &aad(&rp, &ep, &kem_ct) },
            )
            .expect("AEAD encryption");

        Ok(SkeletonSeal { ephemeral_pub: ep, kem_ct, nonce: nonce_bytes, ciphertext: ct })
    }

    /// Расшифровать своим статическим секретом. `None` — если AEAD не сошёлся
    /// (подмена/повреждение — ровно то, что ловит тест разделения слоёв).
    pub fn open(
        &self,
        recipient: &Identity,
        kem_dk: &DecapsulationKey<MlKem768>,
    ) -> Option<Vec<u8>> {
        let eph = PublicKey::from(self.ephemeral_pub);
        let classical_dh = recipient.secret.diffie_hellman(&eph);
        // A wire-supplied ciphertext of the wrong length is a `None`, not a panic — same rule as
        // the encapsulation key above, from the other direction.
        let ct: Ciphertext<MlKem768> = Array::try_from(self.kem_ct.as_slice()).ok()?;
        let pq_shared = kem_dk.decapsulate(&ct);
        let rp = recipient.public.to_bytes();
        let key = derive_key(classical_dh.as_bytes(), pq_shared.as_slice(), &rp, &self.ephemeral_pub);
        let cipher = ChaCha20Poly1305::new(&key);
        cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad(&rp, &self.ephemeral_pub, &self.kem_ct),
                },
            )
            .ok()
    }
}

/// **The seal is hybrid, and both halves are load-bearing** (PRIV-3).
///
/// The point of adding ML-KEM here is a specific adversary: one who records an opener today and
/// breaks X25519 with a quantum computer later, recovering who first wrote to whom. That claim is
/// only true if the PQ half genuinely gates decryption — if the classical secret alone still opened
/// the envelope, the field would be decoration and the claim would be false while looking true.
#[cfg(test)]
mod the_seal_needs_both_halves {
    use super::*;

    fn recipient() -> (Identity, SealKemKeys) {
        (Identity::generate(), SealKemKeys::generate())
    }

    #[test]
    fn a_round_trip_works_with_both_keys() {
        let (id, kem) = recipient();
        let sealed = SkeletonSeal::seal(&id.public, kem.ek(), b"who wrote to whom").expect("seals");
        assert_eq!(kem.open(&sealed, &id).expect("opens"), b"who wrote to whom");
    }

    /// **The PQ half gates decryption.** Holding the X25519 identity and NOT the KEM secret must not
    /// be enough — that is the whole claim.
    ///
    /// Discriminating: pass an empty `pq_shared` in `derive_key` (the pre-PRIV-3 behaviour) and this
    /// goes green again, because the classical secret would once more be sufficient.
    #[test]
    fn the_x25519_secret_alone_does_not_open_it() {
        let (id, kem) = recipient();
        let sealed = SkeletonSeal::seal(&id.public, kem.ek(), b"social graph").expect("seals");
        let wrong_kem = SealKemKeys::generate();
        assert!(
            wrong_kem.open(&sealed, &id).is_none(),
            "the envelope opened with the right X25519 identity and the WRONG ML-KEM secret. The \
             post-quantum half is then decoration: an adversary who breaks X25519 alone still \
             recovers who first wrote to whom, which is exactly the harvest-now-decrypt-later \
             threat this layer exists to stop."
        );
    }

    /// And the classical half still gates it too — a hybrid that quietly stopped using X25519 would
    /// be a downgrade wearing an upgrade's name.
    #[test]
    fn the_kem_secret_alone_does_not_open_it() {
        let (id, kem) = recipient();
        let sealed = SkeletonSeal::seal(&id.public, kem.ek(), b"social graph").expect("seals");
        let other = Identity::generate();
        assert!(kem.open(&sealed, &other).is_none(), "the wrong X25519 identity opened the seal");
    }

    /// `kem_ct` is authenticated, not merely used. Swapping it must be a clean AEAD failure.
    #[test]
    fn a_substituted_kem_ciphertext_is_refused() {
        let (id, kem) = recipient();
        let mut sealed = SkeletonSeal::seal(&id.public, kem.ek(), b"x").expect("seals");
        let other = SkeletonSeal::seal(&id.public, kem.ek(), b"y").expect("seals");
        sealed.kem_ct = other.kem_ct;
        assert!(kem.open(&sealed, &id).is_none(), "a swapped KEM ciphertext was accepted");
    }

    /// A malformed KEM key off the wire is an error, never a panic (the CRYPTO-08 lesson, applied
    /// to the new field): a contact signs its own bundle, so a signature says nothing about whether
    /// these bytes parse.
    #[test]
    fn a_malformed_recipient_kem_key_is_refused_not_panicked() {
        let id = Identity::generate();
        assert!(SkeletonSeal::seal(&id.public, &[7u8; 3], b"x").is_err());
        assert!(SkeletonSeal::seal(&id.public, &[], b"x").is_err());
    }

    /// A malformed ciphertext ON the way in is likewise a `None`.
    #[test]
    fn a_malformed_kem_ciphertext_is_refused_not_panicked() {
        let (id, kem) = recipient();
        let mut sealed = SkeletonSeal::seal(&id.public, kem.ek(), b"x").expect("seals");
        sealed.kem_ct = vec![1u8; 5];
        assert!(kem.open(&sealed, &id).is_none());
    }
}
