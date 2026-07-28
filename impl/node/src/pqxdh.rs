//! §2.1 — PQXDH: аутентифицированное постквантовое СОГЛАСОВАНИЕ КЛЮЧА.
//!
//! Гибрид X3DH + ML-KEM (спека §2.1): `root_key = KDF(classical_DH‖pq_shared)`.
//! Даёт: **аутентификацию отправителя** (долговременный IK_A участвует в DH →
//! только держатель IK_A построит тот же root_key) и **постквантовую защиту**
//! (ML-KEM-768 против harvest-now-decrypt-later). Взломать надо ОБА (гибрид).
//!
//! Этот модуль — ТОЛЬКО согласование ключа: выдаёт `root_key`, которым
//! засевается Double Ratchet (`crate::ratchet`). Шифрованием сообщений
//! занимается ratchet, не этот слой (никакого one-shot AEAD здесь).
//!
//! # Границы среза (явно):
//! - **направленная аутентификация:** Alice→Bob ПРИ подлинном IK_B (вне
//!   канала / §12). НЕ взаимная. Prekey ПОДПИСАН ключом IK (XEdDSA) — подмена
//!   prekey/KEM relay'ем отклоняется явно (`verify_prekey_sig`), а не только fail-closed;
//! - **bundle in-memory** — публикация/фетч prekey у relay (§12) — отдельный срез;
//! - **replay initial-KA** не предотвращается тут (нет one-time-prekey) — но
//!   ratchet поверх сделает повторную установку сессии видимой (см. `ratchet`);
//! - **нет low-order-проверки** трёх X25519-DH — audit-item (для sender-auth не
//!   эксплуатируемо: форжер привязан к подлинному pubkey Alice);
//! - **только 1:1.**
//!
//! # Дисциплина крипты.
//! Примитивы — вендорные (`ml-kem` FIPS 203, `x25519-dalek`, `hkdf`). X3DH-
//! композиция — REFERENCE-код (точная публичная спека, как admission),
//! **НЕ аудирован независимо**. Состязательно протестировано (sender-auth,
//! PQ-нагруженность через различие root_key).

use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport, Kem, TryKeyInit};
use ml_kem::{Ciphertext, DecapsulationKey, EncapsulationKey, MlKem768};
use sha2::Sha256;
use x25519_dalek::PublicKey;

use crate::seal::Identity;

/// Домен KDF — отделён от seal (`KARST-skeleton-seal-v1`), ratchet и fetch-auth.
const DOMAIN: &[u8] = b"KARST-pqxdh-v1";

/// Публичный prekey-bundle получателя — то, что нужно отправителю. Публичный
/// материал (сериализуем для §12 publish/fetch у relay).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PreKeyBundle {
    /// Долговременный identity-ключ (X25519). Он же адрес mailbox.
    pub ik_pub: [u8; 32],
    /// Prekey (X25519), ПОДПИСАН ключом IK (см. `prekey_sig`). Он же начальный
    /// ratchet-ключ получателя.
    pub prekey_pub: [u8; 32],
    /// ML-KEM-768 encapsulation key (~1184 Б).
    pub kem_ek: Vec<u8>,
    /// Optional ONE-TIME prekey for this contact (X25519). When present it adds a fourth
    /// DH term `EK_A × OPK_B` to the root key and is CONSUMED by the recipient, giving the
    /// first message forward secrecy against a later compromise of the long-lived prekey
    /// secret. `None` falls back to the 3-DH agreement unchanged. Appended last (postcard
    /// is positional).
    pub opk_pub: Option<[u8; 32]>,
    /// XEdDSA signature (by the identity key `ik_pub`) over the long-lived prekey material
    /// (`prekey_pub ‖ kem_ek`) — the §2.1 "signed prekey". Lets the sender REJECT a bundle
    /// whose prekey / KEM key a relay substituted, instead of only failing closed later in the
    /// DH agreement. Signed with the SAME X25519 identity key (Signal's XEdDSA), so no second
    /// key and no safety-number change. The one-time prekey is NOT signed. Appended last.
    #[serde(default)]
    pub prekey_sig: Vec<u8>,
    /// The account's public mailbox point `M = m·G` for blinded deposit/fetch key separation
    /// (`crate::blind`). Bound by `prekey_sig` (a relay cannot swap it undetected). The live
    /// drop-box path derives the blinded deposit address from it for established sessions
    /// (`peer.rs` → `blind::deposit_address`). Appended last.
    #[serde(default)]
    pub mailbox_pub: [u8; 32],
}

/// The message the prekey signature covers: a domain tag ‖ the X25519 prekey ‖ the ML-KEM key ‖
/// the mailbox point `M`. All long-lived public materials are bound, so a relay cannot swap the
/// prekey, KEM key, OR the mailbox point undetected.
pub(crate) fn prekey_sig_message(prekey_pub: &[u8; 32], kem_ek: &[u8], mailbox_pub: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(19 + 32 + kem_ek.len() + 32);
    m.extend_from_slice(b"KARST-prekey-sig-v1");
    m.extend_from_slice(prekey_pub);
    m.extend_from_slice(kem_ek);
    m.extend_from_slice(mailbox_pub);
    m
}

impl PreKeyBundle {
    /// Verify the prekey signature against this bundle's `ik_pub`. A sender calls this on a
    /// fetched bundle BEFORE using it: `false` means the relay tampered with the prekey / KEM
    /// key (or the bundle is from an incompatible unsigned version) — do not proceed.
    pub fn verify_prekey_sig(&self) -> bool {
        use xeddsa::Verify;
        let pk = xeddsa::xed25519::PublicKey::from(&PublicKey::from(self.ik_pub));
        let msg = prekey_sig_message(&self.prekey_pub, &self.kem_ek, &self.mailbox_pub);
        let Ok(sig): Result<[u8; 64], _> = self.prekey_sig.as_slice().try_into() else {
            return false; // wrong length = unsigned / incompatible bundle
        };
        pk.verify(&msg, &sig).is_ok()
    }
}

/// Секреты получателя. `accept_key_agreement` восстанавливает root_key.
// Clone lets one logical identity back a per-relay `Peer` each, for multi-homed receive
// (`client::receive_threaded`); every clone carries the same secrets, as a rebuilt-from-seed
// account would.
#[derive(Clone)]
pub struct Account {
    ik: Identity,
    prekey: Identity,
    kem_dk: DecapsulationKey<MlKem768>,
    /// Unconsumed one-time prekey secrets, keyed by their public key. Each seeds at most
    /// one initial agreement, then `accept_key_agreement` deletes it. **In-memory for now**
    /// — this increment is the key-agreement mechanism; the sidecar persistence (kept out
    /// of `account.key`, so the long-lived identity is never at migration risk) and the
    /// relay-side per-fetch distribution that make it end-to-end one-time are the next
    /// increments.
    opks: std::collections::HashMap<[u8; 32], Identity>,
    /// Per-account mailbox secret `m` (Ristretto scalar bytes) for deposit/fetch key SEPARATION
    /// (`crate::blind`). Derived deterministically from the account's own secret material, so it
    /// re-derives from the seed (no separate persistence) and a sender — who lacks that material
    /// — cannot recompute it. Its public `M = m·G` is published in the bundle, and the live
    /// drop-box path fetches blinded boxes with the derived fetch secret for established sessions.
    mailbox_secret: [u8; 32],
}

impl Account {
    pub fn generate() -> Self {
        let (kem_dk, _ek) = MlKem768::generate_keypair();
        let mut acct = Account {
            ik: Identity::generate(),
            prekey: Identity::generate(),
            kem_dk,
            opks: std::collections::HashMap::new(),
            mailbox_secret: [0u8; 32],
        };
        // Derive `m` from the account's OWN secret bytes (same rule as `from_secret_bytes`), so a
        // generated account and one restored from `to_secret_bytes` agree on `M`.
        acct.mailbox_secret = crate::blind::MailboxSecret::derive(&acct.to_secret_bytes()).to_bytes();
        acct
    }

    /// The account's public mailbox point `M = m·G` — published in the bundle so a sender can
    /// derive the blinded deposit addresses (`crate::blind::deposit_address`).
    pub fn mailbox_public(&self) -> [u8; 32] {
        crate::blind::MailboxSecret::from_bytes(&self.mailbox_secret)
            .expect("stored mailbox secret is canonical")
            .public()
    }

    /// The fetch secret `h·m` for one of MY inbound drop-boxes (epoch/direction under the shared
    /// per-session `seed`). Its public key is the box address a sender deposited into; I prove
    /// ownership of the box to the relay with a `blind::FetchOwnershipProof` over this secret.
    pub fn mailbox_fetch_secret(&self, seed: &[u8; 32], epoch: u64, dir: u8) -> [u8; 32] {
        crate::blind::MailboxSecret::from_bytes(&self.mailbox_secret)
            .expect("stored mailbox secret is canonical")
            .fetch_secret(seed, epoch, dir)
    }

    /// Mint a fresh one-time prekey, store its secret, and return its public key — to be
    /// placed in a published bundle. Consumed on first use (see `accept_key_agreement`).
    pub fn add_opk(&mut self) -> [u8; 32] {
        let opk = Identity::generate();
        let pk = opk.public.to_bytes();
        self.opks.insert(pk, opk);
        pk
    }

    /// How many unconsumed one-time prekeys remain (for the batch top-up policy later).
    pub fn opk_count(&self) -> usize {
        self.opks.len()
    }

    /// Public keys of the current unconsumed one-time prekeys — what `publish` advertises.
    pub fn opk_pubs(&self) -> Vec<[u8; 32]> {
        self.opks.keys().copied().collect()
    }

    /// SECRET bytes of the current unconsumed one-time prekeys, for the caller to persist
    /// in a sidecar (kept OUT of `account.key`, so the long-lived identity never migrates).
    /// **These are private keys in the clear** — write under 0600, same care as the account.
    pub fn export_opk_secrets(&self) -> Vec<[u8; 32]> {
        self.opks.values().map(|id| id.to_secret_bytes()).collect()
    }

    /// Load persisted one-time prekey secrets back into the account (see
    /// `export_opk_secrets`). Additive: existing OPKs are kept, so a top-up survives.
    pub fn import_opk_secrets(&mut self, secrets: &[[u8; 32]]) {
        for s in secrets {
            let id = Identity::from_secret_bytes(*s);
            self.opks.insert(id.public.to_bytes(), id);
        }
    }

    /// This account's bundle carrying a specific one-time prekey (must be one of ours, via
    /// `add_opk`). The sender mixes it into the agreement and the recipient consumes it.
    pub fn prekey_bundle_with_opk(&self, opk_pub: [u8; 32]) -> PreKeyBundle {
        PreKeyBundle { opk_pub: Some(opk_pub), ..self.prekey_bundle() }
    }

    /// Сериализовать секреты для персистентности (§2.1-личность стабильна между
    /// запусками). **ВНИМАНИЕ:** это ПРИВАТНЫЕ ключи в открытом виде — ik(32) ‖
    /// prekey(32) ‖ ML-KEM-seed(64). Вызывающий обязан писать под 0600; at-rest
    /// шифрование (парольный KDF) — отложено. НЕ blanket-serde: каждый вынос
    /// секрета на диск умышленен (не утечёт случайно в wire-сообщение).
    /// KEM хранится как 64-байтный seed (FIPS 203 `from_seed`/`to_seed`), не
    /// расширенная форма.
    pub fn to_secret_bytes(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        out[..32].copy_from_slice(&self.ik.to_secret_bytes());
        out[32..64].copy_from_slice(&self.prekey.to_secret_bytes());
        let seed = self.kem_dk.to_seed().expect("KEM dk сгенерирован из seed → Some");
        out[64..].copy_from_slice(seed.as_slice());
        out
    }

    /// Восстановить account из сохранённых секретов (см. `to_secret_bytes`).
    pub fn from_secret_bytes(bytes: &[u8; 128]) -> Self {
        let ik = Identity::from_secret_bytes(bytes[..32].try_into().expect("32"));
        let prekey = Identity::from_secret_bytes(bytes[32..64].try_into().expect("32"));
        let seed = Array::try_from(&bytes[64..]).expect("64-байтный ML-KEM seed");
        let kem_dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        // OPKs are not in `account.key` (see the `opks` field) — a restored account starts
        // with an empty batch. The account.key format is therefore UNCHANGED: no migration
        // of the long-lived identity.
        // The mailbox secret is DERIVED from these same secret bytes (domain-separated), so it
        // re-derives from the seed with no format change and no extra persistence.
        let mailbox_secret = crate::blind::MailboxSecret::derive(bytes).to_bytes();
        Account { ik, prekey, kem_dk, opks: std::collections::HashMap::new(), mailbox_secret }
    }

    /// Долговременный identity-pubkey (адрес/личность получателя).
    pub fn identity_public(&self) -> [u8; 32] {
        self.ik.public.to_bytes()
    }

    /// Sign the code→IK binding for an opt-in discovery record: an XEdDSA signature by the IK over
    /// `(discovery_pub, ik, location, expiry)`. A resolver verifies it (`discovery::verify_binding`)
    /// and thereby trusts that this contact code belongs to this IK — the relay never vouches.
    pub fn sign_discovery(&self, discovery_pub: &[u8; 32], location: &crate::node::RelayDescriptor, expiry: u64, single_use: bool) -> Vec<u8> {
        let msg = crate::discovery::binding_msg(discovery_pub, &self.identity_public(), location, expiry, single_use);
        crate::discovery::sign(&self.ik.to_secret_bytes(), &msg)
    }

    /// Долговременный identity-ключ (для отправки: sender_ik) — внутри крейта,
    /// сессионный слой берёт приватный ключ отсюда.
    pub(crate) fn ik(&self) -> &Identity {
        &self.ik
    }

    /// Prekey-ключ (для приёма: начальный ratchet-ключ получателя).
    pub(crate) fn prekey(&self) -> &Identity {
        &self.prekey
    }

    /// Публичный bundle для отправителя — с XEdDSA-подписью prekey-материала ключом IK.
    pub fn prekey_bundle(&self) -> PreKeyBundle {
        use xeddsa::Sign;
        let prekey_pub = self.prekey.public.to_bytes();
        let kem_ek = self.kem_dk.encapsulation_key().to_bytes().as_slice().to_vec();
        let mailbox_pub = self.mailbox_public();
        // Sign `prekey_pub ‖ kem_ek ‖ M` with the identity key (XEdDSA over the same X25519 key).
        let sk = x25519_dalek::StaticSecret::from(self.ik.to_secret_bytes());
        let signer = xeddsa::xed25519::PrivateKey::from(&sk);
        let prekey_sig: [u8; 64] =
            signer.sign(&prekey_sig_message(&prekey_pub, &kem_ek, &mailbox_pub), rand010::rng());
        let prekey_sig = prekey_sig.to_vec();
        PreKeyBundle {
            ik_pub: self.ik.public.to_bytes(),
            prekey_pub,
            kem_ek,
            opk_pub: None,
            prekey_sig,
            mailbox_pub,
        }
    }

    /// Принять initial key-agreement: восстановить `root_key` и опознать
    /// отправителя. `None` — только если KEM-ct невалидной длины (структурная
    /// ошибка). Аутентификация отправителя проверяется НЕ здесь: неверный IK_A
    /// даёт ДРУГОЙ root_key → первое ratchet-сообщение не расшифруется (AEAD).
    /// Возвращает (root_key, заявленный identity отправителя).
    pub fn accept_key_agreement(&mut self, ka: &KeyAgreement) -> Option<([u8; 32], [u8; 32])> {
        let ik_a = PublicKey::from(ka.ik_a_pub);
        let ek_a = PublicKey::from(ka.ek_a_pub);
        // Зеркало DH отправителя (симметрия static-static X25519).
        let dh1 = self.prekey.dh(&ik_a); // PK_B × IK_A  (аутентификация отправителя)
        let dh2 = self.ik.dh(&ek_a); //     IK_B × EK_A
        let dh3 = self.prekey.dh(&ek_a); //  PK_B × EK_A

        // If the sender used a one-time prekey, find its secret and mirror dh4. A missing
        // OPK (already consumed, or never ours) fails the agreement rather than silently
        // downgrading — the sender committed to it in the transcript, so proceeding without
        // it would derive a different root key anyway.
        let dh4 = match ka.opk_pub {
            Some(opk_pub) => Some(self.opks.get(&opk_pub)?.dh(&ek_a)),
            None => None,
        };

        let ct: Ciphertext<MlKem768> = Array::try_from(ka.kem_ct.as_slice()).ok()?;
        let pq_shared = self.kem_dk.decapsulate(&ct);

        let transcript = transcript(
            &ka.ik_a_pub,
            &self.ik.public.to_bytes(),
            &ka.ek_a_pub,
            &self.prekey.public.to_bytes(),
            &ka.kem_ct,
            ka.opk_pub.as_ref(),
            &ka.mailbox_a_pub,
        );
        let root_key = derive_root_key(&dh1, &dh2, &dh3, dh4.as_ref(), pq_shared.as_slice(), &transcript);
        // Consume the one-time prekey: it must never seed a second agreement, or it is not
        // one-time and the forward-secrecy claim is void.
        if let Some(opk_pub) = ka.opk_pub {
            self.opks.remove(&opk_pub);
        }
        Some((root_key, ka.ik_a_pub))
    }
}

/// Initial key-agreement на проводе (§2.1). Несёт ТОЛЬКО материал согласования
/// (без груза — груз идёт в ratchet-сообщении, приложенном рядом).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyAgreement {
    /// Долговременный identity отправителя (заявленный — аутентифицируется DH1).
    pub ik_a_pub: [u8; 32],
    /// Эфемерный ключ отправителя.
    pub ek_a_pub: [u8; 32],
    /// ML-KEM-768 ciphertext (~1088 Б).
    pub kem_ct: Vec<u8>,
    /// Which one-time prekey the sender used (its public key), so the recipient knows
    /// which OPK secret to mix in and consume. `None` = no OPK was used. Appended last.
    pub opk_pub: Option<[u8; 32]>,
    /// The SENDER's mailbox point `M_A` (`crate::blind`), so the responder can deposit its
    /// replies into the sender's blinded B→A box (the responder never fetches the sender's
    /// bundle, so this is the only channel for `M_A`). Bound into the key-agreement transcript,
    /// so a relay that swaps it derives a different root key and the first message fails closed.
    /// Appended last.
    #[serde(default)]
    pub mailbox_a_pub: [u8; 32],
}

/// Отправитель Alice: согласовать `root_key` с получателем по его bundle.
/// `sender_ik` — долговременный identity Alice (её аутентификатор).
/// Возвращает (root_key, KA-на-провод).
pub fn initiate_key_agreement(
    sender_ik: &Identity,
    sender_mailbox_pub: &[u8; 32],
    bundle: &PreKeyBundle,
) -> ([u8; 32], KeyAgreement) {
    let ik_b = PublicKey::from(bundle.ik_pub);
    let prekey_b = PublicKey::from(bundle.prekey_pub);
    let ek_a = Identity::generate(); // эфемер отправителя

    let dh1 = sender_ik.dh(&prekey_b); // IK_A × PK_B  (аутентификация отправителя)
    let dh2 = ek_a.dh(&ik_b); //         EK_A × IK_B
    let dh3 = ek_a.dh(&prekey_b); //     EK_A × PK_B
    // Fourth DH against the recipient's ONE-TIME prekey, iff the bundle carried one.
    let dh4 = bundle.opk_pub.map(|opk| ek_a.dh(&PublicKey::from(opk)));

    let ek = <EncapsulationKey<MlKem768> as TryKeyInit>::new_from_slice(&bundle.kem_ek)
        .expect("valid bundle KEM key");
    let (ct, pq_shared) = ek.encapsulate();
    let kem_ct = ct.as_slice().to_vec();

    let ik_a_pub = sender_ik.public.to_bytes();
    let ek_a_pub = ek_a.public.to_bytes();
    let transcript = transcript(
        &ik_a_pub,
        &bundle.ik_pub,
        &ek_a_pub,
        &bundle.prekey_pub,
        &kem_ct,
        bundle.opk_pub.as_ref(),
        sender_mailbox_pub,
    );
    let root_key = derive_root_key(&dh1, &dh2, &dh3, dh4.as_ref(), pq_shared.as_slice(), &transcript);

    (
        root_key,
        KeyAgreement { ik_a_pub, ek_a_pub, kem_ct, opk_pub: bundle.opk_pub, mailbox_a_pub: *sender_mailbox_pub },
    )
}

/// Транскрипт: связывает ОБА долговременных ключа (IK_A, IK_B), эфемер, prekey и
/// **KEM-ciphertext** — без последнего возможна атака подстановки инкапсуляции.
/// Идёт в KDF-`info`.
fn transcript(
    ik_a: &[u8; 32],
    ik_b: &[u8; 32],
    ek_a: &[u8; 32],
    prekey_b: &[u8; 32],
    kem_ct: &[u8],
    opk_b: Option<&[u8; 32]>,
    mailbox_a: &[u8; 32],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(DOMAIN.len() + 192 + kem_ct.len());
    t.extend_from_slice(DOMAIN);
    t.extend_from_slice(ik_a);
    t.extend_from_slice(ik_b);
    t.extend_from_slice(ek_a);
    t.extend_from_slice(prekey_b);
    t.extend_from_slice(kem_ct);
    // Bind the sender's mailbox point M_A so a relay cannot swap it (a swap → different root key
    // → the first ratchet message fails closed, rather than silently redirecting B→A replies).
    t.extend_from_slice(mailbox_a);
    // Bind whether an OPK was used AND which one: a 1-byte presence flag then the key, so
    // "no OPK" and "OPK of all-zeros" cannot collide and a stripped OPK changes the key.
    match opk_b {
        Some(opk) => {
            t.push(1);
            t.extend_from_slice(opk);
        }
        None => t.push(0),
    }
    t
}

/// root_key = HKDF-SHA256(ikm = DH1‖DH2‖DH3‖pq_shared, info = transcript).
/// pq_shared входит В IKM — постквантовая нога НАГРУЖЕНА (тест это пиннит).
fn derive_root_key(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4: Option<&[u8; 32]>,
    pq_shared: &[u8],
    transcript: &[u8],
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(128 + pq_shared.len());
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    // The one-time-prekey DH goes in BEFORE the PQ share, in a fixed position. It is
    // present iff an OPK was used; the transcript binds which OPK, so its absence cannot be
    // silently forged into presence or vice versa.
    if let Some(dh4) = dh4 {
        ikm.extend_from_slice(dh4);
    }
    ikm.extend_from_slice(pq_shared);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(transcript, &mut okm).expect("32 within HKDF output limit");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer test against the canonical XEdDSA spec vector (also in the `xeddsa`
    /// crate's own suite). This pins the Montgomery→Edwards key conversion — the subtle part —
    /// so a broken or forked `xeddsa` (or a version bump that changes it) reds in OUR CI, not
    /// just theirs. This is the one part of the primitive our tests can verify against a
    /// reference rather than a self round-trip.
    #[test]
    fn xeddsa_matches_the_spec_known_answer_vector() {
        use xeddsa::CalculateKeyPair;
        let priv_in: [u8; 32] = [
            0xf8, 0xce, 0xd4, 0x2b, 0x07, 0xe7, 0x81, 0x0a, 0x04, 0xcc, 0x85, 0x4b, 0x03, 0x57,
            0x6d, 0xf1, 0xe4, 0xc0, 0xfe, 0xb1, 0x6d, 0x68, 0x5e, 0x0a, 0xc0, 0x42, 0x5e, 0x1c,
            0x3c, 0x5e, 0xb2, 0x47,
        ];
        let sk = xeddsa::xed25519::PrivateKey::from(&priv_in);
        let (_signing, verifying) = sk.calculate_key_pair(0);
        assert_eq!(
            verifying,
            [
                0xD7, 0x6D, 0x40, 0x33, 0x2E, 0xD1, 0x13, 0x88, 0xCA, 0xA6, 0x9B, 0x50, 0x67,
                0x6D, 0x63, 0x08, 0x25, 0xCD, 0xDA, 0xD0, 0x32, 0x46, 0xED, 0xD6, 0x1E, 0xD3,
                0xCA, 0x72, 0xE6, 0xCB, 0x2C, 0x2E,
            ],
            "XEdDSA Montgomery→Edwards conversion diverged from the spec vector"
        );
    }

    /// The prekey signature verifies for a genuine bundle and fails the moment ANY signed
    /// field (prekey or KEM key) is altered — so a relay substitution is caught. Note this is
    /// a round-trip against the vetted `xeddsa` crate (itself checked against the XEdDSA spec
    /// vectors); it proves the WIRING (right key, right message), not the primitive.
    #[test]
    fn prekey_signature_binds_the_prekey_material() {
        let acct = Account::generate();
        let good = acct.prekey_bundle();
        assert!(good.verify_prekey_sig(), "a genuine bundle verifies under its own IK");

        // Swap the prekey → signature no longer covers it.
        let mut tampered = good.clone();
        tampered.prekey_pub = Account::generate().prekey_bundle().prekey_pub;
        assert!(!tampered.verify_prekey_sig(), "a swapped prekey is rejected");

        // Swap the KEM key → also rejected (both long-lived materials are signed).
        let mut tampered_kem = good.clone();
        tampered_kem.kem_ek = Account::generate().prekey_bundle().kem_ek;
        assert!(!tampered_kem.verify_prekey_sig(), "a swapped KEM key is rejected");

        // A bundle claiming a DIFFERENT IK than the signer → rejected (relay can't forge).
        let mut wrong_ik = good.clone();
        wrong_ik.ik_pub = Account::generate().prekey_bundle().ik_pub;
        assert!(!wrong_ik.verify_prekey_sig(), "signature does not verify under a foreign IK");

        // Swap the mailbox point M → also rejected (the sig now binds it, so a relay can't
        // substitute a mailbox point it controls a fetch secret for).
        let mut tampered_mbox = good.clone();
        tampered_mbox.mailbox_pub = Account::generate().prekey_bundle().mailbox_pub;
        assert!(!tampered_mbox.verify_prekey_sig(), "a swapped mailbox point is rejected");
    }

    /// The per-account mailbox point `M` is published in the bundle, equals `m·G`, and — like the
    /// rest of the identity — is STABLE across a re-derive from the seed bytes (so it needs no
    /// separate persistence). Backs the live blinded deposit/fetch key separation.
    #[test]
    fn mailbox_point_is_published_and_seed_stable() {
        let acct = Account::generate();
        let bundle = acct.prekey_bundle();
        assert_ne!(bundle.mailbox_pub, [0u8; 32], "M is present, not the default");
        assert_eq!(bundle.mailbox_pub, acct.mailbox_public(), "bundle M equals the account's M");
        // Re-derive from the seed bytes → same M (no separate persistence needed).
        let restored = Account::from_secret_bytes(&acct.to_secret_bytes());
        assert_eq!(restored.mailbox_public(), acct.mailbox_public(), "M re-derives from the seed");
        // And the sender can already turn M into a blinded deposit address it cannot open.
        let addr = crate::blind::deposit_address(&bundle.mailbox_pub, &[3u8; 32], 5, 0);
        assert!(addr.is_some(), "the published M is a valid Ristretto point");
    }

    /// Дискриминирующий: pq_shared РЕАЛЬНО входит в root_key. Если бы ML-KEM был
    /// декоративным, ключи совпали бы. Нельзя протестировать «квантово-стойко»
    /// напрямую — тестируем, что PQ-вклад ПРОВОДЁН в ключ.
    #[test]
    fn pq_shared_is_load_bearing_in_root_key() {
        let (dh1, dh2, dh3) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let t = b"transcript";
        let k_real = derive_root_key(&dh1, &dh2, &dh3, None, &[9u8; 32], t);
        let k_zero = derive_root_key(&dh1, &dh2, &dh3, None, &[0u8; 32], t);
        assert_ne!(k_real, k_zero, "pq_shared должен влиять на root_key");
    }

    /// Дискриминирующий для АУТЕНТИФИКАЦИИ ОТПРАВИТЕЛЯ: DH1 (единственный член,
    /// зависящий от приватного ключа отправителя) реально входит в root_key.
    /// Без этого root_key = HKDF(DH2‖DH3‖pq) вычислил бы кто угодно из публичного
    /// bundle — подделка удалась бы. Этот тест пиннит, что подделка невозможна
    /// по КЛЮЧУ.
    #[test]
    fn dh1_is_load_bearing_in_root_key() {
        let t = b"transcript";
        let with = derive_root_key(&[7u8; 32], &[2u8; 32], &[3u8; 32], None, &[9u8; 32], t);
        let without = derive_root_key(&[8u8; 32], &[2u8; 32], &[3u8; 32], None, &[9u8; 32], t);
        assert_ne!(with, without, "DH1 (sender-auth) должен влиять на root_key");
    }

    /// The one-time-prekey DH SECRET (not just its public key via the transcript) is mixed
    /// into the root key. Tested at the `derive_root_key` layer so the transcript cannot
    /// mask it: same transcript, different `dh4` → different key. Neuter the `dh4` mix in
    /// `derive_root_key` and both cases collapse to one key → red.
    #[test]
    fn dh4_one_time_prekey_secret_is_load_bearing_in_root_key() {
        let t = b"transcript";
        let (d1, d2, d3, pq) = (&[1u8; 32], &[2u8; 32], &[3u8; 32], &[5u8; 32]);
        let with_a = derive_root_key(d1, d2, d3, Some(&[9u8; 32]), pq, t);
        let with_b = derive_root_key(d1, d2, d3, Some(&[8u8; 32]), pq, t);
        assert_ne!(with_a, with_b, "the OPK DH secret must affect the root key");
        let without = derive_root_key(d1, d2, d3, None, pq, t);
        assert_ne!(with_a, without, "OPK presence must affect the root key");
    }

    /// Персистентность §2.1-личности: восстановленный из байтов account даёт ТОТ
    /// ЖЕ публичный bundle (стабильный адрес/discovery) И согласует тот же
    /// root_key (KEM-seed восстановлен корректно). Не «round-trip не паникует» —
    /// именно неизменность bundle + рабочая decap.
    #[test]
    fn account_persists_identity_bundle_and_decap() {
        let acct = Account::generate();
        let bundle = acct.prekey_bundle();

        let mut restored = Account::from_secret_bytes(&acct.to_secret_bytes());
        let rb = restored.prekey_bundle();
        assert_eq!(rb.ik_pub, bundle.ik_pub, "IK стабилен");
        assert_eq!(rb.prekey_pub, bundle.prekey_pub, "prekey стабилен");
        assert_eq!(rb.kem_ek, bundle.kem_ek, "KEM ek стабилен (seed восстановлен)");

        // Согласование к восстановленному account работает (decap на seed'е).
        let alice = Identity::generate();
        let alice_m = crate::blind::MailboxSecret::generate().public();
        let (alice_rk, ka) = initiate_key_agreement(&alice, &alice_m, &rb);
        assert_eq!(ka.mailbox_a_pub, alice_m, "the KA carries the sender's mailbox point");
        let (bob_rk, sender) = restored.accept_key_agreement(&ka).expect("decap");
        assert_eq!(alice_rk, bob_rk, "восстановленный account согласует ключ");
        assert_eq!(sender, alice.public.to_bytes());
    }
}
