//! §2.1 — Double Ratchet (classical X25519) поверх PQXDH-`root_key`.
//!
//! Пер-сообщенческая **forward secrecy** (ключ сообщения удаляется после
//! использования, цепочка одностороння) + **post-compromise security** (DH-шаг
//! на новом эфемере «лечит» компрометацию). PQ-защита — от начального PQXDH
//! (§2.1: ratchet классический, гибрид живёт в handshake). Спека Signal Double
//! Ratchet, reference-код над примитивами (как PQXDH), НЕ аудирован.
//!
//! # ЭТОТ СРЕЗ и не больше:
//! - **out-of-order терпим** (skipped-message-keys, спека Signal): пропущенные
//!   ключи выводятся и хранятся, входящее не по порядку (mailbox-пачка, DTN
//!   store-and-forward) расшифровывается. Двойная граница анти-DoS: `MAX_SKIP`
//!   на один шаг приёма (анти-unbounded-KDF) + `MAX_STORE` всего с FIFO-эвикцией
//!   (анти-память/диск). Раньше был строго-in-order → один дроп = мёртвая сессия;
//!   а crash-consistency (безусловное продвижение при encrypt) сам плодит дропы;
//! - без header-encryption, без PQ-ratchet, без вплетения в node-путь (сессия
//!   засевается сырым `root_key`); без time-based expiry пропущенных ключей.
//!
//! # Транзакционность (иначе один битый пакет ломает сессию — И сильнее):
//! `decrypt` мутирует КОПИЮ и **проверяет AEAD ДО** коммита. Помимо «битый пакет
//! не ломает сессию», это даёт свойство СВЕРХ спеки Signal: forged-сообщение с
//! большим `n` НЕ наполняет skipped-store и НЕ двигает `nr` (в буквальном Signal
//! `SkipMessageKeys` мутирует до DECRYPT) — противник без валидного AEAD-тега не
//! может заставить хранить ключи. Откат безопасен: состояние цепочки откатывается
//! вместе со store, ретрансмит выведет ключи заново.
//!
//! # FS-компромисс (назван): пропущенные ключи ЛОЖАТСЯ at-rest (в снимок — иначе
//! между recv-вызовами клиента, load→process→save, теряются и фикс бесполезен).
//! Это ослабляет FS-non-retention для ИМЕННО тех pending-сообщений на окно «пока
//! не получены или не вытеснены». Стандартный Signal-компромисс за out-of-order;
//! time-based expiry (есть `wall_clock`) прямо ограничил бы окно — след. шаг.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Mac, SimpleHmac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::PublicKey;

use crate::seal::Identity;

const AAD_DOMAIN: &[u8] = b"KARST-ratchet-v2";

/// Максимум ключей, выводимых за ОДИН шаг приёма (в каждой из до двух цепочек).
/// Анти-DoS: forged `header.n`/`header.pn` не заставит вывести unbounded KDF.
const MAX_SKIP: u32 = 1000;
/// Максимум ВСЕГО хранимых пропущенных ключей (FIFO-эвикция старейших). Должен
/// быть ≥ 2·MAX_SKIP: один decrypt через границу цепочек может добавить до
/// MAX_SKIP (старая цепочка, `pn`) + MAX_SKIP (новая, `n`) — иначе эвикция
/// сработала бы ПОСРЕДИ decrypt и выбросила ровно те gap-filler'ы, что мы кладём.
const MAX_STORE: usize = 2048;

/// How many DH-ratchet generations a skipped key may outlive. Out-of-order delivery spans at most
/// a chain boundary or two; anything older is not late mail, it is retention.
const MAX_SKIPPED_GENERATIONS: u64 = 4;

/// Хранимый пропущенный ключ сообщения: идентифицируется (ratchet-pubkey цепочки,
/// номер). `mk` — ключ сообщения; ложится at-rest (см. FS-компромисс в доке).
#[derive(Clone, serde::Serialize, serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct SkippedKey {
    dh: [u8; 32],
    n: u32,
    mk: [u8; 32],
    /// Which DH-ratchet generation stored this key. Skipped keys were bounded in NUMBER but never
    /// expired, so one could sit at rest long past any plausible reordering window, widening the
    /// interval in which a device compromise yields plaintext for messages that may never even
    /// arrive (A6-9). Age is counted in RATCHET STEPS rather than wall-clock on purpose: the local
    /// clock is an unauthenticated input, and a chain that is several DH steps behind is stale by
    /// the protocol's own measure.
    gen: u64,
}

/// Заголовок сообщения: текущий ratchet-pubkey отправителя, длина предыдущей
/// цепочки (`pn`), номер в текущей цепочке (`n`), пер-сообщенческая соль.
/// Связывается целиком в AEAD-AAD.
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct Header {
    pub dh: [u8; 32],
    pub pn: u32,
    pub n: u32,
    /// Fresh random per message; the AEAD key and nonce are derived from `(mk, salt)` rather
    /// than being `mk` with a zero nonce (CRYPTO-01 residual). See [`message_aead`] — this is
    /// what makes a ratchet-state ROLLBACK non-catastrophic instead of merely unlikely.
    pub salt: [u8; SALT_LEN],
}

/// Per-message salt width. 128 bits: a repeat needs ~2^64 messages in ONE chain, while the
/// cost is 16 bytes per message, which stays inside the current padding bucket (pinned by
/// `a_full_size_chunk_still_fits_its_padding_bucket`) so the change is invisible on the wire.
pub const SALT_LEN: usize = 16;

/// Сообщение на проводе.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RatchetMessage {
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RatchetError {
    /// Скачок номеров > `MAX_SKIP` за один шаг приёма (анти-DoS-граница). Не
    /// «просто не по порядку» — умеренный out-of-order теперь терпим.
    OutOfOrder,
    /// Нет принимающей цепочки (не было первого сообщения).
    NoReceivingChain,
    /// AEAD не сошёлся (подмена/чужой ключ).
    Decrypt,
    /// Заголовок принёс ratchet-ключ малого порядка: DH-шаг был бы НЕ contributory
    /// (общий секрет — нули, известные атакующему), что убило бы PCS-«лечение».
    /// Состояние НЕ продвигается (`decrypt` транзакционен) — CRYPTO-06.
    NonContributoryDh,
}

/// Double-Ratchet session state. `Clone` exists for the transactional decrypt (mutate a copy,
/// commit only once the AEAD verifies).
///
/// `ZeroizeOnDrop` (CRYPTO-09): the root key, both chain keys and every stored skipped message
/// key are overwritten when the session — including each transient decrypt CLONE — is dropped.
/// The clone matters most: a failed decrypt throws its copy away, and that copy held the same
/// chain keys as the original.
///
/// HONEST LIMIT: this scrubs what the value owns at drop time. A move is a memcpy and does not
/// scrub the source, the allocator may have reused the page, and the OS may have paged it out
/// first. It shortens the window; it does not close it.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Session {
    // `x25519_dalek::StaticSecret` inside `Identity` is already `ZeroizeOnDrop`, so scrubbing it
    // again here would be a second pass over bytes dalek has cleared — skipped, not forgotten.
    #[zeroize(skip)]
    dhs: Identity,           // our ratchet pair
    dhr: Option<[u8; 32]>,   // the peer's ratchet public key
    rk: [u8; 32],            // root key
    cks: Option<[u8; 32]>,   // sending chain key
    ckr: Option<[u8; 32]>,   // receiving chain key
    ns: u32,                 // send counter
    nr: u32,                 // receive counter
    pn: u32,                 // length of the previous sending chain
    skipped: Vec<SkippedKey>, // skipped (out-of-order) keys, FIFO-bounded
    /// Counts DH-ratchet steps, so a skipped key can be aged out by protocol progress rather than
    /// by an unauthenticated wall clock (A6-9).
    dh_gen: u64,
    /// **Routing contribution produced by the last DH step**, waiting to be taken by the session
    /// layer (PRIV-2). NOT key material for messages — a domain-separated derivative of the step's
    /// FIRST DH output, which is the one value the peer provably already holds (it computed the
    /// same number as its own second output, one leg earlier). That asymmetry is the whole reason
    /// routing can heal at all: a contribution taken from the step's SECOND output would need a
    /// key the peer has not received yet, so the recipient could never derive the address it is
    /// supposed to poll.
    ///
    /// Deliberately not the raw DH: nothing outside this module should ever hold that.
    routing_contribs: Vec<[u8; 32]>,
}

/// Персистентная форма сессии (для возобновления ratchet между процесс-вызовами
/// CLI). Цепочные/root-ключи + приватный ratchet-ключ + ТОЛЬКО пропущенные
/// (out-of-order) `mk`. Пер-сообщенческие ключи ПРИНЯТЫХ по порядку сообщений на
/// диск НЕ попадают (локальны в encrypt/decrypt) — FS-non-retention для них цел;
/// пропущенные же ложатся ОСОЗНАННО (без этого фикс не переживает reload — см.
/// FS-компромисс в доке модуля). `dhs_secret` — приватный ключ в открытом виде:
/// вызывающий обязан писать под 0600 (тут at-rest — через `client::Store`).
/// Zeroized on drop for the same reason as `Session` (CRYPTO-09): a snapshot is the SAME key
/// material in a serializable shape, and it exists exactly in the window where it is copied
/// around — taken, encoded, sealed, dropped.
#[derive(serde::Serialize, serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SessionSnapshot {
    dhs_secret: [u8; 32],
    dhr: Option<[u8; 32]>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    /// Пропущенные ключи — персистятся ОСОЗНАННО (FS-компромисс, см. доку модуля):
    /// без них out-of-order-фикс не переживает `load→process→save` клиента.
    skipped: Vec<SkippedKey>,
    dh_gen: u64,
    /// Persisted because it is produced on decrypt and consumed by the session layer AFTER the
    /// durable save: dropping it on restart would silently skip one routing generation, and the
    /// two sides would then disagree about the address with no error anywhere.
    routing_contribs: Vec<[u8; 32]>,
}

impl Session {
    /// Снять снимок для персистентности (см. `SessionSnapshot`).
    pub fn snapshot(&self) -> SessionSnapshot {
        SessionSnapshot {
            dhs_secret: self.dhs.to_secret_bytes(),
            dhr: self.dhr,
            rk: self.rk,
            cks: self.cks,
            ckr: self.ckr,
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            skipped: self.skipped.clone(),
            dh_gen: self.dh_gen,
            routing_contribs: self.routing_contribs.clone(),
        }
    }

    /// Восстановить сессию из снимка.
    pub fn restore(mut s: SessionSnapshot) -> Self {
        Session {
            dhs: Identity::from_secret_bytes(s.dhs_secret),
            dhr: s.dhr,
            rk: s.rk,
            cks: s.cks,
            ckr: s.ckr,
            ns: s.ns,
            nr: s.nr,
            pn: s.pn,
            // `SessionSnapshot` zeroizes on drop, which makes it non-`Copy` and unmovable field
            // by field — take the vector out and leave an empty one behind for the drop to scrub.
            skipped: std::mem::take(&mut s.skipped),
            dh_gen: s.dh_gen,
            routing_contribs: s.routing_contribs.clone(),
        }
    }

    /// Инициатор (Alice): знает ratchet-pubkey получателя (его prekey из PQXDH).
    pub fn init_sender(root_key: [u8; 32], their_ratchet_pub: [u8; 32]) -> Self {
        let dhs = Identity::generate();
        let dh_out = dhs.dh(&PublicKey::from(their_ratchet_pub));
        let (rk, cks) = kdf_rk(&root_key, &dh_out);
        // The FIRST element of the shared sequence. The responder computes the same number as the
        // first DH of its own first step, so both sides start the routing chain from it — without
        // this the two sequences would be offset by one element forever and never agree.
        let first_contrib = vec![routing_contrib(&dh_out)];
        Session {
            dhs,
            dhr: Some(their_ratchet_pub),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: Vec::new(),
            dh_gen: 0,
            routing_contribs: first_contrib,
        }
    }

    /// Получатель (Bob): его ratchet-пара = prekey из PQXDH-bundle. Первую
    /// sending-цепочку получит при DH-шаге на первом входящем сообщении.
    pub fn init_receiver(root_key: [u8; 32], our_ratchet_key: Identity) -> Self {
        Session {
            dhs: our_ratchet_key,
            dhr: None,
            rk: root_key,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: Vec::new(),
            dh_gen: 0,
            routing_contribs: Vec::new(),
        }
    }

    /// Ratchet-pubkey нашей текущей пары (для init_sender собеседника).
    pub fn ratchet_public(&self) -> [u8; 32] {
        self.dhs.public.to_bytes()
    }

    /// Зашифровать сообщение. Требует sending-цепочку (Alice — с init; Bob —
    /// после первого decrypt).
    ///
    /// The AEAD key/nonce come from `(mk, fresh salt)`, not from `mk` with a zero nonce. A fresh
    /// message key per message made the zero nonce *safe*, but only for as long as the chain
    /// never goes backwards — and a chain CAN go backwards: restore a backup, clone the disk,
    /// roll back the VM. `cks` then re-derives the same `mk` and, with a fixed nonce, encrypts a
    /// DIFFERENT plaintext under the identical key+nonce: keystream reuse (XOR of the two
    /// plaintexts) plus a reused Poly1305 key. Rollback cannot be *prevented* by a program that
    /// keeps its state in files the attacker can restore, so it is made harmless instead.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> RatchetMessage {
        let ck = self.cks.expect("sending chain (the recipient must receive before we send)");
        let (ck_next, mk) = kdf_ck(&ck);
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let header = Header { dh: self.dhs.public.to_bytes(), pn: self.pn, n: self.ns, salt };
        self.cks = Some(ck_next);
        self.ns += 1;
        let ciphertext = aead_encrypt(&mk, plaintext, &aad(&header), &header.salt);
        RatchetMessage { header, ciphertext }
    }

    /// Take the routing contributions produced since the last call, in the order computed (PRIV-2).
    ///
    /// A step produces TWO, and the sender's init produces one. That is not an implementation
    /// detail — it is the reason the two sides agree at all. The DH outputs form ONE sequence
    /// `v0, v1, v2, …` that both sides walk in the same order, each computing two of them per step
    /// with a one-element overlap. Folding only ONE output per step was tried first and is wrong in
    /// a way no amount of reasoning caught: each side then takes only the even or only the odd
    /// elements, the sequences are DISJOINT, and the recipient can never derive the sender's
    /// address. A test in this module pins the agreement precisely because that mistake looks
    /// correct on paper.
    ///
    /// Take, not read: exactly one caller may fold it into the routing chain, and folding the same
    /// contribution twice would advance one side's generation past the other's with nothing to say
    /// so — the two would then derive different addresses and mail would stop arriving with no
    /// error anywhere. Consuming it makes the double-fold impossible instead of discouraged.
    pub fn take_routing_contributions(&mut self) -> Vec<[u8; 32]> {
        std::mem::take(&mut self.routing_contribs)
    }

    /// Расшифровать. ТРАНЗАКЦИОННО: мутируем копию, проверяем AEAD, коммитим
    /// только при успехе — битый пакет не двигает и не ломает сессию.
    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>, RatchetError> {
        let mut staged = self.clone();
        let mk = staged.advance_for_decrypt(&msg.header)?;
        let pt = aead_decrypt(&mk, &msg.ciphertext, &aad(&msg.header), &msg.header.salt)
            .map_err(|_| RatchetError::Decrypt)?;
        *self = staged; // коммит только после успешной AEAD
        Ok(pt)
    }

    /// Продвинуть СТЕЙДЖ-состояние под заголовок и вернуть ключ сообщения.
    /// Мутирует `self` (это копия из `decrypt`), НЕ трогает AEAD. Алгоритм —
    /// Signal `RatchetDecrypt`: (1) пропущенный ключ; (2) DH-шаг при новом
    /// ratchet-ключе, достраивая хвост прошлой цепочки; (3) пропуски в текущей
    /// цепочке до `header.n`; (4) ключ ровно на `header.n`.
    fn advance_for_decrypt(&mut self, header: &Header) -> Result<[u8; 32], RatchetError> {
        // (1) Out-of-order из этой или ПРОШЛОЙ цепочки — ключ уже выведен и хранится.
        if let Some(mk) = self.take_skipped(header.dh, header.n) {
            return Ok(mk);
        }
        // (2) Новый ratchet-ключ собеседника → сохранить хвост прошлой receiving-
        // цепочки (nr..header.pn) и сделать DH-шаг (PCS-«лечение»).
        if self.dhr != Some(header.dh) {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(header)?;
        }
        // (3) Пропуски в текущей цепочке до header.n (сохраняются).
        self.skip_message_keys(header.n)?;
        // (4) Ключ ровно на header.n (nr здесь == header.n при in-order/после skip).
        let ck = self.ckr.ok_or(RatchetError::NoReceivingChain)?;
        let (ck_next, mk) = kdf_ck(&ck);
        self.ckr = Some(ck_next);
        self.nr += 1;
        Ok(mk)
    }

    /// Изъять пропущенный ключ по (ratchet-pubkey цепочки, номер), если хранится.
    /// Изъятие фиксируется только при коммите `decrypt` (staged) — replay/forgery
    /// без валидного AEAD не удалит ключ.
    fn take_skipped(&mut self, dh: [u8; 32], n: u32) -> Option<[u8; 32]> {
        let i = self.skipped.iter().position(|s| s.dh == dh && s.n == n)?;
        Some(self.skipped.remove(i).mk)
    }

    /// Сохранить пропущенный ключ; при переполнении — FIFO-эвикция старейшего.
    fn store_skipped(&mut self, dh: [u8; 32], n: u32, mk: [u8; 32]) {
        if self.skipped.len() >= MAX_STORE {
            self.skipped.remove(0);
        }
        self.skipped.push(SkippedKey { dh, n, mk, gen: self.dh_gen });
    }

    /// Drop skipped keys older than `MAX_SKIPPED_GENERATIONS` DH steps — run on every ratchet
    /// step, so stale message keys stop living at rest indefinitely (A6-9).
    fn expire_skipped(&mut self) {
        let cutoff = self.dh_gen.saturating_sub(MAX_SKIPPED_GENERATIONS);
        self.skipped.retain(|s| s.gen >= cutoff);
    }

    /// Продвинуть receiving-цепочку до `until`, СОХРАНЯЯ пропущенные ключи под
    /// текущим `dhr`. Анти-DoS: скачок > `MAX_SKIP` за раз → отказ (без вывода
    /// ключей). `until <= nr` → no-op. Overflow-безопасно.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), RatchetError> {
        if until > self.nr && until - self.nr > MAX_SKIP {
            return Err(RatchetError::OutOfOrder);
        }
        if until <= self.nr {
            return Ok(());
        }
        let dh = self.dhr.ok_or(RatchetError::NoReceivingChain)?;
        while self.nr < until {
            let ck = self.ckr.ok_or(RatchetError::NoReceivingChain)?;
            let (ck_next, mk) = kdf_ck(&ck);
            self.store_skipped(dh, self.nr, mk);
            self.ckr = Some(ck_next);
            self.nr += 1;
        }
        Ok(())
    }

    /// DH-ratchet-шаг: новая receiving/sending цепочки на ratchet-ключе собеседника.
    fn dh_ratchet(&mut self, header: &Header) -> Result<(), RatchetError> {
        // Reject a small-order ratchet key BEFORE touching state: its DH is all-zero, i.e. known
        // to the attacker, so the step would inject no fresh entropy and silently defeat the
        // healing (PCS) property this ratchet exists to provide (CRYPTO-06). `decrypt` stages a
        // clone and commits only on success, so returning Err here leaves the session untouched.
        let their = PublicKey::from(header.dh);
        let dh1 = self.dhs.dh_checked(&their).ok_or(RatchetError::NonContributoryDh)?;
        let dhs_new = Identity::generate();
        let dh2 = dhs_new.dh_checked(&their).ok_or(RatchetError::NonContributoryDh)?;
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        let (rk1, ckr) = kdf_rk(&self.rk, &dh1);
        let (rk2, cks) = kdf_rk(&rk1, &dh2);
        self.rk = rk2;
        self.dhr = Some(header.dh);
        self.dhs = dhs_new;
        self.ckr = Some(ckr);
        self.cks = Some(cks);
        // PRIV-2: hand the session layer a routing contribution derived from `dh1` — the output
        // the PEER already computed as its own `dh2` one leg earlier. Domain-separated so it can
        // never collide with a chain or root key, and set here rather than returned so the value
        // rides the same transactional commit as the step itself: `decrypt` stages a clone, so a
        // forged message cannot advance routing any more than it can advance the ratchet.
        self.routing_contribs.push(routing_contrib(&dh1));
        self.routing_contribs.push(routing_contrib(&dh2));
        self.dh_gen = self.dh_gen.saturating_add(1);
        self.expire_skipped();
        Ok(())
    }
}

/// Domain-separated routing contribution from ONE DH output (PRIV-2).
///
/// Separate from `kdf_rk` so routing material can never be confused with a chain or root key, and
/// so the raw DH never leaves this module.
fn routing_contrib(dh_out: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, dh_out);
    let mut out = [0u8; 32];
    hk.expand(b"karst-routing-contrib-v1", &mut out).expect("32 is a valid HKDF length");
    out
}

/// `KDF_RK`: HKDF-SHA256(salt=rk, ikm=dh) → 64 Б → (new_rk, chain_key).
fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(rk), dh_out);
    let mut okm = [0u8; 64];
    hk.expand(b"KARST-ratchet-rk-v1", &mut okm).expect("64 within HKDF output limit");
    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    new_rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    (new_rk, ck)
}

/// `KDF_CK`: (next_chain_key, message_key) через раздельные HMAC-константы.
/// Односторонняя: из `next_ck` не восстановить `mk` (основа forward secrecy).
fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mk = hmac(ck, &[0x01]);
    let next_ck = hmac(ck, &[0x02]);
    (next_ck, mk)
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <SimpleHmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key len");
    m.update(data);
    let out = m.finalize().into_bytes();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

fn aad(header: &Header) -> Vec<u8> {
    let mut a = Vec::with_capacity(AAD_DOMAIN.len() + 40 + SALT_LEN);
    a.extend_from_slice(AAD_DOMAIN);
    a.extend_from_slice(&header.dh);
    a.extend_from_slice(&header.pn.to_le_bytes());
    a.extend_from_slice(&header.n.to_le_bytes());
    a.extend_from_slice(&header.salt);
    a
}

/// `(AEAD key, nonce)` for ONE message: HKDF-SHA256 over the message key, salted with the
/// header's per-message salt. Two encryptions under the same `mk` — which is exactly what a
/// state rollback produces — land on different keys, so neither the keystream nor the Poly1305
/// key is ever reused. The salt is attacker-VISIBLE (it rides in the header) but not
/// attacker-CHOSEN on our side, and it is covered by the AAD, so flipping it in transit only
/// breaks the tag.
fn message_aead(mk: &[u8; 32], salt: &[u8; SALT_LEN]) -> ([u8; 32], [u8; 12]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), mk);
    let mut okm = [0u8; 44];
    hk.expand(b"KARST-ratchet-msg-v2", &mut okm).expect("44 within HKDF output limit");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    (key, nonce)
}

fn aead_encrypt(mk: &[u8; 32], pt: &[u8], aad: &[u8], salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let (key, nonce) = message_aead(mk, salt);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: pt, aad }).expect("AEAD encryption")
}

fn aead_decrypt(
    mk: &[u8; 32],
    ct: &[u8],
    aad: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<Vec<u8>, ()> {
    let (key, nonce) = message_aead(mk, salt);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: ct, aad }).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PCS (лечение), дискриминирующий — как dh1/pq_shared: свежий DH реально
    /// входит в новый root_key. Противник со СТАРЫМ rk, но без нового эфемера
    /// (значит другой DH) не выведет новый root_key.
    #[test]
    fn fresh_dh_is_load_bearing_in_new_root_key() {
        let rk = [5u8; 32];
        let (rk_a, _) = kdf_rk(&rk, &[1u8; 32]);
        let (rk_b, _) = kdf_rk(&rk, &[2u8; 32]);
        assert_ne!(rk_a, rk_b, "a new root_key must depend on a fresh DH (PCS)");
    }

    /// Forward secrecy как NON-RETENTION: после расшифровки сессия НЕ хранит
    /// ключ израсходованного сообщения. Не «разные ключи» и не «replay падает»
    /// (это replay-защита) — именно отсутствие материала ключа в состоянии.
    #[test]
    fn message_key_not_retained_in_session_state() {
        let root = [7u8; 32];
        let bob_prekey = Identity::generate();
        let mut alice = Session::init_sender(root, bob_prekey.public.to_bytes());
        let mut bob = Session::init_receiver(root, bob_prekey);

        let m = alice.encrypt(b"hello");
        // Ключ, которым Bob расшифрует это сообщение (из его текущего состояния
        // после DH-шага). Вычислим тем же путём, что decrypt, но до него.
        let mut probe = bob.clone();
        let mk = probe.advance_for_decrypt(&m.header).unwrap();

        assert_eq!(bob.decrypt(&m).unwrap(), b"hello");

        // Дамп ВСЕГО ключевого материала сессии Bob (вкл. skipped-store) — ключа
        // принятого ПО ПОРЯДКУ сообщения там нет.
        let dump = dump_key_material(&bob);
        assert!(
            !dump.windows(32).any(|w| w == mk),
            "a consumed message key must not stay in the state (FS)"
        );
    }

    /// CRYPTO-01 residual, THE carrying test. A ratchet state that goes BACKWARDS — restored
    /// backup, cloned disk, rolled-back VM — re-derives the same message key and encrypts a
    /// different plaintext with it. Under the old scheme (key = `mk`, nonce = zero) that is a
    /// two-time pad: `ct1 XOR ct2 == pt1 XOR pt2` recovers the XOR of both plaintexts with no
    /// key at all, and the Poly1305 key is reused on top.
    ///
    /// Rollback cannot be PREVENTED locally — an attacker who can restore one file can restore
    /// them all — so it is made harmless instead: the per-message salt lands the two encryptions
    /// on different keys AND different nonces.
    ///
    /// Discriminating on purpose: it asserts the XOR relation is BROKEN, so it goes red the
    /// moment the derivation stops depending on the salt. Asserting merely `ct1 != ct2` would
    /// have passed under the old scheme too (different plaintexts → different ciphertexts).
    #[test]
    fn a_rolled_back_sending_chain_does_not_reuse_the_keystream() {
        let (alice, _bob) = pair();

        // The SAME pre-send state used twice = exactly what restoring a backup does.
        let mut original = alice.clone();
        let mut rolled_back = alice;

        let pt1 = b"transfer 10 to alice............";
        let pt2 = b"transfer 99 to mallory..........";
        let m1 = original.encrypt(pt1);
        let m2 = rolled_back.encrypt(pt2);

        assert_eq!(m1.header.n, m2.header.n, "the rollback must really replay the same message number");
        assert_ne!(m1.header.salt, m2.header.salt, "each message must carry a FRESH salt");

        let xor_ct: Vec<u8> =
            m1.ciphertext.iter().zip(&m2.ciphertext).map(|(a, b)| a ^ b).collect();
        let xor_pt: Vec<u8> = pt1.iter().zip(pt2.iter()).map(|(a, b)| a ^ b).collect();
        assert_ne!(
            &xor_ct[..xor_pt.len()],
            &xor_pt[..],
            "keystream reuse: XOR of the two ciphertexts leaked the XOR of the two plaintexts — \
             the AEAD key/nonce must depend on the per-message salt, not on the message key alone"
        );
    }

    /// The salt is authenticated, not just carried: flipping it in transit must fail the tag
    /// rather than silently decrypting under a different key. Guards against someone deriving
    /// the key from the salt but forgetting to bind the salt into the AAD.
    #[test]
    fn a_tampered_salt_fails_the_tag() {
        let (mut alice, mut bob) = pair();
        let mut msg = alice.encrypt(b"hello");
        msg.header.salt[0] ^= 1;
        assert_eq!(bob.decrypt(&msg), Err(RatchetError::Decrypt));
    }

    /// The 16-byte salt must not push a full-size message into a bigger padding bucket: the
    /// on-wire SIZE CLASS is the observable, and a changed size class is itself a tell. Pins
    /// that a maximum inline chunk (1024 B payload + framing + AEAD tag) still lands in the
    /// same bucket it did before the salt existed.
    #[test]
    fn a_full_size_chunk_still_fits_its_padding_bucket() {
        let (mut alice, _bob) = pair();
        // 1024 = client::content::MAX_CHUNK_PAYLOAD (that crate depends on this one, not the
        // other way round), plus generous room for the Content framing around the chunk.
        let msg = alice.encrypt(&vec![0u8; 1024 + 64]);
        let on_wire = postcard::to_stdvec(&msg).expect("serialize");

        let with_salt = crate::session::bucket_for(4 + on_wire.len());
        let without_salt = crate::session::bucket_for(4 + on_wire.len() - SALT_LEN);
        assert_eq!(
            with_salt, without_salt,
            "the per-message salt moved a full-size message into a different padding bucket \
             ({without_salt} -> {with_salt}): the change became visible on the wire"
        );
    }

    /// Свежая пара сессий на общем root (Alice-отправитель, Bob-получатель).
    fn pair() -> (Session, Session) {
        let root = [7u8; 32];
        let bob_prekey = Identity::generate();
        let alice = Session::init_sender(root, bob_prekey.public.to_bytes());
        let bob = Session::init_receiver(root, bob_prekey);
        (alice, bob)
    }

    /// Весь ключевой материал сессии, включая пропущенные mk.
    fn dump_key_material(s: &Session) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&s.rk);
        if let Some(c) = s.cks {
            d.extend_from_slice(&c);
        }
        if let Some(c) = s.ckr {
            d.extend_from_slice(&c);
        }
        for sk in &s.skipped {
            d.extend_from_slice(&sk.mk);
        }
        d
    }

    /// Out-of-order В ОДНОЙ цепочке: приняли m0, затем m2 (m1 сохранён), затем
    /// «догоняет» m1 — все расшифрованы. Раньше m2 после m0 → OutOfOrder.
    #[test]
    fn out_of_order_within_chain_decrypts_via_skipped() {
        let (mut alice, mut bob) = pair();
        let m0 = alice.encrypt(b"zero");
        let m1 = alice.encrypt(b"one");
        let m2 = alice.encrypt(b"two");

        assert_eq!(bob.decrypt(&m0).unwrap(), b"zero");
        assert_eq!(bob.decrypt(&m2).unwrap(), b"two", "skipping m1 stores the m1 key");
        assert_eq!(bob.skipped.len(), 1, "exactly one skipped key (m1)");
        assert_eq!(bob.decrypt(&m1).unwrap(), b"one", "the late m1 is opened from the store");
        assert!(bob.skipped.is_empty(), "a consumed skipped key is deleted (FS)");
    }

    /// Out-of-order ЧЕРЕЗ границу цепочек: хвост старой цепочки (m1) сохраняется
    /// при DH-шаге и расшифровывается после сообщения из новой цепочки.
    #[test]
    fn out_of_order_across_ratchet_boundary() {
        let (mut alice, mut bob) = pair();
        let a0 = alice.encrypt(b"a0"); // chain A, n0
        let a1 = alice.encrypt(b"a1"); // chain A, n1 (will be delayed)
        assert_eq!(bob.decrypt(&a0).unwrap(), b"a0");

        // Bob отвечает → Alice делает DH-шаг → новая цепочка Alice.
        let r0 = bob.encrypt(b"r0");
        assert_eq!(alice.decrypt(&r0).unwrap(), b"r0");
        let b0 = alice.encrypt(b"b0"); // a NEW chain from Alice, pn=2

        // Bob принимает b0 (новая цепочка): хвост старой (a1) сохраняется, DH-шаг.
        assert_eq!(bob.decrypt(&b0).unwrap(), b"b0");
        assert_eq!(bob.skipped.len(), 1, "the tail of the old chain (a1) is stored");
        // Догнавший a1 из СТАРОЙ цепочки — из store.
        assert_eq!(bob.decrypt(&a1).unwrap(), b"a1");
        assert!(bob.skipped.is_empty());
    }

    /// Load-bearing (ради чего фикс): пропущенный ключ переживает snapshot→restore
    /// (зеркалит `load→process→save` клиента), затем догнавший gap-filler
    /// расшифровывается из ВОССТАНОВЛЕННОГО store.
    #[test]
    fn skipped_key_survives_snapshot_restore() {
        let (mut alice, mut bob) = pair();
        let m0 = alice.encrypt(b"zero");
        let m1 = alice.encrypt(b"one");
        let m2 = alice.encrypt(b"two");
        assert_eq!(bob.decrypt(&m0).unwrap(), b"zero");
        assert_eq!(bob.decrypt(&m2).unwrap(), b"two"); // m1 is stored

        // Круг через персистентную форму.
        let mut bob2 = Session::restore(bob.snapshot());
        assert_eq!(bob2.decrypt(&m1).unwrap(), b"one", "the gap filler comes from the RESTORED store");
    }

    /// Анти-DoS СВЕРХ спеки: forged-сообщение с большим `n` (валидный header, но
    /// битый AEAD) НЕ наполняет skipped-store и НЕ двигает `nr` — откат staged.
    /// Дискриминирующий: коммит до AEAD → store вырос бы, nr прыгнул бы.
    #[test]
    fn forged_high_n_does_not_populate_skipped_store() {
        let (mut alice, mut bob) = pair();
        let m0 = alice.encrypt(b"zero");
        assert_eq!(bob.decrypt(&m0).unwrap(), b"zero");
        let dhr = bob.dhr.unwrap();

        // Валидный header (та же цепочка), n=50, но мусорный ciphertext.
        let forged = RatchetMessage {
            header: Header { dh: dhr, pn: 0, n: 50, salt: [7u8; 16] },
            ciphertext: vec![0u8; 48],
        };
        assert_eq!(bob.decrypt(&forged), Err(RatchetError::Decrypt));
        assert!(bob.skipped.is_empty(), "a forged message did not fill the store (staged changes rolled back)");
        assert_eq!(bob.nr, 1, "a forged message did not advance nr");

        // Сессия цела: следующее легитимное in-order сообщение проходит.
        let m1 = alice.encrypt(b"one");
        assert_eq!(bob.decrypt(&m1).unwrap(), b"one");
    }

    /// `MAX_SKIP`: скачок больше предела за один шаг → отказ, сессия НЕ тронута
    /// (staged отброшен). Граница анти-unbounded-KDF.
    #[test]
    fn gap_larger_than_max_skip_is_rejected_session_intact() {
        let (mut alice, mut bob) = pair();
        let m0 = alice.encrypt(b"zero");
        assert_eq!(bob.decrypt(&m0).unwrap(), b"zero");
        let dhr = bob.dhr.unwrap();

        let too_far = RatchetMessage {
            header: Header { dh: dhr, pn: 0, n: MAX_SKIP + 5, salt: [7u8; 16] },
            ciphertext: vec![0u8; 48],
        };
        assert_eq!(bob.decrypt(&too_far), Err(RatchetError::OutOfOrder));
        assert!(bob.skipped.is_empty(), "no keys were derived");
        assert_eq!(bob.nr, 1, "nr untouched");
        // И сессия продолжает работать в пределах допустимого.
        let m1 = alice.encrypt(b"one");
        assert_eq!(bob.decrypt(&m1).unwrap(), b"one");
    }

    /// CRYPTO-09 (#157): the session's key material is scrubbed when the value is dropped.
    ///
    /// Discriminating on the BYTES, not on the trait: `zeroize()` is called on a session whose
    /// keys are known, and the root key, both chain keys and every stored skipped key must come
    /// back all-zero. Removing `ZeroizeOnDrop` (or a `#[zeroize(skip)]` slapped on `rk` to quiet
    /// a compiler complaint) fails this — an "assert the type implements the trait" test would
    /// not, because the derive can be present and still skip the field that matters.
    ///
    /// What this does NOT prove, stated so nobody reads more into it: that no COPY survives
    /// elsewhere. A move is a memcpy and leaves the source untouched, and reading freed memory to
    /// check would be undefined behaviour. This pins the one thing that is actually checkable —
    /// the owned bytes are cleared — and the type doc carries the rest of the limit.
    #[test]
    fn dropping_a_session_scrubs_its_key_material() {
        use zeroize::Zeroize;
        let (mut alice, mut bob) = pair();
        let m0 = alice.encrypt(b"zero");
        assert_eq!(bob.decrypt(&m0).unwrap(), b"zero");
        // Leave a skipped key behind too, so the vector is not empty when we scrub.
        let _m1 = alice.encrypt(b"one");
        let m2 = alice.encrypt(b"two");
        assert_eq!(bob.decrypt(&m2).unwrap(), b"two");
        assert!(!bob.skipped.is_empty(), "precondition: a skipped key is stored");
        assert_ne!(bob.rk, [0u8; 32], "precondition: the root key is real");
        assert!(bob.ckr.is_some_and(|c| c != [0u8; 32]), "precondition: a receiving chain exists");

        bob.zeroize();

        assert_eq!(bob.rk, [0u8; 32], "the root key must be scrubbed");
        assert_eq!(bob.cks, None, "the sending chain key is gone, not merely blanked");
        assert_eq!(bob.ckr, None, "the receiving chain key is gone, not merely blanked");
        assert!(bob.skipped.is_empty(), "stored skipped message keys must not survive");
    }
}

/// **The claim PRIV-2's whole design rests on**, checked rather than argued.
///
/// The routing chain can only heal if the recipient can derive the next generation BEFORE receiving
/// anything in it. That is possible for exactly one reason: a step's FIRST DH output is numerically
/// the same value the peer computed as its own SECOND output one leg earlier. If that ever stops
/// being true — someone reorders the two `kdf_rk` calls, or takes the contribution from `dh2` —
/// the recipient starts polling an address it cannot compute yet, mail stops arriving, and nothing
/// in the code says why. So it is pinned here, next to the arithmetic that makes it true.
#[cfg(test)]
mod routing_contribution_is_derivable_by_both_sides {
    use super::*;

    /// Both sides produce the SAME contribution sequence, and the recipient produces each element
    /// no later than the sender needs it.
    #[test]
    fn each_step_yields_the_contribution_the_peer_already_produced_one_leg_earlier() {
        // A real two-sided conversation: only `decrypt` advances a DH step, so the legs alternate.
        let root = [5u8; 32];
        let bob_dh = Identity::generate();
        let mut alice = Session::init_sender(root, bob_dh.public.to_bytes());
        let mut bob = Session::init_receiver(root, bob_dh);

        let mut alice_contribs = Vec::new();
        let mut bob_contribs = Vec::new();

        // Six legs, alternating. Each side folds whatever its own step produced.
        for leg in 0..6 {
            if leg % 2 == 0 {
                let m = alice.encrypt(b"from alice");
                bob.decrypt(&m).expect("delivers");
                bob_contribs.extend(bob.take_routing_contributions());
            } else {
                let m = bob.encrypt(b"from bob");
                alice.decrypt(&m).expect("delivers");
                alice_contribs.extend(alice.take_routing_contributions());
            }
        }

        assert!(
            !alice_contribs.is_empty() && !bob_contribs.is_empty(),
            "no contributions were produced at all — the hook is not firing, so the routing chain \
             would silently never advance"
        );

        // THE property, in two halves.
        //
        // (1) SAME SEQUENCE, SAME ORDER. The DH outputs form one sequence both sides walk; each
        //     computes two per step with a one-element overlap, and the sender's init supplies the
        //     first. Compared as PREFIXES, not with an offset: an offset was the first guess and it
        //     was wrong — folding one output per step gives each side only the even or only the odd
        //     elements, so the sequences are disjoint and the recipient can never derive the
        //     sender's address. That mistake reads as correct on paper, which is why this is a test.
        let shared = alice_contribs.len().min(bob_contribs.len());
        assert!(shared >= 4, "not enough legs to compare sequences: {shared}");
        assert_eq!(
            alice_contribs[..shared],
            bob_contribs[..shared],
            "the two sides are walking DIFFERENT contribution sequences. If they do not agree \
             element for element, the recipient cannot derive the box the sender writes to and \
             delivery stops with no error anywhere."
        );

        // (2) DIVERGENCE OF AT MOST ONE. This is what makes a two-wide polling window a BOUND
        //     rather than a guess: a DH step happens only inside `advance_for_decrypt`, so neither
        //     side advances without a successful delivery from the other. If this ever exceeds one,
        //     `drop::ROUTING_WINDOW` is too narrow and mail goes missing intermittently — the
        //     worst possible way for this to break.
        let gap = alice_contribs.len().abs_diff(bob_contribs.len());
        assert!(
            gap <= 1,
            "the two sides drifted {gap} generations apart, not the one leg the design bounds. \
             drop::ROUTING_WINDOW is sized from this bound."
        );
    }

    /// A contribution can be folded once and only once.
    #[test]
    fn a_contribution_is_consumed_not_merely_read() {
        let root = [6u8; 32];
        let bob_dh = Identity::generate();
        let mut alice = Session::init_sender(root, bob_dh.public.to_bytes());
        let mut bob = Session::init_receiver(root, bob_dh);
        let m = alice.encrypt(b"one");
        bob.decrypt(&m).expect("delivers");
        // The first step of a receiver session may or may not ratchet; take twice either way and
        // require the second take to be empty, because a double fold desynchronises the sides.
        let first = bob.take_routing_contributions();
        assert!(
            bob.take_routing_contributions().is_empty(),
            "taking twice returned values twice ({} then more) — folding one step's contributions \
             into two generations puts this side permanently ahead of its peer",
            first.len()
        );
    }

    /// A forged message must not advance routing, for the same reason it must not advance the
    /// ratchet: `decrypt` stages a clone and commits only on a verified AEAD.
    #[test]
    fn a_message_that_fails_to_decrypt_produces_no_contribution() {
        let root = [7u8; 32];
        let bob_dh = Identity::generate();
        let mut alice = Session::init_sender(root, bob_dh.public.to_bytes());
        let mut bob = Session::init_receiver(root, bob_dh);
        let mut m = alice.encrypt(b"one");
        *m.ciphertext.last_mut().expect("non-empty") ^= 0xFF;
        assert!(bob.decrypt(&m).is_err(), "a tampered message must not decrypt");
        assert!(
            bob.take_routing_contributions().is_empty(),
            "a forged message advanced the routing chain — an attacker could push a recipient's \
             routing generation past its peer's and cut delivery without holding any key"
        );
    }
}

/// **Public protocol vectors, and a SECOND implementation that must agree with them** (QA-4).
///
/// Our own tests are written by whoever wrote the code and inherit its misunderstandings. A test
/// that says "`kdf_rk` returns what `kdf_rk` returned last time" catches a typo and nothing else;
/// it cannot catch a misread specification, because both sides of the comparison come from the
/// same reading. So the vectors below are checked twice: once here against the live code, and once
/// by `scripts/verify_vectors.py`, which reimplements the key schedule from the written rules
/// using only Python's standard library — no shared code, no shared crate, no shared reading.
///
/// **Why the key schedule and not the ciphertext.** ChaCha20-Poly1305 is not in Python's standard
/// library, and pulling in a dependency would put a third party's reading of RFC 8439 in the place
/// where an INDEPENDENT reading is supposed to be. HKDF-SHA256 and HMAC-SHA256 are stdlib, so the
/// derivation chain — where a misread spec actually bites, and where a mistake silently produces
/// keys that agree with themselves forever — is fully covered without importing anyone's opinion.
///
/// Pre-alpha means these may be regenerated deliberately (`KARST_REGEN_VECTORS=1`), but BOTH
/// implementations must then be updated and agree again, or the exercise is theatre.
#[cfg(test)]
mod protocol_vectors {
    use super::*;

    const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/ratchet_kdf.json");

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Deterministic inputs, chosen to be obviously arbitrary rather than accidentally special:
    /// no all-zero keys (which hide a missing salt), no equal inputs (which hide a swapped
    /// argument).
    fn cases() -> Vec<(String, String)> {
        let mut out = Vec::new();
        let rk = [0x11u8; 32];
        let dh = [0x22u8; 32];
        let ck = [0x33u8; 32];
        let mk = [0x44u8; 32];
        let salt = [0x55u8; SALT_LEN];

        out.push(("routing_contrib".into(), hex(&routing_contrib(&dh))));
        let (new_rk, chain) = kdf_rk(&rk, &dh);
        out.push(("kdf_rk.new_rk".into(), hex(&new_rk)));
        out.push(("kdf_rk.ck".into(), hex(&chain)));
        let (next_ck, msg_key) = kdf_ck(&ck);
        out.push(("kdf_ck.next_ck".into(), hex(&next_ck)));
        out.push(("kdf_ck.mk".into(), hex(&msg_key)));
        let (key, nonce) = message_aead(&mk, &salt);
        out.push(("message_aead.key".into(), hex(&key)));
        out.push(("message_aead.nonce".into(), hex(&nonce)));

        // The AAD byte layout is part of the wire contract: a reordering here breaks every peer
        // while every local test still passes, because both sides would reorder together.
        let header = Header { dh: [0x66u8; 32], pn: 0x0102_0304, n: 0x0506_0708, salt };
        out.push(("aad".into(), hex(&aad(&header))));
        out
    }

    fn render(cases: &[(String, String)]) -> String {
        let body: Vec<String> =
            cases.iter().map(|(k, v)| format!("  \"{k}\": \"{v}\"")).collect();
        format!("{{\n{}\n}}\n", body.join(",\n"))
    }

    /// The checked-in vectors are what this build produces.
    ///
    /// DISCRIMINATING by construction: change any constant in the key schedule — an info string, a
    /// salt argument, the 0x01/0x02 HMAC tags, the AAD field order — and this reds with the two
    /// values side by side.
    #[test]
    fn the_checked_in_vectors_match_this_build() {
        let produced = render(&cases());
        if std::env::var_os("KARST_REGEN_VECTORS").is_some() {
            std::fs::write(VECTORS, &produced).expect("writing vectors");
            eprintln!("KARST_REGEN_VECTORS: rewrote {VECTORS} — update verify_vectors.py to match");
        }
        let on_disk = std::fs::read_to_string(VECTORS).unwrap_or_default();
        assert_eq!(
            on_disk, produced,
            "the key schedule changed. If that was deliberate: regenerate with \
             KARST_REGEN_VECTORS=1 AND update scripts/verify_vectors.py, which must reach the \
             same numbers from the written rules alone. Updating only one of the two turns this \
             into a test of nothing."
        );
    }

    /// The INDEPENDENT implementation agrees.
    ///
    /// Fails rather than skips when `python3` is missing. A vector check that quietly skips is the
    /// exact failure this file exists to prevent: green, and verifying nothing.
    #[test]
    fn an_independent_implementation_reaches_the_same_numbers() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../scripts/verify_vectors.py");
        let out = std::process::Command::new("python3")
            .arg(script)
            .arg(VECTORS)
            .output()
            .expect("python3 is required for the independent vector check — install it");
        assert!(
            out.status.success(),
            "the independent implementation disagrees with ours:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
