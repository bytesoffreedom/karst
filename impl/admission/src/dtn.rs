//! §7.7 — DTN-класс допуска (store-and-forward mesh: Bluetooth/Wi-Fi Direct).
//!
//! Отдельный от live-класса (§7.1–7.5) класс допуска. Модель угроз иная: в
//! mesh соединение физическое, спуфинг адреса третьей стороны невозможен;
//! защищается не сервер, а устройство-носитель — от соседа по эфиру, который
//! заваливает его мусором, разряжая батарею и забивая память. Поэтому — не
//! epoch-based cookie/RLN, а два независимых механизма + отдельный
//! replay-фильтр на возврате в сеть.
//!
//! Крипто здесь только симметричный HMAC (как §7.2) — никакой экзотики,
//! поэтому модуль в ядре, без feature-гейта.
//!
//! **Область (честно).** Здесь построены ПРИМИТИВЫ DTN-класса
//! (capability + carry-бюджет + rolling-replay), но они ещё НЕ вплетены в
//! конвейер `pipeline.rs`. По §10 (аудит-раунд 3) Ingress ветвится по типу
//! credential на Ступени 4 — отдельный DTN-gateway не заводится, — значит
//! rolling-replay и DTN-capability со временем подключаются в эту ветку
//! `pipeline`, а не как параллельный шлюз. Интеграция — следующий срез.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Placeholder-параметр (§7.7): верхняя граница TTL транзита mesh. Требует
/// калибровки по реальным замерам задержки — 7 дней как отправная точка.
pub const MAX_DTN_TRANSIT_TTL_SECS: u64 = 7 * 24 * 60 * 60;
pub const SECS_PER_DAY: u64 = 24 * 60 * 60;

/// Глобальный потолок размера DTN-capsule (§7.7/§21.1). В отличие от
/// live-класса, DTN-capsule — хранимый объект (до ~1 МБ size-bucket'а §21.1),
/// заливаемый потоком, а НЕ UDP-датаграмма под live-MTU `MAX_PACKET_SIZE`.
/// Это дешёвый pre-verification гейт: отбить заведомо огромную загрузку ДО
/// хеширования. Авторитетную квоту на конкретную capsule задаёт
/// `DtnQuota.max_bytes` (проверяется после верификации capability).
pub const MAX_DTN_CAPSULE_SIZE: usize = 1 << 20; // 1 MiB

// ============================================================================
// 1. DTN Capability — отдельный тип, без квантования по epoch (§7.7 п.1)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtnQuota {
    pub max_bytes: u64,
    /// **Рекомендательное поле, НЕ криптографически обеспеченное (§7.7).**
    /// Ничто не привязывает декремент к реальному числу передач: носитель
    /// физически владеет всем состоянием capsule и может не декрементировать.
    /// Настоящая защита — `CarryBudgetTracker` ниже, распоряжающийся
    /// собственным ресурсом устройства. Оставлено как advisory-метаданные
    /// для добросовестных клиентов.
    pub max_hops: u32,
}

/// Секретная запись у выдавшего relay. По проводу идёт только proof.
#[derive(Debug, Clone)]
pub struct DtnCapability {
    pub capability_id: [u8; 16],
    pub issued_at: u64, // unix seconds, без квантования
    pub not_after: u64, // issued_at + до MAX_DTN_TRANSIT_TTL
    pub quota: DtnQuota,
    pub secret: [u8; 32],
}

/// То, что идёт по проводу вместе с capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtnCapabilityProof {
    pub capability_id: [u8; 16],
    pub mac: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtnCapError {
    UnknownCapability,
    /// now > not_after — транзитное окно истекло.
    Expired,
    /// not_after выходит за пределы issued_at + MAX_DTN_TRANSIT_TTL.
    TtlTooLong,
    /// Размер capsule превышает `quota.max_bytes` этой capability.
    QuotaExceeded,
    BadMac,
}

impl DtnCapability {
    /// Проверить корректность самой выданной capability (инвариант TTL).
    pub fn validate_issue(&self) -> Result<(), DtnCapError> {
        if self.not_after > self.issued_at.saturating_add(MAX_DTN_TRANSIT_TTL_SECS) {
            return Err(DtnCapError::TtlTooLong);
        }
        Ok(())
    }

    /// Построить proof: mac = HMAC(secret, request_nonce).
    /// Без epoch (в отличие от live-класса §7.2) — mesh-доставка занимает дни.
    pub fn prove(&self, request_nonce: &[u8]) -> DtnCapabilityProof {
        DtnCapabilityProof {
            capability_id: self.capability_id,
            mac: compute_mac(&self.secret, request_nonce),
        }
    }
}

/// Локальная таблица выдавшего relay: `capability_id → DtnCapability`.
#[derive(Default)]
pub struct DtnCapabilityTable {
    entries: HashMap<[u8; 16], DtnCapability>,
}

impl DtnCapabilityTable {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, cap: DtnCapability) {
        self.entries.insert(cap.capability_id, cap);
    }

    /// Верификация proof: срок (по своим часам) + размер + MAC.
    /// `capsule_bytes` — фактический размер предъявленной capsule; проверяется
    /// против `quota.max_bytes` (§7.7). Порядок: дешёвые проверки (срок,
    /// размер) до MAC.
    pub fn verify(
        &self,
        proof: &DtnCapabilityProof,
        request_nonce: &[u8],
        capsule_bytes: u64,
        now: u64,
    ) -> Result<&DtnCapability, DtnCapError> {
        let cap = self
            .entries
            .get(&proof.capability_id)
            .ok_or(DtnCapError::UnknownCapability)?;
        if now > cap.not_after {
            return Err(DtnCapError::Expired);
        }
        if capsule_bytes > cap.quota.max_bytes {
            return Err(DtnCapError::QuotaExceeded);
        }
        let expected = compute_mac(&cap.secret, request_nonce);
        if expected.ct_eq(&proof.mac).into() {
            Ok(cap)
        } else {
            Err(DtnCapError::BadMac)
        }
    }
}

fn compute_mac(secret: &[u8; 32], request_nonce: &[u8]) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(request_nonce);
    let full = mac.finalize().into_bytes();
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&full[..16]);
    truncated
}

// ============================================================================
// 2. Локальный бюджет носителя: per-peer + device-wide (§7.7 п.2)
// ============================================================================

/// Эфемерная mesh-identity соседа (Bluetooth/Wi-Fi Direct) — отпечаток.
pub type PeerId = [u8; 16];

#[derive(Debug, Clone, Copy)]
pub struct BudgetLimits {
    /// Скользящее окно (§7.7): напр. 24 ч.
    pub window_secs: u64,
    /// Ограничивает ОДНОГО навязчивого соседа.
    pub per_peer_max_messages: u32,
    pub per_peer_max_bytes: u64,
    /// Ограничивает Sybil из многих дешёвых личностей — агрегатно по ВСЕМ
    /// пирам, независимо от числа identity (§7.7: обязательный второй потолок).
    pub device_max_messages: u32,
    pub device_max_bytes: u64,
    /// Локальный PoW-throttle (§7.7): сколько ведущих нулевых бит обязан
    /// предъявить пир на КАЖДУЮ capsule. Не защита от спуфинга (в mesh его
    /// нет), а чистый rate-throttle: как быстро незнакомый пир может залить
    /// тебя за одну сессию контакта. В бою подстраивается под батарею/память
    /// устройства; здесь конфигурируемая константа. 0 = PoW выключен.
    pub pow_difficulty_bits: u32,
}

/// Предложение соседа принять его capsule. PoW привязан к `capsule_tag`,
/// поэтому не переиспользуется между разными capsule.
#[derive(Debug, Clone, Copy)]
pub struct CarryOffer<'a> {
    pub peer: PeerId,
    /// Уникальный тег capsule (напр. её хэш) — к нему привязан PoW.
    pub capsule_tag: &'a [u8],
    pub bytes: u64,
    /// Найденный пиром PoW-nonce (см. `solve_pow`).
    pub pow_nonce: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarryDecision {
    Accept,
    /// PoW недостаточной сложности — throttle до бюджетных проверок.
    RejectPow,
    /// Один пир превысил свой per-peer лимит (device-бюджет ещё есть).
    RejectPerPeer,
    /// Исчерпан агрегатный device-бюджет — независимо от числа identity.
    /// Именно этот отказ ловит Sybil из многих эфемерных пиров.
    RejectDevice,
}

/// Число ведущих нулевых бит в PoW-хэше связки (peer ‖ capsule_tag ‖ nonce).
pub fn pow_leading_zero_bits(peer: &PeerId, capsule_tag: &[u8], nonce: u64) -> u32 {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(b"KARST-dtn-pow-v1");
    h.update(peer);
    h.update((capsule_tag.len() as u64).to_be_bytes());
    h.update(capsule_tag);
    h.update(nonce.to_be_bytes());
    let digest = h.finalize();
    let mut bits = 0u32;
    for byte in digest.iter() {
        if *byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// Найти PoW-nonce нужной сложности для (peer, capsule_tag) — работа пира,
/// не носителя. Возвращает первый подходящий nonce.
pub fn solve_pow(peer: &PeerId, capsule_tag: &[u8], difficulty_bits: u32) -> u64 {
    let mut nonce = 0u64;
    loop {
        if pow_leading_zero_bits(peer, capsule_tag, nonce) >= difficulty_bits {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// Событие в скользящем окне: (время, размер).
type Event = (u64, u64);

/// Локальная политика устройства-носителя. Не часть сетевого протокола, не
/// требует согласования. Память ограничена самим device-бюджетом: мы храним
/// только события внутри окна, а их число не превышает device_max_messages.
pub struct CarryBudgetTracker {
    limits: BudgetLimits,
    per_peer: HashMap<PeerId, VecDeque<Event>>,
    device: VecDeque<(PeerId, u64, u64)>, // (peer, ts, bytes) для агрегата и prune
    device_bytes: u64,
}

impl CarryBudgetTracker {
    pub fn new(limits: BudgetLimits) -> Self {
        CarryBudgetTracker {
            limits,
            per_peer: HashMap::new(),
            device: VecDeque::new(),
            device_bytes: 0,
        }
    }

    /// Убрать из окна всё старше `now - window`. Обновляет device-агрегат и
    /// вычищает опустевшие per-peer записи (иначе Sybil раздул бы карту).
    fn prune(&mut self, now: u64) {
        let horizon = now.saturating_sub(self.limits.window_secs);
        while let Some(&(peer, ts, bytes)) = self.device.front() {
            if ts <= horizon {
                self.device.pop_front();
                self.device_bytes -= bytes;
                if let Some(q) = self.per_peer.get_mut(&peer) {
                    // Снять соответствующее самое старое событие пира.
                    while let Some(&(pts, _)) = q.front() {
                        if pts <= horizon {
                            q.pop_front();
                        } else {
                            break;
                        }
                    }
                    if q.is_empty() {
                        self.per_peer.remove(&peer);
                    }
                }
            } else {
                break;
            }
        }
    }

    fn peer_totals(&self, peer: &PeerId) -> (u32, u64) {
        match self.per_peer.get(peer) {
            Some(q) => (q.len() as u32, q.iter().map(|&(_, b)| b).sum()),
            None => (0, 0),
        }
    }

    /// Решение по входящему предложению нести capsule.
    /// Порядок: PoW-throttle (заставляет пира тратить CPU на каждую попытку) →
    /// per-peer (дешёвый локальный сосед) → device-wide (Sybil). Записываем
    /// только при Accept.
    pub fn offer(&mut self, offer: &CarryOffer, now: u64) -> CarryDecision {
        // PoW-throttle: связан с конкретной capsule, поэтому не
        // переиспользуется. difficulty=0 → проверка пропускается.
        if self.limits.pow_difficulty_bits > 0
            && pow_leading_zero_bits(&offer.peer, offer.capsule_tag, offer.pow_nonce)
                < self.limits.pow_difficulty_bits
        {
            return CarryDecision::RejectPow;
        }

        self.prune(now);

        let (peer_msgs, peer_bytes) = self.peer_totals(&offer.peer);
        if peer_msgs + 1 > self.limits.per_peer_max_messages
            || peer_bytes + offer.bytes > self.limits.per_peer_max_bytes
        {
            return CarryDecision::RejectPerPeer;
        }

        let device_msgs = self.device.len() as u32;
        if device_msgs + 1 > self.limits.device_max_messages
            || self.device_bytes + offer.bytes > self.limits.device_max_bytes
        {
            return CarryDecision::RejectDevice;
        }

        // Accept: записать в оба окна.
        self.per_peer
            .entry(offer.peer)
            .or_default()
            .push_back((now, offer.bytes));
        self.device.push_back((offer.peer, now, offer.bytes));
        self.device_bytes += offer.bytes;
        CarryDecision::Accept
    }

    /// Текущее число событий в окне (для тестов/интроспекции).
    pub fn device_message_count(&self) -> usize {
        self.device.len()
    }
}

// ============================================================================
// 3. Rolling-window replay на возврате в сеть (§7.7 п.3)
// ============================================================================

/// Отдельная от live-класса (epoch-swap) таблица replay-защиты для capsule,
/// пронесённых через mesh. N дневных корзин; запись живёт до своего
/// `not_after`; самая старая корзина переиспользуется при переходе на новый
/// день. Ограничена по памяти не короткостью окна, а низким объёмом
/// mesh-трафика (§7.7).
pub struct RollingReplayWindow {
    buckets: Vec<std::collections::HashSet<[u8; 16]>>,
    /// Какой день (unix_day) сейчас лежит в каждой корзине; None — пусто.
    bucket_day: Vec<Option<u64>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayCheck {
    /// Свежая capsule — принята и зафиксирована.
    Fresh,
    /// Уже видели в окне — replay.
    Replayed,
    /// now > not_after — истекла, не хранится (и так отбрасывается как истёкшая).
    Expired,
    /// not_after дальше, чем окно из N дней от now — не можем гарантировать
    /// replay-защиту так далеко вперёд (за границей окна), отвергаем.
    BeyondWindow,
}

impl RollingReplayWindow {
    /// `days` — размер окна в дневных корзинах (напр. 8 для 7-дневного TTL с запасом).
    pub fn new(days: usize) -> Self {
        RollingReplayWindow {
            buckets: vec![std::collections::HashSet::new(); days],
            bucket_day: vec![None; days],
        }
    }

    fn slot(&self, unix_day: u64) -> usize {
        (unix_day % self.buckets.len() as u64) as usize
    }

    /// Классифицировать `not_after`/`now` без учёта присутствия id (общая
    /// проверка окна для check и insert).
    fn classify(&self, not_after: u64, now: u64) -> Result<(u64, usize), ReplayCheck> {
        if now > not_after {
            return Err(ReplayCheck::Expired);
        }
        let target_day = not_after / SECS_PER_DAY;
        let today = now / SECS_PER_DAY;
        if target_day >= today + self.buckets.len() as u64 {
            return Err(ReplayCheck::BeyondWindow);
        }
        Ok((target_day, self.slot(target_day)))
    }

    /// Дешёвый read-only scan по всем корзинам: присутствует ли id (без
    /// знания not_after). Нужен на Ступени 3, чтобы отбить очевидный replay
    /// ДО дорогого HMAC — авторитетный not_after доступен только после
    /// look up capability на Ступени 4.
    ///
    /// Замечание: скан включает и ещё-не-переиспользованные (устаревшие)
    /// корзины, поэтому может вернуть `true` для id, чья корзина протухла, но
    /// не очищена. Это безопасно: такая capsule заведомо за своим `not_after` и
    /// всё равно отсеивается как `Expired` на Ступени 4 (verify). Ложный
    /// «replay» здесь не пропускает атаку, а лишь раньше отклоняет и так
    /// истёкшую capsule.
    pub fn contains_any(&self, id: &[u8; 16]) -> bool {
        self.buckets.iter().any(|b| b.contains(id))
    }

    /// Зафиксировать capsule (Ступень 4, только ПОСЛЕ успешной верификации).
    /// Возвращает `Replayed`, если id уже был (гонка/двойная вставка).
    pub fn insert(&mut self, id: [u8; 16], not_after: u64, now: u64) -> ReplayCheck {
        let (target_day, idx) = match self.classify(not_after, now) {
            Ok(v) => v,
            Err(c) => return c,
        };
        // Recycle: если корзина держит другой (старый) день — очистить.
        if self.bucket_day[idx] != Some(target_day) {
            self.buckets[idx].clear();
            self.bucket_day[idx] = Some(target_day);
        }
        if self.buckets[idx].contains(&id) {
            ReplayCheck::Replayed
        } else {
            self.buckets[idx].insert(id);
            ReplayCheck::Fresh
        }
    }

    /// Удобный check-then-insert (для standalone-использования/тестов).
    /// В конвейере НЕ используется — там check на Ступени 3, insert на 4.
    pub fn check_and_insert(&mut self, id: [u8; 16], not_after: u64, now: u64) -> ReplayCheck {
        self.insert(id, not_after, now)
    }
}
