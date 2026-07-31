//! §7.5 / §7.6 — Полный порядок проверки входящего запроса.
//!
//! Память на каждой ступени растёт только пропорционально уже проверенной
//! легитимной нагрузке (§7.5). Порядок ступеней = порядок по цене: дешёвые
//! отказы раньше дорогих (§7.6).
//!
//! ```text
//! Ступень 0  bounded parse         — бюджет на длину, без аллокаций по непроверенной длине
//! Ступень 1  cookie                — нет валидного → ровно 64 байта, состояние НЕ создаётся
//! Ступень 2  формат credential     — структура без крипто, reject мусора бесплатно
//! Ступень 3  replay/freshness      — bounded-фильтр, привязан к quota-эпохе
//! Ступень 4  дорогая криптография  — по возрастанию цены: capability HMAC → token ring-sig → RLN zk
//! Ступень 5  bounded session state — LRU, жёсткий потолок → Mix/Mailbox/Egress (§10)
//! ```

use crate::capability::{
    CapabilityError, CapabilityProof, CapabilityQuotaTracker, CapabilityTable, Quota, QuotaDecision, Scope,
};
use crate::cookie::{Cookie, CookieError, CookieKeyring};
use crate::dtn::{
    DtnCapError, DtnCapabilityProof, DtnCapabilityTable, ReplayCheck, RollingReplayWindow,
    MAX_DTN_CAPSULE_SIZE,
};
use crate::params::COOKIE_CHALLENGE_SIZE;
use crate::token::{AdmissionToken, AdmissionTokenVerifier, IssuerRing, TokenError};

/// Предъявляемый credential (§7.5, Ступень 4). RLN здесь не отдельный
/// credential, а квота-слой поверх допуска; его zk-гейт застаблен (см. `rln`),
/// поэтому в конвейере он представлен явно недоступной ветвью.
pub enum Credential {
    Capability(CapabilityProof),
    Token(AdmissionToken),
    /// RLN-квота: zk-обёртка не реализована (§7.4). Ветвь присутствует,
    /// чтобы конвейер честно показывал «этот путь пока не проходит», а не
    /// делал вид, что RLN готов.
    RlnQuota,
}

pub struct Request<'a> {
    /// Длина сырого пакета до разбора (для Ступени 0).
    pub raw_len: usize,
    /// Stage-0 ceiling for THIS request's CLASS, supplied by the caller.
    ///
    /// It used to be a single hardcoded `MAX_PACKET_SIZE` for every kind of request, which forced
    /// a choice between two wrong answers wherever a class legitimately costs more: charge the
    /// real cost and have stage 0 reject every honest request, or charge a fiction and leave the
    /// difference unmetered. A bundle publish carrying a full one-time-prekey batch is ~28 KiB
    /// against a 2560-byte ceiling, so it took the second — the batch was free (A10-1).
    ///
    /// The caller declares the ceiling because only it knows the class; `wire::max_frame_for`
    /// already does exactly this one layer up, and the asymmetry between the two was the defect.
    /// Use [`crate::params::MAX_PACKET_SIZE`] for the ordinary live path.
    pub max_raw_len: usize,
    pub client_addr: &'a [u8],
    pub carrier_id: &'a [u8],
    /// Cookie, если клиент уже прошёл первый round-trip; None — первый контакт.
    pub cookie: Option<Cookie>,
    pub request_nonce: &'a [u8],
    pub requested_scope: Scope,
    pub credential: Credential,
}

/// Запрос DTN-ветки Ingress (§7.7): capsule, вернувшаяся из mesh и заливаемая
/// в сеть онлайн-носителем.
///
/// **Единственный идентификатор capsule = `H(ciphertext)`** — он же вход MAC
/// (привязка подписи к содержимому), он же ключ rolling-window. Поэтому:
/// - наблюдатель в mesh не может прицепить валидный proof к другому контенту
///   (изменил контент → другой хэш → и MAC, и replay-ключ другие);
/// - `capsule_bytes` и `capsule_id` берутся С ПРОВОДА (из `ciphertext`), а не
///   из клиентских полей; `not_after`/`max_bytes` — из авторитетной
///   capability на Ступени 4.
pub struct DtnRequest<'a> {
    pub raw_len: usize,
    pub client_addr: &'a [u8],
    pub carrier_id: &'a [u8],
    pub cookie: Option<Cookie>,
    /// Proof DTN-capability; его MAC покрывает `H(ciphertext)`.
    pub proof: DtnCapabilityProof,
    /// Сырой шифртекст capsule — источник и id, и размера.
    pub ciphertext: &'a [u8],
}

/// Исход прохождения конвейера.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Ступень 0/2: молчаливый reject без ответа (мусор/переразмер).
    DropNoReply(DropReason),
    /// Ступень 1: нет валидного cookie — ответ ровно 64 байта, состояние не создаётся.
    Challenge([u8; COOKIE_CHALLENGE_SIZE]),
    /// Ступень 3: replay-фильтр переполнен — сигнал поднять adaptive PoW.
    /// Запрос не принят, но это не «мусор», а перегрузка (§7.5, Ступень 3).
    BackpressurePow,
    /// Ступень 3/4: запрос отвергнут по конкретной причине (replay/крипто).
    Reject(RejectReason),
    /// Ступень 5: допущен, передаётся в session state → Mix/Mailbox/Egress.
    Admit,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DropReason {
    /// Ступень 0: длина превышает MAX_PACKET_SIZE.
    Oversize,
    /// Ступень 2: структура credential не разобралась (пустой nonce и т.п.).
    MalformedCredential,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RejectReason {
    Cookie(CookieError),
    Capability(CapabilityError),
    Token(TokenError),
    Replay,
    /// Capability исчерпала квоту (max_requests/max_bytes за окно, §7.2).
    CapabilityQuota,
    /// RLN zk-обёртка не реализована — путь заведомо не проходит (§7.4).
    RlnNotImplemented,
    /// DTN-ветка (§7.7): capability не прошла (срок/размер/MAC/неизвестна).
    Dtn(DtnCapError),
    /// DTN-ветка: capsule уже видели (rolling-window replay).
    DtnReplay,
    /// DTN-ветка: capsule истекла (now > not_after).
    DtnExpired,
    /// DTN-ветка: not_after дальше окна rolling-window — гарантий нет.
    DtnBeyondWindow,
}

/// Bounded replay/freshness-фильтр (§7.5, Ступень 3).
///
/// Спека называет Bloom/cuckoo; здесь — ограниченный по ёмкости `HashSet` с
/// жёстким потолком, привязанный к quota-эпохе и сбрасываемый при её ротации.
/// Свойство, которое проверяет реализация, — именно bounded-memory + сигнал
/// backpressure при переполнении, а не конкретная вероятностная структура
/// (её выбор — оптимизация, не изменение поведения на границе).
pub struct ReplayFilter {
    epoch_id: u32,
    seen: std::collections::HashSet<[u8; 16]>,
    capacity: usize,
}

impl ReplayFilter {
    pub fn new(epoch_id: u32, capacity: usize) -> Self {
        ReplayFilter {
            epoch_id,
            seen: std::collections::HashSet::new(),
            capacity,
        }
    }

    /// Сброс при ротации quota-эпохи (§7.5): весь фильтр обнуляется.
    pub fn roll_epoch(&mut self, new_epoch: u32) {
        if new_epoch != self.epoch_id {
            self.seen.clear();
            self.epoch_id = new_epoch;
        }
    }

    /// Дешёвый READ-ONLY-взгляд: видели ли тег. Ничего не занимает — используется на
    /// Ступени 3, чтобы отбить очевидный replay ДО дорогой крипты, не отдавая
    /// неаутентифицированному запросу слот в фильтре (R2-1).
    fn contains(&self, tag: &[u8; 16]) -> bool {
        self.seen.contains(tag)
    }

    /// Пытается зафиксировать тег. Возвращает:
    /// - `Ok(true)`  — свежий, принят;
    /// - `Ok(false)` — уже видели (replay);
    /// - `Err(())`   — фильтр полон (переполнение → backpressure/PoW).
    ///
    /// Вызывается ТОЛЬКО после успешной верификации credential — иначе мусорный proof
    /// занимает ёмкость и валит отправку всему relay (R2-1; DTN-ветка так делала всегда).
    fn commit(&mut self, tag: [u8; 16]) -> Result<bool, ()> {
        if self.seen.contains(&tag) {
            return Ok(false);
        }
        if self.seen.len() >= self.capacity {
            return Err(());
        }
        self.seen.insert(tag);
        Ok(true)
    }
}

/// Оркестратор конвейера. Держит ссылки на состояние relay.
pub struct AdmissionPipeline<'r, V: AdmissionTokenVerifier> {
    pub keyring: &'r CookieKeyring,
    pub capabilities: &'r CapabilityTable,
    pub token_verifier: &'r V,
    pub issuer_ring: &'r IssuerRing,
}

impl<'r, V: AdmissionTokenVerifier> AdmissionPipeline<'r, V> {
    /// Ступени 0–1, общие для live- и DTN-веток единого Ingress (§10: одна
    /// точка входа, ветвление по типу credential — не отдельный gateway).
    /// `Some(outcome)` = короткое замыкание (drop/challenge); `None` = прошли.
    ///
    /// Cookie сохраняется и для DTN: capsule, вернувшуюся из mesh, заливает в
    /// сеть УЖЕ онлайн-носитель — cookie защищает именно этот онлайн-аплинк от
    /// амплификации (спуфинг внутри самого mesh невозможен, §7.7).
    // Аргументы примитивны и различны; бандл в структуру ради линта добавил бы
    // лишнюю косвенность в приватный хелпер.
    #[allow(clippy::too_many_arguments)]
    fn precheck(
        &self,
        raw_len: usize,
        max_raw_len: usize,
        client_addr: &[u8],
        carrier_id: &[u8],
        cookie: &Option<Cookie>,
        now_secs: u64,
        challenge_bytes: [u8; COOKIE_CHALLENGE_SIZE],
    ) -> Option<Outcome> {
        // Ступень 0: bounded parse. Потолок зависит от класса: live-MTU для
        // live-пути, MB-масштабный DTN-потолок для хранимой mesh-capsule.
        if raw_len > max_raw_len {
            return Some(Outcome::DropNoReply(DropReason::Oversize));
        }
        // Ступень 1: cookie.
        let cookie = match cookie {
            Some(c) => c,
            None => return Some(Outcome::Challenge(challenge_bytes)),
        };
        if self
            .keyring
            .verify(cookie, client_addr, carrier_id, now_secs)
            .is_err()
        {
            return Some(Outcome::Challenge(challenge_bytes));
        }
        None
    }

    /// Live-путь (§7.5). `replay` — epoch-фильтр live-класса; `cap_quota` —
    /// учёт расхода квоты capability за её окно (§7.2), не сбрасывается по
    /// эпохе (в отличие от `replay`) — иначе валидный proof переиспользуем
    /// каждую эпоху до `not_after`.
    pub fn process(
        &self,
        req: &Request,
        now_secs: u64,
        epoch_id: u32,
        challenge_bytes: [u8; COOKIE_CHALLENGE_SIZE],
        replay: &mut ReplayFilter,
        cap_quota: &mut CapabilityQuotaTracker,
    ) -> Outcome {
        self.process_with_policy(req, now_secs, epoch_id, challenge_bytes, replay, cap_quota, None)
    }

    /// As [`process`], but the operator's live quota `policy` clamps every capability's effective
    /// quota (`None` = no ceiling, use the capability's own quota — the historical behaviour). The
    /// relay passes its current policy so a change over the admin channel (or an "off") takes effect
    /// immediately, for already-issued capabilities too.
    #[allow(clippy::too_many_arguments)]
    pub fn process_with_policy(
        &self,
        req: &Request,
        now_secs: u64,
        epoch_id: u32,
        challenge_bytes: [u8; COOKIE_CHALLENGE_SIZE],
        replay: &mut ReplayFilter,
        cap_quota: &mut CapabilityQuotaTracker,
        quota_policy: Option<Quota>,
    ) -> Outcome {
        // --- Ступени 0–1 ---
        if let Some(out) = self.precheck(
            req.raw_len,
            req.max_raw_len,
            req.client_addr,
            req.carrier_id,
            &req.cookie,
            now_secs,
            challenge_bytes,
        ) {
            return out;
        }

        // --- Ступень 2: формат credential (без крипто) ---
        if req.request_nonce.is_empty() {
            return Outcome::DropNoReply(DropReason::MalformedCredential);
        }

        // --- Ступень 3: replay/freshness — ТОЛЬКО read-only CHECK ---
        // Порядок здесь критичен и теперь совпадает с DTN-веткой (см. `process_dtn`).
        // Тег для capability — это `proof.mac`, поле С ПРОВОДА: если фиксировать его ДО
        // проверки HMAC, любой обладатель обычной cookie заливает фильтр мусорными MAC'ами,
        // и после переполнения КАЖДЫЙ новый уникальный запрос получает BackpressurePow до
        // смены эпохи — дешёвый отказ отправки для всего relay (R2-1). Поэтому здесь только
        // дешёвый взгляд (настоящий replay отбивается сразу), а вставка — после Ступени 4.
        replay.roll_epoch(epoch_id);
        let replay_tag = credential_replay_tag(&req.credential);
        if let Some(tag) = replay_tag {
            if replay.contains(&tag) {
                return Outcome::Reject(RejectReason::Replay);
            }
        }

        // --- Ступень 4: дорогая криптография по возрастанию цены ---
        match &req.credential {
            // Шаг 1: Capability HMAC (дешевле всего).
            Credential::Capability(proof) => {
                let cap = match self.capabilities.verify(
                    proof,
                    req.request_nonce,
                    req.requested_scope,
                    now_secs as u32,
                ) {
                    Ok(c) => c,
                    Err(e) => return Outcome::Reject(RejectReason::Capability(e)),
                };
                // Учёт квоты — ТОЛЬКО после успешного MAC (иначе плохой proof
                // жёг бы чужую квоту). Тег = proof.mac (стабилен при дословном
                // replay, в т.ч. через границу эпохи). cap_id/quota — из verify
                // (stored или stateless PoW-cap, учёт одинаков).
                // The operator's policy (if any) clamps the effective quota — a forgeable dev cap or
                // a stale over-generous token cannot exceed what the relay currently allows.
                let effective = match quota_policy {
                    Some(p) => cap.quota.clamped_by(&p),
                    None => cap.quota,
                };
                match cap_quota.consume(cap.capability_id, &effective, proof.mac, req.raw_len as u64, now_secs) {
                    QuotaDecision::Ok => {}
                    QuotaDecision::Replay => return Outcome::Reject(RejectReason::Replay),
                    QuotaDecision::Exceeded => {
                        return Outcome::Reject(RejectReason::CapabilityQuota)
                    }
                }
            }
            // Шаг 2: Admission token ring signature.
            Credential::Token(token) => {
                match self
                    .token_verifier
                    .verify(token, self.issuer_ring, epoch_id)
                {
                    Ok(()) => {}
                    Err(e) => return Outcome::Reject(RejectReason::Token(e)),
                }
            }
            // Шаг 3: RLN zk-proof — не реализован (§7.4), путь честно не проходит.
            Credential::RlnQuota => {
                return Outcome::Reject(RejectReason::RlnNotImplemented)
            }
        }

        // Фиксация replay-тега — ТОЛЬКО теперь, когда credential ВЕРИФИЦИРОВАН (R2-1).
        // Неаутентифицированный запрос сюда не доходит, поэтому ёмкость фильтра тратят лишь
        // те, кто реально предъявил валидный credential (а их дополнительно держит квота).
        if let Some(tag) = replay_tag {
            match replay.commit(tag) {
                Ok(true) => {}
                Ok(false) => return Outcome::Reject(RejectReason::Replay), // lost the race
                Err(()) => return Outcome::BackpressurePow,
            }
        }

        // --- Ступень 5: bounded session state → Mix/Mailbox/Egress ---
        Outcome::Admit
    }

    /// DTN-путь (§7.7) того же Ingress. `dtn_caps` — таблица DTN-capability,
    /// `dtn_replay` — отдельный rolling-window (не epoch-фильтр live-класса).
    ///
    /// Порядок для DTN критичен и ОТЛИЧАЕТСЯ от live (по разбору с advisor):
    /// Ступень 3 — только read-only CHECK (дёшево отбить настоящий replay), а
    /// вставка в rolling-window — ТОЛЬКО после успешного HMAC на Ступени 4.
    /// Иначе атакующий, подсмотревший id capsule в mesh, зальёт её первым с
    /// мусорным proof, сожжёт id на Ступени 3, а настоящую capsule потом отобьют
    /// как «replay».
    pub fn process_dtn(
        &self,
        req: &DtnRequest,
        dtn_caps: &DtnCapabilityTable,
        dtn_replay: &mut RollingReplayWindow,
        now_secs: u64,
        challenge_bytes: [u8; COOKIE_CHALLENGE_SIZE],
    ) -> Outcome {
        // --- Ступени 0–1 (общие) ---
        // DTN-потолок (MB-масштаб), НЕ live-MTU: capsule — хранимый объект.
        // Дешёвый гейт до хеширования ciphertext.
        if let Some(out) = self.precheck(
            req.raw_len,
            MAX_DTN_CAPSULE_SIZE,
            req.client_addr,
            req.carrier_id,
            &req.cookie,
            now_secs,
            challenge_bytes,
        ) {
            return out;
        }

        // --- Ступень 2: формат (без крипто) ---
        if req.ciphertext.is_empty() {
            return Outcome::DropNoReply(DropReason::MalformedCredential);
        }

        // Единственный идентификатор capsule — с провода, не из клиентских полей.
        let full_hash = capsule_hash(req.ciphertext);
        let mut replay_key = [0u8; 16];
        replay_key.copy_from_slice(&full_hash[..16]);
        let capsule_bytes = req.ciphertext.len() as u64;

        // --- Ступень 3: дешёвый read-only CHECK (scan, без not_after) ---
        // Отбивает очевидный replay ДО HMAC, но НЕ сжигает id (insert только
        // после верификации на Ступени 4).
        if dtn_replay.contains_any(&replay_key) {
            return Outcome::Reject(RejectReason::DtnReplay);
        }

        // --- Ступень 4: верификация DTN-capability ---
        // MAC над H(ciphertext) (привязка к содержимому), срок, размер против
        // авторитетной квоты. not_after берём из найденной capability, не из
        // клиента.
        let cap = match dtn_caps.verify(&req.proof, &full_hash, capsule_bytes, now_secs) {
            Ok(c) => c,
            Err(DtnCapError::Expired) => return Outcome::Reject(RejectReason::DtnExpired),
            Err(e) => return Outcome::Reject(RejectReason::Dtn(e)),
        };
        let not_after = cap.not_after;

        // Фиксация в rolling-window — ТОЛЬКО теперь, после успешного HMAC.
        // (Expired здесь не наступит — verify уже проверил срок; BeyondWindow
        // осмыслен — зависит от not_after, окна rolling-window.)
        match dtn_replay.insert(replay_key, not_after, now_secs) {
            ReplayCheck::Fresh => {}
            ReplayCheck::Replayed => return Outcome::Reject(RejectReason::DtnReplay), // lost the race
            ReplayCheck::Expired => return Outcome::Reject(RejectReason::DtnExpired),
            ReplayCheck::BeyondWindow => return Outcome::Reject(RejectReason::DtnBeyondWindow),
        }

        // --- Ступень 5 ---
        Outcome::Admit
    }
}

/// `H(ciphertext)` — единственный идентификатор capsule (§7.7-интеграция).
/// Публичный: DTN-отправитель обязан вычислять id тем же способом, чтобы
/// его proof (MAC над этим значением) совпал с тем, что пересчитает Ingress.
pub fn capsule_hash(ciphertext: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"KARST-dtn-capsule-id");
    h.update(ciphertext);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Тег для replay-фильтра: для токена — его `t` (уникальный per-token); для
/// capability — MAC proof'а (уникален per (nonce, epoch)). RLN не доходит до
/// фильтра в этой реализации (zk застаблен раньше по ветке — но тег на всякий
/// случай не выдаём).
fn credential_replay_tag(cred: &Credential) -> Option<[u8; 16]> {
    match cred {
        Credential::Capability(p) => Some(p.mac),
        Credential::Token(t) => {
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&t.t[..16]);
            Some(tag)
        }
        Credential::RlnQuota => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Дискриминирующий тест `roll_epoch`: смена эпохи ОЧИЩАЕТ live replay-фильтр.
    /// Через полный конвейер это замаскировано quota-трекером (для capability) —
    /// здесь проверяем сам примитив, где эффект наблюдаем напрямую. Именно на это
    /// опирается epoch-scoped replay-защита узла.
    #[test]
    fn roll_epoch_clears_replay_filter() {
        let mut f = ReplayFilter::new(0, 16);
        let tag = [7u8; 16];
        assert_eq!(f.commit(tag), Ok(true)); // fresh
        assert_eq!(f.commit(tag), Ok(false)); // replay inside the same epoch
        f.roll_epoch(1); // epoch change
        assert_eq!(f.commit(tag), Ok(true), "an epoch change must clear the filter");
        // Тот же номер эпохи повторно — идемпотентно, НЕ очищает.
        f.roll_epoch(1);
        assert_eq!(f.commit(tag), Ok(false), "the same epoch_id must not reset it");
    }
}
