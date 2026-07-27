//! §7.2 — Capability (приглашённый доступ).
//!
//! Relay — сам issuer своих capability: симметричная HMAC-схема, PKI не
//! нужна. Таблица `capability_id → secret/scope/quota` локальна у relay и
//! ограничена им самим, не атакующим. По проводу идёт только
//! `CapabilityProof` — сам `secret` устройство не раскрывает.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Scope {
    MessageDelivery,
    MailboxFetch,
}

/// Квота на capability. `window` — секунды; учёт квоты (расход max_requests/
/// max_bytes) ведёт relay в своей локальной таблице — здесь только пределы.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Quota {
    pub max_requests: u32,
    pub max_bytes: u64,
    pub window_secs: u32,
}

impl Quota {
    /// Apply a relay-operator CEILING: the effective limits are the element-wise MIN of what the
    /// presented capability claims and the operator's policy, over the policy's window. This is why
    /// a live policy change (or a forgeable dev cap that claims a huge quota) cannot exceed what the
    /// operator allows — the relay clamps at enforcement time, not just at capability issuance.
    pub fn clamped_by(&self, ceiling: &Quota) -> Quota {
        Quota {
            max_requests: self.max_requests.min(ceiling.max_requests),
            max_bytes: self.max_bytes.min(ceiling.max_bytes),
            window_secs: ceiling.window_secs,
        }
    }
}

/// Секретная запись, живущая ТОЛЬКО у relay (§7.2). Никогда не уходит на
/// провод. serde — для локального хранения клиентом (capability.json, 0600);
/// это НЕ провод.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Capability {
    pub capability_id: [u8; 16],
    pub scope: Scope,
    pub quota: Quota,
    pub not_before: u32,
    pub not_after: u32,
    pub secret: [u8; 32],
}

/// То, что реально идёт по проводу (§7.2).
///
/// `not_after` is carried for STATELESS PoW capabilities (slice 4a): a Public relay stores
/// no record of a PoW cap, so the client's proof must carry the expiry the relay recomputes
/// the secret from. It is bound into the secret, so a forged `not_after` recomputes to a
/// different secret and the MAC (made with the real one) fails. For stored (dev/invite)
/// capabilities the relay looks the entry up by id and IGNORES this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapabilityProof {
    pub capability_id: [u8; 16],
    pub epoch_id: u32,
    pub not_after: u32,
    pub mac: [u8; 16],
}

/// The result of a successful `verify`: just what the quota stage needs. Owned (not a
/// `&Capability`) because a stateless PoW capability has no stored record to borrow from.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedCapability {
    pub capability_id: [u8; 16],
    pub quota: Quota,
}

/// Quota policy for a PoW-earned capability (slice 4a). **This is the spam bound on the
/// Public door**, a deliberate security parameter (not a test knob): each earned capability
/// may spend at most this RATE (requests + bytes per window) for its lifetime. Sustaining a
/// higher rate needs more capabilities — one more PoW solve per extra `POW_CAP_QUOTA` of
/// throughput. The PoW difficulty rate-limits how fast fresh capabilities appear; this bounds
/// each one's rate. (Per-message cost is NOT `N/max_requests` solves — a cap sends at this
/// rate for `ISSUED_CAP_TTL_SECS`; see `pow.rs`.)
pub const POW_CAP_QUOTA: Quota = Quota {
    max_requests: 100,
    max_bytes: 4 * 1024 * 1024,
    window_secs: 600,
};

fn scope_byte(s: Scope) -> u8 {
    match s {
        Scope::MessageDelivery => 1,
        Scope::MailboxFetch => 2,
    }
}

/// Deterministic id of a PoW capability from its solution (slice 4a). Deterministic ⇒
/// replaying the same Join re-derives the SAME capability (same id → same secret → same
/// quota bucket), so a replayed redemption is harmless rather than minting a second cap.
pub fn pow_cap_id(
    issuer_key: &[u8; 32],
    relay_id: &[u8; 32],
    bucket: u32,
    client_seed: &[u8; 32],
    nonce: u64,
) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(issuer_key).expect("HMAC accepts any key length");
    mac.update(b"pow-cap-id");
    mac.update(relay_id);
    mac.update(&bucket.to_be_bytes());
    mac.update(client_seed);
    mac.update(&nonce.to_be_bytes());
    let full = mac.finalize().into_bytes();
    let mut id = [0u8; 16];
    id.copy_from_slice(&full[..16]);
    id
}

/// Secret of a PoW capability, recomputable by the relay from `issuer_key` ALONE — so PoW
/// caps need no stored record (they survive restart and cannot fill a table). Binds
/// `not_after` and `scope`: a client that forges either recomputes to a different secret, so
/// its MAC (made with the real secret) no longer verifies. Only the relay knows `issuer_key`,
/// so the only way to hold a verifying `(id, secret)` pair is to have been ISSUED one — which
/// requires PoW. That is what enforces the door without a record of who was let in.
pub fn pow_cap_secret(issuer_key: &[u8; 32], cap_id: &[u8; 16], not_after: u32, scope: Scope) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(issuer_key).expect("HMAC accepts any key length");
    mac.update(b"pow-cap-secret");
    mac.update(cap_id);
    mac.update(&not_after.to_be_bytes());
    mac.update(&[scope_byte(scope)]);
    let full = mac.finalize().into_bytes();
    let mut s = [0u8; 32];
    s.copy_from_slice(&full[..32]);
    s
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    /// capability_id не найден в локальной таблице relay.
    UnknownCapability,
    /// now вне [not_before, not_after].
    Expired,
    /// scope запроса не совпал со scope выданной capability.
    ScopeMismatch,
    /// MAC не совпал.
    BadMac,
}

impl Capability {
    /// Построить `CapabilityProof` для данного `request_nonce` и эпохи.
    /// mac = HMAC-SHA256(secret, request_nonce || epoch_id)[:16].
    pub fn prove(&self, request_nonce: &[u8], epoch_id: u32) -> CapabilityProof {
        CapabilityProof {
            capability_id: self.capability_id,
            epoch_id,
            not_after: self.not_after,
            mac: compute_mac(&self.secret, request_nonce, epoch_id),
        }
    }
}

/// Локальная таблица relay: `capability_id → Capability`.
///
/// Two kinds of capability verify through here. STORED ones (dev/invite) live in `entries`,
/// looked up by id. STATELESS PoW ones (slice 4a) are NOT stored: when a Public relay sets
/// `pow_issuer`, an id that misses the table is verified by RECOMPUTING its secret from the
/// issuer key (see `pow_cap_secret`). That is what lets the Public door survive a restart and
/// resist a table-filling DoS — there is no table to fill.
#[derive(Default)]
pub struct CapabilityTable {
    entries: std::collections::HashMap<[u8; 16], Capability>,
    /// `Some` on a Public relay: the key stateless PoW-capability secrets are recomputed
    /// from. `None` on Private/Dev — an unknown id is simply rejected.
    pow_issuer: Option<[u8; 32]>,
}

impl CapabilityTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, cap: Capability) {
        self.entries.insert(cap.capability_id, cap);
    }

    /// Enable stateless PoW-capability verification (the Public door, slice 4a). Idempotent.
    pub fn set_pow_issuer(&mut self, issuer_key: [u8; 32]) {
        self.pow_issuer = Some(issuer_key);
    }

    /// Верификация предъявленного proof (§7.5, Ступень 4, шаг 1 — самый
    /// дешёвый крипто-шаг). `request_nonce`/`requested_scope`/`now` — из
    /// текущего запроса. Возвращает `VerifiedCapability` (не `&Capability`), т.к.
    /// stateless PoW-cap не имеет хранимой записи для заимствования.
    pub fn verify(
        &self,
        proof: &CapabilityProof,
        request_nonce: &[u8],
        requested_scope: Scope,
        now: u32,
    ) -> Result<VerifiedCapability, CapabilityError> {
        // Stored (dev/invite) path — semantics unchanged.
        if let Some(cap) = self.entries.get(&proof.capability_id) {
            if now < cap.not_before || now > cap.not_after {
                return Err(CapabilityError::Expired);
            }
            if cap.scope != requested_scope {
                return Err(CapabilityError::ScopeMismatch);
            }
            let expected = compute_mac(&cap.secret, request_nonce, proof.epoch_id);
            return if expected.ct_eq(&proof.mac).into() {
                Ok(VerifiedCapability { capability_id: cap.capability_id, quota: cap.quota })
            } else {
                Err(CapabilityError::BadMac)
            };
        }

        // Stateless PoW path (Public door): recompute the secret from the issuer key. The
        // secret binds `not_after` and `scope`, so a forged expiry or scope yields a
        // non-matching secret → BadMac. `not_before` is moot: a client cannot hold a
        // verifying secret before the relay issued it.
        if let Some(issuer) = self.pow_issuer {
            if now > proof.not_after {
                return Err(CapabilityError::Expired);
            }
            let secret = pow_cap_secret(&issuer, &proof.capability_id, proof.not_after, requested_scope);
            let expected = compute_mac(&secret, request_nonce, proof.epoch_id);
            return if expected.ct_eq(&proof.mac).into() {
                Ok(VerifiedCapability { capability_id: proof.capability_id, quota: POW_CAP_QUOTA })
            } else {
                Err(CapabilityError::BadMac)
            };
        }

        Err(CapabilityError::UnknownCapability)
    }
}

fn compute_mac(secret: &[u8; 32], request_nonce: &[u8], epoch_id: u32) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(request_nonce);
    mac.update(&epoch_id.to_be_bytes());
    let full = mac.finalize().into_bytes();
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&full[..16]);
    truncated
}

/// Исход учёта квоты для одного запроса capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaDecision {
    /// В пределах квоты — запрос учтён.
    Ok,
    /// Тот же proof уже виден в окне (дословный replay) — не учтён повторно.
    Replay,
    /// Превышен `max_requests` или `max_bytes` за окно `window_secs`.
    Exceeded,
}

/// Учёт расхода квоты по capability_id в скользящем окне `window_secs`.
///
/// Закрывает пробел: без него валидный proof переиспользуем по разу в каждой
/// новой эпохе вплоть до `not_after` (epoch-scoped replay-фильтр §7.5
/// сбрасывается, а `verify` считает MAC по `proof.epoch_id` и не проверяет
/// актуальность эпохи — и НЕ должен: capability намеренно многоэпоховая).
/// Настоящая граница — квота самой capability (§7.2), которую relay обязан
/// вести локально. Та же sliding-window логика, что у DTN carry-бюджета (§7.7).
///
/// Дословный replay ловится по `proof.mac` (при повторе захваченного proof он
/// неизменен, в т.ч. через границу эпохи, пока запись в окне). Память
/// ограничена самим `max_requests` (в окне не больше стольких записей).
/// Скользящее окно одной capability: очередь (время, байты, тег proof).
type QuotaWindow = std::collections::VecDeque<(u64, u64, [u8; 16])>;

#[derive(Default)]
pub struct CapabilityQuotaTracker {
    /// capability_id → окно расхода.
    windows: std::collections::HashMap<[u8; 16], QuotaWindow>,
}

impl CapabilityQuotaTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live per-capability windows. Grows by one per distinct `cap_id`; a Public
    /// relay must `reap` idle ones or this is an unbounded-memory DoS (a fresh PoW `cap_id`
    /// per solve). Exposed so a test can assert the reap actually runs.
    pub fn len(&self) -> usize {
        self.windows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }

    /// Учесть запрос против квоты. Вызывать ТОЛЬКО после успешной верификации proof
    /// (иначе плохой MAC жёг бы чужую квоту). `cap_id`/`quota` — из `VerifiedCapability`
    /// (stored или stateless PoW-cap — квота-учёт одинаков, ключ = `cap_id`);
    /// `proof_tag` — `proof.mac`; `bytes` — размер запроса.
    pub fn consume(
        &mut self,
        cap_id: [u8; 16],
        quota: &Quota,
        proof_tag: [u8; 16],
        bytes: u64,
        now: u64,
    ) -> QuotaDecision {
        let window = quota.window_secs as u64;
        let horizon = now.saturating_sub(window);
        let dq = self.windows.entry(cap_id).or_default();
        // Prune: убрать всё старше окна.
        while let Some(&(ts, _, _)) = dq.front() {
            if ts <= horizon {
                dq.pop_front();
            } else {
                break;
            }
        }
        // Дословный replay: тот же proof-тег уже в окне.
        if dq.iter().any(|&(_, _, tag)| tag == proof_tag) {
            return QuotaDecision::Replay;
        }
        // Квота по числу запросов и по байтам за окно.
        let count = dq.len() as u32;
        let bytes_sum: u64 = dq.iter().map(|&(_, b, _)| b).sum();
        if count + 1 > quota.max_requests || bytes_sum + bytes > quota.max_bytes {
            return QuotaDecision::Exceeded;
        }
        dq.push_back((now, bytes, proof_tag));
        QuotaDecision::Ok
    }

    /// Периодическая уборка: выкинуть capability, чьи окна полностью
    /// протухли (не трогались дольше своего `window_secs`). `consume` сам не
    /// освобождает запись капабилити, к которой больше не обращаются, —
    /// relay вызывает `reap` изредка. Не критично для безопасности (число
    /// окон ограничено числом выданных capability, не атакующим), а гигиена
    /// памяти. Возвращает число убранных записей.
    pub fn reap(&mut self, now: u64, default_window_secs: u64) -> usize {
        let before = self.windows.len();
        self.windows.retain(|_, dq| {
            let horizon = now.saturating_sub(default_window_secs);
            while let Some(&(ts, _, _)) = dq.front() {
                if ts <= horizon {
                    dq.pop_front();
                } else {
                    break;
                }
            }
            !dq.is_empty()
        });
        before - self.windows.len()
    }
}
