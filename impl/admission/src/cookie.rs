//! §7.1 — Stateless Cookie.
//!
//! Первый ответ на непроверенный адрес — всегда фиксированный 64-байтовый
//! challenge (§7.5, Ступень 1), независимо от содержимого запроса. Relay
//! хранит только два `relay_epoch_key` (текущий и предыдущий) — O(1) по
//! числу клиентов, никакого per-client состояния.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::params::{cookie_epoch_id, COOKIE_TTL_SECS, GRACE_EPOCHS};

type HmacSha256 = Hmac<Sha256>;

pub const COOKIE_VERSION: u8 = 1;
/// Сериализованный размер cookie на проводе: 1 + 4 + 16 + 4 + 16.
pub const COOKIE_WIRE_SIZE: usize = 41;

/// Причина отказа при верификации cookie. Никогда не логирует адрес клиента.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieError {
    BadLength,
    BadVersion,
    /// epoch_id вне окна [current-GRACE_EPOCHS, current].
    StaleEpoch,
    /// issued_at выходит за пределы COOKIE_TTL относительно now.
    Expired,
    /// MAC не совпал (спуфинг адреса / carrier_id, либо чужой ключ).
    BadMac,
}

/// Cookie в том виде, как он уходит на провод (§7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Cookie {
    pub version: u8,
    pub epoch_id: u32,
    pub client_addr_hash: [u8; 16],
    pub issued_at: u32,
    pub mac: [u8; 16], // truncated HMAC-SHA256
}

impl Cookie {
    pub fn to_bytes(&self) -> [u8; COOKIE_WIRE_SIZE] {
        let mut out = [0u8; COOKIE_WIRE_SIZE];
        out[0] = self.version;
        out[1..5].copy_from_slice(&self.epoch_id.to_be_bytes());
        out[5..21].copy_from_slice(&self.client_addr_hash);
        out[21..25].copy_from_slice(&self.issued_at.to_be_bytes());
        out[25..41].copy_from_slice(&self.mac);
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Cookie, CookieError> {
        if buf.len() != COOKIE_WIRE_SIZE {
            return Err(CookieError::BadLength);
        }
        let mut client_addr_hash = [0u8; 16];
        client_addr_hash.copy_from_slice(&buf[5..21]);
        let mut mac = [0u8; 16];
        mac.copy_from_slice(&buf[25..41]);
        Ok(Cookie {
            version: buf[0],
            epoch_id: u32::from_be_bytes(buf[1..5].try_into().unwrap()),
            client_addr_hash,
            issued_at: u32::from_be_bytes(buf[21..25].try_into().unwrap()),
            mac,
        })
    }
}

/// Держатель эпоховых ключей relay. Хранит ровно 2 ключа: текущий и
/// предыдущий, чтобы cookie на границе ротации не отбрасывались (§7.1).
pub struct CookieKeyring {
    epoch_duration_secs: u64,
    current_epoch: u32,
    current_key: [u8; 32],
    previous_key: [u8; 32],
}

impl CookieKeyring {
    /// `seed_now` — время инициализации; ключи задаются извне (детерминизм
    /// для тест-векторов), в бою генерируются из CSPRNG.
    pub fn new(
        epoch_duration_secs: u64,
        now_secs: u64,
        current_key: [u8; 32],
        previous_key: [u8; 32],
    ) -> Self {
        CookieKeyring {
            epoch_duration_secs,
            current_epoch: cookie_epoch_id(now_secs, epoch_duration_secs),
            current_key,
            previous_key,
        }
    }

    /// Ротация при переходе в новую cookie-эпоху: текущий → предыдущий,
    /// новый ключ → текущий. Relay вызывает это, передавая текущее время;
    /// эпоха выводится из `epoch_duration_secs`, чтобы вся арифметика эпох
    /// жила в одном месте. No-op, если эпоха ещё не сменилась.
    pub fn rotate_if_needed(&mut self, now_secs: u64, new_key: [u8; 32]) -> bool {
        let new_epoch = cookie_epoch_id(now_secs, self.epoch_duration_secs);
        if new_epoch <= self.current_epoch {
            return false;
        }
        self.previous_key = self.current_key;
        self.current_key = new_key;
        self.current_epoch = new_epoch;
        true
    }

    fn key_for_epoch(&self, epoch_id: u32) -> Option<&[u8; 32]> {
        if epoch_id == self.current_epoch {
            Some(&self.current_key)
        } else if self.current_epoch.checked_sub(epoch_id).is_some_and(|d| {
            (d as u64) <= GRACE_EPOCHS && d >= 1
        }) {
            Some(&self.previous_key)
        } else {
            None
        }
    }

    /// Выдать cookie для (client_addr, carrier_id) на текущую эпоху.
    pub fn issue(
        &self,
        client_addr: &[u8],
        carrier_id: &[u8],
        issued_at: u32,
    ) -> Cookie {
        let mac = compute_mac(
            &self.current_key,
            client_addr,
            carrier_id,
            issued_at,
        );
        Cookie {
            version: COOKIE_VERSION,
            epoch_id: self.current_epoch,
            client_addr_hash: addr_hash(client_addr),
            issued_at,
            mac,
        }
    }

    /// Верификация предъявленного cookie (§7.5, Ступень 1).
    ///
    /// `now_secs` нужен для TTL-проверки. Проверки идут от дешёвых к
    /// дорогим: версия → эпоха → TTL → MAC (последний — единственный крипто-
    /// шаг), в духе §7.6.
    pub fn verify(
        &self,
        cookie: &Cookie,
        client_addr: &[u8],
        carrier_id: &[u8],
        now_secs: u64,
    ) -> Result<(), CookieError> {
        if cookie.version != COOKIE_VERSION {
            return Err(CookieError::BadVersion);
        }
        let key = self
            .key_for_epoch(cookie.epoch_id)
            .ok_or(CookieError::StaleEpoch)?;

        // TTL: issued_at не в будущем более чем на допуск, и не старше TTL.
        // Небольшой допуск на рассинхрон часов — один COOKIE_TTL вперёд.
        let issued = cookie.issued_at as u64;
        if issued > now_secs.saturating_add(COOKIE_TTL_SECS)
            || now_secs.saturating_sub(issued) > COOKIE_TTL_SECS
        {
            return Err(CookieError::Expired);
        }

        let expected = compute_mac(key, client_addr, carrier_id, cookie.issued_at);
        // Постоянное время: не даём таймингу выдать, сколько байт совпало.
        if expected.ct_eq(&cookie.mac).into() {
            Ok(())
        } else {
            Err(CookieError::BadMac)
        }
    }
}

/// cookie.mac = HMAC-SHA256(key, client_addr || carrier_id || issued_at)[:16]
/// CANONICAL, LENGTH-PREFIXED MAC input (CRYPTO-07 / A10-7).
///
/// The fields used to be concatenated raw. Two of them are variable length, so `("a", "bc")` and
/// `("ab", "c")` produced the SAME MAC message at the same time — a cookie issued for one
/// (address, carrier) split verified under another, weakening exactly the binding the cookie
/// exists to provide. A domain tag and a version are included too, so a MAC can never be
/// reinterpreted under a different scheme, and `client_addr_hash` is now covered rather than being
/// a field nobody authenticates.
fn compute_mac(
    key: &[u8; 32],
    client_addr: &[u8],
    carrier_id: &[u8],
    issued_at: u32,
) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"KARST-cookie-mac-v1");
    mac.update(&[COOKIE_VERSION]);
    mac.update(&(client_addr.len() as u32).to_be_bytes());
    mac.update(client_addr);
    mac.update(&(carrier_id.len() as u32).to_be_bytes());
    mac.update(carrier_id);
    mac.update(&addr_hash(client_addr));
    mac.update(&issued_at.to_be_bytes());
    let full = mac.finalize().into_bytes();
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&full[..16]);
    truncated
}

/// client_addr_hash в cookie — это не сам адрес, а его отпечаток (не для
/// безопасности MAC, а чтобы relay мог грубо сопоставить без хранения).
/// Полная привязка адреса обеспечивается MAC над сырым client_addr.
fn addr_hash(client_addr: &[u8]) -> [u8; 16] {
    use sha2::Digest;
    let digest = Sha256::digest(client_addr);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}
