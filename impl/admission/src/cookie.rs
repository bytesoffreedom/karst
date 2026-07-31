//! §7.1 — Stateless Cookie.
//!
//! The first reply to an unverified address is always a fixed 64-byte challenge (§7.5, Stage 1),
//! whatever the request contained. The relay keeps only two `relay_epoch_key`s (current and
//! previous) — O(1) in the number of clients, with no per-client state.
//! previous) — O(1) in the number of clients, with no per-client state.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::params::{cookie_epoch_id, COOKIE_TTL_SECS, GRACE_EPOCHS};

type HmacSha256 = Hmac<Sha256>;

pub const COOKIE_VERSION: u8 = 1;
/// The serialised size of a cookie on the wire: 1 + 4 + 16 + 4 + 16.
pub const COOKIE_WIRE_SIZE: usize = 41;

/// The reason a cookie failed verification. It never logs the client's address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieError {
    BadLength,
    BadVersion,
    /// epoch_id is outside the window [current-GRACE_EPOCHS, current].
    StaleEpoch,
    /// issued_at is outside COOKIE_TTL relative to now.
    Expired,
    /// The MAC did not match (a spoofed address or carrier_id, or a foreign key).
    BadMac,
}

/// The cookie as it goes on the wire (§7.1).
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

/// The holder of the relay's epoch keys. It stores exactly two: the current and the previous, so
/// that cookies on a rotation boundary are not discarded (§7.1).
pub struct CookieKeyring {
    epoch_duration_secs: u64,
    current_epoch: u32,
    current_key: [u8; 32],
    previous_key: [u8; 32],
}

impl CookieKeyring {
    /// `seed_now` is the initialisation time; the keys are supplied from outside (determinism for
    /// test vectors) and generated from a CSPRNG in production.
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

    /// Rotation when a new cookie epoch begins: current → previous, and a new key becomes current.
    /// The relay calls this with the current time; the epoch is derived from
    /// `epoch_duration_secs` so that all epoch arithmetic lives in one place. A no-op if the epoch
    /// has not turned yet.
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

    /// Issue a cookie for (client_addr, carrier_id) in the current epoch.
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

    /// Verify a presented cookie (§7.5, Stage 1).
    ///
    /// `now_secs` is needed for the TTL check. The checks run cheapest first: version → epoch →
    /// TTL → MAC (the last being the only crypto step), in the spirit of §7.6.
    /// TTL → MAC (the last being the only crypto step), in the spirit of §7.6.
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

        // TTL: issued_at is not in the future beyond the tolerance, and not older than the TTL.
        // A small tolerance for clock skew — one COOKIE_TTL forward.
        let issued = cookie.issued_at as u64;
        if issued > now_secs.saturating_add(COOKIE_TTL_SECS)
            || now_secs.saturating_sub(issued) > COOKIE_TTL_SECS
        {
            return Err(CookieError::Expired);
        }

        let expected = compute_mac(key, client_addr, carrier_id, cookie.issued_at);
        // Constant time: do not let timing reveal how many bytes matched.
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

/// The client_addr_hash inside a cookie is not the address itself but its fingerprint (not for the
/// MAC's security, but so the relay can match roughly without storing anything). The full address
/// binding comes from the MAC over the raw client_addr.
fn addr_hash(client_addr: &[u8]) -> [u8; 16] {
    use sha2::Digest;
    let digest = Sha256::digest(client_addr);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}
