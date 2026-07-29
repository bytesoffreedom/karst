//! §12 4c — opt-in discovery ("contact code").
//!
//! A user who wants to be findable by strangers publishes a **discovery record** under an
//! unguessable pseudonym. The pseudonym is the hash of a RANDOM per-user discovery key — NOT the
//! identity key — which makes the code:
//!
//!   * **unguessable** — no dictionary attack, because the input is 32 random bytes, not a name;
//!   * **rotatable / revocable** — minting a new keypair mints a new code and retires the old one,
//!     with the permanent identity (IK) untouched, so existing contacts are unaffected;
//!   * **opt-in** — nothing is written until the user explicitly turns discovery on.
//!
//! There are deliberately **no human-chosen usernames**: a chooseable name is a squattable global
//! namespace (two users pick "alice" → collision → whoever writes last hijacks the other), which
//! is exactly what a random code avoids.
//!
//! Two independent signatures protect a record:
//!   * `ik_sig` — the IK signs `(discovery_pub, ik, location_id, expiry)`. A resolver verifies it
//!     and thereby trusts the code→IK binding WITHOUT the relay vouching. The relay cannot forge
//!     it (no IK private key), so it cannot point a code at a victim IK.
//!   * the write signature — the discovery key signs the write/delete. Only the code's owner can
//!     create, overwrite (rotate) or delete its slot, so a contact who merely learns your code
//!     cannot tamper with your record.
//!
//! Honest residual: a relay still sees which pseudonym is queried (no PIR — walled, see STATUS),
//! and could withhold or return a stale record (an availability attack, not a MITM — identity
//! stays anchored on the IK the resolver verifies).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::RelayDescriptor;

/// Lifetime a client stamps on a record. Discovery is **persistent-until-off**: the code stays
/// findable until the user rotates or turns it off, so the TTL is a long safety bound (not a
/// short lease) after which the RELAY garbage-collects a record whose owner vanished without
/// turning it off. There is no background republisher — re-running `discovery on` re-stamps the
/// same code with a fresh expiry (the key persists), which is the manual refresh.
pub const DEFAULT_TTL_SECS: u64 = 365 * 24 * 60 * 60;
/// Ceiling the relay enforces on `expiry` (a little over the default, to absorb clock skew) so a
/// record can never be pinned open indefinitely.
pub const MAX_TTL_SECS: u64 = 370 * 24 * 60 * 60;

/// A published discovery record: an unguessable code, the IK it belongs to, where that IK is
/// reachable, and until when — bound together by the IK's signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryRecord {
    /// The public half of the random discovery key. `discovery_pseudonym(discovery_pub)` is the
    /// lookup slot; the code shared out-of-band carries exactly this value.
    pub discovery_pub: [u8; 32],
    /// The identity key this code resolves to.
    pub ik: [u8; 32],
    /// Where the IK is reachable (relay-id + dial hints). Only the relay-id is signed; `addrs`
    /// are mutable dial hints (availability, not identity).
    pub location: RelayDescriptor,
    /// Unix seconds after which the record is stale and dropped on access.
    pub expiry: u64,
    /// One-time invite: the relay deletes the record after serving it ONCE. Signed into the
    /// binding (below) so a relay can't tamper it — the worst a hostile relay can do is NOT
    /// honour single-use (serve it again), never forge a different IK. `false` = a persistent
    /// (rotatable) discovery code.
    pub single_use: bool,
    /// XEdDSA signature by the IK over `binding_msg` — the resolver's proof of the code→IK binding.
    pub ik_sig: Vec<u8>,
}

/// The lookup slot for a discovery public key: a domain-separated `SHA256`. A compromised relay's
/// discovery map is therefore opaque `H(random) → record`, revealing no roster of identities
/// beyond what each (already unguessable) code would.
pub fn discovery_pseudonym(discovery_pub: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"KARST-disc-v1");
    h.update(discovery_pub);
    h.finalize().into()
}

/// The identity-critical bytes of a location: `noise_pub ‖ fetch_pub` (the relay-id). Dial
/// addresses are excluded — they vary per carrier and are only availability hints.
fn location_id(loc: &RelayDescriptor) -> [u8; 64] {
    let mut id = [0u8; 64];
    id[..32].copy_from_slice(&loc.noise_pub);
    id[32..].copy_from_slice(&loc.fetch_pub);
    id
}

fn tagged(domain: &[u8], discovery_pub: &[u8; 32], ik: &[u8; 32], loc: &RelayDescriptor, expiry: u64, single_use: bool) -> Vec<u8> {
    let mut m = Vec::with_capacity(domain.len() + 32 + 32 + 64 + 8 + 1);
    m.extend_from_slice(domain);
    m.extend_from_slice(discovery_pub);
    m.extend_from_slice(ik);
    m.extend_from_slice(&location_id(loc));
    m.extend_from_slice(&expiry.to_le_bytes());
    m.push(single_use as u8);
    m
}

/// Message the IK signs to bind a code to itself (verified by resolvers).
pub fn binding_msg(discovery_pub: &[u8; 32], ik: &[u8; 32], loc: &RelayDescriptor, expiry: u64, single_use: bool) -> Vec<u8> {
    tagged(b"KARST-disc-bind-v1", discovery_pub, ik, loc, expiry, single_use)
}

/// Message the discovery key signs to authorise a write (create / rotate).
pub fn write_msg(discovery_pub: &[u8; 32], ik: &[u8; 32], loc: &RelayDescriptor, expiry: u64, single_use: bool) -> Vec<u8> {
    tagged(b"KARST-disc-write-v1", discovery_pub, ik, loc, expiry, single_use)
}

/// Sign the code→IK binding for an opt-in discovery record: an XEdDSA signature by the account's
/// identity key over `(discovery_pub, ik, location, expiry, single_use)`. A resolver verifies it
/// with [`verify_binding`] and thereby trusts that this contact code belongs to this IK — the
/// relay never vouches for the pairing.
///
/// A free function here rather than a method on `Account` (#143): the message it covers is
/// defined in this module and the location type it binds is protocol vocabulary, so putting the
/// signature on the crypto type made PQXDH depend on both and closed a cycle around the module
/// graph. The key material never leaves the crate — `ik_secret_bytes` is crate-visible.
pub fn sign_binding(
    account: &crate::pqxdh::Account,
    discovery_pub: &[u8; 32],
    location: &crate::protocol::RelayDescriptor,
    expiry: u64,
    single_use: bool,
) -> Vec<u8> {
    let msg = binding_msg(discovery_pub, &account.identity_public(), location, expiry, single_use);
    sign(&account.ik_secret_bytes(), &msg)
}

/// Message the discovery key signs to authorise a delete (turn discovery off).
pub fn delete_msg(discovery_pub: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(19 + 32);
    m.extend_from_slice(b"KARST-disc-delete-v1");
    m.extend_from_slice(discovery_pub);
    m
}

/// The X25519 public key of a discovery secret.
pub fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret)).to_bytes()
}

/// XEdDSA-sign `msg` with an X25519 secret (the same construction the prekey bundle uses).
pub fn sign(secret: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    use xeddsa::Sign;
    let sk = x25519_dalek::StaticSecret::from(*secret);
    let signer = xeddsa::xed25519::PrivateKey::from(&sk);
    let sig: [u8; 64] = signer.sign(msg, rand010::rng());
    sig.to_vec()
}

/// XEdDSA-verify a signature made by `public` over `msg`. `false` on any structural fault.
pub fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    use xeddsa::Verify;
    let pk = xeddsa::xed25519::PublicKey::from(&x25519_dalek::PublicKey::from(*public));
    let Ok(s): Result<[u8; 64], _> = sig.try_into() else {
        return false;
    };
    pk.verify(msg, &s).is_ok()
}

/// Verify the IK→code binding on a record (what a resolver runs before trusting the IK).
pub fn verify_binding(rec: &DiscoveryRecord) -> bool {
    verify(&rec.ik, &binding_msg(&rec.discovery_pub, &rec.ik, &rec.location, rec.expiry, rec.single_use), &rec.ik_sig)
}

// ----- contact code: a human-transportable encoding of `discovery_pub` -----

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_PREFIX: &str = "KARST-";
const CODE_VERSION: u8 = 1;

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[((buf >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(CROCKFORD[((buf << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let (mut buf, mut bits) = (0u32, 0u32);
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for c in s.chars() {
        // Crockford leniency: I/L → 1, O → 0.
        let c = match c {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        };
        let v = CROCKFORD.iter().position(|&a| a as char == c)? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    // CANONICAL only: the payload is not a whole number of 5-bit groups, so the last character
    // carries a few PADDING bits. The encoder writes them as zero; accepting anything else made
    // eight different strings decode to the same key and pass the same checksum, so one identity
    // had eight valid contact codes / QR images. That is not a key-substitution risk, but it
    // breaks the assumption that the string form identifies a record — which logs, manual
    // comparison, dedup and any future signature over the string all rely on (CRYPTO-17).
    let leftover = buf & ((1u32 << bits) - 1);
    if leftover != 0 {
        return None;
    }
    Some(out)
}

/// Encode a discovery public key as the shareable contact code
/// (`KARST-XXXX-XXXX-…`, uppercase so it rides a QR's compact alphanumeric mode).
pub fn encode_code(discovery_pub: &[u8; 32]) -> String {
    let mut payload = Vec::with_capacity(1 + 32 + 3);
    payload.push(CODE_VERSION);
    payload.extend_from_slice(discovery_pub);
    let mut h = Sha256::new();
    h.update(b"KARST-code-v1");
    h.update(&payload);
    let check = h.finalize();
    payload.extend_from_slice(&check[..3]);

    let body = base32_encode(&payload);
    let mut out = String::from(CODE_PREFIX);
    for (i, ch) in body.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(ch);
    }
    out
}

/// Decode a contact code back to a discovery public key, or `None` if it is malformed, the
/// version is unknown, or the checksum fails (a mistyped/truncated code). Case-insensitive and
/// tolerant of missing/extra separators.
pub fn decode_code(code: &str) -> Option<[u8; 32]> {
    // Uppercase and drop all separators/whitespace, THEN strip the human-readable prefix. The
    // encoded body always starts with '0' (the v1 version byte's top bits), never 'K', so removing
    // a leading "KARST" is unambiguous even after every dash has been stripped out.
    let cleaned: String = code
        .trim()
        .to_ascii_uppercase()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let body = cleaned.strip_prefix("KARST").unwrap_or(&cleaned);
    let raw = base32_decode(body)?;
    if raw.len() != 1 + 32 + 3 || raw[0] != CODE_VERSION {
        return None;
    }
    let mut h = Sha256::new();
    h.update(b"KARST-code-v1");
    h.update(&raw[..33]);
    let check = h.finalize();
    if check[..3] != raw[33..36] {
        return None;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&raw[1..33]);
    Some(pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desc() -> RelayDescriptor {
        RelayDescriptor { noise_pub: [3u8; 32], fetch_pub: [4u8; 32], addrs: vec!["1.2.3.4:9".into()], quic_addrs: Vec::new() }
    }

    #[test]
    fn code_round_trips_and_is_qr_friendly() {
        let pk = public_of(&[7u8; 32]);
        let code = encode_code(&pk);
        assert!(code.starts_with("KARST-"));
        assert!(code.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'));
        assert_eq!(decode_code(&code), Some(pk), "round-trips exactly");
        // Tolerant of copy-paste damage: lowercased, dashes stripped, whitespace around.
        assert_eq!(decode_code(&format!("  {}  ", code.replace('-', "").to_lowercase())), Some(pk));
    }

    #[test]
    fn a_flipped_character_fails_the_checksum() {
        let pk = public_of(&[9u8; 32]);
        let code = encode_code(&pk);
        // Flip one payload char (skip the "KARST-" prefix).
        let mut chars: Vec<char> = code.chars().collect();
        let i = code.len() - 3;
        chars[i] = if chars[i] == '0' { '1' } else { '0' };
        let corrupted: String = chars.into_iter().collect();
        assert_ne!(decode_code(&corrupted), Some(pk));
    }

    #[test]
    fn binding_signature_verifies_and_rejects_tampering() {
        let ik_secret = [11u8; 32];
        let ik = public_of(&ik_secret);
        let dpub = public_of(&[12u8; 32]);
        let expiry = 5_000;
        let sig = sign(&ik_secret, &binding_msg(&dpub, &ik, &desc(), expiry, false));
        let rec = DiscoveryRecord { discovery_pub: dpub, ik, location: desc(), expiry, single_use: false, ik_sig: sig };
        assert!(verify_binding(&rec));
        // Swap the IK the code claims to belong to → binding must fail.
        let mut forged = rec.clone();
        forged.ik = public_of(&[99u8; 32]);
        assert!(!verify_binding(&forged));
        // Move the expiry → signature no longer covers the record.
        let mut moved = rec.clone();
        moved.expiry = expiry + 1;
        assert!(!verify_binding(&moved));
    }

    #[test]
    fn write_auth_is_bound_to_the_discovery_key() {
        let dsecret = [21u8; 32];
        let dpub = public_of(&dsecret);
        let ik = public_of(&[22u8; 32]);
        let m = write_msg(&dpub, &ik, &desc(), 9, false);
        assert!(verify(&dpub, &m, &sign(&dsecret, &m)));
        // A different key cannot authorise a write to this slot.
        assert!(!verify(&dpub, &m, &sign(&[23u8; 32], &m)));
    }

    /// CRYPTO-17 — a contact code must have exactly ONE canonical spelling.
    ///
    /// The payload is not a whole number of 5-bit groups, so the final character carries padding
    /// bits. The encoder zeroes them, but the decoder used to ignore whatever was there — so all
    /// eight variants of that last character decoded to the same key and passed the same
    /// checksum, giving one identity eight valid codes and eight different QR images. No key
    /// substitution, but the string stops identifying the record, which logs, manual comparison,
    /// dedup and any future signature over the string form all depend on.
    #[test]
    fn a_contact_code_has_exactly_one_canonical_spelling() {
        let code = encode_code(&public_of(&[7u8; 32]));
        assert!(decode_code(&code).is_some(), "control: the canonical code decodes");

        // Walk the last data character through the whole alphabet. Every spelling other than the
        // canonical one must be REFUSED, not silently accepted as the same key.
        let mut chars: Vec<char> = code.chars().collect();
        let last = chars.len() - 1;
        let original = chars[last];
        let mut accepted = 0usize;
        for &c in CROCKFORD.iter() {
            chars[last] = c as char;
            let variant: String = chars.iter().collect();
            if decode_code(&variant).is_some() {
                accepted += 1;
                assert_eq!(
                    variant.chars().last(), Some(original),
                    "a non-canonical spelling was accepted: {variant}"
                );
            }
        }
        assert_eq!(accepted, 1, "exactly one spelling of the final character may decode");
    }
}
