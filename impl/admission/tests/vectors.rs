//! Тест-векторы для admission-протокола (§7).
//!
//! Детерминированные векторы генерируются из фиксированных ключей/входов и
//! сериализуются в `vectors.json` (язык-агностичный формат), плюс проверяются
//! свойства на стороне Rust. Цель — не только «наш код себя воспроизводит», а
//! дать эталон, против которого можно писать вторую независимую реализацию
//! (§14 требует независимых реализаций — им нужны общие векторы).

use admission::capability::{Capability, CapabilityTable, Quota, Scope};
use admission::cookie::{Cookie, CookieKeyring, COOKIE_WIRE_SIZE};
use admission::params::EPOCH_DURATION_SECS;
use admission::pipeline::{
    AdmissionPipeline, Credential, DropReason, Outcome, RejectReason, ReplayFilter,
};
use admission::rln::{external_nullifier, slash, IdentitySecret, Field, SlashResult};
use admission::token::{IssuerRing, MockRingVerifier};
use serde::Serialize;

const RELAY_KEY_CUR: [u8; 32] = [0x11; 32];
const RELAY_KEY_PREV: [u8; 32] = [0x22; 32];

// ---------- §7.1 Cookie ----------

#[test]
fn cookie_roundtrip_and_reject() {
    let now = 1_000_000u64;
    let keyring = CookieKeyring::new(EPOCH_DURATION_SECS, now, RELAY_KEY_CUR, RELAY_KEY_PREV);
    let client = b"198.51.100.7:44321";
    let carrier = b"carrier-A";
    let issued_at = now as u32;

    let cookie = keyring.issue(client, carrier, issued_at);

    // Верный cookie принимается.
    assert!(keyring.verify(&cookie, client, carrier, now).is_ok());

    // Изменённый адрес → BadMac (MAC привязан к client_addr).
    assert!(keyring
        .verify(&cookie, b"198.51.100.8:44321", carrier, now)
        .is_err());

    // Изменённый carrier → BadMac (амплификация через смену carrier закрыта).
    assert!(keyring.verify(&cookie, client, b"carrier-B", now).is_err());

    // Просроченный по TTL → отказ.
    assert!(keyring.verify(&cookie, client, carrier, now + 1000).is_err());

    // Сериализация фиксированного размера round-trips.
    let bytes = cookie.to_bytes();
    assert_eq!(bytes.len(), COOKIE_WIRE_SIZE);
    let parsed = Cookie::from_bytes(&bytes).unwrap();
    assert_eq!(parsed, cookie);
}

// ---------- §7.2 Capability ----------

fn sample_capability() -> Capability {
    Capability {
        capability_id: [0xAB; 16],
        scope: Scope::MessageDelivery,
        quota: Quota {
            max_requests: 100,
            max_bytes: 1 << 20,
            window_secs: 600,
        },
        not_before: 0,
        not_after: u32::MAX,
        secret: [0x33; 32],
    }
}

#[test]
fn capability_proof_verifies_and_scope_enforced() {
    let cap = sample_capability();
    let mut table = CapabilityTable::new();
    table.insert(cap.clone());

    let nonce = b"request-nonce-xyz";
    let epoch = 42u32;
    let proof = cap.prove(nonce, epoch);

    // Верный proof + верный scope.
    assert!(table
        .verify(&proof, nonce, Scope::MessageDelivery, 1000)
        .is_ok());

    // Неверный scope → ScopeMismatch.
    assert!(table
        .verify(&proof, nonce, Scope::MailboxFetch, 1000)
        .is_err());

    // Неверный nonce → BadMac.
    assert!(table
        .verify(&proof, b"other-nonce", Scope::MessageDelivery, 1000)
        .is_err());
}

// ---------- §7.4 RLN slashing — несущее свойство корректности ----------

#[test]
fn rln_two_shares_recover_secret() {
    let secret = IdentitySecret(Field::from(0x0BADC0DE_u64) + Field::from(7u64));
    let ext = external_nullifier(99, b"relay-scope-1");

    // Два РАЗНЫХ сообщения в одну эпоху → превышение квоты (limit 1).
    let m1 = Field::from(111u64);
    let m2 = Field::from(222u64);
    let s1 = secret.share(&ext, m1);
    let s2 = secret.share(&ext, m2);

    // Оба предъявления несут один и тот же публичный nullifier (детекция повтора).
    assert_eq!(s1.nullifier, s2.nullifier);

    // Slashing восстанавливает ровно identity_secret.
    match slash(&s1, &s2) {
        SlashResult::Recovered(bytes) => assert_eq!(bytes, secret.0.to_bytes()),
        other => panic!("ожидалось Recovered, получено {:?}", other),
    }
}

#[test]
fn nullifier_is_not_the_slope() {
    // Необходимое условие находки §7.4: публичный nullifier НЕ равен наклону.
    // (Достаточность неразглашения из одной доли держится на preimage-
    // стойкости H(slope) — её этот тест НЕ проверяет, лишь неравенство.)
    let secret = IdentitySecret(Field::from(123456789u64));
    let ext = external_nullifier(5, b"scope");
    let share = secret.share(&ext, Field::from(1000u64));

    let slope = secret.slope(&ext);
    assert_ne!(share.nullifier.to_bytes(), slope.to_bytes());
}

#[test]
fn rln_different_identities_do_not_slash() {
    let a = IdentitySecret(Field::from(1000u64));
    let b = IdentitySecret(Field::from(2000u64));
    let ext = external_nullifier(1, b"scope");
    let sa = a.share(&ext, Field::from(10u64));
    let sb = b.share(&ext, Field::from(20u64));
    // Разные nullifier'ы → это не двойное предъявление, восстановления нет.
    assert_eq!(slash(&sa, &sb), SlashResult::DifferentNullifier);
}

#[test]
fn rln_same_message_is_not_a_violation() {
    let s = IdentitySecret(Field::from(555u64));
    let ext = external_nullifier(2, b"scope");
    let m = Field::from(42u64);
    let share = s.share(&ext, m);
    // Идентичный повтор (тот же message_hash) — не восстанавливаем (x1==x2).
    assert_eq!(slash(&share, &share), SlashResult::SameMessage);
}

// ---------- §7.5/7.6 Pipeline ----------

fn issuer_ring() -> IssuerRing {
    IssuerRing {
        issuer_pubkeys: vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]],
        threshold_t: 2, // «2 из 5»
    }
}

#[test]
fn pipeline_first_contact_gets_challenge() {
    let now = 1_000_000u64;
    let keyring = CookieKeyring::new(EPOCH_DURATION_SECS, now, RELAY_KEY_CUR, RELAY_KEY_PREV);
    let caps = CapabilityTable::new();
    let ring = issuer_ring();
    let verifier = MockRingVerifier;
    let pipe = AdmissionPipeline {
        keyring: &keyring,
        capabilities: &caps,
        token_verifier: &verifier,
        issuer_ring: &ring,
    };
    let mut replay = ReplayFilter::new(0, 1024);

    let req = admission::pipeline::Request {
        raw_len: 200,
        max_raw_len: admission::params::MAX_PACKET_SIZE,
        client_addr: b"203.0.113.5:5000",
        carrier_id: b"c",
        cookie: None, // первый контакт
        request_nonce: b"n",
        requested_scope: Scope::MessageDelivery,
        credential: Credential::RlnQuota,
    };
    let out = pipe.process(&req, now, 0, [0x42; 64], &mut replay, &mut admission::capability::CapabilityQuotaTracker::new());
    assert!(matches!(out, Outcome::Challenge(_)));
}

#[test]
fn pipeline_capability_admits_then_replay_rejects() {
    let now = 1_000_000u64;
    let keyring = CookieKeyring::new(EPOCH_DURATION_SECS, now, RELAY_KEY_CUR, RELAY_KEY_PREV);
    let cap = sample_capability();
    let mut caps = CapabilityTable::new();
    caps.insert(cap.clone());
    let ring = issuer_ring();
    let verifier = MockRingVerifier;
    let pipe = AdmissionPipeline {
        keyring: &keyring,
        capabilities: &caps,
        token_verifier: &verifier,
        issuer_ring: &ring,
    };
    let mut replay = ReplayFilter::new(0, 1024);

    let client = b"203.0.113.9:5001";
    let carrier = b"c";
    let cookie = keyring.issue(client, carrier, now as u32);
    let nonce = b"req-nonce-1";
    let proof = cap.prove(nonce, 0);

    let mk = || admission::pipeline::Request {
        raw_len: 300,
        max_raw_len: admission::params::MAX_PACKET_SIZE,
        client_addr: client,
        carrier_id: carrier,
        cookie: Some(cookie),
        request_nonce: nonce,
        requested_scope: Scope::MessageDelivery,
        credential: Credential::Capability(proof),
    };

    // Первый раз — допущен.
    assert_eq!(pipe.process(&mk(), now, 0, [0; 64], &mut replay, &mut admission::capability::CapabilityQuotaTracker::new()), Outcome::Admit);
    // Повтор того же proof в ту же эпоху — replay.
    assert_eq!(
        pipe.process(&mk(), now, 0, [0; 64], &mut replay, &mut admission::capability::CapabilityQuotaTracker::new()),
        Outcome::Reject(RejectReason::Replay)
    );
}

#[test]
fn pipeline_token_threshold_enforced() {
    let now = 1_000_000u64;
    let keyring = CookieKeyring::new(EPOCH_DURATION_SECS, now, RELAY_KEY_CUR, RELAY_KEY_PREV);
    let caps = CapabilityTable::new();
    let ring = issuer_ring(); // threshold 2
    let verifier = MockRingVerifier;
    let pipe = AdmissionPipeline {
        keyring: &keyring,
        capabilities: &caps,
        token_verifier: &verifier,
        issuer_ring: &ring,
    };
    let client = b"203.0.113.20:5002";
    let carrier = b"c";
    let cookie = keyring.issue(client, carrier, now as u32);

    // Токен, «подписанный» 2 issuer'ами (порог соблюдён) — допущен.
    let good = MockRingVerifier::mock_token([0x77; 32], 0, 2);
    let mut replay = ReplayFilter::new(0, 1024);
    let req_good = admission::pipeline::Request {
        raw_len: 300,
        max_raw_len: admission::params::MAX_PACKET_SIZE,
        client_addr: client,
        carrier_id: carrier,
        cookie: Some(cookie),
        request_nonce: b"n",
        requested_scope: Scope::MessageDelivery,
        credential: Credential::Token(good),
    };
    assert_eq!(pipe.process(&req_good, now, 0, [0; 64], &mut replay, &mut admission::capability::CapabilityQuotaTracker::new()), Outcome::Admit);

    // Токен всего с 1 подписантом (недобор порога 2) — отказ.
    let weak = MockRingVerifier::mock_token([0x88; 32], 0, 1);
    let mut replay2 = ReplayFilter::new(0, 1024);
    let req_weak = admission::pipeline::Request {
        raw_len: 300,
        max_raw_len: admission::params::MAX_PACKET_SIZE,
        client_addr: client,
        carrier_id: carrier,
        cookie: Some(cookie),
        request_nonce: b"n",
        requested_scope: Scope::MessageDelivery,
        credential: Credential::Token(weak),
    };
    assert!(matches!(
        pipe.process(&req_weak, now, 0, [0; 64], &mut replay2, &mut admission::capability::CapabilityQuotaTracker::new()),
        Outcome::Reject(RejectReason::Token(_))
    ));
}

#[test]
fn pipeline_oversize_dropped_silently() {
    let now = 1_000_000u64;
    let keyring = CookieKeyring::new(EPOCH_DURATION_SECS, now, RELAY_KEY_CUR, RELAY_KEY_PREV);
    let caps = CapabilityTable::new();
    let ring = issuer_ring();
    let verifier = MockRingVerifier;
    let pipe = AdmissionPipeline {
        keyring: &keyring,
        capabilities: &caps,
        token_verifier: &verifier,
        issuer_ring: &ring,
    };
    let mut replay = ReplayFilter::new(0, 1024);
    let req = admission::pipeline::Request {
        raw_len: 5000,
        max_raw_len: admission::params::MAX_PACKET_SIZE, // > MAX_PACKET_SIZE
        client_addr: b"x",
        carrier_id: b"c",
        cookie: None,
        request_nonce: b"n",
        requested_scope: Scope::MessageDelivery,
        credential: Credential::RlnQuota,
    };
    assert_eq!(
        pipe.process(&req, now, 0, [0; 64], &mut replay, &mut admission::capability::CapabilityQuotaTracker::new()),
        Outcome::DropNoReply(DropReason::Oversize)
    );
}

// ---------- Экспорт JSON тест-векторов ----------

#[derive(Serialize)]
struct CookieVector {
    description: String,
    relay_key_current_hex: String,
    epoch_duration_secs: u64,
    now_secs: u64,
    client_addr_hex: String,
    carrier_id_hex: String,
    issued_at: u32,
    cookie_wire_hex: String,
    verifies: bool,
}

#[derive(Serialize)]
struct RlnVector {
    description: String,
    identity_secret_hex: String,
    epoch_id: u32,
    relay_scope_id_hex: String,
    message_hash_1: String,
    message_hash_2: String,
    share_a1_1_hex: String,
    share_a1_2_hex: String,
    nullifier_hex: String,
    recovered_secret_hex: String,
    recovery_matches: bool,
}

#[derive(Serialize)]
struct Vectors {
    note: String,
    cookie: CookieVector,
    rln: RlnVector,
}

// Замороженные ожидаемые значения (byte-level pin). Вторая независимая
// реализация ОБЯЗАНА воспроизвести ровно эти байты — иначе конформанс не
// достигнут. Тест ниже падает при любом дрейфе (другой hash_to_field,
// другая сериализация, другой MAC), а не пересчитывает «правильный» ответ
// на лету. Регенерация — только явно, через KARST_REGEN_VECTORS=1.
//
// REGENERATED 2026-07-28, deliberately, for ONE reason: the cookie MAC input became
// canonical (domain tag ‖ version ‖ length-prefixed client_addr ‖ length-prefixed
// carrier_id ‖ addr_hash ‖ issued_at) to remove a split ambiguity where ("a","bc") and
// ("ab","c") produced the same MAC — CRYPTO-07. Only the trailing 16 MAC bytes moved;
// the version, epoch, addr_hash and issued_at prefix is byte-identical, which is the
// evidence that nothing else in the wire format changed. Any OTHER drift in this
// constant is a bug, not a regeneration.
const FROZEN_COOKIE_WIRE_HEX: &str =
    "01000006825e3d1f5adf178dc514193f4520454dea000f42408b9b02ff74814d007784248ef5975384";
const FROZEN_RLN_SECRET_HEX: &str =
    "e5c0ad0b00000000000000000000000000000000000000000000000000000000";
const FROZEN_RLN_A1_1_HEX: &str =
    "80718cd88dc749f2b44d91fba6b2bb1d7a3bfb1a652b6afcfb0e526cb33f0508";
const FROZEN_RLN_A1_2_HEX: &str =
    "2e4e7548012c818c93fe2a546f6b9826f476f635ca56d4f8f71da4d8667f0a00";
const FROZEN_RLN_NULLIFIER_HEX: &str =
    "085a94187605850d6d0e5d2e4e958873b0f4d43c7f25cee1b0eb5fbe2c834806";

#[test]
fn conformance_vectors_match_frozen() {
    // Cookie-вектор.
    let now = 1_000_000u64;
    let keyring = CookieKeyring::new(EPOCH_DURATION_SECS, now, RELAY_KEY_CUR, RELAY_KEY_PREV);
    let client = b"198.51.100.7:44321";
    let carrier = b"carrier-A";
    let cookie = keyring.issue(client, carrier, now as u32);
    let verifies = keyring.verify(&cookie, client, carrier, now).is_ok();

    // Byte-level pin: вычисленное обязано совпасть с замороженным.
    assert_eq!(
        hex::encode(cookie.to_bytes()),
        FROZEN_COOKIE_WIRE_HEX,
        "cookie wire-байты разошлись с замороженным вектором"
    );

    let cookie_vec = CookieVector {
        description: "§7.1 cookie issued and verified with fixed relay key".into(),
        relay_key_current_hex: hex::encode(RELAY_KEY_CUR),
        epoch_duration_secs: EPOCH_DURATION_SECS,
        now_secs: now,
        client_addr_hex: hex::encode(client),
        carrier_id_hex: hex::encode(carrier),
        issued_at: now as u32,
        cookie_wire_hex: hex::encode(cookie.to_bytes()),
        verifies,
    };

    // RLN-вектор.
    let secret = IdentitySecret(Field::from(0x0BADC0DEu64) + Field::from(7u64));
    let ext = external_nullifier(99, b"relay-scope-1");
    let m1 = Field::from(111u64);
    let m2 = Field::from(222u64);
    let s1 = secret.share(&ext, m1);
    let s2 = secret.share(&ext, m2);
    let (recovered_hex, matches) = match slash(&s1, &s2) {
        SlashResult::Recovered(b) => (hex::encode(b), b == secret.0.to_bytes()),
        _ => (String::new(), false),
    };

    // Byte-level pin для RLN: доли, nullifier и восстановленный секрет.
    assert_eq!(hex::encode(secret.0.to_bytes()), FROZEN_RLN_SECRET_HEX);
    assert_eq!(hex::encode(s1.a1.to_bytes()), FROZEN_RLN_A1_1_HEX);
    assert_eq!(hex::encode(s2.a1.to_bytes()), FROZEN_RLN_A1_2_HEX);
    assert_eq!(hex::encode(s1.nullifier.to_bytes()), FROZEN_RLN_NULLIFIER_HEX);
    assert_eq!(recovered_hex, FROZEN_RLN_SECRET_HEX);
    assert!(verifies && matches);

    let rln_vec = RlnVector {
        description: "§7.4 two shares in one epoch recover identity_secret".into(),
        identity_secret_hex: hex::encode(secret.0.to_bytes()),
        epoch_id: 99,
        relay_scope_id_hex: hex::encode(b"relay-scope-1"),
        message_hash_1: hex::encode(m1.to_bytes()),
        message_hash_2: hex::encode(m2.to_bytes()),
        share_a1_1_hex: hex::encode(s1.a1.to_bytes()),
        share_a1_2_hex: hex::encode(s2.a1.to_bytes()),
        nullifier_hex: hex::encode(s1.nullifier.to_bytes()),
        recovered_secret_hex: recovered_hex,
        recovery_matches: matches,
    };

    let vectors = Vectors {
        note: "KARST §7 admission test vectors. Deterministic; for cross-implementation \
               conformance (§14). hash_to_field = SHA-512 wide-reduce over curve25519 scalar \
               field (reference substitute for Poseidon; slashing property is field-only)."
            .into(),
        cookie: cookie_vec,
        rln: rln_vec,
    };

    // Регенерация committed-артефакта — только по явному запросу. По умолчанию
    // тест герметичен и НИЧЕГО не пишет: он лишь сверяет вычисленное с
    // замороженными константами выше. Обновлять vectors.json осознанно:
    //   KARST_REGEN_VECTORS=1 cargo test conformance_vectors_match_frozen
    if std::env::var("KARST_REGEN_VECTORS").is_ok() {
        let json = serde_json::to_string_pretty(&vectors).unwrap();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors.json");
        std::fs::write(path, json).expect("write vectors.json");
    }
}
