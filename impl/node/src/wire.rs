//! Framing/кодек — **внешняя граница доверия** узла: сюда приходят непроверенные
//! байты из сети ДО того, как §7-конвейер увидит структурированный `Request`.
//! §7 не защищает от 4-ГБ длины, обрезанного кадра или мусора — это делает
//! ЭТОТ модуль: bounded-read до аллокации, чистая ошибка вместо паники/зависания.
//!
//! Кодек — postcard (компактный; у библиотечного парсера меньше hostile-surface,
//! чем у ручного). Формат СКЕЛЕТНЫЙ: §15-транспорт перепишет провод целиком и
//! тогда заморозит байт-векторы для второй реализации; сейчас не замораживаем.

use std::io::{self, Read, Write};

use admission::capability::Capability;
use admission::cookie::Cookie;
use admission::params::MAX_PACKET_SIZE;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::discovery::DiscoveryRecord;
use crate::protocol::{AckRequest, BlobGetRequest, BlobPutRequest, BlobResponse, BlobStatRequest, FetchRequest, JoinRequest, Payload, PublishRequest, RelayPolicy, SignedDescriptor, WireMessage};
use crate::pqxdh::PreKeyBundle;

/// Потолок кадра ЗАПРОСА (client→server) — самый враждебный вход. Полезная нагрузка §7 всё равно
/// режется Ступенью 0 по `MAX_PACKET_SIZE`; здесь — потолок аллокации ДО запуска конвейера, с
/// запасом на обёртку (proof/cookie/адреса/postcard-теги).
///
/// Числа тут не повторяются намеренно: этот комментарий говорил «= 1400» ещё две ревизии потолка
/// спустя (1400 → 2560 → 3840). Константа ВЫВЕДЕНА, поэтому она ехала правильно всё это время —
/// врал только текст рядом с ней.
pub const MAX_REQUEST_FRAME: usize = MAX_PACKET_SIZE + 512;


/// Count cap: at most this many seals leave per fetch. The rest stay in the mailbox
/// for the next poll. This is a metadata-hardening knob (§2.2): a fetch response is
/// a FIXED-SIZE page regardless of queue depth, so an on-path observer cannot read
/// "how much mail is queued" from the response size. The tradeoff — every poll pays
/// the full page's bandwidth even for an empty mailbox — is a deliberate product
/// decision (metadata vs bandwidth/latency).
pub const FETCH_CAP: usize = 16;

/// Fixed plaintext length of a fetch page, in bytes. A page ALWAYS occupies exactly
/// this many payload bytes whether it carries 0 or `FETCH_CAP` seals. Sized to sit
/// under session bucket 16384 (leaving room for the `WireResponse` enum tag, the
/// postcard length prefix, and the Noise pad header) so a page costs ONE size class
/// on the wire, not two. Seals are greedily packed until `FETCH_CAP` OR the page
/// body is full; the remainder defers to the next poll.
pub const FETCH_PAGE_LEN: usize = 16_000;

/// Page body budget: `FETCH_PAGE_LEN` minus the 4-byte inner-length header.
const FETCH_PAGE_BODY: usize = FETCH_PAGE_LEN - 4;

/// Response frame ceiling (server→client): one fetch page plus headroom for the
/// other, smaller response variants (`Bundle`, `NeedCookie`, `Rejected`).
pub const MAX_RESPONSE_FRAME: usize = FETCH_PAGE_LEN + 512;

/// §15 large-file frame ceiling — used for `BlobPut`/`BlobGet` requests and blob
/// responses (both carry a ~60 KiB ciphertext chunk). Sized so the padded Noise
/// message still lands in the top 64 KiB session bucket (one size class, not two).
/// Larger than the tight `MAX_REQUEST_FRAME`, but still a BOUNDED post-handshake alloc:
/// only a peer that completed the Noise handshake reaches the frame reader, and blobs
/// are gated by cookie + the store's byte caps. Trade-off, named: a blob transfer is a
/// distinct size class on the wire, so it leaks "large file" to an observer where the
/// padded small-message path does not (see docs/STATUS.md).
pub const MAX_BLOB_FRAME: usize = 65_000;

/// Wire size of one `pqxdh::SignedOpk`: the fixed 32-byte X25519 key, the ONE-TIME ML-KEM-768
/// encapsulation key (1184 B, fixed by the KEM) and the 64-byte XEdDSA signature covering both,
/// each `Vec` length-prefixed. Margin, not an exact postcard count.
///
/// The PQ half is what makes a one-time unit ~12× the size it used to be, and that is what forced
/// `MAX_OPKS_PER_IK` down — see its doc for the trade.
const SIGNED_OPK_WIRE: usize = 32 + 1184 + 64 + 24;

/// Wire size of one `pqxdh::PreKeyBundle`: two X25519 keys (`ik_pub`, `prekey_pub`), the
/// ML-KEM-768 encapsulation key (1184 B, fixed by the KEM), an optional one-time prekey,
/// the XEdDSA prekey signature (64 B), and the mailbox point. Margin, not an exact count.
const PREKEY_BUNDLE_WIRE: usize = 32 + 32 + 1184 + SIGNED_OPK_WIRE + 64 + 32 + 16;

/// `Ack` frame ceiling. A recipient may legitimately ack up to `node::MAX_ACK_IDS`
/// payload ids in ONE request — several fetch pages' worth in one shot, capped for the
/// same reason the app layer already caps it (SEC-28, see `RelayNode::handle_ack`).
/// `MAX_REQUEST_FRAME` was sized for the tight Send/Fetch class and cannot carry a
/// max-size ack, so this is that class's OWN ceiling — derived from the same cap the
/// handler enforces, not hand-picked, so a future change to `MAX_ACK_IDS` moves this with
/// it instead of silently drifting out of sync.
pub const MAX_ACK_FRAME: usize = crate::protocol::MAX_ACK_IDS * 32 + 256;

/// `PublishBundle` frame ceiling. One bundle plus up to `node::MAX_OPKS_PER_IK`
/// freshly-signed one-time prekeys — a well-behaved client never sends more (the relay
/// only ever stores that many, see `RelayNode::handle_publish`), so anything past this is
/// never a legitimate publish, only padding.
pub const MAX_PUBLISH_FRAME: usize =
    PREKEY_BUNDLE_WIRE + crate::protocol::MAX_OPKS_PER_IK * SIGNED_OPK_WIRE + 256;

// Compile-time, not test-only: a class ceiling that isn't actually LARGER than the tight
// default is a no-op, and `MAX_BLOB_FRAME` must stay the largest bucket. Catches a bad edit
// to any of these constants (or to `MAX_ACK_IDS`/`MAX_OPKS_PER_IK`) at `cargo build`, before
// it ever reaches a test run.
const _: () = assert!(MAX_ACK_FRAME > MAX_REQUEST_FRAME);
const _: () = assert!(MAX_PUBLISH_FRAME > MAX_REQUEST_FRAME);
const _: () = assert!(MAX_BLOB_FRAME > MAX_PUBLISH_FRAME);

/// The real per-class ceiling for an INBOUND request, decidable only AFTER decode: the
/// outer frame length is just a padding bucket (§2.2), and the padded size is
/// attacker-chosen, so it cannot reveal which variant is inside before decrypt. Only the
/// classes that structurally need more than the tight default get a larger one — see
/// `socket::handle_conn`, which calls this immediately after `decode` and rejects anything
/// over its class's ceiling before the request reaches a handler.
pub fn max_frame_for(req: &WireRequest) -> usize {
    match req {
        WireRequest::Ack(_) => MAX_ACK_FRAME,
        WireRequest::PublishBundle(_) => MAX_PUBLISH_FRAME,
        WireRequest::BlobPut(_) => MAX_BLOB_FRAME,
        _ => MAX_REQUEST_FRAME,
    }
}

/// Fixed-size fetch page (§2.2 metadata hardening). On the wire it is ALWAYS
/// `FETCH_PAGE_LEN` bytes, so the number of queued messages does not leak through
/// the response length. Layout mirrors the session pad/unpad one layer up:
/// `[u32 inner_len LE][ postcard(Vec<Payload>) ][ zero pad to FETCH_PAGE_LEN ]`.
#[derive(Serialize, Deserialize)]
pub struct FetchPage(Vec<u8>);

impl FetchPage {
    /// How many seals from the FRONT fit into one page: at most `FETCH_CAP`, and
    /// only as many as encode within the fixed body budget. The caller drains
    /// exactly this many and leaves the rest queued. `pack` assumes its input has
    /// already been trimmed to this prefix.
    pub fn fit_prefix(seals: &[Payload]) -> usize {
        let mut n = seals.len().min(FETCH_CAP);
        while n > 0 {
            let enc = postcard::to_stdvec(&seals[..n]).expect("Vec<Payload> serializes");
            if enc.len() <= FETCH_PAGE_BODY {
                break;
            }
            n -= 1;
        }
        n
    }

    /// Pack seals into a constant-size page. Input MUST already fit (see
    /// `fit_prefix`); a page that would overflow the body is a construction bug,
    /// not a runtime input, so it is a debug assertion.
    pub fn pack(seals: &[Payload]) -> FetchPage {
        let inner = postcard::to_stdvec(seals).expect("Vec<Payload> serializes");
        debug_assert!(
            inner.len() <= FETCH_PAGE_BODY,
            "caller must pre-trim to FetchPage::fit_prefix"
        );
        let mut buf = Vec::with_capacity(FETCH_PAGE_LEN);
        buf.extend_from_slice(&(inner.len() as u32).to_le_bytes());
        buf.extend_from_slice(&inner);
        buf.resize(FETCH_PAGE_LEN, 0);
        FetchPage(buf)
    }

    /// Recover the seals from a page. Validates the inner length BEFORE slicing, so
    /// a forged/oversized header is a clean `Decode` error, never an over-read
    /// (same bounded-read ethos as the frame reader above).
    pub fn unpack(&self) -> Result<Vec<Payload>, WireError> {
        if self.0.len() < 4 {
            return Err(WireError::Decode);
        }
        let inner_len = u32::from_le_bytes(self.0[..4].try_into().expect("4 bytes")) as usize;
        if inner_len > self.0.len() - 4 {
            return Err(WireError::Decode);
        }
        postcard::from_bytes(&self.0[4..4 + inner_len]).map_err(|_| WireError::Decode)
    }
}

/// Запрос на проводе. `Send` заметно больше `Fetch`, но enum транзиентный
/// (сериализуется и сразу потребляется, не хранится массово) — боксирование
/// лишь перенесло бы аллокацию, не сэкономив.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize)]
pub enum WireRequest {
    /// Доставить запечатанное сообщение (проходит admission §7).
    Send(WireMessage),
    /// Забрать свой mailbox — с cookie + доказательством владения (§7-fetch-auth).
    Fetch(FetchRequest),
    /// Delete leased messages after durable persistence (same ownership proof as fetch).
    Ack(AckRequest),
    /// §12: опубликовать свой prekey-bundle (cookie + ownership-proof владения IK).
    PublishBundle(PublishRequest),
    /// §12: забрать bundle по IK (публичный read). NEVER carries a one-time prekey — see
    /// `FetchBundleOpk`.
    FetchBundle([u8; 32]),
    /// §12: забрать bundle ВМЕСТЕ с one-time prekey. Admission-gated like a send, because
    /// handing out an OPK destroys a scarce resource the recipient cannot replace until its next
    /// publish (R2-3). See `node::BundleOpkRequest`.
    FetchBundleOpk(crate::protocol::BundleOpkRequest),
    /// §15: upload one ciphertext chunk of a large-file blob.
    BlobPut(BlobPutRequest),
    /// §15: download one ciphertext chunk of a large-file blob.
    BlobGet(BlobGetRequest),
    /// §15: upload progress of a blob (`next`/`count`/`complete`) — the watermark a resumable
    /// upload continues from. Public read by blob-id, no cookie (like `FetchBundle`).
    BlobStat(BlobStatRequest),
    /// §7 slice 4a: ask a PUBLIC relay for its current PoW challenge (bucket + difficulty).
    JoinChallenge,
    /// §7 slice 4a: redeem a solved PoW for a capability (the Public door).
    Join(JoinRequest),
    /// §12 discovery plane: ask which relays this one knows about (node-list). Public read —
    /// it rides the completed Noise session (so the requester is return-routable) and the
    /// response is bounded, so no cookie is needed. Never carries user info.
    GetNodeList,
    /// Ask this relay to advertise its policy (blob persistence/TTL/caps, PoW door). Public read —
    /// rides the completed Noise session, bounded response, no cookie. Carries no user info.
    ///
    /// Kept as a thin reader of the SAME state `GetDescriptor` signs, never a second source: the
    /// handler builds both from `RelayNode::policy()`, so the two can disagree only if that one
    /// function is asked twice across a configuration change.
    GetPolicy,
    /// §12 NODE-1: ask this relay for its signed statement about itself — keys, dial hints and
    /// policy under one signature with an expiry. Public read, same standing as the two above.
    ///
    /// Unlike `GetPolicy`, the answer is useful AWAY from this session: it is self-authenticating,
    /// so whoever receives it can hand it on and the next holder can still check it came from the
    /// relay it describes.
    GetDescriptor,
    /// §12 4c: publish (or rotate) an opt-in discovery record + the discovery-key write signature.
    /// Self-authenticated (see `handle_publish_discovery`), so it rides the Noise session without
    /// a cookie.
    PublishDiscovery { record: DiscoveryRecord, write_sig: Vec<u8> },
    /// §12 4c: delete a discovery record (turn discovery off), with the discovery-key signature
    /// authorising removal of exactly that slot.
    DeleteDiscovery { discovery_pub: [u8; 32], delete_sig: Vec<u8> },
    /// §12 4c: resolve a discovery pseudonym (hash of a contact code) to its record. Public read;
    /// the relay learns the pseudonym queried, never enumerates the directory.
    LookupDiscovery([u8; 32]),
}

/// Ответ на проводе.
/// What a progress query yields. `NeedCookie` exists because the query is admitted now (PRIV-7):
/// the first attempt from an unproven address is answered with a challenge, exactly as a chunk
/// download is, and the client retries once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlobStatOutcome {
    NeedCookie(Cookie),
    /// `(next, count, complete)`; `None` = never seen, or blobs are disabled.
    Stat(Option<(u32, u32, bool)>),
}

#[derive(Serialize, Deserialize)]
pub enum WireResponse {
    NeedCookie(Cookie),
    Accepted,
    Rejected(String),
    /// Fixed-size fetch page — constant on-wire length, hides queue depth (§2.2).
    Fetched(FetchPage),
    /// Leased messages deleted (or already gone — ACK is idempotent).
    Acked,
    /// §12: bundle опубликован.
    BundlePublished,
    /// §12: ответ на fetch bundle (`None` — не опубликован).
    Bundle(Option<PreKeyBundle>),
    /// §15: blob upload/download outcome (wraps the store's own reply variants).
    Blob(BlobResponse),
    /// §15: a blob's upload progress `(next, count, complete)`, or `None` if the relay has no such
    /// blob (a fresh upload starts at `next = 0`).
    BlobStat(BlobStatOutcome),
    /// §7 slice 4a: the PoW challenge to solve — the relay-declared time `bucket`,
    /// required `difficulty_bits`, and the `relay_id` the work binds to (the relay's
    /// fetch-auth key; the relay verifies against its own, so a solution mined for one
    /// relay is worthless at another). See `admission::pow`.
    PowRequired { bucket: u32, difficulty_bits: u32, relay_id: [u8; 32] },
    /// §7 slice 4a: the earned capability. Rides the Noise session (encrypted), so the
    /// secret inside never crosses the wire in the clear.
    Issued(Capability),
    /// §12 discovery plane: the relays this one knows about (bounded, fits one frame).
    ///
    /// Every entry is a statement its OWN relay signed, not this one's summary of it. A relay
    /// re-serving a list is then a carrier of other relays' claims rather than a witness to them:
    /// the recipient checks each signature against the relay-id it already has to pin, so a relay
    /// in the middle can drop entries or serve stale ones but cannot forge or edit one.
    NodeList(Vec<SignedDescriptor>),
    /// This relay's advertised policy (operator-declared — see `RelayPolicy`).
    Policy(RelayPolicy),
    /// §12 NODE-1: this relay's signed descriptor. `None` when the relay has no routable address
    /// to advertise — it is not discoverable by its own choice, and signing a statement with no
    /// way to reach it would be advertising nothing, loudly.
    Descriptor(Option<SignedDescriptor>),
    /// §12 4c: outcome of a discovery publish/delete (`true` = applied).
    DiscoveryAck(bool),
    /// §12 4c: the record a discovery pseudonym resolves to (`None` = not published / expired).
    /// The resolver re-verifies the IK binding itself before trusting it.
    Discovery(Option<DiscoveryRecord>),
}

/// Ошибка кадрирования/декодирования. `FrameTooLarge` возвращается ДО аллокации.
#[derive(Debug)]
pub enum WireError {
    Io(io::Error),
    FrameTooLarge { len: usize, max: usize },
    Decode,
    /// The peer speaks a different wire version (#144). Named rather than folded into `Decode`,
    /// because "we disagree about the protocol" and "these bytes are malformed" call for
    /// completely different responses from an operator.
    ProtocolVersion { got: u16, want: u16 },
    /// The peer set a feature bit this build does not implement. Refused, not ignored.
    UnknownFeatureBits(u32),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Io(e) => write!(f, "io: {e}"),
            WireError::FrameTooLarge { len, max } => {
                write!(f, "frame too large: {len} > {max}")
            }
            WireError::Decode => write!(f, "decode failed"),
            WireError::ProtocolVersion { got, want } => {
                write!(f, "peer speaks wire protocol v{got}, this build speaks v{want}")
            }
            WireError::UnknownFeatureBits(b) => {
                write!(f, "peer requested unimplemented wire features (bits {b:#x})")
            }
        }
    }
}

impl std::error::Error for WireError {}

impl From<io::Error> for WireError {
    fn from(e: io::Error) -> Self {
        WireError::Io(e)
    }
}

/// The protocol version this build speaks. Bump on ANY change to the MEANING of the wire — a
/// renamed variant, a reordered field, a changed unit.
///
/// It exists because postcard is positional and carries no self-description: without a version,
/// two builds that disagree about a shape decode each other's bytes into plausible nonsense and
/// fail somewhere far from the cause. With it, the mismatch names itself at the first frame.
pub const PROTOCOL_VERSION: u16 = 3;

/// What actually goes on the wire: a version, a feature word, and the encoded request/response.
///
/// **No `message_type` field, deliberately.** The payload is already a tagged enum
/// (`WireRequest`/`WireResponse`), so a type field would restate the tag — and two places saying
/// the same thing are two places that can disagree, the interesting case being an attacker who
/// picks the disagreement. The tag inside the payload stays the single source.
///
/// `feature_bits` is reserved and MUST be zero; unknown bits are refused (see `decode`).
#[derive(Serialize, Deserialize)]
struct Envelope {
    protocol_version: u16,
    feature_bits: u32,
    payload: Vec<u8>,
}

/// postcard-сериализация без кадрирования (длину/bounded держит слой сессии
/// поверх Noise). Используется, когда байты уходят в зашифрованный сеанс.
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, WireError> {
    let payload = postcard::to_stdvec(msg).map_err(|_| WireError::Decode)?;
    postcard::to_stdvec(&Envelope { protocol_version: PROTOCOL_VERSION, feature_bits: 0, payload })
        .map_err(|_| WireError::Decode)
}

/// postcard-десериализация — through the versioned envelope (#144).
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, WireError> {
    let env: Envelope = postcard::from_bytes(bytes).map_err(|_| WireError::Decode)?;
    if env.protocol_version != PROTOCOL_VERSION {
        return Err(WireError::ProtocolVersion { got: env.protocol_version, want: PROTOCOL_VERSION });
    }
    // Fail CLOSED on bits we do not understand. A peer setting one is asking for behaviour this
    // build does not implement, and the safe answer to "please also do X" for an unknown X is to
    // refuse rather than proceed pretending X was honoured. That is what makes the field usable
    // from the first release instead of decorative: the day a bit means something, an older build
    // SAYS so rather than silently ignoring it.
    if env.feature_bits != 0 {
        return Err(WireError::UnknownFeatureBits(env.feature_bits));
    }
    postcard::from_bytes(&env.payload).map_err(|_| WireError::Decode)
}

/// Записать один кадр: `u32` LE длина + postcard-тело. Отказ, если тело больше
/// `max` (симметрично проверке чтения — не шлём того, что вторая сторона отвергнет).
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, msg: &T, max: usize) -> Result<(), WireError> {
    let body = postcard::to_stdvec(msg).map_err(|_| WireError::Decode)?;
    if body.len() > max {
        return Err(WireError::FrameTooLarge { len: body.len(), max });
    }
    let len = body.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

/// Прочитать один кадр. Порядок КРИТИЧЕН для безопасности:
/// 1. читаем ровно 4 байта длины (`read_exact`; обрезка → `Io(UnexpectedEof)`);
/// 2. сверяем длину с `max` **до** любой аллокации (враждебная 4-ГБ длина
///    отвергается без выделения памяти);
/// 3. `read_exact` ровно `len` байт (TCP — поток, один `read` ≠ один кадр);
/// 4. декодируем postcard (мусор → `Decode`, не паника).
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R, max: usize) -> Result<T, WireError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > max {
        return Err(WireError::FrameTooLarge { len, max });
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    postcard::from_bytes(&body).map_err(|_| WireError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use admission::capability::CapabilityProof;
    use crate::pqxdh::PreKeyBundle;

    fn dummy_ack() -> WireRequest {
        WireRequest::Ack(AckRequest {
            mailbox: [0u8; 32],
            client_addr: Vec::new(),
            carrier_id: Vec::new(),
            cookie: None,
            proof: [0u8; 16],
            ids: Vec::new(),
            own_proof: Vec::new(),
        })
    }

    fn dummy_publish() -> WireRequest {
        let bundle = PreKeyBundle {
            ik_pub: [0u8; 32],
            prekey_pub: [0u8; 32],
            kem_ek: Vec::new(),
            opk: None,
            prekey_sig: Vec::new(),
            mailbox_pub: [0u8; 32],
        };
        WireRequest::PublishBundle(PublishRequest {
            bundle,
            opks: Vec::new(),
            replace_opks: false,
            client_addr: Vec::new(),
            carrier_id: Vec::new(),
            cookie: None,
            request_nonce: Vec::new(),
            capability_proof: CapabilityProof {
                capability_id: [0u8; 16],
                epoch_id: 0,
                not_after: 0,
                mac: [0u8; 16],
            },
            proof: [0u8; 16],
        })
    }

    fn dummy_blob_put() -> WireRequest {
        WireRequest::BlobPut(BlobPutRequest {
            client_addr: Vec::new(),
            carrier_id: Vec::new(),
            cookie: None,
            // Just needs to decode/frame here — this module tests framing, not admission, so an
            // all-zero proof (which `handle_blob_put` would reject) is fine.
            request_nonce: Vec::new(),
            capability_proof: CapabilityProof { capability_id: [0u8; 16], epoch_id: 0, not_after: 0, mac: [0u8; 16] },
            blob_id: [0u8; 32],
            index: 0,
            count: 0,
            data: Vec::new(),
        })
    }

    #[test]
    fn max_frame_for_gives_each_class_its_own_ceiling_not_the_ordinary_default() {
        // Discriminating for the wiring, not just the arithmetic: if `max_frame_for` collapsed
        // to `_ => MAX_REQUEST_FRAME` for everything (the bug this closes), these three would
        // equal `MAX_REQUEST_FRAME` instead of their own, larger, structurally-derived ceilings.
        assert_eq!(max_frame_for(&dummy_ack()), MAX_ACK_FRAME);
        assert_eq!(max_frame_for(&dummy_publish()), MAX_PUBLISH_FRAME);
        assert_eq!(max_frame_for(&dummy_blob_put()), MAX_BLOB_FRAME);

        // (Each ceiling being strictly larger than `MAX_REQUEST_FRAME`, and `MAX_BLOB_FRAME`
        // staying the largest, is checked at COMPILE time — see the `const _: () = assert!`
        // trio above these constants' definitions.)

        // Everything else (the vast majority of request variants) stays on the tight default —
        // spot-check a unit variant and a small-struct variant.
        assert_eq!(max_frame_for(&WireRequest::GetNodeList), MAX_REQUEST_FRAME);
        assert_eq!(max_frame_for(&WireRequest::JoinChallenge), MAX_REQUEST_FRAME);
    }
}
