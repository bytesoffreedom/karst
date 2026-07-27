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
use crate::node::{
    AckRequest, BlobGetRequest, BlobPutRequest, BlobResponse, FetchRequest, JoinRequest, Payload,
    PublishRequest, RelayDescriptor, RelayPolicy, WireMessage,
};
use crate::pqxdh::PreKeyBundle;

/// Потолок кадра ЗАПРОСА (client→server) — самый враждебный вход. Полезная
/// нагрузка §7 всё равно режется Ступенью 0 (`MAX_PACKET_SIZE` = 1400); здесь —
/// потолок аллокации ДО запуска конвейера, с запасом на обёртку
/// (proof/cookie/адреса/postcard-теги). Тот же ~1.2КБ класс, что задокументирован
/// для скелет-пути в docs/STATUS.md.
pub const MAX_REQUEST_FRAME: usize = MAX_PACKET_SIZE + 512;

/// Mailbox STORAGE ceiling (backpressure at insert, `MailboxFull`). Independent of
/// how many seals leave per fetch — a full mailbox now drains `FETCH_CAP` at a time
/// over several polls.
pub const MAX_FETCH_SEALS: usize = 256;

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
    /// §12: забрать bundle по IK (публичный read).
    FetchBundle([u8; 32]),
    /// §15: upload one ciphertext chunk of a large-file blob.
    BlobPut(BlobPutRequest),
    /// §15: download one ciphertext chunk of a large-file blob.
    BlobGet(BlobGetRequest),
    /// §15: upload progress of a blob (`next`/`count`/`complete`) — the watermark a resumable
    /// upload continues from. Public read by blob-id, no cookie (like `FetchBundle`).
    BlobStat([u8; 32]),
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
    GetPolicy,
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
    BlobStat(Option<(u32, u32, bool)>),
    /// §7 slice 4a: the PoW challenge to solve — the relay-declared time `bucket`,
    /// required `difficulty_bits`, and the `relay_id` the work binds to (the relay's
    /// fetch-auth key; the relay verifies against its own, so a solution mined for one
    /// relay is worthless at another). See `admission::pow`.
    PowRequired { bucket: u32, difficulty_bits: u32, relay_id: [u8; 32] },
    /// §7 slice 4a: the earned capability. Rides the Noise session (encrypted), so the
    /// secret inside never crosses the wire in the clear.
    Issued(Capability),
    /// §12 discovery plane: the relays this one knows about (bounded, fits one frame).
    NodeList(Vec<RelayDescriptor>),
    /// This relay's advertised policy (operator-declared — see `RelayPolicy`).
    Policy(RelayPolicy),
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
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Io(e) => write!(f, "io: {e}"),
            WireError::FrameTooLarge { len, max } => {
                write!(f, "frame too large: {len} > {max}")
            }
            WireError::Decode => write!(f, "decode failed"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<io::Error> for WireError {
    fn from(e: io::Error) -> Self {
        WireError::Io(e)
    }
}

/// postcard-сериализация без кадрирования (длину/bounded держит слой сессии
/// поверх Noise). Используется, когда байты уходят в зашифрованный сеанс.
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, WireError> {
    postcard::to_stdvec(msg).map_err(|_| WireError::Decode)
}

/// postcard-десериализация.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, WireError> {
    postcard::from_bytes(bytes).map_err(|_| WireError::Decode)
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
