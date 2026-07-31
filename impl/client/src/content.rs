//! Контент-конверт сообщения — слой НАД байтовым E2E-путём (`node`/`peer`
//! остаются content-agnostic; вся типизация здесь, в клиенте). Текст и файлы
//! кодируются в `Content` и едут как обычный plaintext через `send_session`.
//!
//! # Файлы через пакетный лимит
//! Ступень-0 admission режет пакет по `admission::params::MAX_PACKET_SIZE`, и
//! `karst_client_core::pad` выводит ИЗ этого потолка размер фиксированного
//! блока: одно Ratchet-сообщение несёт ровно `pad::MAX_PAYLOAD` Б plaintext,
//! сколько бы ни было полезных байт (PRIV-1 — реле не должно узнавать длину).
//! Числа здесь не повторяются намеренно: их дважды меняли (1400 → 2560, потому
//! что ML-KEM-опенер не влезал в собственный обязательный потолок), и оба раза
//! этот абзац оставался с прежней цифрой, описывая проток, которого нет.
//! Единственный источник правды — константы. Файл поэтому **чанкуется**: манифест
//! (имя, размер, число чанков, SHA-256) + N чанков; получатель собирает и
//! СВЕРЯЕТ хэш. Инлайн-путь ограничен `MAX_FILE_CHUNKS` (см. константу — предел
//! ставит capability-quota на admission-пути, а НЕ mailbox), пересборка в памяти
//! в пределах живого процесса (worker держит `Reassembler` между poll'ами).
//! Всё, что больше `MAX_FILE_SIZE`, уходит E2E-blob'ом + `FileRef` — этот путь
//! ВОЗОБНОВЛЯЕМЫЙ (повтор продолжает с watermark релея), см. `client::blob`.
//!
//! Этот абзац протухал уже дважды (см. выше) и один раз — так: он обещал «≤250
//! чанков (~256 KiB), возобновление — следующий срез», когда константа рядом
//! была 48, а blob-путь давно существовал. Поэтому здесь больше нет ни одного
//! числа: считать — по константам ниже.
//!
//! # Анти-DoS
//! Манифест с абсурдным числом чанков/размером отвергается ДО аллокации
//! (как `MAX_SKIP` в ratchet); число одновременных передач ограничено ПЕР ОТПРАВИТЕЛЬ
//! (`MAX_CONCURRENT_TRANSFERS`). Это НЕ бьёт число отправителей и общий RAM всех
//! `Reassembler` сразу (SEC-43: IK свободно генерируется) — тот бюджет считает
//! ВЫЗЫВАЮЩИЙ (см. `client::{offer_reassembly, reap_reassemblers, MAX_REASSEMBLY_SENDERS,
//! MAX_REASSEMBLY_TOTAL_BYTES}` в `lib.rs`), опираясь на `bytes_in_flight`/`has_transfer`
//! отсюда.

use std::collections::HashMap;

use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Полезная нагрузка файла на чанк. Консервативно под Ratchet-лимитом (~1256 Б
/// plaintext минус postcard-обвязка конверта) — валидируется round-trip-тестом
/// через настоящий relay.
pub const MAX_CHUNK_PAYLOAD: usize = 1024;
/// Максимум байт ОДНОГО текстового сообщения (`Content::Text`). Берём тот же
/// проверенный бюджет, что и чанк файла: `FileChunk` несёт 1024 Б данных ПЛЮС
/// больше обвязки (id+index), чем `Text`, и уже проходит round-trip через relay
/// — значит 1024 Б текста заведомо влезают в один Ratchet-пакет. Гейтит UI
/// (байтовая длина, чтобы кириллица 2 Б/симв считалась честно), иначе длинный
/// текст молча падал бы «отправка не удалась».
pub const MAX_TEXT_BYTES: usize = MAX_CHUNK_PAYLOAD;
/// Максимум чанков на inline-файл. Связывающий лимит — НЕ mailbox
/// (`MAX_FETCH_SEALS=256`), а capability-quota на admission-пути: каждый чанк —
/// отдельный запрос к relay, а dev-cap разрешает `max_requests=100` за окно
/// (600 с). Файл в 150+ чанков молча упирался в `CapabilityQuota` где-то на
/// ~100-м чанке и «отправка не удавалась». Держим 48: 48 чанков + манифест = 49
/// запросов, ~50 запросов остаётся на попутный текст/чанки в том же окне. Файлы
/// крупнее уходят по blob-пути (§15, cookie-gated, вне message-quota).
pub const MAX_FILE_CHUNKS: u32 = 48;
/// Максимальный размер inline-файла (48 KiB). Всё, что больше, GUI шлёт по
/// E2E-blob-пути (`client::blob` + `Content::FileRef`).
pub const MAX_FILE_SIZE: u64 = MAX_CHUNK_PAYLOAD as u64 * MAX_FILE_CHUNKS as u64;
/// Лимит длины имени файла (манифест должен влезать даже как Initial-конверт,
/// у которого plaintext ~104 Б из-за KEM-ct).
pub const MAX_FILENAME: usize = 48;
/// Максимум одновременных незавершённых передач в `Reassembler` (анти-память-DoS).
pub const MAX_CONCURRENT_TRANSFERS: usize = 8;
/// A half-assembled transfer with no new chunk for this long is abandoned (a failed/aborted
/// `send_file`) and gets evicted, so it cannot pin a `MAX_CONCURRENT_TRANSFERS` slot forever.
/// Measured from the LAST chunk, so an actively-arriving transfer is never reaped. 5 minutes:
/// generous for a real transfer's inter-chunk gap, prompt for a dead one.
///
/// SEC-43: `reap_stale` (below) only walks THIS Reassembler, and used to run ONLY from
/// `start_transfer` — i.e. only when the SAME sender sent another manifest. A sender who starts a
/// transfer and then goes silent forever would never trigger it again, pinning the slot (and its
/// RAM) until the account was switched or the process exited. `client::reap_reassemblers` in
/// `lib.rs` now also drives this from the ordinary receive path, across EVERY sender, so it fires
/// on the next poll regardless of what the abandoning sender does.
pub const STALE_PARTIAL_SECS: u64 = 300;
/// Верхняя граница байтовой длины эмодзи реакции. С запасом на ZWJ/составные
/// грапхемы (флаги, семьи), но отсекает абсурд ДО аллокации (анти-DoS на приёме).
pub const MAX_EMOJI_BYTES: usize = 64;
/// Byte cap on the (self-declared) profile display name. Rejects an absurd received
/// profile BEFORE allocation.
pub const MAX_PROFILE_NAME: usize = 64;
/// Byte cap on the profile bio ("about me").
pub const MAX_PROFILE_BIO: usize = 280;
/// Byte cap on an (already-encoded) avatar image. A 128px PNG is ~30-60 KiB; this
/// leaves headroom while staying well under the file-chunk mailbox budget. Enforced
/// on the ENCODED bytes (both when producing and when receiving), and gates the
/// avatar reassembler before allocation.
pub const MAX_AVATAR_BYTES: usize = 96 * 1024;
/// Max chunks for an avatar transfer. `MAX_AVATAR_BYTES / MAX_CHUNK_PAYLOAD` rounded
/// up, still << one mailbox (`MAX_FETCH_SEALS=256`) with room for the manifest.
pub const MAX_AVATAR_CHUNKS: u32 = (MAX_AVATAR_BYTES / MAX_CHUNK_PAYLOAD) as u32 + 1;
/// Byte cap on a publication's text. A publication is a single inline session packet
/// (like a chat message), so it shares the one-packet text budget — v1 is text-only.
/// Rejects an absurd received post BEFORE allocation.
pub const MAX_POST_TEXT: usize = MAX_TEXT_BYTES;
/// Byte cap on an (already-encoded) publication/story image. Shares the avatar budget:
/// a chunked, per-recipient E2E transfer with NO shared relay blob (so the relay never
/// sees "the whole audience pulls one blob_id" — the correlation an inline post image is
/// specifically chosen to avoid). Enforced on the ENCODED bytes and gates the reassembler
/// before allocation. Kept at the avatar size so a full post fan-out stays under the
/// admission message-quota (manifest + chunks ≈ one avatar's worth of requests per contact).
pub const MAX_POST_IMAGE_BYTES: usize = 96 * 1024;
/// Max chunks for a post-image transfer (`MAX_POST_IMAGE_BYTES / MAX_CHUNK_PAYLOAD` rounded
/// up, room for the manifest) — mirrors `MAX_AVATAR_CHUNKS`.
pub const MAX_POST_IMAGE_CHUNKS: u32 = (MAX_POST_IMAGE_BYTES / MAX_CHUNK_PAYLOAD) as u32 + 1;
/// Max profile GALLERY photos (beyond the always-shown avatar). The whole gallery travels as ONE
/// transfer that atomically replaces the peer's copy. A SMALL gallery that fits one mailbox goes
/// inline (`GalleryManifest`, no blob TTL); a larger one rides the per-recipient blob path
/// (`GalleryRef`) — same fork as post media (#98). 6 avatar-sized photos pack to ~577 chunks, far
/// past the 256-seal mailbox cap, so those MUST use the blob path (`gallery_fits_inline` decides).
pub const MAX_GALLERY_PHOTOS: usize = 6;
/// Byte cap on the PACKED gallery blob (length-prefixed concat of ≤ `MAX_GALLERY_PHOTOS` avatar-sized
/// images + their 4-byte length headers + the count header). Gates both the inline reassembler and
/// the blob download before allocation.
pub const MAX_GALLERY_BYTES: usize = MAX_GALLERY_PHOTOS * MAX_AVATAR_BYTES + 4 * (MAX_GALLERY_PHOTOS + 1);
/// Max chunks for a gallery transfer (`MAX_GALLERY_BYTES / MAX_CHUNK_PAYLOAD` rounded up, room for
/// the manifest). This is the BLOB-path bound; the inline path is additionally gated by
/// `gallery_fits_inline` to the mailbox cap.
pub const MAX_GALLERY_CHUNKS: u32 = (MAX_GALLERY_BYTES / MAX_CHUNK_PAYLOAD) as u32 + 1;

/// Whether a `PostAttachmentRef`/`GalleryRef`-shaped blob pointer declares a shape an honest
/// sender could have produced. `max_bytes` is the per-kind plaintext ceiling.
///
/// SEC-31: the chunk COUNT is the field that matters, and it was previously only checked for
/// `!= 0`. A blob pointer's `chunks` drives one relay round trip each, so an unbounded count is
/// unbounded work — the relay's own ceiling is `blobstore::MAX_BLOB_CHUNKS` (40 000), five orders
/// of magnitude above anything feed media needs. `chunk_count` is exactly what the sending side
/// computed (`blob_upload` derives its count the same way), so demanding EQUALITY — not merely an
/// upper bound — is both the tightest possible check and free of false rejections. At 60 KiB
/// blob chunks a 96 KiB attachment is two chunks, so this caps the fetch at two round trips.
///
/// `size == 0` is rejected because the send side refuses an empty attachment; without that a
/// zero-byte "attachment" would be a legal way to spend a queue slot.
pub fn blob_ref_shape_ok(size: u64, chunks: u32, max_bytes: usize) -> bool {
    size > 0 && size <= max_bytes as u64 && chunks == crate::blob::chunk_count(size)
}

/// Whether a packed gallery is small enough to send INLINE (its chunks + the manifest fit one
/// 256-seal mailbox), or must instead ride the blob path. The `+2` leaves the manifest seal plus a
/// little headroom for other mail queued in the same mailbox.
pub fn gallery_fits_inline(packed_len: usize) -> bool {
    let chunks = packed_len.div_ceil(MAX_CHUNK_PAYLOAD);
    chunks + 2 < node::protocol::MAX_FETCH_SEALS
}

/// Домен для канонического идентификатора сообщения (разделение доменов — как у
/// остальных KDF/хэш-констант проекта).
const MSG_ID_DOMAIN: &[u8] = b"KARST-msg-id-v1";

/// **Канонический сквозной идентификатор сообщения.** `H(domain ‖ author_ik ‖ ts
/// ‖ text)`, усечён до 16 Б. `author_ik` — АБСОЛЮТНЫЙ автор (у отправителя = свой
/// IK, у получателя = IK собеседника), поэтому обе стороны считают ОДИН и тот же
/// id из одного и того же сообщения — на нём стоят реакции/ответы/правки. Текст в
/// хэше снимает коллизию `ts` (секундная гранулярность). Корректно определён для
/// ШТАМПОВАННЫХ сообщений (`ts` — время отправителя, общее для обеих сторон);
/// для legacy `Text` (без штампа, `ts` — локальное прибытие) — best-effort.
pub fn msg_id(author_ik: &[u8; 32], ts: u64, text: &[u8]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(MSG_ID_DOMAIN);
    h.update(author_ik);
    h.update(ts.to_le_bytes());
    h.update(text);
    let full: [u8; 32] = h.finalize().into();
    full[..16].try_into().expect("16 ≤ 32")
}

/// Типизированный контент сообщения. Едет как postcard-байты в E2E-plaintext.
///
/// ВНИМАНИЕ к порядку вариантов: postcard кодирует вариант ПОЗИЦИОННЫМ индексом
/// (0,1,2,…), не именем. Новые варианты добавлять ТОЛЬКО В КОНЕЦ — иначе поедут
/// индексы и старые сообщения раскодируются как чужой вариант.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Content {
    /// Обычное текстовое сообщение (UTF-8 в байтах).
    Text(Vec<u8>),
    /// Заголовок передачи файла: собирает получатель.
    FileManifest { id: [u8; 16], name: String, size: u64, chunks: u32, hash: [u8; 32] },
    /// Один чанк файла по `id`, позиция `index`.
    FileChunk { id: [u8; 16], index: u32, data: Vec<u8> },
    /// Исчезающий текст: `expire_at` — АБСОЛЮТНОЕ unix-время (секунды) «умереть»,
    /// = момент отправки + TTL. Симметрично для обеих сторон (таймер от ОТПРАВКИ,
    /// не от прочтения — read-receipt'ов у нас нет). Получатель, забравший капсулу
    /// после `expire_at`, просто не показывает её (пришло мёртвым). Исчезающие
    /// НИКОГДА не пишутся в историю на диск — контроль хранения только на
    /// сотрудничающих клиентах; навязать удаление недобросовестному получателю
    /// нельзя (капсула лежит в mailbox до fetch).
    TextExpiring { text: Vec<u8>, expire_at: u64 },
    /// Текст со ШТАМПОМ времени ОТПРАВИТЕЛЯ (`ts`). Получатель хранит ИМЕННО этот
    /// ts (а не своё время прибытия) — так обе стороны согласны по (peer, ts, text)
    /// и это работает как СКВОЗНОЙ идентификатор сообщения: на нём стоят «удалить у
    /// всех», реакции, ответы. `Text` (без ts) остаётся для обратной совместимости.
    TextStamped { text: Vec<u8>, ts: u64 },
    /// Удалить У ВСЕХ: просьба стереть сообщение (`ts` + `text`), которое ОТПРАВИТЕЛЬ
    /// этого control-сообщения ранее послал получателю. Кооперативно: навязать
    /// недобросовестному клиенту нельзя (та же честная граница, что у исчезающих).
    DeleteForEveryone { ts: u64, text: Vec<u8> },
    /// Реакция на сообщение по каноническому `msg_id` (см. `msg_id`). `add=true` —
    /// поставить, `add=false` — снять. Автор реакции = отправитель этого control-
    /// сообщения (получатель атрибутирует по расшифровавшей сессии, как обычный
    /// текст). Маленький E2E-конверт; не файл. `msg_id` уже несёт автора+ts+текст
    /// цели, поэтому обе стороны сходятся на одном сообщении без относительных полей.
    Reaction { msg_id: [u8; 16], emoji: String, add: bool },
    /// Текст-ОТВЕТ (цитата): как `TextStamped` (`text`+`ts` отправителя), плюс
    /// `reply_to` — `msg_id` сообщения, на которое отвечают. Получатель показывает
    /// текст как обычное сообщение и рисует над ним цитату цели (найдя её по
    /// `reply_to` в своей истории). `reply_to` — тот же id у обеих сторон.
    TextReply { text: Vec<u8>, ts: u64, reply_to: [u8; 16] },
    /// ПРАВКА своего ранее отправленного сообщения `target_msg_id`. Overlay: текст
    /// истории не переписывается (иначе `msg_id` уехал бы), новый текст показывается
    /// поверх. Кооперативно (как удалить-у-всех) И только автор цели: получатель
    /// применяет, лишь если `target_msg_id` — сообщение, которое ЭТОТ отправитель
    /// ему прислал (иначе кто угодно правил бы чужие/ваши сообщения на вашем экране).
    EditMessage { target_msg_id: [u8; 16], new_text: Vec<u8>, edit_ts: u64 },
    /// Sender's SELF-DECLARED profile (name + bio). Rides the existing E2E channel
    /// as a control message; the receiver caches it per-contact (`peer_profiles.dat`)
    /// as a HINT. NOT identity: the trust anchor stays the safety number + the local
    /// label/`verified` in `ContactRecord` — a received profile NEVER touches them
    /// (Principle 7). Avatar is a separate slice (chunked, does not fit one packet);
    /// this variant carries text only.
    Profile { name: String, bio: String },
    /// Avatar transfer header (parallel to `FileManifest`, but the assembled bytes go
    /// into the sender's `peer_profiles.dat` avatar field, NOT saved as a file). The
    /// bytes are an opaque (PNG) image; the client never decodes them — the GUI does
    /// the bounded decode / re-encode. `id` groups the chunks; `hash` is verified on
    /// completion.
    AvatarManifest { id: [u8; 16], size: u32, chunks: u32, hash: [u8; 32] },
    /// One avatar chunk by `id`, position `index`.
    AvatarChunk { id: [u8; 16], index: u32, data: Vec<u8> },
    /// §15 large-file reference. APPENDED LAST on purpose: postcard numbers enum
    /// variants by declaration order, so a new variant must go at the end or every later
    /// variant's wire tag shifts (breaking already-encoded data + the variant-index
    /// tests). The file itself is an E2E-encrypted blob parked on the relay; this small
    /// envelope (sent inline over the session) carries everything the recipient needs to
    /// download + decrypt + verify it — the random `blob_id`, the per-file `key`, the
    /// plaintext SHA-256, `name`, `size`, and chunk `count`. The relay never sees `key`.
    FileRef {
        blob_id: [u8; 32],
        key: [u8; 32],
        hash: [u8; 32],
        name: String,
        size: u64,
        chunks: u32,
    },
    /// §15 route offer: "here are extra ways I reach the relay we share". Sent only
    /// when the user explicitly picks a contact to share with — never broadcast, never
    /// automatic. APPENDED LAST (see `FileRef` on why the order matters).
    ///
    /// `relay_noise_pub` says WHICH relay these routes reach. The receiver acts on the
    /// offer only if it matches the relay they already use: Noise authenticates the
    /// relay's static key, so a route to that identity cannot be impersonated — the
    /// worst a hostile route can do is fail. Routes to a DIFFERENT relay are a much
    /// bigger decision (that relay would see your metadata) and are not actionable here.
    ///
    /// The receiving side NEVER applies these automatically: connecting to an offered
    /// endpoint reveals your IP to whoever runs it (unless you ride an external PT), so
    /// accepting is an explicit human decision. Accepted routes still pass the carrier
    /// allowlist, so an offer cannot downgrade the protection you chose.
    RouteOffer { relay_noise_pub: [u8; 32], routes: String },
    /// A PUBLICATION (profile "post"): broadcast to all of the sender's contacts as an
    /// ordinary E2E session message, but routed by TYPE into the recipient's feed
    /// (`feed.dat`) instead of the chat log — the messenger analogue of a moments/timeline
    /// entry, with NO central feed server. It is NOT a private message: the same bytes are
    /// fanned out to every contact, so treat it as broadcast-to-your-audience, not 1:1.
    /// `id` dedups a redelivered copy; `ts` is the sender's clock (DTN may delay arrival).
    /// APPENDED LAST (see `FileRef` on why enum order is load-bearing for postcard tags).
    Publication { id: [u8; 16], text: String, ts: u64 },
    /// A STORY: an ephemeral publication that self-destructs at `expire_at` (absolute unix
    /// secs, typically now + 24h). Same broadcast fan-out as `Publication`, but the receiver
    /// drops it if it already arrived dead (DTN delay past `expire_at`) and the feed hides it
    /// once expired — the timeline analogue of `TextExpiring`. NO read/view receipts by design
    /// (a "seen by" list would be a new metadata surface). APPENDED LAST (postcard tag order).
    Story { id: [u8; 16], text: String, ts: u64, expire_at: u64 },
    /// RETRACT a publication ("delete for everyone"): broadcast to the same contacts, telling
    /// them to drop the post with this `id` from their feed. Best-effort, like chat's
    /// `DeleteForEveryone` — a contact who is offline past the relay's TTL, or who already read
    /// it, may keep it; it cannot claw back a screenshot. APPENDED LAST (postcard tag order).
    RetractPublication { id: [u8; 16] },
    /// A request to SUBSCRIBE to the sender-addressed account's posts. The recipient decides: a
    /// CHANNEL (public) account auto-accepts; a private account queues it for manual approval.
    /// The requester's IK is authenticated by the session, so no fields are needed. Receiving one
    /// NEVER changes the recipient's own channel mode — it can only (in channel mode) add the
    /// sender as a subscriber. APPENDED LAST (postcard tag order).
    JoinRequest,
    /// Sent back when a subscribe request is accepted, so the requester knows they're in and
    /// whether the account is a channel (`is_channel` → show the broadcast badge). A rejection is
    /// silent (no message), to avoid confirming the target to an unwanted requester. APPENDED LAST.
    JoinAccept { is_channel: bool },
    /// CHANNEL MIGRATION: "reach me at `new_ik` from now on." Sent over the EXISTING E2E session
    /// with a contact (which authenticates it as the current channel's owner — an attacker who
    /// merely learned the channel's public address cannot forge a message on that ratchet), so a
    /// compromised/spammed channel can be retired while the chosen contacts keep talking on a
    /// FRESH proxy. Sent SELECTIVELY (only to the contacts you keep), so the attacker never learns
    /// `new_ik`. The recipient re-points the contact to `new_ik` (its safety number changes — the
    /// UI prompts a re-verify). APPENDED LAST (postcard tag order).
    ChannelMigrate { new_ik: [u8; 32] },
    /// Header for a publication/story IMAGE. A post's text is one inline packet
    /// (`Publication`/`Story`); its image does NOT fit one packet, so it is chunked exactly
    /// like an avatar — the chunks reuse `AvatarChunk` (same `{id, index, data}` shape; the
    /// manifest kind disambiguates them). `id` groups the chunks; `post_id` ties the assembled
    /// image to the post it decorates (matched against the `Publication`/`Story` `id` already in
    /// the recipient's feed). Sent per-recipient over the same session fan-out — there is NO
    /// shared relay blob, so an image post reveals no "one blob, whole audience" correlation.
    /// `hash` is verified on completion. APPENDED LAST (postcard tag order).
    PostImageManifest { post_id: [u8; 16], id: [u8; 16], size: u32, chunks: u32, hash: [u8; 32] },
    /// Header for a post ATTACHMENT — the multi-attachment generalisation of `PostImageManifest`
    /// (which stays, for a single-image post). `index` is the attachment's slot in the post, `kind`
    /// = 0 image / 1 file, `name` the file name (empty for an image). Chunks reuse `AvatarChunk`,
    /// grouped by `id`; `post_id` ties it to the post. Same per-recipient fan-out, no relay blob.
    /// APPENDED LAST (postcard tag order).
    PostAttachmentManifest {
        post_id: [u8; 16],
        index: u32,
        kind: u8,
        name: String,
        id: [u8; 16],
        size: u32,
        chunks: u32,
        hash: [u8; 32],
    },
    /// "I'd like to add you" — carries the SENDER's self-declared profile so the recipient can see
    /// WHO is asking (name+bio) before deciding. Mutual-consent contact add: the recipient sees this
    /// as a pending request; accepting sends a `ContactAccept` back. APPENDED LAST (postcard tag).
    ContactRequest { name: String, bio: String },
    /// "I accepted your request" — carries the accepter's profile, so the original requester now sees
    /// the name+bio of the person who accepted. The consent handshake's second half.
    ContactAccept { name: String, bio: String },
    /// "I'd like us both to delete this conversation." A REQUEST (not a forced wipe — you can't make
    /// someone destroy their own data): the recipient is notified and chooses whether to clear their
    /// copy. The sender clears theirs locally. APPENDED LAST (postcard tag).
    DeleteConversation,
    /// A post ATTACHMENT delivered via the relay's BLOB store instead of inline session chunks —
    /// the blob-transport analogue of `PostAttachmentManifest`. A multi-attachment post used to fan
    /// ~90 inline chunks PER attachment PER recipient into the recipient's mailbox; four images
    /// overflowed the 256-seal cap and the later ones bounced off `MailboxFull`. Here the bulk rides
    /// the blob store (its own ceiling, not the mailbox) and only THIS tiny pointer sits in the
    /// mailbox — like `FileRef`, but routed to the post it decorates rather than the files list.
    ///
    /// The blob is **per-recipient** (a fresh random `blob_id`+`key` for each contact), so the relay
    /// never sees "one blob_id, the whole audience pulls it" — the audience-correlation the inline
    /// path was chosen to avoid. The honest cost is N uploads of the same image (one per recipient),
    /// and a recipient offline past the blob TTL (7 days) misses the media (the post TEXT still
    /// shows). `hash` is verified on completion; the relay never sees `key`. APPENDED LAST.
    PostAttachmentRef {
        post_id: [u8; 16],
        index: u32,
        kind: u8,
        name: String,
        blob_id: [u8; 32],
        key: [u8; 32],
        hash: [u8; 32],
        size: u64,
        chunks: u32,
    },
    /// "Show me your recent PUBLIC posts" — a live pull, so someone who isn't a subscriber can visit
    /// a profile and view it. The recipient's client answers by sending back its recent posts marked
    /// PUBLIC (audience = all subscribers) as ordinary `Publication`s — narrow-audience posts are
    /// NEVER served to a puller. Works only while the author is online to answer; the relay sees the
    /// request (who-views-whom), the honest cost of pull-on-demand. No fields — the requester is
    /// authenticated by the session. APPENDED LAST (postcard tag order).
    PostsRequest,
    /// A profile PHOTO-GALLERY transfer header (parallel to `AvatarManifest`): the assembled bytes are
    /// a length-prefixed pack of the sender's ≤ `MAX_GALLERY_PHOTOS` gallery images (`pack_gallery`),
    /// applied ATOMICALLY to `peer_profiles.dat` — replacing the peer's whole gallery, an empty pack
    /// clearing it. Chunks reuse `AvatarChunk`; `hash` is verified on completion. Like the avatar, the
    /// gallery is sent only to CONFIRMED contacts and is NOT backfilled to a later-added contact.
    /// APPENDED LAST (postcard numbers variants by declaration order — a new one must go at the end).
    GalleryManifest { id: [u8; 16], size: u32, chunks: u32, hash: [u8; 32] },
    /// A profile gallery delivered via the relay's BLOB store instead of inline session chunks — the
    /// blob analogue of `GalleryManifest` for a gallery too big for one mailbox (`gallery_fits_inline`
    /// false). Like `PostAttachmentRef`: the packed gallery is a per-recipient E2E blob (fresh random
    /// `blob_id`+`key` for each contact, so the relay never sees "one blob, whole audience"), and only
    /// this tiny pointer sits in the mailbox. Honest cost = N uploads (one per recipient) + a recipient
    /// offline past the blob TTL (7 days) misses the update (their previous gallery stays). `hash` is
    /// verified on completion; the relay never sees `key`. APPENDED LAST (postcard tag order).
    GalleryRef { blob_id: [u8; 32], key: [u8; 32], hash: [u8; 32], size: u64, chunks: u32 },
}

/// Сериализовать конверт в plaintext-байты.
pub fn encode(c: &Content) -> Vec<u8> {
    postcard::to_stdvec(c).expect("postcard serialize Content")
}

/// Разобрать plaintext-байты в конверт. Чужой/битый груз → ошибка (не паника).
pub fn decode(bytes: &[u8]) -> Result<Content, String> {
    postcard::from_bytes(bytes).map_err(|e| format!("content did not decode: {e}"))
}

/// The transfer id a MANIFEST variant would start in a `Reassembler` (`None` for a chunk or any
/// other `Content` — those never open a new transfer slot). Lets a caller admission-check a
/// GLOBAL cross-sender cap (SEC-43) BEFORE a manifest reaches the per-sender `Reassembler`,
/// without re-deriving `start_transfer`'s own per-kind bounds checks.
pub fn manifest_transfer_id(c: &Content) -> Option<[u8; 16]> {
    match c {
        Content::FileManifest { id, .. }
        | Content::AvatarManifest { id, .. }
        | Content::GalleryManifest { id, .. }
        | Content::PostImageManifest { id, .. }
        | Content::PostAttachmentManifest { id, .. } => Some(*id),
        _ => None,
    }
}

/// The byte size a MANIFEST variant declares it will assemble to (`None` for a chunk or any other
/// `Content`) — the sender's COMMITMENT, not what has arrived. SEC-43: a bare manifest carries no
/// payload, so a cap that only counted arrived chunk bytes would let a flood of manifests (no
/// chunks ever sent) reserve every slot for free; the caller's admission check uses THIS instead,
/// exactly like `Reassembler::declared_bytes_in_flight` on the already-admitted side.
pub fn manifest_declared_size(c: &Content) -> Option<u64> {
    match c {
        Content::FileManifest { size, .. } => Some(*size),
        Content::AvatarManifest { size, .. }
        | Content::GalleryManifest { size, .. }
        | Content::PostImageManifest { size, .. }
        | Content::PostAttachmentManifest { size, .. } => Some(*size as u64),
        _ => None,
    }
}

/// Завершённая, собранная и проверенная по хэшу передача файла.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedFile {
    /// The manifest id — a per-transfer identifier. Used as a **dedup key** when saving, so a
    /// re-delivered file (the mailbox/session can re-deliver before an ack) is saved once, not
    /// twice — the inline-path analogue of `blob_id` on the large-file path.
    pub id: [u8; 16],
    pub name: String,
    pub bytes: Vec<u8>,
}

/// A completed, reassembled, hash-verified transfer. Files are saved to disk; avatar
/// bytes are handed to the GUI for bounded decode + storage in the peer profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Assembled {
    File(CompletedFile),
    Avatar { bytes: Vec<u8> },
    /// A completed publication/story image. `post_id` matches the `Publication`/`Story` already in
    /// the recipient's feed; the GUI attaches the bytes to that post (a bounded decode/display).
    PostImage { post_id: [u8; 16], bytes: Vec<u8> },
    /// A completed post ATTACHMENT (multi-attachment posts). `index`/`kind`/`name` place and type it
    /// within the post the GUI stores it against.
    PostAttachment { post_id: [u8; 16], index: u32, kind: u8, name: String, bytes: Vec<u8> },
    /// A completed profile-gallery transfer: `bytes` is the packed image list (`unpack_gallery`),
    /// applied atomically to the sender's peer profile (replacing the whole gallery).
    Gallery { bytes: Vec<u8> },
}

/// Разбить файл на (манифест, чанки). Отвергает слишком длинное имя / большой файл.
pub fn chunk_file(name: &str, bytes: &[u8]) -> Result<(Content, Vec<Content>), String> {
    if name.is_empty() || name.len() > MAX_FILENAME {
        return Err(format!("file name must be 1..{MAX_FILENAME} bytes"));
    }
    if bytes.is_empty() {
        // Пустой файл дал бы манифест с chunks=0, который получатель отвергает —
        // асимметрия (отправитель «успех», получатель «мимо»). Отсекаем у источника.
        return Err("empty file (0 bytes)".into());
    }
    if bytes.len() as u64 > MAX_FILE_SIZE {
        return Err(format!("file larger than {} B (the inline ceiling)", MAX_FILE_SIZE));
    }
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    let chunks: Vec<Content> = bytes
        .chunks(MAX_CHUNK_PAYLOAD)
        .enumerate()
        .map(|(i, ch)| Content::FileChunk { id, index: i as u32, data: ch.to_vec() })
        .collect();
    let manifest = Content::FileManifest {
        id,
        name: name.to_string(),
        size: bytes.len() as u64,
        chunks: chunks.len() as u32,
        hash,
    };
    Ok((manifest, chunks))
}

/// Split an (already-encoded) avatar image into (manifest, chunks). Rejects empty or
/// over-cap input at the source (symmetry with the receiver, which rejects the same).
/// The caller (GUI) must have already produced bounded, re-encoded PNG bytes.
pub fn chunk_avatar(bytes: &[u8]) -> Result<(Content, Vec<Content>), String> {
    if bytes.is_empty() {
        return Err("empty avatar".into());
    }
    if bytes.len() > MAX_AVATAR_BYTES {
        return Err(format!("avatar > {MAX_AVATAR_BYTES} bytes"));
    }
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    let chunks: Vec<Content> = bytes
        .chunks(MAX_CHUNK_PAYLOAD)
        .enumerate()
        .map(|(i, ch)| Content::AvatarChunk { id, index: i as u32, data: ch.to_vec() })
        .collect();
    let manifest = Content::AvatarManifest { id, size: bytes.len() as u32, chunks: chunks.len() as u32, hash };
    Ok((manifest, chunks))
}

/// Pack a gallery (≤ `MAX_GALLERY_PHOTOS` images) into ONE blob: a u64 SENDER-CLOCK `ts` (so the
/// receiver can reject a stale apply — the same gallery may arrive twice out of order across the
/// inline and blob paths), then a u32 count, then per image a u32 byte-length followed by its bytes
/// (all little-endian). The inverse is `unpack_gallery`. An empty gallery packs to a 12-byte
/// `ts+count=0` blob (a valid "clear" transfer).
pub fn pack_gallery(ts: u64, photos: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ts.to_le_bytes());
    out.extend_from_slice(&(photos.len() as u32).to_le_bytes());
    for p in photos {
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// Inverse of `pack_gallery`, returning `(sender_ts, photos)`. Rejects a malformed/oversized pack
/// (anti-DoS on the RECEIVER) rather than trusting the wire: truncated header, bad count, a length
/// past the buffer, an over-cap image, or trailing bytes.
pub fn unpack_gallery(bytes: &[u8]) -> Result<(u64, Vec<Vec<u8>>), String> {
    let mut off = 0usize;
    fn rd_u32(b: &[u8], o: &mut usize) -> Result<u32, String> {
        if *o + 4 > b.len() {
            return Err("gallery pack truncated".into());
        }
        let v = u32::from_le_bytes(b[*o..*o + 4].try_into().unwrap());
        *o += 4;
        Ok(v)
    }
    if bytes.len() < 8 {
        return Err("gallery pack truncated (no ts)".into());
    }
    let ts = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    off += 8;
    let count = rd_u32(bytes, &mut off)? as usize;
    if count > MAX_GALLERY_PHOTOS {
        return Err("gallery pack: too many photos".into());
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let len = rd_u32(bytes, &mut off)? as usize;
        if len == 0 || len > MAX_AVATAR_BYTES {
            return Err("gallery pack: bad image length".into());
        }
        if off + len > bytes.len() {
            return Err("gallery pack: image past buffer".into());
        }
        out.push(bytes[off..off + len].to_vec());
        off += len;
    }
    if off != bytes.len() {
        return Err("gallery pack: trailing bytes".into());
    }
    Ok((ts, out))
}

/// Split a PACKED gallery blob into (manifest, chunks). The caller packs bounded, re-encoded images
/// (each ≤ avatar-sized) with `pack_gallery`; this gates the packed size and chunks it like an avatar
/// (reusing `AvatarChunk`). An empty gallery still yields a 4-byte pack = a valid "clear" transfer.
pub fn chunk_gallery(packed: &[u8]) -> Result<(Content, Vec<Content>), String> {
    if packed.is_empty() {
        return Err("empty gallery pack".into());
    }
    if packed.len() > MAX_GALLERY_BYTES {
        return Err(format!("gallery > {MAX_GALLERY_BYTES} bytes"));
    }
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    let hash: [u8; 32] = Sha256::digest(packed).into();
    let chunks: Vec<Content> = packed
        .chunks(MAX_CHUNK_PAYLOAD)
        .enumerate()
        .map(|(i, ch)| Content::AvatarChunk { id, index: i as u32, data: ch.to_vec() })
        .collect();
    let manifest = Content::GalleryManifest { id, size: packed.len() as u32, chunks: chunks.len() as u32, hash };
    Ok((manifest, chunks))
}

/// Split an (already-encoded) publication/story image into (manifest, chunks) tied to `post_id`.
/// The chunks are `AvatarChunk`s (same shape; the `PostImageManifest` disambiguates the kind on
/// the receiver). The caller (GUI) must have produced bounded, re-encoded image bytes; rejects
/// empty or over-cap input at the source (symmetry with the receiver's manifest check).
pub fn chunk_post_image(post_id: [u8; 16], bytes: &[u8]) -> Result<(Content, Vec<Content>), String> {
    if bytes.is_empty() {
        return Err("empty post image".into());
    }
    if bytes.len() > MAX_POST_IMAGE_BYTES {
        return Err(format!("post image > {MAX_POST_IMAGE_BYTES} bytes"));
    }
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    let chunks: Vec<Content> = bytes
        .chunks(MAX_CHUNK_PAYLOAD)
        .enumerate()
        .map(|(i, ch)| Content::AvatarChunk { id, index: i as u32, data: ch.to_vec() })
        .collect();
    let manifest = Content::PostImageManifest {
        post_id,
        id,
        size: bytes.len() as u32,
        chunks: chunks.len() as u32,
        hash,
    };
    Ok((manifest, chunks))
}

/// Chunk ONE post attachment (image or file) for the multi-attachment fan-out. `kind` = 0 image /
/// 1 file; `index` is its slot in the post; `name` the file name (empty for an image). Same chunked
/// transport as a post image (manifest + `AvatarChunk`s), bounded to a single sidecar-sized payload.
pub fn chunk_post_attachment(
    post_id: [u8; 16],
    index: u32,
    kind: u8,
    name: &str,
    bytes: &[u8],
) -> Result<(Content, Vec<Content>), String> {
    if bytes.is_empty() {
        return Err("empty attachment".into());
    }
    if bytes.len() > MAX_POST_IMAGE_BYTES {
        return Err(format!("attachment > {MAX_POST_IMAGE_BYTES} bytes"));
    }
    if name.len() > MAX_FILENAME {
        return Err("attachment name too long".into());
    }
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    let chunks: Vec<Content> = bytes
        .chunks(MAX_CHUNK_PAYLOAD)
        .enumerate()
        .map(|(i, ch)| Content::AvatarChunk { id, index: i as u32, data: ch.to_vec() })
        .collect();
    let manifest = Content::PostAttachmentManifest {
        post_id,
        index,
        kind,
        name: name.to_string(),
        id,
        size: bytes.len() as u32,
        chunks: chunks.len() as u32,
        hash,
    };
    Ok((manifest, chunks))
}

/// Whether an in-flight transfer becomes a saved file or an avatar image.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
enum TransferKind {
    File { name: String },
    Avatar,
    PostImage { post_id: [u8; 16] },
    PostAttachment { post_id: [u8; 16], index: u32, kind: u8, name: String },
    Gallery,
}

/// Незавершённая передача: метаданные из манифеста + пришедшие чанки.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Partial {
    kind: TransferKind,
    size: u64,
    total: u32,
    hash: [u8; 32],
    received: HashMap<u32, Vec<u8>>,
    /// Wall-clock of the last activity (manifest or a chunk). Drives stale-partial eviction so
    /// an abandoned transfer cannot pin a slot forever.
    last_seen: u64,
}

/// Собиратель файлов из потока `Content`. Держится ВЫЗЫВАЮЩИМ (worker/CLI) между
/// recv-вызовами — пересборка в памяти живого процесса. Текст проходит мимо.
#[derive(Default)]
pub struct Reassembler {
    transfers: HashMap<[u8; 16], Partial>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialize the in-flight transfers so they can outlive the process.
    ///
    /// Inline chunks were reassembled ONLY in RAM while the messages carrying them were already
    /// ACKed — so the relay had been told to delete them. A crash mid-transfer therefore lost the
    /// file with no record and no retry: the sender saw "delivered", the receiver had nothing. The
    /// large-file (blob) path was already crash-safe via pending downloads; this closes the same
    /// hole for the inline path, which is bounded to `MAX_INLINE_FILE` but still a real message.
    pub fn export(&self) -> Result<Vec<u8>, String> {
        let v: Vec<([u8; 16], Partial)> =
            self.transfers.iter().map(|(k, p)| (*k, p.clone())).collect();
        postcard::to_stdvec(&v).map_err(|e| format!("encoding partial transfers: {e}"))
    }

    /// Restore transfers saved by [`Reassembler::export`]. Unreadable state is reported, never
    /// silently treated as "nothing in flight" — that is how the loss looked in the first place.
    pub fn restore(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        let v: Vec<([u8; 16], Partial)> = postcard::from_bytes(bytes)
            .map_err(|e| format!("decoding partial transfers: {e}"))?;
        Ok(Reassembler { transfers: v.into_iter().collect() })
    }

    /// How many transfers are mid-flight (for the caller's "save only when it changed" check).
    pub fn in_flight(&self) -> usize {
        self.transfers.len()
    }

    /// Feed one envelope. `Text` etc. -> ignored (not a transfer). Returns `Some(...)`
    /// when a transfer is complete AND its hash matched (a file or an avatar). `Err` is
    /// detected corruption/absurdity (NOT silently accepted): bad hash, orphan chunk,
    /// overflow.
    pub fn offer(&mut self, c: Content, now: u64) -> Result<Option<Assembled>, String> {
        match c {
            // Текст/исчезающий/штампованный/control — не файлы; собиратель их
            // пропускает (маршрутизируются раньше, в worker'е). Здесь — оборонительно.
            Content::Text(_)
            | Content::TextExpiring { .. }
            | Content::TextStamped { .. }
            | Content::DeleteForEveryone { .. }
            | Content::Reaction { .. }
            | Content::TextReply { .. }
            | Content::EditMessage { .. }
            | Content::Profile { .. }
            // FileRef is a blob pointer handled by the worker (triggers a download), not
            // a chunk-reassembly transfer — the collector passes it through.
            | Content::FileRef { .. }
            // A route offer is a control message for the worker/UI, not a transfer.
            | Content::RouteOffer { .. }
            // A publication / story / retraction / channel control is routed by the worker, not a
            // chunk transfer.
            | Content::Publication { .. }
            | Content::Story { .. }
            | Content::RetractPublication { .. }
            | Content::JoinRequest
            | Content::JoinAccept { .. }
            | Content::ChannelMigrate { .. }
            | Content::ContactRequest { .. }
            | Content::ContactAccept { .. }
            | Content::DeleteConversation
            // A pull request is a control message handled by the worker (send back public posts).
            | Content::PostsRequest
            // Like `FileRef`: a blob pointer the worker turns into a download, not a chunk transfer.
            | Content::PostAttachmentRef { .. }
            // A gallery blob pointer — the worker persists it as a pending gallery + downloads it.
            | Content::GalleryRef { .. } => Ok(None),
            Content::FileManifest { id, name, size, chunks, hash } => {
                // Анти-DoS: отвергаем абсурд ДО аллокации.
                if chunks == 0 || chunks > MAX_FILE_CHUNKS || size > MAX_FILE_SIZE {
                    return Err("manifest outside its limits (chunks/size)".into());
                }
                if name.len() > MAX_FILENAME {
                    return Err("file name too long".into());
                }
                self.start_transfer(id, TransferKind::File { name }, size, chunks, hash, now)
            }
            Content::AvatarManifest { id, size, chunks, hash } => {
                // Anti-DoS: reject an absurd avatar manifest before allocation.
                if chunks == 0 || chunks > MAX_AVATAR_CHUNKS || size as usize > MAX_AVATAR_BYTES {
                    return Err("avatar manifest out of limits (chunks/size)".into());
                }
                self.start_transfer(id, TransferKind::Avatar, size as u64, chunks, hash, now)
            }
            Content::GalleryManifest { id, size, chunks, hash } => {
                // Anti-DoS: reject an absurd gallery manifest before allocation.
                if chunks == 0 || chunks > MAX_GALLERY_CHUNKS || size as usize > MAX_GALLERY_BYTES {
                    return Err("gallery manifest out of limits (chunks/size)".into());
                }
                self.start_transfer(id, TransferKind::Gallery, size as u64, chunks, hash, now)
            }
            Content::PostImageManifest { post_id, id, size, chunks, hash } => {
                // Anti-DoS: reject an absurd post-image manifest before allocation.
                if chunks == 0 || chunks > MAX_POST_IMAGE_CHUNKS || size as usize > MAX_POST_IMAGE_BYTES {
                    return Err("post-image manifest out of limits (chunks/size)".into());
                }
                self.start_transfer(id, TransferKind::PostImage { post_id }, size as u64, chunks, hash, now)
            }
            Content::PostAttachmentManifest { post_id, index, kind, name, id, size, chunks, hash } => {
                // Anti-DoS: reject an absurd manifest before allocation (same bounds as a post image).
                if chunks == 0 || chunks > MAX_POST_IMAGE_CHUNKS || size as usize > MAX_POST_IMAGE_BYTES {
                    return Err("post-attachment manifest out of limits (chunks/size)".into());
                }
                if name.len() > MAX_FILENAME {
                    return Err("attachment name too long".into());
                }
                self.start_transfer(id, TransferKind::PostAttachment { post_id, index, kind, name }, size as u64, chunks, hash, now)
            }
            Content::FileChunk { id, index, data } | Content::AvatarChunk { id, index, data } => {
                let Some(p) = self.transfers.get_mut(&id) else {
                    // ИНВАРИАНТ: манифест приходит ДО своих чанков. Держится тем,
                    // что send_file шлёт манифест первым, mailbox — FIFO, а ratchet
                    // in-order в пределах цепочки. Если это сломать (напр.
                    // распараллелить отправку чанков), передача будет молча гибнуть
                    // здесь — НЕ оптимизировать порядок, не сняв это ограничение.
                    return Err("chunk without a manifest".into());
                };
                if index >= p.total {
                    return Err("chunk index out of range".into());
                }
                if data.len() > MAX_CHUNK_PAYLOAD {
                    return Err("chunk exceeds the limit".into());
                }
                p.last_seen = now; // keep an actively-arriving transfer fresh (never reaped)
                p.received.insert(index, data);
                self.try_complete(id)
            }
        }
    }

    /// Start (idempotently) a file/avatar transfer after its manifest passed the
    /// per-kind caps. Bounds the number of concurrent transfers.
    fn start_transfer(
        &mut self,
        id: [u8; 16],
        kind: TransferKind,
        size: u64,
        chunks: u32,
        hash: [u8; 32],
        now: u64,
    ) -> Result<Option<Assembled>, String> {
        // Reap abandoned partials FIRST, so a dead transfer never blocks a live one from
        // starting (the "8 stalled from one peer → new files rejected until restart" gap).
        self.reap_stale(now);
        if !self.transfers.contains_key(&id) && self.transfers.len() >= MAX_CONCURRENT_TRANSFERS {
            return Err("too many concurrent transfers".into());
        }
        // Idempotent: a repeated manifest does not reset already-received chunks.
        self.transfers.entry(id).or_insert_with(|| Partial {
            kind,
            size,
            total: chunks,
            hash,
            received: HashMap::new(),
            last_seen: now,
        });
        self.try_complete(id)
    }

    /// Drop half-assembled transfers idle longer than `STALE_PARTIAL_SECS`. Called on each new
    /// manifest (so a dead transfer never pins a slot) and exposed so the worker can reap on a
    /// timer too. `saturating_sub` treats a regressed clock as fresh (kept), never spuriously
    /// stale. Returns how many were evicted.
    pub fn reap_stale(&mut self, now: u64) -> usize {
        let before = self.transfers.len();
        self.transfers.retain(|_, p| now.saturating_sub(p.last_seen) <= STALE_PARTIAL_SECS);
        before - self.transfers.len()
    }

    /// Число незавершённых передач (для тестов/диагностики).
    pub fn pending(&self) -> usize {
        self.transfers.len()
    }

    /// Total bytes currently held across all in-flight partials in THIS Reassembler (the sum of
    /// arrived-so-far chunk payloads, not the declared manifest sizes — a transfer that is only
    /// half-arrived pins only half its final weight). A DIAGNOSTIC figure only — the cross-sender
    /// admission cap (SEC-43, see `declared_bytes_in_flight`) does NOT use this, because a bare
    /// manifest carries zero payload: gating on arrived bytes would let a flood of manifests with
    /// no chunks ever sent reserve every slot for free before this number moves at all.
    pub fn bytes_in_flight(&self) -> usize {
        self.transfers.values().map(|p| p.received.values().map(Vec::len).sum::<usize>()).sum()
    }

    /// Sum of DECLARED transfer sizes (the manifest's `size` field — the sender's commitment)
    /// across all in-flight partials in THIS Reassembler. This, not `bytes_in_flight`, is what the
    /// caller's global RAM cap (SEC-43) must admission-check a new manifest against: it bounds the
    /// worst case the sender has already promised to make us allocate, the moment the manifest is
    /// accepted — before a single chunk has to arrive to "prove" the cost is real.
    pub fn declared_bytes_in_flight(&self) -> usize {
        self.transfers.values().map(|p| p.size as usize).sum()
    }

    /// Whether transfer `id` is already tracked here. Lets the caller tell "a repeated manifest
    /// for a transfer already admitted" (a harmless idempotent resend, per `start_transfer`) apart
    /// from "a genuinely new transfer", WITHOUT duplicating `start_transfer`'s own bookkeeping —
    /// needed to admission-check a new transfer against a GLOBAL cap before it reaches this
    /// per-sender Reassembler at all.
    pub fn has_transfer(&self, id: [u8; 16]) -> bool {
        self.transfers.contains_key(&id)
    }

    fn try_complete(&mut self, id: [u8; 16]) -> Result<Option<Assembled>, String> {
        let done = {
            let p = self.transfers.get(&id).expect("id present");
            p.received.len() as u32 == p.total
        };
        if !done {
            return Ok(None);
        }
        let p = self.transfers.remove(&id).expect("id present");
        let mut bytes = Vec::with_capacity(p.size as usize);
        for i in 0..p.total {
            let chunk = p.received.get(&i).expect("every chunk present (done)");
            bytes.extend_from_slice(chunk);
        }
        if bytes.len() as u64 != p.size {
            return Err("reassembled size does not match the manifest".into());
        }
        let got: [u8; 32] = Sha256::digest(&bytes).into();
        if got != p.hash {
            // ОБНАРУЖЕННАЯ порча — не тихо принять.
            return Err("SHA-256 of the reassembled file does not match (corruption or substitution)".into());
        }
        Ok(Some(match p.kind {
            TransferKind::File { name } => Assembled::File(CompletedFile { id, name, bytes }),
            TransferKind::Avatar => Assembled::Avatar { bytes },
            TransferKind::PostImage { post_id } => Assembled::PostImage { post_id, bytes },
            TransferKind::PostAttachment { post_id, index, kind, name } => {
                Assembled::PostAttachment { post_id, index, kind, name, bytes }
            }
            TransferKind::Gallery => Assembled::Gallery { bytes },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(r: &mut Reassembler, manifest: Content, chunks: Vec<Content>) -> Option<Assembled> {
        // Кодируем/декодируем каждый конверт — как на проводе.
        let mut out = None;
        for c in std::iter::once(manifest).chain(chunks) {
            let wire = encode(&c);
            let back = decode(&wire).unwrap();
            if let Some(f) = r.offer(back, 0).unwrap() {
                out = Some(f);
            }
        }
        out
    }

    fn as_file(a: Option<Assembled>) -> CompletedFile {
        match a.expect("transfer completed") {
            Assembled::File(f) => f,
            other => panic!("expected a file, got {other:?}"),
        }
    }

    #[test]
    fn file_roundtrips_byte_identical_across_multiple_chunks() {
        // Несколько чанков (2.5 KiB → 3 чанка по 1024).
        let data: Vec<u8> = (0..2560u32).map(|i| (i * 31) as u8).collect();
        let (m, ch) = chunk_file("photo.jpg", &data).unwrap();
        assert!(ch.len() >= 3, "expected more than one chunk");
        let mut r = Reassembler::new();
        let f = as_file(feed_all(&mut r, m, ch));
        assert_eq!(f.name, "photo.jpg");
        assert_eq!(f.bytes, data, "byte for byte");
        assert_eq!(r.pending(), 0, "the transfer is cleared after reassembly");
    }

    #[test]
    fn avatar_roundtrips_byte_identical_and_is_not_a_file() {
        // Multi-chunk avatar (2.5 KiB -> 3 chunks). Completes as Avatar, not File.
        let data: Vec<u8> = (0..2560u32).map(|i| (i * 17) as u8).collect();
        let (m, ch) = chunk_avatar(&data).unwrap();
        assert!(ch.len() >= 3, "expected >1 chunk");
        assert_eq!(encode(&m)[0], 10, "AvatarManifest is variant 10");
        assert_eq!(encode(&ch[0])[0], 11, "AvatarChunk is variant 11");
        let mut r = Reassembler::new();
        match feed_all(&mut r, m, ch).expect("avatar assembled") {
            Assembled::Avatar { bytes } => assert_eq!(bytes, data, "byte-for-byte"),
            other => panic!("avatar must complete as an avatar, not {other:?}"),
        }
        assert_eq!(r.pending(), 0, "transfer cleared after assembly");
    }

    #[test]
    fn gallery_packs_roundtrips_and_is_variant_27() {
        // Two images, the second spanning multiple chunks — the packed blob round-trips byte-identical
        // and completes as a Gallery (not a File/Avatar).
        let photos = vec![vec![1u8, 2, 3], (0..2000u32).map(|i| (i * 7) as u8).collect::<Vec<u8>>()];
        let packed = pack_gallery(42, &photos);
        assert_eq!(unpack_gallery(&packed).unwrap(), (42, photos.clone()), "pack/unpack incl. ts");
        let (m, ch) = chunk_gallery(&packed).unwrap();
        assert!(ch.len() >= 2, "expected multi-chunk gallery");
        assert_eq!(encode(&m)[0], 27, "GalleryManifest is variant 27 (after PostsRequest=26)");
        assert_eq!(encode(&ch[0])[0], 11, "gallery chunks reuse AvatarChunk (variant 11)");
        let mut r = Reassembler::new();
        match feed_all(&mut r, m, ch).expect("gallery assembled") {
            Assembled::Gallery { bytes } => assert_eq!(unpack_gallery(&bytes).unwrap(), (42, photos)),
            other => panic!("gallery must complete as a gallery, not {other:?}"),
        }
        // Old variant indices are unchanged (the discriminating invariant for appending at the end).
        assert_eq!(encode(&Content::Text(b"x".to_vec()))[0], 0, "Text still variant 0");
        assert_eq!(
            encode(&Content::AvatarManifest { id: [0; 16], size: 1, chunks: 1, hash: [0; 32] })[0],
            10,
            "AvatarManifest still variant 10"
        );
    }

    #[test]
    fn empty_gallery_is_a_valid_clear_transfer() {
        // A 0-photo gallery packs to 12 bytes (ts + count=0) and round-trips to an empty vec — how
        // "clear my gallery" is sent atomically (not an error).
        let packed = pack_gallery(7, &[]);
        assert_eq!(packed.len(), 12);
        assert_eq!(unpack_gallery(&packed).unwrap(), (7, Vec::<Vec<u8>>::new()));
        let (m, ch) = chunk_gallery(&packed).unwrap();
        let mut r = Reassembler::new();
        match feed_all(&mut r, m, ch).expect("empty gallery assembled") {
            Assembled::Gallery { bytes } => assert!(unpack_gallery(&bytes).unwrap().1.is_empty()),
            other => panic!("expected empty Gallery, got {other:?}"),
        }
    }

    #[test]
    fn gallery_ref_is_variant_28_and_fits_inline_decides_by_mailbox_cap() {
        let r = Content::GalleryRef { blob_id: [1; 32], key: [2; 32], hash: [3; 32], size: 9, chunks: 1 };
        assert_eq!(decode(&encode(&r)).unwrap(), r);
        assert_eq!(encode(&r)[0], 28, "GalleryRef is variant 28 (after GalleryManifest=27)");
        // A blob ref is NOT a chunk transfer — the reassembler ignores it.
        assert_eq!(Reassembler::new().offer(r, 0).unwrap(), None);
        // Small pack fits inline; a pack larger than the mailbox worth of chunks does not.
        assert!(gallery_fits_inline(2 * MAX_CHUNK_PAYLOAD));
        assert!(!gallery_fits_inline(MAX_GALLERY_BYTES)); // full 6-photo worst case must go via blob
    }

    #[test]
    fn unpack_gallery_rejects_malformed() {
        assert!(unpack_gallery(&[]).is_err(), "empty buffer (no ts)");
        assert!(unpack_gallery(&[0u8; 4]).is_err(), "shorter than the 8-byte ts header");
        let mut count_only = 0u64.to_le_bytes().to_vec(); // ts
        count_only.extend_from_slice(&99u32.to_le_bytes()); // count=99, no data
        assert!(unpack_gallery(&count_only).is_err(), "count claims photos with no data");
        let mut past = 0u64.to_le_bytes().to_vec(); // ts
        past.extend_from_slice(&1u32.to_le_bytes()); // count=1
        past.extend_from_slice(&5u32.to_le_bytes()); // len=5
        past.push(1); // but only 1 byte follows
        assert!(unpack_gallery(&past).is_err(), "image length past buffer");
        let mut trailing = pack_gallery(0, &[vec![1u8, 2]]);
        trailing.push(0xff); // extra byte after a valid pack
        assert!(unpack_gallery(&trailing).is_err(), "trailing bytes rejected");
    }

    #[test]
    fn post_image_reassembles_and_carries_its_post_id() {
        let post_id = [7u8; 16];
        let data: Vec<u8> = (0..3000u32).map(|i| (i * 31 + 5) as u8).collect();
        let (m, ch) = chunk_post_image(post_id, &data).unwrap();
        assert!(ch.len() >= 3, "expected >1 chunk");
        assert_eq!(encode(&m)[0], 20, "PostImageManifest is variant 20");
        assert_eq!(encode(&ch[0])[0], 11, "post-image chunks reuse AvatarChunk (variant 11)");
        let mut r = Reassembler::new();
        match feed_all(&mut r, m, ch).expect("post image assembled") {
            Assembled::PostImage { post_id: got, bytes } => {
                assert_eq!(got, post_id, "post_id survives reassembly");
                assert_eq!(bytes, data, "byte-for-byte");
            }
            other => panic!("expected a post image, got {other:?}"),
        }
        assert_eq!(r.pending(), 0, "transfer cleared after assembly");
    }

    #[test]
    fn absurd_post_image_manifest_rejected_before_alloc() {
        let mut r = Reassembler::new();
        let m = Content::PostImageManifest { post_id: [1; 16], id: [2; 16], size: u32::MAX, chunks: u32::MAX, hash: [0; 32] };
        assert!(r.offer(m, 0).is_err(), "absurd post-image manifest rejected");
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn absurd_avatar_manifest_rejected_before_alloc() {
        let mut r = Reassembler::new();
        let m = Content::AvatarManifest { id: [2; 16], size: u32::MAX, chunks: u32::MAX, hash: [0; 32] };
        assert!(r.offer(m, 0).is_err(), "absurd avatar manifest rejected");
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn oversize_avatar_rejected_at_source() {
        assert!(chunk_avatar(&vec![0u8; MAX_AVATAR_BYTES + 1]).is_err(), "over-cap avatar rejected");
        assert!(chunk_avatar(b"").is_err(), "empty avatar rejected");
    }

    #[test]
    fn corrupted_chunk_is_detected_not_silently_accepted() {
        let data: Vec<u8> = (0..2000u32).map(|i| i as u8).collect();
        let (m, mut ch) = chunk_file("f.bin", &data).unwrap();
        // Портим байт в первом чанке.
        if let Content::FileChunk { data, .. } = &mut ch[0] {
            data[0] ^= 0xFF;
        }
        let mut r = Reassembler::new();
        r.offer(m, 0).unwrap();
        let mut err = None;
        for c in ch {
            if let Err(e) = r.offer(c, 0) {
                err = Some(e);
            }
        }
        assert!(err.is_some(), "a corrupted chunk must be DETECTED (hash mismatch)");
    }

    #[test]
    fn missing_chunk_never_completes() {
        let data: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let (m, ch) = chunk_file("f.bin", &data).unwrap();
        let mut r = Reassembler::new();
        r.offer(m, 0).unwrap();
        // Подаём все, КРОМЕ последнего.
        let n = ch.len();
        for c in ch.into_iter().take(n - 1) {
            assert_eq!(r.offer(c, 0).unwrap(), None, "an incomplete transfer does not complete");
        }
        assert_eq!(r.pending(), 1, "the transfer stays incomplete");
    }

    #[test]
    fn absurd_manifest_rejected_before_alloc() {
        let mut r = Reassembler::new();
        let m = Content::FileManifest {
            id: [1; 16],
            name: "x".into(),
            size: u64::MAX,
            chunks: u32::MAX,
            hash: [0; 32],
        };
        assert!(r.offer(m, 0).is_err(), "an absurd manifest is refused");
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn oversize_file_and_long_name_rejected_at_chunk() {
        assert!(chunk_file("ok.bin", &vec![0u8; (MAX_FILE_SIZE + 1) as usize]).is_err());
        let long = "n".repeat(MAX_FILENAME + 1);
        assert!(chunk_file(&long, b"hi").is_err());
    }

    #[test]
    fn empty_file_rejected_at_source() {
        // Иначе манифест chunks=0 → получатель отвергает, а отправитель «успех».
        assert!(chunk_file("empty.bin", b"").is_err(), "an empty file is refused at the source");
    }

    #[test]
    fn text_content_passes_through_reassembler() {
        let mut r = Reassembler::new();
        assert_eq!(r.offer(Content::Text(b"hi".to_vec()), 0).unwrap(), None);
    }

    #[test]
    fn expiring_text_roundtrips_and_reassembler_ignores_it() {
        // Новый вариант кодируется/декодируется как есть.
        let c = Content::TextExpiring { text: b"self-destruct".to_vec(), expire_at: 1_700_000_030 };
        let back = decode(&encode(&c)).unwrap();
        assert_eq!(back, c);
        // Не файл → собиратель пропускает.
        let mut r = Reassembler::new();
        assert_eq!(r.offer(c, 0).unwrap(), None);
    }

    #[test]
    fn stamped_and_tombstone_roundtrip_and_are_not_files() {
        let a = Content::TextStamped { text: b"hi".to_vec(), ts: 424_242 };
        assert_eq!(decode(&encode(&a)).unwrap(), a);
        let b = Content::DeleteForEveryone { ts: 424_242, text: b"hi".to_vec() };
        assert_eq!(decode(&encode(&b)).unwrap(), b);
        let mut r = Reassembler::new();
        assert_eq!(r.offer(a, 0).unwrap(), None);
        assert_eq!(r.offer(b, 0).unwrap(), None);
    }

    #[test]
    fn adding_variant_kept_positional_indices_for_old_variants() {
        // Дискриминирующий против перестановки вариантов enum: postcard кодирует
        // вариант ПОЗИЦИОННЫМ индексом. Text должен остаться индексом 0 — первый
        // байт закодированного `Text` = 0 (иначе старые сообщения раскодируются
        // как чужой вариант).
        assert_eq!(encode(&Content::Text(b"x".to_vec()))[0], 0, "Text is variant 0");
        // И Text по-прежнему декодируется в Text, не в TextExpiring.
        assert!(matches!(decode(&encode(&Content::Text(b"x".to_vec()))).unwrap(), Content::Text(_)));
    }

    #[test]
    fn reaction_roundtrips_and_is_not_a_file() {
        let c = Content::Reaction { msg_id: [7u8; 16], emoji: "👍".into(), add: true };
        assert_eq!(decode(&encode(&c)).unwrap(), c);
        // Не файл → собиратель пропускает.
        let mut r = Reassembler::new();
        assert_eq!(r.offer(c, 0).unwrap(), None);
    }

    #[test]
    fn reaction_variant_appended_last_keeps_old_indices() {
        // Дискриминирующий против перестановки: Reaction — ПОСЛЕДНИЙ вариант (индекс
        // 6, после DeleteForEveryone=5). Text по-прежнему 0, DFE по-прежнему 5.
        assert_eq!(encode(&Content::Text(b"x".to_vec()))[0], 0, "Text is variant 0");
        assert_eq!(encode(&Content::DeleteForEveryone { ts: 1, text: vec![] })[0], 5, "DFE — 5");
        assert_eq!(
            encode(&Content::Reaction { msg_id: [0; 16], emoji: "x".into(), add: true })[0],
            6,
            "Reaction is variant 6 (last)"
        );
    }

    #[test]
    fn text_reply_roundtrips_is_not_a_file_and_is_variant_7() {
        let c = Content::TextReply { text: b"re".to_vec(), ts: 9, reply_to: [4u8; 16] };
        assert_eq!(decode(&encode(&c)).unwrap(), c);
        assert_eq!(encode(&c)[0], 7, "TextReply is variant 7 (after Reaction=6)");
        let mut r = Reassembler::new();
        assert_eq!(r.offer(c, 0).unwrap(), None, "a reply is not a file");
    }

    #[test]
    fn edit_message_roundtrips_is_not_a_file_and_is_variant_8() {
        let c = Content::EditMessage { target_msg_id: [3u8; 16], new_text: b"fixed".to_vec(), edit_ts: 5 };
        assert_eq!(decode(&encode(&c)).unwrap(), c);
        assert_eq!(encode(&c)[0], 8, "EditMessage is variant 8 (after TextReply=7)");
        let mut r = Reassembler::new();
        assert_eq!(r.offer(c, 0).unwrap(), None, "an edit is not a file");
    }

    #[test]
    fn profile_roundtrips_is_not_a_file_and_is_variant_9() {
        let c = Content::Profile { name: "Alice".into(), bio: "likes cryptography".into() };
        assert_eq!(decode(&encode(&c)).unwrap(), c);
        assert_eq!(encode(&c)[0], 9, "Profile is variant 9 (after EditMessage=8)");
        let mut r = Reassembler::new();
        assert_eq!(r.offer(c, 0).unwrap(), None, "a profile is not a file");
    }

    #[test]
    fn publication_roundtrips_is_not_a_file_and_is_variant_14() {
        let c = Content::Publication { id: [7u8; 16], text: "shipped a thing".into(), ts: 1234 };
        assert_eq!(decode(&encode(&c)).unwrap(), c);
        assert_eq!(encode(&c)[0], 14, "Publication is variant 14 (appended after RouteOffer=13)");
        let mut r = Reassembler::new();
        assert_eq!(r.offer(c, 0).unwrap(), None, "a publication is not a file");
    }

    #[test]
    fn story_and_retraction_round_trip_at_their_variant_indices() {
        let s = Content::Story { id: [3u8; 16], text: "24h".into(), ts: 10, expire_at: 20 };
        assert_eq!(decode(&encode(&s)).unwrap(), s);
        assert_eq!(encode(&s)[0], 15, "Story is variant 15 (after Publication=14)");
        let r = Content::RetractPublication { id: [4u8; 16] };
        assert_eq!(decode(&encode(&r)).unwrap(), r);
        assert_eq!(encode(&r)[0], 16, "RetractPublication is variant 16 (after Story=15)");
        let mut re = Reassembler::new();
        assert_eq!(re.offer(s, 0).unwrap(), None, "a story is not a file");
        assert_eq!(re.offer(r, 0).unwrap(), None, "a retraction is not a file");
    }

    #[test]
    fn join_request_and_accept_round_trip_at_their_variant_indices() {
        let req = Content::JoinRequest;
        assert_eq!(decode(&encode(&req)).unwrap(), req);
        assert_eq!(encode(&req)[0], 17, "JoinRequest is variant 17 (after RetractPublication=16)");
        let acc = Content::JoinAccept { is_channel: true };
        assert_eq!(decode(&encode(&acc)).unwrap(), acc);
        assert_eq!(encode(&acc)[0], 18, "JoinAccept is variant 18 (after JoinRequest=17)");
        let mig = Content::ChannelMigrate { new_ik: [5u8; 32] };
        assert_eq!(decode(&encode(&mig)).unwrap(), mig);
        assert_eq!(encode(&mig)[0], 19, "ChannelMigrate is variant 19 (after JoinAccept=18)");
    }

    #[test]
    fn msg_id_is_deterministic_and_sensitive_to_every_input() {
        let a = [1u8; 32];
        let base = msg_id(&a, 100, b"hello");
        // Детерминизм: те же входы → тот же id (обе стороны сойдутся).
        assert_eq!(base, msg_id(&a, 100, b"hello"));
        // Чувствительность к КАЖДОМУ входу (иначе реакция сядет не на то сообщение):
        assert_ne!(base, msg_id(&[2u8; 32], 100, b"hello"), "the author changes the id");
        assert_ne!(base, msg_id(&a, 101, b"hello"), "the timestamp changes the id");
        assert_ne!(base, msg_id(&a, 100, b"hell0"), "the text changes the id (breaks a same-timestamp collision)");
    }

    #[test]
    fn msg_id_disambiguates_same_second_different_text() {
        // Два сообщения одного автора в ОДНУ секунду, но разный текст → разные id.
        // (Без текста в хэше реакция была бы неоднозначна — это ловит neuter-тест
        // в контроллере, здесь фиксируем сам примитив.)
        let a = [5u8; 32];
        assert_ne!(msg_id(&a, 424_242, b"first"), msg_id(&a, 424_242, b"second"));
    }

    #[test]
    fn concurrent_transfer_limit_enforced() {
        let mut r = Reassembler::new();
        for i in 0..MAX_CONCURRENT_TRANSFERS {
            let m = Content::FileManifest {
                id: [i as u8; 16],
                name: "f".into(),
                size: 10,
                chunks: 1,
                hash: [0; 32],
            };
            r.offer(m, 0).unwrap();
        }
        let over = Content::FileManifest {
            id: [0xFF; 16],
            name: "f".into(),
            size: 10,
            chunks: 1,
            hash: [0; 32],
        };
        assert!(r.offer(over, 0).is_err(), "beyond the concurrent-transfer limit");
    }

    #[test]
    fn stale_partials_are_reaped_so_a_new_transfer_is_not_blocked_forever() {
        // A failed/aborted send_file leaves a half-assembled transfer (manifest, no completing
        // chunks). MAX_CONCURRENT of them must NOT pin every slot until the process restarts:
        // once they are stale, a new manifest reaps them and starts. Neuter the reap (drop the
        // `reap_stale` call in `start_transfer`) → the "past the timeout" assert reddens.
        let mut r = Reassembler::new();
        let t0 = 1_000u64;
        let manifest = |id: u8| Content::FileManifest {
            id: [id; 16], name: "x".into(), size: 10, chunks: 2, hash: [0; 32],
        };
        for i in 0..MAX_CONCURRENT_TRANSFERS as u8 {
            assert_eq!(r.offer(manifest(i), t0).unwrap(), None);
        }
        assert_eq!(r.pending(), MAX_CONCURRENT_TRANSFERS);

        // Within the window: all slots taken, a new transfer is refused.
        assert!(r.offer(manifest(99), t0 + 10).is_err(), "within the window the slots are full");

        // Past the stale timeout: the abandoned ones are reaped and the new one starts.
        let later = t0 + STALE_PARTIAL_SECS + 1;
        assert_eq!(r.offer(manifest(99), later).unwrap(), None, "a reaped slot admits a new transfer");
        assert!(r.pending() <= MAX_CONCURRENT_TRANSFERS, "the set stays bounded after reaping");
    }

    #[test]
    fn an_actively_arriving_transfer_is_not_reaped() {
        // last_seen updates on every chunk, so a slow-but-live transfer survives the window.
        let mut r = Reassembler::new();
        let t0 = 1_000u64;
        let id = [7u8; 16];
        r.offer(Content::FileManifest { id, name: "big".into(), size: 2048, chunks: 2, hash: [0; 32] }, t0)
            .unwrap();
        // A chunk arrives near the end of the window — refreshes last_seen.
        r.offer(Content::FileChunk { id, index: 0, data: vec![1u8; 1024] }, t0 + STALE_PARTIAL_SECS - 5)
            .unwrap();
        // Well past t0 but only 10s since the last chunk: a reap must NOT drop it.
        assert_eq!(r.reap_stale(t0 + STALE_PARTIAL_SECS + 5), 0, "an active transfer must survive");
        assert_eq!(r.pending(), 1);
    }

    /// Bug E — an inline transfer must survive the process, because its carrier messages are
    /// already ACKed and the relay may have dropped them.
    ///
    /// Chunks used to be reassembled ONLY in RAM, so a crash mid-transfer lost the file with no
    /// record and no retry: the sender saw "delivered", the receiver had nothing to show or
    /// resume. Discriminating: the export/restore round-trip happens BETWEEN chunks, and the file
    /// must still assemble with byte-identical contents afterwards.
    #[test]
    fn an_inline_transfer_survives_a_restart_between_chunks() {
        let payload: Vec<u8> = (0..5_000u32).map(|i| (i % 251) as u8).collect();
        let (manifest, chunks) = chunk_file("report.pdf", &payload).unwrap();
        assert!(chunks.len() >= 2, "the payload must span several chunks for this to mean anything");

        let mut re = Reassembler::new();
        assert!(re.offer(manifest, 100).unwrap().is_none());
        assert!(re.offer(chunks[0].clone(), 101).unwrap().is_none());
        assert_eq!(re.in_flight(), 1, "a transfer is mid-flight");

        // The process stops here and comes back.
        let saved = re.export().expect("in-flight state is serializable");
        let mut re = Reassembler::restore(&saved).expect("and restorable");
        assert_eq!(re.in_flight(), 1, "the transfer came back");

        let mut done = None;
        for c in chunks.iter().skip(1) {
            if let Some(a) = re.offer(c.clone(), 102).unwrap() {
                done = Some(a);
            }
        }
        match done {
            Some(Assembled::File(f)) => {
                assert_eq!(f.name, "report.pdf");
                assert_eq!(f.bytes, payload, "the file must be byte-identical across the restart");
            }
            other => panic!("the transfer did not complete after the restart: {other:?}"),
        }
    }

    /// A4-9 — the reassembler's INVARIANTS, not just its happy path.
    ///
    /// Each of these is a state a hostile or buggy sender can attempt, and each must be REFUSED
    /// rather than absorbed: an orphan chunk with no manifest, a chunk index beyond the declared
    /// count, and a completed transfer whose bytes do not match the declared hash. Absorbing any
    /// of them would let a peer steer the reassembler into a shape the rest of the code assumes
    /// cannot happen.
    #[test]
    fn the_reassembler_refuses_orphan_out_of_range_and_mismatched_transfers() {
        let payload: Vec<u8> = (0..3_000u32).map(|i| (i % 251) as u8).collect();
        let (manifest, chunks) = chunk_file("doc.bin", &payload).unwrap();

        // 1. A chunk with no manifest is an orphan — nothing says how many to expect or what the
        //    result should hash to, so accepting it would allocate on a stranger's say-so.
        let mut re = Reassembler::new();
        assert!(re.offer(chunks[0].clone(), 10).is_err(), "an orphan chunk must be refused");
        assert_eq!(re.in_flight(), 0, "and must not create a transfer slot");

        // 2. An index beyond the declared count.
        let mut re = Reassembler::new();
        assert!(re.offer(manifest.clone(), 10).unwrap().is_none());
        let mut far = chunks[0].clone();
        if let Content::FileChunk { index, .. } = &mut far {
            *index = u32::MAX;
        }
        assert!(re.offer(far, 11).is_err(), "an out-of-range chunk index must be refused");

        // 3. A complete transfer whose content does not match the declared hash: the end-to-end
        //    backstop must fire instead of handing back a corrupted file.
        let mut re = Reassembler::new();
        assert!(re.offer(manifest, 10).unwrap().is_none());
        let mut bad = chunks.clone();
        if let Content::FileChunk { data, .. } = &mut bad[0] {
            data[0] ^= 0xFF;
        }
        let mut outcome = Ok(None);
        for c in bad {
            outcome = re.offer(c, 12);
            if outcome.is_err() {
                break;
            }
        }
        assert!(outcome.is_err(), "a hash mismatch must be reported, not silently assembled");
    }

    fn chunk_data_len(c: &Content) -> usize {
        match c {
            Content::FileChunk { data, .. } | Content::AvatarChunk { data, .. } => data.len(),
            other => panic!("expected a chunk, got {other:?}"),
        }
    }

    #[test]
    fn bytes_in_flight_counts_only_arrived_chunks_not_the_declared_final_size() {
        // A transfer that is only PARTIALLY arrived must weigh only what actually arrived — the
        // whole point of the accounting is to bound REAL RAM, not the sender's promised total.
        let payload: Vec<u8> = (0..3_000u32).map(|i| (i % 251) as u8).collect(); // 3 chunks of ~1024
        let (manifest, chunks) = chunk_file("f.bin", &payload).unwrap();
        let mut r = Reassembler::new();
        assert_eq!(r.bytes_in_flight(), 0, "nothing in flight yet");
        r.offer(manifest, 0).unwrap();
        assert_eq!(r.bytes_in_flight(), 0, "a bare manifest has received no bytes yet");
        r.offer(chunks[0].clone(), 0).unwrap();
        assert_eq!(r.bytes_in_flight(), chunk_data_len(&chunks[0]), "one chunk's worth only");
        r.offer(chunks[1].clone(), 0).unwrap();
        assert_eq!(
            r.bytes_in_flight(),
            chunk_data_len(&chunks[0]) + chunk_data_len(&chunks[1]),
            "two chunks' worth, not the manifest's declared final size"
        );
    }

    #[test]
    fn has_transfer_and_manifest_transfer_id_agree_on_what_is_tracked() {
        let (manifest, chunks) = chunk_file("f.bin", b"hello world").unwrap();
        let id = manifest_transfer_id(&manifest).expect("a manifest carries an id");
        assert_eq!(manifest_transfer_id(&chunks[0]), None, "a chunk starts nothing new");
        let mut r = Reassembler::new();
        assert!(!r.has_transfer(id), "not tracked before the manifest arrives");
        r.offer(manifest, 0).unwrap();
        assert!(r.has_transfer(id), "tracked once the manifest is admitted");
    }
}

/// **Every `Content` variant still fits one padded envelope** (PRIV-1).
///
/// `pad::MAX_PAYLOAD` is derived from the admission ceiling, so it is a fact about the wire rather
/// than a number anyone gets to choose. That makes this the check that matters: if a variant's
/// largest legal instance exceeds it, the feature is broken — and broken in the worst way, because
/// `pad` refuses at the SENDER with a message, while before padding an oversize payload was dropped
/// by admission as `DropNoReply` and reached the user as "sent" followed by silence.
///
/// So this is not a padding test. It is the test that says which product limits the wire permits.
#[cfg(test)]
mod every_content_fits_one_envelope {
    use super::*;
    use karst_client_core::pad;

    /// Build the LARGEST legal instance of each variant, per this module's own limits.
    fn largest_of_each() -> Vec<(&'static str, Content)> {
        let text = vec![b'x'; MAX_TEXT_BYTES];
        let name = "n".repeat(MAX_FILENAME);
        vec![
            ("Text", Content::Text(text.clone())),
            ("TextExpiring", Content::TextExpiring { text: text.clone(), expire_at: u64::MAX }),
            ("TextStamped", Content::TextStamped { text: text.clone(), ts: u64::MAX }),
            ("TextReply", Content::TextReply { text: text.clone(), ts: u64::MAX, reply_to: [7u8; 16] }),
            ("DeleteForEveryone", Content::DeleteForEveryone { ts: u64::MAX, text: text.clone() }),
            (
                "EditMessage",
                Content::EditMessage {
                    target_msg_id: [7u8; 16],
                    new_text: text.clone(),
                    edit_ts: u64::MAX,
                },
            ),
            (
                "FileChunk",
                Content::FileChunk { id: [7u8; 16], index: u32::MAX, data: vec![9u8; MAX_CHUNK_PAYLOAD] },
            ),
            (
                "AvatarChunk",
                Content::AvatarChunk { id: [7u8; 16], index: u32::MAX, data: vec![9u8; MAX_CHUNK_PAYLOAD] },
            ),
            (
                "FileManifest",
                Content::FileManifest {
                    id: [7u8; 16],
                    name: name.clone(),
                    size: u64::MAX,
                    chunks: u32::MAX,
                    hash: [8u8; 32],
                },
            ),
            (
                "Profile",
                Content::Profile {
                    name: "n".repeat(MAX_PROFILE_NAME),
                    bio: "b".repeat(MAX_PROFILE_BIO),
                },
            ),
            ("Reaction", Content::Reaction { msg_id: [7u8; 16], emoji: "e".repeat(MAX_EMOJI_BYTES), add: true }),
            (
                "FileRef",
                Content::FileRef {
                    blob_id: [1u8; 32],
                    key: [2u8; 32],
                    hash: [3u8; 32],
                    name,
                    size: u64::MAX,
                    chunks: u32::MAX,
                },
            ),
            (
                "Publication",
                Content::Publication {
                    id: [7u8; 16],
                    text: "p".repeat(MAX_POST_TEXT),
                    ts: u64::MAX,
                },
            ),
        ]
    }

    #[test]
    fn the_largest_legal_instance_of_every_variant_can_be_padded() {
        let mut worst: (&str, usize) = ("<none>", 0);
        for (name, c) in largest_of_each() {
            let encoded = postcard::to_stdvec(&c).expect("Content serializes");
            if encoded.len() > worst.1 {
                worst = (name, encoded.len());
            }
            pad::pad(&encoded).unwrap_or_else(|e| {
                panic!(
                    "the largest legal `{name}` is {} bytes and does NOT fit one E2E envelope: {e}\n\
                     This is a product limit meeting a wire limit. Either lower this module's cap \
                     for that variant, or send it over the blob path — do NOT raise \
                     pad::PADDED_LEN, which is derived from the admission ceiling and has no \
                     headroom left (see pad's ceiling test).",
                    encoded.len()
                )
            });
        }
        // Reported so the margin is visible in the test log rather than rediscovered by whoever
        // adds the next variant and wonders how much room is left.
        assert!(
            worst.1 <= pad::MAX_PAYLOAD,
            "largest variant `{}` is {} bytes vs a {} byte envelope",
            worst.0,
            worst.1,
            pad::MAX_PAYLOAD
        );
        println!(
            "largest legal Content: {} at {} bytes; envelope carries {} (margin {})",
            worst.0,
            worst.1,
            pad::MAX_PAYLOAD,
            pad::MAX_PAYLOAD - worst.1
        );
    }

    /// `RouteOffer` carries a free-form `routes` string with no cap in this module, so it is the one
    /// variant whose size the type system does not bound. Pinned separately: the failure it would
    /// produce is a route offer that silently never arrives.
    #[test]
    fn a_route_offer_long_enough_to_overflow_is_refused_by_the_sender() {
        let huge = Content::RouteOffer { relay_noise_pub: [1u8; 32], routes: "r".repeat(4096) };
        let encoded = postcard::to_stdvec(&huge).expect("serializes");
        assert!(
            pad::pad(&encoded).is_err(),
            "an over-long RouteOffer must be refused where the user can be told, not dropped by \
             admission with no reply"
        );
    }
}

/// **A control message is not distinguishable from a chat message by size** (PRIV-1 → PRIV-8).
///
/// `PostsRequest` is what a client sends when someone opens a profile they do not subscribe to. It
/// carries no payload at all — a bare enum variant, a couple of bytes — while an ordinary message
/// carries text. Before every ratchet plaintext was padded to one block, that difference was on the
/// wire, and a relay watching a conversation could plausibly have picked profile views out of it by
/// size alone.
///
/// Padding removed that as a side effect rather than as a goal, which is exactly the kind of
/// property that quietly comes back: raise a limit, add a variant that skips the pad path, and the
/// small control messages are legible again with nothing failing. So it is asserted here, next to
/// the variants, rather than left to be inferred from `pad`'s own tests.
///
/// **What this does NOT close.** The AUTHOR still learns who viewed their profile — they receive the
/// request and answer it. That is inherent to a live pull and is peer-visible, not relay-visible;
/// removing it needs published posts to become fetchable batches instead of a per-view question
/// (#263). And viewing a STRANGER's profile still requires establishing a session first, which is a
/// first contact and is visible as one.
#[cfg(test)]
mod control_messages_are_the_same_size_as_chat {
    use super::*;
    use karst_client_core::pad;

    /// DISCRIMINATING: make `pad::pad` return its input unchanged and this reports two very
    /// different lengths — the state in which a relay can pick control traffic out by size.
    #[test]
    fn a_profile_view_and_a_full_length_message_pad_to_one_size() {
        let view = pad::pad(&encode(&Content::PostsRequest)).expect("fits");
        let chat =
            pad::pad(&encode(&Content::Text(vec![b'x'; MAX_TEXT_BYTES]))).expect("fits");
        assert_eq!(
            view.len(),
            chat.len(),
            "a profile-view request is {} bytes on the wire and a full message is {} — a relay \
             watching one conversation can then separate 'they opened a profile' from 'they said \
             something', which is a behavioural read it should not get for free",
            view.len(),
            chat.len()
        );
    }

    /// The same for every OTHER control variant, so the property covers the class rather than the
    /// one example that prompted it.
    #[test]
    fn every_small_control_message_pads_to_the_same_size() {
        let sizes: Vec<usize> = [
            Content::PostsRequest,
            Content::JoinRequest,
            Content::Reaction { msg_id: [1u8; 16], emoji: "x".into(), add: true },
            Content::DeleteForEveryone { ts: 1, text: b"a".to_vec() },
        ]
        .into_iter()
        .map(|c| pad::pad(&encode(&c)).expect("fits").len())
        .collect();
        assert!(
            sizes.windows(2).all(|w| w[0] == w[1]),
            "control messages have varying wire sizes {sizes:?}; each distinct size is a category \
             a relay can count"
        );
    }
}
