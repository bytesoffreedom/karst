//! Контроллер GUI — чистое состояние приложения + действия, БЕЗ egui и БЕЗ сети.
//! Полностью тестируем (drive действиями/событиями, проверяй состояние). Рендер
//! (egui) и сеть (worker) — тонкие слои вокруг; вся логика раскладки/ввода здесь.
//!
//! Разделение позволяет верифицировать GUI-логику end-to-end в headless-среде,
//! где реальное окно не запустить.

use std::collections::HashMap;

use client::store::HistoryRecord;

/// Контакт: имя + долговременный §2.1-IK + флаг сверки. IK вводится ВРУЧНУЮ
/// (вставка hex) — это и есть OOB-канал доверия. `verified` — пользователь
/// подтвердил, что сверил код безопасности (сохраняется на диск; отличает
/// сверенного собеседника от авто-добавленного «неизв.»). Никакого «discovery
/// контактов у relay» (это вернуло бы IK-swap MITM — см. STATUS §12).
#[derive(Clone, PartialEq, Eq)]
pub struct Contact {
    pub name: String,
    pub ik: [u8; 32],
    pub verified: bool,
}

/// Аккаунт в переключателе (как в Telegram): id (подкаталог), метка, §2.1-адрес.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountInfo {
    pub id: String,
    pub label: String,
    pub ik: [u8; 32],
}

/// Статус доставки исходящего сообщения (для входящих — всегда `Sent`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MsgStatus {
    /// Отправляется — worker ещё не отчитался.
    Sending,
    /// Успешно ушло на relay (или входящее/из истории).
    Sent,
    /// Отправка провалилась (не молча «доставлено» — честная пометка).
    Failed,
}

/// Входящее исчезающее сообщение (worker → UI): текст + абсолютное `expire_at`.
#[derive(Clone)]
pub struct ExpiringIn {
    pub sender: [u8; 32],
    pub text: Vec<u8>,
    pub expire_at: u64,
}

/// Совпадение поиска по переписке (локально, по расшифрованным сообщениям в памяти).
#[derive(Clone, PartialEq, Eq)]
pub struct SearchHit {
    pub ik: [u8; 32],
    pub ts: u64,
    pub from_me: bool,
    pub text: String,
}

/// Вид сообщения. Отличает текст от файловой строки — нужно, чтобы пересылка
/// («переслать») работала только с текстом: у файла `text` — это витрина
/// («📎 имя · сохранён: путь»), а не пересылаемое содержимое. Файл в этом срезе
/// не пересылается (отдельный след — нужен переиспользуемый путь к байтам).
#[derive(Clone, PartialEq, Eq)]
pub enum MsgKind {
    Text,
    /// Файловая строка (манифест собран/отправлен). `file_id` — handle of the SEALED
    /// copy in the vault (received files only; `None` for ones we sent). Export needs
    /// it: the plaintext exists only where the user asks for it.
    File { name: String, file_id: Option<String> },
}

/// Сообщение в чате (in-memory — исчезает при закрытии; см. границу истории).
/// `id` связывает оптимистичный пузырь с результатом отправки (`Evt::SendResult`);
/// `0` = не отслеживается (входящие, восстановленные из истории).
#[derive(Clone)]
pub struct ChatMsg {
    pub from_me: bool,
    pub text: String,
    pub id: u64,
    pub status: MsgStatus,
    pub kind: MsgKind,
    /// Исчезающее сообщение: абсолютное unix-время (сек), когда его надо стереть из
    /// памяти. `None` — обычное сообщение. Исчезающие НИКОГДА не пишутся на диск.
    pub expire_at: Option<u64>,
    /// Unix-время (сек) сообщения — для показа и как ЧАСТЬ идентификатора при
    /// удалении/цитировании. КРИТИЧНО: для персистируемых сообщений `ts` в памяти
    /// ДОЛЖЕН совпадать с `ts` записи на диске (иначе delete по (ts,from_me,text) не
    /// найдёт запись). Исходящие штампует контроллер и передаёт в Cmd; входящие
    /// echo'ит worker своими часами. `0` — не отслеживается (оптимистичный/исчез.).
    pub ts: u64,
    /// Large-file transfer progress: `Some((done, total))` in bytes while the
    /// off-loop blob upload/download runs (`Evt::FileProgress`). `None` = not a
    /// transfer in flight (the terminal `SendResult`/`FileReceived` resets it to
    /// `None`). The UI draws the bar + cancel button only while it is `Some`.
    pub progress: Option<(u64, u64)>,
}

impl ChatMsg {
    /// Входящее / восстановленное ТЕКСТовое — уже «доставлено», без корреляции.
    fn incoming(from_me: bool, text: String, ts: u64) -> Self {
        ChatMsg {
            from_me,
            text,
            id: 0,
            status: MsgStatus::Sent,
            kind: MsgKind::Text,
            expire_at: None,
            ts,
            progress: None,
        }
    }
}

/// Черновик ответа: на какое сообщение отвечаем (`to` — его `msg_id`) + короткая
/// цитата для баннера композитора. Живёт, пока пользователь не отправит/не отменит.
#[derive(Clone)]
pub struct ReplyDraft {
    pub to: [u8; 16],
    pub preview: String,
}

/// Короткая одна-строчная цитата (первые ~60 символов, схлопнутые переносы).
fn snippet(text: &str) -> String {
    const N: usize = 60;
    let one_line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() > N {
        one_line.chars().take(N).collect::<String>() + "…"
    } else {
        one_line
    }
}

/// Входящее текстовое (worker → UI): текст + `ts` (часы worker'а, ТОТ ЖЕ, что ушёл
/// в историю на диск) для показа и идентификации при удалении.
#[derive(Clone)]
pub struct IncomingText {
    pub sender: [u8; 32],
    pub plaintext: Vec<u8>,
    pub ts: u64,
}

/// Команда UI → worker (сеть/Store в фоне).
#[derive(Clone)]
pub enum Cmd {
    /// Разблокировать СУЩЕСТВУЮЩИЙ аккаунт паролем + настроить relay; worker
    /// публикует bundle. `socks5` пуст = прямое соединение; иначе адрес локального
    /// SOCKS-порта PT (Tor/obfs4) — маршрут блокоустойчивости.
    Unlock {
        passphrase: String,
        relay_addr: String,
        relay_id: String,
        socks5: String,
        /// Extra failover routes (see `App::in_routes`); empty = a single route.
        routes: String,
        /// SECONDARY relays to multi-home to, one `addr relay-id` per line (see
        /// `App::in_extra_relays`). Empty = keep whatever is already saved (like `relay_id`).
        extra_relays: String,
    },
    /// Завести аккаунт из фразы (создание ИЛИ восстановление): worker персистит
    /// корень (энтропию фразы) под паролем, затем как Unlock. Фраза уже
    /// сгенерирована/введена и сверена в UI; worker её ещё раз валидирует.
    Provision {
        passphrase: String,
        phrase: String,
        relay_addr: String,
        relay_id: String,
        socks5: String,
        /// Extra failover routes (see `App::in_routes`); empty = a single route.
        routes: String,
        /// SECONDARY relays to multi-home to (see `App::in_extra_relays`).
        extra_relays: String,
    },
    /// Отправить текст по §2.1-сессии (worker вызовет `send_text`). `id` — для
    /// корреляции с `Evt::SendResult`. `ts` — штамп времени контроллера: worker
    /// пишет ЕГО в историю (не свои часы), чтобы память и диск совпали по ts.
    Send { to_ik: [u8; 32], text: String, id: u64, ts: u64 },
    /// Отправить текст-ОТВЕТ на сообщение `reply_to` (`msg_id` цели). Как `Send`,
    /// но worker шлёт `TextReply` и пишет `set_reply(msg_id(этого), reply_to)`.
    SendReply { to_ik: [u8; 32], text: String, id: u64, ts: u64, reply_to: [u8; 16] },
    /// Отправить ИСЧЕЗАЮЩИЙ текст: worker вызовет `send_text_expiring` (проставит
    /// абсолютный `expire_at = now + ttl_secs`). В историю НЕ пишется.
    SendExpiring { to_ik: [u8; 32], text: String, id: u64, ttl_secs: u32 },
    /// Отправить файл по пути (worker прочитает, чанкует, `send_file`). `ts` —
    /// штамп контроллера для записи в историю (совпадение память↔диск).
    SendFile { to_ik: [u8; 32], path: String, id: u64, ts: u64 },
    /// Добавить НОВЫЙ аккаунт к уже разблокированному vault (создание/восстановление
    /// без ввода пароля — переиспользуется ключ устройства), затем переключиться на
    /// него. `label` пуст → автометка «Аккаунт N».
    AddAccount { phrase: String, label: String },
    /// Переключиться на аккаунт `id` (в пределах разблокированного vault — без
    /// Argon2, мгновенно).
    SwitchAccount { id: String },
    /// Персистить контакты КОНКРЕТНОГО аккаунта `id` (штампуется на кадре flush,
    /// пока активен ещё он). Без `id` при переключении контакты аккаунта A могли бы
    /// уехать в файл B (FIFO: Switch→B применяется раньше, чем долетит SaveContacts).
    SaveContacts { id: String, contacts: Vec<Contact> },
    /// Стереть с диска ВСЮ историю переписки с `ik` (удаление чата / очистка).
    /// Worker вызовет `rewrite_history`, оставив записи других собеседников.
    ClearChat { ik: [u8; 32] },
    /// Удалить ОДНО сообщение из истории на диске: идентификатор — (peer, ts,
    /// from_me, text), стабильного id нет (см. ts). Точные дубли уйдут вместе.
    DeleteMessage { ik: [u8; 32], ts: u64, from_me: bool, text: String },
    /// Удалить СВОЁ отправленное сообщение У ВСЕХ: стереть локальную копию
    /// (from_me=true) и послать получателю tombstone (кооперативно).
    DeleteForEveryone { to_ik: [u8; 32], ts: u64, text: String },
    /// Поставить/снять реакцию `emoji` на сообщение `msg_id` в чате с `to_ik`.
    /// Worker персистит локально (автор = own_ik) и шлёт control-конверт получателю.
    React { to_ik: [u8; 32], msg_id: [u8; 16], emoji: String, add: bool },
    /// Изменить СВОЁ отправленное сообщение `target_msg_id`: overlay нового текста
    /// (история не переписывается) + кооперативная просьба получателю обновить.
    EditMessage { to_ik: [u8; 32], target_msg_id: [u8; 16], new_text: String, edit_ts: u64 },
    /// Заблокировать/разблокировать `ik` (не принимать от него входящее). Персист
    /// at-rest; worker обновляет свой enforcement-набор и эхом шлёт `Evt::Blocked`.
    SetBlocked { ik: [u8; 32], blocked: bool },
    /// Save OWN profile (name + bio) and broadcast it to contacts over E2E. The
    /// worker writes `profile.dat`, sends `Content::Profile` to each contact, and
    /// echoes `Evt::Profile` back.
    SaveProfile { name: String, bio: String },
    /// Set OUR avatar from a local file `path`: the worker bounded-decodes + re-encodes
    /// it (PNG), stores it, broadcasts the avatar to contacts, and echoes `Evt::Profile`.
    SetAvatar { path: String },
    /// Clear OUR avatar (stores `None`, echoes `Evt::Profile`). Not retro-broadcast —
    /// contacts keep the last avatar until our next explicit avatar send.
    RemoveAvatar,
    /// Cancel an in-flight large-file transfer (the ✕ button in the bubble). `id` is
    /// the optimistic/receiving bubble's id. The worker sets the cancel flag; the
    /// thread ends with `Err("cancelled")` on the next chunk boundary.
    CancelTransfer { id: u64 },
    /// INTERNAL (upload thread → worker, never from the UI): the blob is uploaded (or
    /// cancelled/failed). On ITS OWN thread the worker sends the `FileRef` over the
    /// §2.1 session (the ratchet is touched only here) and writes history.
    /// `blob = None` = the upload failed or was cancelled.
    BlobUploadDone {
        id: u64,
        to_ik: [u8; 32],
        name: String,
        size: u64,
        ts: u64,
        blob: Option<client::UploadedBlob>,
    },
    /// INTERNAL (download thread → worker): the blob was downloaded to `path` (or
    /// failed/cancelled). The worker writes the receive history and emits
    /// `FileReceived`. `path = None` = it did not succeed.
    BlobDownloadDone {
        id: u64,
        sender: [u8; 32],
        name: String,
        ts: u64,
        path: Option<String>,
    },
    /// §15: offer THIS contact the routes I use to reach the relay we share. The user
    /// picks who — never a broadcast, never automatic: handing someone your routes
    /// tells them where you connect from.
    ShareRoutes { to_ik: [u8; 32] },
    /// §15: accept routes a contact offered (explicit — see `Evt::RouteOffer`). The
    /// worker merges them into the saved config and rebuilds the path list.
    AcceptRoutes { routes: String },
    /// Decrypt a received file out of the vault to `dest` — the user's explicit act.
    /// Received files are sealed at rest; this is the only way a plaintext copy exists,
    /// and it lands exactly where the user chose.
    ExportFile { file_id: String, dest: String },
    /// Give the ACTIVE account its own network config (relay + carrier + routes) and
    /// reconnect on it. This is what turns an account from a co-tenant (another name on
    /// the same relay, linked to your other identities by IP + timing) into a real
    /// compartment: an identity WITH ITS OWN relay.
    SetNet { relay_addr: String, relay_id: String, socks5: String, routes: String },
    /// Replace the active account's SECONDARY relay list (multi-homing) with EXACTLY this
    /// set — an empty vec clears it. Unlike the login `extra_relays` field ("empty = keep
    /// saved"), this is an explicit set, so the UI can add and REMOVE. Worker persists it and
    /// rebuilds the relay set.
    SetExtraRelays { relays: Vec<(String, String)> },
    /// Опросить входящие (worker вызовет `recv_session`).
    Poll,
}

/// A status-line message from the worker. Localizable variants carry no free-form
/// detail — the UI renders them in the current language (`render_status`). `Error`
/// carries a lower-layer diagnostic (OS text, a peer error) that stays as-is: a
/// localized prefix glued to an untranslated detail reads worse than a consistent
/// English line, and diagnostics being English is a defensible, conventional line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatusMsg {
    LogInFirst,
    UnlockFirst,
    /// Bundle published on unlock — the account can now receive.
    ReadyToReceive,
    /// A file was sent; carries the file name (interpolated, not translated).
    FileSent(String),
    /// OWN profile not delivered to `n` contacts.
    ProfileNotDelivered(usize),
    /// OWN avatar not delivered to `n` contacts.
    AvatarNotDelivered(usize),
    /// A lower-layer diagnostic, shown verbatim (stays English/OS text).
    Error(String),
}

/// Событие worker → UI.
pub enum Evt {
    /// Разблокировано / переключён аккаунт; наш §2.1-IK. Контроллер СБРАСЫВАЕТ
    /// состояние чатов (контакты/сообщения/непрочитанные/выбор) — новый аккаунт
    /// начинает с чистого листа (важно при переключении).
    Unlocked { own_ik: [u8; 32] },
    /// Список аккаунтов устройства + id активного (для переключателя).
    Accounts { list: Vec<AccountInfo>, active: String },
    /// Сохранённые контакты (имена + флаг сверки) — эмитятся ДО `History`, чтобы
    /// авто-добавление «неизв.» из истории не затёрло названные/сверенные.
    Contacts(Vec<Contact>),
    /// Загруженная с диска история (навалом, при разблокировке) — заполняет чаты.
    History(Vec<HistoryRecord>),
    /// Результат отправки сообщения `id`: `ok` — ушло на relay.
    SendResult { id: u64, ok: bool },
    /// Состояние связи с relay (публикация/опрос): `true` — на связи.
    Connection(bool),
    /// Per-relay reachability for the multi-homed set, aligned to the session's relay order
    /// (index 0 = primary, 1.. = the secondaries in `ExtraRelays` order). Lets the UI show a
    /// live/blocked dot per backup, so "primary down, backup up" is visible.
    RelayHealth(Vec<bool>),
    /// Active §15 carrier for this session (direct/SOCKS5/wss), for the status bar.
    Carrier(client::Carrier),
    /// The account's SECONDARY relays (multi-homing) as `(addr, relay_id)`, for the UI to
    /// display and let the user remove. Emitted on unlock/switch and after every change.
    ExtraRelays(Vec<(String, String)>),
    /// Расшифрованные входящие ТЕКСТЫ (с атрибуцией отправителя + `ts` worker'а,
    /// совпадающим с записью в истории).
    Received(Vec<IncomingText>),
    /// Входящие ИСЧЕЗАЮЩИЕ тексты: (отправитель, текст, абсолютный `expire_at`).
    /// Мёртвые-по-прибытии (now ≥ expire_at) worker уже отфильтровал. В историю
    /// не пишутся — живут только в памяти до `expire_at`.
    ReceivedExpiring(Vec<ExpiringIn>),
    /// Большой файл НАЧАЛ скачиваться (off-loop blob): показать приёмный пузырь с баром.
    /// `id` — корреляция с `FileProgress`/`FileReceived`; `size` — байт всего.
    FileIncoming { sender: [u8; 32], name: String, size: u64, id: u64, ts: u64 },
    /// Прогресс передачи (заливки или скачивания) большого файла: байт `done`/`total`.
    /// `id` адресует пузырь. Троттлится клиентом (`BLOB_PROGRESS_STEP`).
    FileProgress { id: u64, done: u64, total: u64 },
    /// Принят ФАЙЛ, запечатан в vault под `file_id` (НЕ путь: принятые файлы шифруются
    /// at-rest, plaintext появляется только по явному экспорту). `ts` — часы worker'а
    /// (= ts записи истории). `id != 0` — завершить приёмный пузырь по id (blob);
    /// `id == 0` — inline-файл, добавить новый пузырь.
    FileReceived { sender: [u8; 32], name: String, file_id: String, ts: u64, id: u64 },
    /// Пришёл tombstone «удалить у всех» от `peer`: стереть из памяти ПРИНЯТОЕ
    /// сообщение (from_me=false) с (ts, text). На диске worker уже стёр.
    MessageDeleted { peer: [u8; 32], ts: u64, text: Vec<u8> },
    /// Полная карта реакций активного аккаунта (`msg_id → эмодзи → авторы`).
    /// Worker шлёт её при разблокировке и после каждого изменения (свой клик или
    /// входящая реакция); контроллер джойнит к сообщениям по `msg_id` при рендере.
    Meta(client::store::MetaMap),
    /// Множество заблокированных IK (при разблокировке и после каждого изменения).
    Blocked(std::collections::BTreeSet<[u8; 32]>),
    /// OWN profile (name + bio + optional avatar bytes), loaded on unlock or after a
    /// save/avatar change. Fills the profile editor buffers + own-avatar preview.
    Profile { name: String, bio: String, avatar: Option<Vec<u8>> },
    /// Cache of contacts' SELF-DECLARED profiles (`ik -> profile`). Hints layered over
    /// the local labels — they NEVER overwrite the name/`verified` in contacts.
    PeerProfiles(std::collections::BTreeMap<[u8; 32], client::store::Profile>),
    /// §15: a contact offered extra routes to the relay we share. NOT applied — the
    /// UI shows it and the user decides: trying an offered route reveals your IP to
    /// whoever runs it.
    RouteOffer { from: [u8; 32], routes: String },
    /// Инфо/ошибка для строки статуса.
    Status(StatusMsg),
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Screen {
    /// Новый профиль: выбор «создать / восстановить».
    Welcome,
    /// Возврат: ввод пароля (аккаунт уже на диске).
    Unlock,
    /// Создание, шаг 1 — показ свежей фразы (записать).
    CreateShow,
    /// Создание, шаг 2 — сверка слов + пароль + сеть.
    CreateConfirm,
    /// Восстановление — ввод фразы + пароль + сеть.
    Restore,
    /// Рабочий экран.
    Ready,
}

/// Всё состояние GUI. Поля публичны — view читает их напрямую.
pub struct App {
    pub screen: Screen,
    pub own_ik: Option<[u8; 32]>,
    pub contacts: Vec<Contact>,
    /// Выбранный чат — по **IK**, не по индексу (удаление/переупорядочивание
    /// контактов иначе указывало бы на другого человека).
    pub selected: Option<[u8; 32]>,
    pub messages: HashMap<[u8; 32], Vec<ChatMsg>>,
    /// Непрочитанные по чату (растёт на входящее в НЕвыбранный чат; чистится при
    /// открытии). Для бейджа в списке и счётчика в заголовке окна.
    pub unread: HashMap<[u8; 32], usize>,
    /// Реакции активного аккаунта (`msg_id → эмодзи → авторы`), присланные worker'ом.
    /// Джойнятся к сообщениям по каноническому `msg_id` при рендере (`reactions_of`).
    meta: client::store::MetaMap,
    /// Заблокированные IK (от них не принимаем входящее). Источник — worker.
    blocked: std::collections::BTreeSet<[u8; 32]>,
    /// Cache of received contact profiles (`ik -> profile`). A display HINT: the
    /// profile's name/avatar are shown next to the local label but never replace it
    /// or `verified` (trust anchor — Principle 7). Sourced from the worker.
    peer_profiles: std::collections::BTreeMap<[u8; 32], client::store::Profile>,
    /// Черновик набранного, но не отправленного текста ПО ЧАТУ. При переключении
    /// чата текущий `in_compose` прячется сюда и восстанавливается при возврате
    /// (in-memory — как и сообщения; на диск не пишется).
    drafts: HashMap<[u8; 32], String>,
    /// На связи ли с relay (для индикатора). Обновляется по публикации/опросу.
    pub connected: bool,
    /// Per-relay reachability of the multi-homed set (index 0 = primary, 1.. aligned to
    /// `extra_relays`). Empty until the first poll reports it. Drives the per-backup dots.
    pub relay_health: Vec<bool>,
    /// Active §15 carrier for the session (shown in the status bar). `None` until
    /// the first unlock reports it.
    pub carrier: Option<client::Carrier>,
    /// The active account's configured SECONDARY relays (`addr, relay_id`), for display and
    /// removal. Populated from `Evt::ExtraRelays`; the primary is not in here.
    pub extra_relays: Vec<(String, String)>,
    /// Монотонный счётчик id исходящих (корреляция с `Evt::SendResult`).
    next_msg_id: u64,
    /// Контакты изменились и требуют персиста (app сбросит `Cmd::SaveContacts`).
    pub contacts_dirty: bool,
    /// Идёт пересылка: текст выбранного сообщения ждёт выбор целевого чата.
    /// KARST НЕ отслеживает происхождение сообщения между чатами, поэтому
    /// пересланное уходит как обычное новое — структурно без метки «переслано от…».
    pub forwarding: Option<String>,
    /// Идёт составление ОТВЕТА на конкретное сообщение (баннер над композитором).
    pub replying: Option<ReplyDraft>,
    /// Идёт ПРАВКА своего сообщения (`msg_id` цели); композитор держит текущий текст.
    pub editing: Option<[u8; 16]>,
    pub status: String,
    // Буферы ввода.
    pub in_passphrase: String,
    pub in_relay_addr: String,
    pub in_relay_id: String,
    pub in_socks5: String,
    /// Extra §15 routes for failover, comma-separated: `ip:port` (another endpoint on
    /// the same carrier) or `kind@ip:port` (`direct`/`socks5`/`wss`/`wss+socks5`).
    /// Empty = a single route. Switching never drops the carrier you chose (the
    /// allowlist filters it), so a route you did not consent to is never used.
    pub in_routes: String,
    /// SECONDARY relays to multi-home to, one `addr relay-id` per line. Empty = single-homed
    /// (or keep the saved secondaries, on unlock of an existing account). A backup relay is a
    /// DISTINCT relay identity, unlike `in_routes` (extra network paths to the SAME relay).
    pub in_extra_relays: String,
    /// Route offers received from contacts, awaiting an explicit decision (`ik → routes`).
    /// Never applied on arrival — see `Evt::RouteOffer`.
    pub pending_routes: std::collections::HashMap<[u8; 32], String>,
    pub in_contact_name: String,
    pub in_contact_ik: String,
    pub in_compose: String,
    pub in_file_path: String,
    /// Строка поиска по переписке (пусто = поиск не активен).
    pub in_search: String,
    /// Выбранный TTL исчезновения для следующего текста (секунды). `0` = выключено
    /// (обычное сообщение). Устанавливается пресетом в композиторе.
    pub in_expire_ttl: u32,
    // --- Создание/восстановление аккаунта ---
    /// Сгенерированная при создании фраза (12 слов через пробел). Показывается
    /// для записи; очищается после успешной разблокировки (не держим в памяти зря).
    pub new_phrase: Option<String>,
    /// Позиции слов (0-based), которые надо ввести на шаге сверки.
    pub confirm_positions: [usize; 3],
    /// Ответы пользователя на шаге сверки.
    pub in_confirm: [String; 3],
    /// Поле ввода фразы на экране восстановления.
    pub in_restore_phrase: String,
    // --- Мультиаккаунт ---
    /// Аккаунты устройства (для переключателя, как в Telegram).
    pub accounts: Vec<AccountInfo>,
    /// id активного аккаунта.
    pub active_account: Option<String>,
    /// Идёт добавление НОВОГО аккаунта к уже разблокированному vault (создание/
    /// восстановление без пароля). Различает Provision (первый, с паролем) и
    /// AddAccount (последующий, без пароля).
    pub adding_account: bool,
    /// Метка для нового аккаунта (необязательно; пусто → автометка).
    pub in_account_label: String,
    /// Selected UI language. A view-layer preference (not a secret); persisted by the
    /// view to a plaintext file outside the vault (it must be readable before unlock).
    pub lang: crate::i18n::Lang,
    // --- Profile ---
    /// Own display name (from `profile.dat`); empty means unset.
    pub my_name: String,
    /// Own bio (from `profile.dat`).
    pub my_bio: String,
    /// Own avatar bytes (PNG) if set — for the side-panel preview.
    pub my_avatar: Option<Vec<u8>>,
    /// Whether the own-profile editor is open (panel in the side column).
    pub editing_profile: bool,
    /// Editor buffer: name.
    pub in_profile_name: String,
    /// Editor buffer: bio.
    pub in_profile_bio: String,
    /// Editor buffer: local file path to a PNG to use as the avatar.
    pub in_avatar_path: String,
}

impl Default for App {
    fn default() -> Self {
        App {
            screen: Screen::Welcome,
            own_ik: None,
            contacts: Vec::new(),
            selected: None,
            messages: HashMap::new(),
            unread: HashMap::new(),
            meta: client::store::MetaMap::new(),
            blocked: std::collections::BTreeSet::new(),
            peer_profiles: std::collections::BTreeMap::new(),
            drafts: HashMap::new(),
            connected: false,
            relay_health: Vec::new(),
            carrier: None,
            extra_relays: Vec::new(),
            next_msg_id: 0,
            contacts_dirty: false,
            forwarding: None,
            replying: None,
            editing: None,
            status: String::new(),
            in_passphrase: String::new(),
            in_relay_addr: "127.0.0.1:9000".into(),
            in_relay_id: String::new(),
            in_socks5: String::new(),
            in_routes: String::new(),
            in_extra_relays: String::new(),
            pending_routes: std::collections::HashMap::new(),
            in_contact_name: String::new(),
            in_contact_ik: String::new(),
            in_compose: String::new(),
            in_file_path: String::new(),
            in_search: String::new(),
            in_expire_ttl: 0,
            new_phrase: None,
            confirm_positions: [0, 1, 2],
            in_confirm: [String::new(), String::new(), String::new()],
            in_restore_phrase: String::new(),
            accounts: Vec::new(),
            active_account: None,
            adding_account: false,
            in_account_label: String::new(),
            lang: crate::i18n::Lang::default(),
            my_name: String::new(),
            my_bio: String::new(),
            my_avatar: None,
            editing_profile: false,
            in_profile_name: String::new(),
            in_profile_bio: String::new(),
            in_avatar_path: String::new(),
        }
    }
}

impl App {
    pub fn new() -> Self {
        Self::default()
    }

    /// Translate a UI key in the current language.
    pub fn tr(&self, key: crate::i18n::Key) -> &'static str {
        crate::i18n::t(self.lang, key)
    }

    /// Render a worker `StatusMsg` into a display string in the current language.
    /// Pure over `(msg, self.lang)`; `Error` passes through unchanged (stays English).
    pub fn render_status(&self, msg: StatusMsg) -> String {
        use crate::i18n::Key;
        match msg {
            StatusMsg::LogInFirst => self.tr(Key::StLogInFirst).to_string(),
            StatusMsg::UnlockFirst => self.tr(Key::StUnlockFirst).to_string(),
            StatusMsg::ReadyToReceive => self.tr(Key::StReadyToReceive).to_string(),
            StatusMsg::FileSent(name) => self.tr(Key::StFileSentTpl).replace("{}", &name),
            StatusMsg::ProfileNotDelivered(n) => {
                self.tr(Key::StProfileNotDeliveredTpl).replace("{}", &n.to_string())
            }
            StatusMsg::AvatarNotDelivered(n) => {
                self.tr(Key::StAvatarNotDeliveredTpl).replace("{}", &n.to_string())
            }
            StatusMsg::Error(detail) => detail,
        }
    }

    /// Применить событие worker (чистая функция состояния).
    pub fn apply(&mut self, evt: Evt) {
        match evt {
            Evt::Unlocked { own_ik } => {
                self.own_ik = Some(own_ik);
                self.screen = Screen::Ready;
                self.status = self.tr(crate::i18n::Key::StUnlocked).to_string();
                // СБРОС состояния чатов — новый/переключённый аккаунт с чистого
                // листа (иначе контакты/сообщения прошлого аккаунта «протекли» бы;
                // Contacts/History следом наполнят заново). Порядок: Unlocked чистит
                // → Contacts/History наполняют — поэтому буферизованный до switch
                // Received применится к СТАРОМУ состоянию и будет стёрт здесь.
                self.contacts.clear();
                self.messages.clear();
                self.unread.clear();
                self.meta.clear();
                self.blocked.clear();
                self.peer_profiles.clear(); // display hints — reset with the account
                self.my_name.clear();
                self.my_bio.clear();
                self.my_avatar = None;
                self.editing_profile = false;
                self.in_profile_name.clear();
                self.in_profile_bio.clear();
                self.in_avatar_path.clear();
                self.drafts.clear();
                self.replying = None;
                self.editing = None;
                self.selected = None;
                self.in_compose.clear();
                self.in_search.clear();
                self.in_expire_ttl = 0; // не тащить исчезающий режим в другой аккаунт
                // Секреты/режимы входа больше не нужны в памяти view — вычистить.
                self.in_passphrase.clear();
                self.new_phrase = None;
                self.in_confirm = [String::new(), String::new(), String::new()];
                self.in_restore_phrase.clear();
                self.in_account_label.clear();
                self.adding_account = false;
            }
            Evt::Accounts { list, active } => {
                self.accounts = list;
                self.active_account = Some(active);
            }
            Evt::Contacts(list) => {
                // Загруженные с диска контакты — источник имён/флага сверки. Идут
                // ДО History, поэтому последующее авто-добавление лишь дополняет.
                for c in list {
                    if !self.contacts.iter().any(|x| x.ik == c.ik) {
                        self.contacts.push(c);
                    }
                }
            }
            Evt::RouteOffer { from, routes } => {
                // Stored as PENDING, never applied: accepting is the user's call.
                self.ensure_contact(from);
                self.pending_routes.insert(from, routes);
                self.status = self.tr(crate::i18n::Key::StRoutesOffered).to_string();
            }
            Evt::Status(s) => self.status = self.render_status(s),
            Evt::Connection(ok) => self.connected = ok,
            Evt::RelayHealth(health) => self.relay_health = health,
            Evt::Carrier(c) => self.carrier = Some(c),
            Evt::ExtraRelays(list) => self.extra_relays = list,
            Evt::SendResult { id, ok } => {
                // Пометить соответствующий пузырь доставлено/ошибка (не молчать).
                if id != 0 {
                    for msgs in self.messages.values_mut() {
                        if let Some(m) = msgs.iter_mut().find(|m| m.id == id) {
                            m.status = if ok { MsgStatus::Sent } else { MsgStatus::Failed };
                            m.progress = None; // терминал передачи файла — убрать бар
                            break;
                        }
                    }
                }
            }
            Evt::History(recs) => {
                // Восстановление с диска: раскладываем по чатам собеседника, порядок
                // append'а сохранён. Незнакомые IK показываем как контакты (отображение
                // ≠ доверие — то же, что для входящих).
                for r in recs {
                    self.ensure_contact(r.peer_ik);
                    let text = String::from_utf8_lossy(&r.text).into_owned();
                    self.messages
                        .entry(r.peer_ik)
                        .or_default()
                        .push(ChatMsg::incoming(r.from_me, text, r.ts));
                }
            }
            Evt::Received(msgs) => {
                for r in msgs {
                    self.ensure_contact(r.sender);
                    let text = String::from_utf8_lossy(&r.plaintext).into_owned();
                    self.messages
                        .entry(r.sender)
                        .or_default()
                        .push(ChatMsg::incoming(false, text, r.ts));
                    self.bump_unread(r.sender);
                }
            }
            Evt::ReceivedExpiring(msgs) => {
                for r in msgs {
                    self.ensure_contact(r.sender);
                    let text = String::from_utf8_lossy(&r.text).into_owned();
                    self.messages.entry(r.sender).or_default().push(ChatMsg {
                        from_me: false,
                        text,
                        id: 0,
                        status: MsgStatus::Sent,
                        kind: MsgKind::Text,
                        expire_at: Some(r.expire_at),
                        ts: 0, // исчезающие показывают счётчик, не время
                        progress: None,
                    });
                    self.bump_unread(r.sender);
                }
            }
            Evt::FileIncoming { sender, name, size, id, ts } => {
                // Большой файл начал СКАЧИВАТЬСЯ (off-loop): показать «приём…» пузырь с
                // баром сразу; `id` — корреляция с `FileProgress`/`FileReceived`.
                self.ensure_contact(sender);
                self.messages.entry(sender).or_default().push(ChatMsg {
                    from_me: false,
                    text: format!("📎 {name}"),
                    id,
                    status: MsgStatus::Sending,
                    kind: MsgKind::File { name, file_id: None },
                    expire_at: None,
                    ts,
                    progress: Some((0, size)),
                });
                self.bump_unread(sender);
            }
            Evt::FileProgress { id, done, total } => {
                // Обновить бар в пузыре передачи (исходящего или входящего) по id.
                if id != 0 {
                    for msgs in self.messages.values_mut() {
                        if let Some(m) = msgs.iter_mut().find(|m| m.id == id) {
                            m.progress = Some((done, total));
                            break;
                        }
                    }
                }
            }
            Evt::FileReceived { sender, name, file_id, ts, id } => {
                self.ensure_contact(sender);
                let msgs = self.messages.entry(sender).or_default();
                // No path to show: the file is sealed in the vault until the user
                // exports it (right-click → save as).
                let text = format!("📎 {name}");
                // Блоб-приём (`id != 0`): завершить приёмный пузырь, созданный
                // `FileIncoming` (сбросить бар, показать путь). Inline-приём (`id == 0`)
                // или пропавший пузырь — добавить новый.
                let existing = if id != 0 { msgs.iter_mut().find(|m| m.id == id) } else { None };
                if let Some(m) = existing {
                    m.text = text;
                    m.status = MsgStatus::Sent;
                    m.progress = None;
                    m.ts = ts;
                    m.kind = MsgKind::File { name, file_id: Some(file_id) };
                } else {
                    msgs.push(ChatMsg {
                        from_me: false,
                        text,
                        id: 0,
                        status: MsgStatus::Sent,
                        kind: MsgKind::File { name, file_id: Some(file_id) },
                        expire_at: None,
                        ts,
                        progress: None,
                    });
                    self.bump_unread(sender);
                }
            }
            Evt::MessageDeleted { peer, ts, text } => {
                // Отправитель отозвал сообщение: убрать принятое (from_me=false) из памяти.
                let text = String::from_utf8_lossy(&text).into_owned();
                if let Some(msgs) = self.messages.get_mut(&peer) {
                    msgs.retain(|m| !(m.ts == ts && !m.from_me && m.text == text));
                }
            }
            Evt::Meta(map) => {
                // Полная замена карты реакций (worker — источник правды на диске).
                self.meta = map;
            }
            Evt::Blocked(set) => {
                self.blocked = set;
            }
            Evt::Profile { name, bio, avatar } => {
                self.my_name = name;
                self.my_bio = bio;
                self.my_avatar = avatar;
                // Sync the editor buffers only while it is CLOSED — otherwise our own
                // echo would clobber the user's in-progress edits.
                if !self.editing_profile {
                    self.in_profile_name = self.my_name.clone();
                    self.in_profile_bio = self.my_bio.clone();
                }
            }
            Evt::PeerProfiles(map) => {
                // Full replacement of the hint cache (the worker is the disk source of
                // truth). Does NOT touch self.contacts (names/verified) — display only.
                self.peer_profiles = map;
            }
        }
    }

    /// A contact's self-declared name from the received profile (empty -> none). This
    /// is a HINT alongside the local label, not a replacement for it.
    pub fn peer_declared_name(&self, ik: &[u8; 32]) -> Option<&str> {
        self.peer_profiles.get(ik).map(|p| p.name.as_str()).filter(|s| !s.is_empty())
    }

    /// A contact's bio from the received profile (empty -> none).
    pub fn peer_bio(&self, ik: &[u8; 32]) -> Option<&str> {
        self.peer_profiles.get(ik).map(|p| p.bio.as_str()).filter(|s| !s.is_empty())
    }

    /// A contact's avatar bytes (PNG) from the received profile, if any.
    pub fn peer_avatar(&self, ik: &[u8; 32]) -> Option<&[u8]> {
        self.peer_profiles.get(ik).and_then(|p| p.avatar.as_deref())
    }

    /// Set our avatar from a local file path (worker validates + re-encodes + sends).
    /// Trims the path; empty -> no-op (`None`).
    pub fn action_set_avatar(&mut self, path: &str) -> Option<Cmd> {
        let path = path.trim();
        if path.is_empty() {
            return None;
        }
        Some(Cmd::SetAvatar { path: path.to_string() })
    }

    /// Clear our avatar.
    pub fn action_remove_avatar(&mut self) -> Cmd {
        self.my_avatar = None;
        Cmd::RemoveAvatar
    }

    /// Open the own-profile editor (buffers = current values).
    pub fn action_begin_edit_profile(&mut self) {
        self.in_profile_name = self.my_name.clone();
        self.in_profile_bio = self.my_bio.clone();
        self.editing_profile = true;
    }

    /// Close the profile editor without saving.
    pub fn action_cancel_edit_profile(&mut self) {
        self.editing_profile = false;
    }

    /// Save own profile: optimistically updates the display and returns
    /// `Cmd::SaveProfile` (the worker writes to disk and broadcasts to contacts).
    pub fn action_save_profile(&mut self) -> Cmd {
        let name = self.in_profile_name.trim().to_string();
        let bio = self.in_profile_bio.trim().to_string();
        self.my_name = name.clone();
        self.my_bio = bio.clone();
        self.editing_profile = false;
        Cmd::SaveProfile { name, bio }
    }

    /// Заблокирован ли контакт `ik` (не принимаем от него входящее).
    pub fn is_blocked(&self, ik: &[u8; 32]) -> bool {
        self.blocked.contains(ik)
    }

    /// Переключить блокировку контакта `ik`; возвращает `Cmd::SetBlocked` для worker'а
    /// (тот персистит и эхом вернёт актуальный набор). Оптимистично обновляет локально.
    pub fn action_toggle_block(&mut self, ik: [u8; 32]) -> Cmd {
        let blocked = !self.blocked.contains(&ik);
        if blocked {
            self.blocked.insert(ik);
        } else {
            self.blocked.remove(&ik);
        }
        Cmd::SetBlocked { ik, blocked }
    }

    /// Канонический `msg_id` сообщения в ТЕКУЩЕМ выбранном чате. Автор АБСОЛЮТНЫЙ:
    /// исходящее — свой IK, входящее — IK собеседника; так обе стороны сходятся на
    /// одном id. Требует `own_ik` и выбранный чат. Корректен для сообщений со
    /// штампом (`ts != 0`) — оптимистичные/исчезающие (`ts == 0`) не адресуемы.
    fn msg_id_in_selected(&self, from_me: bool, ts: u64, text: &str) -> Option<[u8; 16]> {
        let own = self.own_ik?;
        let peer = self.selected?;
        if ts == 0 {
            return None;
        }
        let author = if from_me { own } else { peer };
        Some(client::content::msg_id(&author, ts, text.as_bytes()))
    }

    /// Реакции на сообщение `m` в выбранном чате: `(эмодзи, число, реагировал ли я)`,
    /// в детерминированном порядке эмодзи. Пусто, если реакций нет / сообщение не
    /// адресуемо. Джойн истории и `meta` по каноническому `msg_id`.
    pub fn reactions_of(&self, m: &ChatMsg) -> Vec<(String, usize, bool)> {
        let Some(id) = self.msg_id_in_selected(m.from_me, m.ts, &m.text) else {
            return Vec::new();
        };
        let Some(mm) = self.meta.get(&id) else { return Vec::new() };
        mm.reactions
            .iter()
            .map(|(emoji, authors)| {
                let mine = self.own_ik.is_some_and(|me| authors.contains(&me));
                (emoji.clone(), authors.len(), mine)
            })
            .collect()
    }

    /// Поставить/снять реакцию `emoji` на сообщение (`from_me`, `ts`, `text`) в
    /// выбранном чате. Тоггл: если Я уже реагировал этим эмодзи — снять, иначе
    /// поставить. Оптимистично обновляет локальную `meta` (автор = own_ik) и
    /// возвращает `Cmd::React` для worker'а (он персистит и шлёт получателю).
    /// `None` — нет выбора/own_ik или сообщение не адресуемо (`ts == 0`).
    pub fn action_react(&mut self, from_me: bool, ts: u64, text: &str, emoji: &str) -> Option<Cmd> {
        let to_ik = self.selected?;
        let own = self.own_ik?;
        let id = self.msg_id_in_selected(from_me, ts, text)?;
        // Текущее состояние моей реакции этим эмодзи → тоггл.
        let currently = self
            .meta
            .get(&id)
            .and_then(|mm| mm.reactions.get(emoji))
            .is_some_and(|authors| authors.contains(&own));
        let add = !currently;
        // Оптимистичное локальное обновление (worker подтвердит полной Meta).
        let mm = self.meta.entry(id).or_default();
        if add {
            mm.reactions.entry(emoji.to_string()).or_default().insert(own);
        } else if let Some(authors) = mm.reactions.get_mut(emoji) {
            authors.remove(&own);
            if authors.is_empty() {
                mm.reactions.remove(emoji);
            }
        }
        if mm.is_empty() {
            self.meta.remove(&id);
        }
        Some(Cmd::React { to_ik, msg_id: id, emoji: emoji.to_string(), add })
    }

    /// Всего непрочитанных (для заголовка окна).
    pub fn total_unread(&self) -> usize {
        self.unread.values().sum()
    }

    /// Поиск по переписке: регистронезависимое вхождение подстроки по всем чатам.
    /// Локально, по расшифрованным сообщениям в памяти — наружу ничего не уходит.
    /// ИСЧЕЗАЮЩИЕ (expire_at) исключены: они эфемерны и не часть хранимой истории.
    /// Пустой/пробельный запрос → пусто. Порядок: как в чатах (сначала по контактам).
    pub fn search_results(&self) -> Vec<SearchHit> {
        let q = self.in_search.trim().to_lowercase();
        if q.is_empty() {
            return Vec::new();
        }
        let mut hits = Vec::new();
        for c in &self.contacts {
            if let Some(msgs) = self.messages.get(&c.ik) {
                for m in msgs {
                    if m.expire_at.is_none() && m.text.to_lowercase().contains(&q) {
                        hits.push(SearchHit { ik: c.ik, ts: m.ts, from_me: m.from_me, text: m.text.clone() });
                    }
                }
            }
        }
        hits
    }

    /// Идёт ли поиск (для переключения списка контактов на результаты).
    pub fn is_searching(&self) -> bool {
        !self.in_search.trim().is_empty()
    }

    /// Стереть из памяти исчезающие сообщения, чей `expire_at` наступил (`now` —
    /// текущее unix-время). Вызывается каждый кадр (repaint ≤500 мс → истечение
    /// не позже чем на полсекунды). Возвращает `true`, если что-то удалено (чтобы
    /// вызывающий обновил заголовок/перерисовал). Обычные сообщения (`expire_at`
    /// = `None`) не трогаются.
    pub fn sweep_expired(&mut self, now: u64) -> bool {
        let mut removed = false;
        for (ik, msgs) in self.messages.iter_mut() {
            let before = msgs.len();
            msgs.retain(|m| m.expire_at.map(|e| now < e).unwrap_or(true));
            if msgs.len() != before {
                removed = true;
                // Не даём счётчику непрочитанных «зависнуть» на исчезнувшем
                // контенте: ограничиваем оставшимся числом сообщений (полное
                // истечение чата → 0). Точный per-message read-state — потом.
                if let Some(u) = self.unread.get_mut(ik) {
                    *u = (*u).min(msgs.len());
                }
            }
        }
        removed
    }

    /// Увеличить счётчик непрочитанных, если чат не открыт сейчас.
    fn bump_unread(&mut self, ik: [u8; 32]) {
        if self.selected != Some(ik) {
            *self.unread.entry(ik).or_insert(0) += 1;
        }
    }

    /// Добавить контакт под известным IK, если его ещё нет (входящее от незнакомца
    /// → показываем как «неизв.», не сверен; отображение ≠ доверие).
    fn ensure_contact(&mut self, ik: [u8; 32]) {
        if !self.contacts.iter().any(|c| c.ik == ik) {
            self.contacts.push(Contact {
                // 8 байт префикса (не 4): чтобы намолотить IK с совпадающим авто-именем
                // «неизв. …» под известный контакт стоило ~2^64, а не ~2^32. Якорь
                // подлинности всё равно — код безопасности; это лишь анти-спуф витрины.
                name: format!("unknown {}", hex::encode(&ik[..8])),
                ik,
                verified: false,
            });
            // Авто-добавленный контакт тоже персистим (иначе имя-плейсхолдер и
            // будущая сверка не переживут рестарт).
            self.contacts_dirty = true;
        }
    }

    // ---- Действия UI: мутируют состояние и, возможно, возвращают Cmd для worker ----

    /// Export a received file: decrypt it out of the vault to `dest`. Explicit by
    /// design — a sealed file only becomes plaintext where the user points it.
    pub fn action_export_file(&mut self, file_id: String, dest: String) -> Option<Cmd> {
        self.status = self.tr(crate::i18n::Key::StFileExported).to_string();
        Some(Cmd::ExportFile { file_id, dest })
    }

    /// Share my routes with ONE chosen contact (the ••• menu). Explicit by design.
    pub fn action_share_routes(&mut self, ik: [u8; 32]) -> Option<Cmd> {
        self.status = self.tr(crate::i18n::Key::StRoutesShared).to_string();
        Some(Cmd::ShareRoutes { to_ik: ik })
    }

    /// Accept the routes this contact offered. Explicit: trying a route reveals your IP
    /// to whoever runs it, so nothing is applied until the user says so.
    pub fn action_accept_routes(&mut self, ik: [u8; 32]) -> Option<Cmd> {
        let routes = self.pending_routes.remove(&ik)?;
        self.status = self.tr(crate::i18n::Key::StRoutesAccepted).to_string();
        Some(Cmd::AcceptRoutes { routes })
    }

    /// Нажата «Разблокировать».
    pub fn action_unlock(&mut self) -> Option<Cmd> {
        if self.in_passphrase.is_empty() {
            self.status = self.tr(crate::i18n::Key::StEnterPassword).to_string();
            return None;
        }
        // An empty relay-id is NOT an error here: the network config is remembered in
        // the (encrypted) vault, so on later launches the passphrase is all that is
        // needed and the worker applies what was saved. It only errors if nothing was
        // ever configured — which the worker knows and the UI cannot (the config is
        // unreadable until the vault opens).
        Some(Cmd::Unlock {
            passphrase: self.in_passphrase.clone(),
            relay_addr: self.in_relay_addr.trim().to_string(),
            relay_id: self.in_relay_id.trim().to_string(),
            socks5: self.in_socks5.trim().to_string(),
            routes: self.in_routes.trim().to_string(),
            extra_relays: self.in_extra_relays.trim().to_string(),
        })
    }

    // ---- Создание / восстановление аккаунта ----

    /// «Создать аккаунт»: сгенерировать свежую фразу и перейти к её показу.
    pub fn action_start_create(&mut self) {
        let m = client::seed::generate_mnemonic();
        self.new_phrase = Some(m.to_string());
        self.confirm_positions = client::seed::confirm_positions();
        self.in_confirm = [String::new(), String::new(), String::new()];
        self.status.clear();
        self.screen = Screen::CreateShow;
    }

    /// С экрана показа фразы → к сверке (доказать, что записал).
    pub fn action_create_continue(&mut self) {
        self.in_confirm = [String::new(), String::new(), String::new()];
        self.status.clear();
        self.screen = Screen::CreateConfirm;
    }

    /// «Восстановить по фразе»: открыть экран ввода фразы.
    pub fn action_start_restore(&mut self) {
        self.in_restore_phrase.clear();
        self.status.clear();
        self.screen = Screen::Restore;
    }

    /// Вернуться к стартовому выбору, забыв незавершённую фразу.
    pub fn action_back_to_welcome(&mut self) {
        self.new_phrase = None;
        self.in_confirm = [String::new(), String::new(), String::new()];
        self.status.clear();
        self.screen = Screen::Welcome;
    }

    /// Подтвердить СОЗДАНИЕ: сверить введённые слова с показанной фразой (доказать
    /// резервную копию — не чекбокс), затем спровижинить. Несовпадение → без Cmd.
    pub fn action_confirm_create(&mut self) -> Option<Cmd> {
        let phrase = self.new_phrase.clone()?;
        let words: Vec<&str> = phrase.split_whitespace().collect();
        for (k, &pos) in self.confirm_positions.iter().enumerate() {
            let want = words.get(pos).copied().unwrap_or("");
            if !self.in_confirm[k].trim().eq_ignore_ascii_case(want) {
                self.status =
                    self.tr(crate::i18n::Key::StWordMismatchTpl).replace("{}", &(pos + 1).to_string());
                return None;
            }
        }
        self.provision_cmd(phrase)
    }

    /// Подтвердить ВОССТАНОВЛЕНИЕ: валидировать введённую фразу (сверка контрольной
    /// суммы), затем спровижинить. Битая фраза → без Cmd, статус с ошибкой.
    pub fn action_restore(&mut self) -> Option<Cmd> {
        let phrase = self.in_restore_phrase.trim().to_string();
        if let Err(e) = client::seed::parse_mnemonic(&phrase) {
            self.status = e;
            return None;
        }
        self.provision_cmd(phrase)
    }

    /// Общий хвост create/restore. В режиме ДОБАВЛЕНИЯ (vault уже разблокирован) —
    /// `AddAccount` без пароля/relay (переиспользуются ключ устройства и сеть). Для
    /// ПЕРВОГО аккаунта — `Provision` с паролем устройства + relay.
    fn provision_cmd(&mut self, phrase: String) -> Option<Cmd> {
        if self.adding_account {
            return Some(Cmd::AddAccount { phrase, label: self.in_account_label.trim().to_string() });
        }
        if self.in_passphrase.is_empty() {
            self.status = self.tr(crate::i18n::Key::StSetPassword).to_string();
            return None;
        }
        if self.in_relay_id.trim().is_empty() {
            self.status = self.tr(crate::i18n::Key::StEnterRelayId).to_string();
            return None;
        }
        Some(Cmd::Provision {
            passphrase: self.in_passphrase.clone(),
            phrase,
            relay_addr: self.in_relay_addr.trim().to_string(),
            relay_id: self.in_relay_id.trim().to_string(),
            socks5: self.in_socks5.trim().to_string(),
            routes: self.in_routes.trim().to_string(),
            extra_relays: self.in_extra_relays.trim().to_string(),
        })
    }

    /// Add ONE secondary relay from the `in_extra_relays` input (`addr relay-id`) to the
    /// current set. Returns the full new set as `SetExtraRelays` (the worker persists +
    /// rebuilds), or `None` on malformed input (status set, nothing sent).
    pub fn action_add_extra_relay(&mut self) -> Option<Cmd> {
        let line = self.in_extra_relays.trim();
        let mut it = line.split_whitespace();
        let (addr, rid) = match (it.next(), it.next(), it.next()) {
            (Some(a), Some(r), None) => (a.to_string(), r.to_string()),
            _ => {
                self.status = "backup relay: type  addr relay-id".to_string();
                return None;
            }
        };
        let entry = (addr, rid);
        let mut relays = self.extra_relays.clone();
        // Skip an exact duplicate — otherwise the account would publish to and poll the same
        // relay twice per cycle, shown as two identical rows.
        if !relays.contains(&entry) {
            relays.push(entry);
        }
        self.in_extra_relays.clear();
        Some(Cmd::SetExtraRelays { relays })
    }

    /// Remove the secondary relay at `idx`. Returns the full remaining set as
    /// `SetExtraRelays` (an empty set clears it), or `None` if the index is stale.
    pub fn action_remove_extra_relay(&mut self, idx: usize) -> Option<Cmd> {
        if idx >= self.extra_relays.len() {
            return None;
        }
        let mut relays = self.extra_relays.clone();
        relays.remove(idx);
        Some(Cmd::SetExtraRelays { relays })
    }

    /// Переключиться на аккаунт `id` (если не активен). Worker сменит сессию и
    /// пришлёт свежие Unlocked/Contacts/History.
    pub fn action_switch_account(&mut self, id: String) -> Option<Cmd> {
        if self.active_account.as_deref() == Some(id.as_str()) {
            return None;
        }
        self.status = self.tr(crate::i18n::Key::StSwitching).to_string();
        Some(Cmd::SwitchAccount { id })
    }

    /// Начать добавление НОВОГО аккаунта: режим add + экран выбора создать/восстановить.
    pub fn action_start_add_account(&mut self) {
        self.adding_account = true;
        self.in_account_label.clear();
        self.new_phrase = None;
        self.in_restore_phrase.clear();
        self.in_confirm = [String::new(), String::new(), String::new()];
        self.status.clear();
        self.screen = Screen::Welcome;
    }

    /// Отменить добавление аккаунта — вернуться к активному чату.
    pub fn action_cancel_add(&mut self) {
        self.adding_account = false;
        self.new_phrase = None;
        self.in_restore_phrase.clear();
        self.status.clear();
        self.screen = Screen::Ready;
    }

    /// Нажата «Добавить контакт». Парсит IK-hex (OOB-вставка).
    pub fn action_add_contact(&mut self) {
        match parse_ik(&self.in_contact_ik) {
            Ok(ik) => {
                // Нельзя добавить самого себя (чат с собой + бессмысленный код
                // безопасности own↔own). Отдельная понятная ошибка.
                if self.own_ik == Some(ik) {
                    self.status = self.tr(crate::i18n::Key::StOwnAddress).to_string();
                    return;
                }
                let name = if self.in_contact_name.trim().is_empty() {
                    hex::encode(&ik[..8]) // 8 байт витрины (см. ensure_contact)
                } else {
                    self.in_contact_name.trim().to_string()
                };
                if let Some(existing) = self.contacts.iter_mut().find(|c| c.ik == ik) {
                    existing.name = name; // переименование существующего
                    self.status = self.tr(crate::i18n::Key::StContactRenamed).to_string();
                } else {
                    self.contacts.push(Contact { name, ik, verified: false });
                    self.status = self.tr(crate::i18n::Key::StContactAdded).to_string();
                }
                self.contacts_dirty = true;
                self.in_contact_name.clear();
                self.in_contact_ik.clear();
            }
            Err(e) => self.status = e,
        }
    }

    /// Выбрать чат по IK контакта; открытие чата сбрасывает его непрочитанные.
    pub fn action_select(&mut self, ik: [u8; 32]) {
        if !self.contacts.iter().any(|c| c.ik == ik) {
            return;
        }
        if self.selected != Some(ik) {
            // Спрятать текущий черновик под СТАРЫЙ чат, восстановить черновик нового.
            if let Some(prev) = self.selected {
                if self.in_compose.is_empty() {
                    self.drafts.remove(&prev);
                } else {
                    self.drafts.insert(prev, std::mem::take(&mut self.in_compose));
                }
            }
            self.in_compose = self.drafts.get(&ik).cloned().unwrap_or_default();
            // Сброс таймера исчезновения при смене чата — fail-safe: по умолчанию
            // сообщение СОХРАНЯЕТСЯ; исчезающий режим надо осознанно включить в
            // ЭТОМ чате (иначе таймер «прилип» бы и тайком жёг сообщения в других).
            self.in_expire_ttl = 0;
            // Черновики ответа/правки привязаны к сообщению в СТАРОМ чате — сбросить.
            self.replying = None;
            self.editing = None;
        }
        self.selected = Some(ik);
        self.unread.remove(&ik);
    }

    /// Удалить контакт (и его чат/непрочитанные). Если он был выбран — снять выбор.
    /// Возвращает `Cmd::ClearChat`, чтобы стереть переписку и НА ДИСКЕ: иначе
    /// история пережила бы удаление и на рестарте контакт (и сообщения) воскресли бы
    /// авто-добавлением из истории.
    pub fn action_delete_contact(&mut self, ik: [u8; 32]) -> Option<Cmd> {
        self.contacts.retain(|c| c.ik != ik);
        self.messages.remove(&ik);
        self.unread.remove(&ik);
        self.drafts.remove(&ik);
        if self.selected == Some(ik) {
            self.selected = None;
        }
        self.contacts_dirty = true;
        self.status = self.tr(crate::i18n::Key::StContactDeleted).to_string();
        Some(Cmd::ClearChat { ik })
    }

    /// Очистить переписку с `ik`, СОХРАНИВ контакт: стереть сообщения/непрочитанные
    /// в памяти и (через Cmd) на диске. Контакт и его сверка остаются.
    pub fn action_clear_chat(&mut self, ik: [u8; 32]) -> Option<Cmd> {
        if !self.contacts.iter().any(|c| c.ik == ik) {
            return None;
        }
        self.messages.remove(&ik);
        self.unread.remove(&ik);
        self.status = self.tr(crate::i18n::Key::StChatCleared).to_string();
        Some(Cmd::ClearChat { ik })
    }

    /// Удалить ОДНО сообщение из чата `ik` у СЕБЯ: убрать из памяти и (через Cmd)
    /// с диска по (ts, from_me, text). Для исчезающих/неотправленных (`ts == 0`)
    /// на диске записи нет — только память, без Cmd. Точные дубли уйдут вместе
    /// (они неразличимы). Все пути удаления сходятся в `rewrite_history` на worker'е.
    pub fn action_delete_message(&mut self, ik: [u8; 32], ts: u64, from_me: bool, text: String) -> Option<Cmd> {
        if let Some(msgs) = self.messages.get_mut(&ik) {
            msgs.retain(|m| !(m.ts == ts && m.from_me == from_me && m.text == text));
        }
        self.status = self.tr(crate::i18n::Key::StMessageDeleted).to_string();
        if ts == 0 {
            return None; // на диск не писалось (исчезающее/неотправленное)
        }
        Some(Cmd::DeleteMessage { ik, ts, from_me, text })
    }

    /// Удалить СВОЁ отправленное сообщение У ВСЕХ: убрать локально (from_me=true) и
    /// послать получателю tombstone. Только для своих сообщений с реальным ts (для
    /// чужих/исчезающих/неотправленных — `None`, отзывать нечего). `ts` — сквозной
    /// штамп отправителя, по нему получатель найдёт свою копию.
    pub fn action_delete_message_everyone(&mut self, ik: [u8; 32], ts: u64, text: String) -> Option<Cmd> {
        if ts == 0 {
            return None;
        }
        if let Some(msgs) = self.messages.get_mut(&ik) {
            msgs.retain(|m| !(m.ts == ts && m.from_me && m.text == text));
        }
        self.status = self.tr(crate::i18n::Key::StDeletedForAll).to_string();
        Some(Cmd::DeleteForEveryone { to_ik: ik, ts, text })
    }

    /// Отметить выбранный контакт сверенным (пользователь подтвердил код
    /// безопасности по OOB-каналу). Персистится.
    pub fn action_verify_selected(&mut self) {
        if let Some(ik) = self.selected {
            if let Some(c) = self.contacts.iter_mut().find(|c| c.ik == ik) {
                c.verified = true;
                self.contacts_dirty = true;
                self.status = self.tr(crate::i18n::Key::StMarkedVerified).to_string();
            }
        }
    }

    /// Выбранный контакт (для рендера имени/флага/удаления).
    pub fn selected_contact(&self) -> Option<&Contact> {
        let ik = self.selected?;
        self.contacts.iter().find(|c| c.ik == ik)
    }

    /// Следующий id исходящего (монотонный, ненулевой).
    fn next_id(&mut self) -> u64 {
        self.next_msg_id += 1;
        self.next_msg_id
    }

    /// Общий хвост отправки текста: валидирует, кладёт оптимистичный пузырь
    /// (`expire_at` = `None` для обычного, `Some(abs)` для исчезающего) и отдаёт
    /// `(ik, text, id)` для сборки конкретной Cmd. `None` — пусто/слишком длинно.
    fn compose_send(&mut self, now: u64, expire_at: Option<u64>) -> Option<([u8; 32], String, u64)> {
        let ik = self.selected?;
        let text = self.in_compose.trim().to_string();
        if text.is_empty() {
            return None;
        }
        if text.len() > client::content::MAX_TEXT_BYTES {
            self.status = self
                .tr(crate::i18n::Key::StMsgTooLongTpl)
                .replacen("{}", &text.len().to_string(), 1)
                .replacen("{}", &client::content::MAX_TEXT_BYTES.to_string(), 1);
            return None;
        }
        let id = self.next_id();
        self.messages.entry(ik).or_default().push(ChatMsg {
            from_me: true,
            text: text.clone(),
            id,
            status: MsgStatus::Sending,
            kind: MsgKind::Text,
            expire_at,
            ts: now,
            progress: None,
        });
        self.in_compose.clear();
        self.drafts.remove(&ik); // отправлено — черновик этого чата больше не нужен
        Some((ik, text, id))
    }

    /// Нажата «Отправить». `now` — unix-время контроллера, штампуется в пузырь и в
    /// `Cmd::Send.ts` (worker пишет его в историю → память и диск совпадут по ts).
    pub fn action_send(&mut self, now: u64) -> Option<Cmd> {
        // Режим ПРАВКИ приоритетнее ответа/обычного — это не новое сообщение, а
        // overlay поверх существующего.
        if self.editing.is_some() {
            return self.action_send_edit(now);
        }
        // Ответ (если составляется) потребляем ДО compose_send; при неудачной
        // сборки (пусто/длинно) — вернуть, чтобы баннер ответа не пропал.
        let reply = self.replying.take();
        let (to_ik, text, id) = match self.compose_send(now, None) {
            Some(v) => v,
            None => {
                self.replying = reply;
                return None;
            }
        };
        if let Some(rd) = reply {
            // Оптимистично: у моего нового сообщения проставить reply_to (цитата
            // покажется сразу, не дожидаясь echo от worker'а).
            if let Some(own) = self.own_ik {
                let my_id = client::content::msg_id(&own, now, text.as_bytes());
                self.meta.entry(my_id).or_default().reply_to = Some(rd.to);
            }
            Some(Cmd::SendReply { to_ik, text, id, ts: now, reply_to: rd.to })
        } else {
            Some(Cmd::Send { to_ik, text, id, ts: now })
        }
    }

    /// Отправить ПРАВКУ (режим editing): overlay нового текста поверх своего
    /// сообщения-цели, история не трогается. `None` — нет выбора/пусто/длинно (в
    /// этом случае режим правки НЕ сбрасывается, чтобы не потерять его молча).
    fn action_send_edit(&mut self, now: u64) -> Option<Cmd> {
        let to_ik = self.selected?;
        let text = self.in_compose.trim().to_string();
        if text.is_empty() {
            return None;
        }
        if text.len() > client::content::MAX_TEXT_BYTES {
            self.status = self
                .tr(crate::i18n::Key::StEditTooLongTpl)
                .replacen("{}", &text.len().to_string(), 1)
                .replacen("{}", &client::content::MAX_TEXT_BYTES.to_string(), 1);
            return None;
        }
        let target = self.editing.take()?;
        // Оптимистичный overlay (worker подтвердит полной Meta).
        self.meta.entry(target).or_default().edited = Some((now, text.as_bytes().to_vec()));
        self.in_compose.clear();
        Some(Cmd::EditMessage { to_ik, target_msg_id: target, new_text: text, edit_ts: now })
    }

    /// Начать правку СВОЕГО сообщения (`from_me=true`, `ts!=0`): грузит текущий текст
    /// (с учётом уже сделанной правки) в композитор и включает режим правки. Чужие/
    /// неадресуемые — игнор (править можно только своё, кооперативно у получателя).
    pub fn action_begin_edit(&mut self, from_me: bool, ts: u64, text: &str) {
        if !from_me || ts == 0 {
            return;
        }
        if let Some(id) = self.msg_id_in_selected(from_me, ts, text) {
            let cur = self
                .meta
                .get(&id)
                .and_then(|mm| mm.edited.as_ref())
                .map(|(_, t)| String::from_utf8_lossy(t).into_owned())
                .unwrap_or_else(|| text.to_string());
            self.in_compose = cur;
            self.editing = Some(id);
            self.replying = None; // взаимоисключимо с ответом
        }
    }

    /// Отменить правку (вернуть композитор в обычный режим).
    pub fn cancel_edit(&mut self) {
        self.editing = None;
        self.in_compose.clear();
    }

    /// Идёт ли правка (для гейта таймера исчезновения в view).
    pub fn is_editing(&self) -> bool {
        self.editing.is_some()
    }

    /// Изменённый текст сообщения `m`, если оно правилось (overlay из meta). Показывать
    /// вместо `m.text` + пометку «изменено». `None` — не правилось.
    pub fn edited_of(&self, m: &ChatMsg) -> Option<String> {
        let id = self.msg_id_in_selected(m.from_me, m.ts, &m.text)?;
        self.meta
            .get(&id)?
            .edited
            .as_ref()
            .map(|(_, t)| String::from_utf8_lossy(t).into_owned())
    }

    /// Начать ответ на сообщение (`from_me`, `ts`, `text`) в выбранном чате: ставит
    /// баннер над композитором. Игнор для неадресуемых (`ts==0`) — цитировать нечего.
    pub fn action_begin_reply(&mut self, from_me: bool, ts: u64, text: &str) {
        if let Some(id) = self.msg_id_in_selected(from_me, ts, text) {
            self.replying = Some(ReplyDraft { to: id, preview: snippet(text) });
            self.editing = None; // взаимоисключимо с правкой
        }
    }

    /// Отменить составление ответа.
    pub fn cancel_reply(&mut self) {
        self.replying = None;
    }

    /// Цитата для сообщения `m`, если это ответ: короткий текст цели (найденной в
    /// текущем чате по `msg_id`), либо «сообщение недоступно» (цель удалена/не
    /// загружена). `None` — сообщение не является ответом.
    pub fn reply_preview_of(&self, m: &ChatMsg) -> Option<String> {
        let id = self.msg_id_in_selected(m.from_me, m.ts, &m.text)?;
        let target = self.meta.get(&id)?.reply_to?;
        let peer = self.selected?;
        let msgs = self.messages.get(&peer)?;
        for c in msgs {
            if self.msg_id_in_selected(c.from_me, c.ts, &c.text) == Some(target) {
                return Some(snippet(&c.text));
            }
        }
        Some("message unavailable".into())
    }

    /// Нажата «Отправить» с включённым таймером исчезновения. `now` — текущее
    /// unix-время (view передаёт часы; контроллер чист). Пузырь получает
    /// `expire_at = now + ttl`; на провод уходит `Cmd::SendExpiring` (worker
    /// проставит абсолютный expire_at по своим часам — авторитет для получателя).
    pub fn action_send_expiring(&mut self, now: u64, ttl_secs: u32) -> Option<Cmd> {
        let expire_at = now.saturating_add(ttl_secs as u64);
        let (to_ik, text, id) = self.compose_send(now, Some(expire_at))?;
        Some(Cmd::SendExpiring { to_ik, text, id, ttl_secs })
    }

    /// Нажата «Отправить файл». Оптимистично показывает строку файла (статус
    /// «отправляется») и возвращает `Cmd::SendFile` (worker прочитает и зачанкует).
    pub fn action_send_file(&mut self, now: u64) -> Option<Cmd> {
        let ik = self.selected?;
        let path = self.in_file_path.trim().to_string();
        if path.is_empty() {
            return None;
        }
        let name = path.rsplit(['/', '\\']).next().unwrap_or(&path).to_string();
        let id = self.next_id();
        self.messages.entry(ik).or_default().push(ChatMsg {
            from_me: true,
            text: format!("📎 {name}"),
            id,
            status: MsgStatus::Sending,
            kind: MsgKind::File { name, file_id: None }, // ours: nothing to export
            expire_at: None,
            ts: now,
            progress: None, // worker выставит бар для blob-пути (крупные файлы)
        });
        self.in_file_path.clear();
        Some(Cmd::SendFile { to_ik: ik, path, id, ts: now })
    }

    /// Начать пересылку ТЕКСТА `text`: запомнить содержимое, ждём выбор целевого
    /// чата. Только для текстовых пузырей (файл пока не пересылается — витринная
    /// строка ≠ переиспользуемые байты; UI гейтит по `MsgKind`).
    pub fn action_begin_forward(&mut self, text: String) {
        self.forwarding = Some(text);
        self.status = self.tr(crate::i18n::Key::StPickForwardTarget).to_string();
    }

    /// Отменить пересылку.
    pub fn action_cancel_forward(&mut self) {
        self.forwarding = None;
        self.status.clear();
    }

    /// Идёт ли пересылка (для баннера/подсветки в UI).
    pub fn is_forwarding(&self) -> bool {
        self.forwarding.is_some()
    }

    /// Переслать запомненный текст в чат `to_ik`: оптимистичный пузырь + `Cmd::Send`
    /// с новым id. Никакой метки «переслано от…» — KARST не отслеживает
    /// происхождение между чатами, поэтому это обычное новое сообщение. Открывает
    /// целевой чат. Неизвестный получатель / нет активной пересылки → без Cmd.
    pub fn action_forward_to(&mut self, to_ik: [u8; 32], now: u64) -> Option<Cmd> {
        self.forwarding.as_ref()?;
        if !self.contacts.iter().any(|c| c.ik == to_ik) {
            return None;
        }
        let text = self.forwarding.take().unwrap();
        let id = self.next_id();
        self.messages.entry(to_ik).or_default().push(ChatMsg {
            from_me: true,
            text: text.clone(),
            id,
            status: MsgStatus::Sending,
            kind: MsgKind::Text,
            expire_at: None,
            ts: now,
            progress: None,
        });
        self.selected = Some(to_ik);
        self.unread.remove(&to_ik);
        self.status = self.tr(crate::i18n::Key::StForwarded).to_string();
        Some(Cmd::Send { to_ik, text, id, ts: now })
    }

    /// Код безопасности выбранного контакта — сверка подлинности IK по OOB-каналу.
    /// `None` до разблокировки (нет `own_ik`) или без выбранного контакта.
    /// Чистая функция уже известных ключей — без сети/worker'а.
    pub fn safety_number(&self) -> Option<String> {
        let own = self.own_ik?;
        let ik = self.selected?;
        Some(node::safety::safety_number(&own, &ik))
    }

    /// Сообщения выбранного чата (для рендера).
    pub fn selected_messages(&self) -> &[ChatMsg] {
        self.selected.and_then(|ik| self.messages.get(&ik)).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

/// Разобрать §2.1-IK из hex (64 hex = 32 байта).
pub fn parse_ik(s: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(s.trim()).map_err(|e| format!("IK is not hex: {e}"))?;
    b.as_slice()
        .try_into()
        .map_err(|_| format!("IK must be 32 bytes (64 hex), got {}", b.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ik(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn render_status_localizes_and_passes_errors_through() {
        use crate::i18n::Lang;
        let mut app = App::new();

        // Localizable variants follow the active language.
        app.lang = Lang::De;
        assert_eq!(app.render_status(StatusMsg::ReadyToReceive), "bereit zum Empfang von Nachrichten");
        assert_eq!(app.render_status(StatusMsg::UnlockFirst), "zuerst entsperren");
        app.lang = Lang::En;
        assert_eq!(app.render_status(StatusMsg::ReadyToReceive), "ready to receive messages");

        // Templated variants interpolate their data into the localized frame.
        app.lang = Lang::Ru;
        assert_eq!(app.render_status(StatusMsg::FileSent("a.png".into())), "файл отправлен: a.png");
        assert_eq!(app.render_status(StatusMsg::ProfileNotDelivered(3)), "профиль: не доставлено 3 контакту(ам)");

        // Errors pass through verbatim — no localization, regardless of language.
        app.lang = Lang::De;
        assert_eq!(app.render_status(StatusMsg::Error("poll: boom".into())), "poll: boom");
    }

    #[test]
    fn unlock_requires_the_passphrase_but_not_a_retyped_relay_id() {
        // The passphrase is still mandatory — it is what opens the vault. The relay-id
        // is NOT: the network config is remembered (encrypted) in the vault, so a
        // returning user types only the passphrase and the worker applies what was
        // saved. Only the worker can tell "nothing was ever configured" from "use the
        // saved one" — the config is unreadable until the vault opens, so the UI must
        // not pre-judge it.
        let mut app = App::new();
        assert!(app.action_unlock().is_none(), "no passphrase → no Cmd");

        app.in_passphrase = "pw".into();
        match app.action_unlock() {
            Some(Cmd::Unlock { relay_id, .. }) => {
                assert!(relay_id.is_empty(), "an empty relay-id means: use the saved config")
            }
            _ => panic!("expected Unlock even without a typed relay-id"),
        }

        app.in_relay_id = "deadbeef".into();
        match app.action_unlock() {
            Some(Cmd::Unlock { relay_id, .. }) => assert_eq!(relay_id, "deadbeef", "a typed relay-id wins"),
            _ => panic!("expected Unlock"),
        }
    }

    #[test]
    fn typed_secondary_relays_ride_the_unlock_command() {
        // The multi-homing input reaches the worker: what the user types in the backup-relay
        // field is carried on the Unlock/Provision Cmd (the worker parses + persists it).
        // Discriminating: drop `extra_relays` from the builder and this reds.
        let mut app = App::new();
        app.in_passphrase = "pw".into();
        app.in_extra_relays = "  1.2.3.4:9000 aabb  ".into();
        match app.action_unlock() {
            Some(Cmd::Unlock { extra_relays, .. }) => {
                assert_eq!(extra_relays, "1.2.3.4:9000 aabb", "the typed secondary relays are carried, trimmed")
            }
            _ => panic!("expected Unlock"),
        }
    }

    #[test]
    fn secondary_relays_can_be_listed_added_and_removed() {
        let mut app = App::new();
        // The display list is populated by the worker's event.
        app.apply(Evt::ExtraRelays(vec![("1.1.1.1:9000".into(), "aa".into())]));
        assert_eq!(app.extra_relays.len(), 1, "the configured secondaries are shown");

        // Add appends to the CURRENT set (not replace) and clears the input.
        app.in_extra_relays = "2.2.2.2:9000 bb".into();
        match app.action_add_extra_relay() {
            Some(Cmd::SetExtraRelays { relays }) => assert_eq!(
                relays,
                vec![("1.1.1.1:9000".into(), "aa".into()), ("2.2.2.2:9000".into(), "bb".into())],
                "add keeps the existing entries and appends the new one"
            ),
            _ => panic!("expected SetExtraRelays"),
        }
        assert!(app.in_extra_relays.is_empty(), "the add input is cleared");

        // Re-adding an existing entry is a no-op (no duplicate rows / double polling).
        app.apply(Evt::ExtraRelays(vec![("1.1.1.1:9000".into(), "aa".into())]));
        app.in_extra_relays = "1.1.1.1:9000 aa".into();
        match app.action_add_extra_relay() {
            Some(Cmd::SetExtraRelays { relays }) => assert_eq!(relays.len(), 1, "a duplicate add is skipped"),
            _ => panic!("expected SetExtraRelays"),
        }

        // Malformed input sends nothing.
        app.in_extra_relays = "garbage".into();
        assert!(app.action_add_extra_relay().is_none(), "malformed input → no command");

        // Remove drops exactly the chosen entry; removing the last one CLEARS the set (which
        // the login field's `empty = keep saved` semantics can never do).
        match app.action_remove_extra_relay(0) {
            Some(Cmd::SetExtraRelays { relays }) => assert!(relays.is_empty(), "removing the only entry clears it"),
            _ => panic!("expected SetExtraRelays"),
        }
        assert!(app.action_remove_extra_relay(9).is_none(), "a stale index sends nothing");
    }

    #[test]
    fn unlocked_event_moves_to_ready() {
        let mut app = App::new();
        app.apply(Evt::Unlocked { own_ik: ik(1) });
        assert!(app.screen == Screen::Ready);
        assert_eq!(app.own_ik, Some(ik(1)));
    }

    #[test]
    fn add_contact_parses_ik_and_rejects_bad_hex() {
        let mut app = App::new();
        app.in_contact_ik = "nothex".into();
        app.action_add_contact();
        assert!(app.contacts.is_empty(), "плохой hex не добавляет контакт");

        app.in_contact_name = "Bob".into();
        app.in_contact_ik = hex::encode(ik(7));
        app.action_add_contact();
        assert_eq!(app.contacts.len(), 1);
        assert_eq!(app.contacts[0].name, "Bob");
        assert_eq!(app.contacts[0].ik, ik(7));
    }

    #[test]
    fn send_appends_optimistically_and_emits_cmd() {
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(2));
        app.action_add_contact();
        app.action_select(ik(2));
        app.in_compose = "hello".into();
        let cmd = app.action_send(1000);
        assert!(matches!(cmd, Some(Cmd::Send { text, .. }) if text == "hello"));
        assert_eq!(app.selected_messages().len(), 1);
        assert!(app.selected_messages()[0].from_me);
        assert_eq!(app.in_compose, "", "поле ввода очищено");
    }

    #[test]
    fn received_routes_to_sender_chat_and_autoadds_unknown() {
        let mut app = App::new();
        let r = IncomingText { sender: ik(9), plaintext: b"hi there".to_vec(), ts: 0 };
        app.apply(Evt::Received(vec![r]));
        // Незнакомый отправитель добавлен как контакт, сообщение в его чате.
        assert_eq!(app.contacts.len(), 1);
        assert_eq!(app.contacts[0].ik, ik(9));
        let msgs = app.messages.get(&ik(9)).unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(!msgs[0].from_me);
        assert_eq!(msgs[0].text, "hi there");
    }

    #[test]
    fn history_populates_chats_by_peer_preserving_order_and_direction() {
        let mut app = App::new();
        app.apply(Evt::History(vec![
            HistoryRecord { from_me: true, peer_ik: ik(5), text: b"first".to_vec(), ts: 1 },
            HistoryRecord { from_me: false, peer_ik: ik(5), text: b"reply".to_vec(), ts: 2 },
            HistoryRecord { from_me: true, peer_ik: ik(6), text: b"elsewhere".to_vec(), ts: 3 },
        ]));
        // Два собеседника → два контакта; сообщения в чатах по peer_ik.
        assert_eq!(app.contacts.len(), 2);
        let chat5 = app.messages.get(&ik(5)).unwrap();
        assert_eq!(chat5.len(), 2);
        assert!(chat5[0].from_me && chat5[0].text == "first", "порядок и направление");
        assert!(!chat5[1].from_me && chat5[1].text == "reply");
        assert_eq!(app.messages.get(&ik(6)).unwrap().len(), 1, "другой чат отдельно");
    }

    #[test]
    fn safety_number_needs_unlock_and_selection_and_is_symmetric() {
        let mut app = App::new();
        assert!(app.safety_number().is_none(), "заблокировано → None");
        app.own_ik = Some(ik(3));
        app.in_contact_ik = hex::encode(ik(8));
        app.action_add_contact();
        assert!(app.safety_number().is_none(), "контакт не выбран → None");
        app.action_select(ik(8));
        let sn = app.safety_number().expect("есть own_ik и выбор");
        // Совпадает с чистой функцией и симметричен относительно порядка IK.
        assert_eq!(sn, node::safety::safety_number(&ik(3), &ik(8)));
        assert_eq!(sn, node::safety::safety_number(&ik(8), &ik(3)), "симметрия");
    }

    #[test]
    fn create_flow_generates_phrase_and_confirm_gates_on_correct_words() {
        let mut app = App::new();
        app.action_start_create();
        assert!(app.screen == Screen::CreateShow, "показ фразы");
        let phrase = app.new_phrase.clone().expect("фраза сгенерирована");
        assert_eq!(phrase.split_whitespace().count(), 12, "12 слов");

        app.action_create_continue();
        assert!(app.screen == Screen::CreateConfirm);

        // Пароль/relay заданы, но слова НЕВЕРНЫ → без Cmd (сверка резервной копии).
        app.in_passphrase = "pw".into();
        app.in_relay_id = "deadbeef".into();
        app.in_confirm = ["нет".into(), "нет".into(), "нет".into()];
        assert!(app.action_confirm_create().is_none(), "неверные слова не пускают дальше");

        // Верные слова на запрошенных позициях → Provision с той же фразой.
        let words: Vec<&str> = phrase.split_whitespace().collect();
        for (k, &pos) in app.confirm_positions.iter().enumerate() {
            app.in_confirm[k] = words[pos].to_string();
        }
        match app.action_confirm_create() {
            Some(Cmd::Provision { phrase: p, passphrase, .. }) => {
                assert_eq!(p, phrase, "передаётся показанная фраза");
                assert_eq!(passphrase, "pw");
            }
            _ => panic!("ожидался Provision"),
        }
    }

    #[test]
    fn create_confirm_requires_password_and_relay() {
        let mut app = App::new();
        app.action_start_create();
        let phrase = app.new_phrase.clone().unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        for (k, &pos) in app.confirm_positions.iter().enumerate() {
            app.in_confirm[k] = words[pos].to_string();
        }
        // Слова верны, но пароля нет → без Cmd.
        assert!(app.action_confirm_create().is_none(), "без пароля нет Cmd");
        app.in_passphrase = "pw".into();
        assert!(app.action_confirm_create().is_none(), "без relay-id нет Cmd");
        app.in_relay_id = "deadbeef".into();
        assert!(matches!(app.action_confirm_create(), Some(Cmd::Provision { .. })));
    }

    #[test]
    fn restore_rejects_bad_phrase_accepts_valid() {
        let mut app = App::new();
        app.action_start_restore();
        assert!(app.screen == Screen::Restore);
        app.in_passphrase = "pw".into();
        app.in_relay_id = "deadbeef".into();

        // Битая контрольная сумма → отвергнуть (не молча «восстановить» пустоту).
        app.in_restore_phrase = "abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon about abandon"
            .into();
        assert!(app.action_restore().is_none(), "битая фраза отвергнута");

        // Валидная фраза → Provision.
        app.in_restore_phrase = "abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon about"
            .into();
        assert!(matches!(app.action_restore(), Some(Cmd::Provision { .. })));
    }

    #[test]
    fn unlock_clears_phrase_and_password_from_memory() {
        let mut app = App::new();
        app.action_start_create();
        app.in_passphrase = "pw".into();
        app.apply(Evt::Unlocked { own_ik: ik(1) });
        assert!(app.new_phrase.is_none(), "фраза вычищена после входа");
        assert!(app.in_passphrase.is_empty(), "пароль вычищен после входа");
        assert!(app.screen == Screen::Ready);
    }

    #[test]
    fn send_result_flips_bubble_status_by_id() {
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(2));
        app.action_add_contact();
        app.action_select(ik(2));
        app.in_compose = "hello".into();
        let Some(Cmd::Send { id, .. }) = app.action_send(1000) else { panic!("Send") };
        assert!(matches!(app.selected_messages()[0].status, MsgStatus::Sending), "сначала «отправляется»");
        // Успех по тому же id → «доставлено».
        app.apply(Evt::SendResult { id, ok: true });
        assert!(matches!(app.selected_messages()[0].status, MsgStatus::Sent));
        // Второе сообщение, провал → «не отправлено», первое не трогается.
        app.in_compose = "second".into();
        let Some(Cmd::Send { id: id2, .. }) = app.action_send(1000) else { panic!() };
        app.apply(Evt::SendResult { id: id2, ok: false });
        assert!(matches!(app.selected_messages()[1].status, MsgStatus::Failed));
        assert!(matches!(app.selected_messages()[0].status, MsgStatus::Sent), "первое не задето");
    }

    #[test]
    fn over_limit_text_is_rejected_with_status_not_sent() {
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(2));
        app.action_add_contact();
        app.action_select(ik(2));
        app.in_compose = "я".repeat(client::content::MAX_TEXT_BYTES); // кириллица 2 Б/симв → сильно за лимит
        assert!(app.action_send(1000).is_none(), "слишком длинное — без Cmd");
        assert!(app.status.contains("too long"));
        assert!(app.selected_messages().is_empty(), "оптимистичный пузырь не добавлен");
    }

    #[test]
    fn unread_increments_for_unselected_clears_on_open() {
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(1));
        app.action_add_contact();
        app.in_contact_ik = hex::encode(ik(2));
        app.action_add_contact();
        app.action_select(ik(1)); // открыт чат 1
        // Входящее в чат 2 (не открыт) → +1 непрочитанное; в чат 1 (открыт) → 0.
        app.apply(Evt::Received(vec![IncomingText { sender: ik(2), plaintext: b"x".to_vec(), ts: 0 }]));
        app.apply(Evt::Received(vec![IncomingText { sender: ik(1), plaintext: b"y".to_vec(), ts: 0 }]));
        assert_eq!(app.unread.get(&ik(2)).copied().unwrap_or(0), 1);
        assert_eq!(app.unread.get(&ik(1)).copied().unwrap_or(0), 0, "открытый чат не копит");
        assert_eq!(app.total_unread(), 1);
        // Открыть чат 2 → сброс.
        app.action_select(ik(2));
        assert_eq!(app.total_unread(), 0);
    }

    #[test]
    fn loaded_contacts_survive_history_autoadd() {
        // Contacts (названный, сверенный) ДО History с тем же IK → имя/флаг НЕ
        // затираются авто-добавлением «неизв.».
        let mut app = App::new();
        app.apply(Evt::Contacts(vec![Contact { name: "Alice".into(), ik: ik(5), verified: true }]));
        app.apply(Evt::History(vec![HistoryRecord {
            from_me: false,
            peer_ik: ik(5),
            text: b"hi".to_vec(),
            ts: 1,
        }]));
        assert_eq!(app.contacts.len(), 1, "не задублирован");
        assert_eq!(app.contacts[0].name, "Alice", "имя сохранено");
        assert!(app.contacts[0].verified, "флаг сверки сохранён");
    }

    #[test]
    fn delete_earlier_contact_keeps_selection_on_other() {
        // Выбор по IK, а не индексу: удаление РАНЬШЕ стоящего контакта не сбивает
        // выбор на другого (был бы баг при индексном selected).
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(1));
        app.action_add_contact();
        app.in_contact_ik = hex::encode(ik(2));
        app.action_add_contact();
        app.action_select(ik(2));
        app.action_delete_contact(ik(1)); // удалить ПЕРВЫЙ
        assert_eq!(app.selected, Some(ik(2)), "выбор остался на том же человеке");
        assert_eq!(app.contacts.len(), 1);
        // Удаление выбранного → снимает выбор.
        app.action_delete_contact(ik(2));
        assert_eq!(app.selected, None);
    }

    #[test]
    fn verify_marks_selected_contact_and_dirties() {
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(3));
        app.action_add_contact();
        app.action_select(ik(3));
        app.contacts_dirty = false;
        app.action_verify_selected();
        assert!(app.selected_contact().unwrap().verified);
        assert!(app.contacts_dirty, "изменение требует персиста");
    }

    fn acc(id: &str, ik_n: u8) -> AccountInfo {
        AccountInfo { id: id.into(), label: format!("Аккаунт {id}"), ik: ik(ik_n) }
    }

    #[test]
    fn switch_account_resets_chat_state_and_sets_active() {
        let mut app = App::new();
        app.apply(Evt::Accounts { list: vec![acc("a", 1), acc("b", 2)], active: "a".into() });
        app.apply(Evt::Unlocked { own_ik: ik(1) });
        app.apply(Evt::Received(vec![IncomingText { sender: ik(9), plaintext: b"hi".to_vec(), ts: 0 }]));
        assert_eq!(app.contacts.len(), 1, "у аккаунта A есть контакт");
        assert_eq!(app.messages.len(), 1);

        // Переключение на B: worker шлёт Unlocked (СБРОС) → Accounts(active=b).
        app.apply(Evt::Unlocked { own_ik: ik(2) });
        assert!(app.contacts.is_empty(), "контакты прошлого аккаунта стёрты");
        assert!(app.messages.is_empty(), "сообщения прошлого аккаунта стёрты");
        assert!(app.selected.is_none());
        app.apply(Evt::Accounts { list: vec![acc("a", 1), acc("b", 2)], active: "b".into() });
        assert_eq!(app.active_account.as_deref(), Some("b"));
        assert_eq!(app.accounts.len(), 2, "список аккаунтов держится через переключение");
    }

    #[test]
    fn stale_received_before_switch_does_not_leak_into_new_account() {
        // Дискриминирующий для сброса-на-Unlocked: буферизованное до switch входящее
        // не должно показаться под новым аккаунтом (FIFO: Received до Unlocked).
        let mut app = App::new();
        app.apply(Evt::Unlocked { own_ik: ik(1) }); // аккаунт A
        app.apply(Evt::Received(vec![IncomingText { sender: ik(9), plaintext: b"secret".to_vec(), ts: 0 }]));
        app.apply(Evt::Unlocked { own_ik: ik(2) }); // switch → B: чистка
        app.apply(Evt::Contacts(vec![])); // контакты B (пусто)
        assert!(!app.messages.contains_key(&ik(9)), "чужое сообщение не протекло в новый аккаунт");
        assert!(app.contacts.is_empty());
    }

    #[test]
    fn adding_account_mode_emits_add_not_provision() {
        let mut app = App::new();
        app.action_start_add_account();
        assert!(app.adding_account);
        assert!(app.screen == Screen::Welcome);

        app.action_start_create();
        let phrase = app.new_phrase.clone().unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        for (k, &pos) in app.confirm_positions.iter().enumerate() {
            app.in_confirm[k] = words[pos].to_string();
        }
        app.in_account_label = "Работа".into();
        // В add-режиме пароль/relay НЕ требуются (переиспользуются) → AddAccount.
        match app.action_confirm_create() {
            Some(Cmd::AddAccount { phrase: p, label }) => {
                assert_eq!(p, phrase);
                assert_eq!(label, "Работа");
            }
            _ => panic!("ожидался AddAccount"),
        }
    }

    #[test]
    fn switch_account_skips_if_already_active() {
        let mut app = App::new();
        app.active_account = Some("a".into());
        assert!(app.action_switch_account("a".into()).is_none(), "уже активен → без Cmd");
        assert!(matches!(app.action_switch_account("b".into()), Some(Cmd::SwitchAccount { .. })));
    }

    #[test]
    fn cannot_add_self_as_contact() {
        let mut app = App::new();
        app.own_ik = Some(ik(1));
        app.in_contact_ik = hex::encode(ik(1)); // свой же адрес
        app.action_add_contact();
        assert!(app.contacts.is_empty(), "себя добавлять нельзя");
        // Чужой — можно.
        app.in_contact_ik = hex::encode(ik(2));
        app.action_add_contact();
        assert_eq!(app.contacts.len(), 1);
    }

    #[test]
    fn received_goes_to_correct_chat_not_selected_one() {
        // Раскладка по ОТПРАВИТЕЛЮ, не по выбранному чату.
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(1));
        app.action_add_contact();
        app.in_contact_ik = hex::encode(ik(2));
        app.action_add_contact();
        app.action_select(ik(1)); // выбран контакт 1
        app.apply(Evt::Received(vec![IncomingText { sender: ik(2), plaintext: b"x".to_vec(), ts: 0 }]));
        assert!(!app.messages.contains_key(&ik(1)), "не в выбранный чат");
        assert_eq!(app.messages.get(&ik(2)).unwrap().len(), 1, "в чат отправителя");
    }

    #[test]
    fn forward_sends_text_verbatim_without_marks() {
        // Пересылка уходит как ОБЫЧНОЕ новое сообщение: тот же текст байт-в-байт,
        // без метки «переслано от…». Дискриминирующий: любой префикс/суффикс
        // («↪», «переслано:») сломал бы равенство текста.
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(1));
        app.action_add_contact();
        app.in_contact_ik = hex::encode(ik(2));
        app.action_add_contact();
        app.action_select(ik(1));

        app.action_begin_forward("секрет".into());
        assert!(app.is_forwarding(), "пересылка началась");
        let cmd = app.action_forward_to(ik(2), 1000);
        match cmd {
            Some(Cmd::Send { to_ik, text, .. }) => {
                assert_eq!(to_ik, ik(2), "ушло выбранному получателю");
                assert_eq!(text, "секрет", "текст без каких-либо меток пересылки");
            }
            _ => panic!("ожидался Cmd::Send"),
        }
        // Оптимистичный пузырь в чате получателя, целевой чат открыт, пересылка снята.
        let msgs = app.messages.get(&ik(2)).unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].from_me && msgs[0].text == "секрет");
        assert_eq!(app.selected, Some(ik(2)), "переключились в чат назначения");
        assert!(!app.is_forwarding(), "пересылка завершена");
    }

    #[test]
    fn forward_to_non_contact_or_no_pending_is_rejected_and_keeps_state() {
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(1));
        app.action_add_contact();
        // Нет активной пересылки → без Cmd.
        assert!(app.action_forward_to(ik(1), 1000).is_none(), "нет ожидающей пересылки");
        // Пересылка есть, но получатель не в контактах → без Cmd, содержимое сохранено.
        app.action_begin_forward("привет".into());
        assert!(app.action_forward_to(ik(9), 1000).is_none(), "получатель не контакт");
        assert!(app.is_forwarding(), "пересылка не потеряна при промахе");
        // В известный контакт — уходит.
        assert!(matches!(app.action_forward_to(ik(1), 1000), Some(Cmd::Send { .. })));
    }

    #[test]
    fn delete_contact_emits_clear_chat_to_wipe_disk_history() {
        // Удаление контакта должно СТЕРЕТЬ и историю на диске (иначе воскреснет).
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(3));
        app.action_add_contact();
        match app.action_delete_contact(ik(3)) {
            Some(Cmd::ClearChat { ik: k }) => assert_eq!(k, ik(3)),
            _ => panic!("ожидался Cmd::ClearChat"),
        }
        assert!(app.contacts.is_empty());
    }

    #[test]
    fn clear_chat_keeps_contact_wipes_messages_and_emits_cmd() {
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(4));
        app.action_add_contact();
        app.action_select(ik(4));
        app.apply(Evt::Received(vec![IncomingText { sender: ik(4), plaintext: b"hi".to_vec(), ts: 0 }]));
        assert!(app.messages.contains_key(&ik(4)));
        match app.action_clear_chat(ik(4)) {
            Some(Cmd::ClearChat { ik: k }) => assert_eq!(k, ik(4)),
            _ => panic!("ожидался Cmd::ClearChat"),
        }
        assert!(!app.messages.contains_key(&ik(4)), "сообщения стёрты");
        assert!(app.contacts.iter().any(|c| c.ik == ik(4)), "контакт сохранён");
        // Неизвестный чат — без Cmd.
        assert!(app.action_clear_chat(ik(99)).is_none());
    }

    #[test]
    fn expiring_send_stamps_expire_at_and_emits_ttl_cmd() {
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(2));
        app.action_add_contact();
        app.action_select(ik(2));
        app.in_compose = "самоуничтожься".into();
        // now=1000, ttl=30 → expire_at=1030 в пузыре, ttl на проводе.
        match app.action_send_expiring(1000, 30) {
            Some(Cmd::SendExpiring { ttl_secs, text, .. }) => {
                assert_eq!(ttl_secs, 30);
                assert_eq!(text, "самоуничтожься");
            }
            _ => panic!("ожидался Cmd::SendExpiring"),
        }
        let m = app.messages.get(&ik(2)).unwrap().last().unwrap();
        assert_eq!(m.expire_at, Some(1030), "пузырь помечен временем смерти");
    }

    #[test]
    fn delete_for_everyone_recalls_own_and_tombstone_removes_received() {
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(2));
        app.action_add_contact();
        app.action_select(ik(2));
        // Своё отправленное с ts=500.
        app.in_compose = "recall me".into();
        app.action_send(500).expect("Send");
        // Удаляем у всех → локально убрано, Cmd с (to_ik, ts, text).
        match app.action_delete_message_everyone(ik(2), 500, "recall me".into()) {
            Some(Cmd::DeleteForEveryone { to_ik, ts, text }) => {
                assert_eq!((to_ik, ts, text.as_str()), (ik(2), 500, "recall me"));
            }
            _ => panic!("ожидался Cmd::DeleteForEveryone"),
        }
        assert!(app.messages.get(&ik(2)).map(|v| v.is_empty()).unwrap_or(true), "своя копия убрана");
        // Своё чужое/исчезающее нельзя — ts=0 → None.
        assert!(app.action_delete_message_everyone(ik(2), 0, "x".into()).is_none());

        // Приём tombstone: принятое (from_me=false) с (ts,text) стирается из памяти.
        app.apply(Evt::Received(vec![IncomingText { sender: ik(2), plaintext: b"their msg".to_vec(), ts: 700 }]));
        assert_eq!(app.messages.get(&ik(2)).unwrap().len(), 1);
        app.apply(Evt::MessageDeleted { peer: ik(2), ts: 700, text: b"their msg".to_vec() });
        assert!(app.messages.get(&ik(2)).unwrap().is_empty(), "tombstone убрал принятое");
    }

    #[test]
    fn search_matches_across_chats_case_insensitive_excludes_disappearing() {
        let mut app = App::new();
        app.apply(Evt::Contacts(vec![
            Contact { name: "Alice".into(), ik: ik(1), verified: false },
            Contact { name: "Bob".into(), ik: ik(2), verified: false },
        ]));
        app.apply(Evt::History(vec![
            HistoryRecord { from_me: true, peer_ik: ik(1), text: b"Hello world".to_vec(), ts: 1 },
            HistoryRecord { from_me: false, peer_ik: ik(2), text: b"another WORLD here".to_vec(), ts: 2 },
            HistoryRecord { from_me: true, peer_ik: ik(1), text: b"unrelated".to_vec(), ts: 3 },
        ]));
        // Исчезающее с тем же словом — НЕ должно попасть в поиск.
        app.apply(Evt::ReceivedExpiring(vec![ExpiringIn { sender: ik(2), text: b"world ephemeral".to_vec(), expire_at: 9999 }]));

        app.in_search = "world".into();
        let hits = app.search_results();
        assert_eq!(hits.len(), 2, "два совпадения в двух чатах, регистр игнор");
        assert!(hits.iter().any(|h| h.ik == ik(1) && h.text == "Hello world"));
        assert!(hits.iter().any(|h| h.ik == ik(2) && h.text == "another WORLD here"));
        assert!(!hits.iter().any(|h| h.text.contains("ephemeral")), "исчезающее исключено");
        // Пустой запрос → пусто.
        app.in_search = "   ".into();
        assert!(app.search_results().is_empty());
    }

    #[test]
    fn delete_message_removes_from_memory_and_emits_disk_cmd() {
        let mut app = App::new();
        app.apply(Evt::History(vec![
            HistoryRecord { from_me: true, peer_ik: ik(2), text: b"keep".to_vec(), ts: 10 },
            HistoryRecord { from_me: false, peer_ik: ik(2), text: b"drop".to_vec(), ts: 11 },
        ]));
        app.action_select(ik(2));
        // Удаляем «drop» (ts=11, входящее). Возвращается Cmd для диска с теми же полями.
        match app.action_delete_message(ik(2), 11, false, "drop".into()) {
            Some(Cmd::DeleteMessage { ik: k, ts, from_me, text }) => {
                assert_eq!((k, ts, from_me, text.as_str()), (ik(2), 11, false, "drop"));
            }
            _ => panic!("ожидался Cmd::DeleteMessage"),
        }
        let left = app.messages.get(&ik(2)).unwrap();
        assert_eq!(left.len(), 1, "в памяти осталось одно");
        assert_eq!(left[0].text, "keep");
        // ts==0 (исчезающее/неотправленное) — только память, без Cmd.
        app.apply(Evt::ReceivedExpiring(vec![ExpiringIn { sender: ik(2), text: b"poof".to_vec(), expire_at: 9999 }]));
        assert!(app.action_delete_message(ik(2), 0, false, "poof".into()).is_none(), "ts=0 → без Cmd");
        assert!(app.messages.get(&ik(2)).unwrap().iter().all(|m| m.text != "poof"), "но из памяти убрано");
    }

    #[test]
    fn ts_is_stamped_on_send_and_carried_on_receive_and_history() {
        // Исходящий пузырь и Cmd::Send несут ОДИН ts (now контроллера) — это и есть
        // совпадение память↔диск, на котором держится удаление/цитирование.
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(2));
        app.action_add_contact();
        app.action_select(ik(2));
        app.in_compose = "at noon".into();
        let Some(Cmd::Send { ts, .. }) = app.action_send(1_700_000_042) else { panic!("Send") };
        assert_eq!(ts, 1_700_000_042, "Cmd несёт now контроллера");
        assert_eq!(app.messages.get(&ik(2)).unwrap().last().unwrap().ts, 1_700_000_042, "пузырь тот же ts");
        // Входящее несёт ts worker'а.
        app.apply(Evt::Received(vec![IncomingText { sender: ik(2), plaintext: b"hi".to_vec(), ts: 999 }]));
        assert_eq!(app.messages.get(&ik(2)).unwrap().last().unwrap().ts, 999, "входящее — ts worker'а");
        // История несёт ts записи.
        app.apply(Evt::History(vec![HistoryRecord { from_me: false, peer_ik: ik(3), text: b"old".to_vec(), ts: 555 }]));
        assert_eq!(app.messages.get(&ik(3)).unwrap()[0].ts, 555, "история — ts записи");
    }

    #[test]
    fn sweep_removes_only_expired_disappearing_messages() {
        // Дискриминирующий: обычные (expire_at=None) НИКОГДА не подметаются;
        // исчезающие — ровно когда now достиг их срока.
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(5));
        app.action_add_contact();
        app.action_select(ik(5));
        // Обычное входящее.
        app.apply(Evt::Received(vec![IncomingText { sender: ik(5), plaintext: "навсегда".as_bytes().to_vec(), ts: 0 }]));
        // Исчезающее входящее с expire_at=1050.
        app.apply(Evt::ReceivedExpiring(vec![ExpiringIn {
            sender: ik(5),
            text: "скоро исчезну".as_bytes().to_vec(),
            expire_at: 1050,
        }]));
        assert_eq!(app.messages.get(&ik(5)).unwrap().len(), 2);
        // До срока — ничего не подметается.
        assert!(!app.sweep_expired(1049));
        assert_eq!(app.messages.get(&ik(5)).unwrap().len(), 2, "до срока оба на месте");
        // На сроке — исчезающее уходит, обычное остаётся.
        assert!(app.sweep_expired(1050));
        let left = app.messages.get(&ik(5)).unwrap();
        assert_eq!(left.len(), 1, "исчезающее подметено");
        assert_eq!(left[0].text, "навсегда", "обычное не тронуто");
        assert!(left[0].expire_at.is_none());
    }

    #[test]
    fn draft_is_saved_per_chat_and_restored_on_return() {
        // Набранный, но не отправленный текст переживает переключение чата и
        // возвращается в СВОЙ чат (а не протекает в чужой).
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(1));
        app.action_add_contact();
        app.in_contact_ik = hex::encode(ik(2));
        app.action_add_contact();
        app.action_select(ik(1));
        app.in_compose = "черновик для 1".into();
        app.action_select(ik(2)); // ушли в чат 2
        assert_eq!(app.in_compose, "", "у чата 2 своего черновика нет — поле пусто");
        app.in_compose = "черновик для 2".into();
        app.action_select(ik(1)); // вернулись в чат 1
        assert_eq!(app.in_compose, "черновик для 1", "восстановлен черновик чата 1");
        app.action_select(ik(2));
        assert_eq!(app.in_compose, "черновик для 2", "восстановлен черновик чата 2");
    }

    #[test]
    fn sending_clears_draft_so_it_does_not_reappear() {
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(1));
        app.action_add_contact();
        app.in_contact_ik = hex::encode(ik(2));
        app.action_add_contact();
        app.action_select(ik(1));
        app.in_compose = "привет".into();
        app.action_send(1000).expect("Cmd::Send");
        assert_eq!(app.in_compose, "", "поле очищено после отправки");
        app.action_select(ik(2));
        app.action_select(ik(1)); // вернулись — черновика быть не должно
        assert_eq!(app.in_compose, "", "отправленный текст не вернулся черновиком");
    }

    #[test]
    fn selecting_chat_resets_disappearing_timer() {
        // Fail-safe: таймер не «прилипает» между чатами (иначе тайком жёг бы
        // сообщения, которые пользователь хотел сохранить).
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(1));
        app.action_add_contact();
        app.in_contact_ik = hex::encode(ik(2));
        app.action_add_contact();
        app.action_select(ik(1));
        app.in_expire_ttl = 30; // включили в чате 1
        app.action_select(ik(2)); // ушли в чат 2
        assert_eq!(app.in_expire_ttl, 0, "исчезающий режим сброшен при смене чата");
    }

    #[test]
    fn sweep_clamps_stuck_unread_on_expired_chat() {
        // Фантомный бейдж: исчезло всё непрочитанное → счётчик не должен «зависнуть».
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(1));
        app.action_add_contact();
        app.in_contact_ik = hex::encode(ik(7));
        app.action_add_contact();
        app.action_select(ik(1)); // открыт ДРУГОЙ чат → в чат 7 копится непрочитанное
        app.apply(Evt::ReceivedExpiring(vec![ExpiringIn {
            sender: ik(7),
            text: "gone".as_bytes().to_vec(),
            expire_at: 1050,
        }]));
        assert_eq!(app.unread.get(&ik(7)).copied().unwrap_or(0), 1);
        app.sweep_expired(1050);
        assert_eq!(app.unread.get(&ik(7)).copied().unwrap_or(0), 0, "бейдж не завис на исчезнувшем");
        assert_eq!(app.total_unread(), 0);
    }

    #[test]
    fn cancel_forward_clears_pending() {
        let mut app = App::new();
        app.action_begin_forward("x".into());
        assert!(app.is_forwarding());
        app.action_cancel_forward();
        assert!(!app.is_forwarding(), "пересылка отменена");
    }

    #[test]
    fn an_offered_route_is_never_applied_without_an_explicit_accept() {
        // The whole trust model of route sharing: an offer sits PENDING until the user
        // says yes. Trying an offered route reveals your IP to whoever runs it, so
        // arrival must never be consent. Discriminating: apply it on arrival (or drop
        // the pending map) and both halves of this red.
        let mut app = App::new();
        app.apply(Evt::RouteOffer { from: ik(2), routes: "10.0.0.9:9000".into() });
        assert_eq!(
            app.pending_routes.get(&ik(2)).map(String::as_str),
            Some("10.0.0.9:9000"),
            "the offer waits for a decision"
        );
        // Nothing is accepted for a contact who offered nothing.
        assert!(app.action_accept_routes(ik(3)).is_none(), "no offer → nothing to accept");

        // Only an explicit accept produces the command that applies it…
        match app.action_accept_routes(ik(2)) {
            Some(Cmd::AcceptRoutes { routes }) => assert_eq!(routes, "10.0.0.9:9000"),
            _ => panic!("expected AcceptRoutes"),
        }
        // …and it is consumed, so a stale offer cannot be applied twice.
        assert!(!app.pending_routes.contains_key(&ik(2)), "accepted offer is consumed");
    }

    #[test]
    fn sharing_routes_is_addressed_to_one_chosen_contact() {
        // The user picks WHO. Discriminating: a broadcast implementation would not carry
        // the selected contact's ik.
        let mut app = App::new();
        match app.action_share_routes(ik(7)) {
            Some(Cmd::ShareRoutes { to_ik }) => assert_eq!(to_ik, ik(7), "sent to the chosen contact only"),
            _ => panic!("expected ShareRoutes"),
        }
    }

    #[test]
    fn typed_routes_reach_the_unlock_and_provision_commands() {
        // The routes field must not be decoration: what the user types has to reach the
        // worker, which is the only reason failover is configurable without env vars.
        // Discriminating: drop `routes:` from the Cmd builders and this reds.
        let mut app = App::new();
        app.in_passphrase = "pw".into();
        app.in_relay_id = "aa".repeat(64);
        app.in_routes = " 10.0.0.9:9000, wss@10.0.0.8:443 ".into();
        match app.action_unlock() {
            Some(Cmd::Unlock { routes, .. }) => {
                assert_eq!(routes, "10.0.0.9:9000, wss@10.0.0.8:443", "typed routes reach Unlock, trimmed");
            }
            _ => panic!("expected Unlock"),
        }
    }

    #[test]
    fn file_bubbles_carry_file_kind_text_bubbles_do_not() {
        // MsgKind различает файл и текст — чтобы UI показывал «переслать» только у
        // текста. Дискриминирующий: если бы отправка файла/приём давали Text-kind,
        // проверка File провалилась бы.
        let mut app = App::new();
        app.in_contact_ik = hex::encode(ik(2));
        app.action_add_contact();
        app.action_select(ik(2));
        // Исходящий файл.
        app.in_file_path = "/tmp/report.pdf".into();
        app.action_send_file(1000).expect("Cmd::SendFile");
        let sent = app.messages.get(&ik(2)).unwrap().last().unwrap();
        assert!(matches!(&sent.kind, MsgKind::File { name, .. } if name == "report.pdf"));
        // Входящий файл.
        app.apply(Evt::FileReceived { sender: ik(2), name: "pic.png".into(), file_id: "abc123".into(), ts: 0, id: 0 });
        let recvd = app.messages.get(&ik(2)).unwrap().last().unwrap();
        assert!(matches!(&recvd.kind, MsgKind::File { name, .. } if name == "pic.png"));
        // Текст — Text-kind.
        app.in_compose = "hi".into();
        app.action_send(1000);
        let txt = app.messages.get(&ik(2)).unwrap().last().unwrap();
        assert!(matches!(txt.kind, MsgKind::Text));
    }

    #[test]
    fn incoming_large_file_lifecycle_updates_one_bubble_by_id() {
        // FileIncoming → FileProgress → FileReceived (тот же id) обновляют ОДИН пузырь:
        // бар растёт, затем исчезает (progress None), статус Sent, текст с путём. Дискр.:
        // если finalize добавлял бы НОВЫЙ пузырь вместо обновления по id, было бы два.
        let mut app = App::new();
        app.action_select(ik(3));
        let id = 0xDEAD_BEEF_u64;
        app.apply(Evt::FileIncoming { sender: ik(3), name: "movie.mkv".into(), size: 1000, id, ts: 5 });
        let m = app.messages.get(&ik(3)).unwrap().last().unwrap();
        assert_eq!(m.progress, Some((0, 1000)), "приёмный пузырь стартует с баром");
        assert!(matches!(m.status, MsgStatus::Sending));

        app.apply(Evt::FileProgress { id, done: 400, total: 1000 });
        assert_eq!(app.messages.get(&ik(3)).unwrap().last().unwrap().progress, Some((400, 1000)));

        app.apply(Evt::FileReceived { sender: ik(3), name: "movie.mkv".into(), file_id: "vaultid".into(), ts: 9, id });
        let msgs = app.messages.get(&ik(3)).unwrap();
        assert_eq!(msgs.len(), 1, "finalize обновил тот же пузырь, а не добавил новый");
        let m = &msgs[0];
        assert_eq!(m.progress, None, "бар исчез по завершении");
        assert!(matches!(m.status, MsgStatus::Sent));
        assert!(m.text.contains("movie.mkv"), "the name is shown; there is no path — the file is sealed");
    }

    // ---- Реакции: джойн истории и meta по каноническому msg_id ----

    use std::collections::BTreeSet;

    /// Построить карту с одной реакцией `emoji` от `author` на сообщение `id`.
    fn meta_one(id: [u8; 16], emoji: &str, author: [u8; 32]) -> client::store::MetaMap {
        let mut mm = client::store::MsgMeta::default();
        mm.reactions.insert(emoji.to_string(), BTreeSet::from([author]));
        let mut map = client::store::MetaMap::new();
        map.insert(id, mm);
        map
    }

    #[test]
    fn reactions_join_incoming_message_by_absolute_peer_author() {
        // Дискриминирующий по КРОСС-УСТРОЙСТВЕННОЙ атрибуции: входящее (from_me=false)
        // адресуется по IK СОБЕСЕДНИКА, не своему. Если msg_id считать по own_ik —
        // джойн не сойдётся (нейтрализация: author = own → тест краснеет).
        let mut app = App::new();
        app.own_ik = Some(ik(1));
        app.selected = Some(ik(2));
        app.messages.entry(ik(2)).or_default().push(ChatMsg::incoming(false, "hi".into(), 100));
        let id = client::content::msg_id(&ik(2), 100, b"hi");
        app.apply(Evt::Meta(meta_one(id, "👍", ik(3)))); // реакция третьей стороны
        let m = app.messages[&ik(2)][0].clone();
        assert_eq!(
            app.reactions_of(&m),
            vec![("👍".to_string(), 1, false)],
            "сматчилось по автору=peer; я (own) не реагировал → mine=false"
        );
    }

    #[test]
    fn reactions_join_own_outgoing_message_by_own_author() {
        // Вторая ветка атрибуции: МОЁ сообщение (from_me=true) адресуется по own_ik.
        // Дискриминирующий против «author = всегда peer»: собеседник отреагировал на
        // моё — должно сматчиться по own(ik1); при нейтрализации (author=peer) id не
        // сойдётся и реакция на своих сообщениях исчезла бы (тест краснеет).
        let mut app = App::new();
        app.own_ik = Some(ik(1));
        app.selected = Some(ik(2));
        app.messages.entry(ik(2)).or_default().push(ChatMsg::incoming(true, "mine".into(), 200));
        let id = client::content::msg_id(&ik(1), 200, b"mine"); // автор = own
        app.apply(Evt::Meta(meta_one(id, "❤", ik(2)))); // peer отреагировал на моё
        let m = app.messages[&ik(2)][0].clone();
        assert_eq!(
            app.reactions_of(&m),
            vec![("❤".to_string(), 1, false)],
            "своё сообщение джойнится по own-автору; реагировал peer → mine=false"
        );
    }

    #[test]
    fn reaction_lands_only_on_same_second_matching_text() {
        // Дискриминирующий против ts-коллизии: два входящих в ОДНУ секунду, разный
        // текст. Реакция стоит только на 'second'. Если убрать текст из msg_id — оба
        // сматчатся и 'first' тоже покажет реакцию (тест краснеет).
        let mut app = App::new();
        app.own_ik = Some(ik(1));
        app.selected = Some(ik(2));
        app.messages.entry(ik(2)).or_default().push(ChatMsg::incoming(false, "first".into(), 100));
        app.messages.entry(ik(2)).or_default().push(ChatMsg::incoming(false, "second".into(), 100));
        let id2 = client::content::msg_id(&ik(2), 100, b"second");
        app.apply(Evt::Meta(meta_one(id2, "🔥", ik(2))));
        let msgs = app.messages[&ik(2)].clone();
        assert!(app.reactions_of(&msgs[0]).is_empty(), "'first' без реакции");
        assert_eq!(app.reactions_of(&msgs[1]).len(), 1, "'second' с реакцией");
    }

    #[test]
    fn action_react_toggles_optimistically_and_emits_react_cmd() {
        let mut app = App::new();
        app.own_ik = Some(ik(1));
        app.selected = Some(ik(2));
        app.messages.entry(ik(2)).or_default().push(ChatMsg::incoming(false, "hi".into(), 100));
        // Первый клик — поставить.
        match app.action_react(false, 100, "hi", "👍").expect("cmd") {
            Cmd::React { to_ik, emoji, add, .. } => {
                assert_eq!(to_ik, ik(2));
                assert_eq!(emoji, "👍");
                assert!(add, "первый клик ставит");
            }
            _ => panic!("ожидался Cmd::React"),
        }
        let m = app.messages[&ik(2)][0].clone();
        assert_eq!(
            app.reactions_of(&m),
            vec![("👍".to_string(), 1, true)],
            "оптимистично показана МОЯ реакция (mine=true)"
        );
        // Второй клик тем же эмодзи — снять (тоггл).
        assert!(
            matches!(app.action_react(false, 100, "hi", "👍"), Some(Cmd::React { add: false, .. })),
            "повтор снимает"
        );
        assert!(app.reactions_of(&m).is_empty(), "оптимистично убрано");
    }

    #[test]
    fn reply_flow_sets_target_emits_sendreply_and_renders_quote() {
        let mut app = App::new();
        app.own_ik = Some(ik(1));
        app.selected = Some(ik(2));
        // Цель — входящее сообщение собеседника.
        app.messages.entry(ik(2)).or_default().push(ChatMsg::incoming(false, "original".into(), 100));
        // Начать ответ: msg_id цели считается по АБСОЛЮТНОМУ автору (peer ik2).
        app.action_begin_reply(false, 100, "original");
        let target = client::content::msg_id(&ik(2), 100, b"original");
        assert_eq!(app.replying.as_ref().unwrap().to, target, "цель ответа — msg_id по peer");
        // Составить и отправить.
        app.in_compose = "my reply".into();
        match app.action_send(200).expect("cmd") {
            Cmd::SendReply { to_ik, reply_to, ts, .. } => {
                assert_eq!((to_ik, ts), (ik(2), 200));
                assert_eq!(reply_to, target, "reply_to = msg_id цели");
            }
            _ => panic!("ожидался Cmd::SendReply"),
        }
        assert!(app.replying.is_none(), "баннер ответа сброшен после отправки");
        // Оптимистичная цитата: моё новое сообщение резолвит цель к её тексту.
        let my = app.messages[&ik(2)].last().unwrap().clone();
        assert_eq!(my.text, "my reply");
        assert_eq!(app.reply_preview_of(&my).as_deref(), Some("original"), "цитата → текст цели");
    }

    #[test]
    fn reply_to_missing_target_renders_unavailable() {
        let mut app = App::new();
        app.own_ik = Some(ik(1));
        app.selected = Some(ik(2));
        // Моё сообщение-ответ есть, а цели в чате нет (удалена/не загружена).
        app.messages.entry(ik(2)).or_default().push(ChatMsg::incoming(true, "reply".into(), 200));
        let my_id = client::content::msg_id(&ik(1), 200, b"reply");
        let mm = client::store::MsgMeta {
            reply_to: Some([0xAB; 16]), // цель, которой нет
            ..Default::default()
        };
        let mut map = client::store::MetaMap::new();
        map.insert(my_id, mm);
        app.apply(Evt::Meta(map));
        let my = app.messages[&ik(2)][0].clone();
        assert_eq!(app.reply_preview_of(&my).as_deref(), Some("message unavailable"));
    }

    #[test]
    fn edit_flow_loads_text_emits_edit_cmd_and_overlays() {
        let mut app = App::new();
        app.own_ik = Some(ik(1));
        app.selected = Some(ik(2));
        // Моё отправленное сообщение.
        app.messages.entry(ik(2)).or_default().push(ChatMsg::incoming(true, "typo".into(), 300));
        // Начать правку: текст грузится в композитор, включается режим.
        app.action_begin_edit(true, 300, "typo");
        assert!(app.is_editing());
        assert_eq!(app.in_compose, "typo", "текущий текст в композиторе");
        // Изменить и сохранить.
        app.in_compose = "fixed".into();
        let target = client::content::msg_id(&ik(1), 300, b"typo");
        match app.action_send(400).expect("cmd") {
            Cmd::EditMessage { to_ik, target_msg_id, new_text, .. } => {
                assert_eq!((to_ik, target_msg_id), (ik(2), target));
                assert_eq!(new_text, "fixed");
            }
            _ => panic!("ожидался Cmd::EditMessage"),
        }
        assert!(!app.is_editing(), "режим правки сброшен");
        // Overlay: сообщение теперь рендерится изменённым текстом.
        let m = app.messages[&ik(2)][0].clone();
        assert_eq!(app.edited_of(&m).as_deref(), Some("fixed"), "показывается изменённый текст");
    }

    #[test]
    fn cannot_begin_edit_of_incoming_or_unaddressable() {
        let mut app = App::new();
        app.own_ik = Some(ik(1));
        app.selected = Some(ik(2));
        app.action_begin_edit(false, 100, "theirs"); // чужое
        assert!(!app.is_editing(), "чужое править нельзя");
        app.action_begin_edit(true, 0, "optimistic"); // неадресуемое
        assert!(!app.is_editing(), "ts=0 не адресуемо");
    }

    #[test]
    fn toggle_block_updates_state_and_emits_cmd() {
        let mut app = App::new();
        assert!(!app.is_blocked(&ik(2)));
        match app.action_toggle_block(ik(2)) {
            Cmd::SetBlocked { ik: k, blocked } => {
                assert_eq!(k, ik(2));
                assert!(blocked, "первый тоггл блокирует");
            }
            _ => panic!("ожидался Cmd::SetBlocked"),
        }
        assert!(app.is_blocked(&ik(2)), "оптимистично заблокирован");
        // Эхо worker'а подтверждает набор.
        app.apply(Evt::Blocked(std::collections::BTreeSet::from([ik(2)])));
        assert!(app.is_blocked(&ik(2)));
        // Повторный тоггл — разблокировать.
        assert!(matches!(app.action_toggle_block(ik(2)), Cmd::SetBlocked { blocked: false, .. }));
        assert!(!app.is_blocked(&ik(2)));
    }

    #[test]
    fn action_react_on_unaddressable_message_is_noop() {
        let mut app = App::new();
        app.own_ik = Some(ik(1));
        app.selected = Some(ik(2));
        // ts=0 — оптимистичное/исчезающее, не имеет сквозного id → без Cmd.
        assert!(app.action_react(true, 0, "x", "👍").is_none());
        // Без выбранного чата — тоже нет.
        app.selected = None;
        assert!(app.action_react(false, 100, "hi", "👍").is_none());
    }

    #[test]
    fn save_profile_updates_own_display_and_emits_cmd() {
        let mut app = App::new();
        app.action_begin_edit_profile();
        app.in_profile_name = "  Alice  ".into(); // whitespace is trimmed
        app.in_profile_bio = "likes crypto".into();
        match app.action_save_profile() {
            Cmd::SaveProfile { name, bio } => {
                assert_eq!(name, "Alice", "name is trimmed");
                assert_eq!(bio, "likes crypto");
            }
            _ => panic!("expected Cmd::SaveProfile"),
        }
        assert_eq!(app.my_name, "Alice", "display updated optimistically");
        assert!(!app.editing_profile, "editor closed after saving");
    }

    #[test]
    fn peer_profile_is_display_hint_and_never_overwrites_contact_label() {
        // HARD trust invariant at the controller level: PeerProfiles is only a display
        // hint; it NEVER changes name/verified in self.contacts. Neuter (if
        // apply(PeerProfiles) starts writing to contacts) -> red.
        let mut app = App::new();
        app.apply(Evt::Contacts(vec![Contact { name: "MyLabel".into(), ik: ik(2), verified: true }]));
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            ik(2),
            client::store::Profile { name: "TheirName".into(), bio: "their bio".into(), avatar: None, photos: vec![], photos_ts: 0 },
        );
        app.apply(Evt::PeerProfiles(map));
        // The contact is untouched.
        let c = app.contacts.iter().find(|c| c.ik == ik(2)).unwrap();
        assert_eq!(c.name, "MyLabel", "local label not overwritten by profile");
        assert!(c.verified, "verified not reset by profile");
        // Hints are available separately.
        assert_eq!(app.peer_declared_name(&ik(2)), Some("TheirName"));
        assert_eq!(app.peer_bio(&ik(2)), Some("their bio"));
    }

    #[test]
    fn profile_echo_does_not_clobber_open_editor() {
        // While the editor is OPEN, the own-profile echo (Evt::Profile) must not
        // overwrite the edit buffers.
        let mut app = App::new();
        app.action_begin_edit_profile();
        app.in_profile_name = "draft".into();
        app.apply(Evt::Profile { name: "old".into(), bio: "old bio".into(), avatar: None });
        assert_eq!(app.in_profile_name, "draft", "open editor not clobbered by echo");
        // With the editor CLOSED, the echo syncs the buffers.
        app.editing_profile = false;
        app.apply(Evt::Profile { name: "new".into(), bio: "new bio".into(), avatar: None });
        assert_eq!(app.in_profile_name, "new");
        assert_eq!(app.my_bio, "new bio");
    }
}
