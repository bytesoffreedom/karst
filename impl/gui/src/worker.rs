//! Worker-поток: владеет `Store` (unlock один раз) и делает всю сеть/диск в фоне,
//! чтобы UI-поток НИКОГДА не блокировался. Вызывает `client::*` ДОСЛОВНО — ноль
//! новой крипты, все инварименты остаются в верифицированной библиотеке.
//!
//! Цикл: `recv_timeout(poll_interval)` — команда обрабатывается сразу, таймаут =
//! фоновый poll входящих. Один поток, без busy-wait. **Poll тоже дренит mailbox**
//! → at-most-once применяется и к фоновому опросу (см. границу истории).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use client::content::{self, Assembled, Content, Reassembler};
use client::store::{AccountEntry, ContactRecord, HistoryRecord, Store, Vault};
use client::RelayId;
use crate::controller::{AccountInfo, Cmd, Contact, Evt, ExpiringIn, IncomingText, StatusMsg};

pub struct WorkerCfg {
    pub dir: PathBuf,
    pub poll_interval: Duration,
    /// Emit loop cover traffic (§2.2). A knob rather than a constant because cover is a
    /// permanent bandwidth and battery tax and competes with real sends for the capability
    /// quota — a cost the user is entitled to decline. Tests turn it OFF so their assertions
    /// measure the traffic they generate, not the traffic they hide in.
    pub cover_traffic: bool,
}

/// Состояние после разблокировки: открытый vault + активный аккаунт + relay.
struct Session {
    /// Разблокированное мультиаккаунтное хранилище (общий ключ устройства).
    vault: Vault,
    /// id активного аккаунта (`accounts/<id>`).
    active_id: String,
    /// Store активного аккаунта (= `vault.account(active_id)`).
    store: Store,
    /// §2.1-IK активного аккаунта — автор СВОИХ реакций и вход в `msg_id` для
    /// исходящих сообщений при чистке метаданных.
    own_ik: [u8; 32],
    /// IK, от которых НЕ принимаем входящее (блок-лист, at-rest). Enforce в начале
    /// приёма: сообщения/реакции/правки/tombstone'ы заблокированного дропаются.
    blocked: std::collections::BTreeSet<[u8; 32]>,
    /// Relays this account is reachable through (multi-homing). NON-EMPTY: the PRIMARY is
    /// `relays[0]` — send/publish/blob still go only there — and any secondaries follow.
    /// Receive polls the whole set (see `poll`).
    relays: Vec<client::Relay>,
    /// Пересборка входящих файлов ПО ОТПРАВИТЕЛЮ (чанки не смешиваются между
    /// отправителями). Живёт между poll'ами в памяти процесса.
    reasm: HashMap<[u8; 32], Reassembler>,
    /// Считаем ли себя на связи с relay (для индикатора). Дебаунс: флип в
    /// «нет связи» только после 2+ подряд провалов опроса (один транзиентный
    /// провал раз в 2 с не должен мигать индикатором).
    net_up: bool,
    net_fails: u32,
    /// Last per-relay reachability we told the UI, aligned to `relays` (index 0 = primary).
    /// The aggregate `net_up` above is the debounced PRIMARY light; this is the raw per-poll
    /// up/down of the WHOLE set, so a user can see "primary blocked, backup carrying me" — the
    /// signal that matters under blocking. Emitted only on CHANGE (see `note_relay_health`).
    relay_health: Vec<bool>,
}

impl Session {
    /// The primary relay (`relays[0]`) — send, publish and blob transfers use only this one
    /// until publish-to-all and send-side relay selection land. Held non-empty by
    /// construction (`account_session`).
    fn primary(&self) -> &client::Relay {
        &self.relays[0]
    }
}

/// Отметить исход сетевой операции (публикация/опрос — достижимость relay) с
/// дебаунсом. Send-к-конкретному-получателю СЮДА НЕ идёт (его провал = получатель
/// офлайн, а не потеря связи). Эмитит `Evt::Connection` только на СМЕНЕ состояния.
fn note_net(s: &mut Session, ok: bool, evt_tx: &Sender<Evt>) {
    if ok {
        s.net_fails = 0;
        if !s.net_up {
            s.net_up = true;
            let _ = evt_tx.send(Evt::Connection(true));
        }
    } else {
        s.net_fails += 1;
        if s.net_up && s.net_fails >= 2 {
            s.net_up = false;
            let _ = evt_tx.send(Evt::Connection(false));
        }
    }
}

/// Emit per-relay reachability for the whole multi-homed set. `failed` holds the relays that
/// did not answer THIS poll, by their position in `s.relays` (primary = 0). Unlike the
/// aggregate `note_net` there is no debounce here — a backup dot flickering on a transient
/// miss is honest, secondary information, not the headline alarm — but we send only when the
/// vector actually CHANGES, so a steady set produces no channel churn.
fn note_relay_health(s: &mut Session, failed: &[usize], evt_tx: &Sender<Evt>) {
    let health: Vec<bool> = (0..s.relays.len()).map(|i| !failed.contains(&i)).collect();
    if health != s.relay_health {
        s.relay_health = health.clone();
        let _ = evt_tx.send(Evt::RelayHealth(health));
    }
}

fn wall_clock() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Прочитать карту реакций с диска и отдать её UI (полная замена). Best-effort:
/// метаданные не критичны, ошибку чтения глотаем (история уже показана).
fn emit_meta(s: &Session, evt_tx: &Sender<Evt>) {
    if let Ok(map) = s.store.load_meta() {
        let _ = evt_tx.send(Evt::Meta(map));
    }
}

/// `msg_id`'ы удалённых из истории записей. Автор АБСОЛЮТНЫЙ (исходящее — own_ik,
/// входящее — peer_ik), как и обе стороны — так чистим ту же запись метаданных.
fn removed_msg_ids(s: &Session, removed: &[client::store::HistoryRecord]) -> Vec<[u8; 16]> {
    removed
        .iter()
        .map(|r| {
            let author = if r.from_me { s.own_ik } else { r.peer_ik };
            client::content::msg_id(&author, r.ts, &r.text)
        })
        .collect()
}

/// Почистить метаданные удалённых записей и обновить UI (для one-shot команд:
/// delete/clear/tombstone). Вызывать ПОСЛЕ rewrite_history.
fn prune_meta_for_removed(s: &Session, removed: &[client::store::HistoryRecord], evt_tx: &Sender<Evt>) {
    let ids = removed_msg_ids(s, removed);
    if ids.is_empty() {
        return;
    }
    let _ = s.store.prune_meta(&ids);
    emit_meta(s, evt_tx);
}

/// Poll-cadence jitter (§2.2 metadata hardening): a FIXED poll interval gives the
/// relay connection a robotic heartbeat an observer can fingerprint ("polls every
/// 2.000 s → KARST"). This spreads each idle wait uniformly over ±25% of the base
/// so there is no constant cadence to match. Non-crypto `xorshift64` is deliberate —
/// the jitter is not a secret; it must not draw from (or drain)
/// any cryptographic RNG. This kills a timing TELL; it does not hide that you use KARST.
struct Jitter {
    state: u64,
}

impl Jitter {
    fn new(seed: u64) -> Self {
        // xorshift64 needs a non-zero state.
        Jitter { state: seed | 1 }
    }

    /// Seed from the wall clock's sub-second nanos — enough entropy to decorrelate
    /// two clients' cadences; determinism is irrelevant here.
    fn from_time() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(1) as u64;
        Jitter::new(nanos.wrapping_mul(0x9E37_79B9_7F4A_7C15))
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// A jittered interval uniform in `[base*0.75, base*1.25]`. `base == 0` stays 0.
    fn interval(&mut self, base: Duration) -> Duration {
        let b = base.as_millis() as u64;
        if b == 0 {
            return Duration::ZERO;
        }
        let quarter = b / 4;
        let low = b - quarter; // 0.75 * base
        let window = quarter * 2 + 1; // 0.5 * base (+1 so the top is reachable)
        Duration::from_millis(low + self.next_u64() % window)
    }

    /// An exponentially-distributed delay with mean `mean` — the gap between two events
    /// of a Poisson process.
    ///
    /// The distribution is the mechanism, not decoration. An exponential is MEMORYLESS:
    /// how long you have waited tells you nothing about how much longer you will wait. A
    /// uniform gap does not have that property — watch a few cover messages and the
    /// window they must fall in is bounded, so the relay learns the cover rate, subtracts
    /// it, and reads the real traffic underneath. Loopix's point is precisely that no
    /// amount of observation sharpens the estimate.
    fn poisson_delay(&mut self, mean: Duration) -> Duration {
        // Inverse-transform: -mean * ln(U), U uniform in (0, 1].
        let u = (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        let u = if u <= 0.0 { f64::MIN_POSITIVE } else { u };
        let secs = -mean.as_secs_f64() * u.ln();
        // Clamp the tail: an exponential is unbounded, and a draw that parks cover traffic
        // for an hour is indistinguishable from having none.
        Duration::from_secs_f64(secs.min(mean.as_secs_f64() * 8.0))
    }
}

/// How often, on average, an idle client emits a loop. Cover traffic is a bandwidth and
/// battery tax charged forever, so the rate is a real cost, not a free win.
///
/// It also competes with real sends for the capability quota, but only through its
/// DEPOSIT: a loop costs one metered request, while the fetches that read it back are
/// free (`handle_fetch` charges no quota). At one loop a minute that is ~10 of the 100
/// requests per 600 s — real, modest, and worth stating precisely rather than as a vague
/// warning. Enough to deny "this client is silent, so its user is not writing" without
/// crowding out the traffic it exists to hide.
const LOOP_MEAN: Duration = Duration::from_secs(60);

/// Registry of in-flight large-file transfers: `id → cancel flag`. The transfer
/// thread holds an `Arc` clone and checks it on each chunk boundary;
/// `Cmd::CancelTransfer` sets it; the terminal arm (`BlobUploadDone`/
/// `BlobDownloadDone`) removes the entry.
type Transfers = HashMap<u64, Arc<AtomicBool>>;

/// Run the worker loop (blocking; spin it on its own thread). `cmd_tx` is a clone of
/// the same channel's sender: file-transfer threads post internal Cmds back through it.
pub fn run(cfg: WorkerCfg, cmd_rx: Receiver<Cmd>, cmd_tx: Sender<Cmd>, evt_tx: Sender<Evt>) {
    let mut session: Option<Session> = None;
    let mut jitter = Jitter::from_time();
    let mut transfers: Transfers = HashMap::new();
    // Cover traffic runs on its own Poisson schedule, deliberately NOT tied to the poll
    // cadence: a loop that rode every Nth poll would be a periodic signal wearing a
    // random costume, and the relay would filter it out by period alone.
    let mut next_loop = Instant::now() + jitter.poisson_delay(LOOP_MEAN);
    loop {
        let was_up = session.is_some();
        // Fresh jittered timeout each wait → no constant poll heartbeat.
        match cmd_rx.recv_timeout(jitter.interval(cfg.poll_interval)) {
            Ok(cmd) => handle(cmd, &cfg, &mut session, &cmd_tx, &evt_tx, &mut transfers),
            Err(RecvTimeoutError::Timeout) => {
                if let Some(s) = &mut session {
                    poll(s, &cmd_tx, &evt_tx, &mut transfers);
                }
            }
            Err(RecvTimeoutError::Disconnected) => break, // UI закрылся
        }
        // A session just came up (login / restart after a crash) → resume any large-file uploads
        // that were interrupted mid-flight (their resumable records survived on disk).
        if !was_up {
            if let Some(s) = &session {
                resume_pending_uploads(s, &cmd_tx, &evt_tx, &mut transfers);
            }
        }
        if cfg.cover_traffic && Instant::now() >= next_loop {
            if let Some(s) = &mut session {
                send_cover(s, &evt_tx);
            }
            next_loop = Instant::now() + jitter.poisson_delay(LOOP_MEAN);
        }
    }
}

/// Emit one loop. A failure here is NOT shown to the user: cover traffic is not their
/// errand, and a toast saying "cover failed" would announce, to anyone glancing at the
/// screen, that this client sends cover at all. It is also not worth a `net_fails` tick —
/// the real poll already tracks reachability, and letting cover drive the network
/// indicator would put a fake-traffic failure in front of the user as a connection
/// problem.
fn send_cover(s: &mut Session, evt_tx: &Sender<Evt>) {
    let _ = evt_tx;
    let _ = client::send_loop(&s.store, s.primary(), wall_clock());
}

fn handle(
    cmd: Cmd,
    cfg: &WorkerCfg,
    session: &mut Option<Session>,
    cmd_tx: &Sender<Cmd>,
    evt_tx: &Sender<Evt>,
    transfers: &mut Transfers,
) {
    match cmd {
        Cmd::Unlock { passphrase, relay_addr, relay_id, socks5, routes, extra_relays } => {
            // Разблокировка устройства (возврат): открыть vault, выбрать активный
            // (первый в реестре) аккаунт. Vault::unlock мигрирует legacy при нужде.
            let r = (|| {
                // The vault opens FIRST: the saved network config is encrypted at rest,
                // so it can only be read once the passphrase is in. That is why the
                // login screen needs only the passphrase on later launches.
                let vault = Vault::unlock(&cfg.dir, passphrase.as_bytes())
                    .map_err(|e| format!("opening the vault: {e}"))?;
                let reg = vault.load_registry().map_err(|e| e.to_string())?;
                let active = reg
                    .first()
                    .map(|e| e.id.clone())
                    .ok_or("no accounts in this profile yet — create or restore one")?;
                // The config belongs to the ACCOUNT, not the device: an account is an
                // identity, and a compartment is an identity plus its own relay.
                let relays = relays_for_account(&vault, &active, &relay_addr, &relay_id, &socks5, &routes, &extra_relays)?;
                account_session(vault, active, relays)
            })();
            enter(r, session, evt_tx);
        }
        Cmd::Provision { passphrase, phrase, relay_addr, relay_id, socks5, routes, extra_relays } => {
            // ПЕРВЫЙ аккаунт: задаёт пароль устройства (создаёт vault) + relay.
            // Валидируем фразу и сеть ДО записи (битый ввод не должен оставить след).
            let r = (|| {
                let m = client::seed::parse_mnemonic(&phrase)?;
                // Validate the network BEFORE writing anything: bad input must not
                // leave a half-provisioned profile behind.
                parse_net(&relay_addr, &relay_id, &socks5, &routes)?;
                let vault = Vault::unlock(&cfg.dir, passphrase.as_bytes())
                    .map_err(|e| format!("opening the vault: {e}"))?;
                let id = provision_account(&vault, &client::seed::entropy_of(&m), "")?;
                remember_net(&vault, &id, &relay_addr, &relay_id, &socks5, &routes);
                // Build the set from the just-saved config (primary) plus any secondaries the
                // user entered; `relays_for_account` persists and validates them.
                let relays = relays_for_account(&vault, &id, "", "", "", "", &extra_relays)?;
                account_session(vault, id, relays)
            })();
            enter(r, session, evt_tx);
        }
        Cmd::AddAccount { phrase, label } => {
            // ДОБАВИТЬ аккаунт к уже разблокированному vault (без пароля) и
            // переключиться. При ошибке активная сессия не теряется (клон vault).
            let Some(s) = session.as_ref() else {
                let _ = evt_tx.send(Evt::Status(StatusMsg::LogInFirst));
                return;
            };
            let (vault, relays) = (s.vault.clone(), s.relays.clone());
            // The new account INHERITS this one's network config — otherwise it has no
            // relay and simply does not work. Be honest about what that makes it: a
            // CO-TENANT on the same relay, not a compartment. Two identities in one room
            // are linked by IP + timing whatever their keys are. It becomes a compartment
            // only when the user gives it a relay of its own.
            let inherited = s.store.load_net().unwrap_or_default();
            let inherited_extras = s.store.load_extra_relays().unwrap_or_default();
            let r = (|| {
                let m = client::seed::parse_mnemonic(&phrase)?;
                let id = provision_account(&vault, &client::seed::entropy_of(&m), label.trim())?;
                if let Err(e) = vault.account(&id).save_net(&inherited) {
                    eprintln!("could not seed the new account's network config: {e}");
                }
                if let Err(e) = vault.account(&id).save_extra_relays(&inherited_extras) {
                    eprintln!("could not seed the new account's secondary relays: {e}");
                }
                account_session(vault, id, relays)
            })();
            enter(r, session, evt_tx);
        }
        Cmd::SwitchAccount { id } => {
            // Переключиться в пределах vault (без Argon2). Клон vault → при ошибке
            // старая сессия цела.
            let Some(s) = session.as_ref() else { return };
            let vault = s.vault.clone();
            let r = (|| {
                // Rebuild the relay from the TARGET account's config. Reusing the
                // previous account's relay (what this used to do) is what made accounts
                // decorative as compartments: separate keys meeting in the same room,
                // linked by IP + timing regardless.
                let relays = relays_for_account(&vault, &id, "", "", "", "", "")?;
                account_session(vault, id, relays)
            })();
            enter(r, session, evt_tx);
        }
        Cmd::Send { to_ik, text, id, ts } => {
            let Some(s) = session else {
                let _ = evt_tx.send(Evt::Status(StatusMsg::UnlockFirst));
                let _ = evt_tx.send(Evt::SendResult { id, ok: false });
                return;
            };
            let res = client::send_text(
                &s.store,
                s.primary(),
                &to_ik,
                text.as_bytes(),
                ts,          // штамп сообщения (сквозной id) = ts контроллера
                wall_clock(), // admission-часы
            );
            match res {
                // Логируем исходящее в историю ТОЛЬКО после успеха: провал отправки
                // не должен долговечно остаться как «доставлено» (та самая
                // оптимистичная граница, но на диске). На рестарте упавшая отправка
                // корректно исчезнет — строго лучше нынешнего in-memory поведения.
                Ok(_) => {
                    let rec = HistoryRecord {
                        from_me: true,
                        peer_ik: to_ik,
                        text: text.into_bytes(),
                        // ts КОНТРОЛЛЕРА (не wall_clock): совпадёт с ChatMsg в памяти,
                        // чтобы удаление по (ts,from_me,text) нашло запись.
                        ts,
                    };
                    if let Err(e) = s.store.append_history(&rec) {
                        let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("history (sent): {e}"))));
                    }
                    let _ = evt_tx.send(Evt::SendResult { id, ok: true });
                }
                Err(e) => {
                    let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("send failed: {e}"))));
                    let _ = evt_tx.send(Evt::SendResult { id, ok: false });
                }
            }
        }
        Cmd::SendReply { to_ik, text, id, ts, reply_to } => {
            let Some(s) = session else {
                let _ = evt_tx.send(Evt::Status(StatusMsg::UnlockFirst));
                let _ = evt_tx.send(Evt::SendResult { id, ok: false });
                return;
            };
            let res = client::send_text_reply(
                &s.store, s.primary(), &to_ik, text.as_bytes(), ts, reply_to,
                wall_clock(),
            );
            match res {
                Ok(()) => {
                    let rec =
                        HistoryRecord { from_me: true, peer_ik: to_ik, text: text.into_bytes(), ts };
                    if let Err(e) = s.store.append_history(&rec) {
                        let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("history (reply): {e}"))));
                    }
                    // Связь «мой ответ → цель» по каноническому msg_id моего сообщения.
                    let my_id = client::content::msg_id(&s.own_ik, ts, &rec.text);
                    let _ = s.store.set_reply(my_id, reply_to);
                    emit_meta(s, evt_tx);
                    let _ = evt_tx.send(Evt::SendResult { id, ok: true });
                }
                Err(e) => {
                    let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("reply not sent: {e}"))));
                    let _ = evt_tx.send(Evt::SendResult { id, ok: false });
                }
            }
        }
        Cmd::SendExpiring { to_ik, text, id, ttl_secs } => {
            let Some(s) = session else {
                let _ = evt_tx.send(Evt::Status(StatusMsg::UnlockFirst));
                let _ = evt_tx.send(Evt::SendResult { id, ok: false });
                return;
            };
            let res = client::send_text_expiring(
                &s.store,
                s.primary(),
                &to_ik,
                text.as_bytes(),
                ttl_secs,
                wall_clock(),
            );
            match res {
                // НЕ логируем в историю: исчезающие живут только в памяти (never-persist).
                Ok(()) => {
                    let _ = evt_tx.send(Evt::SendResult { id, ok: true });
                }
                Err(e) => {
                    let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("send failed: {e}"))));
                    let _ = evt_tx.send(Evt::SendResult { id, ok: false });
                }
            }
        }
        Cmd::SendFile { to_ik, path, id, ts } => {
            let Some(s) = session else {
                let _ = evt_tx.send(Evt::Status(StatusMsg::UnlockFirst));
                let _ = evt_tx.send(Evt::SendResult { id, ok: false });
                return;
            };
            let name = basename(&path);
            let size = match std::fs::metadata(&path) {
                Ok(m) => m.len(),
                Err(e) => {
                    let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("reading file {path}: {e}"))));
                    let _ = evt_tx.send(Evt::SendResult { id, ok: false });
                    return;
                }
            };
            // Dual-path §15: small files ride the inline padded-mailbox path (so §2.2
            // fixed-size fetch still hides them, synchronously — they finish in a blink);
            // large files stream up as an E2E blob OFF-LOOP (a spawned thread; the worker
            // keeps polling/sending) and travel as a small `FileRef`.
            if size <= client::content::MAX_FILE_SIZE {
                let res = match std::fs::read(&path) {
                    Ok(bytes) => client::send_file(&s.store, s.primary(), &to_ik, &name, &bytes, wall_clock()),
                    Err(e) => Err(format!("reading file {path}: {e}")),
                };
                match res {
                    // Ссылка на файл в историю ТОЛЬКО после успеха (не байты — иначе
                    // раздули бы append-лог). Байты у отправителя уже на диске.
                    Ok(()) => {
                        let rec = HistoryRecord {
                            from_me: true,
                            peer_ik: to_ik,
                            text: format!("📎 {name}").into_bytes(),
                            ts, // ts контроллера — совпадение память↔диск
                        };
                        let _ = s.store.append_history(&rec);
                        let _ = evt_tx.send(Evt::Status(StatusMsg::FileSent(name)));
                        let _ = evt_tx.send(Evt::SendResult { id, ok: true });
                    }
                    Err(e) => {
                        let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("file send failed: {e}"))));
                        let _ = evt_tx.send(Evt::SendResult { id, ok: false });
                    }
                }
            } else {
                spawn_blob_upload(s, to_ik, path, name, size, id, ts, cmd_tx, evt_tx, transfers);
            }
        }
        Cmd::SaveContacts { id, contacts } => {
            let Some(s) = session else { return };
            let recs: Vec<ContactRecord> = contacts
                .into_iter()
                .map(|c| ContactRecord { name: c.name, ik: c.ik, verified: c.verified })
                .collect();
            // Пишем в аккаунт `id` через vault (а НЕ в live-сессию `s.store`): к моменту
            // обработки этой команды сессия могла уже переключиться на другой аккаунт.
            if let Err(e) = s.vault.account(&id).save_contacts(&recs) {
                let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("saving contacts: {e}"))));
            }
        }
        Cmd::ClearChat { ik } => {
            // Стереть переписку с `ik` на диске активного аккаунта (оставить чужие).
            // Прямое действие по видимому чату — по live-сессии (как Send/SendFile);
            // переключение аккаунта — отдельный клик в другом кадре, гонки нет.
            let Some(s) = session else { return };
            match s.store.rewrite_history(|r| r.peer_ik != ik) {
                Ok(removed) => prune_meta_for_removed(s, &removed, evt_tx),
                Err(e) => {
                    let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("clearing history: {e}"))));
                }
            }
        }
        Cmd::DeleteMessage { ik, ts, from_me, text } => {
            // Удалить одну запись у себя: тот же примитив перезаписи, что и ClearChat.
            let Some(s) = session else { return };
            let want = text.into_bytes();
            match s.store.rewrite_history(|r| {
                !(r.peer_ik == ik && r.ts == ts && r.from_me == from_me && r.text == want)
            }) {
                Ok(removed) => prune_meta_for_removed(s, &removed, evt_tx),
                Err(e) => {
                    let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("deleting message: {e}"))));
                }
            }
        }
        Cmd::DeleteForEveryone { to_ik, ts, text } => {
            // Стереть СВОЮ копию (from_me=true) и попросить получателя стереть свою.
            let Some(s) = session else { return };
            let want = text.clone().into_bytes();
            if let Ok(removed) = s.store.rewrite_history(|r| {
                !(r.peer_ik == to_ik && r.ts == ts && r.from_me && r.text == want)
            }) {
                prune_meta_for_removed(s, &removed, evt_tx);
            }
            if let Err(e) = client::send_delete_for_everyone(
                &s.store, s.primary(), &to_ik, ts, text.as_bytes(), wall_clock(),
            ) {
                let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("delete for everyone: {e}"))));
            }
        }
        Cmd::React { to_ik, msg_id, emoji, add } => {
            // Локально персистим (автор = own_ik), затем шлём control-конверт
            // получателю и обновляем UI полной картой. Ошибку записи/отправки —
            // в статус; UI уже показал оптимистично.
            let Some(s) = session else { return };
            if let Err(e) = s.store.set_reaction(msg_id, &emoji, s.own_ik, add) {
                let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("reaction: {e}"))));
                return;
            }
            emit_meta(s, evt_tx);
            if let Err(e) = client::send_reaction(
                &s.store, s.primary(), &to_ik, msg_id, &emoji, add, wall_clock(),
            ) {
                let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("reaction not sent: {e}"))));
            }
        }
        Cmd::EditMessage { to_ik, target_msg_id, new_text, edit_ts } => {
            // Правлю СВОЁ сообщение: overlay локально + кооперативная просьба пиру.
            let Some(s) = session else { return };
            if let Err(e) = s.store.set_edit(target_msg_id, edit_ts, new_text.as_bytes()) {
                let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("edit: {e}"))));
                return;
            }
            emit_meta(s, evt_tx);
            if let Err(e) = client::send_edit_message(
                &s.store, s.primary(), &to_ik, target_msg_id,
                new_text.as_bytes(), edit_ts, wall_clock(),
            ) {
                let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("edit not sent: {e}"))));
            }
        }
        Cmd::SetBlocked { ik, blocked } => {
            // Персист + обновить enforcement-набор сессии + эхо в UI. Прошлые
            // сообщения остаются; блок гейтит только новое входящее.
            let Some(s) = session else { return };
            if let Err(e) = s.store.set_blocked(ik, blocked) {
                let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("block: {e}"))));
                return;
            }
            s.blocked = s.store.load_blocked().unwrap_or_default();
            let _ = evt_tx.send(Evt::Blocked(s.blocked.clone()));
        }
        Cmd::SaveProfile { name, bio } => {
            // Write OWN profile (preserving an already-set avatar — Phase 2), echo it
            // back to the UI, and LAZILY broadcast to contacts over E2E (explicit
            // change, not an auto-rebroadcast on launch).
            let Some(s) = session else { return };
            let mut prof = s.store.load_profile().unwrap_or_default();
            prof.name = name.clone();
            prof.bio = bio.clone();
            if let Err(e) = s.store.save_profile(&prof) {
                let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("profile: {e}"))));
                return;
            }
            let _ = evt_tx.send(Evt::Profile {
                name: prof.name.clone(),
                bio: prof.bio.clone(),
                avatar: prof.avatar.clone(),
            });
            let contacts = s.store.load_contacts().unwrap_or_default();
            let mut failed = 0usize;
            for c in &contacts {
                // Do NOT emit our profile to a blocked contact — block means no
                // relationship in either direction; emitting name+bio would leak.
                if s.blocked.contains(&c.ik) {
                    continue;
                }
                if client::send_profile(
                    &s.store, s.primary(), &c.ik, &prof.name, &prof.bio,
                    wall_clock(),
                )
                .is_err()
                {
                    failed += 1;
                }
            }
            if failed > 0 {
                let _ = evt_tx.send(Evt::Status(StatusMsg::ProfileNotDelivered(failed)));
            }
        }
        Cmd::SetAvatar { path } => {
            // Read the picked file, bounded-decode + re-encode (PNG), store, broadcast
            // to non-blocked contacts, echo the updated own profile.
            let Some(s) = session else { return };
            let raw = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("avatar: cannot read file: {e}"))));
                    return;
                }
            };
            let clean = match crate::avatar::ingest(&raw) {
                Ok(b) => b,
                Err(e) => {
                    let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("avatar: {e}"))));
                    return;
                }
            };
            if let Err(e) = s.store.set_own_avatar(Some(clean.clone())) {
                let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("avatar: {e}"))));
                return;
            }
            let prof = s.store.load_profile().unwrap_or_default();
            let _ = evt_tx.send(Evt::Profile { name: prof.name, bio: prof.bio, avatar: prof.avatar });
            broadcast_avatar(s, &clean, evt_tx);
        }
        Cmd::RemoveAvatar => {
            let Some(s) = session else { return };
            if let Err(e) = s.store.set_own_avatar(None) {
                let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("avatar: {e}"))));
                return;
            }
            let prof = s.store.load_profile().unwrap_or_default();
            let _ = evt_tx.send(Evt::Profile { name: prof.name, bio: prof.bio, avatar: prof.avatar });
        }
        Cmd::CancelTransfer { id } => {
            // Set the cancel flag of an in-flight transfer; the thread ends with an
            // Err on the next chunk boundary and posts BlobUploadDone/BlobDownloadDone
            // carrying None.
            if let Some(flag) = transfers.get(&id) {
                flag.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
        Cmd::BlobUploadDone { id, to_ik, name, size, ts, blob } => {
            transfers.remove(&id);
            let Some(s) = session else { return };
            // Any terminal outcome (sent, failed, or cancelled) clears the resumable record — only
            // a CRASH (no BlobUploadDone at all) leaves it, to be resumed on the next login.
            let _ = s.store.remove_pending_upload(&client::upload_id_for(&to_ik, &name, size));
            match blob {
                Some((blob_id, key, hash, chunks)) => {
                    // The ratchet part runs ON THIS THREAD (the sole session owner):
                    // send the tiny FileRef over §2.1. The long upload is already done
                    // by the spawned thread.
                    let fileref = client::content::Content::FileRef {
                        blob_id,
                        key,
                        hash,
                        name: name.clone(),
                        size,
                        chunks,
                    };
                    match client::send_session(
                        &s.store,
                        s.primary(),
                        &to_ik,
                        &client::content::encode(&fileref),
                        // The admission clock, NOT `ts`. `ts` is the message's display
                        // timestamp — the caller's to choose, and 0 in tests. It was
                        // passed here for a while and looked harmless because `now` only
                        // fed cookie freshness, which the relay judges by its own clock.
                        // It stopped being harmless when `now` started picking the
                        // drop-box epoch: a `ts` of 0 deposits into epoch 0, which no
                        // recipient polls.
                        wall_clock(),
                    ) {
                        Ok(_) => {
                            let rec = HistoryRecord {
                                from_me: true,
                                peer_ik: to_ik,
                                text: format!("📎 {name}").into_bytes(),
                                ts,
                            };
                            let _ = s.store.append_history(&rec);
                            let _ = evt_tx.send(Evt::Status(StatusMsg::FileSent(name)));
                            let _ = evt_tx.send(Evt::SendResult { id, ok: true });
                        }
                        Err(e) => {
                            let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("send failed: {e}"))));
                            let _ = evt_tx.send(Evt::SendResult { id, ok: false });
                        }
                    }
                }
                None => {
                    // Upload failed/cancelled — mark the bubble Failed (clears the bar).
                    let _ = evt_tx.send(Evt::SendResult { id, ok: false });
                }
            }
        }
        Cmd::BlobDownloadDone { id, sender, name, ts, path } => {
            transfers.remove(&id);
            let Some(s) = session else { return };
            match path {
                Some(path) => {
                    let rec = HistoryRecord {
                        from_me: false,
                        peer_ik: sender,
                        text: format!("📎 {name}").into_bytes(),
                        ts,
                    };
                    let _ = s.store.append_history(&rec);
                    let _ = evt_tx.send(Evt::FileReceived { sender, name, file_id: path, ts, id });
                }
                None => {
                    // Download failed/cancelled — mark the receiving bubble Failed.
                    let _ = evt_tx.send(Evt::SendResult { id, ok: false });
                }
            }
        }
        Cmd::ShareRoutes { to_ik } => {
            let Some(s) = session else {
                let _ = evt_tx.send(Evt::Status(StatusMsg::UnlockFirst));
                return;
            };
            // Offer everything I know for THIS relay: my primary endpoint plus my
            // configured extras. The recipient can only act on it if it is the relay
            // they already use (Noise authenticates that identity).
            let saved = s.store.load_net().unwrap_or_default();
            let mine = [s.primary().addr.to_string(), saved.routes]
                .into_iter()
                .filter(|v| !v.trim().is_empty())
                .collect::<Vec<_>>()
                .join(",");
            if let Err(e) = client::send_route_offer(&s.store, s.primary(), &to_ik, &mine, wall_clock()) {
                let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("sharing routes: {e}"))));
            }
        }
        Cmd::AcceptRoutes { routes } => {
            let Some(s) = session else { return };
            // Merge into the saved config and rebuild the path list. The accepted
            // entries still pass the carrier allowlist inside `Relay::configured`, so an
            // offer can widen the options but never lower the protection the user chose.
            let mut net = s.store.load_net().unwrap_or_default();
            let merged = merge_routes(&net.routes, &routes);
            net.routes = merged;
            if let Err(e) = s.store.save_net(&net) {
                let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("saving routes: {e}"))));
                return;
            }
            // Reconfigure the PRIMARY's §15 routes in place; secondaries are untouched.
            let (addr, id, proxy) = { let p = s.primary(); (p.addr.clone(), p.id, p.proxy) };
            s.relays[0] = client::Relay::configured(addr, id, proxy, &net.routes);
        }
        Cmd::ExportFile { file_id, dest } => {
            let Some(s) = session else { return };
            // The one place a received file becomes plaintext — where the user pointed.
            if let Err(e) = s.store.export_received_file(&file_id, std::path::Path::new(&dest)) {
                let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("export failed: {e}"))));
            }
        }
        Cmd::SetNet { relay_addr, relay_id, socks5, routes } => {
            let Some(s) = session.as_ref() else {
                let _ = evt_tx.send(Evt::Status(StatusMsg::UnlockFirst));
                return;
            };
            // Validate + persist on the ACTIVE account, then re-enter on its own relay.
            let (vault, id) = (s.vault.clone(), s.active_id.clone());
            let r = (|| {
                let relays = relays_for_account(&vault, &id, &relay_addr, &relay_id, &socks5, &routes, "")?;
                account_session(vault, id, relays)
            })();
            enter(r, session, evt_tx);
        }
        Cmd::SetExtraRelays { relays } => {
            let Some(s) = session.as_ref() else {
                let _ = evt_tx.send(Evt::Status(StatusMsg::UnlockFirst));
                return;
            };
            // Persist the EXACT set (empty clears it), then re-enter so the relay set — and
            // the `Evt::ExtraRelays` the UI shows — are rebuilt from what was just saved.
            let (vault, id) = (s.vault.clone(), s.active_id.clone());
            let r = (|| {
                vault
                    .account(&id)
                    .save_extra_relays(&relays)
                    .map_err(|e| format!("saving secondary relays: {e}"))?;
                let relays = relays_for_account(&vault, &id, "", "", "", "", "")?;
                account_session(vault, id, relays)
            })();
            enter(r, session, evt_tx);
        }
        Cmd::Poll => {
            if let Some(s) = session {
                poll(s, cmd_tx, evt_tx, transfers);
            }
        }
    }
}

/// Broadcast our (already re-encoded) avatar to all non-blocked contacts over E2E.
/// Same blocked-filter as the text-profile broadcast — no emission to blocked IKs.
fn broadcast_avatar(s: &Session, bytes: &[u8], evt_tx: &Sender<Evt>) {
    let contacts = s.store.load_contacts().unwrap_or_default();
    let mut failed = 0usize;
    for c in &contacts {
        if s.blocked.contains(&c.ik) {
            continue;
        }
        if client::send_avatar(&s.store, s.primary(), &c.ik, bytes, wall_clock())
            .is_err()
        {
            failed += 1;
        }
    }
    if failed > 0 {
        let _ = evt_tx.send(Evt::Status(StatusMsg::AvatarNotDelivered(failed)));
    }
}

/// Emit the full contacts' profile cache to the UI (best-effort).
fn emit_peer_profiles(s: &Session, evt_tx: &Sender<Evt>) {
    let map = s.store.load_peer_profiles().unwrap_or_default();
    let _ = evt_tx.send(Evt::PeerProfiles(map));
}

/// Базовое имя файла из пути (без каталогов).
fn basename(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("file")
        .to_string()
}

/// Собрать сессию из УЖЕ открытого стора (в нём есть корень): распарсить relay/
/// socks, дозавести дев-capability, вывести свой §2.1-IK из корня. Общий хвост
/// для Unlock и Provision.
/// Разобрать и провалидировать сетевые параметры. ВЫЗЫВАЕТСЯ ДО `save_seed` в
/// Provision: иначе битый (непустой, но не-hex) relay-id сохранил бы корень, затем
/// упал — и повтор упёрся бы в «аккаунт уже есть», заклинив экран создания.
/// Merge offered routes into the ones already configured, keeping order and dropping
/// duplicates (an offer usually repeats endpoints you already have).
fn merge_routes(current: &str, offered: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for entry in current.split(',').chain(offered.split(',')).map(str::trim) {
        if entry.is_empty() {
            continue;
        }
        if !out.iter().any(|e| e.eq_ignore_ascii_case(entry)) {
            out.push(entry.to_string());
        }
    }
    out.join(",")
}

/// Build the `Relay` for ONE account: what the user TYPED wins (and is remembered on
/// that account); empty means "use what this account saved". The config is encrypted in
/// the vault, so this only runs post-unlock.
///
/// Per-account is the whole point of a compartment: an account is an identity, and a
/// compartment is an identity **with its own relay**. Two accounts sharing a relay are
/// two names in one room — the relay links them by IP and timing no matter how different
/// the keys are.
///
/// Migrates a pre-compartment vault-level config into the account on first use, so an
/// existing profile does not silently lose its relay and land on "no relay configured".
/// Build this account's relay SET (multi-homing): the primary from its `NetSettings`
/// (typed-in or the saved/legacy config), then every secondary from the `extra_relays`
/// sidecar. The primary is `relays[0]`. Secondaries share the primary's proxy; their own
/// §15 failover routes are a later slice.
fn relays_for_account(
    vault: &Vault,
    account_id: &str,
    relay_addr: &str,
    relay_id: &str,
    socks5: &str,
    routes: &str,
    extra_relays: &str,
) -> Result<Vec<client::Relay>, String> {
    let store = vault.account(account_id);
    // Typed-in secondaries replace the saved list (like the primary fields); empty = keep
    // whatever was saved. Validation is per-entry in the build loop below (bad → skipped).
    if !extra_relays.trim().is_empty() {
        if let Err(e) = store.save_extra_relays(&parse_extra_relays(extra_relays)) {
            eprintln!("could not remember the secondary relays: {e}");
        }
    }
    // Determine the effective primary NetSettings: what the user just typed, or the saved
    // (adopting a legacy device-wide config once) config.
    let net = if relay_id.trim().is_empty() {
        let mut saved =
            store.load_net().map_err(|e| format!("reading the account's network config: {e}"))?;
        if saved.relay_id.trim().is_empty() {
            // Legacy: the config used to live device-wide. Adopt it once, then drop it.
            if let Some(legacy) = vault.legacy_net() {
                if !legacy.relay_id.trim().is_empty() {
                    let _ = store.save_net(&legacy);
                    vault.remove_legacy_net();
                    saved = legacy;
                }
            }
        }
        if saved.relay_id.trim().is_empty() {
            return Err("no relay configured for this account — set the relay address and relay-id".into());
        }
        saved
    } else {
        let typed = client::store::NetSettings {
            relay_addr: relay_addr.trim().to_string(),
            relay_id: relay_id.trim().to_string(),
            socks5: socks5.trim().to_string(),
            routes: routes.trim().to_string(),
        mixnet: false,
        };
        // Validate before persisting: a typo must not be remembered as the config.
        parse_net(&typed.relay_addr, &typed.relay_id, &typed.socks5, &typed.routes)?;
        if let Err(e) = store.save_net(&typed) {
            eprintln!("could not remember the network config: {e}");
        }
        typed
    };

    let primary = parse_net(&net.relay_addr, &net.relay_id, &net.socks5, &net.routes)?;
    let mut relays = vec![primary];
    for (addr, rid) in store.load_extra_relays().unwrap_or_default() {
        // A malformed SECONDARY must never sink the unlock — that would lock the account out
        // over a backup relay (the inverse of the multi-homing resilience). Skip it, keep the
        // primary, same fail-open discipline as `parse_path_specs` for bad routes.
        match parse_net(&addr, &rid, &net.socks5, "") {
            Ok(relay) => relays.push(relay),
            Err(e) => eprintln!("skipping a malformed secondary relay {addr:?}: {e}"),
        }
    }
    Ok(relays)
}

/// Persist the network config on the account just provisioned (best-effort: failing to
/// remember it must not fail the account creation).
fn remember_net(vault: &Vault, account_id: &str, relay_addr: &str, relay_id: &str, socks5: &str, routes: &str) {
    let net = client::store::NetSettings {
        relay_addr: relay_addr.trim().to_string(),
        relay_id: relay_id.trim().to_string(),
        socks5: socks5.trim().to_string(),
        routes: routes.trim().to_string(),
        mixnet: false,
    };
    if let Err(e) = vault.account(account_id).save_net(&net) {
        eprintln!("could not remember the network config: {e}");
    }
}

/// Parse the secondary-relay text (one `addr relay-id` per line) into `(addr, relay_id)`
/// pairs. A malformed line is SKIPPED with a warning — same fail-open discipline as
/// `parse_path_specs`; the addr/relay-id are validated later in `relays_for_account`.
fn parse_extra_relays(s: &str) -> Vec<(String, String)> {
    s.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let mut it = line.split_whitespace();
            match (it.next(), it.next(), it.next()) {
                (Some(addr), Some(rid), None) => Some((addr.to_string(), rid.to_string())),
                _ => {
                    eprintln!("secondary relay: {line:?} is not `addr relay-id` — skipped");
                    None
                }
            }
        })
        .collect()
}

fn parse_net(
    relay_addr: &str,
    relay_id: &str,
    socks5: &str,
    routes: &str,
) -> Result<client::Relay, String> {
    let addr: SocketAddr = relay_addr.parse().map_err(|e| format!("relay address: {e}"))?;
    let id = RelayId::parse(relay_id)?;
    // Пусто → прямое соединение; иначе адрес локального SOCKS-порта PT-клиента.
    let proxy: Option<SocketAddr> = match socks5.trim() {
        "" => None,
        a => Some(a.parse().map_err(|e| format!("SOCKS5 address: {e}"))?),
    };
    // Builds the §15 path list once per session (primary + the routes the user
    // configured in the app; empty `routes` = a single path). Env is NOT consulted
    // here — what the user typed is what is used.
    Ok(client::Relay::configured(addr, id, proxy, routes))
}

/// Завести НОВЫЙ аккаунт в vault из фразы: id = ik-hex (уникален), записать корень,
/// добавить в реестр. Возвращает id. Idempotency-guard: если такой IK уже есть —
/// ошибка (а не дубль). НЕ трогает уже существующие аккаунты.
fn provision_account(
    vault: &Vault,
    entropy: &[u8; client::seed::ENTROPY_BYTES],
    label: &str,
) -> Result<String, String> {
    let ik = client::seed::derive(entropy).account.identity_public();
    let id = hex::encode(ik);
    let mut reg = vault.load_registry().map_err(|e| e.to_string())?;
    if reg.iter().any(|e| e.id == id) {
        return Err("this account is already added".into());
    }
    vault.create_account_dir(&id).map_err(|e| format!("creating the directory: {e}"))?;
    vault.account(&id).save_seed(entropy).map_err(|e| format!("writing the root seed: {e}"))?;
    let label = if label.is_empty() { format!("Account {}", reg.len() + 1) } else { label.to_string() };
    reg.push(AccountEntry { id: id.clone(), label, ik });
    vault.save_registry(&reg).map_err(|e| format!("registry: {e}"))?;
    Ok(id)
}

/// Собрать сессию для аккаунта `id` из разблокированного vault. Дозаводит
/// дев-capability, выводит §2.1-IK, каталог приёма файлов — per-account.
fn account_session(
    vault: Vault,
    id: String,
    relays: Vec<client::Relay>,
) -> Result<(Session, [u8; 32]), String> {
    if relays.is_empty() {
        return Err("no relay configured for this account".into());
    }
    let store = vault.account(&id);
    if !store.has_seed() {
        return Err("the account has no root seed (corrupted?)".into());
    }
    if !store.has_capability() {
        // Дев-capability (локальный тест; секрет публичен) — автопровижининг для GUI.
        store.save_capability(&client::dev_capability()).map_err(|e| e.to_string())?;
    }
    let own_ik = store.load_account().map_err(|e| e.to_string())?.identity_public();
    Ok((
        Session {
            vault,
            active_id: id,
            own_ik,
            blocked: store.load_blocked().unwrap_or_default(),
            store,
            relays,
            reasm: HashMap::new(),
            net_up: false,
            net_fails: 0,
            relay_health: Vec::new(),
        },
        own_ik,
    ))
}

/// Общий вход: при успехе — эмитить IK, СПИСОК АККАУНТОВ, контакты, историю,
/// опубликовать bundle и сохранить сессию; при ошибке — статус. Воронка для
/// Unlock/Provision/AddAccount/SwitchAccount.
fn enter(
    r: Result<(Session, [u8; 32]), String>,
    session: &mut Option<Session>,
    evt_tx: &Sender<Evt>,
) {
    match r {
        Ok((mut s, own_ik)) => {
            let _ = evt_tx.send(Evt::Unlocked { own_ik });
            // Список аккaунтов + активный (для переключателя). Сразу после Unlocked
            // (который сбросил чат-состояние), до Contacts/History.
            match s.vault.load_registry() {
                Ok(reg) => {
                    let list: Vec<AccountInfo> = reg
                        .into_iter()
                        .map(|e| AccountInfo { id: e.id, label: e.label, ik: e.ik })
                        .collect();
                    let _ = evt_tx.send(Evt::Accounts { list, active: s.active_id.clone() });
                }
                Err(e) => {
                    let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("account registry: {e}"))));
                }
            }
            // Контакты (имена + флаг сверки) ПЕРЕД историей: авто-добавление
            // «неизв.» из истории лишь дополнит, а не затрёт названные/сверенные.
            match s.store.load_contacts() {
                Ok(recs) => {
                    let list: Vec<Contact> = recs
                        .into_iter()
                        .map(|r| Contact { name: r.name, ik: r.ik, verified: r.verified })
                        .collect();
                    let _ = evt_tx.send(Evt::Contacts(list));
                }
                Err(e) => {
                    let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("contacts: {e}"))));
                }
            }
            // История чатов с диска (навалом) — чтобы UI сразу показал прошлые
            // сообщения. load_history заодно усекает рваный хвост.
            match s.store.load_history() {
                Ok(recs) => {
                    let _ = evt_tx.send(Evt::History(recs));
                }
                Err(e) => {
                    let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("history: {e}"))));
                }
            }
            // Реакции с диска — джойнятся к истории по msg_id в контроллере.
            emit_meta(&s, evt_tx);
            let _ = evt_tx.send(Evt::Blocked(s.blocked.clone()));
            // Own profile + contacts' profile cache (display hints).
            let prof = s.store.load_profile().unwrap_or_default();
            let _ = evt_tx.send(Evt::Profile { name: prof.name, bio: prof.bio, avatar: prof.avatar });
            emit_peer_profiles(&s, evt_tx);
            // Опубликовать свой bundle (чтобы другие могли инициировать). Успех/
            // провал публикации = достижимость relay → индикатор связи.
            // Report the active §15 carrier (direct/SOCKS5/wss) for the status bar —
            // derived from the SAME inputs `transport()` uses, so it can't lie about
            // whether the SOCKS proxy / wss transport is really in effect.
            let _ = evt_tx.send(Evt::Carrier(s.primary().carrier()));
            // The configured secondary relays, for the UI to display and let the user remove.
            let _ = evt_tx.send(Evt::ExtraRelays(s.store.load_extra_relays().unwrap_or_default()));
            let sm = match publish(&s) {
                Ok(()) => StatusMsg::ReadyToReceive,
                Err(e) => StatusMsg::Error(format!("failed to announce to the server: {e}")),
            };
            let ok = matches!(sm, StatusMsg::ReadyToReceive);
            // Первый успех должен ЭМИТИТЬ Connection(true), поэтому net_up=false→true.
            note_net(&mut s, ok, evt_tx);
            let _ = evt_tx.send(Evt::Status(sm));
            *session = Some(s);
        }
        Err(e) => {
            let _ = evt_tx.send(Evt::Status(StatusMsg::Error(e)));
        }
    }
}

fn publish(s: &Session) -> Result<(), String> {
    let cap = s.store.load_capability().map_err(|e| e.to_string())?;
    // Publish to EVERY relay in the set so a contact can first-contact this account through
    // any of them; the primary carries the one-time prekeys (secondaries fall back to 3-DH).
    // The primary's response drives the indicator; a dead secondary is non-fatal.
    match client::publish_all(&s.store, &s.relays, cap, wall_clock())? {
        node::node::PublishResponse::Published => Ok(()),
        node::node::PublishResponse::Rejected(r) => Err(r),
        node::node::PublishResponse::NeedCookie(_) => Err("unexpected NeedCookie".into()),
    }
}

/// Опросить входящие: расшифровать → РАЗОБРАТЬ контент-конверт. `Text` эмитим как
/// `Received` (текстовые байты — контракт сохранён), файловые чанки собираем в
/// `reasm` и по завершении сохраняем на диск + эмитим `FileReceived`.
fn poll(s: &mut Session, cmd_tx: &Sender<Cmd>, evt_tx: &Sender<Evt>, transfers: &mut Transfers) {
    let msgs = match client::recv_session_multi(&s.store, &s.relays, wall_clock()) {
        Ok(poll) => {
            // Connection indicator tracks the PRIMARY relay only: send/publish still go there
            // alone, so a green light because a SECONDARY answered while the primary is down
            // would lie about whether messages can actually be sent. `failed` holds the
            // relays that did not answer, by their position in `s.relays` (primary = 0).
            note_net(s, !poll.failed.contains(&0), evt_tx);
            // The full-set per-relay view (backup dots) — so a blocked primary with a live
            // backup reads as "still reachable via backup", not a bare red light.
            note_relay_health(s, &poll.failed, evt_tx);
            poll.messages
        }
        Err(e) => {
            // A real fault (no relays / store I/O), not a single relay being unreachable —
            // that is data in `failed`, handled above.
            note_net(s, false, evt_tx);
            let all_down: Vec<usize> = (0..s.relays.len()).collect();
            note_relay_health(s, &all_down, evt_tx);
            let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("poll: {e}"))));
            return;
        }
    };
    let mut texts: Vec<IncomingText> = Vec::new();
    let mut expiring: Vec<ExpiringIn> = Vec::new();
    let mut meta_dirty = false; // накопитель: одна Evt::Meta на весь батч poll'а
    let mut profiles_dirty = false; // accumulator: one Evt::PeerProfiles per batch
    for r in msgs.into_iter().flatten() {
        // Блок-лист: от заблокированного IK НЕ принимаем НИЧЕГО (текст/реакция/
        // правка/tombstone) — дропаем ДО разбора содержимого. Прошлое остаётся.
        if s.blocked.contains(&r.sender) {
            continue;
        }
        match content::decode(&r.plaintext) {
            Ok(Content::TextStamped { text, ts }) => {
                // Штампованный: храним ts ОТПРАВИТЕЛЯ (сквозной id) — так «удалить у
                // всех»/реакции найдут запись на обеих сторонах.
                texts.push(IncomingText { sender: r.sender, plaintext: text, ts })
            }
            Ok(Content::Text(t)) => {
                // Легаси-текст без штампа — ts прибытия (worker-часы).
                texts.push(IncomingText { sender: r.sender, plaintext: t, ts: wall_clock() })
            }
            Ok(Content::TextReply { text, ts, reply_to }) => {
                // Ответ: текст — как обычное входящее (в историю + UI по ts отправителя);
                // связь «отвечает на» — overlay в meta по msg_id ЭТОГО сообщения.
                let my_id = client::content::msg_id(&r.sender, ts, &text);
                if s.store.set_reply(my_id, reply_to).is_ok() {
                    meta_dirty = true;
                }
                texts.push(IncomingText { sender: r.sender, plaintext: text, ts });
            }
            Ok(Content::EditMessage { target_msg_id, new_text, edit_ts }) => {
                // Правка от собеседника. GUARD: применяем ТОЛЬКО если отправитель —
                // автор цели (у нас она входящая от него). Иначе он подменил бы текст
                // вашего/чужого сообщения на вашем экране. Плюс лимит длины.
                if new_text.len() <= client::content::MAX_TEXT_BYTES {
                    let recs = s.store.load_history().unwrap_or_default();
                    if client::incoming_edit_allowed(&recs, &r.sender, target_msg_id)
                        && s.store.set_edit(target_msg_id, edit_ts, &new_text).is_ok()
                    {
                        meta_dirty = true;
                    }
                }
            }
            Ok(Content::DeleteForEveryone { ts, text }) => {
                // Просьба стереть у нас ранее ПРИНЯТОЕ (от этого отправителя) сообщение
                // (from_me=false) с (ts,text). Кооперативно; на диске — тот же примитив.
                let want = text.clone();
                if let Ok(removed) = s.store.rewrite_history(|rec| {
                    !(rec.peer_ik == r.sender && rec.ts == ts && !rec.from_me && rec.text == want)
                }) {
                    let ids = removed_msg_ids(s, &removed);
                    if !ids.is_empty() {
                        let _ = s.store.prune_meta(&ids);
                        meta_dirty = true;
                    }
                }
                let _ = evt_tx.send(Evt::MessageDeleted { peer: r.sender, ts, text });
            }
            Ok(Content::Reaction { msg_id, emoji, add }) => {
                // Реакция собеседника: автор = r.sender (атрибуция по сессии). Пишем
                // на диск; UI обновим одной Meta в конце батча.
                if s.store.set_reaction(msg_id, &emoji, r.sender, add).is_ok() {
                    meta_dirty = true;
                }
            }
            Ok(Content::Profile { name, bio }) => {
                // Received peer profile: store it in the per-IK cache as a HINT.
                // set_peer_profile clamps length and NEVER touches contacts.dat
                // (name/verified). The UI is refreshed with one PeerProfiles per batch.
                if s.store.set_peer_profile(r.sender, &name, &bio).is_ok() {
                    profiles_dirty = true;
                }
            }
            Ok(Content::TextExpiring { text, expire_at }) => {
                // Исчезающий текст: мёртвое-по-прибытии (капсула забрана после
                // expire_at) НЕ показываем; живое — только в память, БЕЗ append в
                // историю (never-persist).
                if wall_clock() < expire_at {
                    expiring.push(ExpiringIn { sender: r.sender, text, expire_at });
                }
            }
            Ok(Content::RouteOffer { relay_noise_pub, routes }) => {
                // Only actionable for the relay we already share: Noise authenticates
                // that identity, so a route to it cannot be impersonated. An offer for a
                // DIFFERENT relay would mean trusting that relay with our metadata — a
                // much bigger decision than "another way to reach the one we both use",
                // so it is not surfaced as an accept-able offer here.
                if relay_noise_pub != s.primary().id.noise_pub {
                    let _ = evt_tx.send(Evt::Status(StatusMsg::Error(
                        "ignored a route offer for a different relay".into(),
                    )));
                } else {
                    // Never applied here — the UI asks the user (an offered route
                    // reveals our IP to whoever runs it).
                    let _ = evt_tx.send(Evt::RouteOffer { from: r.sender, routes });
                }
            }
            Ok(Content::FileRef { blob_id, key, hash, name, size, chunks }) => {
                // Large file: download the E2E blob OFF-LOOP (a spawned thread streams to
                // a temp file, hash-verified; the worker keeps polling). A receiving bubble
                // with a bar shows immediately; history + FileReceived on completion.
                //
                // recv_session_multi persisted this FileRef as a pending download (crash-safe
                // retry, used by the desktop). This legacy egui client downloads inline instead,
                // so it consumes the pending entry now to avoid accumulation — it does not do
                // crash-recovery retry (a documented follow-up for this client).
                let _ = s.store.remove_pending_download(&blob_id);
                spawn_blob_download(
                    s, r.sender, blob_id, key, hash, name, size, chunks, wall_clock(), cmd_tx,
                    evt_tx, transfers,
                );
            }
            Ok(c) => {
                let re = s.reasm.entry(r.sender).or_default();
                match re.offer(c, wall_clock()) {
                    Ok(Some(Assembled::File(file))) => {
                        // Один ts на запись и на UI-событие (совпадение для удаления).
                        let ts = wall_clock();
                        // DEDUP by the transfer id: the mailbox/session can re-deliver a file
                        // before its ack, so save + history + UI event fire exactly once.
                        match s.store.save_received_file_deduped(
                            file.id,
                            &basename(&file.name),
                            &file.bytes,
                            r.sender,
                            ts,
                        ) {
                            Ok((file_id, true)) => {
                                // История: ССЫЛКА (не байты) — не раздуваем append-лог.
                                let rec = HistoryRecord {
                                    from_me: false,
                                    peer_ik: r.sender,
                                    text: format!("📎 {}", file.name).into_bytes(),
                                    ts,
                                };
                                let _ = s.store.append_history(&rec);
                                let _ = evt_tx.send(Evt::FileReceived {
                                    sender: r.sender,
                                    name: file.name,
                                    file_id,
                                    ts,
                                    id: 0, // inline-файл: без приёмного пузыря — добавить новый
                                });
                            }
                            // A re-delivery of a file we already have — do not re-save/log/surface.
                            Ok((_, false)) => {}
                            Err(e) => {
                                let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("saving file: {e}"))));
                            }
                        }
                    }
                    Ok(Some(Assembled::Avatar { bytes })) => {
                        // Received avatar: RE-DECODE + re-encode defensively (never
                        // trust the sender's encoding; bounded decode rejects bombs and
                        // strips metadata) before storing in the per-IK profile cache.
                        match crate::avatar::sanitize(&bytes) {
                            Ok(clean) => {
                                if s.store.set_peer_avatar(r.sender, clean).is_ok() {
                                    profiles_dirty = true;
                                }
                            }
                            Err(e) => {
                                let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("avatar rejected: {e}"))));
                            }
                        }
                    }
                    // The legacy egui client has no feed/publications or profile-gallery UI, so a
                    // received post image, attachment, or gallery has nowhere to land — accept and
                    // drop it (the Tauri desktop is the real UI).
                    Ok(Some(Assembled::PostImage { .. }))
                    | Ok(Some(Assembled::PostAttachment { .. }))
                    | Ok(Some(Assembled::Gallery { .. })) => {}
                    Ok(None) => {} // чанк накоплен
                    Err(e) => {
                        let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("file rejected: {e}"))));
                    }
                }
            }
            Err(e) => {
                let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("content: {e}"))));
            }
        }
    }
    if !texts.is_empty() {
        // Incoming text is now persisted to history by `recv_session_multi` itself
        // (plaintext-first, deduped by payload_id), so we do NOT append it again here — that
        // would double it. We only emit it to the UI. The reply/reaction meta above still
        // rides on `content::msg_id` and is unaffected.
        let _ = evt_tx.send(Evt::Received(texts));
    }
    if !expiring.is_empty() {
        // Исчезающие — только в UI (в память), в историю не идут.
        let _ = evt_tx.send(Evt::ReceivedExpiring(expiring));
    }
    if meta_dirty {
        // Одна полная карта на весь батч (входящие реакции / prune tombstone).
        emit_meta(s, evt_tx);
    }
    if profiles_dirty {
        // One full profile map for the whole batch (incoming Content::Profile).
        emit_peer_profiles(s, evt_tx);
    }
}

/// Re-drive any large-file uploads that were interrupted mid-flight (a crash killed the process
/// before the upload finished). Each resumable record persisted its `blob_id`+`key` and source
/// path; `spawn_blob_upload` finds the record and continues from the relay's watermark. Called when
/// a session comes up. A record whose source file is gone is dropped; the stable per-upload id
/// (via `transfers`) keeps a rapid re-login from double-spawning the same upload.
fn resume_pending_uploads(s: &Session, cmd_tx: &Sender<Cmd>, evt_tx: &Sender<Evt>, transfers: &mut Transfers) {
    for pu in s.store.list_pending_uploads().unwrap_or_default() {
        let Some(path) = pu.path.clone() else { continue }; // no path (e.g. a CLI record) → skip
        let id = u64::from_le_bytes(pu.upload_id[..8].try_into().unwrap());
        if transfers.contains_key(&id) {
            continue; // already resuming this upload
        }
        if !std::path::Path::new(&path).exists() {
            let _ = s.store.remove_pending_upload(&pu.upload_id); // source gone → can't resume
            continue;
        }
        spawn_blob_upload(s, pu.to_ik, path, pu.name.clone(), pu.size, id, wall_clock(), cmd_tx, evt_tx, transfers);
    }
}

/// §15 send a LARGE file OFF-LOOP: spawn a thread that streams the file up as an E2E
/// blob (peak RAM O(chunk), fresh per-file key the relay never sees) with progress +
/// cancel, then posts `Cmd::BlobUploadDone` back so the WORKER thread sends the small
/// `FileRef` over the ratchet (kept single-threaded). The worker keeps polling/sending
/// meanwhile.
#[allow(clippy::too_many_arguments)]
fn spawn_blob_upload(
    s: &Session,
    to_ik: [u8; 32],
    path: String,
    name: String,
    size: u64,
    id: u64,
    ts: u64,
    cmd_tx: &Sender<Cmd>,
    evt_tx: &Sender<Evt>,
    transfers: &mut Transfers,
) {
    let relay = s.primary().clone();
    let cancel = Arc::new(AtomicBool::new(false));
    transfers.insert(id, cancel.clone());
    let cmd_tx = cmd_tx.clone();
    let evt_tx = evt_tx.clone();
    // Persist (or reuse) a resumable upload record BEFORE the upload starts, so a crash mid-upload
    // is resumable — a stable blob_id+key keyed by (recipient, name, size), continued from the
    // relay's watermark. Reused verbatim by a resume-on-login spawn. Cleared on `BlobUploadDone`.
    let upload_id = client::upload_id_for(&to_ik, &name, size);
    let (blob_id, key) = match s.store.get_pending_upload(&upload_id) {
        Ok(Some(pu)) => (pu.blob_id, pu.key),
        _ => {
            let (b, k) = (client::blob::random32(), client::blob::random32());
            let _ = s.store.add_pending_upload(&client::store::PendingUpload {
                upload_id,
                blob_id: b,
                key: k,
                to_ik,
                name: name.clone(),
                size,
                queued_at: wall_clock(),
                path: Some(path.clone()),
            });
            (b, k)
        }
    };
    // Show the bar immediately (before the first chunk lands).
    let _ = evt_tx.send(Evt::FileProgress { id, done: 0, total: size });
    std::thread::spawn(move || {
        let blob = (|| {
            let file = std::fs::File::open(&path).map_err(|e| format!("opening {path}: {e}"))?;
            let ep = evt_tx.clone();
            client::blob_upload_resumable_with(&relay, file, size, blob_id, key, &cancel, move |done, total| {
                let _ = ep.send(Evt::FileProgress { id, done, total });
            })
        })();
        let blob = match blob {
            Ok(b) => Some(b),
            Err(e) => {
                if e != "cancelled" {
                    let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("file send failed: {e}"))));
                }
                None
            }
        };
        let _ = cmd_tx.send(Cmd::BlobUploadDone { id, to_ik, name, size, ts, blob });
    });
}

/// §15 receive a LARGE file OFF-LOOP: emit `FileIncoming` (a receiving bubble with a
/// bar) and spawn a thread that downloads the blob to a temp file (streaming,
/// hash-verified) with progress + cancel, promotes it to a path-traversal-safe name
/// under `recv_dir`, and posts `Cmd::BlobDownloadDone` back for the worker to write
/// history + emit `FileReceived`. A failed/cancelled download leaves no partial behind.
#[allow(clippy::too_many_arguments)]
fn spawn_blob_download(
    s: &Session,
    sender: [u8; 32],
    blob_id: [u8; 32],
    key: [u8; 32],
    hash: [u8; 32],
    name: String,
    size: u64,
    chunks: u32,
    ts: u64,
    cmd_tx: &Sender<Cmd>,
    evt_tx: &Sender<Evt>,
    transfers: &mut Transfers,
) {
    let relay = s.primary().clone();
    let store = s.store.clone();
    // Fresh transfer id, disjoint from the controller's small monotonic send ids
    // (random u64 → collision negligible). Never 0 (0 = untracked bubble).
    let id = {
        let r = client::blob::random32();
        let v = u64::from_le_bytes(r[0..8].try_into().unwrap());
        if v == 0 { 1 } else { v }
    };
    let cancel = Arc::new(AtomicBool::new(false));
    transfers.insert(id, cancel.clone());
    let cmd_tx = cmd_tx.clone();
    let evt_tx = evt_tx.clone();
    let _ = evt_tx.send(Evt::FileIncoming { sender, name: name.clone(), size, id, ts });
    std::thread::spawn(move || {
        let path = (|| {
            // Seal straight into the vault as it streams: the download never stages
            // plaintext on disk, so there is no `.part-*` window where a lost or stolen disk
            // would find the file in the clear. Name goes inside the container too.
            let (file_id, writer) = store
                .received_file_writer(&basename(&name))
                .map_err(|e| format!("creating the sealed file: {e}"))?;
            let ep = evt_tx.clone();
            let dl = client::blob_download_with(
                &relay, blob_id, key, chunks, hash, writer, size, &cancel,
                move |done, total| {
                    let _ = ep.send(Evt::FileProgress { id, done, total });
                },
            );
            match dl {
                Ok(w) => {
                    w.finish().map_err(|e| format!("finishing the sealed file: {e}"))?;
                    Ok(file_id)
                }
                Err(e) => {
                    // A failed/cancelled download leaves no partial behind.
                    let _ = store.remove_received_file(&file_id);
                    Err(e)
                }
            }
        })();
        let path = match path {
            Ok(p) => Some(p),
            Err(e) => {
                if e != "cancelled" {
                    let _ = evt_tx.send(Evt::Status(StatusMsg::Error(format!("large file: {e}"))));
                }
                None
            }
        };
        let _ = cmd_tx.send(Cmd::BlobDownloadDone { id, sender, name, ts, path });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cover_delays_have_a_heavy_tail_that_bounded_jitter_cannot_produce() {
        // The distribution IS the mechanism, so the test has to reject the shapes that
        // would look fine on a graph and fail against a relay. Cover whose gaps cluster
        // near the mean lets the relay learn the rate and subtract it. An exponential
        // spends real mass both far below and far above the mean — that is what makes
        // waiting uninformative about how much longer you will wait.
        //
        // Both neuters redden: return `mean` (constant), or reuse `interval` (uniform
        // ±25%, which can never reach mean/4 or 2×mean).
        let mut j = Jitter::new(0x243F_6A88_85A3_08D3);
        let mean = Duration::from_secs(60);
        let draws: Vec<f64> =
            (0..2000).map(|_| j.poisson_delay(mean).as_secs_f64()).collect();

        let short = draws.iter().filter(|d| **d < 15.0).count(); // < mean/4
        let long = draws.iter().filter(|d| **d > 120.0).count(); // > 2*mean
        assert!(short > 300, "too few short gaps ({short}/2000) — the tail is truncated");
        assert!(long > 150, "too few long gaps ({long}/2000) — this is not memoryless");

        // The mean must actually be the mean, or the cover rate is not what we claim.
        let avg = draws.iter().sum::<f64>() / draws.len() as f64;
        assert!((40.0..80.0).contains(&avg), "mean drifted to {avg}s");

        // And the tail is clamped: an unbounded draw would park cover for an hour, which
        // is indistinguishable from having none.
        assert!(draws.iter().all(|d| *d <= 480.0), "a draw escaped the 8x clamp");
    }

    #[test]
    fn jitter_varies_within_bounds_and_is_not_a_constant_cadence() {
        // The whole point: consecutive poll intervals must NOT be a fixed value (that
        // is the fingerprint we are killing), yet must stay bounded around the base so
        // polling stays responsive. Neuter `Jitter::interval` to return `base` and the
        // "not constant" assertion goes red.
        let mut j = Jitter::new(0x1234_5678_9abc_def0);
        let base = Duration::from_secs(2);
        let vals: Vec<Duration> = (0..64).map(|_| j.interval(base)).collect();

        for v in &vals {
            assert!(
                *v >= Duration::from_millis(1500) && *v <= Duration::from_millis(2500),
                "interval {v:?} outside [1.5s, 2.5s]"
            );
        }
        let distinct: std::collections::HashSet<u128> = vals.iter().map(|d| d.as_millis()).collect();
        assert!(
            distinct.len() > 8,
            "poll cadence must vary, not be a constant heartbeat; got {} distinct of 64",
            distinct.len()
        );
    }

    #[test]
    fn jitter_zero_base_stays_zero() {
        // A zero base (no polling configured) must not underflow or spin.
        let mut j = Jitter::new(7);
        assert_eq!(j.interval(Duration::ZERO), Duration::ZERO);
    }
}
