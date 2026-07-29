//! `karst` — десктоп-клиент (Linux), CLI-ядро. **НЕ production** (см.
//! docs/STATUS.md): §2.1 E2E (PQXDH+ratchet) есть, но дев-capability с публичным
//! секретом, доверие к IK — вне канала, нет обфускации транспорта, крипта не аудирована.
//!
//! On-disk secrets are under **at-rest encryption** — the password is prompted for on the
//! terminal with echo off, with `KARST_PASSPHRASE` as the non-interactive fallback (protects a
//! COLD disk, not a live process). Directory: `$KARST_HOME`.
//! Команды: init/id/account/dev-cap/import-cap/publish/send/recv (см. `--help`).

use std::collections::HashMap;
use std::io::BufRead;
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use client::content::{decode, Content, Reassembler};
use client::store::Store;
use node::protocol::PublishResponse;

fn wall_clock() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let rest = &args.get(1..).unwrap_or(&[]);

    let result = match cmd {
        "init" => cmd_init(),
        "restore" => cmd_restore(rest),
        "show-phrase" => cmd_show_phrase(),
        "id" => cmd_id(),
        "account" => cmd_account(),
        "qr" => cmd_qr(),
        "discovery" => cmd_discovery(rest),
        "find" => cmd_find(rest),
        "dev-cap" => cmd_dev_cap(rest),
        "join" => cmd_join(rest),
        "relays" => cmd_relays(rest),
        "relay-info" => cmd_relay_info(rest),
        "relay-prefs" => cmd_relay_prefs(rest),
        "import-cap" => cmd_import_cap(rest),
        "publish" => cmd_publish(rest),
        "send" => cmd_send(rest),
        "send-file" => cmd_send_file(rest),
        "recv" => cmd_recv(rest),
        "files" => cmd_files(rest),
        "export-file" => cmd_export_file(rest),
        "export-chat" => cmd_export_chat(rest),
        "" | "help" | "-h" | "--help" => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        other => Err(format!("unknown command: {other}\n(karst help)")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!(
        "karst (SKELETON, not for production)\n\
         \n\
         karst init                          create an account (prints the recovery phrase)\n\
         karst restore <24 words>            restore an account from the phrase (into an empty $KARST_HOME)\n\
         karst show-phrase                   show your recovery phrase\n\
         karst id                            print the skeleton pubkey (hex)\n\
         karst account                       print the §2.1 IK (the discovery address)\n\
         karst qr                             show your address as a QR to scan (out-of-band)\n\
         karst discovery status              show your contact code (public discovery on/off)\n\
         karst discovery on --relay H:P --relay-id X   become findable by a random contact code\n\
         karst discovery rotate --relay H:P --relay-id X   mint a fresh code (old one stops working)\n\
         karst discovery off --relay H:P --relay-id X  stop being findable; delete the code\n\
         karst discovery invite --relay H:P --relay-id X   mint a short-lived invite code for one person\n\
         karst discovery invites             list your outstanding invites\n\
         karst discovery revoke <CODE> --relay H:P --relay-id X   retire an invite now\n\
         karst find <CODE> --relay H:P --relay-id X    resolve a contact code to an address\n\
         karst dev-cap --relay H:P --relay-id X  write the dev capability FOR that relay (local test)\n\
         karst join --relay H:P --relay-id X earn a capability from a PUBLIC relay (PoW)\n\
         karst relays --relay H:P --relay-id X  list relays this one knows about (--add to multi-home)\n\
         karst relay-info --relay H:P --relay-id X  show a relay's advertised policy (persistence, door)\n\
         karst relay-prefs [--persist durable|ephemeral|any]  prefer relays matching a policy (used by relays --add)\n\
         karst import-cap <file.json> --relay H:P --relay-id X  import a capability FOR that relay (invite)\n\
         karst publish --relay A --relay-id ID  publish your §2.1 bundle (§12)\n\
         karst send --relay A --relay-id ID --to HEX <msg>  send text\n\
         karst send-file --relay A --relay-id ID --to HEX --file PATH  send a file\n\
         karst recv --relay A --relay-id ID  fetch incoming (text + files)\n\
         karst files                         list received files (id, size, name)\n\
         karst export-file <id> [--out PATH] decrypt a received file to a plaintext path\n\
         karst export-chat --to HEX [--out FILE]  write the local chat with a peer to a text file\n\
         \n\
         send/recv also: --socks5 HOST:PORT (route via Tor/obfs4/…)\n\
         relay-id is printed when karst-relay starts\n\
         directory: $KARST_HOME (or ~/.config/karst)"
    );
}

/// Open the vault under at-rest encryption. This protects a COLD disk (theft, a backup, a sync)
/// — not a live process.
///
/// The password is read from the TERMINAL, with echo off, and `KARST_PASSPHRASE` is the fallback
/// for scripts (CRYPTO-09). It used to be the only way in, which put the secret somewhere every
/// child process inherits, `ps -e` environments can show on some systems, and a shell history or
/// a CI log keeps for as long as anyone looks. A prompt has none of those properties, and a
/// non-interactive caller loses nothing — the variable still works when there is no tty.
///
/// The bytes live in a `Zeroizing<String>`, so they are cleared when this function returns rather
/// than lingering in freed heap. Honest limit, as everywhere else in this pass: it does not undo
/// copies the runtime made on the way here (the environment string, the terminal's own buffer),
/// and on a tty the line editor has already seen it.
fn store() -> Result<Store, String> {
    let pass = read_passphrase()?;
    if pass.is_empty() {
        return Err("empty password — the vault needs a non-empty one".into());
    }
    Store::unlock(Store::default_dir(), pass.as_bytes())
        .map_err(|e| format!("opening the vault: {e}"))
}

/// Prompt on the tty with echo disabled; fall back to `KARST_PASSPHRASE` when there is no tty
/// (scripts, CI) or the variable is already set (an explicit choice by the caller).
fn read_passphrase() -> Result<zeroize::Zeroizing<String>, String> {
    if let Ok(v) = std::env::var("KARST_PASSPHRASE") {
        return Ok(zeroize::Zeroizing::new(v));
    }
    let tty = match std::fs::File::open("/dev/tty") {
        Ok(f) => f,
        // No terminal and no variable: say what to do rather than blocking on a read that will
        // never return.
        Err(_) => {
            return Err("no terminal to prompt on — set KARST_PASSPHRASE for non-interactive use".into())
        }
    };
    eprint!("passphrase: ");
    let _guard = EchoOff::new(&tty)?;
    let mut pass = zeroize::Zeroizing::new(String::new());
    std::io::BufReader::new(&tty)
        .read_line(&mut pass)
        .map_err(|e| format!("reading the passphrase: {e}"))?;
    eprintln!();
    while pass.ends_with('\n') || pass.ends_with('\r') {
        pass.pop();
    }
    Ok(pass)
}

/// Turns terminal echo off for as long as it is alive, and back on when dropped — including on
/// an early return or a panic, which is the whole reason it is a guard and not two calls.
struct EchoOff {
    fd: std::os::fd::RawFd,
    restore: libc::termios,
}

impl EchoOff {
    fn new(tty: &std::fs::File) -> Result<Self, String> {
        use std::os::fd::AsRawFd;
        let fd = tty.as_raw_fd();
        // SAFETY: `fd` is a live descriptor for the terminal we just opened, and `termios` is a
        // plain C struct the kernel fills in.
        let mut term: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut term) } != 0 {
            return Err("could not read the terminal mode".into());
        }
        let restore = term;
        term.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) } != 0 {
            return Err("could not turn terminal echo off".into());
        }
        Ok(EchoOff { fd, restore })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // Best effort: if this fails the terminal is left without echo, which is bad UX but not a
        // secret leak — and there is nothing useful to do about it from a `Drop`.
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.restore) };
    }
}

/// Создать аккаунт: свежая 12-словная фраза → корень на диск. Фраза печатается
/// ОДИН раз — её надо записать (единственный способ восстановления). Идемпотентно
/// НЕ перезаписывает существующий корень (иначе сменил бы IK и осиротил сессии).
fn cmd_init() -> Result<(), String> {
    let s = store()?;
    if s.has_seed() {
        let acct = s.load_account().map_err(|e| format!("reading account: {e}"))?;
        println!("account already exists. IK: {}", hex::encode(acct.identity_public()));
        println!("(recovery phrase: karst show-phrase)");
        return Ok(());
    }
    let m = client::seed::generate_mnemonic();
    s.save_seed(&client::seed::entropy_of(&m)).map_err(|e| format!("writing the root seed: {e}"))?;
    let acct = s.load_account().map_err(|e| format!("reading account: {e}"))?;
    println!("ACCOUNT CREATED.\n");
    println!("Recovery phrase — WRITE IT DOWN; without it the account cannot be recovered:\n");
    println!("    {m}\n");
    println!("IK (address for your contacts): {}", hex::encode(acct.identity_public()));
    Ok(())
}

/// Восстановить аккаунт по фразе в ПУСТОЙ `$KARST_HOME`. Та же фраза → тот же IK.
fn cmd_restore(args: &[String]) -> Result<(), String> {
    let phrase = match flag(args, "--phrase") {
        Some(p) => p,
        None => args.iter().filter(|a| !a.starts_with("--")).cloned().collect::<Vec<_>>().join(" "),
    };
    if phrase.trim().is_empty() {
        return Err("provide the phrase: karst restore word1 word2 … word24".into());
    }
    let m = client::seed::parse_mnemonic(&phrase)?;
    let s = store()?;
    if s.has_seed() {
        return Err("this $KARST_HOME already has an account — restore into an EMPTY directory".into());
    }
    s.save_seed(&client::seed::entropy_of(&m)).map_err(|e| format!("writing the root seed: {e}"))?;
    let acct = s.load_account().map_err(|e| format!("reading account: {e}"))?;
    println!("account restored. IK: {}", hex::encode(acct.identity_public()));
    Ok(())
}

/// Показать свою фразу восстановления (расшифровав корень паролем).
fn cmd_show_phrase() -> Result<(), String> {
    let s = store()?;
    let e = s.load_entropy().map_err(|_| "no account (karst init)".to_string())?;
    println!("{}", client::seed::mnemonic_of_entropy(&e));
    Ok(())
}

fn cmd_id() -> Result<(), String> {
    let s = store()?;
    let id = s.load_identity().map_err(|_| "no identity (karst init)".to_string())?;
    println!("{}", hex::encode(id.public.to_bytes()));
    Ok(())
}

/// §2.1-адрес (IK account) — его дают отправителям для discovery/инициации.
fn cmd_account() -> Result<(), String> {
    let s = store()?;
    let acct = s.load_account().map_err(|e| if e.kind() == std::io::ErrorKind::NotFound { "no account (karst init)".to_string() } else { format!("account not decrypted (wrong KARST_PASSPHRASE?): {e}") })?;
    println!("{}", hex::encode(acct.identity_public()));
    Ok(())
}

/// Render a string as a scannable QR in the terminal (unicode half-blocks). Used to show your
/// §2.1 address for out-of-band exchange — the address travels by someone pointing a camera at
/// your screen, NOT by a searchable directory on the relay (which would reintroduce a MITM).
fn render_qr(data: &str) -> Result<String, String> {
    use qrcode::render::unicode;
    let code = qrcode::QrCode::new(data.as_bytes()).map_err(|e| format!("QR encode: {e}"))?;
    Ok(code
        .render::<unicode::Dense1x2>()
        .quiet_zone(true)
        .build())
}

/// `karst qr` — show your §2.1 identity key as a QR for a peer to scan (out-of-band exchange).
fn cmd_qr() -> Result<(), String> {
    let s = store()?;
    let acct = s.load_account().map_err(|e| if e.kind() == std::io::ErrorKind::NotFound { "no account (karst init)".to_string() } else { format!("account not decrypted (wrong KARST_PASSPHRASE?): {e}") })?;
    let ik = hex::encode(acct.identity_public());
    println!("{}", render_qr(&ik)?);
    println!("Your KARST address — have a contact scan this, or copy it:\n{ik}");
    Ok(())
}

/// §12 4c — opt-in discovery. Become findable by a RANDOM, rotatable, revocable contact code
/// (there are no chooseable usernames — a chooseable name would be squattable). `status` is local;
/// `on`/`rotate`/`off` talk to a relay.
fn cmd_discovery(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("status");
    let s = store()?;
    match sub {
        "status" => {
            match client::discovery_code(&s)? {
                Some(code) => {
                    println!("discovery: ON");
                    println!("your contact code (anyone who has it can find you):\n\n  {code}\n");
                    println!("rotate: karst discovery rotate --relay …    off: karst discovery off --relay …");
                }
                None => println!(
                    "discovery: OFF — you are not publicly findable.\nturn on: karst discovery on --relay H:P --relay-id X"
                ),
            }
            Ok(())
        }
        "on" => {
            let r = relay_arg(args)?;
            let code = client::discovery_publish(&s, &r, wall_clock())?;
            println!("discovery ON. Share this contact code out of band — anyone who has it can find you:\n");
            println!("  {code}\n");
            println!("It's random and unguessable (no username to squat or brute-force), it stays on");
            println!("until you rotate (karst discovery rotate) or turn it off (karst discovery off), and");
            println!("your identity never changes so existing contacts are unaffected.");
            if !s.has_capability_for(&r.id) {
                println!("\nTip: also run `karst publish` at this relay — otherwise someone who finds you");
                println!("has your address but no bundle to open a conversation with.");
            }
            Ok(())
        }
        "rotate" => {
            let r = relay_arg(args)?;
            let code = client::discovery_rotate(&s, &r, wall_clock())?;
            println!("rotated. The old code no longer resolves. Your new contact code:\n\n  {code}");
            Ok(())
        }
        "off" => {
            let r = relay_arg(args)?;
            let removed = client::discovery_off(&s, &r)?;
            if removed {
                println!("discovery OFF — your contact code no longer resolves and the local key is deleted.");
            } else {
                println!("discovery OFF — local key deleted. The relay was unreachable (or had nothing), so");
                println!("its copy of the record will disappear on its own when it expires.");
            }
            Ok(())
        }
        // An INVITE is a discovery row of its own: short-lived, revocable, and it never touches
        // the persistent contact code. It is no longer destroyed by the first lookup (A10-4), so
        // the invitee can retry a failed add — and retiring it is the inviter's call.
        "invite" => {
            let r = relay_arg(args)?;
            let code = client::discovery_one_time(&s, &r, wall_clock())?;
            let days = client::INVITE_TTL_SECS / 86_400;
            println!("invite code (hand it to ONE person):\n\n  {code}\n");
            println!("It resolves until you revoke it (karst discovery revoke <CODE>) or it lapses");
            println!("in {days} days. Resolving it does NOT consume it — the person you gave it to can");
            println!("retry if their first attempt failed — so revoke it once they have added you.");
            Ok(())
        }
        "invites" => {
            let now = wall_clock();
            let live = client::invites(&s, now)?;
            if live.is_empty() {
                println!("no outstanding invites (mint one: karst discovery invite --relay …)");
                return Ok(());
            }
            println!("{} outstanding invite(s):", live.len());
            for i in &live {
                println!("  {}  (lapses in {} h)", i.code, i.expiry.saturating_sub(now) / 3600);
            }
            Ok(())
        }
        "revoke" => {
            let code = positional_after_flags(&args[1..])
                .ok_or("usage: karst discovery revoke <INVITE-CODE> --relay H:P --relay-id X")?;
            let r = relay_arg(args)?;
            let removed = client::revoke_invite(&s, &r, &code, wall_clock())?;
            if removed {
                println!("revoked — that invite no longer resolves.");
            } else {
                println!("that invite had already lapsed at the relay; forgotten locally.");
            }
            Ok(())
        }
        other => Err(format!(
            "unknown discovery subcommand: {other}\n(status | on | rotate | off | invite | invites | revoke)"
        )),
    }
}

/// §12 4c — resolve a contact code someone shared with you to their KARST address + location.
fn cmd_find(args: &[String]) -> Result<(), String> {
    let code = positional_after_flags(args)
        .ok_or("usage: karst find <CONTACT-CODE> --relay H:P --relay-id X")?;
    let r = relay_arg(args)?;
    let (ik, loc) = client::find_contact(&r, &code, wall_clock())?;
    println!("found. Their KARST address (IK):\n  {}", hex::encode(ik));
    if !loc.addrs.is_empty() {
        println!("reachable at relay {} @ {}", loc.relay_id_hex(), loc.addrs.join(", "));
    }
    println!("(to message them, use the address above as --to)");
    Ok(())
}

/// A capability belongs to ONE relay (CRYPTO-24), so even the dev credential is written against
/// the relay it will be presented to — there is no account-wide slot left to fall back on.
///
/// Written as SHARED across this account's channels (A8-4): the dev secret is published in this
/// repository, so it is the same `capability_id` for everyone and splitting it per channel would
/// separate nothing that is not already public.
fn cmd_dev_cap(args: &[String]) -> Result<(), String> {
    let r = relay_arg(args)?;
    let s = store()?;
    s.save_shared_capability_for(&r.id, &client::dev_capability())
        .map_err(|e| format!("writing capability: {e}"))?;
    println!("wrote the dev capability for this relay (LOCAL TEST; the secret is public)");
    Ok(())
}

/// §12 — discover relays a given relay knows about (node-list). With `--add`, verify each and
/// import the confirmed ones into this account's multi-homing set.
fn cmd_relays(args: &[String]) -> Result<(), String> {
    let r = relay_arg(args)?;
    if args.iter().any(|a| a == "--add") {
        let s = store()?;
        println!("discovering + verifying relays (dialing each to confirm)…");
        let added = client::import_discovered_relays(&s, &r)?;
        println!(
            "imported {added} new verified relay(s) into this account's multi-homing set{}",
            if added == 0 { " (nothing new to add)" } else { "" }
        );
        return Ok(());
    }
    let list = client::discover_relays(&r)?;
    if list.is_empty() {
        println!("(this relay lists no relays — set KARST_RELAY_PEERS / KARST_RELAY_ADVERTISE on it)");
        return Ok(());
    }
    println!("{} relay(s) known to this one:", list.len());
    for d in &list {
        println!("  {}  @ {}", d.relay_id_hex(), d.addrs.join(", "));
    }
    println!("(add --add to verify and multi-home onto these)");
    Ok(())
}

/// Show a relay's advertised policy so you know what you're connecting to. Everything is
/// OPERATOR-DECLARED; each line notes how far a client can actually check it.
fn cmd_relay_info(args: &[String]) -> Result<(), String> {
    let r = relay_arg(args)?;
    let p = client::relay_policy(&r)?;
    println!("relay policy (advertised by the operator — trust each line per its note):\n");
    match p.blob_persistence {
        None => println!("large-file blobs: disabled on this relay"),
        Some(mode) => {
            match mode {
                node::protocol::BlobPersistence::Durable => {
                    println!("large-file blobs: DURABLE — parked files survive a relay restart");
                    println!("  ✓ verifiable: you can fetch a chunk back and it self-verifies");
                }
                node::protocol::BlobPersistence::Ephemeral => {
                    println!("large-file blobs: EPHEMERAL — wiped on restart");
                    println!("  ~ a claim: no one can check 'it forgot' remotely — trust the operator");
                }
            }
            println!("  limits: up to {} MiB per file, kept up to {} day(s)", p.max_blob_size / (1 << 20), p.blob_ttl_secs / 86_400);
        }
    }
    match p.pow_bits {
        None => println!("door: invite-only or dev (no self-serve issuance) — you need an invite to join"),
        Some(0) => println!("door: OPEN — issues a capability without proof-of-work (quota still bounds it)"),
        Some(n) => println!("door: PUBLIC, {n}-bit proof-of-work — ✓ verifiable: you solve it to join"),
    }
    Ok(())
}

/// Set/show which relays this account prefers, matched against each relay's advertised policy.
/// The preference is applied by `karst relays --add` (multi-homing import).
fn cmd_relay_prefs(args: &[String]) -> Result<(), String> {
    let s = store()?;
    if let Some(v) = flag(args, "--persist") {
        let pref = match v.as_str() {
            "any" => None,
            "durable" => Some(node::protocol::BlobPersistence::Durable),
            "ephemeral" => Some(node::protocol::BlobPersistence::Ephemeral),
            other => return Err(format!("--persist must be durable | ephemeral | any (got {other})")),
        };
        let mut prefs = s.load_relay_prefs().map_err(|e| format!("prefs: {e}"))?;
        prefs.prefer_persistence = pref;
        s.save_relay_prefs(&prefs).map_err(|e| format!("saving prefs: {e}"))?;
    }
    let prefs = s.load_relay_prefs().map_err(|e| format!("prefs: {e}"))?;
    match prefs.prefer_persistence {
        None => println!("relay preference: blob persistence = any (no filter)"),
        Some(node::protocol::BlobPersistence::Durable) => {
            println!("relay preference: blob persistence = DURABLE");
            println!("(karst relays --add will only multi-home onto relays advertising durable storage)");
        }
        Some(node::protocol::BlobPersistence::Ephemeral) => {
            println!("relay preference: blob persistence = EPHEMERAL");
            println!("(karst relays --add will only multi-home onto relays advertising ephemeral storage)");
        }
    }
    Ok(())
}

/// §7 slice 4a — earn a capability from a PUBLIC relay by solving its proof-of-work.
fn cmd_join(args: &[String]) -> Result<(), String> {
    let r = relay_arg(args)?;
    println!("solving proof-of-work…");
    let cap = client::earn_capability(&r)?;
    let s = store()?;
    s.save_capability_for(&r.id, &cap).map_err(|e| format!("writing capability: {e}"))?;
    println!("joined: earned a capability via proof-of-work (you can now send)");
    Ok(())
}

/// An invite file carries a bare capability with NO relay-id in it (the relay writes exactly the
/// serialized credential — see `karst-relay`'s `write_invite`), so the relay it is FOR has to be
/// named here. Storing it against that relay is what keeps it from being presented anywhere else.
fn cmd_import_cap(args: &[String]) -> Result<(), String> {
    let path = positional_after_flags(args)
        .ok_or("usage: karst import-cap <file.json> --relay H:P --relay-id X")?;
    let r = relay_arg(args)?;
    let bytes = std::fs::read(&path).map_err(|e| format!("reading {path}: {e}"))?;
    let cap = serde_json::from_slice(&bytes).map_err(|e| format!("parsing capability: {e}"))?;
    let s = store()?;
    // SHARED across this account's channels, deliberately (A8-4): an invite is ONE credential the
    // operator minted and can revoke as a unit (#231), so N channels cannot each hold their own —
    // only the operator can issue N invites. At an invite-only relay this account's channels do
    // therefore present one `capability_id`, which that relay can cluster; the public/PoW door has
    // no such limit and issues per channel (`karst join`).
    s.save_shared_capability_for(&r.id, &cap).map_err(|e| format!("writing capability: {e}"))?;
    println!("capability imported for this relay (shared by every channel of this account)");
    Ok(())
}

/// §12: опубликовать свой §2.1-bundle у relay (чтобы другие могли писать нам).
fn cmd_publish(args: &[String]) -> Result<(), String> {
    let r = relay_arg(args)?;

    let s = store()?;
    let acct = s.load_account().map_err(|e| if e.kind() == std::io::ErrorKind::NotFound { "no account (karst init)".to_string() } else { format!("account not decrypted (wrong KARST_PASSPHRASE?): {e}") })?;
    let cap = s
        .load_capability_for(&r.id)
        .map_err(|e| format!("cannot publish to this relay: {e}"))?;

    match client::publish_bundle(&r, acct, cap, wall_clock()) {
        PublishResponse::Published => {
            println!("bundle published");
            Ok(())
        }
        PublishResponse::Rejected(r) => Err(format!("relay rejected: {r}")),
        PublishResponse::NeedCookie(_) => Err("protocol: unexpected NeedCookie".into()),
    }
}

fn cmd_send(args: &[String]) -> Result<(), String> {
    let to_hex = flag(args, "--to").ok_or("need --to <§2.1-IK-hex> (recipient karst account)")?;
    let msg = positional_after_flags(args).ok_or("need message text")?;

    let r = relay_arg(args)?;
    let to = parse_pubkey(&to_hex)?; // §2.1-IK получателя

    let s = store()?;
    client::send_text(&s, &r, &to, msg.as_bytes(), wall_clock(), wall_clock())?;
    println!("delivered");
    Ok(())
}

/// Отправить файл: `--file PATH`. Мелкие идут инлайном (padded mailbox); файлы больше
/// `MAX_FILE_SIZE` стримятся E2E-blob'ом + маленьким `FileRef` — заливка ВОЗОБНОВЛЯЕМАЯ
/// (повтор той же команды после обрыва продолжает с watermark релея).
fn cmd_send_file(args: &[String]) -> Result<(), String> {
    let to_hex = flag(args, "--to").ok_or("need --to <§2.1-IK-hex>")?;
    let path = flag(args, "--file").ok_or("need --file <path>")?;

    let r = relay_arg(args)?;
    let to = parse_pubkey(&to_hex)?;

    let bytes = std::fs::read(&path).map_err(|e| format!("reading {path}: {e}"))?;
    // Имя — только базовое (без каталогов): получателю не даём path-traversal.
    let name = Path::new(&path)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("could not determine the file name")?
        .to_string();

    let s = store()?;
    client::send_file(&s, &r, &to, &name, &bytes, wall_clock())?;
    println!("file sent: {name} ({} B)", bytes.len());
    Ok(())
}

fn cmd_recv(args: &[String]) -> Result<(), String> {
    let r = relay_arg(args)?;

    let s = store()?;
    // Send-side retry on the recv cadence: retransmit (verbatim) anything a prior transport
    // failure left queued. Best-effort — a failure here must not block reading incoming mail.
    let _ = client::flush_outbox(&s, &r, wall_clock());
    // Err (недоступен/протокол/отказ auth) отделён от Ok(пусто).
    let msgs = client::recv_session(&s, &r, wall_clock())?;
    // Drive any pending large-file downloads (a FileRef received this poll, or one left by a
    // crash): recv persisted each before acking, so this fetches them crash-safely and
    // idempotently. Synchronous here — a one-shot CLI command, no cancel.
    let never = std::sync::atomic::AtomicBool::new(false);
    for pd in s.list_pending_downloads().unwrap_or_default() {
        let name = pd.name.clone();
        match client::download_blob(&s, &r, &pd, wall_clock(), &never, |_, _| {}) {
            client::DownloadOutcome::Done(id) => println!("file: {name} → received/{id}.dat"),
            client::DownloadOutcome::GaveUp(e) => eprintln!("file {name}: unrecoverable: {e}"),
            client::DownloadOutcome::Retry(e) => eprintln!("file {name}: will retry next recv: {e}"),
        }
    }
    if msgs.is_empty() {
        println!("(empty)");
        return Ok(());
    }
    // Пересборка файлов — по ОТПРАВИТЕЛЮ (чанки одного отправителя не смешиваются
    // с чужими). Одноразовый recv: файл должен уместиться в один mailbox.
    let mut reasm: HashMap<[u8; 32], Reassembler> = HashMap::new();
    let mut shown = 0;
    for m in &msgs {
        match m {
            Some(r) => {
                let from = hex::encode(&r.sender[..8]);
                match decode(&r.plaintext) {
                    Ok(Content::Text(t)) | Ok(Content::TextStamped { text: t, .. }) => {
                        println!("[{from}…] {}", String::from_utf8_lossy(&t));
                        shown += 1;
                    }
                    Ok(Content::TextExpiring { text, .. }) => {
                        println!("[{from}…] (disappearing) {}", String::from_utf8_lossy(&text));
                        shown += 1;
                    }
                    Ok(Content::DeleteForEveryone { .. }) => {
                        println!("[{from}…] (sender recalled the message)");
                        shown += 1;
                    }
                    // Large-file announcement: already persisted + fetched via the pending-
                    // download drive above, not through the inline reassembler.
                    Ok(Content::FileRef { .. }) => shown += 1,
                    Ok(c) => {
                        let re = reasm.entry(r.sender).or_default();
                        match re.offer(c, wall_clock()) {
                            Ok(Some(client::content::Assembled::File(file))) => {
                                // Seal at rest + index it (mirror the desktop path). The old
                                // plaintext `received/` write leaked cleartext to a cold disk and
                                // left the file invisible to `karst files`.
                                match s.save_received_file(&file.name, &file.bytes) {
                                    Ok(id) => {
                                        let _ = s.record_received_file(&client::store::ReceivedFile {
                                            id: id.clone(),
                                            name: file.name.clone(),
                                            size: file.bytes.len() as u64,
                                            sender: r.sender,
                                            ts: wall_clock(),
                                            blob_id: [0u8; 32],
                                        });
                                        println!("[{from}…] file: {} (sealed → id {id})", file.name);
                                    }
                                    Err(e) => eprintln!("saving file: {e}"),
                                }
                                shown += 1;
                            }
                            Ok(Some(client::content::Assembled::Avatar { bytes })) => {
                                // The CLI has no profile UI; just acknowledge receipt.
                                println!("[{from}…] avatar received ({} bytes)", bytes.len());
                                shown += 1;
                            }
                            Ok(Some(client::content::Assembled::PostImage { bytes, .. })) => {
                                // The CLI has no feed UI; just acknowledge receipt.
                                println!("[{from}…] post image received ({} bytes)", bytes.len());
                                shown += 1;
                            }
                            Ok(Some(client::content::Assembled::PostAttachment { kind, name, bytes, .. })) => {
                                let what = if kind == 1 { format!("file {name}") } else { "image".into() };
                                println!("[{from}…] post attachment received ({what}, {} bytes)", bytes.len());
                                shown += 1;
                            }
                            Ok(Some(client::content::Assembled::Gallery { bytes })) => {
                                // The CLI has no profile UI; acknowledge the gallery + its photo count.
                                let n = client::content::unpack_gallery(&bytes).map(|(_, g)| g.len()).unwrap_or(0);
                                println!("[{from}…] gallery received ({n} photos)");
                                shown += 1;
                            }
                            Ok(None) => {} // чанк накоплен, файл ещё не полон
                            Err(e) => eprintln!("[{from}…] file rejected: {e}"),
                        }
                    }
                    Err(e) => eprintln!("[{from}…] {e}"),
                }
            }
            None => eprintln!("(not decrypted — tampering or not addressed to us)"),
        }
    }
    eprintln!("received messages/files: {shown} (envelopes: {})", msgs.len());
    Ok(())
}

/// Export the locally-stored conversation with one peer to a UTF-8 text file
/// (or stdout). Reads only the local history sidecar — no network, no relay.
fn cmd_export_chat(args: &[String]) -> Result<(), String> {
    let to_hex = flag(args, "--to").ok_or("need --to <§2.1-IK-hex> (the peer to export)")?;
    let peer = parse_pubkey(&to_hex)?;

    let s = store()?;
    let records = s.load_history().map_err(|e| format!("reading history: {e}"))?;
    let text = client::format_conversation(&records, &peer);
    if text.is_empty() {
        eprintln!("(no stored messages with that peer)");
        return Ok(());
    }

    match flag(args, "--out") {
        Some(path) => {
            std::fs::write(&path, &text).map_err(|e| format!("writing {path}: {e}"))?;
            eprintln!("wrote {} lines to {path}", text.lines().count());
        }
        None => print!("{text}"),
    }
    Ok(())
}

/// List the files received (and downloaded) into this account, so a user can find the id to
/// export. Files land SEALED at rest; `export-file` is how you get the plaintext back out.
fn cmd_files(_args: &[String]) -> Result<(), String> {
    let s = store()?;
    let files = s.list_received_files().map_err(|e| format!("listing files: {e}"))?;
    if files.is_empty() {
        eprintln!("(no received files)");
        return Ok(());
    }
    for f in &files {
        println!("{}  {:>12} B  {}", f.id, f.size, f.name);
    }
    Ok(())
}

/// Decrypt a received file (sealed at rest) to a plaintext path. `--out PATH` sets the
/// destination; without it the file's own (base) name in the cwd is used. `karst files` lists ids.
fn cmd_export_file(args: &[String]) -> Result<(), String> {
    let id = positional_after_flags(args).ok_or("need <file-id> (see `karst files`)")?;
    let s = store()?;
    let name = s.received_file_name(&id).map_err(|e| format!("no such received file {id}: {e}"))?;
    let out = match flag(args, "--out") {
        Some(p) => p,
        // Default to the sender-supplied name, reduced to a BASE name (no path traversal).
        None => Path::new(&name)
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty())
            .unwrap_or("file")
            .to_string(),
    };
    // Streaming decrypt to disk (no whole-file RAM buffer — the blob path can carry multi-GB).
    s.export_received_file(&id, Path::new(&out)).map_err(|e| format!("exporting file: {e}"))?;
    let n = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    eprintln!("exported {name} ({n} B) to {out}");
    Ok(())
}

// ---------- мелкий разбор аргументов (без внешних крейтов) ----------

/// Значение флага `--name <value>`.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

/// Первый аргумент, не являющийся флагом и не значением флага.
fn positional_after_flags(args: &[String]) -> Option<String> {
    let mut skip_next = false;
    for a in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if a.starts_with("--") {
            skip_next = true; // это флаг → следующий его значение
            continue;
        }
        return Some(a.clone());
    }
    None
}

/// `--socks5 HOST:PORT` → маршрут через внешний PT (Tor/obfs4/…). Отсутствует =
/// прямой TCP.
/// Parse `--socks5` and, as a side effect, announce the §15 carrier that will
/// actually be used (this is the chokepoint every networked subcommand passes
/// through). Printed to stderr so a user who set a proxy or `KARST_WSS` can see
/// there was no silent fallback to direct TCP — the same assurance the GUI's
/// status-bar chip gives. Derived from the SAME inputs `client::transport` uses.
/// Parse `--relay` / `--relay-id` / `--socks5` into the connection context every
/// networked command needs (identity + carrier + the §15 path list failover walks).
fn relay_arg(args: &[String]) -> Result<client::Relay, String> {
    let addr = flag(args, "--relay").ok_or("need --relay <addr>")?;
    // Host:port, not just IP:port — a `<b32>.b32.i2p:port` relay resolved by the SOCKS bridge.
    let addr = karst_transport::transport::Dest::parse(&addr).map_err(|e| format!("relay address: {e}"))?;
    let id = flag(args, "--relay-id")
        .ok_or("need --relay-id <hex> (printed when karst-relay starts)")?;
    let id = client::RelayId::parse(&id)?;
    let proxy = parse_socks5(args)?;
    if client::is_i2p_host(&addr.host) && proxy.is_none() {
        return Err("an .i2p relay needs a SOCKS bridge: pass --socks5 <i2p SAM/SOCKS host:port> \
                    (e.g. 127.0.0.1:4447 for i2pd)"
            .into());
    }
    if client::is_onion_host(&addr.host) && proxy.is_none() {
        return Err("a .onion relay needs Tor: pass --socks5 127.0.0.1:9050 (Tor's SOCKS port)".into());
    }
    // `--mixnet` marks --socks5 as a mixnet (Nym) client's SOCKS port — the carrier reads mixnet.
    let mixnet = args.iter().any(|a| a == "--mixnet");
    if mixnet && proxy.is_none() {
        return Err("--mixnet needs the Nym SOCKS client: pass --socks5 127.0.0.1:1080".into());
    }
    let r = client::Relay::new(addr, id, proxy).with_mixnet(mixnet);
    if r.path_count() > 1 {
        eprintln!("paths: {} (failover across configured routes)", r.path_count());
    }
    Ok(r)
}

fn parse_socks5(args: &[String]) -> Result<Option<SocketAddr>, String> {
    let proxy = match flag(args, "--socks5") {
        None => None,
        Some(a) => Some(a.parse().map_err(|e| format!("socks5 address: {e}"))?),
    };
    eprintln!("carrier: {}", client::active_carrier(proxy).label());
    Ok(proxy)
}

fn parse_pubkey(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("pubkey is not hex: {e}"))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        format!("pubkey must be 32 bytes (64 hex), got {} bytes", bytes.len())
    })?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::render_qr;

    #[test]
    fn qr_renders_deterministically_for_an_address() {
        // A 64-hex IK encodes to a QR whose unicode render is non-empty, multi-line, and
        // stable for the same input (the same address always shows the same code).
        let ik = "a".repeat(64);
        let out = render_qr(&ik).expect("a 64-hex address must QR-encode");
        assert!(out.lines().count() > 8, "a QR for 64 chars is a sizeable grid, got:\n{out}");
        assert!(out.chars().any(|c| c == '█' || c == '▀' || c == '▄'), "renders as block glyphs");
        assert_eq!(render_qr(&ik).unwrap(), out, "same address → same QR");
        // Different addresses differ.
        assert_ne!(render_qr(&"b".repeat(64)).unwrap(), out);
    }
}
