//! `karst-relay` — the skeleton node binary: listens on TCP, runs the §7 admission
//! pipeline, holds mailboxes. **NOT production** (see docs/STATUS.md): classical-only
//! seal, and a dev capability with a known (public) secret so admission isn't enforced.
//!
//! The node key is **PERSISTENT**: the relay-id is stable across restarts (otherwise
//! clients would have to re-pin a new id every time). Key file:
//! `$KARST_RELAY_HOME/relay.key` (default `~/.config/karst-relay`), 0600, created on
//! first run and NEVER overwritten.
//!
//! Run:  karst-relay [addr]   — address from the CLI arg, else $KARST_RELAY_ADDR,
//! else 127.0.0.1:9000. Optional wss carrier via $KARST_RELAY_TLS_CERT + _KEY.

use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use admission::capability::{Capability, Quota, Scope};
use admission::params::DEFAULT_POW_BITS;
use node::node::{BlobPersistence, MailboxDurability, RelayDescriptor, RelayNode};
use node::seal::Identity;
use node::socket::{generate_noise_keypair, RelayServer};

/// Дев-capability: секрет ЗАШИТ и публичен — только для локального теста руками,
/// НЕ для production. В реальной системе провижининг capability — отдельный слой.
const DEV_CAP_SECRET: [u8; 32] = [0x33; 32];
const DEV_CAP_ID: [u8; 16] = [0xCA; 16];

/// The relay's admission role, from `KARST_RELAY_MODE`. This is the "door": who may
/// deposit and fetch at all. The default is the SAFE one — `Private`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    /// Closed door: admission requires a capability whose secret is **random and
    /// persisted**, handed out only via the invite file. Nobody gets in without one.
    /// A closed relay by construction; this is that, made real.
    Private,
    /// Open door, PoW-gated (slice 4a). No pre-shared invite: a client EARNS a capability
    /// by solving hashcash (`karst join`), and the per-capability quota bounds it. Spam is
    /// bounded (N messages cost N/quota PoW solves), not resisted outright — the difficulty
    /// (`KARST_RELAY_POW_BITS`) is a speed bump, the quota is the real per-cap bound.
    Public,
    /// Local testing ONLY: issues the well-known public dev capability, so `karst dev-cap`
    /// (which writes that same known cap on the client) can reach this relay without an
    /// invite. Never for a real deployment — the secret is in the source.
    Dev,
}

impl Role {
    fn from_env() -> Result<Self, String> {
        let mode = std::env::var("KARST_RELAY_MODE").ok();
        Self::parse(mode.as_deref())
    }

    /// Resolve the role, **failing closed**. Pure (env passed in) so it is unit-tested.
    ///
    /// An UNKNOWN mode (a typo like `publik`) REFUSES to start rather than silently becoming
    /// `private`, so an operator who meant `public` never runs a different relay than they
    /// thought. `public` opens directly now: it is a **PoW-gated** door (slice 4a), so it is
    /// spam-BOUNDED (clients earn a capability by hashcash + the per-cap quota) rather than
    /// spam-exposed — the reason the old `KARST_RELAY_ALLOW_UNSAFE_PUBLIC` acknowledgement
    /// existed is gone. Unset / empty / `private` stays the safe (invite-only) default.
    fn parse(mode: Option<&str>) -> Result<Self, String> {
        match mode {
            None | Some("") | Some("private") => Ok(Role::Private),
            Some("dev") => Ok(Role::Dev),
            Some("public") => Ok(Role::Public),
            Some(other) => Err(format!(
                "unknown KARST_RELAY_MODE '{other}' — use private | public | dev. Refusing to \
                 start rather than silently defaulting to a mode you did not choose."
            )),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Role::Private => "private (invite-only)",
            Role::Public => "public (PoW-gated open door)",
            Role::Dev => "dev (known public cap — LOCAL TESTING ONLY)",
        }
    }
}

/// The §15 blob-store restart posture, from `KARST_RELAY_BLOB_PERSIST`. `durable` (default) keeps
/// parked blobs across a restart; `ephemeral` wipes them on start. Fails closed on a typo (never
/// silently runs a posture the operator did not choose). Pure (env passed in) so it is unit-tested.
fn parse_blob_persistence(v: Option<&str>) -> Result<BlobPersistence, String> {
    match v {
        None | Some("") | Some("durable") => Ok(BlobPersistence::Durable),
        Some("ephemeral") => Ok(BlobPersistence::Ephemeral),
        Some(other) => Err(format!(
            "unknown KARST_RELAY_BLOB_PERSIST '{other}' — use durable | ephemeral. Refusing to \
             start rather than silently defaulting to a posture you did not choose."
        )),
    }
}

fn blob_persistence_from_env() -> Result<BlobPersistence, String> {
    parse_blob_persistence(std::env::var("KARST_RELAY_BLOB_PERSIST").ok().as_deref())
}

/// Mailbox restart posture (R2-5, #161), from `KARST_RELAY_MAIL_PERSIST`. `volatile` (default)
/// keeps queued mail in RAM only — an ordinary restart loses anything not yet fetched; `durable`
/// fsyncs every accepted message to a log first and replays it on start. Default stays volatile
/// because durability means opaque ciphertext lingering on the operator's disk, which is a
/// posture an operator opts into, not one they inherit. Same fail-closed-on-a-typo discipline as
/// the blob knob. Pure (env passed in) so it is unit-tested.
fn parse_mail_persistence(v: Option<&str>) -> Result<MailboxDurability, String> {
    match v {
        None | Some("") | Some("volatile") => Ok(MailboxDurability::Volatile),
        Some("durable") => Ok(MailboxDurability::Durable),
        Some(other) => Err(format!(
            "unknown KARST_RELAY_MAIL_PERSIST '{other}' — use volatile | durable. Refusing to \
             start rather than silently defaulting to a posture you did not choose."
        )),
    }
}

fn mail_persistence_from_env() -> Result<MailboxDurability, String> {
    parse_mail_persistence(std::env::var("KARST_RELAY_MAIL_PERSIST").ok().as_deref())
}

/// One issued invite (CRYPTO-25). The capability itself is the bearer credential; everything
/// else is what an OPERATOR needs to manage it.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Invite {
    /// Operator's own name for this invite ("alice", "conference-2026") — the whole point of
    /// per-invite credentials is being able to say WHICH one to revoke.
    label: String,
    created_at: u64,
    /// Revoked invites are KEPT (with this flag) rather than deleted, so the id can never be
    /// re-minted by accident and `invite list` can still explain what happened to it.
    revoked: bool,
    cap: Capability,
}

/// The persisted invite table. Bounded: an operator who can mint invites can also fill a disk,
/// but a bug or a script in a loop should not be able to.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
struct Invites {
    entries: Vec<Invite>,
}

/// Ceiling on stored invites (live + revoked). Generous for any real deployment — a relay handing
/// out more than this is running a public door, not an invite list.
const MAX_INVITES: usize = 4_096;

/// What an invite file carries. NOT a bare `Capability` any more (CRYPTO-24/25): a credential
/// with no idea which relay it belongs to forced the client to be TOLD, out of band, which relay
/// each invite was for — and the client now keeps credentials per relay, so that was a real gap
/// rather than a cosmetic one. `relay_id` is the same 128-hex identifier the connect block
/// prints, so importing an invite binds it to exactly one relay with no extra ceremony.
#[derive(serde::Serialize, serde::Deserialize)]
struct InviteFile {
    relay_id: String,
    addr: String,
    label: String,
    cap: Capability,
}

/// The address a client should actually dial: the advertised one when it is routable, else the
/// listen address. Shared by the invite file and the connect block so they can never disagree.
fn client_addr_hint<'a>(advertise: &'a str, addr: &'a str) -> &'a str {
    if is_routable_advertise(advertise) {
        advertise
    } else {
        addr
    }
}

fn invites_path() -> PathBuf {
    key_dir().join("invites.json")
}

fn load_invites() -> io::Result<Invites> {
    match std::fs::read(invites_path()) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
            // LOUD, not "start with an empty list": an unreadable invite table means every
            // invitee silently loses access, and re-minting would hand out new credentials while
            // the old ones are still in the wild.
            io::Error::new(io::ErrorKind::InvalidData, format!("invites.json unreadable: {e}"))
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Invites::default()),
        Err(e) => Err(e),
    }
}

fn save_invites(inv: &Invites) -> io::Result<()> {
    let dir = key_dir();
    std::fs::create_dir_all(&dir)?;
    let json = serde_json::to_vec_pretty(inv).map_err(io::Error::other)?;
    // The secrets in here ARE the doors. Write via a 0600 temp + rename so a crash cannot leave a
    // truncated table (which `load_invites` would then refuse to start on).
    let tmp = dir.join("invites.json.tmp");
    {
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(&json)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, invites_path())?;
    Ok(())
}

/// Mint a fresh, unique invite credential. Each gets its OWN `capability_id` and secret, which is
/// the whole fix (CRYPTO-25): the quota tracker meters by `capability_id`, so one shared invite
/// meant one shared bucket — every invitee's sending charged against everyone else's — with no
/// way to revoke a single person and no rotation that did not cut off the entire relay.
fn mint_invite(label: &str, now: u64) -> Invite {
    use rand::RngCore;
    let mut id = [0u8; 16];
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut id);
    rand::rngs::OsRng.fill_bytes(&mut secret);
    Invite {
        label: label.to_string(),
        created_at: now,
        revoked: false,
        cap: Capability {
            capability_id: id,
            scope: Scope::MessageDelivery,
            quota: Quota { max_requests: 100, max_bytes: 1 << 20, window_secs: 600 },
            not_before: 0,
            not_after: u32::MAX,
            secret,
        },
    }
}

/// Hex id, for operator commands and file names.
fn invite_id_hex(cap: &Capability) -> String {
    cap.capability_id.iter().map(|b| format!("{b:02x}")).collect()
}

/// The relay's admission capability, sized like the dev one but with a role-appropriate
/// secret. `Dev` returns the known public cap; `Private`/`Public` load or create a random
/// secret persisted 0600 in `capability.key`, so the invite stays valid across restarts.
fn load_or_create_cap(role: Role) -> io::Result<Capability> {
    let quota = Quota { max_requests: 100, max_bytes: 1 << 20, window_secs: 600 };
    if role == Role::Dev {
        return Ok(Capability {
            capability_id: DEV_CAP_ID,
            scope: Scope::MessageDelivery,
            quota,
            not_before: 0,
            not_after: u32::MAX,
            secret: DEV_CAP_SECRET,
        });
    }

    let dir = key_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("capability.key");
    let (id, secret) = match std::fs::File::open(&path) {
        Ok(mut f) => {
            let mut buf = [0u8; 48]; // 16-byte id ‖ 32-byte secret
            f.read_exact(&mut buf)?;
            let mut id = [0u8; 16];
            let mut secret = [0u8; 32];
            id.copy_from_slice(&buf[..16]);
            secret.copy_from_slice(&buf[16..]);
            (id, secret)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            use rand::RngCore;
            let mut buf = [0u8; 48];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
            f.write_all(&buf)?;
            eprintln!("admission secret created (0600): {}", path.display());
            let mut id = [0u8; 16];
            let mut secret = [0u8; 32];
            id.copy_from_slice(&buf[..16]);
            secret.copy_from_slice(&buf[16..]);
            (id, secret)
        }
        Err(e) => return Err(e),
    };
    Ok(Capability {
        capability_id: id,
        scope: Scope::MessageDelivery,
        quota,
        not_before: 0,
        not_after: u32::MAX,
        secret,
    })
}

/// Write ONE invite as the file an operator hands to ONE peer, who runs
/// `karst import-cap <file>`. 0600 — the secret in it IS the key to the door.
///
/// One file per invite, named by its id, so handing out two invites cannot silently overwrite the
/// first (which the single `invite.json` did, and which is how a "per-invite" credential quietly
/// becomes a shared one again).
fn write_invite_file(inv: &Invite, relay_id: &str, addr: &str) -> io::Result<PathBuf> {
    let dir = key_dir().join("invites");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", invite_id_hex(&inv.cap)));
    let file = InviteFile {
        relay_id: relay_id.to_string(),
        addr: addr.to_string(),
        label: inv.label.clone(),
        cap: inv.cap.clone(),
    };
    let json = serde_json::to_vec_pretty(&file).map_err(io::Error::other)?;
    let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path)?;
    f.write_all(&json)?;
    Ok(path)
}

fn wall_clock() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn key_dir() -> PathBuf {
    if let Ok(d) = std::env::var("KARST_RELAY_HOME") {
        return PathBuf::from(d);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config").join("karst-relay")
}

/// Загрузить (или создать при первом запуске) ключ узла: fetch-auth-секрет(32) ‖
/// Noise-priv(32) ‖ Noise-pub(32). Возвращает (fetch-identity, noise_priv,
/// noise_pub). Пара Noise персистится ЦЕЛИКОМ (priv+pub), чтобы не полагаться на
/// совпадение деривации pub из priv. Файл 0600, `create_new` (не перезаписывает).
fn load_or_create_keys() -> io::Result<(Identity, [u8; 32], [u8; 32])> {
    let dir = key_dir();
    std::fs::create_dir_all(&dir)?;
    // The state dir holds the node key AND the admin control socket. Make it 0700 so both are
    // gated to the owner by the DIRECTORY, not only their own file bits — this also removes
    // the umask dependence in the socket's post-bind chmod window. Runs before the socket is
    // bound (main calls this first), so it covers the socket too.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let path = dir.join("relay.key");

    match std::fs::File::open(&path) {
        Ok(mut f) => {
            let mut buf = [0u8; 96];
            f.read_exact(&mut buf)?;
            let fetch = Identity::from_secret_bytes(buf[..32].try_into().unwrap());
            let mut npriv = [0u8; 32];
            let mut npub = [0u8; 32];
            npriv.copy_from_slice(&buf[32..64]);
            npub.copy_from_slice(&buf[64..96]);
            eprintln!("node key loaded: {}", path.display());
            Ok((fetch, npriv, npub))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let fetch = Identity::generate();
            let (npriv, npub) = generate_noise_keypair();
            let mut buf = [0u8; 96];
            buf[..32].copy_from_slice(&fetch.to_secret_bytes());
            buf[32..64].copy_from_slice(&npriv);
            buf[64..96].copy_from_slice(&npub);
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            f.write_all(&buf)?;
            eprintln!("node key created (0600): {}", path.display());
            Ok((fetch, npriv, npub))
        }
        Err(e) => Err(e),
    }
}

/// Parse a 128-hex relay-id into `(noise_pub, fetch_pub)`.
fn parse_relay_id(hex_str: &str) -> Result<([u8; 32], [u8; 32]), String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("relay-id not hex: {e}"))?;
    if bytes.len() != 64 {
        return Err(format!("relay-id must be 64 bytes (128 hex), got {}", bytes.len()));
    }
    let mut noise = [0u8; 32];
    let mut fetch = [0u8; 32];
    noise.copy_from_slice(&bytes[..32]);
    fetch.copy_from_slice(&bytes[32..]);
    Ok((noise, fetch))
}

/// Parse `KARST_RELAY_PEERS` = `addr@relay-id,addr@relay-id` into descriptors (operator-
/// curated seed for the node list). A malformed entry warns and is skipped, never fatal.
fn parse_peers(spec: &str) -> Vec<RelayDescriptor> {
    let mut out = Vec::new();
    for entry in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match entry.split_once('@') {
            Some((addr, id)) => match parse_relay_id(id) {
                Ok((noise_pub, fetch_pub)) => out.push(RelayDescriptor {
                    noise_pub,
                    fetch_pub,
                    addrs: vec![addr.trim().to_string()],
                }),
                Err(e) => eprintln!("WARNING: node-list peer '{entry}' skipped: {e}"),
            },
            None => eprintln!("WARNING: node-list peer '{entry}' skipped: expected addr@relay-id"),
        }
    }
    out
}

/// A self-advertise address is routable if it is a name (`.onion`/DNS) or a non-loopback,
/// non-unspecified IP. NEVER advertise `0.0.0.0`/`127.0.0.1` — that poisons every client's
/// list with a dead entry.
fn is_routable_advertise(addr: &str) -> bool {
    let host = match addr.rsplit_once(':') {
        Some((h, _)) => h,
        None => addr,
    };
    let host = host.trim_matches(|c| c == '[' || c == ']'); // strip ipv6 brackets
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => !ip.is_loopback() && !ip.is_unspecified(),
        Err(_) => !host.is_empty(), // a name (.onion/.i2p/DNS) is routable
    }
}

/// Local admin control socket for a RUNNING relay — owner-only by filesystem perms (0600),
/// same trust model as `relay.key`/`invite.json`. No crypto: reaching it means local fs
/// access. A second invocation of this binary (`karst-relay pow …`) is the client.
fn admin_socket_path() -> PathBuf {
    key_dir().join("admin.sock")
}

/// Human description of the door policy (shared by startup, status, and command replies).
fn describe_pow(d: Option<u32>) -> String {
    match d {
        None => "off — issuance disabled, no new capabilities handed out".into(),
        Some(0) => "open — issuing WITHOUT proof-of-work (quota-only; fine when there is no spam)".into(),
        Some(n) => format!("on — {n}-bit proof-of-work required to earn a capability"),
    }
}

/// A `stop`/`shutdown` line asks the relay to exit gracefully. Recognised in the admin loop
/// (which then process-exits — not unit-testable), so it's a tiny pure predicate kept apart for
/// the test + to keep the parse in one place.
fn is_stop_command(line: &str) -> bool {
    matches!(line.split_whitespace().next(), Some("stop") | Some("shutdown"))
}

/// Apply one admin command line to the running relay, returning the reply line. Pure over the
/// shared relay + the parsed line, so it is unit-tested. `stop` is handled by the caller (it
/// exits the process), so it never reaches here — the error text still lists it for discovery.
fn apply_admin_command(relay: &Arc<RwLock<RelayNode>>, line: &str, ctx: &InviteCtx) -> String {
    let mut parts = line.split_whitespace();
    match (parts.next(), parts.next()) {
        (Some("pow"), Some("status")) | (Some("pow"), None) => {}
        (Some("pow"), Some("off")) => relay.write().expect("relay lock").set_pow_issue(None),
        (Some("pow"), Some("open")) => relay.write().expect("relay lock").set_pow_issue(Some(0)),
        (Some("pow"), Some("on")) => {
            let bits = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(DEFAULT_POW_BITS);
            relay.write().expect("relay lock").set_pow_issue(Some(bits));
        }
        // Live quota ceiling (§7.2): `quota status | off | set REQ BYTES WINDOW | preset NAME`.
        // Applied immediately, existing capabilities included (clamped on each request).
        (Some("quota"), sub) => {
            match sub {
                None | Some("status") => {}
                Some("off") | Some("unlimited") => relay.write().expect("relay lock").set_quota_policy(None),
                Some("set") => {
                    let spec = parts.collect::<Vec<_>>().join(",");
                    match parse_quota_spec(&spec) {
                        Ok(q @ Some(_)) => relay.write().expect("relay lock").set_quota_policy(q),
                        Ok(None) => return "error: quota set REQUESTS BYTES WINDOW_SECS".into(),
                        Err(e) => return format!("error: {e}"),
                    }
                }
                Some("preset") => match parts.next().and_then(quota_preset) {
                    Some(q) => relay.write().expect("relay lock").set_quota_policy(q),
                    None => return "error: quota preset chat-only|media-friendly|bytes-only|unlimited".into(),
                },
                _ => return "error: quota status|off|set REQ BYTES WINDOW|preset NAME".into(),
            }
            let cur = relay.read().expect("relay lock").quota_policy();
            return format!("quota: {}", describe_quota(cur));
        }
        // CRYPTO-25: per-invite credentials an operator can actually manage. `new` mints a fresh
        // id+secret and writes its own file; `revoke` stops honouring one id — on the NEXT
        // request, not at the next restart, because revoking is usually a reaction to something.
        (Some("invite"), sub) => return invite_command(relay, sub, parts.next(), ctx),
        _ => {
            return format!(
                "error: unknown command '{line}' — use: pow status|off|open|on [BITS] | quota status|off|set REQ BYTES WINDOW|preset NAME | invite list|new LABEL|revoke ID | stop"
            )
        }
    }
    let now = relay.read().expect("relay lock").pow_difficulty();
    format!("pow: {}", describe_pow(now))
}

/// What an invite needs to know about the relay it belongs to, so a minted invite file can name
/// its relay (which is what lets a client bind the credential to exactly one relay — the coupling
/// CRYPTO-24 exposed).
#[derive(Clone, Default)]
struct InviteCtx {
    relay_id: String,
    addr: String,
}

/// `invite list | new LABEL | revoke ID`.
fn invite_command(
    relay: &Arc<RwLock<RelayNode>>,
    sub: Option<&str>,
    arg: Option<&str>,
    ctx: &InviteCtx,
) -> String {
    let mut invites = match load_invites() {
        Ok(i) => i,
        // Fail LOUD: minting on top of a table we could not read would hand out a credential
        // while the existing ones are still in the wild and unaccounted for.
        Err(e) => return format!("error: {e}"),
    };
    match sub {
        None | Some("list") => {
            if invites.entries.is_empty() {
                return "invites: none".into();
            }
            let mut out = String::from("invites:");
            for inv in &invites.entries {
                out.push_str(&format!(
                    "\n  {} {:<16} {}",
                    invite_id_hex(&inv.cap),
                    inv.label,
                    if inv.revoked { "revoked" } else { "live" }
                ));
            }
            out
        }
        Some("new") => {
            let Some(label) = arg else { return "error: invite new LABEL".into() };
            if invites.entries.len() >= MAX_INVITES {
                return format!("error: invite table is full ({MAX_INVITES}); revoke some first");
            }
            let inv = mint_invite(label, wall_clock());
            invites.entries.push(inv.clone());
            if let Err(e) = save_invites(&invites) {
                // Persist BEFORE honouring it: a credential the relay accepts but would forget on
                // restart is worse than one that was never minted.
                return format!("error: could not save invites: {e}");
            }
            relay.write().expect("relay lock").issue_capability(inv.cap.clone());
            match write_invite_file(&inv, &ctx.relay_id, &ctx.addr) {
                Ok(p) => format!("invite {} ({}) → {}", invite_id_hex(&inv.cap), inv.label, p.display()),
                Err(e) => format!(
                    "invite {} ({}) minted and live, but its file could not be written: {e}",
                    invite_id_hex(&inv.cap),
                    inv.label
                ),
            }
        }
        Some("revoke") => {
            let Some(id_hex) = arg else { return "error: invite revoke ID".into() };
            let Some(inv) = invites.entries.iter_mut().find(|i| invite_id_hex(&i.cap) == id_hex) else {
                return format!("error: no invite with id {id_hex}");
            };
            if inv.revoked {
                return format!("invite {id_hex} was already revoked");
            }
            inv.revoked = true;
            let cap_id = inv.cap.capability_id;
            let label = inv.label.clone();
            if let Err(e) = save_invites(&invites) {
                return format!("error: could not save invites: {e}");
            }
            // Live effect, and the file goes too — it is a bearer secret with no purpose left.
            relay.write().expect("relay lock").revoke_capability(&cap_id);
            let _ = std::fs::remove_file(key_dir().join("invites").join(format!("{id_hex}.json")));
            format!("invite {id_hex} ({label}) revoked")
        }
        Some(other) => format!("error: unknown invite subcommand '{other}' — use list|new LABEL|revoke ID"),
    }
}

/// A named quota preset → a ceiling (`Some(None)` = unlimited/off; `None` = unknown name).
fn quota_preset(name: &str) -> Option<Option<Quota>> {
    match name {
        "off" | "unlimited" | "none" => Some(None),
        "chat-only" | "chat" => Some(Some(Quota { max_requests: 300, max_bytes: 2 << 20, window_secs: 600 })),
        // Media-friendly: a photo album (each ~90 KiB = ~90 one-packet requests) fits comfortably.
        "media-friendly" | "media" => Some(Some(Quota { max_requests: 200_000, max_bytes: 512 << 20, window_secs: 600 })),
        // Bytes-only: meter by VOLUME, not request count — the request cap is effectively removed
        // (u32::MAX) so a payload of many tiny packets isn't penalised per-packet; only total bytes
        // bound a client. The honest posture for an operator who cares about bandwidth, not chunk
        // count (e.g. serving inline media or blob puts where each chunk is one cheap request).
        "bytes-only" | "bytes" => Some(Some(Quota { max_requests: u32::MAX, max_bytes: 256 << 20, window_secs: 600 })),
        _ => None,
    }
}

/// Parse a byte count with an optional K/M/G suffix ("64M", "1G", "1048576").
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('K' | 'k') => (&s[..s.len() - 1], 1u64 << 10),
        Some('M' | 'm') => (&s[..s.len() - 1], 1u64 << 20),
        Some('G' | 'g') => (&s[..s.len() - 1], 1u64 << 30),
        _ => (s, 1),
    };
    num.trim().parse::<u64>().ok().map(|n| n.saturating_mul(mult))
}

/// Parse a quota spec: a preset name, "off", or "REQ,BYTES,WINDOW" (bytes take a K/M/G suffix).
/// `Ok(None)` = no ceiling. Used by both `KARST_RELAY_QUOTA` and the admin `quota set/preset`.
fn parse_quota_spec(s: &str) -> Result<Option<Quota>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    if let Some(p) = quota_preset(s) {
        return Ok(p);
    }
    let f: Vec<&str> = s.split([',', ' ']).filter(|x| !x.is_empty()).collect();
    if f.len() == 3 {
        let req = f[0].parse::<u32>().map_err(|_| "requests must be a number".to_string())?;
        let bytes = parse_size(f[1]).ok_or("bytes: a number with optional K/M/G".to_string())?;
        let window = f[2].parse::<u32>().map_err(|_| "window must be seconds".to_string())?;
        return Ok(Some(Quota { max_requests: req, max_bytes: bytes, window_secs: window }));
    }
    Err("a preset (chat-only|media-friendly|bytes-only|unlimited) or REQ,BYTES,WINDOW".into())
}

fn describe_quota(q: Option<Quota>) -> String {
    match q {
        None => "off — no operator ceiling; each capability's own quota applies".into(),
        Some(q) => format!("{} requests / {} bytes per {}s (ceiling)", q.max_requests, q.max_bytes, q.window_secs),
    }
}

/// Bind the admin socket and serve it on a background thread. A stale socket from a prior run
/// is removed first (a crash leaves the file behind).
fn spawn_admin_socket(relay: Arc<RwLock<RelayNode>>, ctx: InviteCtx) -> io::Result<()> {
    let path = admin_socket_path();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            // A client that connects and never sends must not wedge the (single-threaded)
            // admin loop — bound the read so control stays available.
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let Ok(peer) = stream.try_clone() else { continue };
            let mut line = String::new();
            if BufReader::new(peer).read_line(&mut line).is_ok() {
                let trimmed = line.trim();
                // Graceful stop: ack the caller, then exit. Blob writes are atomic + the socket
                // is re-created (stale-removed) on next start, so an immediate exit is clean —
                // this is the "stop without kill" path for a detached relay.
                if is_stop_command(trimmed) {
                    let _ = writeln!(stream, "stopping");
                    let _ = stream.flush();
                    eprintln!("admin: stop received — shutting down");
                    std::process::exit(0);
                }
                let reply = apply_admin_command(&relay, trimmed, &ctx);
                let _ = writeln!(stream, "{reply}");
            }
        }
    });
    Ok(())
}

/// A plain-English "no relay to talk to" message for a failed admin connect, chosen by error
/// kind so the user learns WHY: `NotFound` = no socket file at all (never started here);
/// `ConnectionRefused` = a stale socket with nothing listening (e.g. left by a `kill -9`).
/// Both mean the same thing to the operator — no relay is running at this home. Pure, so it is
/// unit-tested; the caller prints it and exits, so `main` never Debug-dumps a raw `io::Error`.
fn no_relay_message(sock: &std::path::Path, e: &io::Error) -> String {
    let why = match e.kind() {
        io::ErrorKind::NotFound => "no relay is running here — there is no admin socket",
        io::ErrorKind::ConnectionRefused => {
            "no relay is running here — the admin socket is stale (nothing is listening; a relay \
             was probably killed with a signal instead of `karst-relay stop`)"
        }
        _ => "could not reach a running relay here",
    };
    format!(
        "karst-relay: {why}.\n  checked: {}\n  Start a relay first, or if it uses a custom state \
         dir point at it:  KARST_RELAY_HOME=<dir> karst-relay stop   (default ~/.config/karst-relay)",
        sock.display()
    )
}

/// Connect to a RUNNING relay's admin socket (owner-only by fs perms, scoped to
/// `KARST_RELAY_HOME`). On failure prints a plain-English "no relay running" line and exits(1)
/// — so the CLI never surfaces a raw `Error: Custom { kind: … }` Debug dump to the user.
fn connect_admin() -> UnixStream {
    let sock = admin_socket_path();
    UnixStream::connect(&sock).unwrap_or_else(|e| {
        eprintln!("{}", no_relay_message(&sock, &e));
        std::process::exit(1);
    })
}

/// Send one line to the admin socket and print the relay's reply. Shared by `pow` and `stop`.
fn admin_send(line: &str) -> io::Result<()> {
    let mut stream = connect_admin();
    writeln!(stream, "{line}")?;
    let mut reply = String::new();
    BufReader::new(&stream).read_line(&mut reply)?;
    print!("{reply}");
    Ok(())
}

/// `karst-relay pow …` — talk to a RUNNING relay's admin socket (same `KARST_RELAY_HOME`).
fn run_admin_client(rest: &[String]) -> io::Result<()> {
    let cmd = if rest.is_empty() { "status".to_string() } else { rest.join(" ") };
    admin_send(&format!("pow {cmd}"))
}

fn main() -> io::Result<()> {
    let arg1 = std::env::args().nth(1);

    // `karst-relay pow …` controls a RUNNING relay (via its admin socket) instead of starting
    // one. Handled before address parsing so `pow` is never mistaken for a listen address.
    if arg1.as_deref() == Some("pow") {
        let rest: Vec<String> = std::env::args().skip(2).collect();
        return run_admin_client(&rest);
    }
    // `karst-relay quota …` — live-tune the operator quota ceiling on a RUNNING relay.
    if arg1.as_deref() == Some("quota") {
        let rest: Vec<String> = std::env::args().skip(2).collect();
        let cmd = if rest.is_empty() { "status".to_string() } else { rest.join(" ") };
        return admin_send(&format!("quota {cmd}"));
    }
    // `karst-relay invite …` — mint / list / revoke per-invitee credentials on a RUNNING relay
    // (CRYPTO-25). Revoking bites on the next request, not at the next restart.
    if arg1.as_deref() == Some("invite") {
        let rest: Vec<String> = std::env::args().skip(2).collect();
        let cmd = if rest.is_empty() { "list".to_string() } else { rest.join(" ") };
        return admin_send(&format!("invite {cmd}"));
    }
    // `karst-relay stop` asks a RUNNING relay (same KARST_RELAY_HOME) to exit gracefully — the
    // no-kill shutdown, works for a detached/background node too.
    if matches!(arg1.as_deref(), Some("stop" | "shutdown")) {
        return admin_send("stop");
    }
    // Handle --help/--version before treating arg 1 as an address (otherwise
    // `karst-relay --help` would try to bind to "--help" and fail confusingly).
    match arg1.as_deref() {
        Some("-h" | "--help") => {
            println!(
                "karst-relay [ADDR]              start a relay (SKELETON, not for production)\n\
                 karst-relay setup | -i          interactive setup, then start (also: bare run at a\n\
                 \x20                              TTY with no addr/env asks the same questions)\n\
                 karst-relay pow status|off|open|on [BITS]   control a RUNNING relay's door\n\
                 karst-relay invite list|new LABEL|revoke ID one credential per invitee, not one\n\
                 \x20                              shared by everyone (revoke takes effect at once)\n\
                 karst-relay stop                stop a RUNNING relay gracefully (no kill; same\n\
                 \x20                              KARST_RELAY_HOME) — works for a detached node\n\
                 \n\
                 ADDR   listen address:port (arg, else $KARST_RELAY_ADDR, else 127.0.0.1:9000)\n\
                 \n\
                 pow (owner control of a running relay via its admin socket, same KARST_RELAY_HOME):\n\
                   off    stop issuing capabilities (already-earned ones keep working)\n\
                   open   issue WITHOUT proof-of-work — quota-only (use when there is no spam)\n\
                   on N   require N-bit proof-of-work (default 20)\n\
                   status print the current door policy\n\
                 \n\
                 env:\n\
                   KARST_RELAY_ADDR       listen address:port\n\
                   KARST_RELAY_HOME       state dir holding the node key (default ~/.config/karst-relay)\n\
                   KARST_RELAY_MODE       private (default, invite-only) | public (PoW door) | dev (test cap)\n\
                                          an unknown value REFUSES to start (no silent default)\n\
                   KARST_RELAY_POW_BITS   public-door PoW difficulty in leading zero bits (default 20;\n\
                                          0 = open, issue without PoW). Toggle live with `karst-relay pow`.\n\
                   KARST_RELAY_QUOTA      per-capability spend ceiling: chat-only | media-friendly | bytes-only\n\
                                          | unlimited | REQ,BYTES,WINDOW (bytes take K/M/G). Unset = off. Live:\n\
                                          `karst-relay quota`.\n\
                   KARST_RELAY_PEERS      node-list seed: addr@relay-id,addr@relay-id (relays clients learn of)\n\
                   KARST_RELAY_ADVERTISE  routable host:port to list SELF as (default: the listen addr,\n\
                                          skipped if it is 0.0.0.0/loopback — not discoverable then)\n\
                   KARST_RELAY_TLS_CERT   PEM cert  -> enables the wss carrier (with _KEY)\n\
                   KARST_RELAY_TLS_KEY    PEM key\n\
                 \n\
                 the relay-id (printed on start) is what clients pin; it is stable across restarts."
            );
            return Ok(());
        }
        Some("-V" | "--version") => {
            println!("karst-relay {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        _ => {}
    }

    // Interactive setup: explicit `setup`/`-i`/`--interactive` always prompts (also to
    // reconfigure when env IS set); a BARE launch prompts only when it is safe — a human at a
    // TTY with no config given (no addr arg, no KARST_RELAY_* env) — so systemd/scripts that
    // pass an addr or an EnvironmentFile keep the current non-interactive path untouched.
    let explicit_setup = matches!(arg1.as_deref(), Some("setup" | "-i" | "--interactive"));
    let any_relay_env =
        std::env::vars_os().any(|(k, _)| k.to_str().is_some_and(|s| s.starts_with("KARST_RELAY_")));
    let auto_wizard = arg1.is_none() && !any_relay_env && io::stdin().is_terminal();

    let addr = if explicit_setup || auto_wizard {
        run_setup_wizard()?; // populates KARST_RELAY_* for the shared startup path below
        std::env::var("KARST_RELAY_ADDR")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "127.0.0.1:9000".to_string())
    } else {
        // Listen address: CLI arg wins (back-compat), else KARST_RELAY_ADDR (so a systemd
        // EnvironmentFile can hold ALL config and ExecStart is just the binary), else default.
        arg1.or_else(|| std::env::var("KARST_RELAY_ADDR").ok().filter(|s| !s.is_empty()))
            .unwrap_or_else(|| "127.0.0.1:9000".to_string())
    };
    run_relay(addr)
}

/// Start the relay on `addr`, taking the rest of the config from the KARST_RELAY_* environment
/// (mode, home, PoW, advertise, blobs, TLS, peers). The single startup path: a plain launch and
/// the interactive wizard both land here — the wizard just fills that environment in first.
fn run_relay(addr: String) -> io::Result<()> {
    // Friendlier bind failure than a raw io::Error (the common "port already in use").
    let listener = std::net::TcpListener::bind(&addr).map_err(|e| {
        io::Error::new(e.kind(), format!("cannot bind {addr}: {e} (is a relay already running there?)"))
    })?;

    let (fetch_identity, noise_priv, noise_pub) = load_or_create_keys()?;
    let fetch_pub = fetch_identity.public.to_bytes();

    let mut relay = RelayNode::with_identity(wall_clock(), fetch_identity);
    // §15 large-file blob store, under the relay home. The operator chooses its restart behaviour
    // via KARST_RELAY_BLOB_PERSIST (durable = parked blobs survive a restart, the reliable default;
    // ephemeral = wiped on start, the lower-residue posture). Either way the relay only ever holds
    // E2E-encrypted ciphertext, capped + TTL-swept (see docs/STATUS.md on the fat-relay tradeoff).
    let persist = match blob_persistence_from_env() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("karst-relay: config error: {e}");
            std::process::exit(1);
        }
    };
    relay.enable_blobs(key_dir().join("blobs"), wall_clock(), persist)?;
    // R2-5 (#161): the mailbox's own restart posture, independent of the blob store's.
    let mail_persist = match mail_persistence_from_env() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("karst-relay: config error: {e}");
            std::process::exit(1);
        }
    };
    if mail_persist == MailboxDurability::Durable {
        // Fail to start rather than run as a silently volatile relay: a client may have chosen
        // this relay precisely for the advertised guarantee.
        relay.enable_durable_mail(key_dir().join("mail"), wall_clock())?;
    }
    // Fail closed on a misconfigured mode: refuse to start rather than run a role the
    // operator did not choose.
    let role = match Role::from_env() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("karst-relay: config error: {e}");
            std::process::exit(1);
        }
    };
    // PoW difficulty for a Public door (operator-tunable). Ignored by Private/Dev.
    let pow_bits = std::env::var("KARST_RELAY_POW_BITS")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(DEFAULT_POW_BITS);

    // Role-specific admission setup. A Public relay earns caps via PoW (no pre-shared
    // secret — a shared invite would BYPASS the door). Private/Dev hand out a stored
    // capability by invite (or the known dev cap).
    let invite_cap = match role {
        Role::Public => {
            relay.enable_pow_issue(pow_bits);
            None
        }
        Role::Dev => {
            let cap = load_or_create_cap(role)?;
            relay.issue_capability(cap.clone());
            None
        }
        Role::Private => {
            // CRYPTO-25: one credential PER INVITE, not one shared by everyone the operator ever
            // invited. The quota tracker meters by `capability_id`, so a shared invite meant a
            // shared bucket — one invitee's traffic charged against everyone else's — with no way
            // to revoke a single person and no rotation that did not lock out the whole relay.
            let mut invites = load_invites()?;
            if !invites.entries.iter().any(|i| !i.revoked) {
                // First run (or every invite revoked): mint one so the operator has something to
                // hand out, exactly as the old single-capability path did.
                invites.entries.push(mint_invite("first", wall_clock()));
                save_invites(&invites)?;
            }
            let live: Vec<Invite> = invites.entries.iter().filter(|i| !i.revoked).cloned().collect();
            for inv in &live {
                relay.issue_capability(inv.cap.clone());
            }
            eprintln!("invites: {} live (karst-relay invite list)", live.len());
            live.last().cloned()
        }
    };

    // Operator quota CEILING (§7.2), live-tunable via `karst-relay quota ...`. Unset/empty = off
    // (each capability's own quota applies — the historical behaviour).
    match std::env::var("KARST_RELAY_QUOTA").ok().map(|s| parse_quota_spec(&s)) {
        Some(Ok(policy)) => relay.set_quota_policy(policy),
        Some(Err(e)) => {
            eprintln!("karst-relay: config error: KARST_RELAY_QUOTA — {e}");
            std::process::exit(1);
        }
        None => {}
    }

    // Discovery plane (§12 node-list): seed the OPERATOR-CURATED set. SELF FIRST — it must sit
    // at the front so it always survives the frame-fitting trim in `node_list()`; gossip
    // verifies a relay by confirming it serves its OWN self-entry, so a relay that trimmed
    // itself out would become unverifiable and stop propagating. Peers (and later verified-
    // gossiped entries) append after, and never push self out.
    let advertise = std::env::var("KARST_RELAY_ADVERTISE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| addr.clone());
    if is_routable_advertise(&advertise) {
        let self_desc = RelayDescriptor { noise_pub, fetch_pub, addrs: vec![advertise.clone()] };
        relay.add_relay(self_desc.clone());
        // §12 4c — the directory records "user X is reachable HERE" using this descriptor as
        // the node_hint; only meaningful when we have a routable address to hand out.
        relay.set_self_descriptor(self_desc);
    } else {
        eprintln!(
            "node-list: not advertising self ({advertise} is not routable — set KARST_RELAY_ADVERTISE \
             to a reachable host:port to be discoverable)"
        );
    }
    if let Ok(spec) = std::env::var("KARST_RELAY_PEERS") {
        for d in parse_peers(&spec) {
            relay.add_relay(d);
        }
    }
    let known_relays = relay.node_list().len();

    // relay-id = Noise-pub ‖ fetch-auth-pub (оба узнаются вне канала). СТАБИЛЕН
    // между перезапусками, т.к. ключ персистентен. Клиент подаёт как `--relay-id`.
    let mut server =
        RelayServer::with_noise_keypair(relay, Arc::new(wall_clock), noise_priv, noise_pub);
    let relay_id = format!("{}{}", hex::encode(noise_pub), hex::encode(fetch_pub));

    // Optional WebSocket-over-TLS carrier (§15): if both a cert and a key path are
    // given, terminate `wss` so the relay presents a standards-compliant HTTPS/WSS endpoint. Use
    // a REAL cert for the relay's hostname (the wss carrier only works if it validates).
    let carrier = match (std::env::var("KARST_RELAY_TLS_CERT"), std::env::var("KARST_RELAY_TLS_KEY"))
    {
        (Ok(cert), Ok(key)) => {
            let config = node::wss::server_config_from_pem_files(
                std::path::Path::new(&cert),
                std::path::Path::new(&key),
            )
            .unwrap_or_else(|e| {
                // A bad/missing cert or key is an operator mistake, not a crash — say so plainly
                // (no raw io::Error Debug dump) and stop before binding.
                eprintln!(
                    "karst-relay: cannot enable wss — TLS cert/key did not load: {e}\n  \
                     cert: {cert}\n  key:  {key}\n  Give PEM files the relay can read (a full \
                     certificate chain + its private key)."
                );
                std::process::exit(1);
            });
            server = server.with_tls(config);
            "WebSocket-over-TLS (wss)"
        }
        _ => "raw TCP (set KARST_RELAY_TLS_CERT + KARST_RELAY_TLS_KEY for wss)",
    };

    // Write the newest invite's file up front so the connect-block below can point at it. Older
    // invites keep their own files (one per id) — writing them again would be pointless churn on
    // secrets that are already in their holders' hands.
    let invite_path = match invite_cap.as_ref() {
        Some(inv) => match write_invite_file(inv, &relay_id, client_addr_hint(&advertise, &addr)) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("WARNING: could not write invite file: {e}");
                None
            }
        },
        None => None,
    };

    eprintln!("karst-relay (SKELETON, NOT for production) listening on {addr}");
    eprintln!("carrier: {carrier}");
    eprintln!("role: {}", role.name());
    eprintln!(
        "large-file blobs: {} (KARST_RELAY_BLOB_PERSIST)",
        match persist {
            BlobPersistence::Durable => "durable — parked blobs survive a restart",
            BlobPersistence::Ephemeral => "ephemeral — wiped on restart",
        }
    );
    eprintln!(
        "queued mail: {} (KARST_RELAY_MAIL_PERSIST)",
        match mail_persist {
            MailboxDurability::Durable => "durable — an accepted message survives a restart",
            MailboxDurability::Volatile => "volatile — queued mail is lost on restart",
        }
    );
    // #145: say what admission actually rests on, at startup, every time. The capability HMAC
    // and the PoW door are real; the threshold-ring token path has no audited verifier, so this
    // relay refuses token credentials outright rather than falling back to a structural stub.
    eprintln!("admission: capability HMAC (real) + PoW door; token credentials refused (no audited verifier)");
    if role == Role::Public {
        eprintln!("admission: {}", describe_pow(Some(pow_bits)));
        eprintln!("  PoW rate-limits fresh capabilities; the per-cap quota bounds each — a spam");
        eprintln!("  BOUND, not Sybil resistance. See docs/STATUS.md.");
    }
    eprintln!("node-list: {known_relays} relay(s) known (served via GetNodeList; clients: karst relays)");

    // Owner control of a RUNNING relay (turn PoW off/open/on live — early on there may be no
    // spam to gate). Owner-only by fs perms. A crash that skips the socket is not fatal to
    // serving, so a bind failure only warns.
    let invite_ctx =
        InviteCtx { relay_id: relay_id.clone(), addr: client_addr_hint(&advertise, &addr).to_string() };
    match spawn_admin_socket(server.relay_handle(), invite_ctx) {
        Ok(()) => eprintln!(
            "admin: karst-relay pow status|off|open|on [BITS]   (socket {}, KARST_RELAY_HOME-scoped)",
            admin_socket_path().display()
        ),
        Err(e) => eprintln!("WARNING: admin control socket unavailable ({e}); PoW not runtime-toggleable"),
    }

    // §12 gossip: converge on peers' node-lists, verify-before-add. Opt-in — only when peers
    // are configured (the operator asked to participate in discovery). Background thread; each
    // round dials known peers, verifies newly-heard descriptors, and merges the real ones.
    if std::env::var("KARST_RELAY_PEERS").map(|s| !s.trim().is_empty()).unwrap_or(false) {
        let handle = server.relay_handle();
        let self_np = noise_pub;
        // Only a LOCAL-TESTING relay may gossip into private/loopback space. A public or private
        // deployment refuses those destinations, so a hostile peer cannot use gossip to make us
        // connect to 127.0.0.1, an RFC1918 host, or the cloud metadata service (A3-12).
        let allow_private = matches!(role, Role::Dev);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(node::gossip::GOSSIP_INTERVAL_SECS));
            let added = node::gossip::gossip_round(&handle, &self_np, allow_private);
            if added > 0 {
                eprintln!("gossip: verified and learned {added} new relay(s)");
            }
        });
        eprintln!(
            "gossip: on — converging on peers' node-lists every {}s (verify-before-add)",
            node::gossip::GOSSIP_INTERVAL_SECS
        );
    }

    // The LAST thing printed, so it is the takeaway after all the startup noise: the exact three
    // values a client needs. relay-id leads (clients pin it; it is not derivable). For a private
    // relay the invite JSON is printed IN FULL — it is what you paste into the app's "Relay invite"
    // box, so you should not have to go `cat` a file. It is the door key: share only with invitees.
    let client_addr = client_addr_hint(&advertise, &addr);
    eprintln!("\n╭─ clients connect with ───────────────────────────────────────");
    eprintln!("│  relay address   {client_addr}");
    eprintln!("│  relay-id        {relay_id}");
    match role {
        Role::Private => {
            eprintln!("│  admission       private — paste the invite below into the app's");
            eprintln!("│                  \"Relay invite\" box (or: karst import-cap <file>)");
            if let Some(inv) = invite_cap.as_ref() {
                match serde_json::to_string(&InviteFile {
                    relay_id: relay_id.clone(),
                    addr: client_addr.to_string(),
                    label: inv.label.clone(),
                    cap: inv.cap.clone(),
                }) {
                    Ok(j) => {
                        eprintln!("│");
                        eprintln!("│  relay invite (this IS the door key — share only with invitees):");
                        eprintln!("{j}");
                        if let Some(p) = invite_path.as_ref() {
                            eprintln!("│  (also saved to {})", p.display());
                        }
                    }
                    Err(e) => eprintln!("│  WARNING: could not render the invite: {e}"),
                }
            }
        }
        Role::Public => eprintln!("│  admission       open (proof-of-work) — no invite; the app just connects"),
        Role::Dev => eprintln!("│  admission       dev cap (local testing) — the app connects with no invite"),
    }
    if !is_routable_advertise(&advertise) {
        eprintln!("│  note: behind Tor / a reverse proxy? give clients your public / .onion");
        eprintln!("│        address, not {addr}.");
    }
    eprintln!("╰──────────────────────────────────────────────────────────────\n");

    server.serve_listener(listener)
}

/// Map validated wizard answers to the `KARST_RELAY_*` env the normal startup path reads. Pure
/// (no I/O), so the mapping is unit-tested like `Role::parse`/`parse_blob_persistence`. Blank
/// optional answers are OMITTED — they fall back to the very same defaults a plain launch uses,
/// so the wizard never sets a surprising value. PoW bits are emitted ONLY for a public door
/// (private/dev ignore them, so we don't record a misleading number).
#[allow(clippy::too_many_arguments)] // a flat answer sheet reads clearer here than a struct
fn env_from_answers(
    mode: &str,
    addr: &str,
    home: &str,
    advertise: &str,
    pow_bits: &str,
    tls_cert: &str,
    tls_key: &str,
    peers: &str,
    blob: &str,
    mail: &str,
    quota: &str,
) -> Vec<(&'static str, String)> {
    let mut env: Vec<(&'static str, String)> = vec![("KARST_RELAY_MODE", mode.trim().to_string())];
    let mut put = |k: &'static str, v: &str| {
        if !v.trim().is_empty() {
            env.push((k, v.trim().to_string()));
        }
    };
    put("KARST_RELAY_ADDR", addr);
    put("KARST_RELAY_HOME", home);
    put("KARST_RELAY_ADVERTISE", advertise);
    if mode.trim() == "public" {
        put("KARST_RELAY_POW_BITS", pow_bits);
    }
    // The wss carrier needs BOTH a cert AND a key; emit them only as a pair so a half-answer
    // never leaves the relay in a confusing "TLS set but won't start" state.
    if !tls_cert.trim().is_empty() && !tls_key.trim().is_empty() {
        put("KARST_RELAY_TLS_CERT", tls_cert);
        put("KARST_RELAY_TLS_KEY", tls_key);
    }
    put("KARST_RELAY_PEERS", peers);
    put("KARST_RELAY_BLOB_PERSIST", blob);
    put("KARST_RELAY_MAIL_PERSIST", mail);
    // Quota ceiling: skip when it is the "unlimited/off" answer (the built-in default is already
    // off, so no env keeps a scripted launch clean) — any other value (preset or custom) is written.
    if !matches!(quota.trim(), "" | "off" | "unlimited" | "none") {
        put("KARST_RELAY_QUOTA", quota);
    }
    env
}

/// A yes-ish answer to a (y/N) prompt. Default is handled by the caller (blank → its default).
fn is_yes(s: &str) -> bool {
    matches!(s.trim().to_ascii_lowercase().as_str(), "y" | "yes" | "true" | "1")
}

/// Single-quote a value for the "equivalent command" echo when it holds a space or shell-special
/// char (paths can). Plain tokens (addresses, bit counts, modes) pass through untouched.
fn shell_quote(v: &str) -> String {
    if !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric() || b":./,-_@=+".contains(&b)) {
        v.to_string()
    } else {
        format!("'{}'", v.replace('\'', "'\\''"))
    }
}

/// Prompt on STDERR (so stdout stays clean for piping) and read a trimmed line from stdin;
/// a blank line (or EOF) yields `default`.
fn ask(prompt: &str, default: &str) -> io::Result<String> {
    if default.is_empty() {
        eprint!("{prompt}\n  > ");
    } else {
        eprint!("{prompt}\n  [{default}] > ");
    }
    io::stderr().flush()?;
    let mut line = String::new();
    let n = io::stdin().read_line(&mut line)?;
    let ans = line.trim();
    Ok(if n == 0 || ans.is_empty() { default.to_string() } else { ans.to_string() })
}

/// Interactive configuration: ask the operator the decisions that matter, populate the
/// `KARST_RELAY_*` environment, then return so `main` starts the relay through the ordinary
/// path. Fail-closed like the rest of this file — an invalid mode re-prompts, never silently
/// defaults. Ends by printing the exact non-interactive equivalent to script or drop in systemd.
fn run_setup_wizard() -> io::Result<()> {
    eprintln!("── karst-relay interactive setup ──────────────────────────────");
    eprintln!("Press Enter to accept each [default]. A relay starts when you're done.\n");

    // Grouped into labelled sections so it reads like a form, not a wall of questions. Each
    // prompt explains the choice in plain terms; a non-expert should be able to answer it.
    eprintln!("── Admission ── who may use this relay");
    let mode = loop {
        let m = ask(
            "Who is allowed to USE this relay?\n\
             \x20 private  — invite-only. Only people you personally hand an invite file to can\n\
             \x20            send through it. Safest, and the default. (It writes the invite for you.)\n\
             \x20 public   — open to anyone, but every newcomer must burn a little CPU (\"proof-of-\n\
             \x20            work\") to get in, which slows spammers down. For running an open relay.\n\
             \x20 dev      — NO protection at all. Only for testing on your own machine — never expose.",
            "private",
        )?;
        match Role::parse(Some(&m)) {
            Ok(_) => break m,
            Err(_) => eprintln!("  ! '{m}' is not a mode — type: private, public, or dev.\n"),
        }
    };

    eprintln!("\n── Network ── where it listens");
    let addr = ask(
        "Which address:port should it listen on?\n\
         \x20 127.0.0.1:9000  — only THIS computer (local testing; also the right choice if you\n\
         \x20                   will front it with Tor/I2P or a reverse proxy — see Transport)\n\
         \x20 0.0.0.0:9000    — every network interface, reachable from outside (open the firewall port)",
        "127.0.0.1:9000",
    )?;

    eprintln!("\n── Identity ── where its keys live");
    let default_home = key_dir().display().to_string();
    let home = ask(
        "Folder for this relay's permanent files — its identity key (so its address / relay-id\n\
         \x20 stays the SAME across restarts) and, for a private relay, the invite file. Worth\n\
         \x20 backing up: delete it and the relay becomes a different one every client must re-add.",
        &default_home,
    )?;

    // Transport applies to EVERY mode. Tor/I2P is not a relay toggle — you front the relay with
    // your own hidden service and hand out the address; the only thing set here is the optional
    // wss (WebSocket-over-TLS) carrier, which makes the relay look like an ordinary HTTPS site.
    eprintln!("\n── Transport ── how the bytes travel");
    let (mut tls_cert, mut tls_key) = (String::new(), String::new());
    let wss = ask(
        "By default the relay speaks plain TCP on the address above. Two ways to harden that:\n\
         \x20 · Tor / I2P — run your OWN hidden service pointing at 127.0.0.1 (bind loopback in\n\
         \x20               Network), then hand out its .onion/.i2p address. Nothing to set here.\n\
         \x20               (Client-side Tor already exists — it is the app's SOCKS5 setting.)\n\
         \x20 · HTTPS/wss — make the relay look like an ordinary web server behind TLS; needs a\n\
         \x20               real certificate for your hostname.\n\
         \x20 Serve the relay over HTTPS (wss)? (y/N)",
        "n",
    )?;
    if is_yes(&wss) {
        tls_cert = ask("\n  TLS certificate — PEM file (e.g. /etc/letsencrypt/live/HOST/fullchain.pem)", "")?;
        tls_key = ask("  TLS private key — PEM file (e.g. /etc/letsencrypt/live/HOST/privkey.pem)", "")?;
        if tls_cert.trim().is_empty() || tls_key.trim().is_empty() {
            eprintln!("  ! wss needs BOTH a cert and a key — skipping it, staying on plain TCP.");
            tls_cert.clear();
            tls_key.clear();
        }
    }

    // PoW + self-advertise + federation are asked ONLY for a public door: they are meaningless or
    // pure noise on the invite-only common path. Their niche uses stay reachable via env vars.
    let mut pow_bits = String::new();
    let mut advertise = String::new();
    let mut peers = String::new();
    if mode.trim() == "public" {
        eprintln!("\n── Spam door ── how newcomers earn admission");
        pow_bits = ask(
            "How hard should a newcomer work to get in? (proof-of-work, in leading zero bits)\n\
             \x20 Higher = more spam-resistance but slower for honest users; 0 = no work, only rate\n\
             \x20 limits. 20 is a sensible start; change it live later with `karst-relay pow`.",
            &DEFAULT_POW_BITS.to_string(),
        )?;
        eprintln!("\n── Discovery ── how people find this relay");
        advertise = ask(
            "Public address to LIST YOURSELF at, so other apps can discover this relay in the\n\
             \x20 network directory. Use a REAL reachable host:port (relay.example.net:9000 — a\n\
             \x20 .onion works too), not 127.0.0.1. Blank = unlisted; anyone you hand the address\n\
             \x20 to directly can still connect.",
            "",
        )?;
        eprintln!("\n── Federation ── optional, advanced");
        peers = ask(
            "Seed other relays into the shared directory this one gossips? Format:\n\
             \x20 addr@relay-id,addr@relay-id  (128-hex relay-ids). Blank = a standalone relay.",
            "",
        )?;
    }

    eprintln!("\n── Admission budget ── how much one admitted client may send");
    let quota = ask(
        "Per-capability spend CEILING (applies on top of whatever a client presents; change it live\n\
         \x20 later with `karst-relay quota`). A photo is ~90 one-packet requests, so a tight cap\n\
         \x20 throttles image posts hard.\n\
         \x20 chat-only       — tight: a few hundred requests / 10 min\n\
         \x20 media-friendly  — photo albums fit comfortably (default)\n\
         \x20 bytes-only      — meter by VOLUME, not packet count (a request cap that never bites)\n\
         \x20 unlimited       — no ceiling (only sensible for a PRIVATE / trusted relay)\n\
         \x20 or custom:  REQUESTS,BYTES,WINDOW_SECS   (bytes take a K/M/G suffix, e.g. 200000,512M,600)",
        "media-friendly",
    )?;
    // Validate now so a typo is a plain message here, not a startup failure.
    if let Err(e) = parse_quota_spec(quota.trim()) {
        eprintln!("  ! that quota didn't parse ({e}); falling back to media-friendly");
    }
    if mode.trim() == "public" && matches!(quota.trim(), "unlimited" | "off" | "none") {
        eprintln!(
            "  ! WARNING: 'unlimited' on a PUBLIC relay means one proof-of-work buys unbounded\n\
             \x20   sending — the PoW difficulty becomes your only spam lever. Keep a ceiling unless\n\
             \x20   you fully trust who can solve the door."
        );
    }
    let quota = if parse_quota_spec(quota.trim()).is_ok() { quota } else { "media-friendly".to_string() };

    eprintln!("\n── Storage ── large file attachments");
    let blob = ask(
        "When the relay RESTARTS, keep large file-attachments still waiting to be picked up?\n\
         \x20 durable    — keep them on disk so an in-progress transfer survives a restart (default)\n\
         \x20 ephemeral  — wipe them on restart. Less data at rest, but an interrupted big file re-sends.",
        "durable",
    )?;
    let mail = ask(
        "When the relay RESTARTS, keep queued MESSAGES that nobody has picked up yet?\n\
         \x20 volatile   — no. Queued mail lives in memory only; a restart loses it and the sender\n\
         \x20              is never told (least data at rest — the default)\n\
         \x20 durable    — yes. Each accepted message is written to disk before the relay says\n\
         \x20              'accepted', so a restart redelivers it. Encrypted either way; this only\n\
         \x20              changes how long ciphertext sits on your disk.",
        "volatile",
    )?;

    // Populate the env the shared startup path reads (safe here: single-threaded, before any
    // thread is spawned), then show a readable summary + the exact scriptable equivalent.
    let env = env_from_answers(
        &mode, &addr, &home, &advertise, &pow_bits, &tls_cert, &tls_key, &peers, &blob, &mail,
        &quota,
    );
    for (k, v) in &env {
        std::env::set_var(k, v);
    }
    let transport = if tls_cert.trim().is_empty() {
        "plain TCP".to_string()
    } else {
        format!("HTTPS/wss (cert {})", tls_cert.trim())
    };
    eprintln!("\n── ready ──────────────────────────────────────────────────────");
    let row = |k: &str, v: &str| eprintln!("  {k:<11} {v}");
    row("mode", mode.trim());
    row("listen", addr.trim());
    row("state dir", home.trim());
    row("transport", &transport);
    if mode.trim() == "public" {
        row("spam door", &format!("{}-bit proof-of-work", pow_bits.trim()));
        row("discovery", if advertise.trim().is_empty() { "(unlisted)" } else { advertise.trim() });
        row("federation", if peers.trim().is_empty() { "(standalone)" } else { peers.trim() });
    }
    row("storage", blob.trim());
    row("queued mail", mail.trim());
    row("budget", quota.trim());
    let inline: Vec<String> = env.iter().map(|(k, v)| format!("{k}={}", shell_quote(v))).collect();
    eprintln!("\nequivalent non-interactive launch:\n  {} karst-relay\n", inline.join(" "));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        apply_admin_command, describe_pow, env_from_answers, is_stop_command, is_yes, InviteCtx,
        no_relay_message, parse_blob_persistence, parse_mail_persistence, parse_quota_spec,
        shell_quote, Role,
    };
    use node::node::{BlobPersistence, RelayNode};
    use std::sync::{Arc, RwLock};

    #[test]
    fn node_list_peer_parsing_and_routable_checks() {
        use super::{is_routable_advertise, parse_peers, parse_relay_id};
        let id = "aa".repeat(64); // a valid 128-hex relay-id
        let peers = parse_peers(&format!("1.2.3.4:9000@{id}"));
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addrs, vec!["1.2.3.4:9000".to_string()]);
        // Malformed entries are skipped, never fatal.
        assert!(parse_peers("garbage-no-at").is_empty(), "no '@' → skipped");
        assert!(parse_peers("1.2.3.4:9000@zz").is_empty(), "bad hex → skipped");
        // Routability: never advertise a dead self-entry.
        assert!(is_routable_advertise("1.2.3.4:9000"));
        assert!(is_routable_advertise("abc.onion:9000"), "a name is routable");
        assert!(!is_routable_advertise("0.0.0.0:9000"), "unspecified must not be advertised");
        assert!(!is_routable_advertise("127.0.0.1:9000"), "loopback must not be advertised");
        // Length check on the id.
        assert!(parse_relay_id(&id).is_ok());
        assert!(parse_relay_id("aa").is_err());
    }

    #[test]
    fn admin_pow_commands_toggle_the_running_door() {
        // The owner's runtime control: off / open / on N / status, applied to a live relay.
        // Discriminating: each command must move `pow_difficulty()` to the right state, and an
        // unknown command must error WITHOUT changing it.
        let relay = Arc::new(RwLock::new(RelayNode::new(1_000_000)));
        assert_eq!(relay.write().unwrap().pow_difficulty(), None, "a fresh relay issues nothing");

        assert!(apply_admin_command(&relay, "pow open", &InviteCtx::default()).contains("open"));
        assert_eq!(relay.write().unwrap().pow_difficulty(), Some(0), "open → issue without PoW");

        assert!(apply_admin_command(&relay, "pow on 22", &InviteCtx::default()).contains("22"));
        assert_eq!(relay.write().unwrap().pow_difficulty(), Some(22));

        // status reports without mutating.
        assert!(apply_admin_command(&relay, "pow status", &InviteCtx::default()).contains("22"));
        assert_eq!(relay.write().unwrap().pow_difficulty(), Some(22));

        apply_admin_command(&relay, "pow off", &InviteCtx::default());
        assert_eq!(relay.write().unwrap().pow_difficulty(), None, "off → issuance disabled");

        // An unknown command errors and leaves the policy untouched.
        let before = relay.write().unwrap().pow_difficulty();
        assert!(apply_admin_command(&relay, "pow frobnicate", &InviteCtx::default()).starts_with("error"));
        assert_eq!(relay.write().unwrap().pow_difficulty(), before, "a bad command must not change state");
        // The unknown-command help lists `stop` so an operator can discover the no-kill shutdown.
        assert!(apply_admin_command(&relay, "bogus", &InviteCtx::default()).contains("stop"));

        assert!(describe_pow(Some(0)).contains("open"));
        assert!(describe_pow(None).contains("off"));
        assert!(describe_pow(Some(20)).contains("20"));
    }

    #[test]
    fn quota_spec_parses_presets_custom_and_off() {
        assert_eq!(parse_quota_spec("").unwrap(), None); // empty = off
        assert_eq!(parse_quota_spec("unlimited").unwrap(), None);
        assert!(parse_quota_spec("chat-only").unwrap().is_some());
        let m = parse_quota_spec("media-friendly").unwrap().unwrap();
        assert!(m.max_requests >= 100_000, "media preset fits a photo album");
        // Bytes-only meters by volume: the request cap is effectively removed, a real byte ceiling
        // stays. So it bounds bytes but never a client for sending many small packets.
        let b = parse_quota_spec("bytes-only").unwrap().unwrap();
        assert_eq!(b.max_requests, u32::MAX, "bytes-only removes the request cap");
        assert!(b.max_bytes > 0 && b.max_bytes < u64::MAX, "bytes-only keeps a real byte ceiling");
        let c = parse_quota_spec("500,64M,600").unwrap().unwrap();
        assert_eq!(c.max_requests, 500);
        assert_eq!(c.max_bytes, 64 << 20, "M suffix");
        assert_eq!(c.window_secs, 600);
        assert!(parse_quota_spec("nonsense-preset").is_err());
        assert!(parse_quota_spec("500,notabyte,600").is_err());
    }

    #[test]
    fn admin_quota_commands_set_the_live_ceiling() {
        let relay = Arc::new(RwLock::new(RelayNode::new(1_000_000)));
        assert_eq!(relay.write().unwrap().quota_policy(), None, "off by default");

        assert!(apply_admin_command(&relay, "quota preset media-friendly", &InviteCtx::default()).contains("ceiling"));
        assert!(relay.write().unwrap().quota_policy().is_some(), "preset set a ceiling");

        assert!(apply_admin_command(&relay, "quota set 500 64M 600", &InviteCtx::default()).contains("500"));
        assert_eq!(relay.write().unwrap().quota_policy().unwrap().max_requests, 500);

        apply_admin_command(&relay, "quota off", &InviteCtx::default());
        assert_eq!(relay.write().unwrap().quota_policy(), None, "off → no ceiling");

        // status reports without mutating; a bad subcommand errors and leaves state alone.
        assert!(apply_admin_command(&relay, "quota status", &InviteCtx::default()).starts_with("quota:"));
        assert!(apply_admin_command(&relay, "quota preset bogus", &InviteCtx::default()).starts_with("error"));
        assert_eq!(relay.write().unwrap().quota_policy(), None);
    }

    #[test]
    fn role_parse_fails_closed_on_an_unknown_mode() {
        // The fail-closed fix: a typo (or any unrecognised value) must REFUSE, not silently
        // become `private` — otherwise an operator who meant `public` runs a different relay
        // than they think, unnoticed. Neuter `parse` to map the `Some(other)` arm to
        // `Ok(Role::Private)` (the old behaviour) and this reddens.
        assert!(Role::parse(Some("publik")).is_err(), "typo must not silently default");
        assert!(Role::parse(Some("PUBLIC")).is_err(), "case mismatch is unknown → refuse");
        assert!(Role::parse(Some("open")).is_err());
    }

    #[test]
    fn blob_persistence_defaults_durable_and_fails_closed_on_a_typo() {
        // Unset / empty → durable (the reliable default; large uploads survive a restart).
        assert_eq!(parse_blob_persistence(None), Ok(BlobPersistence::Durable));
        assert_eq!(parse_blob_persistence(Some("")), Ok(BlobPersistence::Durable));
        assert_eq!(parse_blob_persistence(Some("durable")), Ok(BlobPersistence::Durable));
        assert_eq!(parse_blob_persistence(Some("ephemeral")), Ok(BlobPersistence::Ephemeral));
        // A typo must REFUSE, not silently pick a posture the operator did not choose.
        assert!(parse_blob_persistence(Some("ephemerel")).is_err());
        assert!(parse_blob_persistence(Some("EPHEMERAL")).is_err(), "case mismatch → refuse");
    }

    #[test]
    fn public_opens_directly_now_that_the_pow_gate_exists() {
        // Slice 4a made `public` a PoW-gated (spam-bounded) door, so the old
        // "unsafe acknowledgement" is retired: `public` opens on the bare mode string.
        // (The safety now lives in the PoW door itself, tested in the node crate.)
        assert_eq!(Role::parse(Some("public")).unwrap(), Role::Public);
    }

    /// CRYPTO-25 (#232): one credential PER INVITE, and revoking one must not touch the others.
    ///
    /// The relay used to mint ONE capability and write it into `invite.json` for everybody. The
    /// quota tracker meters by `capability_id`, so that was one shared bucket — every invitee's
    /// traffic charged against everyone else's — with no way to revoke one person and no rotation
    /// that did not lock out the whole relay.
    ///
    /// Discriminating on the property that actually matters: after revoking Alice, ALICE's proof
    /// is refused and BOB's still verifies. A test that only checked "the ids differ" would pass
    /// against a relay that honoured a revoked credential forever.
    #[test]
    fn revoking_one_invite_leaves_every_other_invite_working() {
        use admission::capability::{CapabilityTable, Scope};
        let now = 1_000_000u64;
        let alice = super::mint_invite("alice", now);
        let bob = super::mint_invite("bob", now);
        assert_ne!(
            alice.cap.capability_id, bob.cap.capability_id,
            "two invites must not share an id — that is what makes them separately meterable"
        );
        assert_ne!(alice.cap.secret, bob.cap.secret, "...nor a secret");

        let mut table = CapabilityTable::new();
        table.insert(alice.cap.clone());
        table.insert(bob.cap.clone());
        let nonce = b"request-nonce";
        let alice_proof = alice.cap.prove(nonce, 0);
        let bob_proof = bob.cap.prove(nonce, 0);
        assert!(table.verify(&alice_proof, nonce, Scope::MessageDelivery, now as u32).is_ok());
        assert!(table.verify(&bob_proof, nonce, Scope::MessageDelivery, now as u32).is_ok());

        assert!(table.remove(&alice.cap.capability_id), "revoking a known id reports success");
        assert!(
            table.verify(&alice_proof, nonce, Scope::MessageDelivery, now as u32).is_err(),
            "a revoked invite must stop opening the door"
        );
        assert!(
            table.verify(&bob_proof, nonce, Scope::MessageDelivery, now as u32).is_ok(),
            "...and every OTHER invitee must be untouched — that is the whole point"
        );
        assert!(!table.remove(&alice.cap.capability_id), "revoking twice reports 'unknown', not success");
    }

    #[test]
    fn private_is_the_safe_default_and_dev_is_explicit() {
        assert_eq!(Role::parse(None).unwrap(), Role::Private, "unset → private");
        assert_eq!(Role::parse(Some("")).unwrap(), Role::Private, "empty → private");
        assert_eq!(Role::parse(Some("private")).unwrap(), Role::Private);
        assert_eq!(Role::parse(Some("dev")).unwrap(), Role::Dev);
    }

    #[test]
    fn wizard_answers_map_to_env_and_omit_blanks() {
        // The pure mapping behind the interactive setup. Blank optional answers must be OMITTED
        // (so they fall back to the plain-launch defaults, not set to ""), and the resulting
        // env must round-trip through the SAME parsers a normal launch uses.
        let env = env_from_answers(
            "public", "0.0.0.0:9000", "/srv/relay", "relay.example:9000", "22",
            "/etc/tls/fullchain.pem", "/etc/tls/privkey.pem", "1.2.3.4:9000@aa", "ephemeral", "durable",
            "media-friendly",
        );
        let get = |k: &str| env.iter().find(|(kk, _)| *kk == k).map(|(_, v)| v.as_str());
        assert_eq!(get("KARST_RELAY_MODE"), Some("public"));
        assert_eq!(get("KARST_RELAY_ADDR"), Some("0.0.0.0:9000"));
        assert_eq!(get("KARST_RELAY_HOME"), Some("/srv/relay"));
        assert_eq!(get("KARST_RELAY_ADVERTISE"), Some("relay.example:9000"));
        assert_eq!(get("KARST_RELAY_POW_BITS"), Some("22"));
        assert_eq!(get("KARST_RELAY_TLS_CERT"), Some("/etc/tls/fullchain.pem"));
        assert_eq!(get("KARST_RELAY_TLS_KEY"), Some("/etc/tls/privkey.pem"));
        assert_eq!(get("KARST_RELAY_PEERS"), Some("1.2.3.4:9000@aa"));
        assert_eq!(get("KARST_RELAY_BLOB_PERSIST"), Some("ephemeral"));
        assert_eq!(get("KARST_RELAY_MAIL_PERSIST"), Some("durable"));
        assert!(parse_mail_persistence(get("KARST_RELAY_MAIL_PERSIST")).is_ok());
        // The values must satisfy the fail-closed parsers (no divergence between wizard + env path).
        assert!(Role::parse(get("KARST_RELAY_MODE")).is_ok());
        assert!(parse_blob_persistence(get("KARST_RELAY_BLOB_PERSIST")).is_ok());

        // Private with everything optional blank: ONLY mode is set; PoW bits are dropped even if
        // typed (they are public-only), and blanks never become empty-string env entries.
        let env = env_from_answers("private", "", "", "", "20", "", "", "", "", "", "");
        assert_eq!(env, vec![("KARST_RELAY_MODE", "private".to_string())], "blanks omitted; pow dropped for private");

        // PoW bits are recorded for a public door.
        let env = env_from_answers("public", "", "", "", "18", "", "", "", "", "", "");
        assert!(env.contains(&("KARST_RELAY_POW_BITS", "18".to_string())));

        // wss is emitted only as a cert+key PAIR — a lone cert (or lone key) is dropped, never
        // half-configured (that would make the relay refuse to start).
        let lone = env_from_answers("public", "", "", "", "20", "/c.pem", "", "", "", "", "");
        assert!(!lone.iter().any(|(k, _)| k.starts_with("KARST_RELAY_TLS")), "lone cert dropped");
    }

    #[test]
    fn yes_no_parsing_for_the_wss_prompt() {
        for y in ["y", "Y", "yes", "YES", "true", "1", "  yes  "] {
            assert!(is_yes(y), "{y:?} is yes");
        }
        for n in ["", "n", "no", "nope", "0", "false", "later"] {
            assert!(!is_yes(n), "{n:?} is not yes");
        }
    }

    #[test]
    fn no_relay_message_is_plain_and_keyed_on_error_kind() {
        use std::io::{Error, ErrorKind};
        let sock = std::path::Path::new("/home/me/.config/karst-relay/admin.sock");
        // No socket at all → "no relay is running", and it must NOT leak a Rust Debug dump.
        let m = no_relay_message(sock, &Error::from(ErrorKind::NotFound));
        assert!(m.contains("no relay is running"), "says plainly no relay: {m}");
        assert!(m.contains("admin.sock"), "shows what it checked");
        assert!(m.contains("KARST_RELAY_HOME"), "hints the custom-dir fix");
        assert!(!m.contains("Custom {"), "must not surface the raw io::Error Debug form");
        // Stale socket (post kill -9) → distinct hint about the signal-vs-stop cause.
        let m = no_relay_message(sock, &Error::from(ErrorKind::ConnectionRefused));
        assert!(m.contains("stale"), "explains a stale socket: {m}");
        assert!(m.contains("karst-relay stop"), "nudges the graceful path");
    }

    #[test]
    fn stop_command_recognised_and_distinct_from_pow() {
        // The graceful-shutdown trigger: `stop`/`shutdown` (with any trailing junk) match; a
        // stray `stopwatch` or a pow line must NOT, or we'd exit on the wrong word.
        assert!(is_stop_command("stop"));
        assert!(is_stop_command("shutdown"));
        assert!(is_stop_command("  stop  "), "leading/trailing space still stops");
        assert!(!is_stop_command("stopwatch"), "only the whole first token counts");
        assert!(!is_stop_command("pow off"));
        assert!(!is_stop_command(""));
    }

    #[test]
    fn shell_quote_wraps_only_when_needed() {
        assert_eq!(shell_quote("127.0.0.1:9000"), "127.0.0.1:9000", "plain token unquoted");
        assert_eq!(shell_quote("/srv/karst-relay"), "/srv/karst-relay");
        assert_eq!(shell_quote("public"), "public");
        assert_eq!(shell_quote("/tmp/a b"), "'/tmp/a b'", "space forces quoting");
        assert_eq!(shell_quote(""), "''", "empty forces quoting");
    }
}
