// One-off diagnostic: dump an account's proxies, contacts, and per-proxy session graph so a split
// (each side on a different drop_seed with no matching inbound) is visible. Usage:
//   cargo run -p client --example inspect_vault -- <vault_dir> <password>
use client::store::{Opened, Vault};

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<String>()
}
fn short(b: &[u8; 32]) -> String {
    format!("{}…{}", hx(&b[..4]), hx(&b[28..]))
}

fn main() {
    let mut a = std::env::args().skip(1);
    let dir = a.next().expect("vault dir");
    let pw = a.next().expect("password");
    let vault = match Vault::open(&dir, pw.as_bytes()).expect("open vault") {
        Opened::Real(v) => v,
        Opened::Decoy(_) => { println!("!! DECOY password — this is not the real account"); return; }
        Opened::Wipe => { println!("!! WIPE password"); return; }
        Opened::Hidden(p) => { println!("!! HIDDEN container ({} bytes) — not the real account", p.len()); return; }
    };
    let reg = vault.load_registry().expect("registry");
    let id = reg.first().map(|e| e.id.clone()).expect("an account");
    let root = vault.account(&id);
    let mode = a.next();

    // `... <dir> <pw> forget` — clear every contact's session across every proxy, under the
    // sessions flock so a concurrent desktop poll can't resurrect it. Then a fresh send re-handshakes.
    if mode.as_deref() == Some("forget") {
        let contacts = root.load_contacts().unwrap_or_default();
        for p in root.load_proxies() {
            let ps = root.as_proxy(p.index);
            let _lock = ps.lock_sessions().expect("lock sessions");
            let mut st = ps.load_sessions().expect("load sessions");
            let mut any = false;
            for c in &contacts {
                if st.forget_peer(&c.ik) {
                    println!("proxy #{}: forgot session with {}", p.index, short(&c.ik));
                    any = true;
                }
            }
            if any {
                ps.save_sessions(&st).expect("save sessions");
            }
        }
        return;
    }
    let root_ik = root.load_account().map(|ac| ac.identity_public()).unwrap_or([0; 32]);
    println!("== VAULT {dir}  (account id {id}) ==");
    println!("root IK: {}", short(&root_ik));

    let prof = root.load_profile().unwrap_or_default();
    println!("\n-- own profile --");
    println!("  name={:?} bio={:?} avatar={}", prof.name, prof.bio, prof.avatar.is_some());

    let unconf = root.load_unconfirmed().unwrap_or_default();
    println!("\n-- contacts (● = confirmed, ○ = chat-only) --");
    for c in root.load_contacts().unwrap_or_default() {
        let mark = if unconf.contains(&c.ik) { '○' } else { '●' };
        println!("  {mark} {:20} ik={}  via proxy {:?}", c.name, short(&c.ik), root.contact_proxy(&c.ik));
    }

    println!("\n-- peer profiles (cached name/bio we'd display) --");
    for (ik, p) in root.load_peer_profiles().unwrap_or_default() {
        println!("  {} name={:?} bio={:?} avatar={}", short(&ik), p.name, p.bio, p.avatar.is_some());
    }

    // `... <dir> <pw> poll` — actually RECEIVE from the configured relay (the desktop's poll), so we
    // can see whether a message already sent by the peer arrives and establishes a session.
    if mode.as_deref() == Some("poll") {
        let net = root.load_net().unwrap_or_default();
        let addr = node::transport::Dest::parse(net.relay_addr.trim()).expect("relay addr");
        let id = client::RelayId::parse(net.relay_id.trim()).expect("relay id");
        let relay = client::Relay::configured(addr, id, None, "");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        for p in root.load_proxies().into_iter().filter(|p| p.active) {
            let ps = root.as_proxy(p.index);
            match client::recv_session_multi(&ps, std::slice::from_ref(&relay), now) {
                Ok(poll) => {
                    let msgs: Vec<_> = poll.messages.into_iter().flatten().collect();
                    println!("proxy #{}: {} message(s), failed relays {:?}", p.index, msgs.len(), poll.failed);
                    for m in &msgs {
                        match client::content::decode(&m.plaintext) {
                            Ok(c) => println!("    from {}: {:?}", short(&m.sender), std::mem::discriminant(&c)),
                            Err(_) => println!("    from {}: ({} raw bytes)", short(&m.sender), m.plaintext.len()),
                        }
                    }
                    let st = ps.load_sessions().unwrap_or_else(|_| node::peer::PeerState::empty());
                    let (out, inb) = st.debug_peers();
                    println!("    now holds: {} outbound, {} inbound session(s)", out.len(), inb.len());
                }
                Err(e) => println!("proxy #{}: recv error: {e}", p.index),
            }
        }
        return;
    }

    // `... <dir> <pw> burn <index>` — deactivate a junk/auto-created channel.
    if mode.as_deref() == Some("burn") {
        let idx: u32 = a.next().expect("proxy index").parse().expect("index");
        root.set_proxy_active(idx, false).expect("burn");
        println!("proxy #{idx} deactivated");
        return;
    }
    // `... <dir> <pw> rmcontact <ik_prefix>` — remove a stale contact (by hex prefix).
    if mode.as_deref() == Some("rmcontact") {
        let pref = a.next().expect("ik prefix").to_lowercase();
        let mut cs = root.load_contacts().unwrap_or_default();
        let before = cs.len();
        cs.retain(|c| !hx(&c.ik).starts_with(&pref));
        if cs.len() != before {
            root.save_contacts(&cs).expect("save contacts");
            println!("removed {} contact(s) matching {pref}", before - cs.len());
        } else {
            println!("no contact matched {pref}");
        }
        return;
    }

    // `... <dir> <pw> refreshcap` — overwrite the account's dev capability with the current (raised
    // quota) one, so stuck-in-outbox chunks flush without waiting for the old window.
    if mode.as_deref() == Some("refreshcap") {
        root.save_capability(&client::dev_capability()).expect("save capability");
        println!("dev capability refreshed (raised quota)");
        return;
    }

    // `... <dir> <pw> atts` — dump the feed_attachments sidecar (how many attachments per post).
    if mode.as_deref() == Some("atts") {
        let map = root.load_feed_attachments();
        if map.is_empty() {
            println!("(no attachments)");
        }
        for ((author, id), list) in &map {
            println!("post {} by {} : {} attachment(s)", hx(id), short(author), list.len());
            for a in list {
                let k = if a.kind == 1 { "file" } else { "image" };
                println!("    [{}] {} {:?} {} bytes", a.index, k, a.name, a.bytes.len());
            }
        }
        let imgs = root.load_feed_images();
        println!("legacy single-image sidecar: {} entries", imgs.len());
        return;
    }

    println!("\n-- proxies + their session graph --");
    for p in root.load_proxies() {
        let ps = root.as_proxy(p.index);
        let ik = ps.load_account().map(|ac| ac.identity_public()).unwrap_or([0; 32]);
        let st = ps.load_sessions().unwrap_or_else(|_| node::peer::PeerState::empty());
        let (out, inb) = st.debug_peers();
        println!("  proxy #{} active={} IK={} outbox={}", p.index, p.active, short(&ik), st.outbox_len());
        for (peer, seed) in &out {
            println!("      OUT  → peer {}  drop_seed {}", short(peer), short(seed));
        }
        for (peer, seed) in &inb {
            println!("      IN   ← peer {}  drop_seed {}", short(peer), short(seed));
        }
        if out.is_empty() && inb.is_empty() {
            println!("      (no sessions)");
        }
    }

    println!("\n-- feed ({} posts) --", root.load_feed().map(|f| f.len()).unwrap_or(0));
}
