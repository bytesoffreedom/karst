//! Seed KARST_HOME with demo data for VISUAL inspection of the GUI (reactions, a reply, an edit, a
//! block). Not part of the product — a tool for looking at the interface.
//!
//!   KARST_HOME=/tmp/karst-demo KARST_PASSPHRASE=pw cargo run -p client --example seed_demo

use client::content::msg_id;
use client::seed;
use client::store::{AccountEntry, ContactRecord, HistoryRecord, Vault};

fn b(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn main() {
    let home = std::env::var("KARST_HOME").expect("KARST_HOME");
    let pass = std::env::var("KARST_PASSPHRASE").unwrap_or_else(|_| "pw".into());
    let vault = Vault::unlock(&home, pass.as_bytes()).expect("vault unlock");

    // Our own account from a fixed test phrase.
    let phrase = seed::DEMO_PHRASE;
    let entropy = seed::entropy_of(&seed::parse_mnemonic(phrase).unwrap());
    let ik = seed::derive(&entropy).account.identity_public();
    let id = hex::encode(ik);
    vault.create_account_dir(&id).unwrap();
    let store = vault.account(&id);
    store.save_seed(&entropy).unwrap();
    vault.save_registry(&[AccountEntry { id: id.clone(), label: "Demo".into(), ik }]).unwrap();

    // The peer, "Bob".
    let bob = seed::derive(&[7u8; seed::ENTROPY_BYTES]).account.identity_public();
    store.save_contacts(&[ContactRecord { name: "Bob".into(), ik: bob, verified: true }]).unwrap();

    // The conversation.
    let recs = [
        HistoryRecord { from_me: false, peer_ik: bob, text: b("Hey! how are things?"), ts: 1000 },
        HistoryRecord { from_me: true, peer_ik: bob, text: b("good, thanks"), ts: 1001 },
        HistoryRecord { from_me: false, peer_ik: bob, text: b("send a screenshot when you can"), ts: 1002 },
    ];
    for r in &recs {
        store.append_history(r).unwrap();
    }

    // Reactions on Bob's first (incoming) message (the author is bob).
    let m0 = msg_id(&bob, 1000, "Hey! how are things?".as_bytes());
    store.set_reaction(m0, "👍", ik, true).unwrap();
    store.set_reaction(m0, "👍", bob, true).unwrap();
    store.set_reaction(m0, "🔥", ik, true).unwrap();

    // My message — a reply to Bob's first.
    let m1 = msg_id(&ik, 1001, "good, thanks".as_bytes());
    store.set_reply(m1, m0).unwrap();
    // And the same message, edited.
    store.set_edit(m1, 1005, "good, thanks a lot!".as_bytes()).unwrap();

    // Profiles: own (shown in the side-panel editor) + Bob's received profile
    // (shown as a hint in the chat header, layered over the local label).
    store
        .save_profile(&client::store::Profile {
            name: "Alice".into(),
            bio: "cryptographer, dog person".into(),
            avatar: None,
            photos: vec![],
            photos_ts: 0,
        })
        .unwrap();
    store.set_peer_profile(bob, "Bob (self-declared)", "just here for the memes").unwrap();

    // Optional avatar seeding for visual smoke: KARST_AVATAR_PNG=/path/to.png sets
    // both our own and Bob's avatar from that file's raw bytes (already a small PNG).
    if let Ok(path) = std::env::var("KARST_AVATAR_PNG") {
        let png = std::fs::read(&path).expect("read KARST_AVATAR_PNG");
        store.set_own_avatar(Some(png.clone())).unwrap();
        store.set_peer_avatar(bob, png).unwrap();
        println!("seeded avatars from {path}");
    }

    println!("seeded home={home} ik={id} bob={}", hex::encode(bob));
}
