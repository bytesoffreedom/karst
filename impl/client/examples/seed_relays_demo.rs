//! Seed a KARST_HOME with an account that multi-homes to a LIVE primary, a LIVE
//! backup, and a DEAD backup — for the VISUAL smoke of the per-relay reachability
//! dots. Not product; a verification tool.
//!
//!   KARST_HOME=/tmp/karst-relays KARST_PASSPHRASE=pw \
//!   PRIMARY=127.0.0.1:9000 PRIMARY_ID=<hex> \
//!   BACKUP=127.0.0.1:9001 BACKUP_ID=<hex> DEAD=127.0.0.1:1 \
//!   cargo run -p client --example seed_relays_demo

use client::seed;
use client::store::{AccountEntry, NetSettings, Vault};

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("set {k}"))
}

fn main() {
    let home = env("KARST_HOME");
    let pass = std::env::var("KARST_PASSPHRASE").unwrap_or_else(|_| "pw".into());
    let vault = Vault::unlock(&home, pass.as_bytes()).expect("vault unlock");

    let phrase = seed::DEMO_PHRASE;
    let entropy = seed::entropy_of(&seed::parse_mnemonic(phrase).unwrap());
    let ik = seed::derive(&entropy).account.identity_public();
    let id = hex::encode(ik);
    vault.create_account_dir(&id).unwrap();
    let store = vault.account(&id);
    store.save_seed(&entropy).unwrap();
    // A capability belongs to ONE relay (CRYPTO-24), so the demo seeds the dev credential for
    // each relay it configures below — primary and backup.
    for id_hex in [env("PRIMARY_ID"), env("BACKUP_ID")] {
        let rid = client::RelayId::parse(&id_hex).expect("relay-id hex");
        store.save_capability_for(&rid, &client::dev_capability()).unwrap();
    }
    vault.save_registry(&[AccountEntry { id: id.clone(), label: "Демо".into(), ik }]).unwrap();

    store
        .save_net(&NetSettings {
            relay_addr: env("PRIMARY"),
            relay_id: env("PRIMARY_ID"),
            socks5: String::new(),
            routes: String::new(),
            mixnet: false,
        })
        .unwrap();

    // A LIVE backup (should read green) and a DEAD one (well-formed id, unreachable
    // address → red). The dead entry reuses a valid id so it PARSES into the set.
    store
        .save_extra_relays(&[
            (env("BACKUP"), env("BACKUP_ID")),
            (env("DEAD"), env("BACKUP_ID")),
        ])
        .unwrap();

    println!("seeded home={home} ik={id}");
}
