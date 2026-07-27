//! `karst-gui` — десктоп-клиент KARST (egui). UI-поток + фоновый worker-поток
//! (сеть/Store) общаются через каналы; UI НИКОГДА не блокируется на сети.
//!
//! Каталог состояния — `$KARST_HOME` (или `~/.config/karst`), как у CLI.
//! Пароль вводится в окне (не env), но живёт в памяти процесса — та же граница
//! hot-процесса, что у CLI (at-rest защищает ХОЛОДНЫЙ диск).

mod app;

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use client::store::Store;
use gui::worker::{run, WorkerCfg};

fn main() -> eframe::Result<()> {
    let dir = std::env::var("KARST_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| Store::default_dir());

    // Настроено ли устройство → экран входа паролем; иначе — приветствие
    // (создать/восстановить первый аккаунт). `accounts.dat` = реестр мультиаккаунта;
    // `seed.key` = legacy одиночный аккаунт (мигрируется при первом Vault::unlock).
    let has_account = dir.join("accounts.dat").exists() || dir.join("seed.key").exists();

    // UI language preference: plaintext file in KARST_HOME (must be readable BEFORE
    // any vault is unlocked, since the login screen is localized). Absent/unknown ->
    // default language.
    let lang = std::fs::read_to_string(dir.join("lang"))
        .ok()
        .and_then(|s| gui::i18n::Lang::from_code(s.trim()))
        .unwrap_or_default();

    let (cmd_tx, cmd_rx) = mpsc::channel();
    let (evt_tx, evt_rx) = mpsc::channel();

    let worker_dir = dir.clone();
    // A sender clone for the worker: file-transfer threads post internal Cmds
    // (BlobUploadDone/…) back into the SAME channel the worker already drains
    // (std mpsc cannot select over two Receivers).
    let worker_cmd_tx = cmd_tx.clone();
    thread::spawn(move || {
        run(
            WorkerCfg {
                dir: worker_dir,
                poll_interval: Duration::from_secs(2),
                cover_traffic: true,
            },
            cmd_rx,
            worker_cmd_tx,
            evt_tx,
        );
    });

    let native = eframe::NativeOptions::default();
    eframe::run_native(
        "KARST",
        native,
        Box::new(move |_cc| {
            Ok(Box::new(app::KarstApp::new(cmd_tx, evt_rx, has_account, dir, lang)) as Box<dyn eframe::App>)
        }),
    )
}
