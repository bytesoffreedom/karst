//! KARST — рабочий скелет узла: первый раз, когда куски §7 (admission)
//! становятся ПУТЁМ СООБЩЕНИЯ, а не изолированными механизмами.
//!
//! Скелет проводит одно зашифрованное сообщение Alice → relay → Bob
//! in-process, с реальным admission-handshake (§7) и реальным (но classical-
//! only, см. `seal`) E2E-конвертом. Relay гейтит по credential и НЕ видит
//! содержимое. Сессионный §2.1 (`peer`: PQXDH `pqxdh` + Double Ratchet `ratchet`)
//! — реальный E2E in-process пути сообщения; `seal` ещё несёт сокет/CLI-путь, пока
//! §12 discovery (`peer::publish`/`connect`) и персистентность сессий
//! (`Session::snapshot`/`restore`, `Peer::export_state`/`import_state`)
//! реализованы — CLI `karst` целиком на §2.1. `seal` остаётся лишь как
//! demo-путь `Client`/`Recipient` (тесты). Android-клиент — следующий срез.
//!
//! Границы честно: `seal::SkeletonSeal` — НЕ §2.1 (нет FS/ratchet/PQ), это
//! отложено по выбору, не внешняя стена. Подробности — в doc модуля `seal`.

/// Mailbox deposit/fetch key separation via Ristretto point-blinding — wired into the live
/// drop-box path for established sessions (reference construction; the Schnorr fetch proof is
/// unaudited, first-contact openers keep the identity mailbox + DH proof). See the module.
pub mod blind;
pub mod blobstore;
pub mod discovery;
pub mod drop;
pub mod gossip;
pub mod mailstore;
pub mod node;
pub mod peer;
pub mod pqxdh;
pub mod ratchet;
pub mod safety;
pub mod seal;
pub mod session;
pub mod socket;
pub mod transport;
pub mod wire;
pub mod wss;
