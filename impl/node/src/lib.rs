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
// Injectable failure points for crash-consistency tests (QA-2). Behind an off-by-default feature;
// with it off the macro expands to nothing at all. See the module for why `abort` and not `panic`.
pub mod failpoint;
pub mod blobstore;
pub mod discovery;
// What a helper node may SEE, as a checked invariant rather than a table someone maintains
// (NODE-2). Test-only, like `identity_guard` next door: it asserts a property about this
// workspace's own shape, so it compiles away entirely in a release build.
#[cfg(test)]
mod helper_guard;
pub mod protocol;

// The crypto primitives live in their own crate now (#247). Re-exported so every `node::seal::…`
// path in this workspace keeps working: the CUT is the dependency direction, not a rename, and
// making thirty call sites churn would bury the one change that matters.
pub use karst_crypto::{blind, pqxdh, ratchet, safety, seal, session, veil};
pub mod wire;
