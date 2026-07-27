//! `gui` — десктоп-GUI KARST (egui/eframe) поверх верифицированного `client`.
//!
//! **Ноль новой крипты.** GUI — ПОТРЕБИТЕЛЬ библиотеки: один worker-поток владеет
//! одним `Store` (unlock паролем один раз) и вызывает `client::send_session`/
//! `recv_session`/`publish_bundle` ДОСЛОВНО. Каждый вызов перечитывает/перешифровывает
//! `sessions.dat` под flock ровно как CLI — расточительно, но КОРРЕКТНО, и все
//! крипто-инварианты (keystream-reuse по обеим осям, at-rest) остаются в библиотеке.
//!
//! Слои: `controller` (чистое состояние+действия, тестируем без egui/сети) и
//! `worker` (сеть/Store в фоне, тестируем против живого relay). Рендер (egui) —
//! тонкий `app` в бинаре, компилируется, но НЕ run-verified без дисплея.

pub mod avatar;
pub mod controller;
pub mod i18n;
pub mod worker;
