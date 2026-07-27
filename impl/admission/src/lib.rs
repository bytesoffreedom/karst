//! KARST — референсная реализация admission-протокола (KARST_SPEC.md §7).
//!
//! Область: криптографический admission-путь (§7.1–7.6). Это самый
//! конкретно специфицированный и наиболее нагруженный криптографией кусок
//! спецификации — и потому первый, где prose-аудит структурно не мог
//! проверить, что примитивы (Privacy Pass + threshold ring signature + RLN)
//! реально КОМПОНУЮТСЯ на настоящей крипто-библиотеке. Реализация здесь —
//! это тот рецензент, которым проза быть не может.
//!
//! Явно вне области этого крейта (и почему):
//! - §7.3 threshold ring signature (Bresson–Stern–Szydlo) — нет готового
//!   crate; определён как trait + документированный mock (см. `token`).
//! - §7.4 zk_proof-обёртка RLN — требует circom/halo2-контура, не
//!   off-the-shelf примитив; реализовано ядро (nullifier + Shamir-slashing),
//!   zk-обёртка явно застаблена (см. `rln`).

pub mod params;
pub mod cookie;
pub mod capability;
pub mod pow;
pub mod rln;
pub mod token;
pub mod pipeline;
pub mod dtn;

/// §7.3 threshold ring signature — РЕФЕРЕНС, НЕ ПРОШЁЛ АУДИТ.
/// Только за feature-флагом `unaudited-crypto` (по умолчанию выключен).
#[cfg(feature = "unaudited-crypto")]
pub mod tring;
