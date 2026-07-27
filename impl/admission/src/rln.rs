//! §7.4 — RLN-подобное квотирование: ядро nullifier + Shamir-slashing.
//!
//! Спека (§7.4):
//! ```text
//! RLNProof {
//!   epoch_id
//!   external_nullifier = Hash(epoch_id || relay_scope_id)
//!   nullifier          = Poseidon(identity_secret, external_nullifier)
//!   a1                 = identity_secret + message_hash * a0   // доля Шамира
//!   zk_proof
//! }
//! ```
//! Механизм — не превентивный блок, а экономическое наказание: два разных
//! предъявления одного `identity_secret` в одну эпоху с разными
//! `message_hash` позволяют восстановить `identity_secret` из двух `a1`.
//!
//! # Что реализовано, а что нет (граница честно обозначена)
//!
//! Реализовано настоящее конечное-поле-ядро: вывод slope/nullifier и
//! свойство восстановления секрета из двух долей. Поле — скалярное поле
//! Curve25519 (простой порядок `l`), даёт реальную модульную арифметику с
//! инверсией.
//!
//! НЕ реализовано (и не может быть off-the-shelf): `zk_proof`-обёртка,
//! доказывающая в нуле разглашения, что (а) `identity_secret` в дереве
//! допущенных, (б) `nullifier` и `a1` корректно выведены из него. Это
//! требует circom/halo2-контура, а не примитива с crates.io — см.
//! `ZkProofStub`.
//!
//! # Находка, вскрытая реализацией (не видна prose-аудиту) — см. NOTE ниже.

use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// Элемент поля — скаляр Curve25519 (mod простого порядка `l`).
pub type Field = Scalar;

/// Хэш произвольных байт в элемент поля (равномерно, wide-reduction).
/// В спеке — Poseidon (SNARK-дружественный); здесь для референс-ядра взят
/// SHA-512→wide-reduce. Подстановка НЕ влияет на проверяемое свойство
/// (восстановление секрета из двух долей) — оно чисто полевое и от выбора
/// хэша не зависит; Poseidon нужен лишь чтобы тот же расчёт был дёшев
/// ВНУТРИ zk-контура, которого здесь нет.
fn hash_to_field(parts: &[&[u8]]) -> Field {
    let mut h = Sha512::new();
    for p in parts {
        h.update((p.len() as u64).to_be_bytes()); // домен-разделение по длине
        h.update(p);
    }
    let out = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&out);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// external_nullifier = Hash(epoch_id || relay_scope_id) (§7.4).
pub fn external_nullifier(epoch_id: u32, relay_scope_id: &[u8]) -> Field {
    hash_to_field(&[b"karst-rln-ext", &epoch_id.to_be_bytes(), relay_scope_id])
}

/// Секрет личности (a_0 линии в терминах стандартного RLN — но в СПЕКЕ
/// именно этот секрет назван `identity_secret`, а slope назван `a0`; ниже
/// придерживаемся имён спеки).
#[derive(Clone, Copy)]
pub struct IdentitySecret(pub Field);

impl IdentitySecret {
    /// Детерминированный slope линии разделения для данной эпохи.
    ///
    /// В спеке уравнение доли `a1 = identity_secret + message_hash * a0`
    /// использует `a0` как наклон, но НЕ определяет, откуда `a0` берётся.
    /// Стандартный RLN выводит наклон как `H(identity_secret ||
    /// external_nullifier)` — принимаем это; наклон обязан быть стабилен на
    /// эпоху (иначе две доли не лягут на одну линию) и секретен (иначе см.
    /// NOTE о nullifier ниже).
    pub fn slope(&self, ext_nullifier: &Field) -> Field {
        hash_to_field(&[
            b"karst-rln-slope",
            self.0.as_bytes(),
            ext_nullifier.as_bytes(),
        ])
    }

    /// Публичный per-эпоха тег для обнаружения двойного предъявления.
    ///
    /// NOTE (находка, вскрытая реализацией) — расхождение со спекой §7.4.
    /// Спека пишет `nullifier = Poseidon(identity_secret, external_nullifier)`
    /// — ровно тот же вход, что у наклона `a0`. Если публичный `nullifier`
    /// РАВЕН наклону, то, опубликовав его рядом с ОДНОЙ долей `a1`, кто угодно
    /// считает `identity_secret = a1 - message_hash * a0` из ОДНОГО сообщения
    /// — это деанонимизирует по первому же сообщению и ломает само свойство
    /// «наказывается только повторное превышение квоты». Наклон обязан
    /// оставаться секретным; для детекции нужен ОТДЕЛЬНЫЙ тег, не равный
    /// наклону. Стандартный RLN так и делает: `internal_nullifier =
    /// Poseidon(slope)` (хэш наклона, не сам наклон). Реализуем корректный
    /// вариант; в спеке эту формулу нужно поправить (см. §7.4 патч).
    pub fn nullifier(&self, ext_nullifier: &Field) -> Field {
        let slope = self.slope(ext_nullifier);
        hash_to_field(&[b"karst-rln-null", slope.as_bytes()])
    }
}

/// Доля Шамира по одному сообщению: точка (x, y) на прямой
/// `y = identity_secret + slope * x`, где x = message_hash.
/// (В спеке сама `y` названа `a1`.)
#[derive(Clone, Copy)]
pub struct Share {
    /// x — хэш сообщения (точка вычисления).
    pub message_hash: Field,
    /// y — значение доли (`a1` в терминах спеки).
    pub a1: Field,
    /// Публичный тег эпохи+личности, по которому детектируется повтор.
    pub nullifier: Field,
    /// Публичный вход `external_nullifier = H(epoch_id ‖ scope)`, из которого
    /// выведены `nullifier`/`slope`. Relay проверяет его на актуальность эпохи
    /// (zk-обёртка привязывает к нему nullifier, но НЕ гарантирует, что эпоха
    /// текущая — это relay-side freshness-проверка публичного входа).
    pub external_nullifier: Field,
}

impl IdentitySecret {
    /// Выпустить долю для конкретного сообщения в конкретной эпохе.
    pub fn share(&self, ext_nullifier: &Field, message_hash: Field) -> Share {
        let slope = self.slope(ext_nullifier);
        let a1 = self.0 + message_hash * slope;
        Share {
            message_hash,
            a1,
            nullifier: self.nullifier(ext_nullifier),
            external_nullifier: *ext_nullifier,
        }
    }
}

/// Результат попытки slashing по двум долям.
#[derive(Debug, PartialEq, Eq)]
pub enum SlashResult {
    /// Восстановлен секрет личности (квота превышена, нарушитель деанонимизирован).
    Recovered([u8; 32]),
    /// Доли принадлежат разным личностям/эпохам (nullifier'ы различаются) —
    /// восстанавливать нечего, это не двойное предъявление.
    DifferentNullifier,
    /// Один и тот же message_hash (не два разных сообщения) — вырожденный
    /// случай, x1 == x2, прямая не восстановима (и это не нарушение квоты:
    /// повтор идентичного сообщения = один и тот же RLNProof).
    SameMessage,
}

/// §7.4 — восстановление `identity_secret` из двух долей одной эпохи.
///
/// Две точки (x1,y1),(x2,y2) на прямой `y = s + slope*x` однозначно задают
/// прямую: `slope = (y2-y1)/(x2-x1)`, `s = y1 - slope*x1`. Это и есть
/// «экономическое наказание»: превысил квоту (>1 доля на эпоху) — раскрыл
/// секрет.
pub fn slash(s1: &Share, s2: &Share) -> SlashResult {
    if s1.nullifier != s2.nullifier {
        return SlashResult::DifferentNullifier;
    }
    let dx = s2.message_hash - s1.message_hash;
    if dx == Scalar::ZERO {
        return SlashResult::SameMessage;
    }
    let slope = (s2.a1 - s1.a1) * dx.invert();
    let secret = s1.a1 - slope * s1.message_hash;
    SlashResult::Recovered(secret.to_bytes())
}

/// Явный стаб zk-обёртки (§7.4, поле `zk_proof`).
///
/// НЕ реализовано намеренно: доказательство в нуле разглашения, что
/// `identity_secret` — лист допущенного Merkle-дерева и что `nullifier`/`a1`
/// корректно из него выведены, требует арифметического контура (circom/
/// halo2) и trusted setup либо прозрачного STARK — это не примитив «взять с
/// crates.io», а отдельный слой. Без него ядро выше проверяет полевую
/// математику slashing, но НЕ доказывает, что предъявитель доли реально в
/// множестве допущенных. Это честная граница референс-реализации.
#[derive(Debug, Clone, Copy)]
pub struct ZkProofStub;

impl ZkProofStub {
    /// Всегда возвращает `false`: заглушка не верифицирует ничего и не должна
    /// приниматься за рабочую проверку членства.
    pub fn verify(&self) -> bool {
        false
    }
}

// ============================================================================
// RLN quota-слой: детекция двойного предъявления + slashing (§7.4)
// ============================================================================

/// Исход наблюдения доли трекером квоты.
#[derive(Debug, PartialEq, Eq)]
pub enum RlnOutcome {
    /// Первое сообщение этой личности в эпоху — в пределах квоты.
    Accepted,
    /// Ровно то же сообщение (тот же message_hash) — повтор, не нарушение
    /// квоты (это один и тот же RLNProof).
    Duplicate,
    /// Превышение квоты: второе РАЗНОЕ сообщение той же личности в одну эпоху.
    /// Секрет восстановлен — нарушитель деанонимизирован (экономическое
    /// наказание, а не превентивный блок).
    QuotaViolation { recovered_secret: [u8; 32] },
    /// `external_nullifier` доли не соответствует ни текущей эпохе, ни
    /// предыдущей (grace) — устаревшая/будущая эпоха. БЕЗ этой проверки лимит
    /// обходится циклированием `epoch_id` (каждая эпоха даёт свежий nullifier).
    WrongEpoch,
    /// Трекер полон (bounded memory) — сигнал backpressure/PoW, как у
    /// live-replay-фильтра (§7.5).
    Backpressure,
}

/// Трекер RLN-квоты на один relay-scope. Держит nullifier-состояние текущей и
/// предыдущей эпохи (grace-окно `GRACE_EPOCHS = 1`, как cookie §7.1).
///
/// # ГРАНИЦА (честно): что этот слой гарантирует, а что нет
///
/// Реализует rate-limit «≤ 1 сообщение на личность в эпоху» через детекцию
/// повторного nullifier + slashing (§7.4). Лимит = 1, потому что ядро
/// `Share` — прямая (degree-1); лимиты > 1 требуют полинома степени `limit` и
/// восстановления из `limit+1` долей — этого в ядре нет.
///
/// **Трекер ПРЕДПОЛАГАЕТ, что доли уже zk-верифицированы** (membership в
/// дереве допущенных + корректность вывода `nullifier`/`a1` из секрета) —
/// то есть что за `ZkProofStub` стоит настоящая проверка. Она НЕ реализована
/// (нужен circom/halo2, см. `ZkProofStub`). Без неё атакующий может подать
/// произвольные `(nullifier, a1)`, не связанные с реальной личностью, и
/// slashing восстановит бессмысленный «секрет». Поэтому этот слой — НЕ полный
/// admission-гейт RLN, а слой наказания ПОВЕРХ zk-проверки. В конвейере
/// (§7.5) ветка RLN остаётся `RlnNotImplemented`, пока нет zk.
///
/// Актуальность эпохи (`external_nullifier == H(epoch ‖ scope)`) — НЕ внутри
/// zk-границы: zk привязывает nullifier к external_nullifier, но не
/// подтверждает, что эпоха текущая. Это relay-side freshness-проверка, она
/// здесь реализована.
pub struct RlnQuotaTracker {
    current_epoch: u32,
    scope: Vec<u8>,
    /// nullifier(bytes) → первая доля текущей эпохи.
    current: std::collections::HashMap<[u8; 32], Share>,
    /// То же для предыдущей эпохи (grace) — иначе straddle через границу эпохи
    /// обходит slashing.
    previous: std::collections::HashMap<[u8; 32], Share>,
    /// Потолок на карту (bounded memory).
    capacity: usize,
}

impl RlnQuotaTracker {
    pub fn new(epoch_id: u32, scope: &[u8], capacity: usize) -> Self {
        RlnQuotaTracker {
            current_epoch: epoch_id,
            scope: scope.to_vec(),
            current: std::collections::HashMap::new(),
            previous: std::collections::HashMap::new(),
            capacity,
        }
    }

    /// Продвижение эпохи. На +1 текущая карта становится previous (grace
    /// удерживает её nullifier'ы); при большем скачке grace-окна нет — обе
    /// карты очищаются. Назад время не идёт (no-op).
    pub fn roll_epoch(&mut self, new_epoch: u32) {
        if new_epoch <= self.current_epoch {
            return;
        }
        if new_epoch == self.current_epoch + 1 {
            std::mem::swap(&mut self.previous, &mut self.current);
            self.current.clear();
        } else {
            self.previous.clear();
            self.current.clear();
        }
        self.current_epoch = new_epoch;
    }

    /// Наблюдать долю (предполагается уже zk-верифицированной — см. границу).
    /// Сначала проверяется актуальность эпохи по `external_nullifier`, затем
    /// детекция повтора/нарушения в карте соответствующей эпохи.
    pub fn observe(&mut self, share: &Share) -> RlnOutcome {
        // Актуальность эпохи: external_nullifier должен совпасть с ожидаемым
        // для текущей или (grace) предыдущей эпохи.
        let ext_cur = external_nullifier(self.current_epoch, &self.scope);
        let is_current = share.external_nullifier == ext_cur;
        let is_previous = self.current_epoch > 0
            && share.external_nullifier
                == external_nullifier(self.current_epoch - 1, &self.scope);
        if !is_current && !is_previous {
            return RlnOutcome::WrongEpoch;
        }

        let capacity = self.capacity;
        let map = if is_current {
            &mut self.current
        } else {
            &mut self.previous
        };
        let key = share.nullifier.to_bytes();
        if let Some(first) = map.get(&key) {
            match slash(first, share) {
                SlashResult::Recovered(secret) => {
                    RlnOutcome::QuotaViolation { recovered_secret: secret }
                }
                SlashResult::SameMessage => RlnOutcome::Duplicate,
                SlashResult::DifferentNullifier => {
                    // Ключ карты — сам nullifier, значит nullifier'ы равны;
                    // slash не может вернуть «разные». Если инвариант сломан —
                    // это баг, а не тихий Duplicate.
                    debug_assert!(false, "равный nullifier дал DifferentNullifier");
                    RlnOutcome::Duplicate
                }
            }
        } else {
            if map.len() >= capacity {
                return RlnOutcome::Backpressure;
            }
            map.insert(key, *share);
            RlnOutcome::Accepted
        }
    }
}
