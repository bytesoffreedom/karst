//! §7.3 — Anonymous Admission Token (Privacy Pass-подобный).
//!
//! Предъявление токена — БЕЗ явного `issuer_id`, через **threshold ring
//! signature** (Bresson–Stern–Szydlo, CRYPTO 2002) по набору доверенных
//! issuer'ов: «подписано совместно не менее чем t из N», не раскрывая,
//! какими именно. Это скрывает, каким issuer'ом выдан токен, — иначе
//! анонимность-сет сужается до пользователей конкретного issuer'а (§7.3).
//!
//! # Почему здесь trait + mock, а не реализация
//!
//! Threshold ring signatures Bresson–Stern–Szydlo НЕ имеют готового,
//! проверенного crate на crates.io (в отличие от Ed25519, HMAC, RLN-поля,
//! которые реализованы «по-настоящему» в соседних модулях). Реализовывать
//! пороговую кольцевую подпись с нуля в референс-скелете — значит поставить
//! непроаудированную крипту в основание; это ХУЖЕ, чем честная заглушка.
//!
//! Поэтому здесь определён `AdmissionTokenVerifier` — trait, против которого
//! компонуется весь конвейер (§7.5, Ступень 4, шаг 2), и `MockRingVerifier`
//! — заведомо НЕ криптографическая заглушка для интеграционных тестов
//! пайплайна. Это одна из находок, которые prose-аудит структурно пропускал:
//! спека называла примитив по имени, но «назван по имени» ≠ «существует
//! готовая реализация, которая компонуется с остальным».
//!
//! # Итог обследования экосистемы (перед попыткой реализации)
//!
//! Проверка crates.io зафиксировала исход «внешней зависимости», а не
//! «сейчас реализую»:
//!
//! - Пороговой кольцевой подписи Bresson–Stern–Szydlo в Rust НЕ существует.
//! - Все доступные кольцевые крейты — 1-of-N (Monero-семейство: SAG/bLSAG/
//!   CLSAG/MLSAG), не покрывают «2 из 5».
//! - FROST-семейство даёт «t из N», но НЕ анонимно (подписанты известны) и
//!   требует DKG/общего группового ключа — другая модель доверия, чем
//!   ad-hoc кольцо N независимых issuer'ов.
//! - Сам BSS построен на RSA/trapdoor-перестановках (RST), а стек KARST —
//!   Curve25519/Ed25519: буквальный BSS не компонуется. Корректная замена —
//!   curve-friendly discrete-log пороговая кольцевая конструкция, которую
//!   ещё нужно выбрать и проверить. См. §7.3 спецификации.
//!
//! Реализовывать пороговую кольцевую крипту с нуля здесь ОПАСНЕЕ, чем
//! оставить честную заглушку (happy-path тесты на самодельной крипте
//! фабрикуют ложную уверенность в security-критичном примитиве). Поэтому
//! stub остаётся рабочим кодом до выбора и аудита конкретной конструкции.

/// Токен в том виде, как он предъявляется relay (§7.3). `ring_sig` —
/// непрозрачные байты пороговой кольцевой подписи над `t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionToken {
    /// Пороговая кольцевая подпись над `t` по набору доверенных issuer-ключей.
    pub ring_sig: Vec<u8>,
    /// Разслеплённый nonce токена (bytes[32]).
    pub t: [u8; 32],
    pub epoch_id: u32,
}

/// Публичные ключи доверенных issuer'ов и требуемый порог t из N.
#[derive(Debug, Clone)]
pub struct IssuerRing {
    pub issuer_pubkeys: Vec<[u8; 32]>,
    /// Порог: сколько issuer'ов ДОЛЖНЫ совместно подписать (1..=N). Покрывает
    /// и «1 из 5», и «2 из 5» одним примитивом (§7.3).
    pub threshold_t: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Порог вне [1, N].
    BadThreshold,
    /// Подпись не прошла проверку по кольцу.
    BadRingSignature,
    /// Токен уже виден в этой эпохе (double-spend) — детектируется вызывающим
    /// через replay-фильтр (§7.5, Ступень 3), не самим verifier'ом.
    Replayed,
}

/// Контракт, против которого компонуется конвейер (§7.5, Ступень 4 шаг 2).
/// Реальный verifier (порт BSS) и mock реализуют один и тот же trait —
/// пайплайн от подмены не меняется.
pub trait AdmissionTokenVerifier {
    /// Проверить, что `token.ring_sig` — валидная пороговая кольцевая подпись
    /// над `token.t` по `ring`, для эпохи `expected_epoch`.
    fn verify(
        &self,
        token: &AdmissionToken,
        ring: &IssuerRing,
        expected_epoch: u32,
    ) -> Result<(), TokenError>;
}

/// НЕ КРИПТОГРАФИЧЕСКАЯ заглушка для интеграционных тестов пайплайна.
///
/// Проверяет только структурную осмысленность (порог в диапазоне, эпоха
/// совпала, подпись непустая и её длина закодирована ожидаемо). НИКОГДА не
/// должна использоваться в бою — единственная её задача — дать конвейеру
/// объект нужного типа, пока настоящий BSS-verifier не портирован.
pub struct MockRingVerifier;

/// Формат mock-«подписи»: первый байт — заявленное число подписантов,
/// далее это число 32-байтовых «пустых» слотов. Ровно достаточно, чтобы
/// пайплайн-тест мог сконструировать «валидный по структуре» токен и
/// «невалидный» (недобор порога), не претендуя на крипто-стойкость.
pub const MOCK_SIG_SLOT: usize = 32;

impl AdmissionTokenVerifier for MockRingVerifier {
    fn verify(
        &self,
        token: &AdmissionToken,
        ring: &IssuerRing,
        expected_epoch: u32,
    ) -> Result<(), TokenError> {
        let n = ring.issuer_pubkeys.len();
        if ring.threshold_t == 0 || ring.threshold_t > n {
            return Err(TokenError::BadThreshold);
        }
        if token.epoch_id != expected_epoch {
            return Err(TokenError::BadRingSignature);
        }
        // «Число подписантов» из первого байта mock-подписи.
        let claimed_signers = *token.ring_sig.first().ok_or(TokenError::BadRingSignature)? as usize;
        let expected_len = 1 + claimed_signers * MOCK_SIG_SLOT;
        if token.ring_sig.len() != expected_len {
            return Err(TokenError::BadRingSignature);
        }
        // Порог: подписантов должно быть не меньше t и не больше N.
        if claimed_signers < ring.threshold_t || claimed_signers > n {
            return Err(TokenError::BadRingSignature);
        }
        Ok(())
    }
}

impl MockRingVerifier {
    /// Собрать mock-токен, «подписанный» `signers` issuer'ами, для тестов.
    pub fn mock_token(t: [u8; 32], epoch_id: u32, signers: usize) -> AdmissionToken {
        let mut ring_sig = Vec::with_capacity(1 + signers * MOCK_SIG_SLOT);
        ring_sig.push(signers as u8);
        ring_sig.resize(1 + signers * MOCK_SIG_SLOT, 0u8);
        AdmissionToken {
            ring_sig,
            t,
            epoch_id,
        }
    }
}

/// Настоящий verifier поверх пороговой кольцевой подписи §7.3 (tring).
/// РЕФЕРЕНС, НЕ ПРОШЁЛ АУДИТ — только за feature-флагом `unaudited-crypto`.
///
/// Композиция, ради которой существует trait: конвейер (§7.5, Ступень 4 шаг 2)
/// теперь может исполняться против настоящей крипты, а не только mock.
///
/// **Граница.** Кольцевая подпись доказывает «≥ t issuer'ов подписали nonce
/// токена `t`». `epoch_id` НЕ входит в саму подпись (issuer в модели Privacy
/// Pass подписывает токен однократно вслепую, не зная будущую эпоху) —
/// свежесть по эпохе обеспечивает отдельный replay-фильтр конвейера,
/// привязанный к quota-эпохе (§7.5, Ступень 3). Здесь проверяется только,
/// что заявленная эпоха токена совпала с ожидаемой.
#[cfg(feature = "unaudited-crypto")]
pub struct RealRingVerifier;

#[cfg(feature = "unaudited-crypto")]
impl AdmissionTokenVerifier for RealRingVerifier {
    fn verify(
        &self,
        token: &AdmissionToken,
        ring: &IssuerRing,
        expected_epoch: u32,
    ) -> Result<(), TokenError> {
        let n = ring.issuer_pubkeys.len();
        if ring.threshold_t == 0 || ring.threshold_t > n {
            return Err(TokenError::BadThreshold);
        }
        if token.epoch_id != expected_epoch {
            return Err(TokenError::BadRingSignature);
        }
        // Декодировать issuer-ключи кольца в точки Ristretto.
        let mut ring_points = Vec::with_capacity(n);
        for pk in &ring.issuer_pubkeys {
            let p = crate::tring::point_from_bytes(pk).ok_or(TokenError::BadRingSignature)?;
            ring_points.push(p);
        }
        // Разобрать подпись и проверить против nonce токена как сообщения.
        let sig = crate::tring::ThresholdRingSig::from_bytes(&token.ring_sig)
            .ok_or(TokenError::BadRingSignature)?;
        if sig.challenges.len() != n {
            return Err(TokenError::BadRingSignature);
        }
        if crate::tring::verify(&token.t, &ring_points, ring.threshold_t, &sig) {
            Ok(())
        } else {
            Err(TokenError::BadRingSignature)
        }
    }
}
