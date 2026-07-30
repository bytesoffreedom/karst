//! **Every ratchet plaintext is the same length**, so the relay learns nothing from size (PRIV-1).
//!
//! The transport already shapes what an ON-PATH observer sees: Noise frames ride fixed buckets and
//! a fetch page is a fixed 16 000 bytes. The relay is not on that path — it TERMINATES Noise, so it
//! reads the envelope after decryption and sees `msg.ciphertext.len()`, which until now was the
//! plaintext's length plus a tag. A one-word reply and a 1 KB paragraph were different sizes to the
//! one party we explicitly do not want to trust.
//!
//! That also quietly devalued cover traffic. `Peer::send_loop` used a fixed 96-byte ciphertext to
//! sit "in the same size class as the traffic it is hiding" — but real traffic had no class, it had
//! a distribution, and a relay comparing distributions separates the populations. Loops that a
//! relay can identify are worse than no loops: it can subtract them from a user's volume, and it
//! can drop the real mail while faithfully returning the loops, so the drop detector reports
//! all-clear while messages vanish.
//!
//! # Two classes, and why not one
//!
//! Padding the plaintext to one fixed block gives the wire exactly two shapes, because
//! `SkeletonSeal`'s ciphertext is a deterministic size:
//!
//! - `Ratchet` — a fixed length. Text, reaction, ACK, file chunk and cover loop are identical.
//! - `InitialSealed` — a larger fixed length (it carries the sealed key agreement).
//!
//! Collapsing those two into ONE class was considered and refused. It would cost every ordinary
//! message the ~1.2 KB of an opener it does not carry, and it would buy nothing: `SessionEnvelope`
//! is a `node::protocol` enum that the relay deserializes (`Payload::approx_len` matches on the
//! variant), so "this is a first contact" is visible STRUCTURALLY. Paying for every message to hide
//! something the enum tag announces anyway is not a privacy improvement, it is a bandwidth bill.
//!
//! # The size is derived, never chosen
//!
//! [`PADDED_LEN`] is computed from the stage-0 admission ceiling. That direction matters: an
//! oversize packet is not an error, it is `Outcome::DropNoReply(Oversize)` — the message vanishes
//! with no reply and no log. Rounding UP to a pretty 1024 or 2048 and hoping is exactly how you
//! ship a client whose first message to a new contact silently never arrives, and
//! `admission::params::MAX_PACKET_SIZE` carries the scar from the last time this bit
//! (1400 → 2560, because an ML-KEM opener did not fit its own mandated ceiling).
//!
//! The opener is the binding case, so the budget is taken from it and ordinary messages inherit the
//! same block.

use admission::params::MAX_PACKET_SIZE;

/// What `RelayNode::admit_send` adds to `Payload::approx_len()` before the stage-0 gate.
const ADMIT_FRAMING: usize = 128;
/// What `Payload::approx_len` charges an `InitialSealed` on top of its two ciphertexts.
const OPENER_FRAMING: usize = 64;
/// ChaCha20-Poly1305 tag, added to the plaintext by `Session::encrypt`.
const AEAD_TAG: usize = 16;

/// Size of the sealed key agreement an opener carries.
///
/// PINNED by [`tests::the_sealed_key_agreement_is_still_the_size_this_budget_assumes`], which builds
/// a real one. If `KeyAgreement` grows a field, that test fails with the new number — which is the
/// only way this constant should ever change, because guessing it wrong moves openers over the
/// stage-0 ceiling where they disappear without a word.
pub const SEALED_KA_CIPHERTEXT: usize = 1235;

/// **Every ratchet plaintext is padded to exactly this.** Derived from the ceiling, not picked.
pub const PADDED_LEN: usize =
    MAX_PACKET_SIZE - ADMIT_FRAMING - OPENER_FRAMING - AEAD_TAG - SEALED_KA_CIPHERTEXT;

/// Bytes a caller may actually hand to [`pad`]: the length prefix lives inside the fixed block.
pub const MAX_PAYLOAD: usize = PADDED_LEN - 4;

/// Wrap `plaintext` in the fixed-size block: `len` (4 bytes, little-endian) ‖ plaintext ‖ zeros.
///
/// A length prefix rather than a delimiter byte, because the payload is arbitrary bytes: any
/// sentinel would need escaping, and an escape rule is one more thing to get subtly wrong in a
/// place where "subtly wrong" means a truncated message that still authenticates.
pub fn pad(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if plaintext.len() > MAX_PAYLOAD {
        // LOUD, and deliberately at the send side. The alternative is the relay dropping it for
        // being oversize, which reaches the user as "sent" followed by silence.
        return Err(format!(
            "message is {} bytes; one E2E envelope carries at most {MAX_PAYLOAD} \
             (send it as a file — see content::MAX_TEXT_BYTES)",
            plaintext.len()
        ));
    }
    let mut block = vec![0u8; PADDED_LEN];
    block[..4].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
    block[4..4 + plaintext.len()].copy_from_slice(plaintext);
    Ok(block)
}

/// Recover the payload from a fixed-size block. **Strict**: anything off-shape is refused.
///
/// Strictness is free here and it is not an oracle: this runs only AFTER the AEAD has verified the
/// message, so a malformed block means an authenticated peer sent something our own encoder cannot
/// produce — a bug or a version mismatch, both of which should be loud rather than silently
/// reinterpreted. Per the pre-alpha rule there is no lenient path to fall back to.
pub fn unpad(block: &[u8]) -> Result<Vec<u8>, String> {
    if block.len() != PADDED_LEN {
        return Err(format!("padded block is {} bytes, expected {PADDED_LEN}", block.len()));
    }
    let len = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(format!("padded block claims {len} bytes of payload, cap is {MAX_PAYLOAD}"));
    }
    // The tail must be zeros. Not required for correctness — the length prefix already says where
    // the payload ends — but it turns a padding bug into a test failure instead of a silent
    // divergence between two clients that both "work".
    if block[4 + len..].iter().any(|&b| b != 0) {
        return Err("padded block has non-zero bytes past the payload".into());
    }
    Ok(block[4..4 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The budget's one empirical input. If this fails, `SEALED_KA_CIPHERTEXT` is stale and
    /// [`PADDED_LEN`] is wrong in the direction that makes openers disappear.
    #[test]
    fn the_sealed_key_agreement_is_still_the_size_this_budget_assumes() {
        let ka = karst_crypto::pqxdh::KeyAgreement {
            ik_a_pub: [1u8; 32],
            ek_a_pub: [2u8; 32],
            // ML-KEM-768 ciphertext.
            kem_ct: vec![3u8; 1088],
            // `Some` is the LARGER arm, and the budget must hold for the larger arm.
            opk_pub: Some([4u8; 32]),
            mailbox_a_pub: [5u8; 32],
        };
        let plain = postcard::to_stdvec(&ka).expect("KeyAgreement serializes");
        let sealed = karst_crypto::seal::SkeletonSeal::seal(
            &x25519_dalek::PublicKey::from([9u8; 32]),
            &plain,
        );
        assert_eq!(
            sealed.ciphertext.len(),
            SEALED_KA_CIPHERTEXT,
            "the sealed key agreement changed size. Recompute SEALED_KA_CIPHERTEXT from THIS \
             number — do not adjust PADDED_LEN by hand, and do not round it up: an opener over \
             the stage-0 ceiling is dropped with no reply (admission::params::MAX_PACKET_SIZE)."
        );
    }

    /// **A padded OPENER still clears the stage-0 size gate** — the whole reason the block is this
    /// size and not a rounder one.
    ///
    /// Mirrors `RelayNode::admit_send`: `raw_len = payload.approx_len() + 128` against
    /// `MAX_PACKET_SIZE`. Discriminating: raise `PADDED_LEN` by one and this goes red.
    #[test]
    fn a_padded_opener_fits_under_the_admission_ceiling_with_nothing_to_spare() {
        let ratchet_ciphertext = PADDED_LEN + AEAD_TAG;
        let approx_len = SEALED_KA_CIPHERTEXT + ratchet_ciphertext + OPENER_FRAMING;
        let raw_len = approx_len + ADMIT_FRAMING;
        assert_eq!(
            raw_len, MAX_PACKET_SIZE,
            "the block no longer uses the ceiling exactly: {raw_len} vs {MAX_PACKET_SIZE}. \
             Under is wasted privacy budget, over is a message that vanishes."
        );
    }

    #[test]
    fn every_padded_message_is_the_same_length_whatever_it_carries() {
        let sizes: Vec<usize> = [0usize, 1, 5, 300, MAX_PAYLOAD]
            .iter()
            .map(|&n| pad(&vec![b'x'; n]).expect("fits").len())
            .collect();
        assert!(
            sizes.iter().all(|&s| s == PADDED_LEN),
            "padding produced varying lengths {sizes:?} — the leak this module exists to close"
        );
    }

    #[test]
    fn a_padded_block_round_trips_at_every_boundary() {
        for n in [0usize, 1, 4, 5, 1000, MAX_PAYLOAD] {
            let payload = vec![(n % 251) as u8; n];
            let back = unpad(&pad(&payload).expect("fits")).expect("round trip");
            assert_eq!(back, payload, "payload of {n} bytes did not survive the round trip");
        }
    }

    #[test]
    fn an_oversize_payload_is_refused_at_the_sender_not_dropped_by_the_relay() {
        let err = pad(&vec![0u8; MAX_PAYLOAD + 1]).expect_err("must refuse");
        assert!(
            err.contains("at most"),
            "the refusal has to say what the limit is, or the caller cannot act on it: {err}"
        );
    }

    #[test]
    fn a_block_of_the_wrong_shape_is_refused() {
        assert!(unpad(&[0u8; 10]).is_err(), "a short block must not be accepted");
        let mut too_long = pad(b"hi").expect("fits");
        too_long.push(0);
        assert!(unpad(&too_long).is_err(), "a long block must not be accepted");

        // A length field larger than the block can hold: the arithmetic below it would panic on a
        // slice out of range, so this must be refused BEFORE the slice.
        let mut lying = pad(b"hi").expect("fits");
        lying[..4].copy_from_slice(&(u32::MAX).to_le_bytes());
        assert!(unpad(&lying).is_err(), "a lying length field must not be accepted");

        let mut dirty = pad(b"hi").expect("fits");
        *dirty.last_mut().expect("non-empty") = 1;
        assert!(unpad(&dirty).is_err(), "a non-zero tail must not be accepted");
    }
}
