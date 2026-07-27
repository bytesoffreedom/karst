//! Avatar image pipeline — the ONLY place the `image` crate is used. `client` stays
//! image-agnostic (opaque bytes); everything that decodes untrusted image data lives
//! here, behind bounded decoders.
//!
//! # Threat model
//! A peer-supplied avatar is attacker-controlled: a tiny, highly-compressible PNG can
//! declare gigapixel dimensions (a decompression bomb) and blow up memory on decode
//! (spec §5 — never spend more than the sender did). Defense: EVERY decode goes
//! through `ImageReader::limits(...)` with explicit width/height/alloc caps set BEFORE
//! `decode()`. `image::load_from_memory` (no limits) is NEVER used. The receiver
//! re-decodes and re-encodes received bytes (`sanitize`) rather than trusting the
//! sender's encoding — which also strips any EXIF/ancillary metadata for free (PNG
//! re-encode drops it).
//!
//! # Format
//! PNG only (the sole codec compiled in — see `Cargo.toml`). JPEG needs `zune-jpeg`,
//! deferred to a later slice. Non-PNG input gets a clear, user-facing error.

use std::io::Cursor;

use client::content::MAX_AVATAR_BYTES;
use image::{ImageFormat, ImageReader, Limits};

/// Output avatar dimension cap (square box; aspect preserved). Avatars render small;
/// 128px is plenty and keeps the re-encoded PNG well under `MAX_AVATAR_BYTES`.
pub const MAX_AVATAR_DIM: u32 = 128;

/// Bounded decode of PNG bytes with explicit width/height/alloc limits. Rejects
/// non-PNG and anything exceeding the caps BEFORE pixel allocation. This is the
/// single choke point — no other function in this module decodes.
fn decode_bounded(bytes: &[u8], max_dim: u32, max_alloc: u64) -> Result<image::DynamicImage, String> {
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| format!("unreadable image: {e}"))?;
    match reader.format() {
        Some(ImageFormat::Png) => {}
        Some(_) => return Err("avatar must be a PNG for now".into()),
        None => return Err("unrecognized image format (PNG required)".into()),
    }
    let mut lim = Limits::default();
    lim.max_image_width = Some(max_dim);
    lim.max_image_height = Some(max_dim);
    lim.max_alloc = Some(max_alloc);
    reader.limits(lim);
    reader.decode().map_err(|e| format!("image rejected: {e}"))
}

/// Encode a (already-bounded) image to PNG, enforcing the byte cap on the result.
fn encode_png_capped(img: &image::DynamicImage) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
        .map_err(|e| format!("png encode: {e}"))?;
    if out.len() > MAX_AVATAR_BYTES {
        return Err(format!("encoded avatar too large ({} bytes)", out.len()));
    }
    Ok(out)
}

/// INGEST a locally-picked avatar for sending: bounded-decode a PNG (generous but
/// finite source caps), downscale to fit `MAX_AVATAR_DIM`, re-encode PNG. Returns the
/// opaque bytes handed to `client` for chunking.
pub fn ingest(bytes: &[u8]) -> Result<Vec<u8>, String> {
    // Source caps: a real photo may be a few thousand px; reject the absurd. Alloc
    // backstop sized so the 4096px cap is actually reachable (4096² RGBA ≈ 67 MiB).
    let img = decode_bounded(bytes, 4096, 68 << 20)?;
    let small = img.resize(MAX_AVATAR_DIM, MAX_AVATAR_DIM, image::imageops::FilterType::Triangle);
    encode_png_capped(&small)
}

/// SANITIZE received avatar bytes before storing/rendering: a stricter bounded decode
/// (the payload should already be a small avatar), downscale as a belt-and-braces,
/// re-encode PNG. This is the receiver-side defense — never cache raw peer bytes.
pub fn sanitize(bytes: &[u8]) -> Result<Vec<u8>, String> {
    // A legit received avatar is <=128px; allow a small margin, tight alloc backstop.
    let img = decode_bounded(bytes, 512, 8 << 20)?;
    let small = img.resize(MAX_AVATAR_DIM, MAX_AVATAR_DIM, image::imageops::FilterType::Triangle);
    encode_png_capped(&small)
}

/// Decode stored avatar bytes to `(width, height, rgba)` for an egui texture. Bounded
/// (defense in depth even for our own re-encoded bytes). `None` on any failure —
/// rendering falls back to a placeholder.
pub fn to_rgba(bytes: &[u8]) -> Option<(usize, usize, Vec<u8>)> {
    let img = decode_bounded(bytes, 512, 8 << 20).ok()?;
    let rgba = img.to_rgba8();
    let (w, h) = (rgba.width() as usize, rgba.height() as usize);
    Some((w, h, rgba.into_raw()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a solid-color RGBA image of the given dimensions to PNG bytes.
    fn png_of(w: u32, h: u32) -> Vec<u8> {
        let buf = image::RgbaImage::from_pixel(w, h, image::Rgba([10, 20, 30, 255]));
        let mut out = Vec::new();
        image::DynamicImage::ImageRgba8(buf)
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    #[test]
    fn ingest_downscales_and_bounds_output() {
        // A 900x600 PNG ingests to <=128px on the long side and stays under the cap.
        let src = png_of(900, 600);
        let out = ingest(&src).unwrap();
        assert!(out.len() <= MAX_AVATAR_BYTES, "encoded within cap");
        let (w, h, _) = to_rgba(&out).unwrap();
        assert!(w <= MAX_AVATAR_DIM as usize && h <= MAX_AVATAR_DIM as usize, "downscaled to box");
        assert!(w == MAX_AVATAR_DIM as usize || h == MAX_AVATAR_DIM as usize, "fills the box on one axis");
    }

    #[test]
    fn sanitize_rejects_oversize_dimensions_before_alloc() {
        // Discriminating for the DIMENSION cap specifically: 700x700 decodes to
        // ~1.96 MiB — comfortably UNDER sanitize's 8 MiB alloc backstop, so only the
        // 512px width/height limit can reject it. Neuter that limit (drop
        // max_image_width/height in decode_bounded) and this 700x700 image decodes
        // fine (allocatable, no OOM) and sanitize succeeds -> test goes red. That
        // proves the width/height cap, not the alloc backstop, is doing the work.
        let bomb = png_of(700, 700);
        assert!(bomb.len() <= MAX_AVATAR_BYTES, "solid 700x700 PNG is tiny on disk");
        assert!(sanitize(&bomb).is_err(), "over-dimension avatar rejected by the width/height limit");
    }

    #[test]
    fn non_png_is_rejected_with_clear_error() {
        // Not an image at all -> rejected (and never panics).
        assert!(ingest(b"definitely not a png").is_err());
        assert!(sanitize(b"\x00\x01\x02\x03").is_err());
    }
}
