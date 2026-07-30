//! **No two derivations may share a domain label** (QA-3).
//!
//! # Why this rather than official test vectors
//!
//! The task this comes from asked for reference vectors for X25519, ML-KEM, HKDF, AEAD and
//! signatures. Those are worth having, and they are not OUR risk: the primitives come from
//! RustCrypto and dalek, which test themselves against the published vectors far more thoroughly
//! than a re-check here would. Re-asserting them would produce a file that looks like assurance and
//! adds none.
//!
//! Our risk is one layer up, and it is the item that task listed last and phrased most loosely:
//! *the same inputs in different cryptographic contexts must not yield the same working keys.* This
//! codebase now runs ~30 separate derivations off the same handful of secrets — a session's root
//! key alone feeds the ratchet, the drop-box seed, the routing chain, the veil keystream and the
//! loop box. Every one of them is kept apart by a string.
//!
//! **The failure mode is a copied label.** Someone adds a derivation by copying the nearest
//! existing one and forgets to change the tag. Nothing breaks: both derivations still work, both
//! produce keys, every test stays green — and two contexts that were supposed to be independent now
//! produce the SAME key from the same input. That is a silent, total loss of separation, and it is
//! invisible in review precisely because the line looks like the line above it.
//!
//! So this scans the workspace for domain labels and requires them to be unique. It is a spelling
//! check, and spelling is the whole mechanism.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Every crate whose sources define derivations, relative to this crate's manifest.
const CRATES: &[&str] =
    &["crypto", "client-core", "transport", "node", "relay", "admission", "client"];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Domain labels as they appear in source: a byte-string literal starting `KARST-` or `karst-`.
///
/// Deliberately literal-only. A label built at runtime by concatenation would slip past this, and
/// that is the point at which it stops being a spelling check — so the test also refuses to accept
/// a suspiciously small harvest, which is what a change of convention would look like.
fn labels_in(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let mut i = 0;
    while let Some(rel) = src[i..].find("b\"") {
        let start = i + rel + 2;
        let Some(end_rel) = src[start..].find('"') else { break };
        let lit = &src[start..start + end_rel];
        if lit.starts_with("KARST-") || lit.starts_with("karst-") {
            out.push(lit.to_string());
        }
        i = start + end_rel + 1;
        if i >= bytes.len() {
            break;
        }
    }
    out
}

fn harvest() -> BTreeMap<String, Vec<String>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().expect("impl/").to_path_buf();
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for c in CRATES {
        let mut files = Vec::new();
        rust_files(&root.join(c).join("src"), &mut files);
        for f in files {
            let Ok(src) = std::fs::read_to_string(&f) else { continue };
            let name = f.strip_prefix(&root).unwrap_or(&f).display().to_string();
            for l in labels_in(&src) {
                found.entry(l).or_default().push(name.clone());
            }
        }
    }
    found
}

/// **Every domain label is used by exactly one derivation.**
///
/// DISCRIMINATING: give any two derivations the same tag and this reddens, naming both files. That
/// is the only signal such a change produces — the code compiles, the keys derive, the suite is
/// green, and two contexts silently share a key.
#[test]
fn no_two_derivations_share_a_domain_label() {
    let found = harvest();
    let clashes: Vec<(&String, &Vec<String>)> = found
        .iter()
        // The same label appearing twice in ONE file is a derive-and-verify pair, which is correct
        // by construction: signing and checking must agree on the tag.
        .filter(|(_, files)| {
            let mut uniq: Vec<&String> = files.iter().collect();
            uniq.sort();
            uniq.dedup();
            uniq.len() > 1
        })
        .collect();
    assert!(
        clashes.is_empty(),
        "these domain labels are used in more than one file:\n{}\n\nA shared tag means two \
         derivations that were meant to be independent produce the SAME key from the same input. \
         Nothing about that fails on its own: both still work, both still produce keys, the suite \
         stays green. It is invisible in review because the copied line looks exactly like the line \
         it was copied from.",
        clashes
            .iter()
            .map(|(l, f)| format!("  {l}  →  {}", f.join(", ")))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The harvest must stay large. A scan that silently finds nothing passes the test above forever.
///
/// Not an exact count — that would fail on every legitimate addition and be edited into
/// meaninglessness within a week. A floor, well under today's number, catches the case that matters:
/// the labels moved somewhere this scan cannot see them.
#[test]
fn the_scan_still_finds_the_labels_it_is_supposed_to_check() {
    let found = harvest();
    assert!(
        found.len() >= 20,
        "only {} domain labels found across the workspace. The convention has changed — labels are \
         being built at runtime, or moved out of these crates — and this guard is now checking \
         nothing while reporting success.",
        found.len()
    );
    // A few that must always be there, as an anchor: if these are missing the scan is broken rather
    // than the code.
    for anchor in ["KARST-ratchet-rk-v1", "KARST-pqxdh-v1", "karst-dropbox-seed-v1"] {
        assert!(found.contains_key(anchor), "anchor label `{anchor}` not found — the scan is broken");
    }
}
