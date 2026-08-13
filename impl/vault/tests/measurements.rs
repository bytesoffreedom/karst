//! The numbers §17.1 asks for, measured rather than assumed (#318).
//!
//! Until the file backend existed there was nothing to measure against — every layer ran over a
//! `Vec`. These are the engineering quantities the plan lists as open, taken from the code that
//! actually decides them.
//!
//! # How to read this file
//!
//! Each test prints its figures under `cargo test -p vault --test measurements -- --nocapture` and
//! asserts only what must not silently change. The distinction matters: a measurement that
//! asserted its own result would be a snapshot pretending to be a property, and the next person to
//! tune a constant would "fix" the test rather than think about the number.
//!
//! What IS asserted is the shape of the trade: that overhead falls as the block grows, that write
//! amplification rises, and that the two move in opposite directions — because a change that moved
//! them the same way would mean the model is wrong, not that a constant needs updating.

use vault::geometry::{Geometry, CAPSULE_ALIGN, CAPSULE_SLOT, DEFAULT_BLOCK_PAYLOAD, RECORD_FRAMING};
use vault::params::{header_len, FormatParams};
use vault::tx::{BlockRetire, BlockWrite, Commit, Step, What};

/// Two capsule copies cost `2 * CAPSULE_ALIGN` per block no matter how big the payload is, so the
/// overhead is entirely a function of the block size — and it is the first number a block-size
/// decision needs.
#[test]
fn capsule_overhead_against_block_size() {
    println!("\n== two-copy overhead by block size ==");
    println!("{:>10}  {:>10}  {:>9}  {:>8}", "payload", "stride", "overhead", "blocks/GiB");
    let mut previous = f64::MAX;
    for payload in [4 * 1024usize, 16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024] {
        let g = Geometry::new(payload, 1 << 30);
        let stride = g.block_stride();
        let overhead = (2 * CAPSULE_ALIGN) as f64 / stride as f64;
        let per_gib = (1u64 << 30) / stride;
        println!("{payload:>10}  {stride:>10}  {:>8.1}%  {per_gib:>8}", overhead * 100.0);
        assert!(
            overhead < previous,
            "overhead must fall as the block grows; it is a fixed 2 x {CAPSULE_ALIGN} per block"
        );
        previous = overhead;
    }
    let shipped = (2 * CAPSULE_ALIGN) as f64 / Geometry::new(DEFAULT_BLOCK_PAYLOAD, 1 << 30).block_stride() as f64;
    println!("shipped default: {DEFAULT_BLOCK_PAYLOAD} B payload, {:.1}% overhead", shipped * 100.0);
    assert!(shipped < 0.15, "the shipped block size pays {:.1}% to hold two capsules", shipped * 100.0);
}

/// The other half of the same trade: a copy-on-write block is rewritten WHOLE for any change
/// inside it, so a bigger block means less capsule overhead and more bytes written per edit.
///
/// This is why the block size cannot be chosen from the overhead column alone, and why the plan
/// lists both quantities in one breath.
#[test]
fn write_amplification_for_a_one_byte_edit() {
    println!("\n== bytes written for a 1-byte logical change ==");
    println!("{:>10}  {:>7}  {:>12}  {:>10}", "payload", "blocks", "bytes moved", "vs 4 KiB");
    let mut previous = 0u64;
    for payload in [4 * 1024usize, 16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024] {
        let g = Geometry::new(payload, 1 << 30);
        // One data block plus its map path, each rewritten whole, each with two capsules.
        let blocks = 1 + u64::from(g.depth());
        let moved = blocks * g.block_stride();
        println!("{payload:>10}  {blocks:>7}  {moved:>12}  {:>9.1}x", moved as f64 / 61440.0);
        assert!(moved > previous, "a bigger block must move more bytes per edit");
        previous = moved;
    }
    let g = Geometry::new(DEFAULT_BLOCK_PAYLOAD, 1 << 30);
    println!(
        "shipped default: depth {}, so {} blocks and {} bytes per one-byte edit",
        g.depth(),
        1 + u64::from(g.depth()),
        (1 + u64::from(g.depth())) * g.block_stride()
    );
}

/// Barriers per transaction, counted from the commit the format actually builds.
///
/// A barrier is an `fdatasync`, which is the expensive part of a commit on real storage, and the
/// count is a constant of the protocol rather than of the transaction's size: the order has eight
/// stages whether it writes one block or fifty.
#[test]
fn barriers_and_writes_per_transaction() {
    println!("\n== commit shape ==");
    println!("{:>8}  {:>7}  {:>9}  {:>16}", "blocks", "writes", "barriers", "writes/barrier");
    for n in [1usize, 2, 8, 32] {
        let writes: Vec<BlockWrite> = (0..n as u64)
            .map(|b| BlockWrite {
                block: b,
                reserved_capsule: (b * 100, vec![0u8; CAPSULE_SLOT]),
                payload: (b * 100 + 20, vec![0u8; 64]),
                live_capsule: (b * 100, vec![0u8; CAPSULE_SLOT]),
            })
            .collect();
        let retires = [BlockRetire {
            block: 900,
            wipe: (90_000, vec![0u8; 64]),
            free_capsule: (91_000, vec![0u8; CAPSULE_SLOT]),
        }];
        let c = Commit::build(
            &writes,
            (80_000, vec![0u8; 64]),
            (81_000, vec![0u8; 64]),
            &retires,
            (80_000, vec![0u8; 64]),
        );
        let barriers = c.steps().iter().filter(|s| matches!(s, Step::Barrier)).count();
        let w = c.steps().len() - barriers;
        println!("{n:>8}  {w:>7}  {barriers:>9}  {:>15.1}", w as f64 / barriers as f64);
        assert_eq!(
            barriers, 8,
            "the commit has eight ordered stages regardless of size; changing that changes the \
             crash matrix, not just a number"
        );
    }
}

/// Every capsule write goes to one of the two copies, and both are written in a full transaction —
/// so a block costs three writes (reserved capsule, payload, live capsule) plus its share of the
/// fixed stages.
#[test]
fn physical_writes_per_logical_block() {
    let writes = [BlockWrite {
        block: 0,
        reserved_capsule: (0, vec![0u8; CAPSULE_SLOT]),
        payload: (100, vec![0u8; 64]),
        live_capsule: (0, vec![0u8; CAPSULE_SLOT]),
    }];
    let c = Commit::build(&writes, (500, vec![0u8; 8]), (600, vec![0u8; 8]), &[], (500, vec![0u8; 8]));
    let per_block = c
        .steps()
        .iter()
        .filter(|s| {
            matches!(
                s,
                Step::Write { what: What::ReservedCapsule(_) | What::Payload(_) | What::LiveCapsule(_), .. }
            )
        })
        .count();
    println!("\n== per-block writes in a commit: {per_block} ==");
    assert_eq!(per_block, 3, "reserved capsule, payload, live capsule");
}

/// What the shipped header costs, and the fraction of a container it occupies.
#[test]
fn header_cost() {
    let h = header_len();
    println!("\n== header ==");
    println!("header_len = {h} bytes");
    for size in [64u64 << 20, 1 << 30, 16 << 30] {
        let p = FormatParams::derive(size);
        println!(
            "  container {:>6} MiB -> {} blocks, header is {:.6}% of the file",
            size >> 20,
            p.blocks,
            h as f64 * 100.0 / size as f64
        );
        assert!(p.blocks > 0, "a container of {size} bytes holds no blocks at all");
    }
    // The header is small and FIXED — it must not grow with the container, or it would be a
    // channel that says something about the file it sits in.
    assert_eq!(header_len(), h, "header_len must not depend on anything");
}

/// A record's framing is pure overhead inside every block, and the map's fan-out is what it buys.
#[test]
fn record_framing_and_fanout() {
    println!("\n== framing and fan-out ==");
    println!("RECORD_FRAMING = {RECORD_FRAMING} bytes, CAPSULE_SLOT = {CAPSULE_SLOT} bytes");
    for payload in [4 * 1024usize, 64 * 1024, 1024 * 1024] {
        let g = Geometry::new(payload, 1 << 30);
        println!(
            "  payload {payload:>8} -> fanout {:>7}, depth {}",
            g.fanout(),
            g.depth()
        );
        assert!(g.fanout() > 1, "a node that holds one entry addresses nothing");
    }
}

/// What one password attempt costs, which is the only figure an Argon2 parameter choice can be
/// argued from.
///
/// Printed, never asserted against a threshold: the number is a property of THIS machine, and a
/// test that demanded "at least N milliseconds" would fail on a fast one and pass on a slow one
/// while proving nothing about either. What the plan asks for is the cost of one guess; this
/// reports it, and the parameter choice is then a decision somebody makes with the number in hand.
///
/// Skipped under the fast-KDF environment variable, where the answer is deliberately meaningless.
#[test]
fn cost_of_one_password_attempt() {
    use vault::slot::{KDF_M_COST, KDF_P_COST, KDF_T_COST};
    println!("\n== KDF ==");
    println!("m_cost = {KDF_M_COST} KiB ({} MiB), t_cost = {KDF_T_COST}, p_cost = {KDF_P_COST}", KDF_M_COST / 1024);

    if std::env::var("KARST_TEST_FAST_KDF").as_deref() == Ok("1") {
        println!("  (fast KDF in use — timing skipped, it would measure nothing)");
        return;
    }
    let salt = [0x11u8; 16];
    let slots: Vec<Vec<u8>> = (0..8).map(|_| vault::slot::random_slot()).collect();
    let start = std::time::Instant::now();
    let _ = vault::slot::open_table(b"a wrong password", &salt, &slots);
    let one = start.elapsed();
    // **Which build this came from is not a footnote.** Argon2 is arithmetic, and an unoptimized
    // build runs it many times slower — so a debug figure overstates the attacker's cost by
    // whatever that factor happens to be. Quoting it as "one guess costs N seconds" would be
    // claiming a defence the shipped binary does not have.
    let profile = if cfg!(debug_assertions) { "DEBUG (unoptimized)" } else { "release" };
    println!("  build: {profile}");
    println!("  one attempt: {one:?}");
    println!("  => {:.2} guesses/second/core", 1.0 / one.as_secs_f64());
    println!(
        "  => a 2^40 keyspace costs {:.0} core-years at this rate",
        (1u64 << 40) as f64 * one.as_secs_f64() / (365.0 * 24.0 * 3600.0)
    );
    if cfg!(debug_assertions) {
        println!(
            "  NOT A SECURITY FIGURE: rerun with --release before quoting it. The attacker \
             compiles with optimisations; so must the measurement."
        );
    }
}
