//! Which physical block a write lands in — and why the answer must be unpredictable.
//!
//! # The leak this exists to close
//!
//! Under the protected password the allocator skips blocks that belong to the hidden space. The
//! skip itself is invisible, but its CONSEQUENCE is not: the public space's own allocation map
//! records that block 500 is free while 501 onward are used, and that map is fully readable under
//! the public password. With a deterministic allocator — sequential, first-fit, best-fit, anything
//! that would be written without thinking about it — that pattern has no explanation in the public
//! space's own history of files and deletions.
//!
//! An adversary holding the public password, the space's metadata and this source code can replay
//! the allocation and subtract predicted-free from actually-free. The remainder is the hidden
//! space. One snapshot is enough, and the hidden space never has to be used.
//!
//! So the requirement is not "random-looking". It is that the sequence be **unreproducible by
//! someone holding the public password**, which means the seed lives only in memory and dies with
//! the session.
//!
//! # Fisher–Yates, not a home-made small-domain permutation
//!
//! The tempting alternative is a keyed permutation over `[0, blocks)` — a small Feistel network
//! with cycle walking. That is a cryptographic primitive with no fixed algorithm, no test vectors
//! and no distinguishing-advantage argument, and round counts for small domains are not something
//! to pick by feel. It is also unnecessary: a container of `2^20` blocks needs a `u32` array of a
//! few megabytes, shuffled once at mount. If memory ever makes that impossible, the replacement is
//! a standard analysed construction, not a guess.

use rand::rngs::OsRng;
use rand::RngCore;

/// The order this session will consider physical blocks in.
///
/// Held only in memory. Nothing about it — not the seed, not the cursor, not how many candidates
/// were rejected — is ever written anywhere the public password can read, because all three would
/// let the sequence be replayed.
pub struct Allocator {
    order: Vec<u32>,
    cursor: usize,
}

impl Allocator {
    /// A fresh order over `[0, blocks)`, shuffled with system randomness.
    ///
    /// Block 0 is excluded: a zero entry in a map node means "no mapping", so block 0 must never
    /// be handed out or that meaning becomes ambiguous.
    pub fn new(blocks: u64) -> Self {
        let n = blocks.min(u64::from(u32::MAX)) as u32;
        let mut order: Vec<u32> = (1..n).collect();
        shuffle(&mut order);
        Self { order, cursor: 0 }
    }

    /// The next candidate, or `None` once every block has been offered.
    ///
    /// Candidates are OFFERED, not granted: the caller checks the ownership layer and comes back
    /// for another if this one is not free. That rejection must leave no trace — see the module
    /// docs — which is why the cursor lives here and not in anything that gets persisted.
    pub fn next_candidate(&mut self) -> Option<u64> {
        let c = self.order.get(self.cursor).copied()?;
        self.cursor += 1;
        Some(u64::from(c))
    }

    /// Candidates not yet offered this session.
    pub fn remaining(&self) -> usize {
        self.order.len().saturating_sub(self.cursor)
    }
}

/// Fisher–Yates with unbiased index selection.
///
/// The bias matters: `rand % range` is skewed toward low indices whenever `range` does not divide
/// the generator's span, and a skewed shuffle is a skewed placement — which is a statistical
/// distinguisher on exactly the thing this module exists to hide. So indices are drawn by
/// rejection instead.
fn shuffle(v: &mut [u32]) {
    if v.len() < 2 {
        return;
    }
    for i in (1..v.len()).rev() {
        let j = uniform_below(i as u64 + 1) as usize;
        v.swap(i, j);
    }
}

/// A uniform integer in `[0, n)`, by rejection sampling. Never `%` on a raw draw.
fn uniform_below(n: u64) -> u64 {
    debug_assert!(n > 0);
    // Largest multiple of `n` that fits; draws at or above it are discarded rather than folded,
    // which is what keeps the result uniform.
    let limit = u64::MAX - (u64::MAX % n) - 1;
    loop {
        let x = OsRng.next_u64();
        if x <= limit {
            return x % n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Every block is offered exactly once — a permutation, not a random walk. A repeat would hand
    /// the same block to two writes in one transaction; a gap would strand capacity forever.
    #[test]
    fn every_block_is_offered_exactly_once() {
        let mut a = Allocator::new(500);
        let mut seen = HashSet::new();
        while let Some(b) = a.next_candidate() {
            assert!(seen.insert(b), "block {b} was offered twice");
        }
        assert_eq!(seen.len(), 499, "expected every block but block 0");
        assert!(!seen.contains(&0), "block 0 must never be allocated");
    }

    /// Two mounts must not produce the same order. This is the property the whole module exists
    /// for: an order that repeats is an order the holder of the public password can replay.
    #[test]
    fn two_sessions_do_not_share_an_order() {
        let first: Vec<u64> = std::iter::from_fn({
            let mut a = Allocator::new(2000);
            move || a.next_candidate()
        })
        .collect();
        let second: Vec<u64> = std::iter::from_fn({
            let mut a = Allocator::new(2000);
            move || a.next_candidate()
        })
        .collect();
        assert_ne!(first, second, "two mounts produced an identical allocation order");
    }

    /// The order must not be the identity, or near it. A shuffle that quietly did nothing would
    /// pass the permutation test above while leaking exactly as much as no shuffle at all.
    #[test]
    fn the_order_is_actually_shuffled_and_not_merely_a_permutation() {
        let mut a = Allocator::new(1000);
        let seq: Vec<u64> = std::iter::from_fn(|| a.next_candidate()).collect();
        let fixed = seq.iter().enumerate().filter(|(i, &b)| b == *i as u64 + 1).count();
        // A uniform shuffle of 999 elements leaves ~1 element in place on average; 50 would mean
        // the shuffle is barely moving anything.
        assert!(fixed < 50, "{fixed} blocks stayed in their original position — barely shuffled");
    }

    /// Rejection sampling stays inside its bound and does not loop forever on awkward moduli.
    #[test]
    fn uniform_below_respects_its_bound() {
        for n in [1u64, 2, 3, 7, 1000, u64::MAX / 3] {
            for _ in 0..50 {
                assert!(uniform_below(n) < n, "uniform_below({n}) escaped its bound");
            }
        }
    }

    /// A degenerate container does not panic — it simply has nothing to offer.
    #[test]
    fn a_container_with_no_usable_blocks_offers_nothing() {
        let mut a = Allocator::new(1);
        assert_eq!(a.next_candidate(), None, "only block 0 exists, and it is reserved");
        assert_eq!(a.remaining(), 0);
    }

    /// `remaining` tracks what is left, so a caller can tell "out of candidates" from "rejected
    /// every candidate so far" without inspecting the order.
    #[test]
    fn remaining_counts_down_as_candidates_are_offered() {
        let mut a = Allocator::new(10);
        assert_eq!(a.remaining(), 9);
        a.next_candidate();
        assert_eq!(a.remaining(), 8);
    }
}
