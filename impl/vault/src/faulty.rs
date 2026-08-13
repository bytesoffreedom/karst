//! A storage backend that can lose power the way real storage does.
//!
//! # Killing the process is not a power-loss model
//!
//! The existing failpoint mechanism aborts the process between logical steps, and that catches a
//! useful class of bug. It does not catch this one: when a process dies, its dirty pages are still
//! in the kernel's cache and the kernel writes them out afterwards. The file on disk ends up more
//! complete than the process ever made it. Real power loss is the opposite — writes that the
//! application believed were done may simply not be there, and writes it issued in one order may
//! have landed in another.
//!
//! So the rows of the crash matrix that say "mid-write", "torn", or "the FREE capsule was
//! partially written" are not reachable by aborting. They need a backend that models the two
//! things the kernel actually promises: writes are visible to later reads immediately, and become
//! DURABLE only at a barrier.
//!
//! # The model
//!
//! Writes go to a volatile queue and are visible to reads at once. A barrier moves everything
//! queued so far into the durable image. A simulated power cut discards the queue — but first it
//! may apply an arbitrary subset of it, in an arbitrary order, and each applied write may land
//! whole, not at all, or torn at either end.
//!
//! The one rule that is NOT negotiable: **writes never move across a barrier that returned
//! successfully.** Reordering inside the current epoch is fair game; reordering across a completed
//! barrier would model a device that lies about `fsync`, and a format cannot be built to survive
//! that — it can only be built to detect it.

use std::collections::HashMap;

/// How one pending write survives a power cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// Landed completely.
    Whole,
    /// Never reached the platter.
    Lost,
    /// Only the first `n` bytes landed.
    TornPrefix(usize),
    /// Only the last `n` bytes landed.
    TornSuffix(usize),
}

#[derive(Debug, Clone)]
struct Pending {
    offset: u64,
    bytes: Vec<u8>,
}

/// A file that can lose power.
pub struct FaultyStore {
    durable: Vec<u8>,
    volatile: Vec<Pending>,
    /// Barriers that have completed. Writes queued before one can never be reordered past it.
    epochs: usize,
}

impl FaultyStore {
    /// A store of `len` bytes, durable and zeroed.
    pub fn new(len: usize) -> Self {
        Self { durable: vec![0u8; len], volatile: Vec::new(), epochs: 0 }
    }

    /// Queue a write. Visible to reads immediately; durable only after a barrier.
    pub fn write(&mut self, offset: u64, bytes: &[u8]) {
        self.volatile.push(Pending { offset, bytes: bytes.to_vec() });
    }

    /// Read as the application sees it: durable image with everything pending applied in order.
    pub fn read(&self, offset: u64, len: usize) -> Vec<u8> {
        let mut view = self.durable.clone();
        for p in &self.volatile {
            apply(&mut view, p.offset, &p.bytes);
        }
        slice(&view, offset, len)
    }

    /// Read only what has actually reached the platter.
    pub fn read_durable(&self, offset: u64, len: usize) -> Vec<u8> {
        slice(&self.durable, offset, len)
    }

    /// A successful `fsync`: everything queued becomes durable, in order.
    pub fn barrier(&mut self) {
        for p in std::mem::take(&mut self.volatile) {
            apply(&mut self.durable, p.offset, &p.bytes);
        }
        self.epochs += 1;
    }

    /// Completed barriers so far — the epoch counter a test asserts against.
    pub fn epochs(&self) -> usize {
        self.epochs
    }

    /// Pull the plug. `fates` decides what happens to each pending write, and `order` the sequence
    /// they land in; both are supplied by the test rather than drawn randomly, so a failure is
    /// reproducible without a seed to chase.
    ///
    /// Writes from before the last barrier are untouched — they are already durable, and moving
    /// them would model a device that lied about `fsync`.
    pub fn power_cut(&mut self, order: &[usize], fates: &[Fate]) {
        let pending = std::mem::take(&mut self.volatile);
        for (n, &i) in order.iter().enumerate() {
            let Some(p) = pending.get(i) else { continue };
            let fate = fates.get(n).copied().unwrap_or(Fate::Whole);
            match fate {
                Fate::Whole => apply(&mut self.durable, p.offset, &p.bytes),
                Fate::Lost => {}
                Fate::TornPrefix(n) => {
                    let n = n.min(p.bytes.len());
                    apply(&mut self.durable, p.offset, &p.bytes[..n]);
                }
                Fate::TornSuffix(n) => {
                    let n = n.min(p.bytes.len());
                    let start = p.bytes.len() - n;
                    apply(&mut self.durable, p.offset + start as u64, &p.bytes[start..]);
                }
            }
        }
    }

    /// Every pending write is lost — the harshest cut, and the one a commit protocol must survive
    /// by definition.
    pub fn power_cut_losing_everything(&mut self) {
        self.volatile.clear();
    }

    /// How many writes are waiting on a barrier.
    pub fn pending(&self) -> usize {
        self.volatile.len()
    }
}

fn apply(image: &mut [u8], offset: u64, bytes: &[u8]) {
    let start = offset as usize;
    let end = (start + bytes.len()).min(image.len());
    if start < image.len() {
        image[start..end].copy_from_slice(&bytes[..end - start]);
    }
}

fn slice(image: &[u8], offset: u64, len: usize) -> Vec<u8> {
    let start = (offset as usize).min(image.len());
    let end = (start + len).min(image.len());
    image[start..end].to_vec()
}

/// Every ordering of `n` pending writes, for exhaustively checking a short sequence.
///
/// Bounded deliberately: a commit protocol's critical section is a handful of writes, and a test
/// that quietly stopped enumerating past some size would report "all orderings pass" while having
/// checked a fraction of them.
pub fn all_orderings(n: usize) -> Vec<Vec<usize>> {
    assert!(n <= 6, "refusing to enumerate {n}! orderings — keep the critical section short");
    let mut out = Vec::new();
    permute(&mut (0..n).collect::<Vec<_>>(), 0, &mut out);
    out
}

fn permute(v: &mut Vec<usize>, k: usize, out: &mut Vec<Vec<usize>>) {
    if k == v.len() {
        out.push(v.clone());
        return;
    }
    for i in k..v.len() {
        v.swap(k, i);
        permute(v, k + 1, out);
        v.swap(k, i);
    }
}

/// Which writes are durable after a cut, as a map from offset to what landed. A helper for
/// asserting about the resulting image without hand-slicing it in every test.
pub fn durable_map(store: &FaultyStore, spans: &[(u64, usize)]) -> HashMap<u64, Vec<u8>> {
    spans.iter().map(|&(off, len)| (off, store.read_durable(off, len))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A write is visible to the application before it is durable. That gap IS the bug class this
    /// backend exists to find: code that reads back what it wrote and concludes it is safe.
    #[test]
    fn a_write_is_visible_long_before_it_is_durable() {
        let mut s = FaultyStore::new(64);
        s.write(0, b"hello");
        assert_eq!(s.read(0, 5), b"hello", "the application must see its own write");
        assert_eq!(s.read_durable(0, 5), &[0u8; 5], "but nothing has reached the platter");
        s.barrier();
        assert_eq!(s.read_durable(0, 5), b"hello");
    }

    /// Losing everything pending is the baseline a commit protocol must survive: the durable image
    /// is exactly what the last barrier left.
    #[test]
    fn a_cut_before_any_barrier_leaves_the_previous_state() {
        let mut s = FaultyStore::new(64);
        s.write(0, b"first");
        s.barrier();
        s.write(0, b"secnd");
        s.power_cut_losing_everything();
        assert_eq!(s.read_durable(0, 5), b"first", "an unbarriered write survived a power cut");
    }

    /// Writes queued before a completed barrier are never reordered past it. Without this the
    /// backend would model a device that lies about fsync, which nothing can be built against.
    #[test]
    fn a_completed_barrier_is_never_crossed() {
        let mut s = FaultyStore::new(64);
        s.write(0, b"AAAA");
        s.barrier();
        s.write(0, b"BBBB");
        // Even the harshest cut cannot un-write what the barrier made durable.
        s.power_cut(&[0], &[Fate::Lost]);
        assert_eq!(s.read_durable(0, 4), b"AAAA");
    }

    /// Reordering inside one epoch is fair game, and the backend really does it — a test that
    /// asked for a reversed order and silently got the original would prove nothing.
    #[test]
    fn writes_inside_one_epoch_really_do_reorder() {
        let mut s = FaultyStore::new(16);
        s.write(0, b"1111");
        s.write(0, b"2222");
        s.power_cut(&[1, 0], &[Fate::Whole, Fate::Whole]);
        assert_eq!(s.read_durable(0, 4), b"1111", "the later write should have landed first");
    }

    /// A torn write leaves part of the range. This is the row of the matrix an abort cannot reach.
    #[test]
    fn a_torn_write_leaves_only_part_of_the_range() {
        let mut s = FaultyStore::new(16);
        s.write(0, b"ABCDEFGH");
        s.power_cut(&[0], &[Fate::TornPrefix(3)]);
        assert_eq!(s.read_durable(0, 8), b"ABC\0\0\0\0\0");

        let mut s = FaultyStore::new(16);
        s.write(0, b"ABCDEFGH");
        s.power_cut(&[0], &[Fate::TornSuffix(3)]);
        assert_eq!(s.read_durable(0, 8), b"\0\0\0\0\0FGH");
    }

    /// A lost write leaves nothing, even when its neighbours land.
    #[test]
    fn one_write_can_be_lost_while_its_neighbours_land() {
        let mut s = FaultyStore::new(32);
        s.write(0, b"AA");
        s.write(4, b"BB");
        s.write(8, b"CC");
        s.power_cut(&[0, 1, 2], &[Fate::Whole, Fate::Lost, Fate::Whole]);
        assert_eq!(s.read_durable(0, 2), b"AA");
        assert_eq!(s.read_durable(4, 2), &[0u8; 2]);
        assert_eq!(s.read_durable(8, 2), b"CC");
    }

    /// Enumeration is exhaustive for short sequences and refuses to pretend for long ones.
    #[test]
    fn orderings_are_exhaustive_and_bounded() {
        assert_eq!(all_orderings(3).len(), 6);
        assert_eq!(all_orderings(0).len(), 1);
        let three = all_orderings(3);
        assert!(three.contains(&vec![2, 1, 0]) && three.contains(&vec![0, 1, 2]));
    }

    #[test]
    #[should_panic(expected = "keep the critical section short")]
    fn enumerating_too_many_orderings_is_refused_rather_than_truncated() {
        all_orderings(9);
    }

    /// A barrier empties the queue, so an epoch really is a boundary and not a growing list.
    #[test]
    fn a_barrier_clears_what_was_pending() {
        let mut s = FaultyStore::new(16);
        s.write(0, b"x");
        assert_eq!(s.pending(), 1);
        s.barrier();
        assert_eq!(s.pending(), 0);
        assert_eq!(s.epochs(), 1);
    }
}
