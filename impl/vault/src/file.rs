//! The container as a real file, with the medium assumptions written down rather than assumed.
//!
//! Everything above this module has been exercised against [`crate::faulty::FaultyStore`], which
//! models power loss faithfully and touches no disk. That was the right order — a format whose
//! ordering is wrong is wrong on any medium — but it left the whole crate one step short of being
//! a container: nothing had ever written a byte.
//!
//! # What the plan requires of the file, and what this actually enforces
//!
//! The plan's medium section is explicit that "the two capsule copies land in different atomic
//! write units" is **too strong a claim for an ordinary file**: an application cannot know the
//! real atomic unit of the filesystem, the page cache, the block layer, the controller and the
//! drive. Guaranteed untearable writes on Linux need filesystem and device support plus direct
//! I/O; aligning a `pwrite` does not buy them. So the honest formulation, and the one implemented
//! here, is:
//!
//! - the two copies live in **different aligned pages** of the file;
//! - they are **never written by one `pwrite`** — [`crate::tx::Commit`] emits them as separate
//!   steps, and `geometry` asserts that their offsets fall in different pages;
//! - **a barrier stands between logically dependent updates** — `Commit` emits those too, and
//!   [`crate::medium::apply`] turns each into an `fdatasync`;
//! - correctness is proven in a model where **any single unfinished write may tear arbitrarily**,
//!   which is what `FaultyStore` and the crash matrix do.
//!
//! The environment assumption without which none of it is provable, stated so a reader can decide
//! whether they believe it: **a successful `fdatasync` means every preceding write survives a
//! later loss of power.** A failed one is treated as a failed commit, because Linux may report a
//! deferred writeback error exactly there and may report it only once.
//!
//! # What is enforced here, and what is only documented
//!
//! Enforced: the file is fully preallocated and non-sparse; it is entirely random at creation; its
//! size never changes; access past the end is refused; a second opener is refused by an exclusive
//! `flock`. The capsule-page separation is enforced in `geometry`, where the offsets are decided —
//! not here, where it would only be a check on writes that happen to arrive.
//!
//! Documented and NOT enforced: no network filesystem. There is no portable, honest way to detect
//! one — the magic-number check is a denylist that a new filesystem defeats silently, and a silent
//! partial defence is worse than a stated limit.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::medium::{Medium, MediumError};

/// The alignment the layout is built on: the two capsule copies must land in different units of
/// this size.
///
/// 4096 because that is the page size of every platform this runs on and the smallest unit any of
/// the layers below plausibly treats as a whole. It is NOT a claim that a 4096-byte write is
/// atomic — see the module docs. It is the granularity at which the format keeps its two copies
/// apart so that one torn write cannot damage both.
pub const PAGE: u64 = 4096;

/// A container file, opened exclusively.
pub struct FileStore {
    file: File,
    len: u64,
    path: PathBuf,
}

impl FileStore {
    /// Create a container of exactly `len` bytes, filled with random.
    ///
    /// Refuses to overwrite an existing file: a container is indistinguishable from random by
    /// design, so "is this already a container?" is a question nothing can answer, and clobbering
    /// one would be silent and total.
    ///
    /// The fill is what makes the file **non-sparse and uniformly random**, and both matter for
    /// the same reason: a container must not be able to say whether the hidden space exists. A
    /// sparse file answers that question through its allocated-block count, and a zero-filled one
    /// answers it through entropy — every block that was never written would stand out from every
    /// block that was.
    pub fn create(path: impl AsRef<Path>, len: u64) -> Result<Self, MediumError> {
        let path = path.as_ref().to_path_buf();
        if len == 0 || !len.is_multiple_of(PAGE) {
            return Err(MediumError::OutOfBounds { offset: 0, len: 0, capacity: len });
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true) // never clobber
            .open(&path)
            .map_err(MediumError::Io)?;

        // Written in chunks rather than one allocation: a container is sized for a user's data,
        // and materialising all of it in memory first would make creating a large one fail on a
        // small machine for no reason.
        const CHUNK: usize = 1 << 20;
        let mut written = 0u64;
        let mut buf = vec![0u8; CHUNK];
        while written < len {
            let take = CHUNK.min((len - written) as usize);
            fill_random(&mut buf[..take]);
            file.write_all(&buf[..take]).map_err(MediumError::Io)?;
            written += take as u64;
        }
        // The creation is itself a commit: a half-written container is a file of the right size
        // with a non-random tail, which is the one thing the fill exists to prevent.
        file.sync_all().map_err(MediumError::Io)?;
        drop(file);

        Self::open(path, len)
    }

    /// Open an existing container of exactly `expect_len` bytes, exclusively.
    ///
    /// **The size is checked, not adopted.** Reading the length off the file would let a truncated
    /// or extended container be opened as if it were whole, and every offset above the truncation
    /// would then read random bytes that fail to decrypt — reported to the user as corruption,
    /// with no hint that the file is simply the wrong size.
    pub fn open(path: impl AsRef<Path>, expect_len: u64) -> Result<Self, MediumError> {
        let path = path.as_ref().to_path_buf();
        let file =
            OpenOptions::new().read(true).write(true).open(&path).map_err(MediumError::Io)?;
        let actual = file.metadata().map_err(MediumError::Io)?.len();
        if actual != expect_len {
            return Err(MediumError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "container is {actual} bytes, the format says {expect_len}; refusing rather \
                     than reading past or short of the real end"
                ),
            )));
        }
        lock_exclusive(&file)?;
        Ok(FileStore { file, len: expect_len, path })
    }

    /// Where this container lives — for an error message that names the file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn bounds(&self, offset: u64, len: usize) -> Result<(), MediumError> {
        if offset.saturating_add(len as u64) > self.len {
            return Err(MediumError::OutOfBounds { offset, len, capacity: self.len });
        }
        Ok(())
    }
}

impl Medium for FileStore {
    /// A positioned write.
    ///
    /// **It deliberately does NOT refuse writes that cross a page boundary**, and the first
    /// version did. That was a misreading of the layout rule with teeth: a payload is
    /// `DEFAULT_BLOCK_PAYLOAD` bytes — 64 KiB, seventeen pages — so a blanket refusal rejected
    /// every real payload write in the format. Nothing caught it because the tests here wrote
    /// sixty-four bytes at a time.
    ///
    /// The rule is about the two CAPSULE COPIES, not about every write: they must not share a page,
    /// so that one torn write cannot damage both. That is a property of where the offsets are, so
    /// it is asserted where they are computed — see `geometry::capsules_never_share_a_page`.
    fn write(&mut self, offset: u64, bytes: &[u8]) -> Result<(), MediumError> {
        self.bounds(offset, bytes.len())?;
        if bytes.is_empty() {
            return Ok(());
        }
        self.file.write_all_at(bytes, offset).map_err(MediumError::Io)
    }

    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>, MediumError> {
        self.bounds(offset, len)?;
        let mut buf = vec![0u8; len];
        self.file.read_exact_at(&mut buf, offset).map_err(MediumError::Io)?;
        Ok(buf)
    }

    /// `fdatasync`, and its failure is the transaction's failure.
    ///
    /// `sync_data` rather than `sync_all`: the file's length and mode never change after creation,
    /// so there is no metadata a commit depends on, and syncing it every barrier would pay for an
    /// inode write per step of every transaction.
    fn barrier(&mut self) -> Result<(), MediumError> {
        self.file.sync_data().map_err(MediumError::Io)
    }

    fn capacity(&self) -> u64 {
        self.len
    }
}

/// An exclusive advisory lock for as long as this file description is open.
///
/// `flock` is per open-file-description, so this refuses a second `FileStore` on the same path in
/// the SAME process as well as in another one — which is the case that matters, because a second
/// handle in one process is what a careless refactor produces and what no amount of care between
/// processes would catch. Released by the kernel when the file closes, including on a crash.
///
/// This is the exclusion the conformance list carried as NOT YET ENFORCED: the format's ordering
/// argument assumes one writer, and two writers interleaving transactions would break it in a way
/// no invariant inside a single transaction can detect.
fn lock_exclusive(file: &File) -> Result<(), MediumError> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(MediumError::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "the container is already open elsewhere; a second writer would interleave \
             transactions and break the ordering the format rests on",
        )));
    }
    Ok(())
}

/// Random bytes for the fill. Uses the same OS source the rest of the crate seals with.
fn fill_random(buf: &mut [u8]) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(buf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::medium::apply;
    use crate::tx::{Step, What};

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("karst-test").join(format!(
            "vault-file-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir.join("container.bin")
    }

    const LEN: u64 = 16 * PAGE;

    /// A fresh container is the size asked for, and it is random — not zeros.
    ///
    /// The zero check is the one that matters: a zero-filled or sparse file answers "does the
    /// hidden space exist" by itself, through allocated blocks or through entropy, whatever the
    /// crypto above it does.
    #[test]
    fn a_new_container_is_fully_written_and_random() {
        let p = scratch("random");
        let s = FileStore::create(&p, LEN).expect("create");
        assert_eq!(s.capacity(), LEN);
        assert_eq!(std::fs::metadata(&p).unwrap().len(), LEN, "exactly the size asked for");

        // Sample widely rather than reading it all: the claim is "no region was left unwritten".
        for page in [0u64, 1, 7, 15] {
            let bytes = s.read(page * PAGE, 512).expect("read");
            assert!(bytes.iter().any(|&b| b != 0), "page {page} is all zeros — it was never filled");
        }
        // And two distant regions must not be identical, which a lazy fill would make them.
        assert_ne!(s.read(0, 256).unwrap(), s.read(8 * PAGE, 256).unwrap());
    }

    /// Creating never overwrites. A container is indistinguishable from random, so nothing can ask
    /// "is this already one?" — clobbering would be silent and total.
    #[test]
    fn create_refuses_to_clobber_an_existing_file() {
        let p = scratch("clobber");
        let _s = FileStore::create(&p, LEN).expect("first create");
        let again = FileStore::create(&p, LEN);
        assert!(again.is_err(), "a second create must refuse rather than overwrite a container");
    }

    /// A write is visible to a read, and survives a close/reopen once a barrier has run.
    #[test]
    fn what_a_barrier_commits_is_there_after_reopening() {
        let p = scratch("durable");
        {
            let mut s = FileStore::create(&p, LEN).expect("create");
            s.write(PAGE, &[0xAB; 32]).expect("write");
            assert_eq!(s.read(PAGE, 32).unwrap(), vec![0xAB; 32], "visible immediately");
            s.barrier().expect("fdatasync");
        }
        let s = FileStore::open(&p, LEN).expect("reopen");
        assert_eq!(s.read(PAGE, 32).unwrap(), vec![0xAB; 32], "and durable across a close");
    }

    /// The size is checked against the format, never adopted from the file.
    #[test]
    fn opening_the_wrong_size_is_refused_rather_than_believed() {
        let p = scratch("size");
        {
            let _s = FileStore::create(&p, LEN).expect("create");
        }
        assert!(FileStore::open(&p, LEN + PAGE).is_err(), "a larger expectation must refuse");
        assert!(FileStore::open(&p, LEN - PAGE).is_err(), "a smaller expectation must refuse");
        assert!(FileStore::open(&p, LEN).is_ok(), "and the right one must open");
    }

    /// A second opener is refused — including in this same process, which is the case a refactor
    /// actually produces.
    #[test]
    fn a_second_opener_is_refused_while_the_first_is_alive() {
        let p = scratch("exclusive");
        let first = FileStore::create(&p, LEN).expect("create");
        let second = FileStore::open(&p, LEN);
        assert!(second.is_err(), "two writers would interleave transactions");
        drop(first);
        assert!(FileStore::open(&p, LEN).is_ok(), "and it opens again once the first is gone");
    }

    /// A payload-sized write works. It spans many pages, and it must.
    ///
    /// This is the test the first version of this module did not have, and it is why that version
    /// shipped a `write` that refused every real payload: `DEFAULT_BLOCK_PAYLOAD` is 64 KiB and no
    /// test here wrote more than sixty-four bytes.
    #[test]
    fn a_full_payload_sized_write_spans_many_pages_and_is_fine() {
        let p = scratch("payload");
        let payload = crate::geometry::DEFAULT_BLOCK_PAYLOAD;
        let len = (payload as u64 + 8 * PAGE).div_ceil(PAGE) * PAGE;
        let mut s = FileStore::create(&p, len).expect("create");
        let bytes = vec![0x5Cu8; payload];
        assert!(
            payload as u64 > PAGE,
            "this test is only meaningful while a payload is larger than one page"
        );
        s.write(PAGE, &bytes).expect("a payload write spans pages and must be accepted");
        s.barrier().expect("sync");
        assert_eq!(s.read(PAGE, payload).unwrap(), bytes);
    }

    /// Past the end is refused rather than growing the file. The container never changes size.
    #[test]
    fn access_past_the_end_is_refused_and_the_file_does_not_grow() {
        let p = scratch("bounds");
        let mut s = FileStore::create(&p, LEN).expect("create");
        assert!(s.write(LEN - 4, &[0u8; 8]).is_err());
        assert!(s.read(LEN - 4, 8).is_err());
        drop(s);
        assert_eq!(std::fs::metadata(&p).unwrap().len(), LEN, "the file did not grow");
    }

    /// The real point of the trait: a commit built by `tx` applies to a FILE through the same
    /// executor the crash matrix drives, with no per-backend apply loop.
    #[test]
    fn a_commit_applies_to_a_real_file_through_the_shared_executor() {
        let p = scratch("commit");
        let mut s = FileStore::create(&p, LEN).expect("create");
        let steps = [
            Step::Write { offset: 0, bytes: vec![0x11; 16], what: What::ReservedCapsule(0) },
            Step::Barrier,
            Step::Write { offset: 2 * PAGE, bytes: vec![0x22; 16], what: What::Payload(0) },
            Step::Barrier,
        ];
        apply(&steps, &mut s).expect("the commit applies to a file");
        drop(s);

        let s = FileStore::open(&p, LEN).expect("reopen");
        assert_eq!(s.read(0, 16).unwrap(), vec![0x11; 16]);
        assert_eq!(s.read(2 * PAGE, 16).unwrap(), vec![0x22; 16]);
    }

    /// The same commit, applied to the model and to the file, produces the same bytes.
    ///
    /// This is what makes every crash-matrix result mean something about the file: the matrix
    /// proves the ORDER survives power loss on the model, and this proves the file is the same
    /// bytes under that order. Without it the two backends could diverge and only the cheap one
    /// would be under test.
    #[test]
    fn the_file_and_the_model_agree_byte_for_byte() {
        let p = scratch("agree");
        let mut file = FileStore::create(&p, LEN).expect("create");
        let mut model = crate::faulty::FaultyStore::new(LEN as usize);

        let steps: Vec<Step> = (0..8u64)
            .map(|i| Step::Write {
                offset: i * PAGE + (i * 7 % 100),
                bytes: vec![i as u8 + 1; 64],
                what: What::Payload(i),
            })
            .flat_map(|w| [w, Step::Barrier])
            .collect();

        apply(&steps, &mut file).expect("file");
        apply(&steps, &mut model).expect("model");

        for i in 0..8u64 {
            let at = i * PAGE + (i * 7 % 100);
            assert_eq!(
                file.read(at, 64).unwrap(),
                Medium::read(&model, at, 64).unwrap(),
                "the file and the model disagree at {at}"
            );
        }
    }
}
