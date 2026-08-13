//! The one interface a commit is applied through, and the one place the ordering is enforced.
//!
//! Until now every layer of this crate planned bytes and let the caller put them somewhere: the
//! crash matrix wrote them into [`crate::faulty::FaultyStore`] by hand, matching on `Step` in the
//! test itself. That was right while the question was "is the ORDER correct", and it is wrong the
//! moment a second backend exists — two copies of the apply loop are two places for the barrier
//! discipline to drift, and the copy that drifts would be the one nobody is testing power cuts
//! against.
//!
//! So: one trait, one [`apply`], and the fault model and the real file are two implementations of
//! it. A test that passes against the model is testing the same executor production runs.
//!
//! # `barrier` returns a `Result`, and that is the whole difference between the two backends
//!
//! The model's barrier cannot fail — it is memory. A real `fdatasync` can, and the plan is explicit
//! about what that means: **a failed sync is a failed COMMIT, not a warning.** Linux reports
//! writeback errors on `fsync` and may only report them once, so a caller that logs and carries on
//! has just told the user their data is safe on the strength of the error it ignored.

use crate::tx::Step;

/// What went wrong underneath a commit.
#[derive(Debug)]
pub enum MediumError {
    /// The access was outside the container. The container never grows, so this is a bug in the
    /// layer above rather than a condition to handle.
    OutOfBounds { offset: u64, len: usize, capacity: u64 },
    /// The write reached the OS but the barrier did not confirm it. **The transaction did not
    /// commit.**
    Io(std::io::Error),
}

impl std::fmt::Display for MediumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MediumError::OutOfBounds { offset, len, capacity } => write!(
                f,
                "access at {offset}+{len} is past the container's {capacity} bytes; the container \
                 never grows, so this is a planning bug and not a storage condition"
            ),
            MediumError::Io(e) => write!(f, "storage: {e}"),
        }
    }
}

impl std::error::Error for MediumError {}

/// Somewhere a container's bytes live.
///
/// Deliberately three operations. Anything richer — "write these blocks", "commit this
/// transaction" — would put ordering decisions inside the backend, which is exactly the knowledge
/// this crate exists to keep in one place.
pub trait Medium {
    /// Queue bytes at a byte offset. Visible to later reads; durable only after a successful
    /// [`Medium::barrier`].
    fn write(&mut self, offset: u64, bytes: &[u8]) -> Result<(), MediumError>;

    /// Read what the application would see now: durable bytes with anything queued applied.
    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>, MediumError>;

    /// Make everything written so far durable. **An error means the commit failed.**
    fn barrier(&mut self) -> Result<(), MediumError>;

    /// The container's fixed size in bytes.
    fn capacity(&self) -> u64;
}

/// Apply a commit's steps in order.
///
/// The steps are already ordered by [`crate::tx::Commit::build`]; this does not reorder, skip or
/// merge them. It exists so that "a barrier is an fsync and a failed fsync aborts" is written once.
///
/// On error it stops where it stopped. It deliberately does NOT try to undo anything: there is no
/// undo on a medium that may have lost power, and the format's own recovery is what reads a
/// half-applied commit — see [`crate::recover`]. Rolling back here would be a second, untested
/// recovery path racing the tested one.
pub fn apply<M: Medium>(steps: &[Step], medium: &mut M) -> Result<(), MediumError> {
    for step in steps {
        match step {
            Step::Write { offset, bytes, .. } => medium.write(*offset, bytes)?,
            Step::Barrier => medium.barrier()?,
        }
    }
    Ok(())
}

/// How far a commit got before it failed — for a caller that wants to say something specific
/// rather than "storage error".
///
/// `Ok(())` means every step landed. `Err((n, e))` means step `n` failed; steps before it were
/// issued, and those before the last successful barrier are durable.
pub fn apply_reporting<M: Medium>(
    steps: &[Step],
    medium: &mut M,
) -> Result<(), (usize, MediumError)> {
    for (i, step) in steps.iter().enumerate() {
        let r = match step {
            Step::Write { offset, bytes, .. } => medium.write(*offset, bytes),
            Step::Barrier => medium.barrier(),
        };
        if let Err(e) = r {
            return Err((i, e));
        }
    }
    Ok(())
}

impl Medium for crate::faulty::FaultyStore {
    /// The model has no bounds to violate in the same way a file does — it is a `Vec` — but it
    /// answers the SAME refusal, so a planning bug is caught in the cheap backend rather than only
    /// in the expensive one.
    fn write(&mut self, offset: u64, bytes: &[u8]) -> Result<(), MediumError> {
        let cap = self.capacity();
        if offset.saturating_add(bytes.len() as u64) > cap {
            return Err(MediumError::OutOfBounds { offset, len: bytes.len(), capacity: cap });
        }
        crate::faulty::FaultyStore::write(self, offset, bytes);
        Ok(())
    }

    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>, MediumError> {
        let cap = Medium::capacity(self);
        if offset.saturating_add(len as u64) > cap {
            return Err(MediumError::OutOfBounds { offset, len, capacity: cap });
        }
        Ok(crate::faulty::FaultyStore::read(self, offset, len))
    }

    /// Cannot fail: it is memory. Modelling a failing barrier would mean modelling a device that
    /// lies about `fsync`, and the crate's own note on that says a format can only DETECT such a
    /// device, not survive it.
    fn barrier(&mut self) -> Result<(), MediumError> {
        crate::faulty::FaultyStore::barrier(self);
        Ok(())
    }

    fn capacity(&self) -> u64 {
        crate::faulty::FaultyStore::len(self) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::faulty::FaultyStore;
    use crate::tx::What;

    fn w(offset: u64, byte: u8, len: usize) -> Step {
        Step::Write { offset, bytes: vec![byte; len], what: What::Payload(0) }
    }

    /// The executor does what the steps say, in the order they say it, and a barrier is what makes
    /// bytes durable.
    #[test]
    fn apply_writes_in_order_and_a_barrier_is_what_commits() {
        let mut m = FaultyStore::new(256);
        apply(&[w(0, 0xAA, 8), w(8, 0xBB, 8)], &mut m).expect("in bounds");
        assert_eq!(m.read_durable(0, 16), vec![0u8; 16], "nothing is durable without a barrier");

        apply(&[Step::Barrier], &mut m).expect("barrier");
        let mut want = vec![0xAAu8; 8];
        want.extend_from_slice(&[0xBB; 8]);
        assert_eq!(m.read_durable(0, 16), want, "the barrier made exactly what was queued durable");
    }

    /// An access past the end is refused rather than silently clamped. The container is a fixed
    /// size by construction, so this can only be a planning bug — and a clamp would turn it into
    /// corruption that reads back as a decrypt failure much later.
    #[test]
    fn an_access_past_the_end_is_refused_by_both_halves_of_the_interface() {
        let mut m = FaultyStore::new(64);
        assert!(matches!(
            Medium::write(&mut m, 60, &[0u8; 8]),
            Err(MediumError::OutOfBounds { .. })
        ));
        assert!(matches!(Medium::read(&m, 60, 8), Err(MediumError::OutOfBounds { .. })));
        // The boundary itself is legal: the last byte is addressable.
        assert!(Medium::write(&mut m, 56, &[0u8; 8]).is_ok());
        assert!(Medium::read(&m, 56, 8).is_ok());
    }

    /// A failing step stops the commit where it failed and says which step it was.
    #[test]
    fn a_failed_step_is_reported_by_position() {
        let mut m = FaultyStore::new(64);
        let steps = [w(0, 1, 8), Step::Barrier, w(60, 2, 8)];
        let (at, _) = apply_reporting(&steps, &mut m).expect_err("the third step is out of bounds");
        assert_eq!(at, 2, "the failure names the step that failed");
        assert_eq!(m.read_durable(0, 8), vec![1u8; 8], "what committed before it stays committed");
    }
}
