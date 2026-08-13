//! The object catalogue, and what "free space" is allowed to mean.
//!
//! # A fixed array, not a growable structure
//!
//! Objects are numbered slots in an array whose size is a constant of the format, and each slot
//! owns a static range of the logical address space. Nothing here grows, splits, or spills into a
//! chain — which is what makes the credit planner able to state a transaction's worst case as a
//! number rather than a recurrence.
//!
//! The cost is a ceiling on how many objects a container can hold. Running out of slots is a
//! distinct, honest error — "no more objects" — and not the same answer as running out of space,
//! because they need different things from the user.
//!
//! # Free space, and why there are two of it
//!
//! The cheap answer comes from the free-block hint and is a LOWER BOUND: the hint is lazy, may lag
//! reality, and is corrected by re-reading capsules before a block is taken. The exact answer costs
//! a capsule scan.
//!
//! Neither is a promise that an operation will fit. That question belongs to the credit planner,
//! which is the only thing that knows what a particular mutation needs. A UI number and an
//! admission decision are different questions and conflating them is how a container reports 40 MB
//! free and then refuses a 1 MB write.
//!
//! # The number the protected mode shows is not the number it stores
//!
//! Under the protected password some blocks are the hidden space's, so the honest figure is
//! smaller than the public map's own arithmetic would give. That smaller figure is computed in
//! memory and shown; it is never written down. Persisting it would put a number in the public
//! space's metadata that only makes sense if a hidden space exists — which is the leak the whole
//! ownership layer exists to avoid.

/// One object's record, as it sits in a catalogue block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectRecord {
    pub state: ObjectState,
    /// Application-level type. The storage layer never interprets it.
    pub kind: u32,
    pub size: u64,
    /// Monotonic creation order, so `list` has a stable order that does not leak slot reuse.
    pub created_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectState {
    Free,
    Live,
    /// Being deleted: its mappings are still being cleared. Not `Free` until they are, or its
    /// blocks would be handed out while the map still points at them.
    Deleting,
}

/// Bytes one record occupies.
pub const RECORD_LEN: usize = 32;

/// Why an object operation refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectError {
    /// Every slot is occupied. Distinct from running out of space on purpose: the two need
    /// different things from the user, and reporting one as the other sends them to delete files
    /// when they need to delete objects, or the reverse.
    NoFreeSlot,
    /// The object does not exist.
    NoSuchObject,
    /// The write would run past the end of the slot's logical range.
    TooLarge,
}

/// The in-memory catalogue.
pub struct Catalogue {
    records: Vec<ObjectRecord>,
    next_seq: u64,
}

impl Catalogue {
    pub fn empty(slots: usize) -> Self {
        Self {
            records: vec![
                ObjectRecord {
                    state: ObjectState::Free,
                    kind: 0,
                    size: 0,
                    created_seq: 0
                };
                slots
            ],
            next_seq: 1,
        }
    }

    /// Claim the lowest free slot.
    ///
    /// Lowest rather than random: an object's slot decides its logical range, and the logical
    /// range is invisible to anyone without the space key — physical placement is what is
    /// observable, and that is randomised elsewhere. Randomising here would buy nothing and make
    /// the catalogue's own layout harder to reason about.
    pub fn create(&mut self, kind: u32) -> Result<u64, ObjectError> {
        // Slot 0 is the catalogue itself.
        let slot = self
            .records
            .iter()
            .enumerate()
            .skip(1)
            .find(|(_, r)| r.state == ObjectState::Free)
            .map(|(i, _)| i)
            .ok_or(ObjectError::NoFreeSlot)?;
        self.records[slot] = ObjectRecord {
            state: ObjectState::Live,
            kind,
            size: 0,
            created_seq: self.next_seq,
        };
        self.next_seq += 1;
        Ok(slot as u64)
    }

    pub fn get(&self, slot: u64) -> Result<ObjectRecord, ObjectError> {
        let r = self.records.get(slot as usize).ok_or(ObjectError::NoSuchObject)?;
        if r.state == ObjectState::Live {
            Ok(*r)
        } else {
            Err(ObjectError::NoSuchObject)
        }
    }

    /// Begin a delete. The slot does not become free until the mappings are cleared — releasing it
    /// first would let a new object take the range while the old map still points into it.
    pub fn begin_delete(&mut self, slot: u64) -> Result<(), ObjectError> {
        let r = self.records.get_mut(slot as usize).ok_or(ObjectError::NoSuchObject)?;
        if r.state != ObjectState::Live {
            return Err(ObjectError::NoSuchObject);
        }
        r.state = ObjectState::Deleting;
        Ok(())
    }

    /// Finish a delete once the mappings are gone.
    pub fn finish_delete(&mut self, slot: u64) -> Result<(), ObjectError> {
        let r = self.records.get_mut(slot as usize).ok_or(ObjectError::NoSuchObject)?;
        if r.state != ObjectState::Deleting {
            return Err(ObjectError::NoSuchObject);
        }
        *r = ObjectRecord { state: ObjectState::Free, kind: 0, size: 0, created_seq: 0 };
        Ok(())
    }

    /// Record a new size after a write.
    pub fn set_size(&mut self, slot: u64, size: u64, max: u64) -> Result<(), ObjectError> {
        if size > max {
            return Err(ObjectError::TooLarge);
        }
        let r = self.records.get_mut(slot as usize).ok_or(ObjectError::NoSuchObject)?;
        if r.state != ObjectState::Live {
            return Err(ObjectError::NoSuchObject);
        }
        r.size = size;
        Ok(())
    }

    /// Live objects, in creation order.
    pub fn list(&self) -> Vec<(u64, ObjectRecord)> {
        let mut v: Vec<(u64, ObjectRecord)> = self
            .records
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(_, r)| r.state == ObjectState::Live)
            .map(|(i, r)| (i as u64, *r))
            .collect();
        v.sort_by_key(|(_, r)| r.created_seq);
        v
    }

    /// Slots still available.
    pub fn free_slots(&self) -> usize {
        self.records.iter().skip(1).filter(|r| r.state == ObjectState::Free).count()
    }
}

/// What a session may say about free space.
///
/// Two constructors rather than one number, because the two are answers to different questions and
/// a single `free_space()` would let a caller use the cheap one where only the exact one is sound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeSpace {
    /// From the free-block hint: cheap, and never more than the truth.
    LowerBound(u64),
    /// From a capsule scan: exact as of the scan.
    Exact(u64),
}

impl FreeSpace {
    /// The number to show a person. Both kinds are showable; neither is a promise.
    pub fn blocks(&self) -> u64 {
        match self {
            FreeSpace::LowerBound(n) | FreeSpace::Exact(n) => *n,
        }
    }

    /// Deliberately absent: there is no `will_fit`. Whether an operation fits is the credit
    /// planner's question, and answering it from a free-space figure is how a container reports
    /// space it cannot actually give.
    pub fn is_exact(&self) -> bool {
        matches!(self, FreeSpace::Exact(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_created_object_is_live_and_listed() {
        let mut c = Catalogue::empty(8);
        let slot = c.create(7).expect("a free slot");
        assert_ne!(slot, 0, "slot 0 is the catalogue itself");
        assert_eq!(c.get(slot).unwrap().kind, 7);
        assert_eq!(c.list().len(), 1);
    }

    /// Running out of slots is its own error. Reporting it as "out of space" would send someone to
    /// delete large files when what they need is to delete objects.
    #[test]
    fn running_out_of_slots_is_not_reported_as_running_out_of_space() {
        let mut c = Catalogue::empty(3); // slot 0 plus two usable
        c.create(1).unwrap();
        c.create(1).unwrap();
        assert_eq!(c.create(1), Err(ObjectError::NoFreeSlot));
    }

    /// A deleted object's slot is not reusable until its mappings are cleared. Freeing it earlier
    /// would let a new object take the same logical range while the old map still points into it.
    #[test]
    fn a_slot_is_not_reusable_until_its_mappings_are_cleared() {
        let mut c = Catalogue::empty(3);
        let a = c.create(1).unwrap();
        c.create(1).unwrap();
        c.begin_delete(a).unwrap();
        assert_eq!(c.create(1), Err(ObjectError::NoFreeSlot), "a deleting slot was handed out");
        c.finish_delete(a).unwrap();
        assert_eq!(c.create(1), Ok(a), "the slot should be reusable once cleared");
    }

    /// A half-deleted object is not readable, so nothing can act on a size that is about to be
    /// wrong.
    #[test]
    fn a_deleting_object_cannot_be_read() {
        let mut c = Catalogue::empty(4);
        let a = c.create(1).unwrap();
        c.begin_delete(a).unwrap();
        assert_eq!(c.get(a), Err(ObjectError::NoSuchObject));
        assert!(c.list().is_empty());
    }

    /// Writing past the slot's range is refused rather than wrapping into the neighbour's.
    #[test]
    fn a_size_past_the_slice_is_refused() {
        let mut c = Catalogue::empty(4);
        let a = c.create(1).unwrap();
        assert_eq!(c.set_size(a, 101, 100), Err(ObjectError::TooLarge));
        assert_eq!(c.set_size(a, 100, 100), Ok(()), "exactly the maximum must be allowed");
    }

    /// Listing is in creation order, so it does not leak which slots were reused.
    #[test]
    fn listing_is_in_creation_order_not_slot_order() {
        let mut c = Catalogue::empty(5);
        let a = c.create(1).unwrap();
        let b = c.create(1).unwrap();
        c.begin_delete(a).unwrap();
        c.finish_delete(a).unwrap();
        let reused = c.create(1).unwrap();
        assert_eq!(reused, a, "the low slot should be reused");
        let order: Vec<u64> = c.list().iter().map(|(s, _)| *s).collect();
        assert_eq!(order, vec![b, reused], "list leaked slot numbering instead of creation order");
    }

    /// Free space comes in two kinds and they stay distinguishable. A caller that needs the exact
    /// figure must not be able to receive the cheap one without noticing.
    #[test]
    fn a_cheap_free_space_figure_cannot_pass_as_an_exact_one() {
        assert!(!FreeSpace::LowerBound(10).is_exact());
        assert!(FreeSpace::Exact(10).is_exact());
        assert_eq!(FreeSpace::LowerBound(10).blocks(), 10);
    }

    /// An unknown slot is not an object, and neither is a never-created one.
    #[test]
    fn an_unknown_slot_is_not_an_object() {
        let c = Catalogue::empty(4);
        assert_eq!(c.get(2), Err(ObjectError::NoSuchObject));
        assert_eq!(c.get(999), Err(ObjectError::NoSuchObject));
    }
}
