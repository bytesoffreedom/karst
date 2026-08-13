//! Putting a container back together after a crash — separately for each password.
//!
//! # There is no single recovery table, and there cannot be
//!
//! The obvious design is one table mapping every block state to an action. It cannot exist,
//! because no session can read it:
//!
//! - the protected password holds the public space's key and the ownership key, but not the
//!   hidden space's;
//! - the hidden password holds the hidden space's key and the ownership key, but not the public
//!   space's;
//! - the public password holds only the public space's key.
//!
//! A table with a "is it reachable from the other space's root?" column is a table nobody can
//! evaluate. Worse, a session that GUESSED that column would be deciding the fate of data it
//! cannot see: the hidden session finding `Reserved(Public)` and reclaiming it because no root it
//! can read points at it would be destroying a public transaction that was merely interrupted.
//!
//! So each session resolves only what it can prove, and leaves the rest exactly as it found it.
//! Blocks belonging to the other space are not a problem to be solved — they are none of this
//! session's business.
//!
//! # What a session may do
//!
//! Only where the ownership layer says the block is this session's AND the session's own root
//! settles the question. Everything else is left alone, including states that look obviously
//! stale, because "obviously" here means "as far as I can see", and this session cannot see far.

use crate::capsule::{Owner, State, Verdict};
use crate::record::SpaceId;

/// Which password is doing the recovering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Session {
    /// Public space plus the ownership layer.
    Protected,
    /// Hidden space plus the ownership layer.
    Hidden,
    /// Public space only — no ownership key, so it cannot repair the layer at all.
    Public,
}

impl Session {
    /// The space this session can read.
    pub fn space(&self) -> SpaceId {
        match self {
            Session::Protected | Session::Public => SpaceId::Public,
            Session::Hidden => SpaceId::Hidden,
        }
    }

    /// The owner tag this session may act on.
    fn owner(&self) -> Owner {
        match self {
            Session::Protected | Session::Public => Owner::Public,
            Session::Hidden => Owner::Hidden,
        }
    }

    /// Whether this session can write capsules at all.
    pub fn can_repair_layer(&self) -> bool {
        !matches!(self, Session::Public)
    }
}

/// What recovery decided about one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Not this session's business. Includes every block of the other space, and every block whose
    /// owner cannot be established.
    LeaveAlone,
    /// A reservation whose transaction never committed: wipe it and mark it free.
    ReleaseOrphanedReservation,
    /// Live but unreachable from the committed root: the same, a transaction that did not land.
    ReleaseOrphanedBlock,
    /// Mid-retirement when the power went: finish the retirement.
    FinishRetirement,
    /// The capsule is damaged but the root reaches the block and its contents verify: rewrite the
    /// capsule and keep the data.
    RepairCapsule,
}

/// Decide what one block needs.
///
/// `reachable` is whether the session's own committed root reaches this block. `payload_ok` is
/// whether its contents verify under the session's key, and is only consulted where it decides
/// something — hashing every block during recovery would make recovery cost the container.
pub fn action_for(
    session: Session,
    verdict: Verdict,
    reachable: bool,
    payload_ok: bool,
) -> Action {
    if !session.can_repair_layer() {
        // No ownership key: this session cannot write a capsule, so every outcome would be a lie
        // about what it did. See `public::RebuildPlan` for the way back.
        return Action::LeaveAlone;
    }

    let claim = match verdict {
        Verdict::Confirmed(c) => c,
        // An unchecked Live claim is not evidence the payload is this session's, and recovery is
        // exactly the caller that must not act on one. Ask again with a digest or leave it.
        Verdict::Unchecked(_) => return Action::LeaveAlone,
        Verdict::Unknown => {
            // The layer cannot vouch for the block. Only the root can rescue it, and only if the
            // contents actually verify — otherwise this is debris, or another space's data whose
            // capsule was torn, and touching it would be destroying what we cannot read.
            return if reachable && payload_ok { Action::RepairCapsule } else { Action::LeaveAlone };
        }
    };

    match claim.state {
        State::Reserved(o) if o == session.owner() && !reachable => {
            Action::ReleaseOrphanedReservation
        }
        State::Live(o) if o == session.owner() && !reachable => Action::ReleaseOrphanedBlock,
        State::Retiring(o) if o == session.owner() => Action::FinishRetirement,
        // Everything else: the other space's blocks, this session's live and reachable blocks,
        // free blocks, and metadata. All fine as they are.
        _ => Action::LeaveAlone,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::Claim;

    fn claim(state: State) -> Claim {
        Claim { state, generation: 1, transaction: 1, binding: [0u8; 32] }
    }

    fn confirmed(state: State) -> Verdict {
        Verdict::Confirmed(claim(state))
    }

    /// The case that would silently destroy an interrupted transaction of the OTHER space: the
    /// hidden session finds a public reservation no root it can read points at. It must leave it.
    #[test]
    fn a_session_never_reclaims_the_other_spaces_reservation() {
        let v = confirmed(State::Reserved(Owner::Public));
        assert_eq!(action_for(Session::Hidden, v, false, false), Action::LeaveAlone);

        let v = confirmed(State::Reserved(Owner::Hidden));
        assert_eq!(action_for(Session::Protected, v, false, false), Action::LeaveAlone);
    }

    /// Nor the other space's live data, however unreachable it looks from here.
    #[test]
    fn a_session_never_reclaims_the_other_spaces_live_block() {
        let v = confirmed(State::Live(Owner::Hidden));
        assert_eq!(action_for(Session::Protected, v, false, true), Action::LeaveAlone);
    }

    /// Its own orphaned reservation is fair game: the transaction that made it never committed,
    /// and nothing else can be pointing at the block.
    #[test]
    fn a_session_releases_its_own_orphaned_reservation() {
        let v = confirmed(State::Reserved(Owner::Public));
        assert_eq!(
            action_for(Session::Protected, v, false, false),
            Action::ReleaseOrphanedReservation
        );
    }

    /// A live block the committed root still reaches is left alone — it is the data.
    #[test]
    fn a_live_reachable_block_is_left_alone() {
        let v = confirmed(State::Live(Owner::Public));
        assert_eq!(action_for(Session::Protected, v, true, true), Action::LeaveAlone);
    }

    /// A live block the root does NOT reach is a transaction that did not land.
    #[test]
    fn a_live_unreachable_block_is_released() {
        let v = confirmed(State::Live(Owner::Public));
        assert_eq!(action_for(Session::Protected, v, false, true), Action::ReleaseOrphanedBlock);
    }

    /// A retirement interrupted mid-way is finished rather than abandoned, or the block stays
    /// unusable forever.
    #[test]
    fn an_interrupted_retirement_is_finished() {
        let v = confirmed(State::Retiring(Owner::Public));
        assert_eq!(action_for(Session::Protected, v, false, false), Action::FinishRetirement);
    }

    /// A damaged capsule on a block the root reaches AND whose contents verify is repaired. This
    /// is what keeps a torn capsule from costing a block.
    #[test]
    fn a_torn_capsule_on_verified_reachable_data_is_repaired() {
        assert_eq!(
            action_for(Session::Protected, Verdict::Unknown, true, true),
            Action::RepairCapsule
        );
    }

    /// But an Unknown block the root does not reach is left alone — it may be the other space's
    /// data whose capsule was torn, and reclaiming it would destroy what this session cannot read.
    #[test]
    fn an_unknown_unreachable_block_is_left_alone() {
        assert_eq!(
            action_for(Session::Protected, Verdict::Unknown, false, false),
            Action::LeaveAlone
        );
    }

    /// And an Unknown block the root reaches but whose contents do NOT verify is left alone too:
    /// the map pointing at it is not proof the bytes are ours.
    #[test]
    fn an_unknown_block_whose_contents_do_not_verify_is_left_alone() {
        assert_eq!(
            action_for(Session::Protected, Verdict::Unknown, true, false),
            Action::LeaveAlone
        );
    }

    /// An UNCHECKED live claim is not enough for recovery to act on, however reachable the block
    /// is. This is the distinction the verdict split exists for.
    #[test]
    fn recovery_never_acts_on_an_unchecked_claim() {
        let v = Verdict::Unchecked(claim(State::Live(Owner::Public)));
        assert_eq!(action_for(Session::Protected, v, false, true), Action::LeaveAlone);
    }

    /// The public session repairs nothing at all, whatever it is shown: it has no ownership key,
    /// so any action would be a claim about a capsule it cannot write.
    #[test]
    fn the_public_session_repairs_nothing() {
        assert!(!Session::Public.can_repair_layer());
        for v in [
            confirmed(State::Reserved(Owner::Public)),
            confirmed(State::Live(Owner::Public)),
            confirmed(State::Retiring(Owner::Public)),
            Verdict::Unknown,
        ] {
            assert_eq!(action_for(Session::Public, v, false, true), Action::LeaveAlone);
        }
    }

    /// Each session reads its own space, and the two are not the same space.
    #[test]
    fn each_session_reads_its_own_space() {
        assert_eq!(Session::Protected.space(), SpaceId::Public);
        assert_eq!(Session::Public.space(), SpaceId::Public);
        assert_eq!(Session::Hidden.space(), SpaceId::Hidden);
    }
}
