//! Who owns a physical block — the hidden layer, and the rule that keeps it safe.
//!
//! # Why this is not in the public space's metadata
//!
//! The public space must not record "these blocks are reserved". Anyone holding the public
//! password would see blocks marked used with no file behind them, and that is the whole game. So
//! ownership lives in its own layer under its own key: two capsules beside every block, opaque
//! without that key, present in every container whether or not a hidden space exists.
//!
//! # The rule everything else leans on
//!
//! **A capsule that does not verify is `Unknown`, and `Unknown` is never free.**
//!
//! It would be natural to treat an unreadable capsule as an empty one — the block looks like
//! random bytes, nothing claims it, take it. That is precisely the bug: a live block of the hidden
//! space whose capsule was torn by a crash looks exactly like that, and reusing it destroys data
//! the owner had no way to protect. Fail-closed costs some capacity after a crash. Fail-open costs
//! the hidden space.
//!
//! # Why the binding depends on the state
//!
//! A capsule ties itself to the block's contents so that a payload rewritten behind the layer's
//! back invalidates the claim. But that binding cannot hold in every state: `Reserved` exists
//! precisely while the payload is NOT yet written, and `Retiring` exists while it is being
//! overwritten with random. Requiring a content hash in those states would make every capsule
//! invalid for the duration of the operation it was introduced to protect. So `Live` binds the
//! contents, `Free` binds a witness, and the transitional states bind neither and say only "not
//! yours".

use crate::record::{Context, MasterKey, RecordType, SpaceId};

/// Which space a block belongs to, from the ownership layer's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    Public,
    Hidden,
}

/// A block's ownership state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Available. Binds a witness, not the payload — a free block's contents are meaningless.
    Free,
    /// Claimed for a transaction that has not yet written the payload. Binds nothing about the
    /// contents, because there are none yet.
    Reserved(Owner),
    /// Holding live data. Binds the exact bytes on disk.
    Live(Owner),
    /// On its way out: the payload is being overwritten. Binds nothing, and must not be handed out
    /// however far the overwrite has got.
    Retiring(Owner),
    /// Permanently held by the layer itself — roots, the free index, transaction manifests. Its
    /// contents authenticate under their own record and are deliberately NOT bound here, so the
    /// structure can be updated in place without invalidating the claim on the block.
    Meta(SpaceId),
}

impl State {
    fn tag(&self) -> u8 {
        match self {
            State::Free => 1,
            State::Reserved(Owner::Public) => 2,
            State::Reserved(Owner::Hidden) => 3,
            State::Live(Owner::Public) => 4,
            State::Live(Owner::Hidden) => 5,
            State::Retiring(Owner::Public) => 6,
            State::Retiring(Owner::Hidden) => 7,
            State::Meta(SpaceId::Public) => 8,
            State::Meta(SpaceId::Hidden) => 9,
            State::Meta(SpaceId::Ownership) => 10,
        }
    }

    fn from_tag(t: u8) -> Option<Self> {
        Some(match t {
            1 => State::Free,
            2 => State::Reserved(Owner::Public),
            3 => State::Reserved(Owner::Hidden),
            4 => State::Live(Owner::Public),
            5 => State::Live(Owner::Hidden),
            6 => State::Retiring(Owner::Public),
            7 => State::Retiring(Owner::Hidden),
            8 => State::Meta(SpaceId::Public),
            9 => State::Meta(SpaceId::Hidden),
            10 => State::Meta(SpaceId::Ownership),
            _ => return None,
        })
    }

    /// Whether this state binds the block's payload bytes.
    ///
    /// Only `Live` does. See the module docs: binding in `Reserved` or `Retiring` would invalidate
    /// the capsule for exactly the window the state exists to cover, and binding in `Meta` would
    /// stop a root from being updated in place.
    pub fn binds_payload(&self) -> bool {
        matches!(self, State::Live(_))
    }

    /// Whether a block in this state may be handed to an allocator.
    ///
    /// Only `Free`. Everything else — including another space's live data, a reservation that may
    /// belong to a transaction still in flight, and anything mid-retirement — is off limits.
    pub fn is_allocatable(&self) -> bool {
        matches!(self, State::Free)
    }
}

/// What a capsule claims about one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Claim {
    pub state: State,
    pub generation: u64,
    pub transaction: u64,
    /// For `Live`, the digest of the payload. For `Free`, a witness that changes on every release
    /// so a stale capsule cannot be replayed onto a block that has since been reused.
    pub binding: [u8; 32],
}

/// The verdict of reading a block's capsules. `Unknown` is a RESULT, never a stored state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Known(Claim),
    /// Neither copy verified, or the payload does not match a `Live` claim. Fail-closed: the block
    /// is not free, not ours, not touchable.
    Unknown,
}

impl Verdict {
    /// The only question the allocator is allowed to ask.
    pub fn is_allocatable(&self) -> bool {
        match self {
            Verdict::Known(c) => c.state.is_allocatable(),
            Verdict::Unknown => false,
        }
    }
}

fn encode(c: &Claim) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 8 + 8 + 32);
    v.push(c.state.tag());
    v.extend_from_slice(&c.generation.to_le_bytes());
    v.extend_from_slice(&c.transaction.to_le_bytes());
    v.extend_from_slice(&c.binding);
    v
}

fn decode(b: &[u8]) -> Option<Claim> {
    if b.len() != 1 + 8 + 8 + 32 {
        return None;
    }
    let mut binding = [0u8; 32];
    binding.copy_from_slice(&b[17..49]);
    Some(Claim {
        state: State::from_tag(b[0])?,
        generation: u64::from_le_bytes(b[1..9].try_into().expect("8 bytes")),
        transaction: u64::from_le_bytes(b[9..17].try_into().expect("8 bytes")),
        binding,
    })
}

fn ctx(format_hash: [u8; 32], block: u64, generation: u64, copy: u8) -> Context {
    Context {
        format_hash,
        record_type: RecordType::Capsule,
        space: SpaceId::Ownership,
        physical_block: block,
        logical_or_prefix: 0,
        generation,
        copy_index: copy,
    }
}

/// Seal a claim as copy `copy` of block `block`'s capsule.
pub fn seal_claim(
    key: &MasterKey,
    format_hash: [u8; 32],
    block: u64,
    copy: u8,
    claim: &Claim,
) -> Vec<u8> {
    crate::record::seal(key, &ctx(format_hash, block, claim.generation, copy), &encode(claim))
}

/// Read both copies of a block's capsule and decide.
///
/// `payload_digest` is what the block's contents actually hash to, supplied by the caller because
/// hashing is expensive and the free-block scan must not pay for it: it is checked ONLY against a
/// `Live` claim, and only when the caller has a digest to offer. A `Live` claim whose digest does
/// not match is `Unknown` — someone wrote the payload without going through this layer, which is
/// exactly what the public mode does, and the block must not be treated as ours afterwards.
pub fn read_capsules(
    key: &MasterKey,
    format_hash: [u8; 32],
    block: u64,
    copies: [&[u8]; 2],
    payload_digest: Option<[u8; 32]>,
) -> Verdict {
    let mut best: Option<Claim> = None;
    for (i, raw) in copies.iter().enumerate() {
        // The generation is inside the sealed claim and also in the aad, so it cannot be read
        // before decrypting. Both copies are tried against every generation the caller could be
        // holding by decoding with the generation the record itself asserts — which is why the
        // claim carries it and the aad binds it: a copy re-sealed at another generation will not
        // open at this one.
        if let Some(claim) = try_open(key, format_hash, block, i as u8, raw) {
            if best.is_none_or(|b| claim.generation > b.generation) {
                best = Some(claim);
            }
        }
    }
    let Some(claim) = best else { return Verdict::Unknown };

    if claim.state.binds_payload() {
        match payload_digest {
            Some(d) if d == claim.binding => Verdict::Known(claim),
            Some(_) => Verdict::Unknown, // contents changed behind the layer's back
            None => Verdict::Known(claim), // caller did not ask for the expensive check
        }
    } else {
        Verdict::Known(claim)
    }
}

/// Try both plausible generations for a copy. The aad binds the generation, so opening requires
/// knowing it; a claim asserts its own, so the search is over what the record could say — bounded
/// by trying the value the claim would have to carry.
fn try_open(
    key: &MasterKey,
    format_hash: [u8; 32],
    block: u64,
    copy: u8,
    raw: &[u8],
) -> Option<Claim> {
    // The generation lives in the aad, so it must be guessed before decryption. Rather than
    // searching, the sealed plaintext repeats it: seal with generation G in the aad, and the
    // reader learns G from the copy's own header slot. That header is the generation itself,
    // written in the clear ahead of the record and covered by the record's aad — so tampering with
    // it makes the record fail to open rather than redirecting it.
    if raw.len() < 8 {
        return None;
    }
    let generation = u64::from_le_bytes(raw[..8].try_into().expect("8 bytes"));
    let opened = crate::record::open(key, &ctx(format_hash, block, generation, copy), &raw[8..])?;
    let claim = decode(&opened)?;
    // The clear generation and the sealed one must agree, or the clear one was tampered with.
    (claim.generation == generation).then_some(claim)
}

/// Frame a sealed capsule with its clear generation prefix, as it is stored.
pub fn frame(claim: &Claim, sealed: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + sealed.len());
    out.extend_from_slice(&claim.generation.to_le_bytes());
    out.extend_from_slice(&sealed);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const FH: [u8; 32] = [3u8; 32];

    fn stored(key: &MasterKey, block: u64, copy: u8, claim: &Claim) -> Vec<u8> {
        frame(claim, seal_claim(key, FH, block, copy, claim))
    }

    fn claim(state: State, generation: u64) -> Claim {
        Claim { state, generation, transaction: 1, binding: [9u8; 32] }
    }

    /// The rule everything leans on: an unreadable capsule is not free.
    #[test]
    fn an_unreadable_capsule_is_unknown_and_never_allocatable() {
        let k = MasterKey::generate();
        let junk = vec![0xABu8; 80];
        let v = read_capsules(&k, FH, 1, [&junk, &junk], None);
        assert_eq!(v, Verdict::Unknown);
        assert!(!v.is_allocatable(), "random bytes were treated as a free block");
    }

    /// A live block of the OTHER space is not allocatable either — this is the case that would
    /// destroy the hidden space if it were.
    #[test]
    fn another_spaces_live_block_is_not_allocatable() {
        let k = MasterKey::generate();
        let c = claim(State::Live(Owner::Hidden), 5);
        let s = stored(&k, 7, 0, &c);
        let v = read_capsules(&k, FH, 7, [&s, &[]], None);
        assert!(matches!(v, Verdict::Known(_)));
        assert!(!v.is_allocatable(), "the hidden space's live block was offered to the allocator");
    }

    /// Only `Free` is allocatable. Reserved and Retiring are the states a crash leaves behind, and
    /// handing either out would race a transaction that may still land.
    #[test]
    fn only_free_is_allocatable() {
        for (state, allocatable) in [
            (State::Free, true),
            (State::Reserved(Owner::Public), false),
            (State::Live(Owner::Public), false),
            (State::Retiring(Owner::Public), false),
            (State::Meta(SpaceId::Ownership), false),
        ] {
            assert_eq!(state.is_allocatable(), allocatable, "{state:?}");
        }
    }

    /// Only `Live` binds the payload. Binding in the transitional states would make the capsule
    /// invalid for exactly the window it exists to cover.
    #[test]
    fn only_live_binds_the_payload() {
        assert!(State::Live(Owner::Public).binds_payload());
        assert!(!State::Reserved(Owner::Public).binds_payload());
        assert!(!State::Retiring(Owner::Public).binds_payload());
        assert!(!State::Free.binds_payload());
        assert!(!State::Meta(SpaceId::Public).binds_payload(), "a root could not be updated");
    }

    /// A payload rewritten behind the layer's back invalidates a `Live` claim. That is what the
    /// public mode does to a block it takes, and afterwards the block must not read as ours.
    #[test]
    fn a_live_claim_whose_payload_changed_is_unknown() {
        let k = MasterKey::generate();
        let mut c = claim(State::Live(Owner::Public), 2);
        c.binding = [1u8; 32];
        let s = stored(&k, 4, 0, &c);
        assert!(matches!(read_capsules(&k, FH, 4, [&s, &[]], Some([1u8; 32])), Verdict::Known(_)));
        assert_eq!(
            read_capsules(&k, FH, 4, [&s, &[]], Some([2u8; 32])),
            Verdict::Unknown,
            "a rewritten payload still authenticated as live"
        );
    }

    /// The newer copy wins, so a half-finished update to one copy cannot roll the block back.
    #[test]
    fn the_higher_generation_copy_wins() {
        let k = MasterKey::generate();
        let old = claim(State::Free, 4);
        let new = claim(State::Live(Owner::Public), 9);
        let a = stored(&k, 2, 0, &old);
        let b = stored(&k, 2, 1, &new);
        match read_capsules(&k, FH, 2, [&a, &b], None) {
            Verdict::Known(c) => assert_eq!(c.generation, 9),
            Verdict::Unknown => panic!("both copies were readable"),
        }
    }

    /// One torn copy does not lose the block: the other still speaks for it. This is the entire
    /// reason there are two.
    #[test]
    fn one_torn_copy_is_survived_by_the_other() {
        let k = MasterKey::generate();
        let c = claim(State::Live(Owner::Public), 3);
        let good = stored(&k, 6, 1, &c);
        let torn = vec![0u8; 40];
        assert!(matches!(read_capsules(&k, FH, 6, [&torn, &good], None), Verdict::Known(_)));
    }

    /// Tampering with the clear generation prefix breaks the record rather than redirecting it.
    #[test]
    fn editing_the_clear_generation_invalidates_the_capsule() {
        let k = MasterKey::generate();
        let c = claim(State::Free, 5);
        let mut s = stored(&k, 8, 0, &c);
        s[0] ^= 0xFF;
        assert_eq!(read_capsules(&k, FH, 8, [&s, &[]], None), Verdict::Unknown);
    }

    /// A capsule is bound to its block: lifting it to another block does not carry the claim.
    #[test]
    fn a_capsule_does_not_travel_to_another_block() {
        let k = MasterKey::generate();
        let c = claim(State::Free, 1);
        let s = stored(&k, 10, 0, &c);
        assert_eq!(read_capsules(&k, FH, 11, [&s, &[]], None), Verdict::Unknown);
    }

    /// And to its copy slot, so copy 0 cannot be duplicated into copy 1 to fake agreement.
    #[test]
    fn a_capsule_does_not_travel_to_the_other_copy_slot() {
        let k = MasterKey::generate();
        let c = claim(State::Free, 1);
        let s = stored(&k, 10, 0, &c);
        assert_eq!(read_capsules(&k, FH, 10, [&[], &s], None), Verdict::Unknown);
    }
}
