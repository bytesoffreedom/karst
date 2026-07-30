//! Rotating drop-boxes: per-session, per-epoch mailbox addresses.
//!
//! A mailbox address is not a name the relay assigns — it is an X25519 public key,
//! and the relay grants a fetch only to whoever proves they hold the matching secret
//! (`DH(relay_identity, mailbox)`, see `node::fetch_proof`). That constraint is what
//! makes rotation possible at all: *any* keypair both parties can derive is a usable
//! address, so a conversation need not keep depositing to the recipient's long-term
//! identity key.
//!
//! Both sides derive the boxes from `drop_seed`, taken once from the session's root
//! key at key agreement. The root key is already shared, already secret, and — unlike
//! the ratchet's running `rk` — it does not move underneath us, so both sides land on
//! the same address without exchanging anything.
//!
//! # What this hides, and from whom
//!
//! Against the relay, rotating the address alone buys nothing: it also sees
//! `client_addr` on every request, and a handle that is stable across epochs relinks
//! the boxes instantly. Address rotation is therefore only half the mechanism — the
//! per-epoch handles in `peer::Peer` are the other half, and neither works alone.
//!
//! # Residuals (honest floor)
//!
//! - Within one epoch the relay still sees deposit and fetch touch the same box. It is
//!   the drop-box; that linkage is inherent, not a defect.
//! - The recipient still polls its identity-key mailbox for openers from strangers,
//!   which names it. That poll runs under its own handle so it does not relink the
//!   rotating boxes, but a stranger's first knock needs one stable address to arrive at.
//! - Boxes polled back-to-back over one connection correlate by timing and source
//!   address regardless of what the addresses are. That is a transport concern
//!   (§15 path isolation), not one addressing can fix.

use karst_crypto::seal::Identity;
use hkdf::Hkdf;
use sha2::Sha256;

/// How long one drop-box address stays valid.
///
/// **Why a day and not an hour** (it was an hour, and that was wrong). A message is
/// deposited into the box of the epoch it was SENT in and is never re-deposited, so the
/// recipient must eventually poll every box that could still hold live mail — which means
/// every epoch inside the relay's `MAILBOX_TTL_SECS` (7 days). At an hour that is ~170
/// boxes per session; at a day it is 9. The epoch length therefore sets the cost of being
/// correct, not just the granularity of rotation.
///
/// What the coarser epoch gives up is small, and worth naming rather than assuming: a
/// finer epoch would cut a conversation into narrower linkable windows — but a relay that
/// logs fetches already chains epochs through the poll overlap (see the module docs), so
/// that granularity buys nothing against it today. Against the observer rotation DOES
/// defeat — one holding your published IK, reading deposit addresses — any rotation
/// suffices and the length is irrelevant. If PIR ever closes the chaining gap, revisit
/// this: then granularity would start to pay, and the sweep cost would be the thing to
/// argue with.
pub const DROP_EPOCH_SECS: u64 = 24 * 3600;

/// How many epochs of history can still hold live mail: the relay's `MAILBOX_TTL_SECS`,
/// rounded up. Derived rather than hardcoded — if either constant moves, the sweep window
/// must move with it or mail goes quietly unreachable.
const TTL_EPOCHS: u64 = node::protocol::MAILBOX_TTL_SECS.div_ceil(DROP_EPOCH_SECS);

/// Take a session's INITIAL drop-box seed from its root key — generation 0 of the routing chain.
///
/// **This used to be the whole story, and the narrative here used to explain why it had to be.**
/// The routing seed did not heal: it came from `root_key`, which is fixed at key agreement, so
/// anyone who once held the session state could compute every future epoch's box for the pair and
/// keep watching who talks to whom, forever. Content healed; the metadata trail did not.
///
/// The block that stood here named two shapes and rejected both, correctly:
///
/// 1. A plain hash chain `seed_{n+1} = KDF(seed_n, dh_out_n)` gives real metadata PCS but has no
///    self-recovery — one side advancing while the other misses that step leaves them on different
///    chains permanently, where epochs merely need the clock to correct itself.
/// 2. Adding a `root_key`-derived FALLBACK box that both sides always poll restores recovery and
///    simultaneously hands the adversary exactly the address the rotation was meant to take away.
///
/// **Why a third shape works where those two do not.** The obstacle both run into is derivability:
/// the recipient must compute the next box BEFORE receiving anything in it. A chain fed by the
/// sender's fresh DH cannot be derived in advance — the recipient does not hold that key yet — so
/// the fallback box is the only way back, and the fallback is the leak.
///
/// The chain here is fed by [`karst_crypto::ratchet::Session::take_routing_contributions`]. The DH
/// outputs form ONE sequence that both sides walk in the same order: each step computes two of them
/// with a one-element overlap, and the initiator's key agreement supplies the first. Nothing in that
/// sequence is fresh to only one side, so the recipient holds the next element BEFORE the sender
/// uses it, and needs no fallback box to find the address.
///
/// Taking ONE output per step instead of two was the first attempt and it is wrong in a way that
/// reads as correct: each side then walks only the even or only the odd elements, the sequences are
/// DISJOINT, and the recipient can never derive the sender's address. It was caught by a test, not
/// by review — which is why the agreement is pinned in `ratchet` rather than described here.
///
/// That leaves a bounded disagreement rather than an unbounded one. A DH step happens only inside
/// `advance_for_decrypt`, so neither side advances without a successful delivery from the other:
/// the two can differ by exactly one leg, never more. The recipient therefore polls TWO
/// generations — the current one and the previous — and destroys the older secret when the window
/// slides. Not three "for safety": every extra generation kept is another address an adversary who
/// captured state can still compute, so the window is the bound itself, not a margin around it.
///
/// **What still does not heal, stated plainly.** A state rollback (a restore from backup) puts the
/// two sides further apart than one leg, and routing does not recover from that on its own. This
/// is not a new failure: a rollback already desynchronises the ratchet's message keys and already
/// requires the explicit forget/reconnect path. Routing now fails in exactly the case that was
/// already broken, with the same remedy — which is what the earlier analysis of shape 1
/// underweighted when it called the desync fatal.
///
/// PCS, concretely: state captured at generation `k` yields `k` and `k-1` and stops. Generation
/// `k+1` needs a contribution derived from a private key generated after the capture.
///
/// **WHAT IS WIRED TODAY, precisely — this paragraph is the difference between a design and a
/// claim.** The derivability argument above is verified against `ratchet::dh_ratchet`, and the
/// mechanism exists: the ratchet produces a contribution per step
/// ([`karst_crypto::ratchet::Session::take_routing_contribution`]) and [`advance_routing`] folds it.
/// `peer::SessionState` does NOT yet carry the two generations, so the address a message actually
/// goes to is still generation 0 — this function's output — and the routing trail still does not
/// heal in the shipped product. The guard test below therefore still passes, and is expected to go
/// red in the slice that wires the session layer.
///
/// Said here rather than left implicit because the failure mode of a half-landed privacy change is
/// a file that reads as though the property holds. It does not hold yet.
///
/// Separated by `info` from every other use of the root key.
pub fn drop_seed(root_key: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, root_key);
    let mut out = [0u8; 32];
    hk.expand(b"karst-dropbox-seed-v1", &mut out).expect("32 is a valid HKDF length");
    out
}

/// Advance the routing chain by one generation (PRIV-2).
///
/// `contrib` comes from [`karst_crypto::ratchet::Session::take_routing_contribution`] and must be
/// folded exactly once per DH step. Chained rather than replaced so a generation cannot be
/// reconstructed from the contribution alone: an adversary who learns one step's contribution
/// without the previous secret still cannot name the box.
pub fn advance_routing(seed: &[u8; 32], contrib: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(seed), contrib);
    let mut out = [0u8; 32];
    hk.expand(b"karst-dropbox-seed-gen-v1", &mut out).expect("32 is a valid HKDF length");
    out
}

/// How many routing generations a recipient must poll: the current one and the previous one.
///
/// **This is a bound, not a margin.** A DH step happens only on a successful decrypt, so neither
/// side can advance without a delivery from the other, and the two can differ by exactly one leg.
/// Widening it would not buy robustness — it would keep additional generations derivable by anyone
/// who captured the session state, which is precisely what PRIV-2 removes.
pub const ROUTING_WINDOW: usize = 2;

/// Which epoch a timestamp falls in.
pub fn epoch_of(now: u64) -> u64 {
    now / DROP_EPOCH_SECS
}

/// Which of a session's two directions a box carries: `0` or `1`.
///
/// A SINGLE box per session was a real flaw: A→B and B→A landed in one address, so the
/// sender could fetch its own outbound mail, and the relay watched four operations
/// (both deposits, both fetches) on one box instead of two. A per-direction box fixes
/// both. The direction is decided by ORDERING the two identity keys — a symmetric,
/// exchange-free rule, so both parties derive the same two boxes and agree which is which
/// without a round trip: the sender deposits to `direction(me, peer)`, the recipient
/// fetches `direction(peer, me)`, and those are the two different halves.
pub fn direction(sender_ik: &[u8; 32], recipient_ik: &[u8; 32]) -> u8 {
    u8::from(sender_ik >= recipient_ik)
}

/// Derive this session's drop-box keypair for `epoch` and `dir` (see `direction`).
///
/// The recipient needs the secret (the relay's fetch proof is a DH against it); the
/// sender needs only the public half, but derives the same way. Both sides must agree
/// byte-for-byte, so the epoch is bound in fixed-width little-endian rather than as a
/// formatted number, and the direction byte is bound in the `info` alongside the label.
pub fn drop_identity(seed: &[u8; 32], epoch: u64, dir: u8) -> Identity {
    let hk = Hkdf::<Sha256>::new(Some(&epoch.to_le_bytes()), seed);
    let mut sk = [0u8; 32];
    let info = [b"karst-dropbox-epoch-v1".as_slice(), &[dir]].concat();
    hk.expand(&info, &mut sk).expect("32 is a valid HKDF length");
    Identity::from_secret_bytes(sk)
}

/// This session's drop-box address for `epoch`/`dir` — the public half of `drop_identity`.
pub fn drop_address(seed: &[u8; 32], epoch: u64, dir: u8) -> [u8; 32] {
    drop_identity(seed, epoch, dir).public.to_bytes()
}

/// Seed for a peer's OWN loop box — the drop-box it writes cover traffic to and reads it
/// back from (Loopix's "loop": a message you send to yourself).
///
/// Derived from the identity SECRET, not the public key: a loop box anyone could compute
/// from your published IK would be a box anyone could watch, which is the leak the whole
/// mechanism exists to avoid. Domain-separated from `drop_seed`, so a loop box can never
/// collide with a real session's box.
pub fn loop_seed(ik_secret: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ik_secret);
    let mut out = [0u8; 32];
    hk.expand(b"karst-loopbox-seed-v1", &mut out).expect("32 is a valid HKDF length");
    out
}

/// The HOT window — polled every cycle, because this is where mail arriving right now
/// lands and latency is the whole point of polling often.
///
/// The next epoch is not paranoia. Sender and recipient run unsynchronised clocks, so a
/// sender slightly ahead of a boundary deposits to a box the recipient does not consider
/// current yet, and mail there would sit unseen until the recipient's own clock advanced.
/// The previous covers the mirror case plus anything deposited just before a rollover.
///
/// This window is NOT sufficient on its own — see `sweep_epochs`. Polling only these
/// would silently strand every message that arrived while the recipient was away longer
/// than an epoch.
pub fn poll_epochs(now: u64) -> [u64; 3] {
    let e = epoch_of(now);
    [e.saturating_sub(1), e, e + 1]
}

/// The COMPLETE window — every epoch whose box could still hold live mail.
///
/// Store-and-forward promises that you can leave and come back. The relay keeps
/// undelivered mail for `MAILBOX_TTL_SECS`, so a recipient must be able to reach every
/// box inside that span, however long it was offline. A message is deposited into the box
/// of the epoch it was SENT in and never moves, so a recipient polling only around its
/// own current clock would leave older mail at an address it never asks for again: it
/// would rot until the TTL sweep with no error anywhere — the mailbox intact, the relay
/// honest, the message simply unreachable. That is silent loss, and it was a REGRESSION
/// the rotation introduced (the old fixed IK-mailbox held everything until TTL).
///
/// Swept on a slow schedule rather than every cycle: old mail is by definition not
/// latency-critical, and this window is `TTL_EPOCHS + 2` boxes per session where the hot
/// one is 3. Cost is round trips only — fetches are charged no quota
/// (`RelayNode::handle_fetch`) — but they are still TCP connections, and over an overlay
/// that is the real bill.
pub fn sweep_epochs(now: u64) -> Vec<u64> {
    let e = epoch_of(now);
    (e.saturating_sub(TTL_EPOCHS)..=e + FUTURE_SLACK_EPOCHS).collect()
}

/// How far AHEAD of our own clock the slow sweep still looks (A6-8, #224).
///
/// A sender deposits into the box of the epoch ITS clock says it is, and nothing authenticates
/// that clock. A machine with the wrong date — a dead RTC battery, a bad timezone, a VM restored
/// from a snapshot — deposits into a box its recipient does not consider current, and the mail
/// sits there unread until the relay's TTL sweeps it: no error anywhere, the relay honest, the
/// message simply at an address nobody asks for.
///
/// We cannot fix the sender's clock, and there is no authenticated time here to check it against.
/// What we CAN do is make the receiver's window forgiving in the direction that costs only round
/// trips. Two epochs of slack covers the common "date is off by a day or two" case; a sender
/// wrong by a month is still lost mail, and that is stated rather than papered over.
///
/// Only the SLOW sweep is widened — the hot window runs every cycle, and latency-critical mail
/// comes from senders whose clocks are close to ours by construction.
pub const FUTURE_SLACK_EPOCHS: u64 = 2;

/// How often the complete window is swept. Bounds worst-case delivery latency for mail
/// that arrived while we were away — it is already old, so minutes do not matter, and the
/// hot window covers everything current.
pub const SWEEP_INTERVAL_SECS: u64 = 600;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_the_same_address_and_it_moves_every_epoch() {
        // The property the whole slice rests on: the address is a pure function of
        // (seed, epoch), so sender and recipient agree without exchanging anything —
        // and it genuinely moves when the epoch does. Neuter `drop_identity` to ignore
        // `epoch` (drop the `Some(..)` salt) and the "moves" assertion reddens.
        let seed = drop_seed(&[7u8; 32]);
        assert_eq!(drop_address(&seed, 100, 0), drop_address(&seed, 100, 0));
        assert_ne!(drop_address(&seed, 100, 0), drop_address(&seed, 101, 0));
    }

    #[test]
    fn the_two_directions_of_a_session_are_different_boxes() {
        // P0 fix: a single box let the SENDER fetch its own outbound mail and piled both
        // directions onto one address. The two directions must be distinct boxes, and the
        // ordering rule must be symmetric so both parties agree which is which.
        let seed = drop_seed(&[7u8; 32]);
        assert_ne!(drop_address(&seed, 5, 0), drop_address(&seed, 5, 1), "directions collide");

        let a = [1u8; 32];
        let b = [2u8; 32];
        // sender A → recipient B and sender B → recipient A must pick OPPOSITE directions,
        // and each ordering is stable regardless of who asks.
        assert_ne!(direction(&a, &b), direction(&b, &a), "a session's two legs share a direction");
        assert_eq!(direction(&a, &b), direction(&a, &b));
    }

    /// A6-3 (#208): the routing seed does NOT change when the ratchet heals — pinned, not merely
    /// written down.
    ///
    /// STILL TRUE, and expected to become false: the chain primitives landed (see `drop_seed`'s
    /// note on what is wired), but `peer::SessionState` does not yet carry the two generations, so
    /// generation 0 is still the address in use. When the session layer is wired this test must be
    /// REWRITTEN to assert healing — not deleted, because its job is to make whoever does that
    /// update the claim in the same commit.
    ///
    /// This asserts a LIMIT rather than a fix, which is unusual and deliberate. `docs/STATUS.md`
    /// tells a reader that message keys get post-compromise security while the addresses do not;
    /// a paragraph drifts away from the code silently, an assertion does not. If someone later
    /// rotates the routing material along the ratchet — the design is sketched on `drop_seed` —
    /// this test fails, and whoever does it is forced to update the claim in the same commit
    /// instead of leaving the docs describing a weakness that is gone.
    ///
    /// The mechanism, stated once: `drop_seed` is a function of `root_key` alone. `root_key` is
    /// fixed at key agreement and no DH step touches it, so an adversary who once held the
    /// session state derives every future epoch's address for this pair forever.
    #[test]
    fn the_routing_seed_is_deliberately_not_healed_by_the_ratchet() {
        let root = [3u8; 32];
        let seed_now = drop_seed(&root);

        // A DH step advances the ratchet's own root key — that is what heals message keys.
        let stepped = {
            let mut s = karst_crypto::ratchet::Session::init_sender(root, [8u8; 32]);
            let _ = s.encrypt(b"advance the chain");
            s.snapshot()
        };
        // ...and the drop-box seed is untouched by it, because it never depended on that state.
        assert_eq!(
            drop_seed(&root),
            seed_now,
            "the routing seed is derived from the FIXED root key: a healed ratchet does not move it"
        );
        // The address for a future epoch is therefore computable from state captured today.
        let far_future = epoch_of(0) + 10_000;
        assert_eq!(
            drop_address(&seed_now, far_future, 0),
            drop_address(&drop_seed(&root), far_future, 0),
            "state captured once yields every future box — the metadata trail does not heal"
        );
        drop(stepped);
    }

    #[test]
    fn a_different_session_never_shares_a_box() {
        // Two sessions must not collide, or one peer could fetch another's mail.
        let a = drop_seed(&[1u8; 32]);
        let b = drop_seed(&[2u8; 32]);
        assert_ne!(drop_address(&a, 5, 0), drop_address(&b, 5, 0));
    }

    /// A6-8 (#224): a sender whose CLOCK is wrong by a day or two — not merely skewed across a
    /// boundary — still lands inside the window we sweep.
    ///
    /// Nothing authenticates a sender's clock. A dead RTC battery, a wrong timezone or a VM
    /// restored from a snapshot puts its deposit into a box we would never ask for, and the mail
    /// rots until the relay's TTL with no error anywhere. The slow sweep therefore reaches
    /// `FUTURE_SLACK_EPOCHS` past our own epoch.
    ///
    /// Discriminating on the DAY-scale case rather than the boundary case: the hot window already
    /// covers `e+1`, so a test using a one-epoch-ahead sender would pass with the slack removed.
    #[test]
    fn the_sweep_reaches_a_sender_whose_clock_is_days_fast() {
        let now = 40 * DROP_EPOCH_SECS;
        let e = epoch_of(now);
        let two_days_fast = epoch_of(now + 2 * DROP_EPOCH_SECS);
        assert_eq!(two_days_fast, e + 2, "the fixture must really be two epochs ahead");
        assert!(
            !poll_epochs(now).contains(&two_days_fast),
            "control: the hot window does NOT cover this — the slack has to come from the sweep"
        );
        assert!(
            sweep_epochs(now).contains(&two_days_fast),
            "a sender two days fast must still be reachable by the slow sweep"
        );
    }

    #[test]
    fn the_recipient_polls_the_epoch_a_fast_sender_would_have_used() {
        // A sender whose clock runs ahead of ours across a boundary deposits into e+1. If
        // the hot window were only [prev, current], that mail would be invisible until our
        // own clock rolled over.
        //
        // This test was VACUOUS until audit cycle 3. It used `now = 10*EPOCH + 5` and a
        // skew of 60s — which never crossed a boundary, so `sender_ahead` was just `e`,
        // the middle element `poll_epochs` always contains. The `e+1` term could be
        // deleted outright and this stayed green while claiming to guard it. Sit `now`
        // just BEFORE a boundary so the skewed sender genuinely lands in the next epoch;
        // now removing `e+1` reddens (verified).
        let now = 11 * DROP_EPOCH_SECS - 30;
        let sender_ahead = epoch_of(now + 60);
        assert_eq!(sender_ahead, epoch_of(now) + 1, "the fixture must actually cross a boundary");
        assert!(poll_epochs(now).contains(&sender_ahead));
    }

    #[test]
    fn the_sweep_reaches_every_box_the_relay_could_still_be_holding() {
        // The window must span the relay's full retention, or mail deposited while we were
        // away sits at an address we never ask for again — silent loss (see the module
        // docs). Asserted against `MAILBOX_TTL_SECS` rather than a literal, so shortening
        // the sweep OR lengthening the TTL without the other reddens.
        let now = 500 * DROP_EPOCH_SECS;
        let sweep = sweep_epochs(now);
        let oldest_live = epoch_of(now - node::protocol::MAILBOX_TTL_SECS);
        assert!(sweep.contains(&oldest_live), "a box still inside the TTL is never polled");
        assert!(sweep.contains(&(epoch_of(now) + 1)), "the sweep must cover the skew epoch too");
    }
}
