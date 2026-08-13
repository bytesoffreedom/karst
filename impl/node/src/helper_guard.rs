//! What a helper node may SEE — enforced, not tabulated (NODE-2).
//!
//! The claim worth keeping is one sentence: **no single component may see who you are, whom you
//! are talking to, and what you said.** Everything else in the helper design is an arrangement of
//! that sentence.
//!
//! # Why this is a module and not a table in a document
//!
//! Helpers arrive one at a time, and each one arrives with a reason it needs one more field than
//! the last. A bridge that also knows the mailbox is easier to route; a storage node that also
//! knows the contact is easier to garbage-collect. Each step is locally sensible and the boundary
//! is gone after four of them, with every test still green. This repository has watched exactly
//! that happen to decisions kept in prose, which is why `identity_guard` exists next door.
//!
//! # The anti-vacuity problem, said out loud
//!
//! No helper exists yet. A guard that only scans helper sources would therefore assert nothing at
//! all while looking like enforcement — worse than a paragraph, because a paragraph does not
//! reassure a reviewer. So this guard is built on two things that are real today:
//!
//! 1. **An enumeration that must stay complete.** Every workspace member is classified below, and
//!    the test parses the workspace manifest and refuses to pass if the two sets differ. A new
//!    crate — which is how a helper will arrive — fails the build until someone says what it is
//!    allowed to see.
//! 2. **A rule that is executable.** `Facets::links_everything` decides whether a set of visible
//!    facets is a violation, and it is tested against a hypothetical over-broad helper. The rule
//!    is exercised today even though nothing violates it today.

/// One thing a component can learn about a user. Grouped, because the danger is not any single
/// facet — it is holding facets from all three groups at once.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Facet {
    /// WHO: the client's network address.
    Ip,
    /// WHO: a long-lived account identifier that survives rotation.
    AccountId,
    /// WITH WHOM: a drop-box / mailbox address.
    Mailbox,
    /// WITH WHOM: a contact relationship, however encoded.
    Contact,
    /// WHAT: plaintext, or anything that reveals it.
    Content,
}

impl Facet {
    /// `who` / `with whom` / `what` — the three groups whose intersection is a dossier.
    fn group(self) -> u8 {
        match self {
            Facet::Ip | Facet::AccountId => 0,
            Facet::Mailbox | Facet::Contact => 1,
            Facet::Content => 2,
        }
    }
}

/// What some component is allowed to see.
#[derive(Clone, Copy)]
pub struct Facets(pub &'static [Facet]);

impl Facets {
    /// Does this set span all three groups? That is the violation: knowing WHO, WITH WHOM and
    /// WHAT in one place is a dossier regardless of how the fields are named or how briefly they
    /// are held.
    ///
    /// Deliberately NOT "sees all five facets". Requiring the full five would let a component
    /// hold IP + mailbox + content — a complete record of one conversation — and still pass,
    /// because it happened not to also keep an account id.
    pub fn links_everything(self) -> bool {
        let mut seen = [false; 3];
        for f in self.0 {
            seen[f.group() as usize] = true;
        }
        seen.iter().all(|g| *g)
    }
}

/// What a component is, for the purposes of this boundary.
pub enum Role {
    /// Not a helper: part of the client, or a library with no network vantage point of its own.
    NotAHelper,
    /// The relay as it exists today — the ACKNOWLEDGED exception, and the reason helpers are
    /// interesting at all. It sees an address and a drop-box (groups 0 and 1); it never sees
    /// content, because content is a ratchet ciphertext it has no key for.
    Relay,
    /// A helper node, with the facets it is allowed to see.
    Helper(Facets),
}

/// **Every workspace member, classified.** The test below diffs this against the manifest, so
/// adding a crate without adding it here fails the build.
///
/// The helper rows are written in advance ON PURPOSE. An invariant introduced after three
/// implementations has to be introduced as a refactor of three implementations.
const CLASSIFIED: &[(&str, Role)] = &[
    ("admission", Role::NotAHelper),
    ("crypto", Role::NotAHelper),
    ("node", Role::NotAHelper),
    ("transport", Role::NotAHelper),
    ("client-core", Role::NotAHelper),
    ("relay", Role::Relay),
    ("client", Role::NotAHelper),
    ("desktop", Role::NotAHelper),
    // The container's storage layer. Not a helper and structurally incapable of becoming one: it
    // runs entirely on the owner's machine, holds no network code, and depends on the crypto
    // primitives and nothing else in the workspace. There is no vantage point to classify because
    // there is no second party.
    ("vault", Role::NotAHelper),
];

/// The roles a helper may be given, and what each may see. A new helper picks a row here or adds
/// one — and adding one is where the rule gets applied.
///
/// Two corrections to the sketch these came from, both recorded because they change what may be
/// CLAIMED rather than what is built:
///
/// - **Storage buys capacity, not privacy.** The sketch credited a storage helper with hiding
///   what a user stores. That property is already ours and owes the helper nothing: a blob id is
///   random per recipient and the relay never holds the key. So a storage helper offloads bytes.
///   Saying more would be selling a property twice.
/// - **Replica is only safe because of the veil.** Re-serving one envelope from two places would
///   otherwise let two operators match on equal BYTES and learn "same message" with no analysis
///   at all. `crypto::veil` re-randomises per relay, so this row stands — it did not when the
///   sketch was written.
pub const HELPER_ROLES: &[(&str, Role)] = &[
    // Sees where a connection comes from and where it goes next; never which box, never why.
    ("bridge", Role::Helper(Facets(&[Facet::Ip]))),
    // Random encrypted shards. No filename, no type, no contact, no mailbox, no key.
    ("storage", Role::Helper(Facets(&[]))),
    // Re-packed ciphertext only, distinct per relay (see the veil note above).
    ("replica", Role::Helper(Facets(&[]))),
    // Packets in, packets out, delayed. The address is the point; nothing else is visible.
    ("mix", Role::Helper(Facets(&[Facet::Ip]))),
    // Public roots.
    ("witness", Role::Helper(Facets(&[]))),
    // Signed descriptors, which are public statements by relays about themselves.
    ("directory", Role::Helper(Facets(&[]))),
    // A random wake token and nothing to join it to.
    ("notification", Role::Helper(Facets(&[]))),
];

/// What someone reversing this has to answer first, printed when they try.
const REVERSAL_CONDITIONS: &str = "\
Before widening what a helper may see, answer these:

  1. WHICH GROUP does the new facet belong to — who / with whom / what? If the component already
     holds the other two, this is the dossier the whole arrangement exists to prevent, and no
     amount of \"only briefly\" or \"only hashed\" changes that. A hash of a mailbox is a mailbox.

  2. WHO ELSE can already see it? A facet available at two helpers that can be correlated is a
     facet at one helper. Colocation, shared operators and shared hosting all count.

  3. WHAT IS THE ALTERNATIVE that keeps the boundary? These roles were drawn narrow because the
     narrow version was buildable, not because nobody wanted the convenient version.

If the answers hold: update the role table here FIRST, with the reasoning, then the code.";

#[cfg(test)]
mod tests {
    use super::*;

    /// The classification must cover the workspace exactly.
    ///
    /// This is the assertion that stops the guard being decorative before the first helper lands:
    /// it has real input today, and the day a helper crate is added it fails until classified.
    /// DISCRIMINATING: add a member to the workspace manifest without touching `CLASSIFIED`.
    #[test]
    fn every_workspace_member_is_classified() {
        let manifest = include_str!("../../Cargo.toml");
        let list = manifest
            .split("members = [")
            .nth(1)
            .expect("the workspace manifest declares members")
            .split(']')
            .next()
            .expect("the members list is closed");
        let members: Vec<&str> =
            list.split(',').map(|m| m.trim().trim_matches('"')).filter(|m| !m.is_empty()).collect();

        for m in &members {
            assert!(
                CLASSIFIED.iter().any(|(name, _)| name == m),
                "workspace member `{m}` is not classified in `CLASSIFIED`. Say what it may see \
                 before it ships: a component whose vantage point nobody wrote down is one \
                 nobody reviewed.\n\n{REVERSAL_CONDITIONS}"
            );
        }
        for (name, _) in CLASSIFIED {
            assert!(
                members.contains(name),
                "`{name}` is classified here but is no longer a workspace member — the guard is \
                 describing something that does not exist, which is how a table starts lying."
            );
        }
    }

    /// The rule itself, exercised. Without this the guard would only be as good as the table.
    #[test]
    fn a_component_that_spans_all_three_groups_is_a_violation() {
        // The dossier: who, with whom, and what.
        assert!(Facets(&[Facet::Ip, Facet::Mailbox, Facet::Content]).links_everything());
        assert!(Facets(&[Facet::AccountId, Facet::Contact, Facet::Content]).links_everything());
        // Two groups is the relay's position — bad enough to be the reason helpers exist, but it
        // is what we have today and the guard must not pretend otherwise.
        assert!(!Facets(&[Facet::Ip, Facet::Mailbox]).links_everything());
        // Content alone is what a storage helper would hold if it held anything: unreadable bytes
        // with nobody attached.
        assert!(!Facets(&[Facet::Content]).links_everything());
        assert!(!Facets(&[]).links_everything());
    }

    /// No declared helper role may already be a violation.
    #[test]
    fn no_declared_helper_role_sees_a_whole_conversation() {
        for (name, role) in HELPER_ROLES {
            let Role::Helper(facets) = role else {
                panic!("`{name}` is in the helper table but is not classified as a helper");
            };
            assert!(
                !facets.links_everything(),
                "helper role `{name}` would see who, with whom AND what — the one arrangement \
                 the boundary exists to prevent.\n\n{REVERSAL_CONDITIONS}"
            );
        }
    }

    /// The relay is the exception, and it is an exception about CONTENT specifically.
    ///
    /// Pinning it here keeps the honest version in front of anyone reading the table: today's
    /// relay does see an address and a drop-box together. What it cannot see is what was said,
    /// and that is the property the whole design rests on.
    #[test]
    fn the_relay_exception_is_narrow_and_stated() {
        let relay = CLASSIFIED
            .iter()
            .find(|(name, _)| *name == "relay")
            .map(|(_, role)| role)
            .expect("the relay is classified");
        assert!(
            matches!(relay, Role::Relay),
            "the relay was reclassified. It is neither a helper nor an ordinary crate: it is the \
             acknowledged exception that sees an address and a drop-box, and reclassifying it \
             hides the one trade this design actually makes.\n\n{REVERSAL_CONDITIONS}"
        );
    }
}
