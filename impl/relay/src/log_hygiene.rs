//! **The relay's request path writes nothing down** — enforced, not remembered (PRIV-9).
//!
//! An honest floor of this design is that a relay cannot hand over what it never recorded. Today
//! that holds in the strongest possible way: there is not one logging statement anywhere in this
//! crate's library code. Every print in `relay` lives in `bin/relay.rs` and belongs to the operator
//! — a startup banner, the configuration in effect, the address and relay-id a client needs.
//!
//! **Why a guard for something that is already true.** This property has no test that fails when it
//! breaks, because breaking it does not break anything. A line like
//!
//! ```text
//! eprintln!("fetch from {} for {}", client_addr, hex::encode(mailbox));
//! ```
//!
//! is what someone writes while chasing a delivery bug at 2am, it works, it ships, and from then on
//! the relay's disk holds exactly the join a seizure or a subpoena wants: source address beside
//! drop-box address. Nothing goes red. The reviewer sees a debug line.
//!
//! So the check is mechanical and it is about the ABSENCE of a thing, which is the only kind of
//! property a source scan is genuinely good at.
//!
//! **What this does NOT claim.** It says nothing about what an operator's own infrastructure records
//! — a reverse proxy's access log, the kernel's conntrack, a hosting provider's netflow. Those are
//! outside this binary and outside our reach, and the client cannot verify any of it; a relay's
//! stated policy is a CLAIM, not a proof (see `RelayPolicy`). This guard covers precisely one thing:
//! that OUR code does not add to the pile.

#[cfg(test)]
mod tests {
    /// Library sources of this crate — the request path. `bin/relay.rs` is deliberately absent: its
    /// output is operator-facing configuration, printed before any client exists.
    const LIBRARY: &[(&str, &str)] = &[
        ("server.rs", include_str!("server.rs")),
        ("node.rs", include_str!("node.rs")),
        ("mailstore.rs", include_str!("mailstore.rs")),
        ("gossip.rs", include_str!("gossip.rs")),
        ("quic_server.rs", include_str!("quic_server.rs")),
    ];

    /// **Nothing on the request path writes anything anywhere.**
    ///
    /// DISCRIMINATING: add any print or log call to a library module and this goes red with the
    /// reason, rather than the change passing review as a harmless debug line.
    #[test]
    fn the_request_path_records_nothing() {
        // Assembled from fragments so this file is not itself a match.
        let needles = [
            concat!("eprint", "ln!"),
            concat!("print", "ln!"),
            concat!("eprint", "!"),
            concat!("dbg", "!"),
            concat!("log", "::"),
            concat!("tracing", "::"),
        ];
        for (name, src) in LIBRARY {
            for n in needles {
                assert!(
                    !src.contains(n),
                    "`{n}` appeared in relay/src/{name}. The relay's request path deliberately \
                     records NOTHING: no client address, no mailbox or drop-box address, no blob \
                     id, no timing. That is not tidiness — it is the only part of \"a seized relay \
                     reveals little\" that we can actually deliver, because a relay cannot hand \
                     over what it never wrote down.\n\n\
                     A debug line here is how that stops being true. It will look harmless, it will \
                     work, and afterwards the disk holds the exact join an adversary wants: source \
                     address beside drop-box address.\n\n\
                     If you need output while debugging, keep it out of the commit. If a relay \
                     genuinely needs operational visibility, that is a DESIGN change — aggregate \
                     counters with no per-request identifiers, declared in `RelayPolicy` so a \
                     client learns the posture before it connects — not a print statement."
                );
            }
        }
    }

    /// The operator-facing banner is allowed to exist, and this asserts it DOES — so the test above
    /// cannot be satisfied by deleting all output everywhere and calling it hygiene.
    #[test]
    fn the_operator_banner_still_exists_in_the_binary() {
        let bin = include_str!("bin/relay.rs");
        assert!(
            bin.contains(concat!("eprint", "ln!")),
            "the startup banner is gone. An operator has to be able to see the address, the \
             relay-id and the configuration in effect; hiding those would not improve anyone's \
             privacy, it would just make the relay unusable."
        );
    }
}
