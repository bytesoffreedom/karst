//! **The client's unrequested output must not name who you talk to** (PRIV-9, client half).
//!
//! The relay records nothing — `relay::log_hygiene` keeps it that way, and a blanket "no output"
//! rule is possible there because a relay has nobody to talk to. The client is the opposite case: it
//! prints on purpose, because a person is watching and route problems, unreadable state and refused
//! migrations all need saying out loud.
//!
//! So the rule cannot be "print nothing". The line this draws is **who asked**:
//!
//! - **Answers to a command the person just typed** are the product. `karst id` prints your identity
//!   key because printing it is the entire command; `karst init` prints the recovery phrase because
//!   an account you cannot write down is not an account. Suppressing those would not protect anyone,
//!   it would just break the tool. Same exemption, same reasoning, as the relay's operator banner.
//!
//! - **Diagnostics nobody asked for** are the leak. Nothing requested them, so their content is
//!   whatever the author found handy while debugging, and they land wherever the process's stderr
//!   goes: a journal, a crash report, terminal scrollback, a support bundle a user pastes to a
//!   stranger. This scan found exactly one — a failed channel migration printed the peer's identity
//!   key in hex — and it bought nothing even when it worked, because whoever read the warning
//!   already knew which contact they had been migrating.
//!
//! The stakes are higher than that single line suggests. This build has hidden accounts and a duress
//! mode; a diagnostic naming a contact, a box or a vault path undoes both for anyone who reads the
//! file, without touching any cryptography.
//!
//! **What this does NOT cover**, stated because a guard trusted past its reach is worse than none:
//!
//! - **A laundered value.** `let x = hex::encode(ik); eprintln!("{x}")` passes. This is a spelling
//!   check, like `domain_separation`, aimed at the way it actually goes wrong: interpolating the
//!   identifier already in scope.
//! - **Panic messages**, which is the one gap the module's own argument points at — a crash report
//!   IS a panic message, and `.expect(&format!("no session for {hex_ik}"))` sails past. Not covered
//!   because the same rule applied to `panic!`/`assert!` would have to exclude `#[cfg(test)]`
//!   modules, where forbidden names appear legitimately by the dozen. Checked by hand at the time of
//!   writing: no panic outside a test module interpolates any identifier on this list.

use std::path::{Path, PathBuf};

/// Sources whose output is unrequested — the diagnostic surface.
///
/// `client/src/bin/` is excluded by [`is_exempt`]; the GUI is not, because nobody asks a desktop app
/// for stderr.
const CRATES: &[&str] = &["client", "client-core", "desktop", "transport"];

/// Identifiers that must never reach unrequested output.
///
/// Names, not values, because that is what a scan can see. `hex::encode(` earns its place by being
/// how a raw key becomes printable at all: inside a print, it is the tell.
const FORBIDDEN: &[&str] = &[
    "hex_ik",
    "peer_ik",
    "identity_public",
    "drop_seed",
    "mailbox",
    "fetch_secret",
    "entropy",
    "mnemonic",
    "hex::encode(",
    // A filesystem path. This one is about the hidden account rather than about a contact: the
    // whole property of a hidden vault is that nothing evidences its existence, and a warning
    // naming its directory evidences it to anyone reading the log. Found one — a failed cleanup
    // printed the full path of a burned proxy's file.
    "display()",
];

/// Facilities with no legitimate use in shipped client code at all, banned outright — no format
/// analysis, no CLI exemption.
///
/// `dbg!` is the canonical 2am artifact and is worse than a stray `eprintln!`, because it prints the
/// expression's SOURCE TEXT beside the value: `dbg!(hex_ik)` labels the leak for the reader. `log::`
/// and `tracing::` are here because a logging framework arriving quietly would route this crate's
/// output somewhere durable — a file, a subscriber, an aggregator — which is the property this whole
/// guard exists to prevent. None of the three appears anywhere in these crates today, so the ban
/// costs nothing now and is precisely the moment to state it.
const NEVER: &[&str] = &[concat!("dbg", "!"), concat!("log", "::"), concat!("tracing", "::")];

/// The CLI is a person typing a command and reading the answer. Every print in it is that answer.
fn is_exempt(path: &str) -> bool {
    path.contains("/bin/")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// One print macro call, split the way the rule needs it.
struct Call {
    line: usize,
    /// The format string's contents — prose. Only `{…}` placeholders in here name values.
    literal: String,
    /// Everything after the format string: the arguments, which are all values.
    args: String,
}

/// Every print macro in `src`, with its format string separated from its arguments.
///
/// A scan, not a parse. It is string-aware only as far as it must be — enough that the word "phrase"
/// in a help message is not mistaken for a printed phrase, which was the first thing this got wrong.
fn print_calls(src: &str) -> Vec<Call> {
    let mut out = Vec::new();
    // Anchored on the shared stem, because the names nest: `println!(` is a substring of
    // `eprintln!(`, and `print!(` of both. Searching for each name in turn counts one `eprintln!`
    // up to four times — which silently quadrupled the floor test below, making a guard that
    // claimed to want 20 diagnostics content with five.
    let mut from = 0;
    while let Some(rel) = src[from..].find("print") {
        let stem = from + rel;
        from = stem + 5;
        let head = &src[..stem];
        let prefixed = head.ends_with('e');
        let start = if prefixed { stem - 1 } else { stem };
        // Not part of a longer identifier (`sprint`, `fooprint`, `.print`).
        if src[..start].ends_with(|c: char| c.is_alphanumeric() || c == '_' || c == '.') {
            continue;
        }
        let tail = &src[stem + 5..];
        let tail = tail.strip_prefix("ln").unwrap_or(tail);
        let Some(rest) = tail.strip_prefix("!(") else { continue };
        {
            let open = src.len() - rest.len();
            let line = src[..open].matches('\n').count() + 1;
            // The format string, if this call opens with one.
            let (literal, after) = match rest.find('"') {
                Some(q) if rest[..q].trim().is_empty() => {
                    let body = &rest[q + 1..];
                    let mut end = None;
                    let mut esc = false;
                    for (i, c) in body.char_indices() {
                        if esc {
                            esc = false;
                        } else if c == '\\' {
                            esc = true;
                        } else if c == '"' {
                            end = Some(i);
                            break;
                        }
                    }
                    match end {
                        Some(e) => (body[..e].to_string(), &body[e + 1..]),
                        None => (String::new(), rest),
                    }
                }
                _ => (String::new(), rest),
            };
            // The argument list runs to the macro's closing paren. Depth from 1 (we are past the
            // opening paren already); string contents inside the args are not tracked, which can
            // end the call early — under-reading the arguments, never over-reading past them.
            let mut depth = 1usize;
            let mut args_end = after.len();
            for (i, c) in after.char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            args_end = i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            out.push(Call { line, literal, args: after[..args_end].to_string() });
        }
    }
    out
}

/// The identifiers a format string interpolates inline: the `x` of `{x}` or `{x:?}`.
fn inline_names(literal: &str) -> Vec<String> {
    let mut names = Vec::new();
    let b: Vec<char> = literal.chars().collect();
    let mut i = 0;
    while i < b.len() {
        if b[i] == '{' {
            if b.get(i + 1) == Some(&'{') {
                i += 2;
                continue;
            }
            let mut j = i + 1;
            let mut name = String::new();
            while j < b.len() && b[j] != '}' && b[j] != ':' {
                name.push(b[j]);
                j += 1;
            }
            if !name.is_empty() {
                names.push(name);
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    names
}

fn offences() -> Vec<String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().expect("impl/").to_path_buf();
    let mut hits = Vec::new();
    for c in CRATES {
        let mut files = Vec::new();
        rust_files(&root.join(c).join("src"), &mut files);
        for f in files {
            let name = f.strip_prefix(&root).unwrap_or(&f).display().to_string();
            let Ok(src) = std::fs::read_to_string(&f) else { continue };
            // Outright bans apply everywhere, the CLI included: nothing about a person typing a
            // command makes `dbg!` appropriate.
            for n in NEVER {
                if src.contains(n) {
                    hits.push(format!("  {name}  uses `{n}`, which is banned outright"));
                }
            }
            if is_exempt(&name) {
                continue;
            }
            for call in print_calls(&src) {
                let names = inline_names(&call.literal);
                for bad in FORBIDDEN {
                    let ident = bad.trim_end_matches('(');
                    if names.iter().any(|n| n.contains(ident)) || call.args.contains(bad) {
                        hits.push(format!("  {name}:{}  prints `{bad}`", call.line));
                    }
                }
            }
        }
    }
    hits
}

/// **No unrequested output names a person, a box, or a secret.**
///
/// DISCRIMINATING: put a contact's identity key back into any diagnostic and this reddens with the
/// file, the line and the identifier. That is the only signal such a change gives — it compiles, the
/// message is more helpful than before, and a reviewer sees a better error message.
#[test]
fn no_unrequested_client_output_can_identify_a_contact() {
    let hits = offences();
    assert!(
        hits.is_empty(),
        "unrequested client output would identify a contact or reveal secret material:\n{}\n\n\
         Nobody asked for these lines, and they land wherever this process's stderr goes: a journal, \
         a crash report, terminal scrollback, a support bundle pasted to a stranger. A contact's \
         identity key there is a device-to-contact link written down for free — and it buys nothing, \
         because whoever reads the message already knows which contact it was about. This build also \
         has hidden accounts and a duress mode: a diagnostic naming a contact, a box or a vault path \
         undoes both for anyone holding the file, with no cryptography involved.\n\n\
         Say WHAT failed, never WHO it was about. If a value is genuinely the answer to a command \
         the person just typed, it belongs in the CLI (`client/src/bin/`), which is exempt for that \
         reason.",
        hits.join("\n")
    );
}

/// The scan must still be seeing this code's output. One that matches nothing passes the test above
/// forever, and renaming or wrapping the print macros is exactly how that would happen quietly.
#[test]
fn the_scan_still_sees_the_clients_diagnostics() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().expect("impl/").to_path_buf();
    let mut total = 0usize;
    for c in CRATES {
        let mut files = Vec::new();
        rust_files(&root.join(c).join("src"), &mut files);
        for f in files {
            let name = f.strip_prefix(&root).unwrap_or(&f).display().to_string();
            if !is_exempt(&name) {
                if let Ok(src) = std::fs::read_to_string(&f) {
                    total += print_calls(&src).len();
                }
            }
        }
    }
    assert!(
        total >= 20,
        "only {total} diagnostics found across the client crates — the scan is no longer seeing this \
         code's output, so the guard above is checking nothing while reporting success"
    );
}

/// **The exemption's blast radius, measured rather than assumed.**
///
/// `is_exempt` matches `/bin/` anywhere under the four scanned crates, and today that is exactly one
/// file. An exemption whose reach nobody has counted is how a leaky diagnostic gets past this later —
/// a second binary, or a module moved under `bin/`, would inherit a licence granted to a CLI on the
/// grounds that a person typed a command and is reading the answer.
#[test]
fn the_exemption_covers_exactly_the_one_file_it_was_granted_for() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().expect("impl/").to_path_buf();
    let mut exempt = Vec::new();
    for c in CRATES {
        let mut files = Vec::new();
        rust_files(&root.join(c).join("src"), &mut files);
        for f in files {
            let name = f.strip_prefix(&root).unwrap_or(&f).display().to_string();
            if is_exempt(&name) {
                exempt.push(name);
            }
        }
    }
    exempt.sort();
    assert_eq!(
        exempt,
        vec!["client/src/bin/karst.rs".to_string()],
        "the set of files exempt from the diagnostic rule has changed. The exemption exists for one \
         reason — a CLI's output is the answer to a command someone just typed — and it does not \
         transfer to anything else by being placed in a `bin/` directory. If a new binary genuinely \
         needs it, add it here deliberately."
    );
}

/// **The exemption is for output a person asked for — so that output must still exist.**
///
/// Without this, the test above could be satisfied by deleting `karst id`'s answer, or by moving a
/// leaky diagnostic into `bin/` to get it past the filter. This pins that the CLI's commands still
/// print what they exist to print.
#[test]
fn the_cli_still_answers_the_commands_it_exists_for() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().expect("impl/").to_path_buf();
    let cli = std::fs::read_to_string(root.join("client/src/bin/karst.rs")).expect("the CLI");
    for (cmd, needle) in [
        ("karst id / account", "hex::encode("),
        ("karst show-phrase", "mnemonic_of_entropy"),
    ] {
        assert!(
            cli.contains(needle),
            "`{cmd}` no longer produces its answer. The CLI is exempt from the diagnostic rule \
             BECAUSE its output is what a person typed a command to see; an account whose recovery \
             phrase cannot be read, or an identity you cannot give a contact, protects nobody and \
             breaks the tool."
        );
    }
}
