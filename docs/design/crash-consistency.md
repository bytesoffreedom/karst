# Crash consistency across the vault's files

**Status: an inventory and a set of rules, not a transaction manager.**

The vault writes ~51 files. Each one is atomic on its own — temp file, fsync,
rename — but there is **no transaction across files**. A crash between two writes
can leave two files that disagree.

This document is the enumeration that has been missing: which files must agree,
what a crash between them actually costs, and which rule keeps that cost
recoverable. It exists because the alternative — reaching for a transactional
store — means a new dependency and a rewrite of a 4600-line module, when most of
the 51 files are genuinely independent and the ones that are not are few enough
to name.

---

## The rule that governs the whole list

> **Order writes so that a crash leaves a state that is either self-evidently
> incomplete or safely retryable — never one that is silently wrong.**

Concretely, in decreasing order of preference:

1. **Fold the group into ONE file.** A single atomic write cannot be half-done.
   This is what CRYPTO-26 did: the one-time prekey secrets moved *inside*
   `sessions.dat`, because a session and the prekey it consumed have to commit
   together or the prekey is either burned twice or lost.
2. **Write the recoverable side first.** If the crash window leaves work to redo,
   redo is cheap; if it leaves work silently skipped, it is not.
3. **Sweep the residue at unlock.** When ordering is dictated by something more
   important than tidiness (see the burn case below), collect the leftovers at
   the one moment the authoritative file is known good.

---

## The groups

### 1. Session state + anti-rollback anchor — `sessions.dat` + `sessions.anchor`

**Already correct, by design.** The anchor exists precisely so that a mismatch
is *detected* rather than tolerated (CRYPTO-01). A crash between them is not a
consistency bug; it is the condition the anchor was built to catch.

### 2. Session state + one-time prekeys — `sessions.dat`

**Already folded (CRYPTO-26).** They used to be `sessions.dat` + `opks.dat`, and
a crash between them either burned a prekey with no session to show for it or
kept a session whose prekey had been handed out again. One file, one write.

### 3. Ratchet state + delivered content — `sessions.dat` + `quarantine.dat`

**Already correct (SEC-40 / A6-6).** Content that cannot be applied yet is parked
durably *before* the ACK, so the crash window cannot delete relay-side mail that
the client has not committed. The ordering is load-bearing and tested.

### 4. Received message + its metadata — `history.dat` + `meta.dat`

Reactions, edits and replies key off `msg_id`. A crash after the history write
leaves a message with no metadata (harmless: the metadata is additive and
re-arrives), and a crash after the metadata write leaves metadata for a message
that is not there (also harmless: it is keyed, so it is simply never read).
**Write history first**, so the dangling side is the additive one.

### 5. A contact and where to reach them — `contacts.dat` + `contact_proxy.dat`
+ `contact_relays.dat` + `peer_profiles.dat`

The dangerous direction is the tag: a contact whose `contact_proxy` entry is
missing falls back to the DEFAULT channel, which means talking to them from the
wrong identity — silently wrong, which is exactly the class this rule exists to
avoid. **Write the tag before the contact.** A tag with no contact is inert
(nothing looks it up); a contact with no tag is a misrouted conversation.

### 6. A post and its media — `feed.dat` + `feed_attachments.dat` + `feed_images.dat`

Attachments are looked up by post id. **Write the attachments first**: a stored
attachment nobody references is swept, while a post referencing a missing
attachment renders as a broken item the user cannot repair.

### 7. A download and its bytes — `downloads.dat` + `partials.dat` + `index.dat`

**Already handled**: `sweep_orphan_files` at unlock removes partials no record
points at, and the record is written before the ACK (A8-10 / A5-2). State is
proportional to arrived chunks, so a crash costs at most the chunks in flight.

### 8. A burned channel — `proxies.dat` + `capabilities.dat` + `sessions.p<n>.dat`
+ `discovery.key.p<n>` + `contact_proxy.dat`

**The one case where the preferred ordering is deliberately NOT used.**

`burn_proxy` destroys the registry entry — the proxy's only secret — *first*, and
only then removes its namespaced files, its admission credentials and the contact
tags pointing at it. That is the wrong order for tidiness and the right order for
the threat: burning is the action taken under duress, and what matters is that
the identity becomes unrecoverable as early as possible. Reordering would trade a
security property for a housekeeping one.

So the residue is real: a crash mid-burn leaves the identity correctly gone and
`sessions.p7.dat`, a live admission credential and a stale tag behind. Rule 3
applies — `Store::sweep_orphaned_proxy_state` collects them at unlock, where the
registry is known good. Pinned by a test that simulates the crash exactly
(registry entry removed, nothing else touched).

### 9. Vault accounts and slots — `accounts.dat` + `slots.dat` + `slotmap.dat`

Slot creation is the multipassword/duress surface, and the invariants there
(A3-1: a second hidden account must not destroy the first; A3-6: a failed save
must not delete the only copy) are enforced within the operations rather than by
ordering. **Not re-litigated here** — see `docs/design/duress-multipassword.md`.

### 10. Everything else

`prefs.dat`, `net.dat`, `relay_prefs.dat`, `blocked.dat`, `invites.dat`,
`dedup.dat`, `pulled.dat`, `subscribers.dat`, `channel.dat`, … are independent:
losing the last write of any one of them loses that one setting or one row, and
nothing else reads it expecting a matching row elsewhere. A crash costs the write
that was in flight, which is the same cost a single-file store would have.

---

## What this does NOT give

It is not atomicity. Groups 4, 5 and 6 are ordering rules, which means the crash
window still exists — it is merely pointed at the harmless side. Making those
truly atomic means folding each group into one file, the way group 2 was folded;
that is the natural next step and each group is its own contained change.

It also does not cover the relay's own storage: `mailstore` (its durable mail
log) and `blobstore` have their own crash-consistency stories, and the relay is
a separate crate with a separate trust posture.
