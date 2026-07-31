# Metadata minimisation: how far it can go, and where it stops

## The question, restated so it can be answered

"Can we get rid of metadata entirely?" — no, and the reason matters more than the answer.

Delivery requires that bytes physically arrive somewhere and that somebody later collects them.
Those are two observable events, and no cryptography makes an event unobservable to the machine it
happens on. So the honest goal is not zero metadata. It is this:

> **No single observer should see both halves of an edge.**

An "edge" is one conversation link: *this party deposited* and *that party collected*. Everything
below is measured against that sentence, because it is achievable, whereas "no metadata" is not.

The second reason to state it this way: it exposes the arrangements that *look* like progress and
are not. Encrypting a field that a relay can re-derive from timing changes nothing. Splitting a
request across two nodes run by one operator changes nothing. The test is always "who can now join
the two halves", not "how many fields are ciphertext".

## Where we are (verified against the code, 2026-07-31)

Already removed, and each with a test that reddens if it comes back:

| Was visible | Removed by |
|---|---|
| Message content | E2E (PQXDH + double ratchet) — never negotiable |
| Sender identity on a delivered message | Sealed opener (PRIV-3); the whole envelope is scanned for the IK, not one field |
| Recipient identity in the address | Rotating, blinded per-session drop-boxes (PRIV-2/12) |
| Message size and type | Fixed-size padded envelope, one class (PRIV-1) — control messages pad to chat size, so a profile view is not distinguishable from a message |
| Byte-equality of one message across two relays | Per-relay veil (PRIV-4) — deterministic nonce so relay-side dedup still works |
| Drop-box address being the same at every relay | Relay-derived box address (PRIV-12) |
| Queue depth in a fetch response | Fixed-size fetch page (`FETCH_PAGE_LEN`) |
| Retention posture requiring a connection to learn | Signed descriptor carries policy (NODE-1) |

What the relay still learns, stated exactly as the audit states it: **your IP, your sizes and
timing, who you are whenever you poll for openers, and — if it keeps logs — which rotating boxes
belong to one conversation over time.**

## The five remaining axes, strongest move first

### 1. One relay sees both halves of the edge — the largest one left

Today a deposit and the matching fetch go to the **same relay**. Everything above hides *who* the
parties are; none of it stops one operator from observing that box `B` received a deposit at
`t₀` and was drained at `t₁`. That is the edge, pseudonymously, for free, with no analysis.

**The move:** deposit at `R1`, collect from `R2`. The sender wraps an inner envelope addressed to a
box at `R2` inside an outer one addressed to `R1`; `R1` forwards without learning the inner box.
`R1` then knows "somebody deposited something", `R2` knows "somebody drained box B", and neither
knows the pair.

This is exactly the README's Principle 5 ("no single intermediary learns both source and
destination"), which today is a stated GOAL and not a description of the build. Naming it as the
top of this list is the same statement, made actionable.

**What it costs, honestly:**
- Latency, and an availability dependency: if `R1` silently drops the forward, mail vanishes with
  no signal. Needs the same receipt discipline the ACK path already has.
- It is worthless if `R1` and `R2` share an operator, a host, or a network vantage point. So it
  needs relay *diversity* to be real, which is a reputation/selection problem, not a crypto one.
- It multiplies exposure if done naively across `n` relays (STATUS already records this about
  replication: availability × n also means metadata × n). Two, chosen for independence, not `n`.

### 2. The identity mailbox is the last stable address

"Who you are whenever you poll for openers." A stranger's first contact needs one address that
does not rotate, so one stable box remains — and polling it is a self-identifying act.

Already softened: the proxy-identity model means that address belongs to a **disposable proxy**,
never to a root identity, and the root has no address at all.

**The move (#261):** one-time rendezvous boxes for first contact, with the stable box demoted to an
emergency channel that a normal client rarely touches. The stable address stops being the *default*
place you are found, which is what makes polling it a signal.

**Cost — and the shape of it was already settled, which this document got wrong on first writing.**
The obvious objection is "a rendezvous box has to be published somewhere a stranger can find it,
which reintroduces a stable identifier one layer down". #261 does not publish them at all: a set of
single-use addresses is handed over *during contact exchange*, and further sets are delivered inside
the established E2E session. So the stable address is needed only by someone who has never had your
contact code — which is exactly the emergency channel it is being demoted to.

What remains genuinely open is narrower: what a client does when a set is exhausted and the session
is cold, and whether set exhaustion is itself observable (a peer that suddenly falls back to the
stable box has told the relay something).

### 3. Timing is now the loudest signal we still emit

With sizes normalised, timing carries what size used to. Three parts, only one of which exists:

- **Cover traffic — BUILT, and off by default.** `cover_tick` deposits real, self-addressed,
  correctly-sized traffic on a Poisson schedule. The knob exists in Settings.
- **Send on a schedule, not on keypress (#260)** — not built. Until then, a deposit happens when a
  human presses a key, and that is a keystroke-accurate timestamp of "this person is writing now".
- **Bundling (#281)** — not built. Several messages in one envelope, so the *count* of exchanges
  stops tracking the count of messages.

**The move:** make the three one mechanism rather than three switches. Real messages should leave
in the same shaped stream as cover, in bundles, on a schedule — so that "a message was sent" and
"nothing was sent" produce identical observations. Cover traffic that only runs when idle is
decoration; cover traffic indistinguishable from real sending is the property.

**Cost, and it is the honest reason this is not on by default:** constant bandwidth and battery,
plus latency. It is a real trade, not a free win, and per-profile (Normal / Private / Anonymous) is
the right shape.

### 4. A blob is a distinct size class — we told the observer "large file"

`MAX_BLOB_FRAME = 65_000` versus the ordinary `FETCH_PAGE_LEN = 16_000`. `wire.rs` already says it
plainly: "a blob transfer is a distinct size class on the wire, so it leaks *large file* to an
observer where the padded small-message path does not."

**Two ways out, and they differ in who pays:**
- Send blob chunks in the *ordinary* class: no new class, ~4× more requests per byte.
- Put everything in one large class: no new class, wasteful for short messages — unless bundling
  (#281) fills the space, which is why these two tasks belong together.

Either way the rule to keep is structural: **one class on the wire, enforced by a test that
enumerates the classes** — the guard shape already used for carriers and domains, so a future
fifth class cannot appear quietly.

### 5. "Which box are you reading" — PIR is walled, but k-anonymity is not

#272 (PIR/OMR) is blocked externally: no usable library, and the composition is not something to
hand-roll. That has been read as "nothing can be done here". It should not be.

**The cheaper move that needs no new crypto:** fetch a *set* of boxes per request, of which only
one is yours, the rest being other users' or plausible non-existent addresses. The relay learns
"one of these k", not "this one". Cost is bandwidth × k, and it degrades gracefully — k = 4 is not
PIR but it is not 1 either.

**A distinction that must not be blurred, because the same action means opposite things:**
- Batching *your own* boxes into one request (#280) is a **speed** optimisation and it **links**
  your boxes to each other. Permitted only on the direct carrier, where the transport already
  linked them, and structurally forbidden under a proxy.
- Batching your box among *other people's* is a **privacy** measure and links nothing.

They are both "batch several boxes" and they are opposites. Any implementation must make it
impossible to reach the first while believing you built the second.

## What stays, no matter what

Written down so nobody has to rediscover it, and so no claim is made that outruns it:

1. **That you use KARST at all.** The relay terminates your connection; the network sees traffic to
   it. Only an external carrier (Tor / I2P / mixnet — built, with a structural no-downgrade rule)
   moves this, and that is someone else's anonymity, not ours.
2. **An observer who sees both ends.** Every overlay states this ceiling; so do we.
3. **That a box exists and receives deposits.** A relay storing mail for you knows it is storing
   mail. PIR would reduce *which* box you read, never *that* boxes are read.
4. **Your peer knows what you told them.** Nothing here is about the person you are talking to.

## Order of work, and why this order

1. **#281 bundling (format first)** — gates #260, #275 and axis 4. Nothing about timing can be
   settled while the count of envelopes still tracks the count of messages.
2. **#260 schedule + cover as one mechanism** — the largest single reduction available without new
   infrastructure, because it closes the axis that is loudest *today*.
3. **Axis 4 (one size class)** — cheap once bundling exists; near-free guard test.
4. **Axis 5 (k-anonymity fetch)** — no new crypto, and it unblocks the *idea* behind #272 without
   waiting for PIR to become available.
5. **Axis 1 (two-relay edge split)** — the biggest win and the biggest build. Needs relay
   diversity and forward receipts to be honest, so it goes after the cheap wins, not before.
6. **#261 rendezvous boxes** — depends on answering "where is the rendezvous address published".

Axis 1 is deliberately not first. It is the strongest move, and it is the one most likely to be
built into a shape that *looks* like it splits the edge while both relays sit in one datacentre.
The cheap axes should land while that design is argued about.
