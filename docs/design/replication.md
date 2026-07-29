# Multi-homing is failover, not durability — and what it would cost to change that

**Status: a DECISION about scope, plus the design that would follow if it is
reversed.** Nothing here is implemented. The point is that the current property
is stated honestly and the alternative is costed, rather than the gap being
discovered by someone losing a message.

---

## What multi-homing actually gives today

A send completes when **one** relay accepts the ciphertext. The path list exists
so a dead, blocked or slow relay does not strand a message — the next one carries
it. That is route failover, and it works.

What it does not give is **independent copies**. After a successful send there is
exactly one relay holding that ciphertext. If that relay loses it, the message is
gone:

- On a `Volatile` relay (the default) the mail lives in memory, so a restart
  loses it — with no resend signal to the sender (R2-5 made this a per-relay,
  advertised property rather than a silent one).
- On a `Durable` relay it survives a restart, but `MAILBOX_TTL_SECS` (7 days)
  still sweeps it, and an operator's disk cleanup is not bound by anything KARST
  can check.
- A blob has its own TTL and its own store. A large attachment is *more* exposed
  than a message, not less.

The receiver's side is fine: mail is fetched from every relay and deduplicated,
so wherever a message landed it arrives once. The gap is entirely on the
**storage** side — one copy, at one operator, for a bounded time.

---

## The decision

> **KARST does not promise durability, and will not pretend to. Multi-homing is
> failover. The honest posture is to SAY that, and to make the sender's own
> retry the safety net, rather than to build a replication layer.**

Two reasons, and the second is the load-bearing one.

**It is not where the losses come from.** The message path already has a durable
sender-side queue: an unacknowledged send stays in the outbox and is retransmitted
verbatim across every relay on the poll cadence (R2-6/7 made stranded sends
recorded rather than silently dropped). A relay that loses mail before delivery
therefore mostly resolves as a resend, not as a loss. The window that actually
loses data is narrow: the sender has to be gone for good *and* the single relay
has to lose the ciphertext *and* the recipient has to not have fetched it.

**Replication buys durability by spending unlinkability.** This is the part that
decides it. Depositing the same object at k relays means k relays each hold a
ciphertext for the same recipient in the same window — a correlation that does
not exist today, and one that survives every rotation the design does elsewhere
(the drop-box addresses differ per relay, but the timing and the size do not).
The whole architecture spends effort making one deposit unlinkable from another;
paying for durability with a k-fold increase in correlatable events is a bad
trade for a messenger whose threat model is metadata.

So: not a replication layer. Instead —

**What is done instead, and is honest:** the relay's retention posture is a
property a client can read (`RelayPolicy::mailbox_durability`) and use to CHOOSE
a relay, which is where the decision belongs. A user who needs their mail to
survive a relay restart picks a relay that advertises `Durable`. That is a claim,
not a proof — an operator can lie — and the document that says so is the same one
that says a relay is untrusted anyway.

---

## If this is ever reversed, this is the shape

Recorded so the decision can be revisited with the design already thought
through, rather than re-derived under pressure.

1. **k-of-n deposit with a receipt per relay.** A send is not complete until k
   relays have each returned a durable receipt. The receipt has to name the
   deposit (R2-6's idempotent deposit id), so a retry is recognisable rather than
   a second copy.
2. **Durable retry until the replication factor is met**, driven by the same
   outbox that already retransmits. A send at k=1 of 3 is a send that is *not
   yet finished*, and the UI has to say so — a message shown as sent that is one
   disk failure from gone is the same class of lie as an ACK before a commit
   (SEC-34).
3. **Erasure coding for large attachments**, not replication: a 2 GiB file
   replicated three times is 6 GiB of upload on a link that already struggles
   with one. Reed-Solomon over the chunk set gives the same survivability for a
   fraction of the bytes, and the chunking is already content-addressed and
   resumable (CRYPTO-31, A4-1).
4. **Separate retention for mailbox and media.** They fail differently: mail is
   small and short-lived, a blob is large and its TTL is the thing that expires
   first. One knob for both would be set for the wrong one.
5. **A repair process.** Replicas are only durable if a missing one is noticed
   and replaced; without repair, k-of-n decays to 1-of-n at the rate relays
   churn. This is the part such designs usually omit and then need most.
6. **And the metadata cost stated in the UI**, not just in a design file: turning
   on replication tells k operators that someone deposited for this recipient at
   this moment. If that is not said where the switch is, the switch is a trap.

---

## What this does not touch

- **Receiving** across several relays stays as it is: fetch everywhere,
  deduplicate. That is failover on the read side and costs nothing extra.
- **Publishing a bundle** to several relays is unrelated — that is presence, so a
  contact can reach you at whichever relay they can reach. It is already
  multi-relay and should stay so.
- **The blob store's own crash-consistency** (chunks proportional to arrivals,
  resumable uploads) is a separate, solved problem.
