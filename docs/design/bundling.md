# Bundled deposits: the envelope format

Status: **implemented end to end.** `client::send_session_bundle` seals a padded batch and
puts it on the wire; `Peer::flush_outbox_bundled` groups the outbox and offers each class as
one request; the relay admits it once and answers per slot; the receive path drops the
padding before any caller sees it.

Wiring it up changed two things in the format that were wrong on paper, both recorded below:
slots carry VEILED envelopes, and the request nonce carries a salt.

Gates the scheduled-send slice, the compression slice, and the wake-up slice — all three
need to know what a bundle is before they can be built on one.

## What a deposit costs today

One message is one `WireMessage`: one cookie stage, one capability proof, one admission
pass, one mailbox write. Send five messages to the same contact and the relay sees five
of everything, spaced by however long you took to type.

The envelope is already one fixed size class (PRIV-1), so the relay learns nothing from
any single message's length. What it still learns is **how many** you sent and **when**.
Five deposits thirty seconds apart is a conversation; one deposit is not.

## The format

A bundle is a deposit that carries several envelopes **to one recipient**.

    BundleRequest {
        client_addr, carrier_id, cookie,     // same admission preamble as a deposit
        request_nonce,                       // salt ‖ H(recipient, slots, salt)
        capability_proof,
        recipient: [u8; 32],                 // ONE recipient for the whole bundle
        slots: Vec<BundleSlot>,              // exactly SLOT_CLASS entries
    }

    BundleSlot { veil_nonce, veiled }        // a ratchet envelope, veiled for THIS relay

Every slot holds an ordinary ratchet envelope, already padded to the one fixed class, so a
bundle's size is exactly `slot_count × envelope`.

### Slots are veiled, and the first version of this format got it wrong

The slot type was `RatchetEnvelope` — the bare envelope — and **nothing would have failed.**
The recipient accepts veiled and unveiled envelopes alike, so bundled mail would have
decrypted perfectly. What it would have lost is PRIV-4: the veil re-randomises an envelope
per relay, and it is applied at deposit time, so an envelope that never becomes a slot's
veiled form is the same bytes at every relay it reaches. Send-side failover deposits the
same queued envelope at a second relay as a matter of course, so this was not an edge case —
it was most of what the veil exists for, silently switched off for exactly the messages a
bundle carries.

So a slot is a veiled envelope and nothing else. Two properties fall out of the type rather
than out of a rule someone has to remember:

- **An opener cannot be expressed.** The veil key is the session's `drop_seed`, which a
  first contact does not have; an `InitialSealed` envelope has no veiled form at all. That
  is the same exclusion the old slot type bought — an opener is a larger fixed class of its
  own, and a bundle mixing one in would have two possible sizes — arrived at through the
  property that matters. A first contact deposits alone, which costs nothing: a first
  contact is one message by definition.
- **The veil cannot be dropped by a later caller.** There is no way to put a bare envelope
  in a slot.

The veil is applied at flush time, per relay, never at queue time: a queued envelope
flushed through a secondary relay must be re-veiled for THAT relay, and freezing the
primary's veil into the outbox would hand two relays identical bytes again by another
route.

### The slot count is a class, not a number

`slots.len()` must be one of a short ladder and never an arbitrary count. A bundle of
exactly the messages you happened to have written IS the count of messages you happened to
have written; padding to a class is what makes five sends and eight sends look the same.

Above the top class a bundle splits into several bundles.

**The ladder itself is NOT measured.** `[1, 4, 16]` is a plausible first guess and nothing
more. A three-rung ladder makes a two-message burst cost four envelopes — a 2x amplification
on a common case — and #256 is the precedent for taking that seriously: there, four size
classes were considered and ONE was chosen, because the sizes did not fit the wire. The
rungs here must come from measuring real send bursts against the bandwidth they cost, not
from a round number. Until that measurement exists, treat the ladder as a placeholder and
do not build a bandwidth argument on it.

### What fills the unused slots — and why not a loop

The obvious filler is the existing cover loop, and it is the wrong one. A loop deposits to
**a box only the sender can compute**; that self-addressing is exactly what makes it a
drop detector. A "loop" addressed to your contact is not a loop at all — it is a message
their client receives, and the padding becomes their problem.

So the filler is a **padding envelope addressed to the recipient**, and it must be honest
about both halves of its cost:

- The recipient's client receives it and discards it after decryption. It therefore needs
  a plaintext marker inside the sealed envelope — never on the wire — and the receive path
  must drop it before anything user-facing, or a padded bundle shows up as blank messages
  in a chat.
- The relay stores it and the recipient fetches it. That is real storage and real fetch
  bandwidth spent to hide a count.

This works only because the envelope is one size class: a padding envelope and a real one
are the same bytes to the relay, which is the property PRIV-1 bought and the reason it was
worth buying. It does NOT give the sender a drop detector — that remains the self-addressed
loop's job, unchanged and separate.

### One recipient, and why not several

Bundling across recipients — one deposit carrying mail for five different contacts — is
the bigger performance win and it is **not** what this format does.

It would tell the relay that those five mailboxes received mail from one sender in one
breath. Today those deposits can ride separate circuits under per-handle path isolation,
and the relay has to work to link them. A cross-recipient bundle hands over the link for
free, in the request structure itself. That trades a timing correlation the adversary must
build for a set correlation we would be handing them, and the trade is not obviously good
in either direction — which is exactly the kind of thing that should not be decided as a
side effect of a performance change.

So: per-recipient bundles now; cross-recipient bundling stays a separate question with its
own threat argument, not a knob quietly added here.

## Rules the implementation must keep

**Quota is charged per slot, not per bundle.** Otherwise a bundle is a quota bypass:
sixteen messages for the price of one admission. The point of bundling is to spend fewer
round trips and reveal less shape — not to send more than the capability allows.

**The nonce binds the whole bundle — under a fresh salt.**
`request_nonce = salt ‖ H(recipient, slots, salt)`, with the salt drawn per attempt and the
relay verifying the tail rather than recomputing a nonce of its own. The binding stops a
capability proof minted for one bundle being replayed with slots swapped in or out — same
discipline as `blob_put_nonce`, and the cheap structural check runs before the capability
HMAC, so a proof minted elsewhere costs no crypto to reject.

The salt is the half that is easy to leave out, and leaving it out is a livelock. The
relay's replay filter keys on the request nonce. A nonce that were a pure function of the
bundle's contents would make every retransmit of that bundle byte-identical — and a
retransmit exists precisely because the response can be lost, with the bundle already
stored. Those entries would retry identically and be refused as replays, forever, on the
one path that exists to survive a lost response. The ordinary deposit path does not have
this problem because it draws a random nonce per attempt; the salt gives a bundle the same
freshness without giving up the binding. `an_identical_bundle_can_be_retransmitted_but_a_
verbatim_replay_cannot` states both halves against a real relay.

**Admission is bundle-level; storage outcome is per slot.** Cookie, capability and the
size gate apply to the bundle as a unit. What each slot did — stored, duplicate, mailbox
full — comes back per slot inside the Noise-encrypted response, where an on-path observer
cannot read it and the sender needs it to know what to retry.

**A partially stored bundle must not be silently reported as stored.** If slot 3 of 4
fails, the response says so; the sender re-bundles what failed rather than assuming
delivery. The failure that matters here is the quiet one, not the loud one.

**Padding slots are not free**, and the bill is longer than storage. A padding envelope
costs the sender's quota exactly like a real message, because to the relay it IS one — any
accounting that exempts it re-introduces the distinguisher the padding exists to remove. It
also costs:

- **a ratchet position.** Filler is sealed through the ratchet like anything else, so a
  two-message send padded to four consumes the recipient's skipped-key window (`MAX_SKIP`,
  `MAX_STORE`) four times as fast as two deposits would. At the top rung, sixteen.
- **an outbox slot**, against the same cap the all-or-nothing batch reservation checks. A
  batch is refused whole if its slots — padding included — do not fit.
- **a fetch, and often more than one.** Twenty slots do not fit one fixed-size fetch page,
  so a top-rung bundle is drained by the recipient over several polls. That is ordinary
  backlog behaviour, not a fault, but it means a bundle's latency is not one round trip.

**Padding is never recorded as a pending send.** It is sealed and queued exactly like a real
message — the relay must not be able to tell them apart — but it does not enter the loss
ledger, or an evicted/expired filler would surface as a "message lost" report for a message
the user never wrote.

**The receive path drops padding centrally.** There are exactly two places a decrypted batch
enters the client crate, and both strip it there rather than leaving a `Padding` arm to
every dispatch site. The desktop's decode loop and the CLI's both have catch-alls that would
have handed filler to the file reassembler.

## What this does not do

It does not hide **that** you deposited, or when. A bundle is still a request at a
moment in time; it hides how many messages that moment contained, not that the moment
happened. Hiding the moment is the scheduled-send slice's job, and bundling is its
prerequisite: a scheduler with nothing to batch just re-emits the same timing it was
supposed to smear.

It does not reduce what a relay learns about **who** you talk to. One bundle names one
recipient, exactly as one deposit does.

**It does not hide that a deposit WAS bundled.** A bundle and an ordinary deposit are
different requests on the wire, so while both shapes exist, "this one was bundled" is itself
a signal — and it correlates with the sender having several messages to send. The ladder
starts at 1, so a lone message could in principle go out as a one-slot bundle and erase the
difference; it deliberately does not, because a one-slot bundle would ADD a distinguisher
(a single message that chose to look bundled) rather than remove one. Erasing it properly
means making the bundle the only deposit shape there is — the same argument
`splitting-the-edge.md` reaches about forwarding: either everything takes the path, or the
choice leaks the choice. That is a later slice, and it is named here rather than left to be
discovered.
