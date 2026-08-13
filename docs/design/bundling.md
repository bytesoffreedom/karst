# Bundled deposits: the envelope format

Status: **partly implemented.** The wire type, the nonce binding, the slot-count class check,
the relay's admission with per-slot quota, and the serve-loop handling exist. What does not
exist yet: the client side that assembles a bundle and pads it to a class, and the padding
envelope itself.

So a relay will accept a correct bundle today and no client sends one. That is the honest
state — the half that had to be agreed before three other slices could proceed is the half
that is done.

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
        request_nonce,                       // = bundle_nonce(recipient, slots)
        capability_proof,
        recipient: [u8; 32],                 // ONE recipient for the whole bundle
        slots: Vec<RatchetEnvelope>,         // exactly SLOT_CLASS entries
    }

Every slot holds an ordinary **ratchet** envelope, already padded to the one fixed class,
so a bundle's size is exactly `slot_count × envelope`.

**Openers are not bundled.** `Payload` has two variants and `InitialSealed` is a larger
fixed class of its own (`pad.rs`): a bundle mixing an opener with ratchet envelopes would
have two possible sizes, and the size claim above would stop being true. A first contact
deposits alone — which costs nothing in practice, because a first contact is one message
by definition. The slot type says so rather than a comment asking implementers to
remember.

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

**The nonce binds the whole bundle.** `request_nonce = bundle_nonce(recipient, slots)`,
so a capability proof minted for one bundle cannot be replayed with slots swapped in or
out. Same discipline as `blob_put_nonce`: the cheap structural check runs before the
capability HMAC, so a proof minted elsewhere is rejected at zero crypto cost.

**Admission is bundle-level; storage outcome is per slot.** Cookie, capability and the
size gate apply to the bundle as a unit. What each slot did — stored, duplicate, mailbox
full — comes back per slot inside the Noise-encrypted response, where an on-path observer
cannot read it and the sender needs it to know what to retry.

**A partially stored bundle must not be silently reported as stored.** If slot 3 of 4
fails, the response says so; the sender re-bundles what failed rather than assuming
delivery. The failure that matters here is the quiet one, not the loud one.

**Padding slots are not free.** A padding envelope costs the sender's quota exactly like a
real message, because to the relay it IS one. Any accounting that exempts it re-introduces
the distinguisher the padding exists to remove — and it also costs the recipient a fetch,
which is the half of the bill that is easy to forget because someone else pays it.

## What this does not do

It does not hide **that** you deposited, or when. A bundle is still a request at a
moment in time; it hides how many messages that moment contained, not that the moment
happened. Hiding the moment is the scheduled-send slice's job, and bundling is its
prerequisite: a scheduler with nothing to batch just re-emits the same timing it was
supposed to smear.

It does not reduce what a relay learns about **who** you talk to. One bundle names one
recipient, exactly as one deposit does.
