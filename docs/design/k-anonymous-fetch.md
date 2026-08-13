# One of k boxes: what it costs, and which version is actually free

Status: analysis. The task this comes from says a k-anonymous fetch is available now and
needs no new crypto. Half of that is true, and the half that is not changes what should be
built.

## Why the obvious version is not free

A fetch today carries an ownership proof — a DH proof for an identity mailbox, a Schnorr
proof for a blinded drop-box. It is what stops a stranger draining someone else's mail.

"Fetch k boxes, only one of them yours" cannot produce proofs for the other k-1, because
producing one is exactly what owning a box means. So the version that hides you among other
people's boxes requires the relay to serve reads **without** a proof — grouping boxes into
buckets and returning a whole bucket to anyone who asks for it.

That is not a free metadata improvement. It trades:

- **an access-control property for a metadata one.** Anyone could harvest anyone's
  ciphertext, at any rate, for later. The bytes stay sealed, so this is not a confidentiality
  break — but "sealed today" is a claim about today's primitives, and a harvested archive
  outlives them;
- **the delivery accounting.** Leases and deletes are per-fetcher. A bucket read hands you
  other people's messages, which you must not lease and must not delete, so the at-most-once
  work either stops applying to bucket reads or has to be rebuilt around them;
- **k times the download**, paid by every reader on every poll.

None of that makes it wrong. It makes it a design with a cost, not a switch that was sitting
there unflipped. Written down because the task's framing invited flipping it.

## The version that really is free

There is a k-anonymity that costs nothing and needs no protocol change: fetch several boxes
**you own**.

With one-time rendezvous boxes, a client holds a box per correspondent rather than one
mailbox for everything. Fetching several of them in one request, always the same number,
hides **which correspondent you are checking** — and the relay already lets you prove every
one of them, because they are yours.

What it hides:

- which of your correspondents has mail waiting, and therefore who is talking to you right
  now;
- the difference between "checking one busy conversation" and "checking everything".

What it does not hide:

- that the boxes belong to one person. The relay sees k proofs from one connection and
  learns they are the same holder's. This is anonymity among your own boxes, not among
  other people's.

That is a narrower property than the task assumed, and it is the one available without
paying in access control.

## The rule that makes even the free version work

**The number of boxes fetched must be constant**, not "however many I have". A client with
three correspondents fetching three boxes and one with thirty fetching thirty has published
its correspondent count — which is most of the social graph the boxes exist to hide.

So: a fixed k, padded with boxes that are yours and empty, exactly like padding a bundle
with envelopes that carry nothing. And when a client exceeds k correspondents, it fetches in
several rounds of k rather than one round of many.

## Sequencing

This depends on one-time rendezvous boxes existing, because without them a client has one
mailbox and there is nothing to be anonymous among. The dependency runs that way and not the
other, so the rendezvous slice comes first.
