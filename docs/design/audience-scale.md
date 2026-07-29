# How large an audience KARST serves, and why that is a number and not an accident

**Status: a DECISION, recorded. It closes a question, it does not fix a defect.**

Publication in KARST is per-recipient. A post is encrypted separately for every
subscriber, over that subscriber's own ratchet, and an attached image is uploaded
once per recipient as its own blob under its own key. Cost — bandwidth, storage,
CPU, relay quota — grows **linearly with the audience**.

That is deliberate. It is what stops the relay reading an object's audience off
its own disk: there is no shared ciphertext for N recipients to fetch, so there
is no set for the relay to observe. What it is not, is free.

The awkward part, and the reason this document exists: `MAX_SUBSCRIBERS` is
**50 000**. The store has been quietly permitting a scale the crypto model
charges linearly for. Keeping both "mass reach" and "the relay cannot see who
your audience is" is the thing that cannot be had, and until now nobody had said
which one KARST gives up.

---

## The decision

> **KARST's feed is a SMALL-AUDIENCE medium. The hidden-audience property is
> the product; mass reach is not.**
>
> A channel is bounded at a size where per-recipient publication stays honest.
> `MAX_SUBSCRIBERS` drops from 50 000 to **512**, and the UI says what that means
> rather than letting a user discover it as slowness.

512 is not a round number chosen for looks. It is the size at which one post with
one image — call it 300 KB — costs the publisher ~150 MB of upload per post. That
is already at the edge of reasonable on a mobile connection, and past it the
model stops being something a person can actually use. Setting the cap where the
cost becomes visible is more honest than setting it where the data structure
happens to stop.

### What is given up, plainly

Broadcast. KARST will not carry a channel with ten thousand readers, and it will
not pretend to. A project that needs that reach needs a different crypto model,
and adopting one is a decision about what the product is — not a performance
improvement.

---

## Why not the alternatives

Each of these makes large audiences affordable, and each pays for it in the same
currency.

**Sender keys / MLS-style group keys.** One ciphertext for the whole group,
distributed to members who share a group key. Cost becomes O(1) in the audience
for the message body. The price: the group is now a *thing* — it has a key, a
membership list, and a rekey event whenever someone joins or leaves. Those events
are observable and correlated, and a relay that stores one object served to many
fetchers learns the audience by watching who fetches it, which is precisely the
observation the current model removes. It also introduces the entire membership
and rekeying problem, which is where group messaging protocols spend most of
their complexity and most of their historical vulnerabilities.

**One encrypted blob + per-recipient wrapped content keys.** The blob is stored
once; each recipient gets a small wrapper carrying the content key. This is the
cheapest of the three and the most tempting: storage becomes O(1) and only the
key wrappers are O(N), and the wrappers are tiny. It is genuinely worth
revisiting. But it, too, gives the relay one object with N fetchers — the same
audience-by-fetch-pattern leak — and the leak is worse than it first looks
because the fetches are spread over time, so an observer accumulates the set
rather than seeing it once. **If this is ever adopted, adopt it with the leak
stated**, not as an optimisation.

**Relay-side fan-out.** The relay copies one upload to N mailboxes. Cheapest for
the publisher, and it hands the relay the audience list directly. Named here only
so it is on the record as considered and refused.

---

## What the number does NOT bound

Stated so the cap is not mistaken for a general scale limit:

- **Contacts.** One-to-one conversations are not affected. This is about the
  fan-out of a published post, not about how many people you can talk to.
- **Reach through re-sharing.** A subscriber can forward what they receive. The
  cap bounds direct fan-out, not eventual audience — the same distinction any
  end-to-end system has.
- **Relay capacity.** `MAX_BUNDLES`, mailbox caps and quotas are the relay's own
  bounds and are unrelated to this one.

---

## How the limit behaves

The cap is enforced where subscriptions are accepted, and the refusal is loud —
a new subscriber past the limit is REFUSED, not silently dropped, the same
discipline `MAX_MAILBOXES` and `MAX_SESSIONS` follow. A silent drop would make a
publisher believe they have readers they do not have.

The honest residual, which the cap does not remove: at 512 recipients a post
with a large attachment is still a large upload, done N times. The cap makes that
bounded and predictable, not cheap. Publishing to a full channel over a slow link
will take a while, and the UI should say so rather than appear stalled.

---

## When to reopen this

If KARST ever wants a broadcast medium, the answer is not to raise the number. It
is to add a SECOND, explicitly different publication mode with its own stated
metadata properties — "public channel, the relay can see who reads it" — so a
user chooses between reach and audience privacy knowingly, instead of getting
whichever one the implementation happened to make cheaper.
