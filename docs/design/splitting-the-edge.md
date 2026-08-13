# Depositing at one relay, fetching from another

Status: design. This is the largest metadata a single relay still gets, and the fix has a
precondition that is easy to state and hard to satisfy, so the note ends with what would
have to be true rather than with a plan.

## What one relay sees today

A message is deposited to a drop-box and later fetched from it. Both legs happen at the
same relay, so that relay sees:

- an address depositing to box B, from one IP;
- a different address fetching box B, from another IP.

The box is blinded and the bytes are sealed, so it learns nothing about who or what. It
learns that **these two endpoints are talking**, which is the edge of the social graph, and
it learns it without any analysis at all — the two legs are joined by the box identifier
sitting in both requests.

Everything else built so far narrows around this and does not remove it. Blinded addresses
stop the box naming an identity. Per-relay addresses (PRIV-12) stop two relays from
recognising the same box. The veil (PRIV-4) stops two relays from matching identical bytes.
Padding stops sizes from separating traffic classes. The edge survives all of it, because
the edge is not a leak in the data — it is the shape of the operation.

## The split

The sender deposits at R1. The recipient fetches from R2. R1 forwards.

Addresses already differ per relay, so the box the sender writes at R1 is not the box the
recipient reads at R2 — R1 cannot recognise the forwarded item at R2 by its address, and R2
cannot recognise it at R1. The veil already re-randomises the ciphertext per relay, so it
cannot be recognised by its bytes either. Those two are prerequisites and both exist.

What each party then sees:

- **R1**: the sender's IP, a deposit, and that it forwarded to R2. Not the recipient's IP,
  and not the fetch.
- **R2**: the recipient's IP, a fetch, and that the item arrived from R1. Not the sender's
  IP, and not the deposit.

Neither holds both IPs against one item. That is the property being bought, and it is worth
saying exactly: it is unlinkability of the two ENDPOINTS at one observer, not anonymity of
either.

## The precondition, and why it is the whole difficulty

**R1 and R2 must not be the same party.** Two relays with one operator, or on one host, or
sharing a network vantage point, reconstruct the edge by joining their own logs — and the
join is trivial, because R1 knows what it forwarded and R2 knows what it received. The
split then costs a round trip and buys nothing.

This is not a hypothetical. It is the same condition the helper roles already carry, and
the honest reading of it is: **the split's value equals the independence of the two relays,
and nothing in the protocol can establish that independence.** A client can pick two relays
that claim different operators; claims are not proofs, and the relay-policy work already
concluded that advertised properties are claims that reputation makes accountable later,
not facts the protocol verifies.

So the deliverable of this design is not "split the edge and the leak is gone". It is:

- the mechanism, which is buildable and whose pieces exist;
- and a statement, in the interface, that its value depends on a property the user chooses
  and cannot verify.

A version that ships the mechanism and lets the interface imply the guarantee would be
worse than not shipping it, because the user would stop looking for the leak.

## Costs, named

**Forwarding is a store-and-forward hop.** Latency is one extra relay, and delivery now
depends on two operators rather than one — either can drop. The at-least-once machinery
covers the drop; it does not cover a relay that drops selectively, and a relay that can spot
forwarded items can drop exactly those.

**Storage is paid twice.** The item sits at R1 until forwarded and at R2 until fetched, so
the network holds two copies for part of its life. The quota accounting has to charge the
sender once, not twice, or the split becomes a way to double someone's cost.

**R1 learns which relay the recipient uses.** That is in the recipient's published bundle
already, so it is not new information — but it becomes information R1 records per message
rather than something a sender looks up once.

**A forwarded item is distinguishable at R1 from a locally-fetched one**, unless every
deposit is forwarded. If some are and some are not, "this one was forwarded" is itself a
signal, and it correlates with the sender caring. So either all deposits forward, or the
choice leaks the choice.

That last one is the constraint that decides the shape: it has to be the default path, not
a mode.

## What would have to be true to build it

1. Relay-to-relay forwarding exists as a transport, with its own admission (a relay
   accepting forwards from strangers is an open relay).
2. Forwarding is the default for every deposit, not an option.
3. Quota charges the sender once across both hops.
4. The interface states that the guarantee rests on the two relays being independent, in
   the place where the user picks them.

None of those is exotic. The fourth is the one that decides whether the feature is honest.
