# Design note: mailbox deposit/fetch key separation

**Status: SHIPPED (2026-07-21).** The separation is now wired into the live drop-box path — the
sender computes the deposit address from the recipient's public mailbox point `M` and cannot derive
the fetch secret, and the relay gates a fetch/ack with an in-group Schnorr ownership proof
(`blind::FetchOwnershipProof`). See `node/src/blind.rs`, `node/src/peer.rs`, `node/src/pqxdh.rs`,
and the discriminating test `a_blinded_box_is_fetchable_only_by_its_fetch_secret_holder`. The
analysis, impact bound, and target design below are kept as the design record; the "Decision" was to
defer, and it was later superseded — see the note at the head of that section.

## The property in question

A mailbox address is an X25519 **public** key; the relay grants a *fetch* only to whoever proves they
hold the matching **secret** (`fetch_proof` = `DH(mailbox_secret, relay_pub)`, `node/src/node.rs`).
Deposits are open; only reads are gated by the ownership proof. So in principle:

- a **sender** needs only the recipient's mailbox *public* key (to deposit), and
- only the **recipient** should be able to derive the *private* key (to fetch).

**Today that separation does not hold.** Both sides derive the per-epoch, per-direction mailbox from a
single shared `drop_seed` (`node/src/drop.rs`), taken from the session root key:

```
drop_seed   = HKDF(root_key, "karst-dropbox-seed-v1")        # shared: both hold root_key
drop_identity(drop_seed, epoch, dir) -> full X25519 keypair  # deterministic, symmetric
```

`drop_identity` returns the **whole keypair** (secret + public). Because `drop_seed` is shared, the
sender can compute `drop_identity` for the *recipient's* inbound box and thus its **private fetch
key** — the module comment even states it plainly ("the sender needs only the public half, but derives
the same way"). This is the reviewer-raised gap: deposit capability implicitly confers fetch
capability.

## Impact: bounded to two-party defense-in-depth (not an active leak)

Drop boxes are **per-session, two-party** (derived from the 2-party session root key — only A and B
can derive them; `drop.rs:1`). There are exactly two boxes: A→B (A deposits, B fetches) and B→A. A
malicious party can derive the other direction's fetch key, but:

- the **A→B box** holds only **A's own deposits** — A reading it learns nothing new;
- the **B→A box** is **meant for A** to fetch anyway.

So within the current two-party model, a party can only ever fetch a box that holds data it is already
party to. There is **no cross-party confidentiality leak** and no griefing vector (a party fetching a
box only consumes messages it sent or was the intended recipient of).

**What would break the bound** (and turn this into a real leak), so it is fixed *before* then:

1. Extending the box model past two parties (group mailboxes, a shared inbox), where "can deposit"
   must not imply "can read what others deposited".
2. Delegating deposit to a third party (a "post on my behalf" capability) that must not also grant
   fetch.

## Why the clean fix is heavy (the discriminating question)

The natural fix keeps the zero-exchange, per-epoch rotation: the recipient contributes a per-session
mailbox point `M = m·G` (secret `m`), and each epoch's box is a **blinded** key —
`deposit_pub = h·M`, `fetch_secret = h·m`, with `h = H(root_key, epoch, dir)`. The sender computes
`h·M` (public only); only the recipient, holding `m`, computes `h·m`.

Two landmines make this **not** a small change:

1. **X25519 clamping breaks multiplicative blinding.** x25519-dalek (the node's only curve dep) clamps
   scalars and exposes no scalar arithmetic mod ℓ, so `pub_of(h·m) ≠ h·(m·G)` and the construction is
   not even expressible. A correct version needs a prime-order group with clean scalar math —
   Ristretto255 / Edwards via `curve25519-dalek`.
2. **The fetch proof is a DH against the relay's X25519 identity.** `fetch_proof =
   DH(mailbox_secret, relay_pub)` where `relay_pub` is the relay's **X25519 / Noise** static key. A
   Ristretto mailbox key shares no DH with an X25519 relay key, so moving the mailbox keys to a clean
   group **also forces a relay-side proof change** (new key type and/or a different ownership-proof
   construction) — a wire-format and every-client change (`node`, `client`, `gui`, `desktop`).

Discriminating question (per review): *can `fetch_proof`'s DH move to the group the mailbox keys live
in without changing the relay identity?* **No.** That is what makes the clean fix a relay + wire +
all-clients change.

### Alternative without exotic crypto

The recipient generates per-epoch inbound-box keypairs, keeps the secrets, and **publishes the public
deposit addresses** (piggybacked on the existing §12 bundle the sender already fetches). Correct, no
new curve — but it **unwinds the deliberate "both sides derive the address with zero exchange"**
property and adds ongoing publish/refresh traffic (a rolling window of addresses re-published as
epochs advance).

## Decision

> **SUPERSEDED (2026-07-21): the target design was IMPLEMENTED and wired live** (per-account `m`,
> `M` published in the bundle + carried in the authenticated key-agreement, blinded deposit
> addresses, and a relay-side Schnorr ownership proof). What follows is the original decision, kept
> for the record. In the end the "target design" shipped rather than the cheaper interim — with the
> honest caveat that the Schnorr proof is a reference construction and wants known-answer vectors
> before any production claim, and that it was a BREAKING change (old bundles re-publish, old
> sessions re-establish; a stale session fails LOUD on send rather than dropping mail).

**Defer the implementation; it is disproportionate to a bounded, two-party, defense-in-depth gap.**
Both real fixes touch the relay identity / wire and every client:

- **Target design** (when the box model extends past two parties, or deposit delegation is added):
  Ristretto255 mailbox keys with per-epoch point-blinding (`deposit_pub = h·M`, `fetch_secret = h·m`)
  **and** a matching relay-side ownership proof in the same group. This is the clean end-state that
  actually gives "sender holds only the public deposit key."
- **Cheaper interim** (if the property is wanted before groups exist): published per-epoch deposit
  addresses in the bundle, accepting the loss of zero-exchange rotation.

Until then this is a **documented, bounded property**, not a silent one. Do not describe the current
build as giving deposit/fetch key separation — it does not. *(As of the SHIPPED note above, this is
no longer true: the build now DOES give the separation on the live path. This sentence is the
historical pre-implementation stance.)*

Tracked in the protocol-hardening backlog alongside lease/ACK + exact retransmit and crash-safe blob
retry, which share the "advance/commit state only after the durable + confirmed step" discipline.

## Spike result (2026-07-19) — the primitive is built and proven, NOT wired

`node/src/blind.rs` implements the point-blinding half as an **isolated, unwired spike**
(nothing calls it; it changes no live behaviour). It confirms the construction works over
**Ristretto255** — the prime-order group that makes `h·(m·G) = (h·m)·G` hold exactly, which the
X25519-clamping landmine above prevented:

- The recipient holds an INDEPENDENT random `m` (never derived from `root_key`) and publishes
  only `M = m·G`.
- `h = H("KARST-mailbox-blind-v1" ‖ root_key ‖ epoch ‖ dir)`, wide-reduced to a uniform scalar.
- **deposit address** `= h·M` — the sender computes it from the public `M` + `h`, with no
  access to `m`.
- **fetch secret** `= h·m` — only the holder of `m` computes it, and `deposit = fetch·G`.

Tests pin the defining property (sender derives the box a recipient's fetch secret unlocks,
without `m`), that the fetch secret is bound to the private `m`, and per-epoch / per-direction
rotation. So the "sender holds only the public deposit key" property is now demonstrably
achievable.

### Second spike (2026-07-21) — the relay-side ownership proof is now ALSO built

The relay-side ownership proof named below is now a built, unwired spike too:
`blind::FetchOwnershipProof`. The live relay gates a fetch with
`DH(mailbox_secret, relay_x25519_identity)`; a Ristretto fetch secret shares no DH with the
relay's X25519 key, so a blinded mailbox needs an **in-group Schnorr proof of knowledge of
`fetch_secret`** (the discrete log of the deposit address `P = s·G`) instead. The relay verifies
against only public `P` + a challenge, never the secret. Construction: `R = r·G` with `r`
wide-reduced from 64 random bytes; `c = H(domain ‖ P ‖ R ‖ context)` binding the STATEMENT (else a
proof transfers to another box) and the context (else it replays); `z = r + c·s`; verify
`z·G == R + c·P`; reject identity + non-canonical inputs. Tests pin what tests CAN — valid proof
verifies; wrong secret / tampered proof / wrong context / wrong statement / malformed inputs do not.
Still un-CI-able the way a signature is; **before it could ship it needs known-answer vectors** (the
randomized `prove` can't have a full-proof KAT, but the deterministic challenge format can).

**So BOTH crypto halves are now proven on the shelf** (point-blinding + ownership proof), unwired.

**What is STILL deferred (and why the spikes are not a ship decision):**

1. **The live wiring — a wire-format change touching every client.** Shipping the separation means
   moving `peer.rs`'s drop-box derivation off the shared `drop_seed` onto the blinded keys (the
   recipient's `M` published in the §12 bundle), replacing the relay's `DH` fetch gate with
   `FetchOwnershipProof`, and the wire/format churn across `node`/`client`/`gui`/`desktop`. The
   crypto is done; this integration is not, and it does not self-merge.
2. **The threat model is unchanged.** This is still bounded to two-party defence-in-depth (no
   cross-party leak); the spikes prove *viability and measure cost*, they do not reverse the
   deferral. The trigger to actually ship is when "can deposit" must stop implying "can read" —
   i.e. **group mailboxes or deposit delegation**. Until then, `blind.rs` is a proven primitive
   on the shelf, and the live drop-box path is unchanged.
