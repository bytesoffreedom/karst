# KARST — feature roadmap (principle-compatible backlog)

> This file is a **plan**, not a promise and not an implementation status. What
> already works for real is in [STATUS.md](STATUS.md) (the code is the source of
> truth). Here are selected features from popular messengers that we **don't have
> yet** and that **don't contradict** the 7 principles (see the root
> [README](../README.md)): open design (Kerckhoffs), transport diversity and
> resilient delivery, no mandatory central service, resource-bounded relay
> operation, explicit privacy boundaries, hybrid post-quantum key agreement,
> honesty over marketing.
>
> The plan includes "green" (fit as-is) and "yellow" (metadata leakage, and so
> **off by default**, enabled deliberately by the user — a separate section
> below). Incompatible ("red") ones are only in "Boundaries".

Effort: **S** — small (client/UX), **M** — medium (light protocol), **L** — a
large effort.

## THE PLAN: the privacy architecture (outranks everything below)

Derived from the design audits in [STATUS.md](STATUS.md) (2026-07-17). Everything
in the feature backlog below is optional next to this; this is the part that decides
whether KARST is what it claims to be.

**The thesis.** Every alternative we examined — onion routing between our own nodes, a
federation of friends, a stake, a directory, betting on Tor — buys privacy with **other
people's honesty**: hops that do not compare notes, an overlay that is not compromised,
friends who vouch truthfully and stay online. Every such bill is priced by someone else
and cannot be verified by us.

> **Build the design whose entire bill is payable in what we control — CPU, bandwidth,
> our own code. Make the relay BLIND, rather than making the network complicated.**

## Identity: a root with no address, reached only through disposable proxies (design settled 2026-07-22 — SHIPPED 2026-07-23, phases 1–5)

**Full design: [`docs/design/proxy-identity.md`](design/proxy-identity.md).** BUILT — see
[STATUS.md](STATUS.md) "What landed since the last reconcile". Phases 1–5 landed: `derive_proxy`,
`Store::as_proxy` + `net_file` namespacing, desktop publish/poll/send iterating proxies, the
connection-channels UI, and channel migration. It reframed what "an account" is, so it outranked
the feature backlog below — that reframing is now the shipped baseline.

The flaw it fixes: today your identity **is** your IK — a permanent address that cannot be
changed and that every way of reaching you (a shared address, a contact code, a one-time invite)
hands over for good. One leaked or abused address is therefore permanent exposure, with no escape
short of abandoning the identity your contacts know.

The model: **the root (what the phrase + password unlock) has no IK and no network presence** —
it is a seed and a local hub that owns all your data (profile, contacts, one unified inbox, feed),
one copy. The only things on the wire are **proxies**: disposable HD-derived keypairs
(`derive_proxy(seed, n)`, a *separate frozen domain* from the root `derive`) that are pure
communication channels — not personas, so no data is duplicated. You hand a proxy (or a code that
resolves to it) to a contact or a group; you rotate or burn it freely; the root is never exposed
because it is not a network object at all. Spam and abuse are handled at the channel level (reject
/ block / rotate), never by changing your identity.

Honest limits (carried into the UI, see the design doc): a relay can still cluster your proxies
with **each other** by fetch behaviour unless each rides its own circuit; showing the same profile
over many proxies re-links them at the profile layer; recovery re-derives empty proxy **keys**,
not your conversations, live indices, or ratchet state. This **re-targets discovery / contact
codes / one-time invites (below and in STATUS) onto proxies** — a code resolves to a disposable
proxy IK, never to anything permanent, which is what finally makes "one-time" meaningful.

## The network shape: Public and Private nodes (design settled 2026-07-17)

A long design discussion converged on how KARST becomes a *network* without becoming a
*federation*. The result is two node roles — the same binary, distinguished by policy —
and one hard rule about what nodes may do to each other. Recorded here as the settled
design; the build slices that follow implement it bottom-up. Nothing here is built yet
beyond the primitives noted.

### The governing distinction: "network" is not "federation"

The instinct that KARST must let strangers reach each other kept pulling toward
relay-to-relay message forwarding (federation). It was rejected every time for one
reason: **forwarding is transitive exposure.** A node that relays another node's traffic
learns metadata about users it does not host, bypasses the destination node's admission
(it can deposit on anyone's behalf), and — for a full mesh — caps total write-throughput
at a single node's capacity. This is trap #1, and no amount of content-encryption fixes
it, because the leak is *who-talks-to-whom at the network layer*, not content.

**The resolution is the web's model, not email's.** Web servers do not forward to each
other; the browser goes where the address points, and the web is still a network. Here:
**the client is the bridge, not the infrastructure.** A user reaches someone by learning
*which node* they are on and connecting there **directly** (`client-direct` delivery).
Nodes never carry each other's messages. Cross-node reachability comes from a shared
*directory* (discovery) plus client multi-homing — not from interconnection of the
delivery path.

This splits cleanly into two planes, and the split is the whole design:

- **Discovery plane** — "which nodes exist" and "where is user A". MAY be shared between
  nodes. Cheap and on-thesis for the *node list* (relays are public infrastructure). For
  the *user directory* it carries the enumeration tradeoff (below).
- **Delivery plane** — the actual message A→B. MUST stay client-direct. Never
  node-forwarded. This is the invariant that keeps every privacy property the slices won.

### The two node roles

| Role | Directory | Door | Reach | Knows about |
|---|---|---|---|---|
| **Public** | listed; Public nodes replicate a **blinded** directory among themselves | open — a pass via **PoW** | anyone can find you and message you (client connects to your node directly) | other Public nodes only |
| **Private** | none | closed — **invite only** | only people you brought in; you are *led to*, never *found* | nothing published; **only its users know it exists** |

**Public ⊥ Private is a first-class security property, and it holds mechanically:**
a Private node is never in any directory, so Public nodes have nowhere to learn it from;
and when a user migrates a contact from Public to their Private node, the invite
(`RouteOffer`) travels as **sealed E2E content** — a Public node relaying it sees an
opaque payload, not the Private address inside. The one residual: a Public node can see a
conversation *go quiet* on it and infer a migration happened, but never where to.

**Public nodes are the high-throughput tier, and it scales — because they do NOT
forward.** Each Public node serves its own users; adding nodes adds capacity
(horizontal). Replicating the directory buys *universal findability + resilience* (any
node answers "where is A", no single load-bearing directory), which is a different mechanism
from throughput and must not be confused with it. The blinded directory means compromising any
one node yields opaque `pseudonym → node` tokens, not a roster of names — at the cost that
the (blinded) count and fact-of-participation are maximally replicated. Full replication
is a server-storage cost at very large N; sharding removes it but reintroduces the
"which node holds A's entry" lookup, deferred until it binds.

### The privacy gradient — one identity, settings not modes

The two roles are the ends of a gradient a single user moves along with settings, never a
"paranoid mode" toggle:

1. **Public, stable identity** — findable, convenient, content-private. The directory
   sees the *set* of who first-contacted you (blinded), and on a busy Public node the
   relay sees individual conversation *edges* pseudonymously (the graph residual; see
   STATUS).
2. **Migrate marked contacts to your own node** — after first contact on Public, move the
   relationship to a Private node you run. The rendezvous leaves the shared relay; your
   graph fragments across the Private nodes of the people you talk to, so no single node
   aggregates you. It is an *offer* (`RouteOffer`) the recipient may decline. Carrier of your node is
   *your* choice — Tor hidden service, VPS, whatever; **not forced to Tor** (Tor is often
   a bigger traffic-classification trigger, not universally more private).
3. **Different contacts on different nodes of yours** — inbound compartments: no single
   node, even your own, sees your whole inbound graph; compromising one exposes only its
   slice.
4. **Not in the directory at all** — hand out unique one-time invite addresses OOB, each
   leading to your Private node. Not publicly findable; the Public tier does not know you
   exist. The strongest, at the cost that you can only be *led to*, never *found*.

**Disposable accounts and the Sybil tension, resolved.** A requester may knock from a
throwaway account so their stable identity never touches the relationship. This needs
cheap account creation — which is exactly what spam needs too. The resolution the design
reached: **paranoia pays for itself.** Creation is gated by **PoW** (anonymous, leaves no
trail, unlike a payment or invite gate that would relink the very burners it hides);
combined with the existing per-capability quota, spam is bounded and burners cost the
spammer the same as the paranoid. The fully-anonymous *rate-limited* ideal is RLN — an
external wall — but the practical gate (PoW → capability → quota) needs no RLN and is
buildable now. One mechanism serves three jobs: spam resistance, the Public door, and the
price of a burner.

### Two thesis-level forks, named not built

These reverse a stated principle and are the user's call, surfaced rather than
engineered around:

- **Relay-to-relay federation** (message forwarding / full mesh). Reintroduces trap #1.
  Not built.
- **Minted rewards** (for registrations or for storage). A *minted* reward — from a pool
  or token, proportional to work reported by the party that also reports it — pays for the
  attack the door exists to stop (the operator farms fake registrations; a storage node
  claims files it dropped). It also needs a token (commercial — KARST is stated
  *non-commercial* — plus the "other people's honesty" bill of consensus), and for storage
  it additionally needs proof-of-storage, the entire technical core of Filecoin/Sia.
  **Conserved** payment (a registrant pays their host directly; a Public node may charge
  its own users; mission/community operators run nodes for their own people) is fine and
  on-thesis — it cannot be farmed because faking a registration means paying yourself.
  The incentive must come from the operator's own benefit, never a global minted pool.

### File transfer: transient buffer, not a storage economy

Already built (`node/src/blobstore.rs`): disk-backed, **encrypted**, **TTL-swept (7
days)**, hard-capped per-blob/per-sender/globally, reject-when-full (never evict a live
transfer). This is the correct shape — the relay is a **transient buffer**; files live
durably on the endpoint devices, not on nodes, exactly as the mailbox holds messages
transiently. No dedicated "storage node" role and no reward is needed or wanted for
*transfer*. Permanent/broadly-shared *hosting* is a different product (file hosting, not
messaging) and is the same thesis fork as minted rewards. **One cheap improvement worth a
slice:** drop a blob on successful fetch (like the mailbox drains), keeping the TTL only
as the fallback for a recipient who never comes — minimising both storage and compromise
surface.

**Landed 2026-07-20 — reliability + an honest trust story (details in `docs/STATUS.md`).**
The buffer got durable and its posture became the operator's, advertised choice: the blob
INDEX now survives a relay restart (FT2), so a parked multi-GB upload no longer vanishes;
whether it survives is a **per-relay toggle** (`KARST_RELAY_BLOB_PERSIST=durable|ephemeral`
— durable is reliable, ephemeral is the lower-residue posture), the relay **advertises** it
(`karst relay-info`), a client can **prefer** relays that match (`karst relay-prefs`), and —
the honest keystone — a client can **PROVE** the durable claim by fetching a chunk back
(`verify_durability`, proof-of-retrievability) while "ephemeral" stays an unprovable claim
(you cannot check a remote deletion). Plus robustness: the download fsyncs in ~2 MiB batches
not per chunk (FT3), and a re-delivered inline file dedups instead of double-saving (#30).
This is still a transient buffer — encryption/caps/TTL unchanged, and confidentiality never
rested on ephemerality; the new part is that durability is a stated, checkable choice.

**What building slices 2 and 3 taught us, recorded because it reorders the rest.** Both
slices rotate identifiers — mailbox addresses, `client_addr` handles, traffic timing —
and both hit the same wall from opposite sides: **the relay reads the source IP on every
leg, and every identifier we rotate sits above it.** Rotation is undone underneath.
That made per-handle path isolation (3b) not a polish item but the precondition for two
things already shipped — now delivered, which closed slice 3's residual outright and
turned slice 2's remaining one into a pure addressing problem for PIR. The lesson
generalises and outlives the slices: *an identifier is only as unlinkable as the layer
beneath it*, so every future slice should be asked what the IP gives back before its claim
is written down. The `known_gap_` pins are what made this cheap to act on — the gap was
already written down and executable, so closing it was an inversion, not an
archaeology expedition.

| # | Slice | Effort | What it buys | What it still does NOT buy |
|---|---|---|---|---|
| 0 | **Dial hidden services** (`Dest` + SOCKS5 ATYP `0x03`) | — | ✅ **DONE.** A relay can be a `.onion`/`.i2p` with **no clearnet IP**; unlocks every SOCKS overlay at once, carried side by side with failover. A Tor circuit to an onion service already IS client↔node onion routing — we ride it instead of building it. The relay side needs **no KARST code** | Nothing about what the relay learns |
| 1 | **Sealed openers** — ✅ **DONE** | M | The conversation opener stops naming the sender: encrypt the "it is me" to the recipient so PQXDH still works and the relay reads nothing. Removes the last plaintext identity on the send side | The mailbox still names the recipient |
| 2 | **Rotating drop-boxes** — ✅ **DONE** | M–L | After the opener, the mailbox stops being your identity: its address is derived per epoch from the secret both sides already share, so an observer holding your published discovery key cannot read your inbound social graph off deposit addresses. Handles rotate with the boxes — address rotation alone is theater, since the relay reads `client_addr` on every request. Prerequisite for PIR | The stranger's first knock still needs one stable address — **and, found while building it, a relay that LOGS fetches can still chain epochs**: skew tolerance forces re-polling a box across each boundary, and a box polled in two epochs bridges them. Not fixable by rotating harder (on a re-poll the address IS the linker); polling one epoch only would close it by stranding mail. **This is what slice 5 is for.** Pinned by `known_gap_the_relay_can_still_chain_epochs_through_the_overlap` |
| 3 | **Loop cover + Poisson delays** — ✅ **DONE** (garlic bundling not started) | M | Silence stops being an answer: the client deposits to a box only it can compute, on an EXPONENTIAL (memoryless) schedule — no amount of watching sharpens the rate estimate, which bounded jitter cannot claim. A loop that never returns is the one drop-detection signal store-and-forward gets free. Cover is a user-facing knob: it is a permanent bandwidth/battery tax and its deposit (not its free fetches) competes with real sends for the quota — ~10 of 100 requests per 600 s at one loop a minute | **Against the relay itself, mostly nothing yet — found while building it.** The relay reads the source IP on both legs: a real message's box sees two addresses (sender deposits, recipient fetches), a loop's sees one. Handles sit above the IP and do not help. So the relay can subtract loops from your volume, and — worse — a relay that can spot loops drops real mail while returning loops, making the detector lie. **Both benefits were conditional on per-handle path isolation — which slice 3b then delivered**, so the legs now ride separate circuits and a loop wears a real message's shape. Conditional now only on using an isolating carrier at all: over direct TCP one IP serves both legs. That `known_gap_` test is inverted into `a_loops_two_legs_ride_different_circuits_like_a_real_messages_do` |
| 3b | **Per-handle path isolation** — ✅ **DONE** | M | The missing dependency of two shipped slices, not a new feature. Every handle now asks the carrier for its own circuit: the compartment token and a per-request scope are COMBINED (both separations must hold — accounts must not share a circuit, and nor must two handles inside one account), and the scope is a HASH of the handle so a proxy operator and a relay operator cannot join logs on an exact match. **Closes the loop-cover gap**: a loop's legs were sharing a handle and therefore a circuit, giving one source address where a real message shows two — the thing that let a relay filter cover and fake the drop detector. Legs are split (`LoopSend`/`LoopRecv`), and that `known_gap_` test is inverted into the property | **Only over an isolating carrier.** Circuits exist if you use a SOCKS proxy honouring `IsolateSOCKSAuth`; over direct TCP there is one source address however many handles ask for one — you have one IP and no addressing scheme conjures a second. Costs a circuit build per handle. Does nothing for a relay reading fetch ADDRESSES — the epoch-chaining gap is still slice 5's |
| 4 | **Public/Private network (client-direct, no forwarding)** — the network-shape section above | M–L | Turns standalone relays into a network the on-thesis way. Concretely: (a) **configurable wss path** so a node co-hosts behind an ordinary website on one domain (secret, unguessable path — a known one is a prober's fingerprint); (b) **contact relay-hint** (a `ContactRecord` learns *where* a key lives) + **client multi-homing** (`Session` holds a set of relays; send picks per contact) with **per-relay cookie/handle scoping** (two relays must not join you on a shared handle); (c) **`RouteOffer`-driven migration** of marked contacts to a node you run (already an accept-or-ignore offer). Delivers the Private tier and the "found by link, never met" reach end-to-end | Federation (message forwarding) is explicitly NOT this — see the fork above. The **user directory** (blinded, PoW-gated, replicated across Public nodes) is the heavier, later part; multi-homing + relay-hint gives reachability-by-address without it |
| 4a | **The door: real capability issuance (PoW)** — ✅ **DONE** | M | Replaces the forgeable public dev-cap. `KARST_RELAY_MODE=public` now runs a **PoW-gated** door: a client solves hashcash (`karst join`) to EARN a capability, and the existing per-capability quota bounds it — one mechanism, the Public door + spam gate + burner price. The earned capability is **stateless** (`pow_cap_secret` = HMAC(issuer_key, id‖not_after‖scope), recomputed on every verify, deterministic per solution) so it survives a relay restart and there is **no table to fill** — the front-door DoS a stored-cap design would have. `admission::pow`, `RelayNode::{enable_pow_issue,handle_join}`, wire `JoinChallenge`/`Join`→`Issued`. Difficulty is an operator knob (`KARST_RELAY_POW_BITS`), **toggleable live** by the node owner — `karst-relay pow off\|open\|on N` over a 0600 admin socket, so a relay with no spam yet can run OPEN (difficulty 0, quota-only) and turn PoW on when it appears (turning issuance off keeps already-earned caps working). No RLN needed | It is a spam **rate bound**, not Sybil **resistance**: one solve buys a capability sending at `POW_CAP_QUOTA` (≤100 req/10 min) for its lifetime, so sustaining more throughput costs one solve per extra cap — the difficulty is a speed bump, a GPU farm still mints many caps; the honest ceiling is unchanged. The fully-anonymous *rate-limited* form (relay can't link messages to your capability at all) is RLN — external wall |
| 4c | **Opt-in discovery (contact code)** — ✅ **single-relay DONE**; replication + PIR later | L | The Public tier's discovery. **Landed:** opt-in, **rotatable, revocable** discovery by a RANDOM contact code decoupled from the IK (no chooseable usernames — squattable; `node/src/discovery.rs`, `karst discovery on/rotate/off` + `karst find`). Records self-authenticate (IK-signed code→IK binding + discovery-key write auth) and carry a TTL. Being reachable no longer enrolls you — findability is explicit opt-in. **Still to do:** REPLICATION across Public nodes (gossip the record + freshness/anti-rollback — the TTL is the hook) and **PIR lookup** so the directory does not learn *whom* you sought (a directory is slow-changing — FrodoPIR's assumption, opposite of slice 5) | Total count + fact-of-participation still leak — the honest floor of being findable at all. Anyone holding your code can confirm you are enrolled (now scoped to a code you handed out, not your permanent identity). The graph residual at scale is unchanged (that is slice 5) |
| 4b | **Compartments (client-side)** | M | Different relationships carry different risk; one posture for all means over-paying or under-protecting. A compartment = **its own identity + its own relay + its own circuit**, so a compromised public relay does not reveal your other life. **Blast-radius limitation.** Details + the enforcement rules below | **Nothing against your own device**: one vault = one passphrase = every compartment falls together. Real device-level separation is a separate PROFILE (own `KARST_HOME`, own passphrase) — already supported, and must be said plainly rather than left for the user to assume |
| 5 | **PIR** — ⛔ **BLOCKED on an external wall** (measured 2026-07-17) | L | Would close the last two residuals: the stranger's first knock, and slice 2's epoch chaining (the defect is that a fetch reveals WHICH box is read — exactly what PIR removes). **The architecture fits** — verified, not argued: PIR deletes fetch-auth's access control, but fetch-auth never provided confidentiality (payloads are already sealed), only protection from DELETION — and under PIR you cannot target what you cannot name. Pinned by `a_mailbox_payload_is_useless_to_anyone_but_its_recipient` | **The available crypto does not fit.** ChalametPIR (FrodoPIR family) measured: a ~5 MB client hint, driven by the LWE dimension rather than DB size, invalidated by EVERY deposit. That family assumes a slowly-changing DB (a breach list, a CRL); a mailbox changes on every message, so the hint's amortisation never pays. The family that fits does preprocessing server-side (Spiral `0.2.1-alpha`, or OMR — literally this problem as a primitive), and both are research-grade in Rust. Same class of wall as the RLN zk circuit |

### Compartments (4b) — how it stays real instead of decorative

Compartments are linked by **any single** shared axis. A half-measure is worse than
nothing: it produces the *appearance* of separation with none of the substance. So each
axis is either enforced or honestly disclaimed.

| Axis | State | What makes it real |
|---|---|---|
| **Identity** | ✅ already | An account IS an IK (`accounts/<id>/`, each with its own). Nothing to build |
| **Relay** | ✅ **fixed** | `NetSettings` now lives on the ACCOUNT (`accounts/<id>/net.dat`, migrating a legacy vault-level config once), `SwitchAccount` rebuilds the `Relay` from the TARGET account's config instead of reusing the previous one, and `Cmd::SetNet` lets an account be given a relay of its own — without which "per-account config" was unreachable. A new account INHERITS the current one's config so it works at all: a **co-tenant**, not a compartment, until its relay differs. **The old plan item here said REFUSE two compartments sharing a relay. That is now wrong, and slice 3b is why** — see below |
| **Circuit** | ✅ **fixed** | `Socks5Adapter` now offers user/pass (RFC 1929) alongside no-auth and presents a random per-`Relay` token (`isolation_token()`), so Tor's `IsolateSOCKSAuth` puts each account on its OWN circuit — enforced by Tor, not hoped for. The token is random, never derived from an identity (a derived one would be that identity's stable label in the proxy's hands). A proxy that ignores isolation still works: it picks no-auth |
| **Timing** | ✅ already — do not "fix" it | Exactly ONE session is active at a time (accounts switch, they are not all online). That means you are never present in two compartments at once, so there is no "both appeared at 14:03" to correlate. **This is a deliberate property. Do NOT "improve" it into all-accounts-online** — that would hand a correlator the link for free |
| **Visibility** | ✗ missing | A silent wrong choice — messaging a source over the public relay without noticing — is how this feature gets someone hurt. The compartment must be shown in the chat like the carrier chip, and the default must be the safe one |
| **Device / at-rest** | ⚠ cannot be fixed here | One vault, one passphrase, and `accounts.dat` lists every account: a lost or stolen *unlocked* device gives up all compartments together. In-app compartments defend against the RELAY, never against your own device — separate profiles do that, and the docs must say so instead of letting the user infer otherwise |

**Architectural constraint, not a UI choice:** a compartment is a **shared space**. Both
parties must be on the same relay (the sender fetches the bundle from their OWN relay),
so "which mode do I use with Bob" really means "which compartment do we BOTH inhabit" —
you cannot drag a contact onto your Private node unilaterally.

**"Two compartments must not share a relay" — RETIRED 2026-07-17, and 3b is why.** The
rule was written when sharing a relay plausibly meant sharing a circuit. It no longer
does: `Relay::configured` mints a fresh isolation token per construction and the worker
builds one `Relay` per account, so two accounts pointed at the SAME address, proxy and
routes still ride **different Tor circuits** — the relay cannot join them by source
address. Pinned by `two_accounts_on_one_relay_do_not_share_a_circuit` (derive the token
from the relay address and it reddens).

What co-tenancy actually costs is **blast radius**: one compromise exposes both accounts'
mail. A refusal is the wrong tool for that, on two counts. It would break the
inherit-on-`AddAccount` default, so a new account would not work at all until reconfigured;
and it would forbid a user from deliberately trusting one relay with two lives, which is a
legitimate choice we have no standing to overrule. The rule would have been a
half-measure of the exact kind this table exists to reject — the appearance of enforcement
against a threat (linkage) that is already handled, while the real cost (device compromise) goes
unmentioned.

**So the axis becomes DISCLOSE, not REFUSE**: say plainly which compartment is active and
whether it is a co-tenant, and let the user price the blast radius. That is the remaining
4b work, together with the visibility chip.

**Scope note (rewritten 2026-07-17 — the prediction it made was wrong).** It used to read
"once rotating drop-boxes land, the relay stops learning who you are anyway." Slice 2
landed and that is not what happened: you still poll your identity mailbox for openers,
which names you, and a relay that keeps logs can still chain a conversation's epochs
through the poll overlap. So compartments have NOT been demoted to blast-radius-only —
against a logging relay they remain one of the few things that actually separates your
lives, and they stay worth having on both counts.

**Why this order and not the ambitious one:** onion routing needs a crowd to hide in —
five users and three relays make correlation trivial no matter how many layers a packet
wears, and its price (non-collusion) is one we cannot set or verify. The blind-mailbox
layers are *cheapest exactly where an anonymity network is useless*. And no layer here is
load-bearing for everything: a fully compromised overlay still learns only "someone
reached this relay" (not who, not whose mailbox — that is our payload); a hostile relay
still never sees your IP (that is the carrier). Break either, the other holds.

**Explicitly NOT on the plan** (each with its reason in STATUS): our own onion network
(a bet on strangers, and theater at our size), a token/stake (an economy, and a state
outbids you), directory authorities (the coercible point we exist to avoid), betting on
any single overlay (diversify the delegation instead).

**Permanent limits — unchanged by any slice above, and to be repeated wherever the
benefits are:** an adversary watching both ends defeats it (every network admits this);
the relay still sees volume and timing against a rotating address; total blocking with no
working route leaves you dark (out-of-band rescue only, and it needs no code); a lost or stolen
*unlocked* device reveals contacts and who you verified.

## Already done (for context)

Multi-account, contacts + safety number, E2E text (PQXDH + Double Ratchet), **file
transfer of any size** (inline ≤48 KiB + E2E-encrypted blobs, off-loop with a progress
bar and cancel), delivery status, unread, at-rest history, forwarding without
forward-marks, deleting a contact / clearing a conversation, **disappearing messages**
(never-persist), per-chat drafts, copying a message, SOCKS5/PT + wss carrier, **path
failover across carriers with a fail-closed allowlist**, per-path health, remembered
(encrypted) network config, **contact route sharing**, **received files encrypted at
rest**, **hidden-service dialing**.

## Green — client-side / light protocol (quick wins)

| Feature | Effort | What it is / principle fit |
|---|---|---|
| Message time in the UI | S | Right now `ts` is discarded in `ChatMsg`. A basic thing; it also unblocks reply and deleting an individual message. |
| Reactions (emoji) | S–M | A small control message over the same E2E channel — just another sealed envelope, no leakage. |
| Reply / quote (reply-to) | M | A reference to a specific message (needs an identifier — `ts`). Purely client-side. |
| Text formatting (bold/italic/`code`) | S | Markup at render time, zero protocol. |
| Search over a conversation | S–M | Locally over the decrypted history. **A perfect fit** — all on the device, nothing goes out. |
| Export a conversation to a file | S | Client-side; the user is in control. |
| Block a contact | S | Locally stop accepting from an IK. |
| QR code for exchanging addresses — ✅ **DONE** | S | `karst qr` encodes your IK into a terminal QR. **An excellent fit** — it simplifies the out-of-band exchange WITHOUT introducing discovery on the relay (the trust model stays intact). |
| Inline image previews | M | Show received images in the feed rather than "saved: path". |
| Voice messages | M | Record audio → send as a file (the pipeline already exists; requires a size >240 KiB — see the larger ones). |
| Pin a chat/message, archive, folders, mute | S each | Client-side organization of the list. |
| Notes to self ("Saved Messages") | S | A local notes space (a self-contact is currently forbidden — make it a separate mode). |
| Multi-line composer (Shift+Enter), emoji picker, drag-drop/paste a file | S | UX niceties. |

## Green — larger, but not contradicting the principles

| Feature | Effort | What it is / principle fit |
|---|---|---|
| Deleting an individual message ("for me" / "for everyone") | M | "For me" reuses `rewrite_history`. "For everyone" is a tombstone message; **honestly: like disappearing messages, it cannot be forced on an uncooperative recipient**, only on a cooperating client. |
| Editing a sent message | M | A wire update; the recipient cooperatively redraws. The same honest framing. |
| Files >240 KiB / resumable transfer | L | Multi-mailbox chunking (§21.1 of the spec), back-pressure, persistent partial reassembly. |
| Group chats | L | Compatible (sender-keys / MLS; MLS is even PQ-friendly). Invariant: the relay must not learn the group membership. |
| Linked devices (E2E, no cloud) | L | Like Signal — device↔device over E2E. Compatible, but a large effort. |
| Local encrypted history backup | M | Export/import under the user's key. **Not** the cloud (which would be a central point of compromise). |

## 🟡 Optional — off by default, enabled by the user

These features are convenient but **leak activity metadata** (who, when, whether
online), which strains Principle 5 (privacy without identity). So they enter the
plan **only as an explicit opt-in, off by default**, with an honest explanation
next to the toggle (Principle 7): what exactly is disclosed, and to whom. Nothing
is enabled silently.

| Feature | Effort | What it discloses / how to make it safer |
|---|---|---|
| Read receipts ("read") | M | Discloses to the sender the fact and time of reading. Opt-in; can be per-chat. |
| Typing indicator ("typing…") | M | Discloses real-time activity; requires online↔online (the relay is store-and-forward, presence would have to be built on top). Opt-in, the most contentious. |
| "Last seen" / presence | M | Discloses your presence schedule. Opt-in; not published by default. |
| Link previews | S–M | Auto-fetching the URL by the recipient **deanonymizes** them (a leak to the link's host). The safe variant: the previews are generated by the SENDER and embedded in the message; auto-fetch by the recipient only if explicitly enabled. |

Technically "off by default" = not sending the corresponding control message / not
publishing presence until the user flips the toggle in the chat or profile
settings. The off state must not be distinguishable on the wire (no signal — as if
the feature isn't there), so as not to create a fingerprint (Principle 2).

## Recommended order of the next slices

> **The privacy architecture above outranks this list.** These are features; that is
> whether the product means what it says. Do them in the gaps, not instead.

1. **Time in the UI + deleting an individual message** — one slice: `ts` in
   `ChatMsg` unblocks both features and reply.
2. **Search over a conversation** — the purest fit (all local), high value.
3. **QR address exchange** — removes the main onboarding friction without touching
   the trust model.
4. **Reactions** — cheap, noticeably livens things up.

Each feature goes as a separate advisor-reviewed slice with discriminating tests
(neuter the fix → the test goes red → restore), like the rest of the development.

## Settings (compared with popular apps, principle-compatible)

Right now settings are baked into the code (dark theme, relay/SOCKS fields at
login, multi-account). Below is a settings screen and options from
Signal/Telegram/WhatsApp that **don't contradict** the principles. Everything is
local; **there is no settings sync via a server** (that would be a point of
compromise — the independent-relays principle).

**Privacy and security** (a strong fit)
| Option | Effort | Note |
|---|---|---|
| Hide message text in notifications | S | Show "new message", not the content. Privacy on someone else's screen. |
| Auto-lock the app | M | Require the passphrase after N minutes of inactivity (the device passphrase already exists). |
| Block screenshots/window preview | S | Best-effort at the OS level. |
| Default disappearing timer (global / per-chat) | S | A toggle for the already-built disappearing messages. |
| Auto-delete old messages (retention: older than N days) | M | Local control of storage, reuses `rewrite_history`. Fits the history model. |
| Message request for a first message | M | An unknown IK waits for acceptance. Without a directory — simply a gate on incoming. |
| Change the device passphrase | M | Re-derive the `MasterKey` + re-encrypt at rest. Important. |
| Show the recovery phrase (behind a repeat passphrase) | S | Already stored; a safe display after re-authentication. |
| Wipe data on this device | S | A local wipe of the profile. |
| Toggles for the "yellow" features (read/typing/presence) | — | They live here, off by default (see the section above). |

### Duress / decoy / dead-man passwords — multipassword (in progress)

Design + honesty in [design/duress-multipassword.md](design/duress-multipassword.md).
Four password roles on one device: **real** (normal), **decoy** (opens a
plausible empty compartment under coercion), **wipe/duress** (entering it
crypto-erases everything), **dead-man** (must be entered within an interval or
data auto-wipes).

| Tier | State | Deniability it buys | Cost |
|---|---|---|---|
| **Tier 1** (default, layout A′) | 🚧 keyslot foundation DONE; decoy/wipe/dead-man + Security-card UI next | Hides **which** compartment is real (symmetric `c/<id>/` dirs, indistinguishable keyslots). Defeats coercion-to-unlock. | **Zero** extra disk — compartments hold only real data. |
| **Tier 2** (opt-in "maximum deniability") | ⏳ DEFERRED | Hides **that a hidden compartment exists at all** (opaque, fixed-size container padded with random, so used vs. free space is indistinguishable). For the "disk was imaged and analysed" threat model. | **Reserved disk space** — the container is a fixed budget (e.g. 500 MB / 2 GB) regardless of actual usage, and cannot grow past it without revealing the hidden volume. Opt-in per device precisely because of this cost. |

Honest limits repeated wherever the benefit is: Tier 1 leaks compartment
**count** + **size correlation** and the `slots.dat`/`slotmap.dat` base-level
tells (a coercer can infer a hidden one *exists*, just not which). Salt-shred
crypto-erase is not guaranteed against SSD/CoW free-space recovery. Even Tier 2
is not absolute (FS timestamps, backups, wear-leveling). The Security-card UI
must state the active tier's real boundary plainly.

**Network** (a fit, some of it Principle 2)
| Option | Effort | Note |
|---|---|---|
| Proxy settings (Tor/obfs4/SOCKS) in the UI | S | Right now only fields at login — move them into settings. |
| Multiple relays / relay selection | M | Directly per Principle 2 (no single load-bearing carrier): backup paths. |
| Media auto-download policy (never / on request) | S | Saves bandwidth + privacy. |

**Appearance / chats** (neutral, client)
| Option | Effort | Note |
|---|---|---|
| Theme: light/dark/system | S | Dark is currently baked in. |
| Font size / density | S | Accessibility. |
| Enter — send vs newline | S | Plus a multi-line composer. |
| Interface language (i18n) | M | The UI is in a single hardcoded language right now; extract the strings. |
| Storage management: size, per-chat cache clearing | M | Local. |

**Diagnostics** (strictly local)
| Option | Effort | Note |
|---|---|---|
| Local relay logs/diagnostics | S | Only to the user's disk, **no telemetry out** (Principle 5/7). |

**Settings that will NOT exist:** syncing settings/chats to the provider's cloud,
server-side telemetry/crash reports, "who can find me by number/username" (there
is no directory and no identity by design). See "Boundaries".

## Profile (what you can tell about yourself)

Identity in KARST is the **IK from the seed phrase**; there is no central profile
store by design. So a profile (name, avatar, bio) is not "hosted" anywhere but is
**distributed to contacts peer-to-peer over the existing E2E channel** (as a
control message, on connect/change or on request). The recipient caches it
locally. Visibility is naturally **per-contact**: you decide what each one learns
(Principle 5).

**Honestly (Principle 7):** a self-declared profile ≠ an identity document. The
name "Alice" can be set by anyone (impersonation). The trust anchor stays the same
— the **safety number** + the **local label the recipient sets** (that one wins in
the UI). A profile is a convenient hint, not confirmation.

| Option | Effort | Note / principle fit |
|---|---|---|
| Display name (self-declared) | M | Sent to contacts over E2E. Does NOT replace the recipient's local label; for a new contact it's only a default pre-fill. |
| Avatar / profile photo | M | A small image over E2E; EXIF is stripped on the client (§21.1). Limit the size. |
| About / status text (bio) | S–M | A short description, E2E, per-contact. |
| Profile per account (personas) | S | Each account has its own name/avatar/bio; compartmentalization strengthens "privacy without identity". Multi-account already exists — add per-account fields. |
| Profile visibility per contact | M | Since the profile is sent per-contact — control over "share name/avatar with this contact / minimal profile". Directly per Principle 5. |
| Reset / delete a profile | S | Locally + send an "empty" update to contacts. |
| Local account label | — | Already exists (the label in the switcher). |

**Shipped:** display name + bio (Phase 1) and avatar (Phase 2) are implemented —
self-declared, sent to non-blocked contacts over E2E, cached per-contact, and they
never overwrite the local label / `verified`. Avatars are bounded-decoded (PNG,
≤128px, decompression-bomb defense) and re-encoded on receipt (which also strips
EXIF). **Deferred:** (a) propagation is on explicit change only — a profile set
before adding a contact is not auto-sent "on first connect" until the next change;
(b) avatar input is **PNG-only** for now (JPEG needs `zune-jpeg`, added when the
build has network); non-PNG gets a clear error.

**A profile that will NOT exist:** a username/@handle as a way to **find** you (it
would bring back a central directory — Principle 3; the replacement is IK + QR); a
phone number in the profile (identity — Principle 5); a public profile visible to
everyone, "people nearby", geo (a central fetchable store + a location leak).

## Broadcast, channels, and bots ("Telegram-like", only what fits the principles)

The mechanics (one-to-many broadcast, groups, automated participants) are
compatible. What is **not** compatible is everything Telegram does on the server:
a central directory, search by `@username`, and server-hosted bots — those are
exactly the single point of compromise or pressure and the identity leak that the independent-relays and privacy-boundary principles
3 and 5 exist to prevent. The dividing line is constant: **the broadcast and
automation are fine; central discovery (a directory / name search) and server-side
hosting/brokering are the red line.** The replacement for discovery is the same as
for contacts — IK + QR + an invite link with a short TTL (§12 discovery without a
global list).

| Feature | Effort | What it is / principle fit |
|---|---|---|
| Channel as a broadcast primitive (one publisher → many subscribers) | L | Built on the same MLS/sender-keys layer as group chats. The relay stores sealed capsules opaquely; subscribers fetch. **Compatible** — same class as groups. |
| Joining a channel/group by invite link/key (not by search) | M | Out-of-band, like a private invite (§12). Yields a "private / semi-public channel by link", not a searchable public showcase. |
| Bot as an automated peer (its own IK, speaks the same E2E protocol) | S | Just a client that auto-responds; added by IK/QR like any contact. Zero new protocol. **Perfect fit.** |
| Broadcast metadata protection (relay must not learn the subscriber list) | L | Otherwise the same presence-oracle already named in §12. A hard invariant for any channel work, not an add-on. |

These all sit behind the same large protocol checkpoint as group chats (MLS,
sealed-sender, broadcast metadata) — deliberately deferred, months of work, not a
slice. See also `Group chats` in "Green — larger" above.

**What will NOT exist (the red line for this area):** a public channel/bot
**directory** or search by name/`@username` (a central enumerable list — Principle
3; the replacement is invite links + QR); a **server-hosted bot platform**
(BotFather-style webhooks, globally discoverable inline bots — the server would see
content/metadata and become a central point of compromise, privacy-boundary principle); "channels you
discover by browsing", view counters and other server-side aggregation. See
Boundaries below.

## Boundaries (the plan does NOT go here)

- **Incompatible** (we won't build these): binding to a phone number / SMS;
  server-side contact search by number/username (it would bring back a MITM and a
  central directory); public usernames / a directory; cloud storage of
  conversations at the provider; a bot platform with server-side integrations;
  telemetry. All are a single point of compromise or pressure or an identity leak
  (Principles 3, 5). Our replacements: the seed phrase + IK, a manual out-of-band
  exchange + QR, a local backup.
