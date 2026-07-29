# KARST — an open protocol for private messaging over independently operated relays

A working document. It consolidates the original architecture, the analysis of
weak points, and the formal specification of the admission protocol. Section 8
contains open questions — that is where development continues.

---

## 1. The basic principle

We design the system assuming the adversary:

- has read all the source code;
- knows the full specification;
- has built their own client;
- runs millions of malicious nodes;
- can actively scan addresses;
- records and analyzes traffic;
- knows the route-finding algorithms;
- tries to overload CPU, memory, disks, and communication channels;
- blocks discovered addresses and protocols.

The adversary must NOT have:

- users' private keys;
- one-time contact capabilities;
- specific relays' keys;
- current epoch secrets;
- the ability to break standard cryptography;
- control over all devices and all internet routes at once.

Kerckhoffs's principle: the whole protocol is open, only keys, one-time
capabilities, and the dynamic state of the network are secret. Openness of the
algorithm does not reveal a capability — just as the openness of TLS does not
reveal a server's private key.

A mandatory requirement: **open source code**. Security must not depend on secrecy
of the protocol or source code — only on protected keys and reviewed cryptographic
mechanisms (Kerckhoffs). Publishing the specification and code is what makes
independent review possible.

## 2. What is open and what is secret

**Fully open:** the protocol specification, the source code of clients and
servers, the formats of encrypted capsules, cryptographic algorithms, routing
logic, rate-limiting algorithms, DoS protection, transport adapters, the update
system, test vectors, deployment documentation, relay code, threat models.

**Only dynamic values are secret:**

| Secret | Purpose |
|---|---|
| Device key | Identification and decryption |
| Contact key | The right to send a message to a specific person |
| Rotating mailbox token | Receiving messages from a temporary mailbox |
| One-time admission token | The right to spend a relay's resources |
| Server cookie key | Stateless verification of a client's address |
| Temporary relay capability | Access to a specific non-public node |
| Route randomness | Selection of hops and transport |
| Epoch key | Regular rotation of addresses and tokens |

There must not be a single shared secret key baked into all apps — extraction
from one phone must not destroy the whole network.

### 2.1 End-to-end encryption, forward secrecy, and post-quantum protection

> **Identity model — implemented (see [`docs/STATUS.md`](docs/STATUS.md)):** the
> [proxy-identity model](docs/design/proxy-identity.md) is live in the shipping desktop client.
> The root identity gets **no address at all**; every key that appears on the wire belongs to a
> **disposable, HD-derived proxy** you can rotate or burn. The key-agreement and ratchet
> described below are unchanged and apply **per proxy** — a proxy is a full identity for a
> session; what the proxy layer adds is *which* identity is exposed (a throwaway one) and that
> the root never appears on the wire. So wherever this spec writes "identity (IK)" or "address",
> read it as **one proxy's** IK and address, not the root's.

The "contact key" above gives the right to send a message to a specific person,
but the scheme for key agreement and obtaining forward secrecy was nowhere
specified in this document — the previous 21 sections covered admission,
transport, storage, governance, coercion, but not how exactly the content is
encrypted between sender and recipient. This is a separate, independently
important gap, not just a missing detail.

**The threat is not storage on nodes, but passive recording of traffic.** The
threat model (section 1) explicitly includes an adversary who "records and
analyzes traffic". Such an adversary gets their own copy of the encrypted capsule
right off the wire, regardless of what the relay does with its copy afterward —
deletion on nodes (section 13) protects against compromise of infrastructure, but
not against **harvest now, decrypt later**: the adversary collects ciphertext
today and waits until a quantum computer can break classical asymmetric
cryptography (Shor's algorithm against the discrete logarithm/factorization).

**The solution is not to invent one, but to take an already-deployed
construction.** Since 2023, Signal has used exactly for this task **PQXDH**
(Post-Quantum Extended Diffie-Hellman): a hybrid key agreement combining
CRYSTALS-Kyber (standardized by NIST as ML-KEM, FIPS 203) with classical X25519,
on top of which the Double Ratchet keeps working — ordinary per-message forward
secrecy.

```
InitialHandshake (analog of X3DH/PQXDH):
  classical_shared = X25519(...)          // as usual
  pq_shared        = ML-KEM.Decap(...)     // post-quantum KEM
  root_key         = KDF(classical_shared || pq_shared)

DoubleRatchet(root_key):
  each message gets a new encryption key,
  the previous keys are destroyed immediately after use
```

**Why a hybrid and not pure post-quantum.** ML-KEM is younger and less
time-tested than ECC — a hybrid requires breaking both algorithms at once, not
just one. This is the current NIST-recommended practice, already proven in
production (Signal, the hybrid TLS configurations of Chrome/Cloudflare).

**Why this solves exactly the stated threat.** Even if the adversary recorded the
ciphertext today, and in 10 years gets a quantum computer that breaks X25519 via
Shor's algorithm — the post-quantum part (ML-KEM) is not based on the discrete
logarithm and keeps the secret. The mechanism works entirely at the
sender↔recipient level, before the message becomes a capsule — the nodes (section
10) did not see the content before and do not see it now, regardless of the
post-quantum upgrade.

**Compatibility with asynchronous delivery is already solved in the original.**
X3DH/PQXDH are specifically designed for the case where the recipient is offline:
the sender uses a prekey bundle published in advance by the recipient — this
naturally fits the same capability exchange between contacts (section 12), and the
recipient processes it on the next connection. The same pattern works for
mailbox/DTN delivery (sections 7.7, 13) — not a new problem for the mesh, but the
same asynchronous agreement that Signal has been using for years for offline
recipients.

**A side effect for padding (section 3.1).** Post-quantum keys and ciphertexts
are noticeably larger than classical ones (a Kyber-768 public key is about 1184
bytes versus 32 bytes for X25519). The initial handshake message on first contact
will be noticeably larger than ordinary messages — a separate, sufficiently
capacious size bucket is needed specifically for the handshake, otherwise its size
itself becomes a fingerprint of "a PQ contact is being established here",
distinguishable from ordinary traffic.

**A separate, not the same, question — the quantum vulnerability of the admission
protocol's signatures.** Ed25519 and the threshold ring signature (section 7.3)
also break under Shor's algorithm, but this is a threat of a different class —
forging an issuer's signature **in the future**, not decrypting already-collected
data today. Confidentiality of past traffic is solved by the PQ-KEM above; future
integrity/authenticity is a separate task of migrating to post-quantum signatures
(e.g. ML-DSA/Dilithium), which remains future work and must not be mixed up with
this section.

**A one-time prekey is ONE unit covering both legs.** A published one-time prekey
carries an X25519 key and its own ML-KEM-768 encapsulation key, signed together by
the owner's identity key. The sender encapsulates against that one-time KEM key
rather than the bundle's long-lived one, and the recipient destroys the unit's seed
on the same commit that consumes the X25519 half — so a recorded first contact
cannot be reopened later from the account's long-lived material. The long-lived
`kem_ek` remains as the last-resort key for a sender who arrives after the batch is
exhausted, and it is NOT rotated; that case is the reported downgrade below, not a
silent one. Keeping the two halves in one unit is deliberate: separate batches can
go out of step, and a per-leg downgrade is precisely what a single unit cannot
express.

**Prekey exhaustion — a DoS attack on the asynchronous-contact mechanism
itself.** X3DH/PQXDH rest on a pack of one-time prekeys published in advance — an
attacker who mass-requests a victim's prekey bundle can exhaust this supply,
forcing a fallback to a weaker mode (the signed prekey and the static KEM key, no
one-time unit) or a refusal of new contacts.

**By which credential exactly — not just any admission token, or a bootstrap
paradox for the first contact.** The first formulation ("the same admission
gating as any other request") did not specify which one — an anonymous
network-wide admission token (section 7.3) proves only "I am a legitimate user of
the network", not "I am this person's contact", and gating with it would mean any
network participant can exhaust any other's prekeys, not only those of their
contacts. The right credential is the same "contact key" (section 2) that is
already issued during a contact exchange (section 12): a prekey bundle request is
gated by the personal capability of a specific contact, not by a network-wide
token. For a stranger who wants to write for the first time, this is the same
pattern already solved for the rest of the network — first an
invitation/capability is needed (section 12), only then can the prekey bundle be
fetched; no separate, weaker public door is created.

A fallback to "only a signed prekey" is also not a silent fallback (the same
principle as section 15): the client must explicitly know that it is establishing
a session in a weakened mode.

### 2.2 Group messages

Section 2.1 describes only the pairwise (1:1) Double Ratchet — but a messenger
without groups is not a messenger, and none of the document's 22 sections
explicitly addressed them, although "mailbox" and "contacts" imply groups
implicitly.

**Why you can't just replicate the pairwise ratchet over N participants.** A
separate Double Ratchet session for each pair of group participants technically
works, but: (a) it does not scale — a group of M participants needs M×(M-1)/2
separate ratchet states; (b) each message is encrypted M-1 times separately,
exploding the traffic and creating M different ciphertexts of the same content —
a pattern distinguishable from 1:1 correspondence even with padding (section 3.1).

**The solution is MLS (Messaging Layer Security, RFC 9420), not Signal Sender
Keys.** MLS is an already IETF-standardized protocol for exactly this task:
scalable group key agreement via TreeKEM (logarithmic, not quadratic, complexity
of updates on adding/removing a participant), with forward secrecy **and**
post-compromise security — a property that Sender Keys (used by Signal for groups)
provides more weakly for the sake of less network load. The document consistently
chooses the stronger, not the more convenient, option (Monero over Lightning, a
threshold ring signature over a simple one) — MLS here is the same choice, not
extra paranoia.

**Post-quantum compatibility — the same solution, not a separate one.** MLS
already has an evolving specification of a hybrid TreeKEM with ML-KEM — the same
post-quantum pair chosen in section 2.1 for the pairwise case.

**An MLS Delivery Service — not new infrastructure, but requires explicit
conflict resolution, not just forwarding.** The first version of this idea assumed
that a decentralized Mix/Mailbox could simply take on the role of the Delivery
Service for free — it did not survive scrutiny: MLS formally assumes that the DS
provides a **total order** of group operations (commits) so that TreeKEM stays
synchronized across all participants. A decentralized network with no single
arbiter (sections 10–12) does not provide such an order by construction. The
solution is not to build a total order but to explicitly adopt the behavior
already existing in MLS for competing commits: if two commits simultaneously
extend the same epoch, all clients apply a deterministic resolution rule, and the
losing commit is discarded and re-sent.

**A "lowest-hash" tie-break is grindable — a participant can iterate over variants
of their commit until they find a guaranteed winner, and silently suppress others'
group operations.** What is needed is not just the "lowest hash" but a value that
cannot be cheaply regenerated. The solution is to reuse the cost of the admission
request already existing in sections 5/7, not to invent a separate anti-grinding
mechanism: the tie-break is computed as a hash of (commit || admission-nonce,
bound to the current quota epoch, section 7). Re-grinding a winning commit
requires obtaining a new admission-nonce on each attempt — and that is exactly as
expensive and rate-limited as any other admission-gated request; grinding costs
the same as a mass attack on the quota, which the document already knows how to
repel.

Mix/Mailbox then indeed requires no new infrastructure — but only on the condition
that clients implement this tie-break and do not assume an order the network does
not guarantee. The price is random extra round-trips on simultaneous group
operations, nothing more.

**Multi-device — not solved by merging 1:1 and groups into one mechanism.** Once
we introduce MLS, there is a temptation to model 1:1 correspondence as a "group of
2" and get multi-device for free (each device is a separate tree leaf). It did not
survive scrutiny: key updates in MLS happen per-commit (a group operation), not
per-message — this is noticeably rarer post-compromise healing than a dedicated
Double Ratchet, where each message advances the DH ratchet. Abandoning the Double
Ratchet in favor of a single MLS-for-everything would weaken the most common use
case (ordinary 1:1 correspondence) for the sake of architectural simplicity. We
keep section 2.1 (Double Ratchet) for 1:1 separate from 2.2 (MLS) for groups —
multi-device for 1:1 is closed by a separate Double Ratchet session for each pair
(sender's device, recipient's device), not by one shared mechanism. Synchronization
between a single user's OWN devices (contacts, read statuses) is a separate task,
still unsolved in this document, not to be confused with message encryption.

**A post-compromise healing delay during a long offline period — an honestly
acknowledged property of the Double Ratchet, not a KARST gap.** Healing requires a
real round-trip: if the recipient is offline for up to 7 days (DTN, section 7.7),
and the sender sends several messages in a row, the ratchet does not update until
the first reply. The same property exists in Signal — it is a limitation of the
primitive, not something solved at the KARST level.

**Group delivery makes someone see the whole participant list at once for the
first time — a stronger metadata leak than in the pairwise case.** A commit has to
be delivered to all M group participants — if this happens in a single operation
"here is the recipient list, send to everyone", some node learns the full group
membership at once for the first time, exactly what section 10 avoids for ordinary
correspondence ("no node should see the source and destination at the same time").
The solution is not new anonymous infrastructure but moving the fan-out to the
client side: the **sender** (not the network) knows the participant list and
performs M independent deliveries, each an ordinary pairwise mailbox drop, routed
through the mix independently (section 10) and spread out in time by the same
jitter/cover mechanism already used for push (sections 3.2, 16.2–16.3) — otherwise
M nearly simultaneous deliveries from one sender themselves become a signature of
"this is a group broadcast". No node still sees the full participant list — it sees
only the same thing as with an ordinary 1:1 message, repeated M times.

## 3. No network fingerprint

```
KARST capsule
      ↓
encryption before transmission
      ↓
a standard external carrier
      ├── HTTPS
      ├── HTTP/3
      ├── OHTTP
      ├── WebRTC
      ├── MASQUE
      ├── local Wi-Fi
      └── Bluetooth
```

An adversary may know the exact internal format of a capsule, but must not be able to
see it inside a protected connection. Encryption alone is not enough — an
application can be detected by packet size, intervals, TLS fingerprint, request
order, the character of re-connections, bootstrap behavior.

**KARST does not implement its own approximate copy of HTTPS.** Each carrier uses
a full-fledged, mass implementation of the external protocol and behaves like an
ordinary user of that protocol. The protection is not a secret signature but the
**absence of a distinct KARST signature**.

### 3.1 Capsule size padding

The carrier level above protects the transport fingerprint, but not the
fingerprint of the content itself: the encrypted blob of a text message, a voice
message, and a file have characteristically different sizes even after passing
through the mix (section 10) — size on its own is a classifying feature if it is
not hidden separately.

A capsule is padded to a fixed set of size buckets before encryption, regardless
of the real content size, up to a set maximum:

```
SIZE_BUCKETS = { 1 KB, 4 KB, 16 KB, 64 KB, 256 KB, 1 MB, ... }
```

Nothing new is invented — the same principle already applied by Signal (padding
messages to fixed lengths before sending). The trade-off is overhead on traffic (a
200-byte message occupies a whole 1 KB bucket), the same "privacy over efficiency"
trade-off already accepted everywhere in this document (mix, cover push, batched
computation).

### 3.2 The statistical shape of traffic, not just signature and size

Section 3 requires using a full-fledged implementation of an external protocol —
but modern traffic-classification systems increasingly classify traffic by its
**statistical shape** (the distribution of packet sizes, burst patterns,
inter-packet intervals) rather than by a fixed signature — documented for
Shadowsocks/V2Ray/obfs4.

**The FTE/Marionette approach was considered and not chosen as the main
solution** (exactly cloning the statistical profile of a specific target
protocol/site). Both have a track record: they were deployed as pluggable
transports for Tor and over time practically exhausted themselves — traffic classification adapted
faster than the complexity of exact cloning paid off.

**The chosen solution is a generalization of an already-existing mechanism, not a
new primitive.** Jitter and cover events (sections 16.2–16.3) already solve this
task at the level of "when to check the mail" — the same principle is applied at
the packet level within a single carrier connection: data is transmitted not as
fast as possible in one burst but at a pace and in portions resembling an ordinary
interactive HTTP session (the same tactic already used by Snowflake/meek — a real
library, the real timings of an ordinary client, not an exact imitation of someone
else's protocol).

**Honestly not solved.** This closes crude, easily automated heuristics but does
not guarantee resistance to advanced ML classification by subtle statistical
features — this is an open research front (the same category as the mentioned
FTE/Marionette), not a solved task. The formulation of the guarantee is as in
section 18: it reduces the probability of automatic classification, it does not
eliminate it entirely.

### 3.3 Deployment diversity and availability

The ideas below concern how independent operators can deploy relays for resilience
and reachability; each was reworked after a first formulation did not survive review.

**Co-location behind widely-used shared infrastructure.** Hosting a relay endpoint
behind infrastructure that many unrelated services already use (for example a common
shared CDN) is a deployment option: an endpoint reached this way is not tied to a
single dedicated address. This is an availability/reachability property, not an
anonymity one — the relay still sees the metadata described elsewhere.

**Multi-provider diversification — buys time and redundancy, not a linear cost.** The
honest formulation: spreading endpoints across independent providers gives (a) time —
each new provider is a separate reachability path; (b) resilience — the network keeps
partially working when a single provider's path becomes unavailable, rather than
failing all at once.

**Carrier rotation — a directed escalation, not a random walk.** Not "change
providers back and forth" but deliberately shifting toward ever more
expensive-to-block infrastructures as the easy options are knocked out one by one
— the same logic already applied to key/epoch rotation (section 7), extended to
the choice of carrier infrastructure as a whole, not only of secrets.

## 4. A capability-gated relay

A relay's public address does not mean any visitor can make it perform KARST
operations. Without the right capability, the server serves a genuine ordinary web
resource, returns a standard HTTP response, or silently drops the request. The
verification algorithm is open, only the capability is secret.

This protects against the scenario: download the code → learn the special request
→ scan the internet → get a list of relays → block them.

A capability is not eternal: a limited validity period, a specific scope of
authority, a request limit, a volume limit, local revocation, regular rotation.
The leak of one capability must not reveal the whole network.

**The "ordinary web resource" must be genuine, not a decoration.** Active probing
is not limited to "is there a response or not" — repeated requests, comparison
with an internet archive, checking the consistency of the content over time expose
a thin 200-OK stub. This is not a protocol requirement (a protocol cannot obligate
a volunteer to maintain a real site) but a recommendation to operators: a cover
service should be genuine and independently useful (a small, really working
tool/service), not a prop — exposure then costs more, because someone's real
infrastructure is at stake, not a prop. The reference relay implementation ships
with a ready, genuinely useful cover service by default, rather than leaving this
work to the operator from scratch.

**The response to a valid and an invalid capability must be indistinguishable in
form and timing, not only in content.** Even behind a genuine cover site, a
difference in timing/size of the response between "has a capability" and "no
capability" is a fingerprint in itself. This is already partly covered by the
early, cheap stages of the admission protocol (sections 5, 7.5) — here it is
explicitly extended to the end: the path "admitted as an ordinary site visitor"
and the path "admitted as a KARST client" must be indistinguishable in externally
observable response time up to the point where this stops being physically
possible (after which the difference is already hidden inside the encrypted
connection).

## 5. DoS protection: the order of admission

The main principle: **an unauthorized request must not force a node to spend
significantly more resources than the sender spent.**

- **Stage 0 — a bounded parser.** A fixed CPU/memory budget, no memory allocation
  based on unverified fields, no unbounded recursion, drops the excess without a
  response.
- **Stage 1 — confirmation of the return address.** A stateless cookie before any
  state is created (details — section 7).
- **Stage 2 — a capability or an anonymous token.** A contact capability, a
  Privacy Pass-like token, an RLN quota proof, a relay voucher.
- **Stage 3 — adaptive proof of work.** Enabled only under overload (difficulty
  rises as the queue fills, falls when idle). Not the only protection: a botnet has
  more compute than victims' mobile devices; PoW is an emergency filter, not the
  main identification.
- **Stage 4 — a bounded queue.** Only after the previous stages does the node
  create session state, verify an expensive signature, access the DB.

## 6. Anonymous rate limiting

IP-based rate limiting is a poor fit (NAT, IP change, a concentration of users
behind one proxy). The quota is tied not to an identity and not to an IP but to an
anonymous right to a volume of work: Privacy Pass (a one-time permission) + an
RLN-like scheme (a bounded series of requests per epoch, a repeat overrun is
detected by the nullifier without revealing the identity).

## 7. The formal admission protocol

### 7.0 Parameters

```
EPOCH_DURATION        = 10 min
COOKIE_TTL            = 30 sec
GRACE_EPOCHS          = 1
MAX_PACKET_SIZE       = 2560 bytes
COOKIE_CHALLENGE_SIZE = 64 bytes (fixed)
```

**On `MAX_PACKET_SIZE` (revised 2026-07-17 — it was 1400 and contradicted this spec's
own Principle 6).** It is a bounded-parse DoS ceiling at admission stage 0, not a link
MTU: the live path runs TCP inside a Noise session, which frames and reassembles, so
there is no 1400-byte wire unit to match. Meanwhile a post-quantum opener cannot fit
1400: an ML-KEM-768 key agreement is ~1.1 KB on its own, so first contact carrying a
message longer than ~120 bytes was being dropped as oversize — silently, with
`DropNoReply`. A spec that mandates post-quantum key agreement AND a ceiling too small
to carry one is inconsistent; the ceiling is the part that was arbitrary. 2560 is sized
from the protocol we actually have: a sealed ML-KEM opener (~1.2 KB) plus a
maximum-length first message (1 KB) plus framing. Ordinary messages are unaffected — they
are ~1 KB — so the extra headroom only exists for the one envelope that needs it.

Two different notions of an epoch:
- a **cookie epoch** — a purely local relay secret, rotated independently, needs
  no network synchronization;
- a **quota epoch** — the window for anonymous rate limiting, computed by each
  participant independently of wall-clock (as in Waku RLN), requiring only weakly
  synchronized clocks, not consensus.

### 7.1 A stateless cookie

```
Cookie {
  version         : u8
  epoch_id        : u32
  client_addr_hash: bytes[16]
  issued_at       : u32
  mac             : bytes[16]   // truncated HMAC-SHA256
}

cookie.mac = HMAC-SHA256(relay_epoch_key[epoch_id],
                          client_addr || carrier_id || issued_at)[:16]
```

The first response to an unverified address is always a fixed 64-byte challenge,
regardless of the request content. The server stores only 2 `relay_epoch_key`
values (the current and the previous) — O(1) in the number of clients.

### 7.2 A capability (invited access)

The relay is itself the issuer of its capabilities, a symmetric scheme, no PKI
needed:

```
Capability {
  capability_id : bytes[16]
  scope         : enum{MESSAGE_DELIVERY, MAILBOX_FETCH}
  quota         : {max_requests, max_bytes, window}
  not_before/not_after : u32
  secret        : bytes[32]
}

CapabilityProof {           // what actually goes over the wire
  capability_id
  epoch_id
  mac: HMAC-SHA256(secret, request_nonce || epoch_id)[:16]
}
```

The `capability_id → secret/scope/quota` table is local to the relay, bounded by
it, not by the attacker.

### 7.3 An anonymous admission token (Privacy Pass-like)

Issuance (off the relay's critical path, at an independent issuer from a set of N):

```
t' = Blind(random_nonce, blinding_factor)
→ the client proves to the issuer the right to a token
  (captcha / history / anonymous payment / attestation)
sig' = Sign(issuer_privkey, t')
sig  = Unblind(sig', blinding_factor)
```

Presentation — **without an explicit `issuer_id`**, a threshold ring signature
over the set of trusted issuers:

```
AdmissionToken {
  ring_sig  : ThresholdRingSignature-over(trusted_issuer_pubkeys, threshold_t, t)
              // "signed JOINTLY by at least t of N",
              // without revealing which ones
  t         : bytes[32]
  epoch_id  : u32
}
```

**Why not an explicit `issuer_id`.** In the original version the token carried
`issuer_id` openly — the relay saw which of the N issuers had issued the token.
Even without collusion between the issuer and the relay this is a leak: if issuers
are specialized by admission path (one for captcha, another for organizational
attestation, a third for payment), `issuer_id` crudely classifies the user's
origin, and the anonymity set narrows to "users of exactly this issuer" rather
than the whole network.

**A clarification — an ordinary ring signature does not cover "2 of 5".** The
first version of this fix replaced `issuer_id` with a flat ring signature ("signed
by one of N") — but just above in this same section a trust policy of the form "1
of 5" **or "2 of 5"** is already fixed, and an ordinary ring signature proves only
that exactly one signer belongs to the set, not "t of N jointly". A **threshold
ring signature** is needed (Bresson–Stern–Szydlo, "Threshold Ring Signatures and
Applications to Ad-hoc Groups", CRYPTO 2002) — an established, not new,
construction generalizing the ring signature to an arbitrary threshold t: the
relay verifies admissibility without narrowing anonymity to a subset, and the
`threshold_t` parameter covers both "1 of 5" and "2 of 5" with the same primitive,
just with a different t.

It is more CPU-expensive than a single Ed25519 verification, and grows with t —
this is already accounted for by the check order of section 7.6 (the signature is
not the cheapest step).

**A finding surfaced by the attempt to implement it (impl/admission, §7.3).** A
survey of the Rust ecosystem before implementation revealed two facts not visible
in a prose audit:

1. **There is no ready, vetted implementation.** A Bresson–Stern–Szydlo threshold
   ring signature does not exist in Rust; all available ring crates are 1-of-N (the
   Monero family: SAG/bLSAG/CLSAG/MLSAG), they do not cover "2 of 5". Threshold
   crates of the FROST family give "t of N", but are NOT anonymous (the signer set
   is not hidden) and require distributed key generation with a shared group key —
   a different trust model than an ad-hoc ring of N independent issuers. Neither
   fits §7.3.

2. **BSS itself is not algebraically compatible with the KARST stack.** The
   original Bresson–Stern–Szydlo is built on Rivest–Shamir–Tauman ring signatures
   over RSA/trapdoor permutations. The rest of KARST's crypto stack is
   Curve25519/Ed25519 (§2.1, §7). "Naming BSS" ≠ "this primitive composes with the
   rest": literal BSS would drag in RSA parameters, separate from everything else.
   So the correct specification here is **not literal BSS but a curve-friendly
   threshold ring construction** over the same group (discrete-log versions of
   threshold ring signatures exist in the literature), compatible with the already
   used primitives.

**A web survey (July 2026) confirmed the gap.** There is no ready production
implementation of a threshold (t-of-N) ring signature in Rust or in any other
language — this is not a peculiarity of the Rust ecosystem but an objectively
narrow niche:
- 1-of-N rings exist (jimouris/ring-signatures on Ristretto, MIT;
  rot256/research-stacksig on Ristretto, but **GPLv3 + "not for production"**;
  Monero CLSAG/MLSAG, BSD-3) — they do not express a threshold;
- threshold Schnorr (FROST, RFC 9591) is mature, but not anonymous;
- actual threshold *ring* signatures exist only as academic constructions with
  benchmarks, without a maintained open repository: "Count Me In! Extendability for
  Threshold Ring Signatures" (Aranha, Hall-Andersen, Nitulescu, Pagnin, Yakoubov,
  PKC 2022) — on the discrete logarithm; "Threshold ring signature: generic
  construction and logarithmic size instantiation" (Cybersecurity, 2024);
- DualRing/DualDory — on bilinear pairings, not compatible with Curve25519.

**The chosen path (reliability over speed).** We build a threshold layer on top of
the already-used, audited `curve25519-dalek` (Ristretto), with the CDS technique
(Cramer–Damgård–Schoenmakers): an OR-composition of Schnorr proofs with a "t of N"
threshold via Shamir-splitting the challenge (Shamir-in-the-exponent). This is a
discrete-log construction compatible with the Ed25519 stack (unlike RSA-BSS),
anchored to ETRS (Aranha–Pagnin) as a reference. GPLv3 code is not taken as a
dependency (copyleft impedes embeddability and broad embeddability — §1); only
a permissive base.

**Status until an independent audit.** "More reliable" for a security-critical
primitive ultimately means an independent audit, which does not yet exist. So the
implementation of the threshold layer ships **feature-gated** (off by default),
explicitly marked "reference, not for production", and the weight is carried by
**adversarial** tests (t−1 signers → verify must fail; a forgery → fail;
unlinkability of one set's signatures over different messages). In the main §7.3
path, until an audit, an `AdmissionTokenVerifier` trait + a non-crypto mock remain.

A separate recommendation to issuers: do not specialize by admission path (each
issuer supports all paths — captcha, attestation, payment) — a ring signature
hides which issuer signed, but does not help if issuers have different admission
policies and this is somehow traceable through side channels (issuance time, token
volume per issuer).

No issuer should know on which relay a token was used, to whom a message is sent,
the user's route, or the time of subsequent use.

### 7.4 RLN-like quota

```
RLNProof {
  epoch_id
  external_nullifier = Hash(epoch_id || relay_scope_id)
  nullifier           = Poseidon(identity_secret, external_nullifier)
  a1                  = identity_secret + message_hash * a0   // a Shamir share
  zk_proof
}
```

Not a preventive block but an economic punishment: two different nullifier
presentations of one `identity_secret` in one epoch with different `message_hash`
allow recovering `identity_secret` from the two `a1` → a quota violator is
deanonymized automatically.

**A correction surfaced by the reference implementation (impl/admission, §7.4).**
The record above leaves the slope `a0` of the sharing line **undefined**, and
defines `nullifier` as `Poseidon(identity_secret, external_nullifier)` — but that
is exactly the formula by which standard RLN computes the *slope*, not the
detecting nullifier. If you follow the standard slope derivation
`a0 = H(identity_secret ‖ external_nullifier)`, it coincides with the `nullifier`
published here — i.e. the slope turns out to be public. Then, having the
`nullifier` and **one** share `a1`, anyone computes
`identity_secret = a1 − message_hash · a0` from a single message: deanonymization
happens on the first message, not on a repeat, and the property "only overrunning
the quota is punished" breaks. The slope must remain secret; for repeat detection a
**separate** tag is needed, not equal to the slope. The correct construction (as in
standard RLN): `a0 = H(identity_secret ‖ external_nullifier)` — the secret slope;
`nullifier = H(a0)` — the hash of the slope, not the slope itself (non-disclosure
of the secret from one share rests on the preimage resistance of this hash). The
discrepancy was not visible in a prose audit (the formula "sounded" consistent) and
surfaced only when trying to implement the field arithmetic; the implementation
takes the correct variant.

### 7.5 The full order of checking an incoming request

```
Stage 0  bounded parse
         a fixed budget, reject without allocating memory by an
         unverified length, no response

Stage 1  cookie
         no valid cookie → a response of exactly 64 bytes, state NOT created
         a valid cookie → onward

Stage 2  credential format
         a structure check without crypto → reject garbage for free

Stage 3  replay/freshness
         a bounded Bloom/cuckoo filter, tied to the quota epoch,
         reset on epoch rotation
         (filter overflow = a signal for the adaptive PoW)

Stage 4  expensive cryptography, in ascending order of cost:
         1) Capability HMAC (cheapest)
         2) Admission token signature (Ed25519/VOPRF)
         3) RLN zk-proof (most expensive, enabled when the first two are
            unavailable and given the current PoW difficulty)

Stage 5  bounded session state (LRU, a hard ceiling) →
         handoff to Mix/Mailbox/Egress (section 10)
```

Memory at each stage grows only in proportion to the already-verified legitimate
load.

### 7.6 The check order by CPU cost (the general principle)

```
1. length and version
2. stateless cookie
3. a fast MAC
4. an expiry and replay-filter check
5. admission token
6. a signature or ZK proof
7. decryption
8. storage or routing
```

Additionally: checks have a CPU budget; proofs are verified in batches; repeated
invalid requests are temporarily rate-limited; separate worker pools separate
different operations; overflow of one pool does not block the rest; a relay has
circuit breakers.

### 7.7 The DTN admission class (a store-and-forward mesh)

The live class (7.1–7.5) does not fit a Bluetooth/Wi-Fi Direct offline mesh:
delivery may take days, `epoch_id` goes stale, and stretching the replay filter
over many epochs "in reserve" breaks the bounded-memory guarantee of Stage 3.

**The key difference in the threat model.** On a live transport the attacker is a
remote botnet attacking the server; the cookie (7.1) protects precisely against
address spoofing and amplification. In a mesh the connection is physical, over a
Bluetooth pair or Wi-Fi Direct; you cannot spoof a third party's address over such
a link. The real threat is different: a neighbor over the air floods someone's
carrier phone with garbage, draining its battery and clogging its memory. So the
mesh protects not the server but the carrier device, and does so locally, without
network state.

The solution is **not** to reuse epoch-based RLN/cookie, but to introduce a
separate admission class with two independent mechanisms.

**1. A DTN capability** — a separate type, without epoch quantization:

```
DTNCapability {
  capability_id : bytes[16]
  issued_at     : u64                 // unix seconds, without quantization
  not_after     : u64                 // issued_at + up to MAX_DTN_TRANSIT_TTL
  scope         : MESSAGE_DELIVERY
  quota         : { max_bytes, max_hops }
  secret        : bytes[32]
}

MAX_DTN_TRANSIT_TTL = 7 days   // a placeholder parameter, needs
                               // calibration against real measurements
                               // of mesh-delivery latency
```

**`max_hops` — an advisory field, not cryptographically enforced.** Honestly:
nothing ties the decrement of this field to the real number of transfers — the
current carrier of a capsule physically owns all of its state and may not
decrement or may reset the counter on forwarding. A strict cryptographic version (a
hash chain where each hop must reveal the next preimage) does not work here: it
requires the sender to distribute exactly N preimages to specific future carriers
in advance, and in a mesh carriers are met opportunistically and are not known in
advance. The real protection is not `max_hops` but the `LocalCarryBudget` below:
the device controls only its own decision whether to accept/carry someone else's
capsule further, and that decision is really verifiable because it disposes of its
own resource. A pair of dishonest devices bouncing a capsule at each other harms
only their own batteries — it cannot force THIRD-PARTY devices to participate
beyond their own `LocalCarryBudget`. `max_hops` is kept as advisory metadata for
honest clients (the same category of honesty as the replication of section 13 —
only there it is additionally verified by the admission quota on the live
transport, and here there is nothing to verify it with).

**The rule for choosing a token class — on the sender side.** A client queuing a
message via the "Emergency" profile (section 15) must request a DTNCapability, not
reuse a live-class admission token. No post-facto detection/conversion of the token
is provided — if a message was not originally intended for the mesh, and the live
epoch expired in transit, it is simply dropped as expired.

**2. A local per-hop budget** — not part of the admission protocol but a local
policy of each carrier device, requiring no network agreement:

```
LocalCarryBudget {
  per_peer_max_messages   // a sliding window on the local clock, e.g. 24h
  per_peer_max_bytes
  local_pow_difficulty    // adjusts to its own battery/memory state,
                          // not to the network's global load
}

DeviceCarryBudget {
  total_max_messages_per_window   // aggregate across ALL peers, not per peer
  total_max_bytes_per_window
}
```

PoW here does not protect against spoofing (in a mesh spoofing is impossible) — it
is a pure local throttle: how fast an unknown peer can flood you with data in one
contact session.

**A per-peer budget alone is not enough.** A Bluetooth/Wi-Fi Direct identity is
cheap to recreate (unlike the ASN diversification of section 11) — an attacker,
staying under the `per_peer_max_messages` threshold with each separate ephemeral
identity, can in aggregate still clog the device with many "new" peers in turn.
`DeviceCarryBudget` is a mandatory second ceiling: the total spend across all peers
per window, regardless of how many different identities created it. The per-peer
budget limits one pushy neighbor, the device-wide budget limits a Sybil of many
cheap identities.

**3. A final check on return to the network.** When a capsule carried through the
mesh finally reaches an online ingress node, it holds a replay-protection table
**separate** from the live class — not an epoch swap (the whole filter is reset at
the epoch boundary, as in 7.5) but a **rolling window**: N daily buckets, each
record expiring by its own `not_after`, the oldest bucket freed and reused once a
day.

This stays bounded in memory not because the window is short but because the
physical volume of mesh traffic (data carried by people) is orders of magnitude
smaller than the volume of live internet traffic over the same time — a table for a
7-day window at low mesh throughput is cheaper than a table for a 10-minute window
at full internet scale.

**Open in this solution:** the specific value of `MAX_DTN_TRANSIT_TTL` — a
temporary parameter (7 days), needs calibration against real latency measurements;
the local per-hop budgets are deliberately heuristic and give no network guarantee
(acceptable, since DTN is a best-effort emergency mode, not the main path).

## 8. Open questions (a development backlog) — history

All six original backlog items are solved and moved into the main text: 7.7
(mesh epochs), 16 (push), 19.1 (operator legal considerations), 19.2 (infrastructure reward), 12.1
(bootstrap), 12.2 (app distribution). This section is left empty deliberately — as
a log of the fact that there was a working entry point for elaboration here; see
section 20 for the history of decisions.

## 9. Comparison with existing projects (as of July 2026)

A complete solution — a messenger + open source + no enumerable list of nodes +
resistant to state-level blocking + makes blocking economically devastating +
protected from anonymous DoS/Sybil + works over Wi-Fi/Bluetooth without the
internet — was not found. Almost every element is already implemented separately:

| Project | Provides | Does not provide |
|---|---|---|
| Tor + Snowflake + WebTunnel + Conjure | The most developed network-level blocking resistance, refraction inside ISP networks (>1M users) | It is a transport, not a messenger; there is published research on enumerating Snowflake proxies and fingerprinting |
| Waku | Relay, temporary storage, Lightpush, RLN | Not dissolved into ordinary HTTPS, no ISP refraction, no Bluetooth/Wi-Fi |
| Nym | An open mixnet, a gateway as a temporary mailbox, economic node incentives | A separate network with recognizable behavior, no local mode |
| Briar | A ready messenger with no central server, Tor + Wi-Fi + Bluetooth + removable media | At a distance it depends on Tor, no multi-transport/refraction/anonymous quotas |
| SimpleX | No global IDs, temporary relays, one-time invitations, open source | Server addresses are blockable, no refraction/mixnet/DTN |
| Session | Distributed storage, onion routing, a stake per node (the price of Sybil) | A recognizable transport of its own, an adversary need not touch the rest of the internet |

Closest to the main goal is **refraction networking**: hiding individual proxies is
not enough (everything a user finds, an adversary finds too), so proxying is moved
inside the networks of cooperating ISPs — blocking requires excluding whole
external networks.

KARST is not an invention of new cryptography but a first attempt to combine:

```
SimpleX-like private queues
        +
Waku-like transport and anonymous RLN rate limiting
        +
Nym-like mixnet and metadata protection
        +
Tor/Snowflake-like temporary entry nodes
        +
Conjure/refraction (as an external plugin, not infrastructure of its own)
        +
Briar-like Bluetooth/Wi-Fi delivery
        +
a single session independent of the transport
```

## 10. Splitting the relay by function

```
Ingress  — verifies the address and the admission token
    ↓
Mix      — shuffles and forwards capsules
    ↓
Mailbox  — temporarily stores capsules
    ↓
Egress   — connects to another transport
```

No node should at the same time: see the source IP, know the mailbox token, store
the message, know the next final route, issue network tokens to the user (the model
is analogous to Oblivious HTTP: the relay sees the client but not the content; the
gateway processes the request without seeing the IP).

The DoS consequence: overloading the mailbox does not stop ingress; an attack on
the issuer does not destroy already-issued tokens; overloading one carrier does not
break the cryptographic session; the collapse of the mix does not destroy the
storage.

**The return of a DTN capsule (section 7.7, point 3) enters through the same
Ingress, not a separate path.** This was nowhere stated explicitly: the pipeline
above is described only for the live transport. Ingress must distinguish the
credential type at Stage 4 (sections 7.5/7.6) — a fourth branch of expensive
cryptography is added alongside Capability HMAC / admission token signature / RLN
zk-proof: DTNCapability HMAC, with its own rolling-window replay protection (section
7.7, point 3) instead of the live class's epoch-swap filter. No separate "DTN
gateway" node is set up — the same Ingress branches by the type of presented
credential, not by the type of transport the capsule physically arrived over.

## 11. Sybil protection

The number of network identifiers means nothing in itself (10,000 nodes may belong
to one attacker). Independence is assessed by observable resources: different
autonomous systems, different IP prefixes, different operators, different transport
types, different jurisdictions, independent issuers, availability history, measured
(not claimed) throughput.

Route-concentration limits: no more than one relay from one /24, no more than one
relay from one ASN, no more than two relays from one operator, no more than one
relay from one issuer class. The full route is chosen by the client from several
independent sources of descriptors — the relay does not itself propose the next
hop.

## 12. Discovery without a global list

A mixed model:
- a **public part** — high-performance relays, commercial privacy gateways,
  volunteer entry nodes, designed for mass load;
- a **limited-distribution part** — descriptors through contacts, invitations, the
  social graph, an already-established encrypted channel, in small random samples
  with a short TTL;
- a **private part** — a personal capability to a relay from a contact (endpoint +
  expiry + quota + capability + transport profiles + public key).

The leak of one descriptor damages only a small part of the routes and only until
it expires. The secret is a specific temporary access right, not the distribution
algorithm (which is open).

### 12.1 Bootstrap for a user with no contacts

The section above does not answer: where does the *first* descriptor come from for
a person who does not yet have a single contact in the network? Any single public
entry point recreates an enumerable directory — the same central-list problem this
section exists to avoid, now at the entry point.

**A fundamental asymmetry that cannot be removed, only made more expensive.** At
the moment of the very first contact with a new pseudonym there is no way to
distinguish a genuine new user from an automated probe — both look the same: a
new account with no history, requesting bootstrap material. No open network solves this
with one technique; the robust approach is a portfolio of independent channels,
each with its own cost of compromise. KARST follows this rather than inventing a
new mechanism.

**1. Splitting the public pool into independent buckets.** Public descriptors (section 12, "the public part") are split into many
independent subsets, handed out through different, uncoordinated distribution
channels. The compromise of one channel burns only its bucket, the rest keep
working. Since there is no central operator, the split is not coordinated by a single
authority — it arises organically from different independent volunteers
holding different subsets. The protocol fixes only the format and the issuance
rules, not the distributor itself.

**2. A diversity of handout channels, not one "right" way:**
- **In-person offline handoff** (a QR code, a physical meeting) — the most
  expensive channel for an adversary, naturally limited in scale;
- **A request via an autoresponder on a mass platform** — availability rides on
  shared, widely-used infrastructure, the same principle as in section 3;
- **A request built into the client** — uses the already-existing multi-carrier
  Path Manager (section 15),
  requires nothing manual from the user;
- **Offline handout** — printed materials, sneakernet, an auxiliary
  channel, not part of the protocol core.

**3. Reputation against an automated actor pretending to be a new user.** Since
a fresh pseudonym cannot be told apart on first contact, each new pseudonym gets a deliberately
reduced bootstrap set, and trust is grown only from the observed result:

```
BootstrapBucket {
  bucket_id
  distribution_channel   // e.g. "qr:physical", "email:autoresponder",
                          // "carrier:domain-fronted"
  descriptors[k]          // a small random subset, k ~ 3–5
  issued_at
  ttl                     // short, days, not months
}

BootstrapTrust[requester_pseudonym] = {
  bucket_id_given
  still_reachable_after(T)   // observed externally: did the descriptors survive issuance
  credit                     // grows if they survived; reset to zero if the
                              // issued descriptors stopped working soon after
                              // issuance — a leak signal
}
```

An account whose descriptors regularly stop working soon after receipt loses credit
and gets ever more reduced buckets on subsequent requests — this does not identify
the actor but probabilistically limits the damage from each compromised or automated
account, denying it scalable access to large buckets.

**Who exactly checks `still_reachable_after` — different mechanisms for the public
and the private layer, not one shared answer.** Independent reachability monitoring can measure whether
**known, cataloged** public targets are reachable. This suits the **public layer** (section 12, large
relays that can in principle end up in someone's measurement catalog) — but does
not solve verification for a **private bootstrap bucket** handed to one specific
user: by construction no one but the recipient knows this descriptor set exists,
and such monitoring cannot test what is not in its list of targets.

So for the private layer `still_reachable_after` remains a **client self-report**
("I managed to connect through the issued descriptor") — this is an admittedly
gameable signal (a dishonest recipient may lie either way), but it is the only
available data source for by-construction secret descriptors, and precisely for
that reason the implementation must not overestimate its reliability: `credit`
grows slowly and over many independent reports, not on a single "all ok" message.
Such monitoring is used only where genuinely applicable — for the public
layer, not as a replacement for the self-report of the private one.

**A separate risk category: a compromised distributor, not only a hostile
requester.** Point 3 closes the case "an adversary pretends to be a new user" — but not
the case "a distribution channel is itself compromised". In that case the whole bucket and all the requesters'
metadata are visible to the compromised distributor directly, with no need for a
reputation attack — this is a more dangerous, not a weaker, case. The only
available mitigation is the same channel diversification from point 2: an explicit
recommendation to the client never to rely on a single distribution channel if it
is possible to get bootstrap material from several independent sources at once and
take the intersection/majority. This does not eliminate the risk but reduces the
chance that the single source the user used is the compromised one.

**4. Reusing the trust graph — the third time, but not the raw edges.**
`BootstrapTrust` uses the same contact/capability graph structure as the
limited-distribution part (section 12) and Level 1 of the economic incentive
(section 19.2). Three functions on one graph is compact but naive: reusing the same
edge/identifier for three different tasks means that an observer of ONE function
(e.g. an operator seeing the `RelayReceipt` flow) gains partial visibility into the
structure of the same graph that section 12 protects as private precisely because
it reveals contacts. This is the same as reusing one cryptographic key for
different purposes — only at the graph level, not the key level.

The fix is **derived, unlinkable identifiers per function** from one trust root,
not shared edges:

```
ContactRoot = a shared secret, established during a contact exchange (section 12)

discovery_id = KDF(ContactRoot, "discovery")   // for section 12
bootstrap_id = KDF(ContactRoot, "bootstrap")   // for BootstrapTrust
credit_id    = KDF(ContactRoot, "credit")      // for LocalCreditLedger
```

Each function sees only its own derived identifier — computationally unlinkable to
the identifiers of the other functions of the same contact pair, even under full
compromise of visibility into one of the three. This is not a new construction: the
same principle of separating keys by purpose already used by Double Ratchet/X3DH
(separate keys from one root for different purposes) or BIP32 (hierarchical derived
keys per wallet). KARST does not invent a new primitive — it applies a
domain-separated KDF to what used to be one raw identifier across all three
subsystems.

**5. A bootstrap capability is always weaker than an ordinary one.** The first
descriptor set received is deliberately low-scope: a short TTL, a small quota, a
limited set of relays (the principle of section 4 applied to the first contact).
Even if an adversary mass-collects the whole bucket of one distribution channel, the
blast radius is limited to low-value, short-lived descriptors — real permanent
access comes from the private layer (section 12), reachable only after the user has
real contacts.

**Not solved, but made more expensive.** This is a deliberately accepted position,
not a claim of a complete solution — consistent with section 18: the first-contact
asymmetry is fundamental, the portfolio of independent channels and reputational
throttling raise the cost of a mass attack but do not make it impossible.

### 12.2 App distribution across independent channels

An adjacent but separate problem: 12.1 solves how to get network access if you
already have it. Here the question is earlier — how to get the app itself
without depending on any single distribution channel remaining available. No single
channel is guaranteed to stay available everywhere, independent of who publishes it.

**The trust anchor is an already-existing mechanism, not a new one.** Since there
must be many distribution channels and none is universally recognized as official,
the user needs a way to verify that a binary downloaded from anywhere corresponds
to the published code — this is exactly what section 14 already introduces
reproducible builds and threshold maintainer signatures for. The 12.2 solution is
not to invent a new trust mechanism but to explicitly extend the existing one to a
diversity of channels: don't trust the channel, verify the build hash against what
is published and signed by independent maintainers.

**Channel diversification — the same bucket-splitting principle as in 12.1,
applied to the binary:**
- official stores (Apple App Store, Google Play) — the best UX, but a single point
  of dependence;
- **F-Droid** — an independent open repository, naturally compatible with the
  reproducible-builds requirement of section 14;
- direct APK download from **several independent mirrors** — with no single
  canonical domain, the same multi-mirror logic long used by open-source projects
  for availability;
- releases on GitHub/GitLab — another independent channel that adds resilience;
- the same offline/QR/sneakernet channels already established in 12.1 for bootstrap
  descriptors — the APK file is distributed by the same portfolio of channels as
  network invitations, a third reuse of one idea instead of new infrastructure for
  each task.

**iOS — a separate, heavier sub-strategy.** Apple's ecosystem does not allow
sideloading without a jailbreak comparable to Android's:
- **A PWA (Progressive Web App)** — does not depend on the App Store at all, is
  installed via the browser, but cannot provide raw access to Bluetooth/Wi-Fi Direct
  for the DTN mesh (section 7.7) — suitable as a lite client with basic delivery, not
  a full-featured replacement;
- **TestFlight** — a temporary crutch: a 10,000-user limit per app, and Apple can
  remove the app from there too;
- **Enterprise/ad-hoc certificates** — a historically working but fragile channel:
  Apple has revoked such certificates before on discovering off-label use (example —
  the Facebook Research app, 2019); not considered a main channel, only a tactical
  one;
- under the EU DMA, Apple is already obliged to allow alternative stores and
  sideloading — this shows the technical capability exists in iOS and is limited by
  policy, not architecture; worth tracking, not building into the plan.

**Self-update via its own transport, not via a store.** If the app is already
installed (by any of the channels) and a given store channel later becomes
unavailable, it can keep getting updates via its own multi-carrier transport (section 15),
verifying each update against the same reproducible-build + threshold-signature
scheme (section 14) — not depending on the continued cooperation of a specific
store. **A platform limitation:** iOS does not allow apps from the App Store to
download and execute arbitrary code on their own, bypassing Apple's own update
mechanism — this works for Android/F-Droid/APK builds but not for an iOS build
distributed through the official store while it remains there.

**What is not solved but acknowledged as a section-18 limitation.** If a device is
placed under full external control (a managed, locked-down device with an app
allowlist), no distribution-channel diversification will help — the same limit
already fixed in section 18 for the whole architecture. Losing a specific mirror or
repository is possible like any other resource — diversification raises the cost of
losing availability, it does not make it impossible.

## 13. Storage and CPU protection

```
StorageEnvelope {
    fixed_max_size
    expiry
    mailbox_capability
    quota_proof
    encrypted_payload
}
```

A maximum capsule size, a maximum TTL, a maximum volume per capability, a total
mailbox limit, a ban on indefinite renewal, **immediate** deletion right upon
confirmation of delivery (not only on TTL expiry — the TTL remains protection in
case a delivery confirmation never arrives), deduplication, erasure coding instead
of full copying of large files, the size checked against actually received data
before decryption.

**What this deletion solves and what it does not.** Immediate deletion after
delivery reduces exposure to compromise of, or a legal demand against, a specific mailbox operator —
if the data is already off the disk, there is nothing to hand over. This is **not**
protection against harvest now, decrypt later (passive recording of traffic on the
wire, independent of node storage) — that threat is solved at the level of the
content encryption itself, see section 2.1. These are two different mechanisms
against two different adversaries, not interchangeable.

Replication must not become a DoS amplifier: a capsule is copied to N nodes only if
the admission token debits N storage units in advance. An ordinary message: 2
copies + 1 spare. An important one: 3 of 5 erasure-coding fragments.

**"Immediate deletion after delivery" must reach all replicas, not only the one the
recipient fetched from.** If the recipient fetched the message from copy #1, copies
#2 and #3 do not by themselves know delivery happened — without an explicit
mechanism they sit until TTL expiry rather than being deleted immediately as stated
above. The recipient, having successfully decrypted the message, signs a delivery
receipt and broadcasts it over the same set of replicas (the same list of nodes
that took part in replication/erasure coding) — only after this does deletion
become truly immediate for all copies, not just one.

**Fragment placement must obey the same concentration limits as route selection
(section 11).** Otherwise 3 of 5 fragments may physically end up in one ASN/at one
operator — a single block of that ASN destroys the message's availability despite
the formal erasure-coding redundancy. The nodes for fragments are chosen with the
same limits: no more than one from a /24, no more than one ASN, no more than two at
one operator (section 11) — erasure coding gives resilience to node loss only when
node loss is uncorrelated.

Checked and NOT extended to `CreditOnion` (section 19.2): at first glance the same
limit seemed applicable to the choice of hops for transitive credit too — but
`CreditOnion` hops go along the social graph of contacts (who knows whom), not
freely chosen from a pool of infrastructure, so diversification by ASN/jurisdiction
is inapplicable to them the same way it is to erasure-coding nodes or relay
selection. The only honest thing that can be said about the privacy of `CreditOnion`
— it is meaningful for paths of 3+ hops; for paths of 1–2 hops (a close contact) it
degenerates almost to the already-accepted bilateral case (section 19.2, Level 1) —
this is a path-length limitation, not a diversification one, and is not removed by
the protocol.

## 14. Protecting the control layer

Publishing a descriptor, changing routes, issuing tokens, updating software,
revoking keys, changing PoW parameters must not go over the same channel as user
capsules. Needed: signatures from several maintainers, a threshold signature for
critical changes, a transparent release log, a delay before accepting a critical
update, rollback, independent implementations, reproducible builds.

The preferred policy (a governance parameter, not a protocol one):
```
ordinary release: 2 of 5 signatures
emergency cryptography change: 4 of 7 signatures
trust-roots change: manual user confirmation
```

No single key should let its holder silently update all clients.

**A signature threshold protects against remote hacking, not physical coercion.**
The "2 of 5" / "4 of 7" model assumes an attacker who hacks or steals keys
remotely. But the whole document's threat model (section 1) includes an adversary capable of
physically detaining and coercing a specific person. If the threshold holders are
known and findable, the number of signatures on its own does not protect — such an
adversary can detain a threshold-sufficient number of maintainers at once. The protection here
is not a larger threshold but the same principle of infrastructure diversification
already applied to routes (section 11) and to the decision not to set up a legal
entity (section 19): the key holders should be distributed across different
jurisdictions and, where possible, unknown/pseudonymous as a group — otherwise the
signature threshold protects against the wrong adversary.

**"Independent implementations" — a correlated blind spot if written by similar AI
systems.** Section 19 fixes that core development is done by AI. The requirement of
"independent implementations" above assumes that different implementations check
each other, finding errors the first one missed. This stops working if the
independent implementations are written by the same or similar AI models — a shared
training history means shared blind spots to the same classes of vulnerabilities,
"independence" is then formal, not real. Requirement: independent implementations
must use **different AI systems/vendors**, and the critical threshold-signing gate
(an emergency cryptography change, a trust-roots change) requires human, not only
AI-assisted, review.

A separate consequence of the same fact: if AI removes the need for a large staff
of human engineers (section 19), this does not mean the pool of key holders will
naturally appear on its own — previously one could assume that among the people
involved in development there would be enough candidates for a jurisdictionally
diverse signature threshold above. The key-holder pool is a separate, deliberate
task of recruiting/attracting people, not a derivative of who writes the code (of
which there may be almost none).

## 15. The transport layer (Carrier / Path Manager)

```
KARST messages
        ↓
an independent protected session
        ↓
Path Manager — selecting and combining routes
        ↓
Transport Adapters
 ├── direct TCP / QUIC
 ├── SOCKS5 (TCP CONNECT + UDP ASSOCIATE)
 ├── HTTP/HTTPS CONNECT
 ├── MASQUE (CONNECT-UDP, CONNECT-IP)
 ├── Tor (via SOCKS)
 ├── I2P
 ├── pluggable transports (an interface, not an implementation of its own)
 ├── refraction networking (external, not its own)
 └── local Wi-Fi / Bluetooth
        ↓
The operating system
        ↓
possibly a system-level WireGuard/OpenVPN/IPsec (transparently, KARST does not know)
```

The adapter contract:

```
TransportAdapter {
    probe(configuration) -> Capabilities
    connect(destination, policy) -> Channel
    listen(policy) -> OptionalListener
    health() -> HealthState
    migrate(session, new_path)
    close()
}

Capabilities {
    stream, datagram, inbound_connections, ipv4, ipv6, remote_dns,
    multiplexing, max_packet_size, estimated_mtu, authentication_types,
    metered_network, anonymity_class, reachability_class
}
```

For each route a failure class is stored (not two SOCKS proxies at one provider —
not two independent routes):

```
Path { transport, provider, ASN, jurisdiction, protocol_family,
       endpoint_family, privacy_properties }
```

**No silent fallback** — a critically important rule. A dangerous mistake: "Tor did
not connect → the app silently went direct → the IP was revealed". User profiles:

```
Normal     — direct → proxy → alternative proxy
Private    — only allowed proxy/VPN, a direct connection is forbidden
Anonymous  — only Tor/mixnet/refraction, no direct fallback
Emergency  — all pre-approved channels, including the mesh
```

Privacy rules take priority over availability.

**An important caveat about "Emergency".** This profile maximizes availability at
the cost of privacy — which means switching to it must not be something that can be
triggered by coercing the device owner ("unlock and turn it on"). Switching the
profile must not itself be distinguishable from the outside as "this session is
under coercion" — see section 20, where entry under coercion is analyzed as a
separate mechanism that does not intersect with this profile.

Third-party transports are isolated in separate sandbox processes and receive only
encrypted capsules — not the message content, not contact keys, not the address
book, not the list of other transports.

DoS protection is preserved over a VPN/proxy: cookie, capability, admission token,
and quota are presented even after tunneling — otherwise an attacker bypasses the
limits through a thousand free VPNs.

**Encrypted Client Hello (ECH) is mandatory for HTTPS/HTTP3/MASQUE adapters.**
Without it the whole point of carrier transport encapsulation (section 3) does not work in
practice: even sitting on one IP with a thousand other domains behind a shared CDN,
the TLS ClientHello by default reveals the SNI in the clear — an adversary blocks by the
specific SNI value surgically, without affecting other sites, regardless of how well
the rest of the traffic is hidden. Large CDNs (e.g. Cloudflare since 2023) deploy
ECH such that the external, network-visible `public_name` is shared across all the
CDN's clients rather than an individual domain, which is structurally more robust
than classic domain fronting, not a crutch on top of it.

A known and accepted limitation: an adversary can block the very use of ECH/QUIC
(already happened — some national networks have interfered with ESNI/ECH connections). This is
not a defeat of the strategy but exactly its goal — the adversary is forced to block
ECH for all the CDN's users at once instead of surgically blocking one domain, i.e.
moves from a cheap targeted strike to an expensive mass one.

**No silent fallback to a plaintext SNI.** If ECH is unavailable for the chosen
carrier (no config, a negotiation failure), the Private/Anonymous profiles (see the
profiles above) must not silently send the SNI in the clear — the same "no silent
fallback" principle already established in this section applies here too: a carrier
without ECH in these profiles is either not used at all or requires the user's
explicit consent.

Adapter priority for the first version: system network/VPN → SOCKS5 → HTTP(S)
CONNECT → HTTP/2/3 → MASQUE CONNECT-UDP → CONNECT-IP → Tor via SOCKS → a universal
plugin interface → WebRTC/temporary proxies → refraction networking → I2P and
special plugins → chains and multi-path.

## 16. Push notifications and metadata

The problem: an app on iOS/Android is almost obliged to use APNs/FCM for background
delivery — otherwise the OS kills the background process and instant delivery is
impossible. The push provider then always sees which device received a push and
when. This is not a hypothetical risk — there are documented cases of push tokens
being requested from Apple/Google by law enforcement for deanonymization. Push is
mandatory for UX but must be treated as an untrusted external channel with
metadata, not as part of the core.

**What the push channel does not protect — explicitly.** The jitter, batching, and
cover push below do not hide from Apple/Google themselves the fact "device X
received a push at moment t" — they always see this, it is their delivery channel.
The protection is aimed at a **third party** correlating "the sender pressed send at
t1" with "the recipient received a push at t2" through subpoenas against the mailbox
operator and the push provider separately. This is a limited guarantee, not a
complete solution.

### 16.1 An emptied push

The only thing that ever passes through APNs/FCM:

```
PushRegistration {
  device_push_token   // an APNs/FCM token, opaque to KARST
  rotation_epoch       // periodic re-registration, independent of
                        // the quota epoch of section 7
}

PushWakeSignal {
  wake_nonce: bytes[16]   // fresh random, not linked to the mailbox_token
                           // or capsule content
}
```

On receiving a `PushWakeSignal`, the client always performs a full mailbox fetch
via a separate KARST transport (section 15) — the push never carries the content or
metadata of a message, only the fact "check the mail".

### 16.2 Batching with time quantization (a tick)

Per-message jitter helps weakly — if an event is singular, a delay shift creates no
uncertainty about who the sender is. The protection works only when several
independent events merge into one indistinguishable window. So instead of (or
together with) per-message jitter — batching of dispatch at the mailbox node:

```
DISPATCH_TICK = 60 sec

at a tick boundary:
  pending = capsules that arrived for the device since the last tick
  if pending is non-empty OR a cover event is scheduled for this tick:
      send PushWakeSignal(a fresh wake_nonce) via the PushAdapter
```

This coarsens the leak from an exact timestamp to "in which 60-second window" —
provided that events of other users pass through the same mailbox node in the same
window.

### 16.3 Cover push (inspired by Poisson cover traffic, as in Loopix)

Periodic pushes with no real message make the fact "a push was received" not
identical to "a message was received". The frequency is by profile:

```
COVER_LAMBDA[profile]:
  Normal    = 0                       // only tick quantization, no cover
  Private   = 1 event / ~20 min       // a Poisson process
  Anonymous = push fully disabled, manual pull (see section 15)
```

A cover event is indistinguishable to an external observer from a real one: the
same `PushWakeSignal` with a fresh `wake_nonce`, the client likewise performs a
mailbox fetch and simply finds nothing new. The price is the device's battery and
the push provider's rate quota; so this is a profile choice, not mandatory default
behavior.

### 16.4 Push as an untrusted Transport Adapter

The push channel is implemented as a `PushAdapter` within the `TransportAdapter`
contract (section 15), with `Capabilities.anonymity_class = LOW`. The Path Manager
must treat it as strictly as the other low-anonymity paths: never transmit capsule
content over push, only a wake signal, and never treat push as the only delivery
channel (where APNs/FCM are unavailable, a backup wake
channel is needed — a WebSocket/long-poll over an ordinary Carrier, section 15).

**Open:** an APNs/FCM push token is a stable per-install identifier, a periodic
`rotation_epoch` softens long-term linkability but does not eliminate it (the token
does not change on demand, only on reinstall/OS update) — this is a fundamental
platform limitation, not solvable at the protocol level.

## 17. Mandatory invariants

**Network level**
- No mandatory carrier is a single entry point.
- No mandatory server list is the sole bootstrap.
- A network session does not depend on a specific carrier.
- There is no distinct plaintext first KARST packet.
- An unverified address does not get an amplified response.
- Active scanning without a capability does not reveal a relay's function.

**Resources**
- Before address confirmation the server creates no long-lived state.
- Before an admission proof no expensive cryptography is performed.
- Every object has a maximum size and TTL, every queue a maximum length.
- Replication is counted in the sender's quota.
- One token does not create an unbounded number of requests.
- Under overload work degrades gradually, it does not collapse entirely.

**Decentralization**
- There is no single issuer, update key, or relay catalog.
- There is no single organization able to revoke all users.
- The reward/credit history of an operator (section 19.2) is never an input to
  route selection **for someone else's/forwarded traffic** (section 11, Sybil
  protection) — otherwise volume becomes a cheap Sybil vector via self-dealing
  loops. This does not forbid a node from using its own `LocalCreditLedger` to
  decide whether and with what priority to serve a specific peer (section 19.2,
  Level 1) — bilateral throttling by one's own resource and Sybil-resistant route
  selection for someone else's traffic are different decisions at different levels,
  and only the second is forbidden to use credit as an input.
- Creating identities does not on its own grant network resources.
- Routes are chosen accounting for real infrastructural independence.

**Privacy**
- Rate limiting does not require a persistent user identifier.
- A relay does not receive plaintext correspondence data.
- The mailbox token changes regularly.
- No single intermediary knows both the source and the destination — except the
  explicitly named exception for the call media stream (section 21.2), limited to
  that stream only and disclosed to the user.
- The leak of one capability does not reveal the other contacts or relays.
- A push payload never contains anything but an unlinkable wake_nonce.
- Push dispatch is quantized by a tick and/or supplemented by cover events by
  profile; immediate push on receiving a capsule is forbidden.
- The push channel has anonymity_class = LOW and is never used as a channel for
  delivering capsule content.

## 18. What cannot be guaranteed

Even this architecture does not guarantee absolute protection against a volumetric
DDoS — if an attacker physically fills a node's whole channel, the protocol will not
restore throughput; distributed infrastructure, spare bandwidth, anycast, and
operator-level protection are needed. A well-resourced adversary can also block the network via a
strict app allowlist, device control, or a full shutdown of the external internet —
this is not solved by the protocol.

**Reproducible builds (section 14) are in a real, not trick-removable, conflict
with resistance to device-level scanning.** Checked twice, both times unsuccessfully:
(a) publishing several differently-built but each independently reproducible builds
does not raise the cost for a state scanner — all published hashes still end up in
the block list, diversification does not work if verification is possible at all; (b)
individual per-user patching of the binary breaks verifiability (an ordinary person
can no longer check against a single published hash) without giving in exchange
protection against real heuristic scanners, which look not for an exact hash but for
a characteristic package name/permissions/network behavior. KARST deliberately
chooses supply verifiability over resistance to device scanning — the same
prioritization already made in section 1 (openness over secrecy): a silently
compromised build is worse than a detectable honest one.

The correct formulation of the guarantee:

> KARST's source code and specification are fully open. Knowledge of the
> implementation does not make it possible to identify all connections, enumerate
> all relays, gain access to node resources, or create an unbounded load. Every
> expenditure of a limited resource requires an address check and a cryptographic
> proof of the right, and breaking one component does not stop the other transport
> paths.

## 19. The position on organization and governance (a decision made)

A deliberate choice: KARST is developed **publicly and non-commercially, with no
mandatory central operator.** The protocol and source are published; users run the
software themselves and operate infrastructure independently. The rationale and
precedents:

- the protocol does not require a single mandatory relay operator or a central
  service, so no one operator is load-bearing for the network to function;
- open, non-commercial development keeps the specification and code available for
  independent review;
- Bitcoin, BitTorrent, I2P, Monero have worked for decades without a single
  governing organization;
- a consequence: refraction networking via one's own ISP partnerships is excluded
  from the first version's goals — it is the only element of the original plan that
  structurally required a central operating organization;
- core development is done by AI, which removes the need for traditional engineering
  salaries and, with it, the main motive for fundraising for development — the only
  thing left open is a reward for infrastructure (see 19.2).

This decision must be observed in further elaboration — do not reintroduce the
notions of "fund", "organization", "official representative" into any subsequent
section.

### 19.1 A format for a community reference on operator legal considerations

The problem of item 8.3 was precisely the mandate: who writes and maintains such a
reference if no one has the authority to speak on behalf of the project? The answer
is to make it structurally not need authority, analogously to how the protocol
itself does not need secrecy of the implementation.

**1. It lives in the protocol repository, not on a separate site.** A simple
markdown file (`LEGAL_NOTES.md`) next to the specification, versioned by the same
git, mirrored together with the code on any number of independent hostings. There
is no single "official" load-bearing domain — the same principle as
for node discovery (section 12).

**2. Public domain, not copyrighted.** A CC0 license — no one has to ask permission
to fork, translate, or edit, and no one acts as the content's rights holder. This
solves the "who owns and must maintain this document" question — the answer is "no
one in particular", as with Wikipedia itself.

An important caveat: CC0 removes the copyright-ownership question but **does not
necessarily remove the tort liability** of a specific editor for a specific
inaccurate edit in individual jurisdictions — these are different legal questions,
and the phrasing "no one is liable" would be an overstatement. The practical
protection is not the license but the strict record template in point 3 (facts
only, no "this is safe" conclusions) and an explicit disclaimer on each record —
they reduce, not eliminate, this residual risk for the editor.

**3. A strict record template excluding legal advice on the merits:**

```
### <node role / jurisdiction>
- Precedent: <public link to a case, if any>
- Applicable rule: <a specific article of existing law,
  e.g. EU e-Commerce Directive Art. 12–15, US DMCA §512>
- Not legal advice — check with a local lawyer.
- Last verified: <date>, editor: <pseudonym, optional>
```

Records describe publicly known facts (the text of the law, the outcome of a case),
not a "this is safe" conclusion — reducing the risk of the editor practicing law
without a license.

**4. Verification — the same way as protocol changes (section 14), but without a
signature threshold.** Anyone may propose an edit; a record is marked `unverified`
until independent editors from different jurisdictions confirm it matches a public
source. Git blame and `Last verified` give provenance transparency without a formal
arbiter.

**5. Don't invent analysis — refer to existing independent resources.** Established
internet-law resources have for years published such materials independently of any
protocol. The KARST reference aggregates and points to their materials rather than
duplicating legal analysis. The base reference for the "mere
conduit" frame is the already-existing cross-jurisdictional **Manila Principles on
Intermediary Liability** document (2015, EFF et al.) — it can be referenced
directly rather than reformulated.

**6. The format for the operator — a self-classification checklist, not a
country-specific conclusion:**

```
Question 1: The node's role? (ingress / mix / mailbox / DTN carrier /
            call-relay — a separate risk profile, see below)
            → the baseline risk level by section 10
Question 2: Does the jurisdiction recognize a safe harbor for intermediaries
            ("mere conduit" / "caching")? → see the Manila Principles
            and public trackers (e.g. the Global Network Initiative)
Question 3: What obligations apply to infrastructure operators in this
            jurisdiction? → see the records in LEGAL_NOTES.md
The decision stays with the operator.
```

**A call-relay (section 21.2) — a separate risk category, not covered by the roles
of section 10.** Real-time relaying of voice/video is in some jurisdictions
regulated separately from ordinary data forwarding (VoIP/telephony licensing),
regardless of what applies to a mere conduit for the rest of the traffic. This is a
separate line in LEGAL_NOTES.md, not reducible to the ingress/mix/mailbox/DTN roles
— an operator who agrees to run a call-relay needs a separate check, this role does
not automatically inherit the classification applicable to the rest of KARST's
infrastructure.

**Remains open:** the up-to-dateness of records over time depends solely on
voluntary crowdsourced maintenance — with no organization there is no mechanism to
guarantee complete coverage of all jurisdictions. This is an accepted trade-off, not
a solved problem — the same limitation as any purely voluntary wiki.

### 19.2 An economic incentive for infrastructure operators

Core development is done by AI — this removes the main line item for which a
Monero-CCS-like fundraise is usually needed (engineers' salaries). What remains is a
separate, narrower task: to reward those who **hold infrastructure** — bandwidth,
storage, token issuance — without a central organization, without a token of one's own, and
without a centralized registry of "who did how much".

The first version of this section was built on the Lightning Network and was
revised: Lightning's public channel graph recreated an enumerable node list (exactly
what section 12 avoids), real-time HTLCs created a timing side channel between the
financial and the communication layer, and any attempt to hide this via Tor is
unreliable, and Tor is not always reachable. The revised model —
two independent, mutually optional layers.

#### Level 1 (basic, by default): local mutual credit with no currency

No blockchain, no convertible unit — the same principle on which BitTorrent
tit-for-tat has held for 20+ years, applied to forwarding capsules instead of file
chunks.

```
LocalCreditLedger[peer_id] = {
  bytes_they_forwarded_for_us
  bytes_we_forwarded_for_them
  last_receipt_signature
}

RelayReceipt {
  peer_id
  bytes_forwarded
  session_nonce      // replay protection
  signature          // signed by the party that received the service
}
```

This is the maximum possible decentralization: no global consensus — only pairwise
local accounting between two nodes that themselves decide how much to throttle each
other on imbalance. This is their own local policy, not a network rule.

**A `RelayReceipt` — non-repudiable evidence, not just an accounting entry.** A
signed `(peer_id, bytes_forwarded, session_nonce)` pair is exactly what the rest of
the document avoids: a persistent, third-party-verifiable record "A interacted with
B, in such a volume, at such a moment". Privacy Pass and the RLN nullifier (sections
6–7) are specifically designed to be indistinguishable; a `RelayReceipt` in its
original form is not.

For the **direct bilateral** case (two nodes are neighbors over one forwarding hop)
this is an acknowledged, scale-limited trade-off: they already know of each other's
existence — the capability exchange of section 12 already implies that contacts see
each other. The receipt reveals nothing beyond that.

For the **transitive** case (credit is settled over a path longer than one hop) the
receipt must not travel in the clear through the intermediate graph nodes —
otherwise it is exactly they who get a log of others' relationships that they should
not see. A **blinded/onion construction for transferring credit** is needed — the
same idea already used for private payment channels (Bolt/zkChannels, Green &
Miers): each intermediate node on the path confirms "I passed a valid credit
transfer onward" without learning either the original or the final recipient. Direct
bilateral confirmation stays a simple signature; transitive transfer is the only
place where a heavier construction is needed, not all of Level 1.

**A clarification — the previous version named the construction by analogy, did not
specify it.** The problem: each `ContactRoot` (12.1, point 4) exists only between two
people who know each other directly — between graph-non-adjacent parties there is no
shared secret at all, so simply "making credit transitive" does not work without an
explicit multi-hop construction. The solution is to reuse the **Sphinx onion-packet
format** (the same primitive on which Lightning's payment routing and Tor's node
chains are built, not a new invention):

```
CreditOnion {
  layers[hop_count]   // encrypted_layer_i is encrypted with the public key
                       // of hop_i from ITS OWN ContactRoot with its neighbor
}

each hop:
  decrypts its layer →
  learns only (next_hop_id, amount) — not the source, not the final recipient
  updates ITS OWN LOCAL LocalCreditLedger with its immediate neighbor
    (this is the already-accepted bilateral case — an ordinary signature, no problem)
  passes the remaining layers onward

the final hop reveals the preimage R by an HTLC-like scheme back along the chain →
  the whole settlement chain is atomically confirmed or not confirmed as a whole
  (a timeout without revealing R = no one updates their ledger)
```

Each hop knows only its immediate neighbor on either side — exactly the same
visibility limit that onion routing already gives for capsules themselves.
Transitive credit is not a new cryptographic construction but the application of an
already-existing primitive to a different data field (a credit amount instead of
message content).

**An acknowledged limitation.** Pure bilateral credit works poorly between strangers
with a one-off interaction (unlike a BitTorrent swarm, where a pair of peers meet
repeatedly). The solution is not to invent a separate reputation system but to make
credit **transitive along the already-existing trust graph** (contacts/capabilities
from section 12) via the onion confirmation above, not an open receipt: a node can
settle its balance not only with the one it helped directly but with anyone it has a
path to through common contacts, without revealing that path to the intermediate
links. A structure that already exists is reused, instead of a new one — but with
derived, unlinkable identifiers per function (see the corrected point 4 in section
12.1) instead of raw graph edges.

#### Level 2 (optional, at the operator's risk): settlement in Monero

For those who want real income, not just service priority. Per decision 19.1 —
whether to accept payment is decided by the operator, who is responsible for
compliance in their jurisdiction; the protocol does not obligate it.

**Why Monero, not Lightning/Bitcoin:**
- **Stealth addresses** — the operator publishes one address, each payment to it
  creates a new one-time on-chain key, unlinkable to other payments to the same
  address by an external observer. This solves the enumerability problem by the
  currency's construction;
- **ring signatures + RingCT** hide the sender among a decoy set and the amount —
  stronger defaults than Bitcoin/Lightning;
- **no payment-routing graph at all** — an ordinary UTXO chain, no need to maintain
  a channel topology, which was the source of the leak in the Lightning variant;
- settlement is on-chain only (~2 min/block) — which coincides with the already
  needed timing-side-channel mitigation: settlement must be batched anyway, not
  per-block in real time.

**Grin/Mimblewimble was considered and rejected** — stronger than Monero in
graph-analysis resistance (no on-chain addresses at all), but requires
**interactive** transaction construction (both parties must be online at the same
time) — incompatible with the asynchronous mailbox/DTN architecture (sections 7.7,
13), where the recipient may be offline at the moment of settlement. Monero does not
require recipient interactivity.

**Exchanging invoices/receipts — an ordinary KARST capsule.** Payment metadata is
transmitted via the already-existing multi-carrier transport (section 15).

**Embedding into the admission protocol (section 7.3)** — buying tokens in a batch
analogously to the LSAT pattern (pay once, get N blinded tokens, spend later
anonymously, unlinkable to the purchase or to each other), but settling in XMR
instead of sats.

**Reward by role (section 10):**

| Role | Payment |
|---|---|
| Ingress / Mix | periodic batch settlement for confirmed volume (a Receipt from Level 1, converted to an XMR payout at the operator's wish) |
| Mailbox | payment proportional to TTL × size, in a batch — a generalization of the "replication is counted in the sender's quota" principle (section 13) |
| Issuer | the sum of a batch purchase of admission tokens |
| DTN carrier (mesh, 7.7) | **not monetized** — the mesh stays purely volunteer, as before |

**Does not cancel the pure volunteer mode.** Level 1 works for everyone by default;
Level 2 is an option on top of it, not a replacement.

#### Mining as an optional personal way to obtain a small amount of XMR — a limited supplement, not a network-funding mechanism

The idea of letting users mine XMR themselves was considered and narrowed to a
personal, small-scale way of obtaining coin — not a way to fund the network's
infrastructure. Reasons for the restriction:

- an individual phone's CPU hashrate is economically negligible (RandomX light mode
  on a mobile CPU — fractions of a cent a day), the same effect as browser mining
  Coinhive 2017–2019;
- the Apple App Store and Google Play **explicitly forbid** cryptocurrency mining in
  apps — embedding it into the main messenger guaranteed breaks distribution through
  the official stores (a conflict with 8.6);
- solo mining almost never finds a block → a pool is needed → a pool is a new point
  of centralization, unless it is **P2Pool** (a decentralized pool for Monero via a
  p2p sharechain, with no central operator, really exists and has worked since
  2022);
- even via P2Pool the payout goes to whoever provided the hashrate (the user), not
  the relay/mailbox operator — "automatic distribution to infrastructure" would
  require another consensus layer, reintroducing the centralized accounting that
  Level 1 avoids.

Therefore: mining is an **optional, off-by-default** feature only in the
sideload/desktop build (never in a build from an official store), honestly labeled a
slow personal trickle for topping up Level 2, not earnings and not network funding.
The precedent already exists — the official Monero GUI Wallet has exactly such an
option separate from any messenger functionality.

**Remains open:**
- obtaining XMR is an operator-side concern outside the protocol — an informational
  record in `LEGAL_NOTES.md` (19.1) may note the available options, not protocol
  infrastructure;
- the specific parameters of Level 1 credit transitivity (path depth in the trust
  graph, the imbalance threshold for throttling) — calibrated by practice, not fixed
  by the protocol.

## 20. Coercion and physical access to the device

The threat model (section 1) here includes an adversary with physical control of a
person and device: not only a remote attacker but the ability to detain a person,
search their device, and coerce them into unlocking it. None of the previous 19
sections addressed this — even though it is a real threat this section must cover.

### 20.1 Two different mechanisms — not to be confused with each other

**Duress unlock** and **panic wipe** are different solutions with different
trade-offs, and must be different actions (a different code/gesture), not one:

```
UnlockSecret → one of two outcomes:
  RealIdentity    — the real keys, contacts, history
  DuressIdentity  — a separate keyset, generated in advance,
                    with plausible but content-empty
                    contacts and history

PanicTrigger → a separate gesture/code, does NOT coincide with the DuressIdentity unlock
             → really destroys the RealIdentity keys (does not hide — erases)
             → the device keeps working as DuressIdentity
               or as a freshly installed app
```

The difference matters: hiding (DuressIdentity) preserves the ability to return to
real data later but leaves it physically existing and potentially extractable by a
deeper forensic analysis. Destruction (PanicTrigger) irreversibly removes the data
but is itself suspicious if the device was just wiped before an inspection. The
choice between them is the user's decision in the moment, not something the protocol
can make for them.

**Decoy contacts must be real, not dummies.** If the contacts and capabilities in
`DuressIdentity` are just generated stubs leading nowhere, a sufficiently thorough
check (a real attempt to message a decoy contact, to use a decoy capability) will
discover that they are "dead" — exposing the profile as fake under active, not only
passive, inspection. A decoy profile must point to genuinely working but harmless
endpoints (public bots, test accounts), not to non-existent ones. This requirement
extends to call history (section 21.2) too, not only messages — a plausible decoy
profile should show at least a few calls to the same decoy contacts, otherwise an
inspection checking both types of history (which real forensic analysis of modern
messengers does) will see a suspicious asymmetry: active correspondence with a
complete absence of calls.

**The storage format must not reveal the presence of a second slot even on a single
snapshot.** It is not enough to protect only against a multi-snapshot comparison
(section 20.4) — if the data format on disk is itself structurally distinguishable
("there is room here for a hidden profile") already on a single search, before any
snapshot comparison over time, deniability does not work at all. All allocated
storage must look equally full/random regardless of whether a hidden profile is
provisioned — the same technique already used by VeraCrypt hidden volumes (unused
space is filled with random data indistinguishable from encrypted content).

### 20.2 Undetectability on the network side — a mandatory condition

If a relay/mailbox can tell a `DuressIdentity` session from a `RealIdentity` one by
any network feature, the whole mechanism is pointless. The solution — `DuressIdentity`
uses **the same admission protocol** (section 7, the `Capability`/`AdmissionToken`
format) with a separate but structurally indistinguishable keyset — not a separate
protocol path, which would itself be a signal "this is duress mode".

**The device's push token (section 16.4) — a shared channel between the two
identities, not only the network level.** The limitation already acknowledged there
("an APNs/FCM push token is a stable per-install identifier") means: `DuressIdentity`
and `RealIdentity` on one physical device most likely use the same push token/a
similar IP — a remote observer (not only whoever holds the device physically) can
potentially correlate that both profiles ever worked from one device, even before
physical access to the device. The mitigation, where platform limits allow, is a separate push
registration for `DuressIdentity`; where they do not allow (the same reasons as in
16.4), this remains an uncovered residual risk, not a solved problem.

### 20.3 Decoy app icon

A separate icon/name for the app, indistinguishable from a neutral tool (a
calculator, notes), reduces the chance that a cursory search of the device
recognizes the very presence of a messenger. A precedent already exists and works:
**Tella (Guardian Project)** — an app for exactly this audience, with an icon
decoy mode and a panic wipe by gesture, battle-tested for years in real
conditions.

**The same app-store caveat as with mining (19.2).** A fake icon/name is a direct
violation of Apple/Google policies against misleading apps, the same category of ban
that already led to the decision not to embed mining in a build from the official
store (12.2). It would be inconsistent to allow here what is forbidden there for the
same reason: decoy mode is available only in the **sideload/desktop build**, like
mining. A build from the official store keeps an honest icon/name — for it,
duress-unlock and panic wipe (20.1) remain available, which do not require
misleading app metadata and so do not conflict with the stores' policy.

### 20.4 An honest limitation — multi-snapshot forensic analysis

As everywhere in this document (section 18), we do not claim a complete solution.
Plausible-deniability schemes (`DuressIdentity` alongside hidden real data) are
vulnerable to a **multi-snapshot attack**: if the adversary obtains several forensic
snapshots of the device at different times (taken and returned, then taken again),
statistical differences in storage occupancy between snapshots can reveal the very
existence of a hidden partition — a known, published class of attacks on
deniable-storage schemes (the same class of problems as TrueCrypt/VeraCrypt hidden
volumes). KARST does not solve this attack — it is an upstream limitation of the
plausible-deniability approach itself, not a flaw of a specific implementation.

### 20.5 Openness of the code does not contradict this section

Section 1 requires fully open code — which means the very existence of a duress/panic
mechanism in KARST will be publicly known to an adversary from the start (unlike
proprietary solutions, where the presence of such a feature could be hidden). This
does not weaken the protection: security is built not on the secrecy of the fact
"KARST has a duress mode" but on the indistinguishability of a specific session at a
specific moment — the same Kerckhoffs's principle as everywhere else in the
document.

## 21. Media attachments and calls

**An explicit boundary of this section: ordinary messages do not change anywhere.**
Everything described in sections 2.1, 2.2, 5–13 for text messages stays as is — this
section adds two new, separate capabilities (large attachments and calls) without
modifying the existing message pipeline. Calls in particular deliberately accept
weaker anonymity guarantees than messages — this is an isolated, explicitly marked
exception, not a lowering of the bar for the whole network.

### 21.1 Photos, audio messages, files — refinement of the existing pipeline

This is not a new architecture but larger asynchronous messages via the
already-existing capsule/mailbox mechanism (sections 3.1, 13). Three refinements:

- **Chunking files larger than the largest size bucket** (section 3.1, currently up
  to ~1 MB) — splitting into several capsules with reassembly at the receiver, each
  chunk counted in the admission quota separately (section 5), not as one charge for
  the whole file;
- **An explicit, stricter size limit for DTN/mesh transfer** (section 7.7) — instead
  of a general "the volume is physically small and self-limited", a specific number,
  separate from the live transport;
- **Stripping EXIF/metadata on the client before encryption** — a photo from a phone
  carries geolocation, the device model, the capture timestamp; this is a
  requirement of the client app (the same technique already used by Signal), not of
  the protocol.

### 21.2 Calls (voice/video) — a separate subsystem with explicitly weaker anonymity

**Why you can't just pass voice through the existing pipeline.** Mix, batching,
cover traffic, DTN (sections 10, 16, 7.7) are techniques that deliberately add delay
and jitter for the sake of anonymity. A call requires the opposite: low and
predictable latency. This is not solved by improving the protocol — the Tor Project
itself explicitly does not recommend Tor for voice/video for this reason.

**Splitting into signaling and the media stream.**

```
Signaling (a call invitation, ICE candidates, SDP)
    → an ordinary capsule via the existing mailbox/mix (section 10)
    → the same encryption as ordinary messages (section 2.1/2.2)
    → does NOT change relative to section 10 at all

The media stream (audio/video, SRTP)
    → a separate path described below
```

Signaling is no different from sending an ordinary message — low volume, not
latency-sensitive, fully fits the existing architecture unchanged.

**The media stream — not raw WebRTC/STUN/TURN, but the same transport encapsulation as the rest
of the traffic.** Raw WebRTC/STUN/TURN has its own well-known traffic-analysis fingerprint —
WhatsApp/Skype voice/video calls have already been selectively blocked on some
networks precisely by this fingerprint, separately from the rest
of the app's traffic. The solution is not to invent call anonymity but to preserve
only the requirement of sections 3/15: the SRTP media stream is transmitted over
**MASQUE CONNECT-UDP** (already in the list of transport adapters, section 15) on top
of the same encapsulated HTTPS/QUIC carrier with ECH (section 15) as the rest of the
network — not as separate, easily recognizable STUN/TURN traffic.

**Why this does not contradict the low-latency requirement.** The latency of
Tor/mixnet is a consequence of deliberately adding many hops and artificial delay for
anonymity. Encapsulation as HTTPS to a CDN via MASQUE is **not the same**: CDN edge
networks are specially optimized for low latency (that is the whole point of a CDN),
not for anonymity via many hops. The "anonymity versus latency" conflict exists
precisely for onion/mix routing — not for masking traffic as ordinary HTTPS. So the
property "blocking requires breaking shared infrastructure" (sections 3, 3.3) can be
preserved for calls without sacrificing conversational usability.

**An explicit, named exception to the invariant of section 17.** A NAT-traversal
relay for the media stream by construction sees both ends of a call at once in real
time — exactly what the invariant "no single intermediary should know both the
source and the destination" forbids for messages. The content is still protected
(SRTP encryption), but the call metadata (who called whom, when, for how long) is
revealed to the relay more than message metadata. This is a deliberate, explicitly
named exception, limited to the call media stream only — not a silent weakening of
the invariant for the whole network.

**Mandatory disclosure to the user, not silent degradation.** The same "no silent
fallback" principle (section 15): before starting or accepting a call the app must
explicitly show that the call's anonymity is weaker than that of messages. In the
"Anonymous" profile (section 15), whose guarantee is "no direct fallback", outgoing
calls are disabled by default or require explicit conscious confirmation on each call
— a silent degradation of this profile's guarantee is not allowed. Incoming calls in
this profile are a separate case with a different limitation, see 21.3 (a conflict
with fully disabling push, section 16.3).

**Direct P2P — an option, not the default choice.** If NAT allows a direct WebRTC
connection, it is faster but reveals the interlocutor's real IP directly — this must
be a conscious user choice with an explicit warning, not an automatic fallback when
the relay path is unavailable.

### 21.3 Intersections with the rest of the architecture

Section 21 adds a new feature on top of the already-stabilized architecture
(sections 5–20) — below are the points where a call-relay requires the same mechanism
that already exists for the rest of the traffic, explicitly extended to this role,
not implied by default.

**Admission gating of the media stream (sections 5, 7).** The principle "an
unauthorized request must not force a node to spend significantly more resources than
the sender spent" (section 5) extends to a call-relay without exception: an attempt to
establish a call is a resource request (real-time bandwidth, orders of magnitude more
than one message), and must pass the same admission protocol (cookie/capability/token,
sections 6–7) before the relay starts forwarding the SRTP stream, not only at the
signaling stage. Without this, a call-relay is a new, unprotected amplification point:
the cost of a call invitation for an attacker is far less than the cost of serving it
for the victim relay.

**A call push notification cannot wait for DISPATCH_TICK (section 16.2).** Batching
into 60-second windows was designed for messages, where a delay within a minute does
not affect connection usability. An incoming call delayed up to 60 seconds before the
callee even learns of the call is in practice not a call — the caller will hang up
first. This is a structural, not an engineering, conflict: you cannot both hide the
exact time of an event in a shared window and deliver it almost instantly. The
solution is not to fix batching but to explicitly extend the principle already
accepted in 21.2 "calls are a named exception with weaker anonymity, disclosed to the
user": the push signal of a call invitation is marked a separate, immediate class
(`urgent`, bypassing the tick queue), and this is explicitly shown in the UI as part
of the same warning about calls' weak guarantees (section 21.2, "mandatory
disclosure"), not presented as a property of the push channel as a whole. A side
effect — the very fact "the push arrived immediately, not at a tick boundary"
distinguishes a call from a message for an observer of the push channel; this is
accepted as part of the already-disclosed call trade-off, not a new hidden
degradation.

This `urgent` class assumes a push channel exists at all — true for the "Normal" and
"Private" profiles. In the "Anonymous" profile push is fully disabled, not just
batched (section 16.3) — this is a guarantee of the profile, not an implementation
detail, and the `urgent` class cannot bypass it without thereby silently breaking it.
So in the "Anonymous" profile **incoming** calls are structurally undeliverable: there
is no channel to wake the device without violating "push fully disabled". This is not
the same limitation as "calls disabled by default, requiring confirmation" from 21.2 —
that describes outgoing calls and a general protective barrier, this is a hard ban
precisely on receiving incoming calls in this profile, lifted only by an explicit user
decision to downgrade the profile to "Private" for the duration of a session, not by a
setting inside the "Anonymous" profile.

**Sybil diversification of call-relay selection (section 11).** The explicit exception
of section 21.2 to the invariant of section 17 concerns only the visibility of the
session content ("the relay sees both ends") — it does not remove the need for
diversification when SELECTING that relay. A cheap Sybil attack specifically on the
call-relay role gives the attacker scalable collection of "who called whom and when"
metadata without needing to break any cryptography — a different motive for Sybil than
for an ordinary route, but the same protection mechanism (section 11: different /24s,
ASNs, operators, issuer classes) must apply to call-relay selection as strictly as to
an ordinary message route.

**The economic incentive recalculated by volume (section 19.2).** The
`RelayReceipt`/`bytes_forwarded` model was calibrated for the message-forwarding
profile (kilobytes). A call forwards orders of magnitude more traffic per session
(audio — hundreds of KB/min, video — single-to-tens of MB/min) — the same formula
works unchanged (credit is counted by bytes, not events anyway), but the voluntary
economics differ: an operator willing to relay short messages for free is not
necessarily willing to hold a multi-hour video call on the same selfless basis. The
protocol does not impose a decision — this is an explicitly operator-discretion
trade-off (the same imbalance-throttling logic of `LocalCreditLedger` as in 19.2), but
it is worth fixing explicitly: a node may apply a separate, stricter limit
specifically to call-relay bytes, not conflating it with the general
message-forwarding limit.

## 22. Next steps

The original backlog of section 8 is fully closed:

1. ~~Decide the quota mechanism for the store-and-forward mesh~~ — solved, see 7.7.
2. ~~Formalize the push-jitter/cover-push protocol~~ — solved, see 16.
3. ~~Define the format of a community reference on operator legal considerations~~ — solved, see
   19.1.
4. ~~Devise an infrastructure reward without a central organization~~ — solved, see 19.2
   (bilateral credit + optional settlement in Monero, mining as a limited personal
   supplement).
5. ~~Work out a bootstrap/bridges distribution strategy~~ — solved, see 12.1.
6. ~~Work out a plan for distributing the app bypassing the app store~~ — solved, see
   12.2.

Each item, when solved, was moved from section 8 into the main text of the document
with a formal description (structures, state machine, invariants — modeled on section
7).

**A round of end-to-end critical audit (after closing the backlog) — nine findings,
all fixed:**

1. No coercion/duress mode → section 20 added.
2. A `RelayReceipt` is non-repudiable evidence → the bilateral/transitive cases were
   separated, the transitive one requires a blinded construction (19.2, Level 1).
3. `max_hops` in DTN was presented as a protocol guarantee but is not
   cryptographically enforced → downgraded to advisory metadata, the real protection
   is `LocalCarryBudget` (7.7).
4. One trust graph for three functions with no separation → derived per-function
   identifiers via a KDF from one root (12.1, point 4).
5. A capsule size padding scheme was missing → section 3.1 added.
6. `still_reachable_after` in bootstrap reputation had no concrete verification
   mechanism and did not distinguish a hostile requester from a hostile distributor →
   a binding to OONI and a separate risk category added (12.1, point 3).
7. The invariant of section 17 literally contradicted the design of Level 1 (19.2) →
   reformulated with an explicit separation of "route selection for someone else's
   traffic" and "bilateral throttling by one's own resource".
8. CC0 in 19.1 was claimed to fully remove the editor's liability → the wording was
   softened, residual tort liability noted.
9. The maintainers' threshold signatures (14) protected only against remote hacking,
   not against physical coercion of the holder group by a state → a caveat about the
   maintainers' jurisdictional diversification/pseudonymity added.

**A second audit round — six findings, all fixed. Some of them are a side effect of
the first round's fixes, not new independent problems:**

1. `LocalCarryBudget` protected only against one pushy peer, not against a Sybil of
   many cheap mesh identities → an aggregate `DeviceCarryBudget` on top of the
   per-peer budget added (7.7).
2. OONI cannot confirm the reachability of by-construction secret private bootstrap
   descriptors (it measures only cataloged targets) → the scope was narrowed to the
   public layer, for the private one a gameable client self-report is explicitly named
   as the only source (12.1, point 3).
3. KDF separation of identifiers by function (first round, finding 4) solved the
   inter-function leak but did not specify how transitive credit crosses a chain of
   pairwise-independent `ContactRoot`s at all → a concrete Sphinx-like onion
   construction for transferring credit through intermediaries added (19.2, Level 1).
4. `issuer_id` in `AdmissionToken` was sent in the clear, narrowing the anonymity set
   to the users of a specific issuer → replaced with a ring signature over a set of
   trusted issuers (7.3).
5. The decoy app icon (20.3) was not reconciled with the app-store policy already
   applied to mining (19.2) → limited to the sideload/desktop build for the same
   reason.
6. A decoy profile under coercion could be exposed by an active check ("does this
   really work?") or by the storage format already on a single snapshot → decoy
   contacts must lead to real harmless endpoints, storage must look equally full
   regardless of the presence of a hidden profile (20.1).

**A third audit round — five findings, all fixed. One of the ideas along the way did
not survive its own check and was narrowed rather than silently discarded:**

1. The ring signature (the second round's fix) supported only "1 of N", while section
   7.3 already allowed a "2 of 5" policy → replaced with a threshold ring signature
   (Bresson–Stern–Szydlo), parameterizable by the threshold t (7.3).
2. The concentration limits of section 11 were never explicitly tied to the placement
   of erasure-coding fragments (13) → tied explicitly. It initially seemed the same
   should apply to the choice of `CreditOnion` hops (19.2) — on checking it turned out
   that the hops there go along the social graph, not freely chosen from a pool of
   infrastructure, so this part of the idea was discarded; in its place an honest
   limitation was fixed — the onion privacy of `CreditOnion` is meaningful only for
   paths of 3+ hops.
3. The return of a DTN capsule to the network (7.7) was not explicitly embedded in the
   Ingress/Mix/Mailbox/Egress pipeline (10) → Ingress explicitly branches by credential
   type, no separate DTN gateway is set up.
   **Clarified by the implementation (impl/admission, pipeline.rs):** the branching is
   in fact at Stages **3–4**, not only 4 — the DTN replay mechanism is fundamentally
   different (a rolling window by `not_after` instead of an epoch swap), so Stage 3
   branches too. Plus two integration subtleties invisible to a prose audit that
   surfaced during implementation: (a) a DTN proof travels through untrusted, observing
   mesh carriers, so the single capsule identifier = `H(ciphertext)` serves as both the
   MAC input and the rolling-window key — otherwise an observer would attach a valid
   proof to other content; (b) for DTN, insertion into the rolling window happens only
   AFTER a successful HMAC (Stage 3 is a read-only CHECK), otherwise a garbage proof
   uploaded first would burn the id and block a real capsule.
4. AI development (19) creates a risk of correlated blind spots for "independent
   implementations" (14) if they are written by similar AI systems, and separately —
   shrinks the natural pool of candidates for threshold-key holders → independent
   implementations require different AI vendors and human review at the critical gate;
   the set of key holders is a separate recruiting task, not a derivative of who writes
   the code.
5. `DuressIdentity` and `RealIdentity` (20) share one device push token — the
   limitation already acknowledged in section 16.4 applies here too → a separate push
   registration for duress mode where the platform allows; honestly acknowledged as
   uncovered where it does not.

Further work — beyond these rounds: the transition from specification to
implementation (choice of language/runtime, test vectors for the admission protocol of
section 7, a reference client), or the next round of critical analysis as the
implementation deepens — by the same principle already applied three times in this
document.
