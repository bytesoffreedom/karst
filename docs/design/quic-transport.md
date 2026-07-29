# QUIC as a transport for KARST — where it applies, and where it must not

**Status: DESIGN, nothing implemented.** This document is the gate for the QUIC
work: it exists so the one decision that shapes everything else is written down
before any code, rather than discovered halfway through an adapter.

The source of truth is the code. Where this document and the code disagree, the
code is right and this file is what gets fixed.

---

## 1. The decision this document exists for

QUIC's whole benefit is **one long-lived, multiplexed connection**: several
operations in flight at once, a file upload that does not stall an ACK, a
session that survives the phone moving from Wi-Fi to LTE. Every one of those
follows from reusing a connection.

KARST spent considerable effort making connections *not* reusable.
`Peer::scope_for(handle)` derives a SOCKS stream-isolation token **per handle**,
and a handle is per-purpose, per-box, per-epoch. Over Tor, that means every
request already rides its own circuit, and two of this account's drop-boxes
polled a second apart share nothing an observer at the relay can join up.

That property is not incidental. It is load-bearing for **A8-4 / #206**: the
reason a shared `capability_id` was re-prioritised from "minor" to "the primary
linkage channel" is precisely that per-handle isolation had already removed the
connection-level clustering an earlier revision leaned on. See
`docs/design/proxy-identity.md` § Honest limits #6 for that correction in full.

**Pooling QUIC connections gives the linkage back.** Several handles of one
proxy arriving over one connection re-clusters exactly the boxes that address
rotation separates. This is not a tuning parameter; it is the same finding
#206 closed, re-opened one layer down.

### The resolution

> **QUIC is the transport of the DIRECT path. Tor and SOCKS stay on TCP/WSS
> with per-handle isolation.**

This is the same argument #206 used, applied to the transport layer:

- A user on a **direct** connection is linked by their IP address on every
  request regardless of what we do above it. Connection reuse tells the relay
  nothing it could not already read off the socket. They lose nothing and gain
  QUIC's multiplexing.
- A user on **Tor** is linked by essentially nothing else, which is the whole
  point of the configuration. Pooling would hand the relay the one join it
  currently cannot make.

It also happens to be forced by the network: Tor carries TCP streams and does
not implement SOCKS5 `UDP ASSOCIATE`, so ordinary QUIC through a Tor SOCKS port
does not work at all. The privacy answer and the plumbing answer coincide —
which is worth stating, because it means nobody will later be tempted to "fix"
the plumbing and quietly take the privacy with it.

**Rule, not default:** the connection pool is enabled only on the direct path.
On a SOCKS/Tor path there is no pool even if QUIC were somehow available — a
connection per handle, as today. Written as a rule so that a later performance
pass cannot flip it as a configuration choice.

### What the pool is keyed by — settled when it was built (QUIC-5)

The sketch above assumed the key would be the proxy identity, and that
`Relay`, which today is built once from an account's settings, would have to be
rebuilt per channel to supply it. **Both were wrong, and the reason is worth
keeping** — the alternative was a refactor of ~35 call sites that would have
landed a COARSER key than the one already available.

The key is the **per-request scope** the caller already threads through
`connect_isolated` (`Peer::scope_for`, derived from the handle the relay sees in
the clear). It is strictly finer than a per-proxy key, needs no new plumbing,
and is the value the SOCKS carrier already uses for the same purpose one layer
along. On the direct path the finer granularity costs only connections, not
unlinkability, because there is no circuit to separate — which is the same
observation that put QUIC on the direct path in the first place.

The load-bearing half is what happens when there is **no** scope. An unscoped
request has not said which compartment it belongs to, and pooling on "unknown"
would put every unscoped request in the process — bundle publishes, blob
transfers, discovery lookups, across every channel — onto one connection. That
is the #206 join rebuilt at the transport layer, and it would be *worse* than
no pool, since today each of those requests dials its own connection. So:

> **No scope, no pool.** An unscoped request gets a fresh connection every
> time. This is a rule with no setting behind it.

A pooled connection that has died is evicted and redialled, never handed on as
live — that is the client half of "migration off" (§4): from here, a local
network change looks exactly like a connection the relay refused to migrate.

### Which request classes carry a scope — settled (QUIC-13)

The pool only merges what a caller scoped, so "which classes get a scope" decides
what QUIC is worth. Surveyed class by class; the answer is **the two that already
have one, and no more**.

**Scoped, and correctly so.** Mail — `send`, `fetch`, `ack` — carries the handle
scope (`Peer::scope_for`), which is the frequent path and the one pooling was
built for. A blob DOWNLOAD carries a scope minted per download (QUIC-7), which is
the heavy path.

**Left unscoped deliberately, not by omission:**

- **Public reads** — `get_policy`, `get_node_list`, `blob_stat`,
  `lookup_discovery`, `fetch_bundle`. These carry no identity and are answered to
  anyone. Giving one a scope would attach a channel label to a request that has
  none today — *creating* linkage in the name of pooling. This is the sharp case:
  scoping them would be actively harmful, so a guard keeps them unscoped rather
  than trusting the next reader to notice.
- **Channel-bearing but rare** — `publish_bundle`, `join`, discovery publish and
  delete, `fetch_bundle_opk`. A scope here would add no linkage the relay lacks
  (these already carry the channel's key) and would save roughly one handshake
  per channel per relay per unlock. Not worth a moving part. Revisit only if
  something makes them frequent.
- **Blob upload** — already holds one session per file since FT4, so there is
  nothing for a pool to merge; unscoped means that session is never pooled with
  anything else, which is the most separated arrangement available.

The conclusion is that pooling pays on exactly the two paths that already use it.
That is a smaller answer than "wire scopes everywhere", and it is the honest one:
the remaining classes are either too rare to matter or would be made *worse* by a
label they currently do without.


---

## 2. Where QUIC applies

| Path | Transport | Pooling |
|---|---|---|
| Direct (clearnet) | QUIC preferred, WSS/TCP fallback | Yes: one connection per (relay × proxy identity) |
| SOCKS5 with real `UDP ASSOCIATE` | QUIC possible, only if that proxy actually supports it | No |
| Tor SOCKS | TCP/WSS only — Tor has no UDP | No |
| I2P | Its own stream (TCP-like) adapter | No |
| Networks that block UDP | WSS on TCP/443 | n/a |

WSS is not a legacy fallback to be retired. It rides HTTPS/WebSocket over
TCP/443 and therefore traverses ordinary reverse proxies and corporate networks
that drop UDP/443 outright. UDP and TCP can use the same port number
simultaneously, so one relay offers QUIC and WSS on 443 without choosing.

---

## 3. The stack for the first version

```
UDP
 → QUIC / TLS 1.3   (ALPN "karst-relay/1")
 → Noise transport session          ← KEPT
 → KARST wire protocol
 → E2E ciphertext (PQXDH + Double Ratchet)
```

**Noise stays.** QUIC's TLS protects client ↔ relay; the Double Ratchet
protects sender ↔ recipient. They are different segments and one does not
substitute for the other. Keeping Noise inside costs a second handshake and a
second layer of transport encryption, and buys the thing that matters for a
first implementation: **the trust model does not move.** Relay identity is still
`Noise_NK` against the pinned `relay_id`, QUIC remains a swappable carrier, and
TCP, WSS and QUIC all speak the identical protocol above the adapter.

### DECIDED (QUIC-9): Noise stays, and this is no longer waiting on an audit

The task that held this open assumed the answer needed an audit. It does not —
it needs the cost measured and the trust model looked at, and both now point the
same way.

**The load-bearing reason: the alternative is not buildable from here.** Removing
Noise means relay identity moves into a pinned TLS certificate — and there is
nothing to pin it against. A descriptor's signature covers the relay-id and not
the unsigned remainder, which is exactly why a certificate-fingerprint field was
REFUSED in QUIC-1 (§10). So the first step of removing Noise is not a deletion,
it is adding a signed identity to the descriptor: a protocol and trust change.

**And it would make the trust model carrier-dependent.** Relay identity is
decided in one place today and the same way on every carrier: Noise against the
pinned `relay_id`. A TLS-certificate identity exists only on QUIC and WSS, so a
client would authenticate its relay differently depending on which route
happened to win a race (QUIC-4). Two answers to "am I talking to the right
relay" is one too many.

**Supporting evidence: the cost is small and is now paid rarely.** Noise here is
`Noise_NK` — `-> e, es` / `<- e, ee`, exactly **one round trip** — plus a few
milliseconds of computation. A one-off measurement over loopback against a real
QUIC relay (40 handshakes each way) put QUIC alone at 2.28 ms and QUIC + Noise
at 5.04 ms per connection. Treat that delta as indicative, not as a pinned
figure: over loopback it bundles Noise's computation together with its extra
round trip, and the measurement was taken with a throwaway test that is not in
the repository. The unambiguous part is the round trip.

What made the cost look serious was *how often it was paid*. Before this batch a
download opened a connection per CHUNK, so a large file paid the handshake tens
of thousands of times. After QUIC-5 (pooling by scope) and QUIC-7 (one session
per transfer) it is paid **once per transfer**. The optimisation people reach for
when they propose removing Noise has already been made somewhere that costs
nothing.

**So: kept, deliberately and not provisionally.** Not "kept until an audit says
otherwise" — kept because the replacement does not exist and would cost more
than the thing it replaces.

**And enforced, not remembered.** `transport/src/identity_guard.rs` fails the
build if any carrier starts establishing relay identity for itself — running the
handshake, pinning a certificate, comparing a fingerprint — or if the QUIC
certificate verifier stops being the deliberate no-op its name advertises. The
risk this guards is not a deliberate reversal after reading this file; it is a
second mechanism appearing quietly because, on the one carrier somebody is
working on, it looks like an obvious improvement. Then the carrier that wins the
race (§8) decides how the relay was authenticated, the weaker mechanism becomes
the security level, and an attacker picks which one you use by making the other
path fail.

The guard's failure message carries the three conditions a reversal needs — a
signed identity in the descriptor, one answer that holds on every carrier, and a
reproducible cost figure — so whoever tries meets them at the moment they are
useful rather than in a document they did not know to open.

Note what is NOT prohibited: the `wss` carrier verifies its TLS certificate
against the webpki roots. That authenticates a hostname so the tunnel is a
well-formed `wss://` connection — encapsulation, with the relay still
authenticated by Noise inside it. The rule is about identity, not about whether a
carrier may use TLS.

### Why this fits the existing abstraction cheaply

`TransportAdapter::connect(&Dest) -> Box<dyn Channel>`, where
`Channel: Read + Write + Send`. One QUIC bidirectional stream is exactly a
`Read + Write`. So the document's "one operation, one stream" model maps onto
the existing "one connection, one request" model with **no changes above the
adapter**: Noise, framing, `round_trip`, the admission pipeline and the
per-class frame ceilings all stay as they are.

The real cost is asynchrony. `quinn` is async (Tokio) and the client transport
is blocking throughout. The adapter therefore **owns its own runtime** and
bridges with `block_on` at the read/write boundary. That async stays inside the
adapter; it does not become the client's execution model. (`rustls` is already
in the dependency tree via the WSS carrier, so the new weight is `quinn` +
`tokio`.)

---

## 4. Settings fixed now

**0-RTT application data: OFF.** Early data is replayable — a server can process
one application action several times, and QUIC's own specification puts the
burden on the application to say which operations are safe. Nearly all of ours
change state: `Deposit`, `Ack`, `BlobPut`, `PublishBundle`, `PublishDiscovery`,
`DeleteDiscovery`, capability spend, credential revocation. Even `FetchBundle`
is not a safe read: with a one-time prekey it CONSUMES a unit (#159 gated that
path for exactly this reason, and CRYPTO-33 made a unit carry a destroyable KEM
seed as well). Session *resumption* is fine; early *data* is not. A later pass
may enable 0-RTT for something provably idempotent — a signed public checkpoint
— and nothing else.

**Session tickets: off, or partitioned.** A ticket is a resumption identifier,
which is another way to recognise a returning client. Either disable them or
key the ticket store per (proxy identity × relay), never one store shared
across an account's channels. A shared ticket store would rebuild the linkage
#206 removed, from a different direction.

**Connection migration: off by default.** Surviving a Wi-Fi → LTE switch is
genuinely useful on mobile, and it tells the relay that the old address and the
new address are the same client — the RFC warns about exactly this and requires
distinct connection IDs. The private posture is the default: on a network
change, a new session on a new connection and a new route. Migration
is an explicit opt-in whose UI text says plainly what the relay learns. Same
shape as the direct-P2P rule: the convenient thing is opt-in, never a "safe"
default.

**ALPN: `karst-relay/1`.** Version negotiation lives here, not in a
handshake-time guess.

---

## 5. What QUIC does not fix

Stating these because a transport change invites the assumption that it fixes
things one layer up.

**Offline delivery.** QUIC connects two endpoints that are both online. It is
not store-and-forward. Alice deposits, the relay holds the ciphertext, Bob
appears a day later and fetches it — mailboxes, leases, durable ACKs and blob
storage remain application concerns and are untouched.

**End-to-end encryption.** QUIC TLS covers client ↔ relay only. PQXDH, the
Double Ratchet and bundle signatures all stay exactly where they are. QUIC must
never see plaintext: KARST ciphertext goes *into* QUIC TLS, not the reverse.

**The relay's internal concurrency.** The global relay lock is an `RwLock` since
#142, but if every QUIC stream still queues behind one writer, multiplexing
buys nothing inside the relay. QUIC delivers requests in parallel; it does not
make the handler parallel. That is #146's problem and QUIC does not touch it.

**Acknowledgement semantics.** A QUIC ACK means a packet reached the transport
stack. It does not mean the relay durably recorded the message, and it certainly
does not mean the recipient stored and decrypted it. These stay four distinct
states:

```
QUIC packet acknowledged
  ≠ relay durable receipt
  ≠ recipient durable ACK
  ≠ read by the user
```

KARST's own deposit ids, durable receipts, leases and recipient-level ACKs
remain necessary and unchanged.

---

## 6. Stream model

**One operation, one bidirectional stream.** The client opens a stream, writes
the request header and body, finishes its send half; the relay checks limits,
executes, writes the response and finishes the stream. This is the shape the
current one-request-per-connection code already has, which is why it drops in
without touching the layers above.

**One long-lived control stream** for protocol version, capability negotiation,
server notices, graceful shutdown, backpressure and checkpoint announcements.

**One blob, one stream** — never a stream per chunk, which would multiply
stream state into the thousands. *Built (QUIC-7), and it turned out to be half
built already:* an UPLOAD has held one session for a whole file since FT4, so on
this carrier it was already one stream. A DOWNLOAD was not — every chunk paid a
fresh connect and a fresh Noise handshake, so a large file cost tens of thousands
of handshakes to fetch and one to send. `BlobSession::get` is the missing half,
and a download now scopes its session by its own `client_addr` (fresh per
download since #248), which is what keeps two transfers off one pooled
connection. Small feed media stays one-shot on purpose: bounded by
`MAX_POST_IMAGE_BYTES` and usually a single chunk, it would pay a session setup
to save nothing. Reopening is the NORMAL case, not the exception —
`MAX_REQUESTS_PER_CONN` ends the relay's run on any large file — so a failed
reopen degrades to the old one-shot fetch rather than failing a download that
would otherwise have worked. The stream header carries operation id, blob
id, total size, chunk range, content hash and the capability proof; the chunks
follow as binary. Everything the blob path already guarantees stays: per-chunk
salt and content-bound upload id (CRYPTO-31), resumable uploads (A4-1), state
proportional to arrived rather than declared chunks (A5-2). And
`MAX_CHUNK_PAYLOAD` does not move — it is fixed by 1400-byte packet camouflage,
and the throughput win there came from batched saves, not larger chunks.

---

## 7. Limits the relay needs before any of this ships

QUIC has built-in address validation and amplification limits before a client's
address is confirmed. Those are transport-level and not sufficient. KARST must
add, at minimum:

- max QUIC connections per IP
- max connections per capability
- **max concurrent streams before any stream on that connection has passed
  admission**
- max request bytes per stream
- max blob streams per client
- connection-wide flow-control limit
- stream idle timeout
- handshake deadline
- application deadline
- global memory budget

### The one that is a real regression risk

`MAX_UNADMITTED_REQUESTS` (R2-13, 8) is counted **per connection**, and that
works today only because a connection carries one request. Under QUIC an
attacker opens thousands of streams on a single connection and sends nothing in
any of them. The leash must therefore count **across all streams of a
connection**, with its own ceiling on concurrent streams that have not yet had
one admitted. Without that, R2-13 is closed on TCP and wide open on QUIC —
a protection that exists on one carrier and not another is worse than one that
exists nowhere, because the record says it is closed.

---

## 8. Transport selection

```
1. Direct path → start QUIC at t=0
2. Start WSS at t=200–400 ms, in parallel
3. First transport to AUTHENTICATE successfully wins
4. Tor/SOCKS without UDP ASSOCIATE → go straight to TCP/WSS, no QUIC attempt
```

Never wait out a QUIC timeout before falling back: networks drop UDP silently,
so the timeout is the common case, not the exception.

**Both routes must perform the identical relay-identity check and carry the
identical end-to-end message.** A race must never become a path to a weaker
check — that is the silent-downgrade shape this codebase has caught before
(A8-11: no quiet fallback to the dev capability).

Some of this already exists: `SocketTransport` keeps an ordered `Path` list and
fails over on connect-or-handshake failure, and `PathHealth::last_ok` (#217)
already feeds the carrier indicator. That indicator must name the transport that
actually carried the bytes, never the one that was attempted first.

---

## 9. Datagrams — later, and a product decision

QUIC datagrams are delivered without retransmission, which suits data that
expires quickly: typing indicators, short-lived presence, latency measurement,
call signalling, real-time media metadata.

**Never** for messages, key changes, mailbox ACKs, quota operations, credential
revocation or administrative commands. All of those change state and belong on
reliable streams.

Note what this actually proposes: presence and typing are **new metadata
disclosures**. KARST has none today. Whether they exist, and who can see them,
is a product decision that must be made before the transport makes them cheap.
Call signalling additionally sits under the standing rule that direct P2P is
opt-in only, never a default and never an automatic "safe" fallback; the relay
remains the primary mode.

**DECIDED (QUIC-8): they are not emitted — not "off by default", not built.**
See `docs/design/presence-and-typing.md` for the reasoning, for the one shape a
reversal could take (the ordinary message path, never a datagram — a datagram is
distinguishable, which is the specific problem), and for why neither side sets a
QUIC keepalive: a heartbeat per pooled connection is a heartbeat per scope, i.e.
presence at a lower resolution introduced as a performance setting. That
absence is pinned by a test, because the "fix" for it is one unremarkable line.

That leaves nothing in this section to build. Call signalling has no calls to
signal yet, and latency measurement is QUIC's own. So QUIC-8 ships as a decision
rather than as a datagram path with nothing safe to carry.

---

## 10. Descriptor additions

`RelayDescriptor` gains ONE field:

```rust
quic_addrs: Vec<String>,   // UDP endpoints where this relay also answers QUIC
```

Bounded exactly like `addrs` (`MAX_ADDRS_PER_RELAY`, `MAX_ADDR_LEN`, swept on
gossip and on discovery-record storage), for exactly the same reasons: these are
operator **claims**, not proofs (CRYPTO-23), and an unbounded list is both an
SSRF vector and a memory-growth one (A3-12, A3-13).

**The sketch for this work proposed three more fields. On inspection, none of
them should exist:**

- **`quic_alpn`.** The ALPN is a protocol CONSTANT (`karst-relay/1`), not
  per-relay data. Advertising it per relay would let a relay name a different
  one — a negotiation nobody asked for, at the layer that decides which protocol
  is spoken.
- **`quic_cert_fingerprint`.** It would be unverifiable today. The descriptor's
  signature covers the relay-id and NOTHING else (`discovery::location_id`
  deliberately excludes `addrs`, because dial hints are availability, not
  identity). A fingerprint would therefore sit in the unsigned part, where a
  relay in the middle substitutes it — a field that invites exactly the trust it
  cannot carry. It becomes meaningful only if QUIC's TLS ever REPLACES Noise as
  how relay identity is established, which is §6's audit-gated decision. Add it
  *then*, together with signing it.
- **`supported_transports`.** It would restate "is `quic_addrs` non-empty" — a
  second place saying the same thing, hence a second place that can disagree with
  the first, with an attacker choosing the disagreement. Same reasoning that kept
  `message_type` out of the wire envelope.

Relay identity is not established by an address in any case: it is `Noise_NK`
against the pinned relay-id, over whichever carrier the bytes arrived on. That is
what makes a QUIC address safe to publish unsigned — the worst a forged one
achieves is a failed handshake.

## 11. Summary of the trade

**Gained:** better behaviour on lossy and unstable networks; independent streams
so a file transfer stops blocking messages and ACKs; a session that can survive
a network change (opt-in); a foundation for calls and real-time data; fewer OS
threads; faster reconnection to a known relay; QUIC on UDP/443 alongside WSS on
TCP/443.

**Paid:** UDP is blocked on some networks; Tor cannot carry it, so TCP/WSS stays
mandatory rather than legacy; a larger codebase (three carriers plus selection
logic); connection reuse re-introduces a linkage channel, which is why §1 fences
it to the direct path; a new class of DoS limits; a second transport handshake
and a second layer of transport encryption for as long as Noise stays; and
0-RTT stays off, so the fastest thing QUIC offers is deliberately not used.

**Not gained:** offline delivery, end-to-end guarantees, relay-internal
concurrency, or any of the acknowledgement semantics above.
