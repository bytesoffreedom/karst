# Design note: reusing one Noise session for many requests (FT4), safely

**Status:** analysis + decision. Records an ATTEMPT that was reverted, the DoS property that reverted
it, and the target design — so a future implementation is not started from scratch and does not
re-ship the regression.

## The goal

A large-file transfer is many small requests (one `BlobGet`/`BlobPut` per ~60 KiB chunk). Today each
request is its own connection: **TCP connect + Noise handshake + one request/response + close**
(`node/src/socket.rs`, `handle_conn` serves exactly one request; `SocketTransport::round_trip` opens a
fresh connection per call). Over a high-latency carrier (Tor) that handshake-per-chunk dominates
transfer time. Reusing ONE Noise session for the whole file — one handshake, many request/response
pairs — is the single biggest speedup available for large transfers.

## What was attempted, and why it was reverted (2026-07-20)

**FT4a:** split `handle_conn` into a `serve_request` loop so one session carries many requests
(backward-compatible — a one-shot client sends one request and closes, and the next read returns
cleanly, ending the loop). It was functionally clean and the whole test suite passed, including a new
multi-request test.

**Reverted in review.** The change alters the relay's **resource/DoS posture** — a thing tests cannot
see:

- **Before:** a connection = handshake + one request + close. To occupy a `ConnLimiter` handler
  thread continuously, an attacker must **re-handshake** every ~`CONN_READ_TIMEOUT` (30 s). STATUS
  names that per-connection handshake as the (weak) CPU-cost limiter on connection churn.
- **After the loop:** one handshake, then hold the thread **indefinitely** by trickling one cheap
  request (a `GetNodeList`) every 29 s. The per-read timeout bounds *idle-per-read*, NOT total
  connection lifetime; the `ConnLimiter` (`MAX_CONNECTIONS = 1024`) is precisely what gets exhausted.
  `N` such slowloris clients pin all handler permits forever and deny everyone else — cheaper and
  unbounded versus the re-handshake cost before.

Crucially, **there was zero benefit yet**: no client sends multiple requests per connection until the
client half (below) exists, so the merge would have activated the attack surface for nothing. On an
explicitly-untrusted relay that is not an acceptable trade. (This is the same "don't silently worsen
the untrusted-relay DoS profile" standard the rest of the relay work holds to — so it blocks.)

## Target design — bounded connection reuse

Reuse is fine; **unbounded holding** is the problem. Bound it on two axes, ON TOP of the existing idle
`CONN_READ_TIMEOUT`:

1. **Requests-per-connection cap.** After `MAX_REQUESTS_PER_CONN` served requests, close the
   connection; the client reconnects (paying one handshake). The cap must clear a legitimate large
   transfer in one connection: a 2 GiB file is up to `MAX_BLOB_CHUNKS` (~40k) chunks, so the cap must
   exceed that with headroom (e.g. 64k) — high enough that honest transfers never reconnect
   mid-file, low enough that it is a finite bound, not "forever".
2. **Total-connection-lifetime cap.** A wall-clock ceiling per connection (e.g. a few minutes past the
   expected slow-link transfer time) so a slowloris trickling *under* the request cap still cannot
   hold a thread indefinitely. Set from: `MAX_BLOB_CHUNKS × worst-case per-chunk RTT over Tor`, plus
   headroom — the same envelope the request cap is sized against.

Both are cheap (a counter + a deadline in the `serve_request` loop). The honest tension is that the
caps must simultaneously (a) never interrupt a real multi-GB transfer over a slow circuit and (b)
still bound abuse — that envelope is the real design work, and why FT4 is its own slice rather than a
drive-by. Pick the numbers from the transfer envelope, write them down here when chosen, and pin them
with a test (a legit `MAX_BLOB_CHUNKS`-request transfer completes on one connection; request N+1 past
the cap forces a reconnect).

Also revisit **`ConnLimiter` accounting** for long-lived connections: with reuse, a handler thread is
held for a whole transfer, so `MAX_CONNECTIONS` now bounds *concurrent transfers*, not *concurrent
requests*. Either raise it, or (better) separate "in a transfer" from "idle between requests" so a few
big transfers cannot starve many small interactions.

## Dead end (recorded so it is not retried): a response-byte throughput floor

A second attempt (2026-07-20) tried to distinguish a real transfer from a slowloris by a **minimum
average RESPONSE-byte throughput** (close a connection whose bytes/sec falls under a floor after a
grace period), on the theory that a real transfer streams ~60 KiB chunks while a trickler moves almost
nothing. **It does not work, and the structure cannot be re-tuned into working.** The floor is on
*response* bytes, which the attacker controls cheaply: any request eliciting a response larger than
`floor × read-timeout` (e.g. a `BlobGet` on a **self-uploaded** blob → ~60 KB), trickled once per
timeout window, sails over any floor low enough to spare a slow honest transfer — while still pinning
the thread. So the effective bound collapses back to the lifetime cap alone, and "upload one blob
first" is the whole cost. A false bound (with a passing test that asserts safety) is worse than a
named gap, so it was reverted. **Do not reintroduce a byte-rate floor.**

**Promising direction instead: bind a reused connection to the ADMISSION CAPABILITY's existing
quota.** The relay already gates real work behind a capability with a per-window request/byte quota
(`admission`, §7). Rather than guessing a byte rate, count a reused connection's requests against that
capability's quota (or cap requests-per-connection by it) — abuse is then bounded by the same
mechanism that already prices sending, not by a heuristic. Design this properly in the dedicated FT4
session; it is the reason FT4 is not a marathon add-on.

## The client half (FT4b), and its separate risk

The relay loop alone does nothing; the client must actually reuse a connection across a transfer. Two
shapes, each with a cost:

- **Transparent keep-alive in `SocketTransport`** (cache a live session, reuse it on the next
  `round_trip`): the blob loops (`download_blob`/`blob_upload_with`, with their cookie/resume/cancel/
  progress logic) do not change — but this touches the CORE request path used by EVERY request type,
  and must interact correctly with the existing **path-failover + "nothing retried after the request
  is written"** invariants (`round_trip_scoped_sized`). High blast radius.
- **Explicit session handle used only by the blob loops:** narrower blast radius (only the blob path
  changes), but invasive to those already-complex, integrity-checked loops.

Neither is a drive-by; pick one deliberately in the FT4 session. Favour the option whose failure mode
is *loud* — the blob path is AEAD-per-chunk + end-to-end SHA-256, so a reuse bug fails a transfer
(retry) rather than corrupting data, which is the safer place to take the risk.

## Summary for the implementer

Ship the relay `serve_request` loop **only together with** a working DoS bound and one client
consumer — never the loop alone, and never a byte-rate floor (proven a dead end above). The bound
should ride the **admission capability's quota** (count a reused connection's requests against the
capability that already gates the relay), plus the `ConnLimiter` re-accounting for long-lived
connections. **Two attempts are on record** (unbounded FT4a; the response-throughput floor) precisely
so the third does not repeat them — start from the quota-binding design, in the dedicated session.
