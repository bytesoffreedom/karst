# Typing indicators and presence — the decision, and the only version that would not break the model

**Status: a DECISION not to build something, plus the design that would follow
if it is ever reversed.** The transport work that would have made these cheap
(QUIC datagrams, QUIC-8) is finished around them; this document is why the last
step was not taken.

---

## What was on the table

`docs/design/quic-transport.md` §9 lists what QUIC datagrams suit: data that
expires faster than a retransmission would arrive. Typing indicators,
short-lived presence, latency measurement, call signalling. The transport was
built to the point where adding them would have been a small change.

That is exactly the moment to decide, rather than after the change is small
enough that nobody notices it being made.

---

## The decision

> **KARST does not emit typing indicators or presence. Not off by default —
> not built. The transport work stops at the point where it would begin to
> manufacture a metadata channel that does not exist today.**

Three reasons, in the order they actually decide it.

**It is a new disclosure, not a cheaper version of an existing one.** Everything
else on the wire is a discrete event a user caused: a message deposited, a
bundle published, a blob fetched. Presence is *continuous*, and typing is
finer-grained than the message it precedes — it reports the composition of a
message that may never be sent. A relay watching one channel's datagram stream
learns when its owner is at the keyboard, for how long, in what rhythm, and
which conversations that correlates with. Nothing in KARST produces a signal of
that resolution now, and the whole architecture is built to keep it that way:
disposable channels, blinded drop-boxes, per-download addresses (#248),
per-channel credentials (#206). Spending that on "…is typing" is a bad trade in
a product whose threat model is metadata.

**A datagram is distinguishable, which is the specific problem.** Ordinary
traffic here is a request on a reliable stream. A datagram is a different frame
type on the same connection, unreliable and unacknowledged — a relay separates
the two without decrypting anything. So a presence datagram is not "one more
packet among many"; it is a *labelled* packet whose mere existence says
"activity, now, on this channel". That is worse than sending presence as an
ordinary message would be, and it is the feature this task was about.

**"Off by default" is not a resting state.** It is a switch, and a switch that
ships in a messenger gets turned on for parity with messengers that have it.
The honest posture is that this signal has no place in the design, said once,
rather than a preference toggle whose text nobody reads. The same shape as the
standing rule that direct P2P is opt-in and never an automatic "safe" fallback
— except that rule keeps a capability the user may genuinely need, and this one
would not.

---

## What that leaves from QUIC-8

- **Typing / presence** — refused, above.
- **Call signalling** — nothing to signal. Calls are not built, and when they
  are they sit under the direct-P2P rule (opt-in, relay stays the primary mode),
  so their signalling design belongs to that work and not to the transport.
- **Latency measurement / keepalive** — already provided by QUIC itself, and
  deliberately left off. See below; this is the part that touches code.

So QUIC-8 ships as this document. That is the whole deliverable, and saying so
is more useful than shipping a datagram path with nothing safe to put in it.

---

## The keepalive that is deliberately absent

Neither side sets `keep_alive_interval`. Both set `max_idle_timeout` to
`READ_TIMEOUT` (15 s), so a pooled connection with nothing to carry simply dies,
and the pool evicts and redials it on the next use (`QuicAdapter::pool`).

This will look like a defect the first time someone profiles the pool: the
connection everyone wanted to keep warm keeps going cold. It is not. A keepalive
is a periodic packet per pooled connection — that is, **per scope** — sent while
the user is doing nothing. It is presence, at a lower resolution, arriving
through the back door of a performance setting. A redial costs one handshake on
the next request; a keepalive costs a heartbeat the relay can graph for as long
as the client is running.

If a future pass wants warm connections, the trade has to be argued here first,
not settled in a transport config.

---

## If this is ever reversed, this is the shape

Recorded so a reversal starts from a design rather than from the easiest patch.

1. **It rides the ordinary message path, not a datagram.** An indistinguishable
   signal costs unlinkability nothing; a distinguishable one costs it everything.
   That means an ephemeral, end-to-end encrypted message the relay cannot tell
   from any other deposit — which also means it pays a deposit's quota, and the
   cost is the point: it bounds the rate to something coarse enough not to be a
   keystroke trace.
2. **Coarse by construction, not by convention.** "Composing" latched for a
   fixed window with no update while it holds, never an event per keystroke and
   never a "stopped typing". A signal that cannot be sampled finely cannot be
   graphed finely.
3. **Per channel, never per account.** The same rule as everything else here:
   a proxy's presence must not be joinable with another proxy's (#206, #248).
4. **Recipient-visible only.** Presence a relay can read is presence for the
   relay. If it is not end-to-end sealed to the specific contact, it is not this
   feature, it is telemetry.
5. **And the cost stated where the switch is.** Not in this file — in the UI
   text next to the setting. A privacy cost documented only in a design
   repository is a cost the user never paid knowingly.

---

## What this does not touch

- **Delivery and read state** are a different question, already answered
  differently: an ACK exists because the protocol needs it for at-most-once
  delivery (SEC-34, R2-6/7), and it is bounded, discrete and caused by a
  received message rather than by a person's attention.
- **The QUIC datagram capability itself** stays unconfigured rather than
  disabled-with-a-flag. There is nothing to send; a path with no payload is not
  a feature waiting to be enabled.
