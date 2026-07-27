# Format & protocol versioning

How KARST handles format change, so a future breaking change does not silently
mis-parse. This is the discipline behind backlog item #6.

## The reality: postcard is positional, `#[serde(default)]` is inert

Persisted and wire formats are `postcard` (compact, non-self-describing). Fields
are encoded **by position**, with no names and no per-field framing. Two
consequences that are easy to get wrong:

- **Appending a field is a break for OLD readers of NEW data only if they parse
  strictly; NEW readers of OLD data always break** — the trailing field's bytes
  are absent, so `from_bytes` errors with `UnexpectedEnd`. Never reorder or insert
  fields; append only.
- **`#[serde(default)]` does nothing under postcard.** postcard reads each field
  positionally and errors on a missing trailing field — it never falls back to
  `Default`. The attribute is present on a few structs (`FetchRequest.ack`,
  `PreKeyBundle.prekey_sig`, `PeerState.outbox`, …) only for a hypothetical
  self-describing path (`serde_json`) and to document intent. **Do not rely on it
  for on-disk / on-wire migration.** Read the code, not the attribute.

## Three real mechanisms in use

1. **Try-new-then-fallback (at-rest, positional).** `PeerState::from_bytes_compat`
   tries the current layout, then a mirror of the previous one on `UnexpectedEnd`,
   filling new fields with a chosen default. Same per-record for the history log
   (`StoredHistory` → bare `HistoryRecord`) and the received-files index
   (`ReceivedFile` → `ReceivedFileV0`). **Order matters:** try NEW first — postcard
   *ignores trailing bytes*, so trying OLD first would silently drop the new field
   from new data. This is correct but does not scale past a couple of versions.

2. **Explicit version envelope (`Store::seal_versioned` / `open_versioned`).** For
   formats where a clean version tag is worth it, the sealed plaintext is prefixed
   with a 4-byte magic (`KRV1`) + a `u8` version, then dispatched on load. Unlike
   (1) this is unambiguous (a magic never collides with a postcard length byte) and
   scales to N versions by adding a match arm. The pending-downloads store
   (`downloads.dat`) uses it as the reference; new at-rest formats should adopt it
   rather than growing another try-fallback mirror. It lives INSIDE the seal, so
   the version is authenticated.

3. **Hashed VERSION constant (derived values).** Where the format feeds a hash
   rather than a parser — the safety number — a `const VERSION: u8` is mixed into
   the digest (`safety.rs`), so a change produces a different, non-colliding value.

## Wire formats

The session/admission wire (`WireRequest`/`WireResponse`, `PreKeyBundle`) is
negotiated fresh per connection and there are no external users yet, so a breaking
wire change is handled by a coordinated deploy (client and relay ship together),
not runtime negotiation. If/when independent client versions must interoperate,
add an explicit protocol-version field to the handshake (the same envelope idea,
one layer up) — tracked here so it is a deliberate step, not a silent assumption.

## Rule of thumb

- New at-rest format, or a format likely to change again → **`seal_versioned`**.
- One-off field append to an existing positional struct → **try-new-fallback**,
  append-only, new-first.
- A value that is hashed, not parsed → **a `VERSION` constant in the digest**.
- Never trust `#[serde(default)]` to migrate postcard data.
