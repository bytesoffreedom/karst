# Format & protocol versioning

How KARST handles format change, so a future breaking change does not silently
mis-parse. This is the discipline behind backlog item #6.

## The mechanism that governs at-rest data: `STATE_VERSION`

Every at-rest blob is written by `MasterKey::seal(label, plain)` in the format-v2
envelope:

```
MAGIC("KRS2") ‖ state_version(u16 LE) ‖ nonce(24) ‖ AEAD(key = HKDF(master, label),
                                                        aad = MAGIC ‖ version ‖ len(label) ‖ label)
```

`secretbox::STATE_VERSION` is the version of the **state schema**, not of the
envelope. The rule is short:

> **Change any struct that is persisted under this envelope → bump `STATE_VERSION`.**

`open` refuses any other version with a message that names the direction ("written
by a newer/older KARST … upgrade the client"), distinct from both "not our format"
and "wrong password". An older binary therefore cannot read a newer file, fill the
fields it does not know with defaults, and write that loss straight back (A6-5).

The cost is deliberate and stated plainly: bumping the version makes existing local
data unreadable. There are no users and no migrations (see `docs/POSITIONING.md`);
that window is worth more than the shims it replaces.

The `label` half of the envelope is the at-rest context — `acct:<id>/contacts.dat`,
`vault/accounts.dat`, `keyslot` — so a sealed file is bound to the account and the
name it lives under, not merely to the device key (CRYPTO-05). Labels are LOGICAL:
they never contain a real filesystem path, so moving the vault directory does not
break decryption.

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

1. **~~Try-new-then-fallback~~ — REMOVED.** `PeerState::from_bytes_compat` and the
   at-rest `#[serde(default)]` trailing fields are gone. They existed to let a new
   binary read old data, and their mirror image — an old binary reading new data
   lossily — is exactly A6-5. `STATE_VERSION` replaces both: one loud refusal
   instead of two silent guesses.

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

- Changed a persisted struct → **bump `secretbox::STATE_VERSION`**. Always.
- New at-rest format that will keep evolving on its own cadence → **`seal_versioned`**
  (a per-file version inside the envelope, on top of the global one).
- Never add a compat shim so an old binary can read new data; that is the bug.
- A value that is hashed, not parsed → **a `VERSION` constant in the digest**.
- Never trust `#[serde(default)]` to migrate postcard data.
