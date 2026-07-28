# Duress, decoy, and dead-man passwords — audit & plan

Status: **Tier 1 SHIPPED end-to-end** — keyslot foundation + decoy / wipe (duress) /
dead-man, all wired in the desktop Security card. Tier 2 (opaque hidden-volume container)
is deferred and opt-in (see ROADMAP). This note audits how to add multiple device passwords
with distinct behaviours and lays out the phased, honest plan. Source of truth is the code;
when they disagree, fix this note.

## Implementation status (what's built vs. promised)

Built in `client::store` (layout A′, the user chose "hide from disk analysis"):
- **Keyslots** — `slots.dat`, `SLOT_COUNT` fixed-length records; each configured
  password owns one, unused slots are `MAGIC ‖ random` of the same length, so the
  slot table does not reveal how many passwords exist. `Vault::open` derives the
  key once and trial-opens every slot to route.
- **Symmetric compartments** — every compartment (real included) lives under
  `base/c/<random_id>/`; real and decoy are structurally identical, so **no blob
  is visibly "the primary one."** This is the single biggest tell A′ removes over
  the rejected Design A (which left `accounts.dat` at the root).
- **Migration** — a pre-multipassword vault is relocated root→`c/<id>/` on first
  open, copy-then-commit(slot)-then-delete, idempotent and crash-safe (verified by
  test). No re-encryption of real secrets.
- **Clobber-safe management** — `slotmap.dat` (sealed under the real key) tracks
  occupancy so a new decoy/wipe slot never overwrites another password's slot.
- **Crypto-erase** — `Vault::open` on a wipe slot shreds `salt` first (that alone
  makes every compartment permanently unopenable) then unlinks the rest.
- Routing (`Opened::{Real,Decoy,Wipe}`) + roles + tests are in. `Vault::unlock`
  stays as a compat wrapper so every existing caller is unchanged.

**Honest residual leaks (A′ is NOT a full hidden volume — say so in the UI):**
- **Compartment count / size correlation.** A coercer who opens the decoy can
  still *count* the `c/<id>/` directories and compare their sizes, so A′ hides
  *which* compartment is real but not fully *that a hidden one exists*. Closing
  this needs a fixed pool of same-shaped dummy compartments — and even that leaks
  via size unless data is padded to a fixed container. **True existence-hiding is
  Tier 2** (opaque fixed-size container); A′ is "can't tell which is real," a real
  improvement but not "can't tell a hidden one exists."
- **Base-level tells.** `slots.dat` and `slotmap.dat` at the vault root reveal
  that a keyslot system (and a real key) exist. Same Tier-2 fix.
- **Crypto-erase on SSD/CoW/journaled FS.** Deleting the 16-byte `salt` is
  crypto-erase only in theory; the bytes can linger in free space, so a forensic
  adversary who imaged the disk (or recovers the salt) plus a known password could
  still get in. Adjacent to the pre-image caveat below.

The Security-card UI copy MUST state these plainly so no one over-trusts the
decoy under genuine threat.

## The four password roles the user asked for

1. **Real** — the normal password. Opens the real vault (all accounts). (exists today)
2. **Wipe (duress)** — entering it destroys all data instead of unlocking.
3. **Decoy** — opens a plausible but empty/innocuous account; the real vault
   stays hidden. Plausible deniability under coercion.
4. **Dead-man switch** — the real password must be entered at least once per
   configured interval; if the interval lapses, all data is auto-wiped.

## What the current architecture already gives us (the key insight)

`Vault::unlock(base, passphrase)` derives a `MasterKey` with Argon2id over
`(passphrase, salt)` and **does not verify the password**. There is no verifier
file. A wrong password simply derives a different key, and the *registry*
(`accounts.dat`, XChaCha20-Poly1305) fails to authenticate on `open()` — that
AEAD failure is the implicit "wrong password".

Consequences that make this feature natural rather than bolted-on:

- **Different passwords already produce different keys and different views.**
  A decoy password is not a special case — it is just another key that happens
  to decrypt a different container.
- **AEAD `open()` fails cleanly on the wrong key** (authenticated, no garbage).
  So we can *trial-decrypt* a small set of "keyslots" and act on whichever one
  authenticates. This is the VeraCrypt/LUKS keyslot idea.
- **Everything at rest is sealed under a salt-derived key**, so shredding the
  `salt` file is an instant, irreversible **crypto-erase** of the whole vault
  (real + decoy) — a fast, plausible wipe primitive that needs no per-file
  overwriting.

## Core mechanism: a keyslot table (unifies all four roles)

Replace the single implicit "registry = verifier" with a small **keyslot file**
`slots.dat`: a fixed array of `N` (say 8) fixed-size records. Each *configured*
password owns one slot; unused slots are decoy fill.

**Slot fill must match the sealed-blob shape, or the count leaks.** A sealed
blob is `MAGIC(4) ‖ nonce(24) ‖ ct` (see `secretbox`), and `ct` is pseudorandom
without the key — but the fixed 4-byte `MAGIC` prefix is a tell. If unused slots
were pure random, an adversary would count *used* slots by counting the magic
prefixes. So unused slots are written as `MAGIC ‖ 24 random bytes ‖ random tail`
of the same fixed length: prefix identical, remainder indistinguishable from a
real ciphertext without the key. Only then is the number of configured passwords
not inferable from `slots.dat`.

On unlock, derive `K = Argon2id(password, salt)` and **trial-`open()` every
slot**. The slot that authenticates yields a small plaintext:

```
struct Slot {
    role: u8,          // 0=Real, 1=Decoy, 2=Wipe
    vault_id: [u8;16], // which container this password opens (Real/Decoy)
    // (reserved)
}
```

- **Real** → open the real container (`accounts.dat` today) and enter.
- **Decoy** → open the decoy container (its own registry + account dir) and enter.
- **Wipe** → crypto-erase (shred `salt` + slots + all account dirs), then show
  the fresh "create account" screen as if nothing was ever here.
- **No slot authenticates** → "wrong password" (unchanged UX).

Why this is the right shape:

- **One code path** handles decoy, duress, and normal — the role byte routes.
- **The wipe trigger is indistinguishable from a decoy slot** on disk: both are
  just AEAD blobs. A forensic adversary cannot point at "this is the wipe slot".
- **Deniable slot count**: unused slots carry the same magic prefix + random
  tail as sealed ones (see the fill note above), so the number of configured
  passwords is not revealed by the file. (Pure-random fill would leak it via the
  magic prefix — do not skip this.)
- Adding a password requires the **real** password (to derive the vault linkage
  and write a new slot under the shared salt); this is enforced in the UI.

### Migration from today's single-password vaults

First unlock after upgrade: if `slots.dat` is absent but `accounts.dat`
authenticates under the entered key, synthesise a single Real slot for that key
and write `slots.dat` (idempotent, mirrors the existing `migrate_legacy`
commit-last pattern). Old vaults keep working; the slot table is created lazily.

## Dead-man switch

Store, inside the real container (sealed under the real key), `last_seen` (unix
secs) and `deadman_interval` (0 = disabled). Every successful **real** unlock
rewrites `last_seen = now`.

Enforcement points:
- **On launch**, before showing the unlock screen, if a plaintext "armed"
  marker says a deadman is configured and `now - last_seen > interval`, wipe.
  (The interval/last_seen themselves are sealed; to check them pre-unlock we
  keep a *separate, minimal* plaintext `deadman.dat` = `{armed: bool,
  last_seen, interval}`. This leaks that a deadman exists — accepted, see
  Threat models.)
- **Optional background agent** (systemd user timer / autostart) that runs the
  same check even if the app is never opened — otherwise an adversary defeats
  the switch by simply not launching the app. Ship the app-launch check first;
  document the agent as the stronger tier.

Decoy unlocks do **not** reset the real `last_seen` (the point is that a coerced
user giving the decoy password does not keep the real data alive).

## Wipe semantics

**Tier-2 container caveat (CRYPTO-12), stated before the Tier-1 description below:**
`Container::wipe()` randomises the buffer and persists it — but `persist` writes a NEW
file and renames over the old name, so the previous inode (keyslots, wrapped region
keys, ciphertext) is UNLINKED, not overwritten. Those blocks can survive in free space,
the journal, a CoW snapshot, the SSD FTL or a backup, and reopen if a P1/P2 password is
later obtained — even for an adversary who imaged the disk only *after* the wipe.
In-place overwriting would not fix it either. Call it best-effort; a real guarantee needs
an independently erasable KEK (OS/hardware keystore) that wipe destroys.

`wipe()` (Tier 1) = crypto-erase: remove `salt`, `slots.dat`, `deadman.dat`, and
`accounts/` (real and decoy dirs). Because every sealed file's key is
`Argon2id(pw, salt)`, deleting `salt` alone already makes *all* ciphertext
permanently unopenable even with the correct password. We still unlink the
account dirs so the on-disk footprint shrinks to "fresh install". Best-effort
`fsync` the parent dir. Note honestly: this does **not** defend against an
adversary who imaged the disk *before* the wipe — it defends against
coercion-to-unlock and against later loss or theft of the disk.

## Threat models — be honest about what each tier buys

- **Coercion-to-unlock (mugging or other physical coercion):** you are forced to type *a*
  password. Decoy (show empty account) and Wipe (destroy) both defend here.
  Strongest realistic protection this feature offers.
- **Forensic disk analysis (adversary images the disk cold):** Tier 1 leaks
  that *compartments* exist — account directories are discrete, visibly-sized
  files, and `deadman.dat` reveals a switch is armed. So Tier 1 gives
  *behavioural* deniability (what a password *does* when typed), **not**
  hidden-volume deniability (proving the real vault does not exist). This must
  be stated plainly in the UI so no one over-trusts it.
- **Pre-image + coercion (they copy the disk, THEN make you talk):** no
  software-only scheme fully wins; crypto-erase is moot against a prior image.
  Out of scope; document it.

## Tiers

- **Tier 1 (shippable on current architecture):** keyslot table (Real/Decoy/
  Wipe), decoy = separate empty account container, wipe = crypto-erase,
  dead-man switch with app-launch enforcement. Discrete account dirs remain
  visible → behavioural deniability only. **This is the plan we execute.**
- **Tier 2 (future, large):** true hidden-volume deniability — an opaque
  single-container store with random-named per-slot storage and
  indistinguishable free space, plus a background dead-man agent. Deferred;
  tracked separately.

## UI (everything must work in the UI — user requirement)

New **Security** card in Settings, gated behind the real password:
- "Add a decoy password" → set a second password that opens an empty account.
- "Add a duress (wipe) password" → set a password that erases everything;
  with a blunt warning + a distinct-from-real-and-decoy check.
- "Dead-man switch" → toggle + interval picker (e.g. 1/3/7/30 days); shows time
  remaining; a clear "this erases all data if you don't sign in" warning.
- "Remove" for each configured extra password.
- An honesty banner stating Tier-1 limits (behavioural deniability, not
  hidden-volume).

The unlock screen is **unchanged**: the user just types whichever password; the
keyslot router decides Real/Decoy/Wipe transparently. No UI hint that extra
roles exist (that would defeat the point).

## Crypto/UX hazards to get right

- **Typo safety:** a typo of the real password derives a random key that
  matches no slot → "wrong password". It cannot accidentally hit the Wipe slot
  (would need to derive `K_W` exactly — 2^-huge). Confirmed safe by AEAD.
- **Distinct passwords:** enforce decoy ≠ real ≠ wipe at set-time (compare
  derived keys, not plaintext) so roles never collide.
- **Argon2id cost × N slots:** trial-decrypt is `N` AEAD `open()`s but only
  **one** Argon2id derivation (all slots share the salt+key). Cheap.
- **No plaintext role map ever** (except the deliberate `deadman.dat` marker).
- **Wipe must be atomic-ish:** shred `salt` FIRST (that alone is the erase),
  then unlink dirs; a crash mid-unlink still leaves everything crypto-dead.

## Verification plan (when implemented)

Unit/integration tests in `client`:
- three distinct passwords → Real opens real, Decoy opens empty decoy, Wipe
  erases (salt + dirs gone, subsequent real password now fails).
- unused slots carry magic-prefix + random tail (byte-shape identical to a
  sealed slot); slot count not inferable from `slots.dat`.
- migration: legacy single-password vault gains a Real slot on first unlock.
- dead-man: advancing the clock past interval wipes on launch; a real unlock
  inside the interval resets `last_seen`; decoy unlock does not.
- typo never triggers wipe; decoy/real/wipe key-collision rejected at set-time.

Desktop: click-through of the Security card (add/remove decoy, add/remove wipe,
arm/disarm dead-man), plus an unlock-screen test that each password routes
correctly.
