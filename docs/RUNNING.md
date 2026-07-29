# Running KARST locally

> **SKELETON, NOT for production.** Brings up a dev relay with a public
> capability secret; the crypto is a reference and unaudited (see
> [STATUS.md](STATUS.md)). The goal is to run the whole system on one machine and
> confirm that it works.

Scope: **Linux desktop** (relay + CLI `karst` + the Tauri client `karst-desktop`).
The Android client is a separate large effort and is not here.

## Quick check — one command

Brings up a relay and two clients, sends a message in both directions, and cleans
up after itself:

```sh
scripts/karst-demo.sh
```

Expected tail of the output:

```
[<Alice's IK>…] hi Bob — this is Alice        (Bob received)
[<Bob's IK>…]   hi Alice — got it             (Alice received)
== DONE: end-to-end text exchange in both directions + file transfer ==
```

If that printed, the core of the system (relay, §12 discovery, PQXDH+ratchet E2E,
mailbox, sender attribution) works end-to-end between real processes.

## Manual run (GUI or CLI)

Bring up a relay and leave it running (it prints ready-to-paste commands and the
relay-id):

```sh
scripts/karst-up.sh            # relay on 127.0.0.1:9000
# ... work with the clients (see below) ...
scripts/karst-down.sh          # stop the relay
```

### Desktop clients — two windows

You need a graphical session (`DISPLAY`/Wayland) — not a bare SSH.

The **Tauri desktop client** (`karst-desktop`) is the actively-developed client;
run it directly (needs the WebKitGTK deps — see the repo README's prerequisites):

```sh
scripts/karst-up.sh                                 # bring up the relay (once)
KARST_DEV_CAP=1 KARST_HOME=/tmp/alice cargo run -p desktop   # Alice's window
KARST_DEV_CAP=1 KARST_HOME=/tmp/bob   cargo run -p desktop   # Bob's window (another terminal)
```

`KARST_DEV_CAP=1` writes the **dev** admission capability for whatever relay the window is
pointed at. Its secret is published in this repository, so anyone can forge deposits under it —
it exists so the one-machine demo works against a `dev`-mode relay, and the client refuses to
guess: without the flag an account holds a credential only for relays it actually joined
(`karst join`) or imported an invite for, and a relay it has none for is skipped, with a reason,
instead of being handed a forgeable one. Never set it against a relay you did not start yourself.

`karst-up.sh` does NOT launch the client — it only prints commands and the
relay-id to paste in. In each window (first run of a profile):

1. **Create account** → write down the **12 words** shown (the only way to
   restore; on a new device, use "Restore from phrase"). → confirm the words →
   set a **device passphrase** (encrypts secrets on THIS disk; ≠ the phrase) →
   **Create account** (relay and relay-id are already filled in by the script).
   On later runs → just the passphrase → "Log in".
2. Use the button at the top to copy your **IK**, paste it as a contact in the
   OTHER window (manually pasting the IK = out-of-band trust; there is no "search
   by name" on the relay, which would reintroduce a MITM).
3. Expand the **safety number** and confirm it matches in both windows.
4. Type text; send a file (the **📎** field → "Send file") — it lands in the
   recipient's `received/`. For Tor/obfs4, use the **SOCKS5** field (e.g.
   `127.0.0.1:9050`).

### CLI (terminal)

The commands are printed by `karst-up.sh`; in brief (`$R` = `--relay ...
--relay-id ...`):

```sh
> The CLI PROMPTS for the vault password on the terminal (echo off). `KARST_PASSPHRASE` below
> is the non-interactive escape hatch for scripts — convenient here, but it puts the secret into
> an environment every child process inherits and into your shell history, so prefer the prompt
> for anything you care about.

KARST_HOME=/tmp/a KARST_PASSPHRASE=pw karst init          # → prints the PHRASE + IK
# restore on another device: karst restore word1 … word12  (into an empty $KARST_HOME)
KARST_HOME=/tmp/a KARST_PASSPHRASE=pw karst dev-cap $R    # a credential is per RELAY, so name it
KARST_HOME=/tmp/a KARST_PASSPHRASE=pw karst publish $R
KARST_HOME=/tmp/a KARST_PASSPHRASE=pw karst send $R --to <recipient's IK> "text"
KARST_HOME=/tmp/a KARST_PASSPHRASE=pw karst send-file $R --to <IK> --file ./pic.jpg
KARST_HOME=/tmp/b KARST_PASSPHRASE=pw karst recv $R        # files → $KARST_HOME/received/
```

File transfer: the first slice handles up to ~256 KiB (chunked under the
1400-byte limit, reassembled with a SHA-256 check). In the GUI, use the "📎 file
path" field + "Send file".

## Running a PUBLIC relay (operator guide)

A relay is a **dumb, untrusted mailbox**: it never sees message plaintext (that is E2E-sealed;
the relay holds no key), and there is no account/signup database on it — your identity is a key,
not an account, and relays are interchangeable. It *does* hold the **public** prekey-bundles
clients publish (keyed by their IK, so others can reach them), so a compromised relay learns which
IKs published there — see "what an operator can and cannot see" below. Running one is safe and
useful. The interactive installer (`scripts/install-node.sh`)
walks you through everything below and can install a `systemd --user` service; this section is
the reference for what it configures.

### The door — who may use your relay (`KARST_RELAY_MODE`)

| Mode | Who gets in | Use it for |
|---|---|---|
| `private` (default) | invite-only — one credential per invitee (`karst-relay invite new NAME`), handed over as its own file | a closed group; the safe default |
| `public` | anyone who **earns** a capability (`karst join`), rate-bounded by proof-of-work + the per-capability quota | public infrastructure |
| `dev` | a known, public capability (local testing only — never expose) | the one-machine demo above |

An **unknown** mode value refuses to start (no silent default).

A private relay mints **one credential per invitee**, not one shared by everybody:

```sh
karst-relay invite new alice     # mint + write invites/<id>.json (0600) — hand THAT file to Alice
karst-relay invite list          # id, label, live/revoked
karst-relay invite revoke <id>   # stops working on the NEXT request, not at the next restart
```

That matters because the quota tracker meters by `capability_id`. With one shared invite, every
invitee drew on one bucket: a single noisy or compromised client could exhaust it and everyone
else started getting `CapabilityQuota` back, you could not revoke or rate-limit one person, you
could not tell whose traffic was whose, and rotating the secret cut off the entire group at once.

Honest limit that per-invite credentials do NOT fix: a capability is a bearer token, so any holder
can pass theirs on voluntarily. What changed is that quota is isolated, a targeted revoke exists,
and one compromised client can no longer deny service to the whole group.

Since a capability belongs to ONE relay, the client always names the relay an invite is for:
`karst import-cap invites/<id>.json --relay HOST:PORT --relay-id <hex>`. The invite file now
carries the relay-id and address itself, so those flags are a cross-check rather than the only
source of truth.

### Proof-of-work on a public door — and toggling it live

A public relay is spam-**bounded**, not Sybil-proof: `KARST_RELAY_POW_BITS` sets the difficulty
(default `20`; `0` = **open**, issue without PoW — the per-capability quota still bounds each). It
is the node owner's **live** call — you can flip it on a running relay without a restart or a
dropped connection, from the same machine (owner-only, by the state dir's `0700` perms):

```sh
karst-relay pow status          # what is the door doing now
karst-relay pow open            # issue without PoW (fine when there is no spam yet)
karst-relay pow on 20           # require 20-bit PoW
karst-relay pow off             # stop issuing new capabilities (earned ones keep working)
```

Run it with the same `KARST_RELAY_HOME` as the relay (it reaches the relay's admin socket there).

### Large-file blobs — how long they linger (`KARST_RELAY_BLOB_PERSIST`)

Big files are parked on your relay as **end-to-end-encrypted** chunks (you never hold the key),
capped and TTL-swept. You choose what a restart does to a parked transfer:

| Value | Behaviour | Use it for |
|---|---|---|
| `durable` (default) | parked blobs are recovered on restart, so a big upload survives a reboot/crash/deploy | reliable large-file delivery |
| `ephemeral` | the blob store is wiped on start — blobs do not outlive the process | the lower-residue posture (minimise what a lost or stolen disk holds) |

Either way the relay only ever holds opaque ciphertext, capped, and auto-deleted after the TTL —
so this changes only **how long** encrypted bytes linger, never what the relay can read (nothing).
An unknown value refuses to start. Note the honest asymmetry: a client can **prove** a `durable`
relay still holds its file (ask for a chunk back — it verifies), but `ephemeral` is a claim no one
can check remotely, so trust it only as far as you trust the operator.

### Queued messages — do they survive a restart? (`KARST_RELAY_MAIL_PERSIST`)

A message sits in the recipient's mailbox on your relay until they poll for it. What happens to
it if you restart in that window is your call:

| Value | Behaviour | Use it for |
|---|---|---|
| `volatile` (default) | queued mail lives in memory only — a restart loses anything not yet fetched, and the sender is never told | the lower-residue posture: nothing undelivered is ever written to your disk |
| `durable` | each accepted message is fsynced to a log **before** the relay says "accepted", and replayed on start | reliability — a reboot or deploy no longer drops mail |

The default is deliberately the opposite of the blob knob's: a big file transfer is expensive to
redo, while a message is small — and the reason to run a relay is often to hold as little as
possible. Opt in when reliability matters more.

Honest limits, both directions:

* `durable` is single-relay durability, not delivery reliability. If the disk dies or the relay
  goes away, the message goes with it — nothing replicates it to another relay yet.
* It is **at-least-once**: a crash can redeliver a message the recipient already had (the app
  detects the duplicate and drops it). Making that impossible would mean an fsync on every fetch.
* A relay that is told to be `durable` and cannot write **refuses to start**, and one that cannot
  write a particular message **rejects** it rather than claiming it was accepted. A promise that
  quietly stops holding is worse than no promise.
* Clients can require a match: the relay advertises which mode it runs, and an app set to prefer
  durable mail will not multi-home onto a volatile relay.

### Being discovered — the node-list

Relays share a list of **which relays exist** (never *which users exist* — that is a separate,
sensitive directory). To be listed, advertise a **routable** address (never `0.0.0.0`/loopback):

```sh
KARST_RELAY_ADVERTISE=relay.example.net:9000        # how clients reach THIS relay
KARST_RELAY_PEERS=other.example.net:9000@<relay-id> # relays to seed the list from
```

With peers set, the relay **gossips**: every few minutes it pulls its peers' lists and merges new
relays — but only after **dialing each to verify** it is the relay it claims (a bogus address that
isn't a KARST relay is refused, so gossip can't be aimed at a victim). Clients discover with
`karst relays --relay … --relay-id …` (add `--add` to multi-home onto the verified ones).

### WebSocket-over-TLS carrier (`wss`)

Point a **real** TLS cert for the relay's hostname at it and the relay terminates WebSocket-over-TLS,
carrying the encrypted KARST protocol over a standards-compliant `wss://` endpoint (a self-signed cert
is an observable feature — use certbot/Let's Encrypt). This does not guarantee indistinguishability
from browser traffic — the IP, SNI, and connection characteristics may remain observable:

```sh
KARST_RELAY_TLS_CERT=/etc/letsencrypt/live/HOST/fullchain.pem
KARST_RELAY_TLS_KEY=/etc/letsencrypt/live/HOST/privkey.pem
```

To have **no blockable IP at all**, run the relay as a Tor onion service (or I2P): point the hidden
service at the relay's port and hand out the `.onion` as the address — **no KARST code needed** on
the relay side; clients dial names over their SOCKS carrier.

### What a relay operator can and cannot see (state this to your users)

- **Cannot** read any message — payloads are end-to-end sealed (post-quantum PQXDH + ratchet); the
  relay has no key. A blob (large-file) store holds only E2E ciphertext, so an operator can honestly
  say they do not know what they are storing (operator deniability).
- **Can** see the source IP of each connection (use a carrier — Tor/wss — if that matters), the
  timing/volume of deposits and fetches, and — on a busy public relay — pseudonymous conversation
  *edges*. See [STATUS.md](STATUS.md) for the honest metadata map.

## Definition of done ("works as intended")

We iterate until everything is green:

- [x] the relay starts and prints a stable relay-id (survives restart)
- [x] two clients exchange messages in BOTH directions (CLI, `karst-demo.sh`)
- [x] file transfer (chunking+reassembly+SHA) — byte-for-byte (CLI, `karst-demo.sh`)
- [x] sessions/history survive a process restart
- [x] a route through a SOCKS5 PT works and fails hard with no silent direct fallback
- [x] **the desktop UI launches and renders** — the Tauri `karst-desktop` opens its
      welcome screen (verified by screenshot at a display, 2026-07-19)
- [ ] **GUI full flow by hand: unlock, copy IK, send/receive text between two
      windows, safety number matches, and a FILE (the "📎" field) → the
      recipient's `received/` byte-for-byte** — the two-window interactive exchange
      is still driven by eye (the worker's logic, incl. files, is covered by tests;
      the CLI equivalent of text-both-ways + file IS verified live, above)

The last item is closed by driving the GUI by eye — report what you see and we'll
refine the visual layer.
