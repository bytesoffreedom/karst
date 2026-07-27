# Tier 2 — deniable container + hidden ACCOUNT (design, pre-implementation)

Status: **DESIGN — supersedes the shipped note-based `hidden.dat` (#95, commit
`3680b4a`).** That first cut sealed a *secret note* into an opaque fixed region and
proved indistinguishability at rest. It is honest for what it is, but the user's
verdict is decisive: **a hidden note is a bad cover — "по заметке тебя и спалят."**
A password-protected secret note *proves you deliberately hid something*; a mundane
empty account does not. So Tier 2 becomes a **hidden full account**, not a note.

This note is the agreed contract before the storage rewrite. Source of truth is the
code once it lands. Design converged with the user 2026‑07‑26.

---

## 0. What changed from the earlier design notes

- The hidden compartment opens a **real, working (empty/light) account**, not a note.
- The old "K equal partitions" scheme is replaced by a **main‑region + hidden‑tail**
  layout driven by a **three‑password policy** (below). P1 subsumes the old
  disjoint‑partition safety; P3 adds snapshot‑diff masking the old model could not.
- A whole new axis the earlier note ignored entirely: **network deniability**. A
  hidden *account* leaks through the wire, not just the disk. This sets the honest
  ceiling (§5) and forces the offline/isolation controls (§6).

---

## 1. The honest ceiling (write this FIRST, before any code or UI copy)

Per our duress discipline, overclaiming here is worse than not shipping. The claim is:

> **Deniable at rest, on this disk, while offline.** A cold disk image cannot prove a
> hidden account exists inside the container; and while the hidden account is offline
> it emits nothing to the network. **Not** deniable against an adversary who also has
> **relay/network logs** correlated over time — an *online* hidden account is a second
> network identity, observable regardless of how perfect the container is.

Strong against: loss or theft of the device, disk forensics, backup theft, "unlock it or else."
Partial/again­st only with effort: a relay‑capable or global‑passive network observer
(§5). The UI must say this; silence here is the failure mode.

---

## 2. The three‑password scheme (fits the existing 8 fixed keyslots)

Deniability of *which/whether* passwords exist already comes from the Tier‑1 design:
**8 fixed padded slots**, so the *number* of real passwords never leaks. We fold the
slot table **inside** the container (no separate `slots.dat` base file). Roles:

- **P1 — main, PROTECT.** Opens the main account; allocator hard‑capped so it never
  writes the hidden tail. Hidden stays intact. (This is the old disjoint‑partition
  safety, now a per‑login choice.)
- **P2 — hidden.** Opens the hidden account (its own region key).
- **P3 — main, BLIND.** Opens the **same** main account (same main key + a policy
  flag in the slot), allocator allowed the **whole** container → may overwrite the
  hidden tail. Two purposes: (a) it is the *cover* you reveal under duress ("just my
  account, writes across the disk, nothing hidden"), and (b) main activity churning
  the tail is what masks hidden writes against snapshot diffing (§5).

P1 and P3 wrap the **same** main data key, differing only by the protect/blind flag.
Revealing P3 under coercion does not expose P1 or P2: each slot is sealed under its
own password‑key, wrapped contents are untestable without it, and unused slots are
random — so the "8 slots" cover holds and a coercer cannot prove P1/P2 exist.

**Overwrite decision (settled):** blind writes are an *accepted risk*, not a bug.
Under P3 a growing main account may clobber the hidden tail — "повезёт — жив, нет —
хуй с ним." P1 is the safe mode for when durability matters. We keep BOTH mechanisms.
Corruption‑avoidance without leaking the hidden extent is provably impossible on one
key (anything the main allocator can read to avoid, a coercer with the main password
can read to detect), so we do not pretend to solve it — we expose the choice.

Optional later: a generic "re‑randomize the reserve region" duress password (panic
burn of the tail; harmless no‑op when empty, so its presence implies nothing), and a
two‑password "refresh" that re‑randomizes the whole container at once (a partial
future‑snapshot mitigation).

---

## 3. Container layout (userspace, no FUSE/loopback/root)

```
container.dat  (exactly N bytes, every byte indistinguishable from random)
├─ salt prefix        random 16–32 B (a salt is supposed to look random)
├─ 8 header slots     sealed(K_pw, role ‖ policy ‖ region_descriptor) | random
├─ mgmt directory     sealed(mgmt_key, used-slot list) — hidden from P3
├─ VISIBLE region [A] ALL non-hidden accounts (multiple) + channels — one region
└─ HIDDEN region  [B] the single hidden account (text/contacts only)
```

- **Compact METADATA vault — not a big disk-filling volume.** The container holds only
  the light state: contacts, sessions/ratchets, net files, **text history**, small
  previews. That is **megabytes even for many accounts**. **Bulk media (photos/files —
  the tens of GB) lives OUTSIDE** the container as separate encrypted blobs, for the
  VISIBLE accounts only. So N stays small regardless of an account's total footprint;
  a huge always-random file would be both pointless and conspicuous. (Corrects the
  earlier "size up to free space / fill with random" framing.)
- **One hidden, many visible.** All non-hidden accounts (incl. channels — public
  auto-accept accounts are just visible accounts) share the VISIBLE region under one
  device password (P1 protect / P3 blind). The one hidden account is the HIDDEN region
  under P2. This keeps it to the three-password model.
- **Hidden = text/contacts only.** The zero-external-artifact rule means the hidden
  account can't put media outside, and heavy media inside would bloat the container →
  the hidden account is deliberately light (messaging + contacts), no media library.
- **No plaintext header.** The only visible structure is "a file of N random bytes";
  everything is reached by trial-decrypt keyed on the password.
- **Inside a region: small mutable core + append-only history chunks (NOT one
  monolithic blob).** A monolithic format-(b) blob would re-encrypt the WHOLE account
  on every message — wasteful and, worse, laggy on big accounts. Instead: a tiny
  "index + recent state" core (re-sealed per save, instant) plus history stored as
  **append-only sealed chunks** — a new message seals ONE small chunk appended after
  the high-water mark; **old chunks are never re-encrypted**. Data still grows
  contiguously with a leftover-random tail, so logical length L stays unobservable
  exactly as before. Cost: occasional background **compaction** to reclaim gaps left by
  deleted/expired messages.
- **When we persist: on each message (event-driven), never on a timer.** Working copy
  lives decrypted in memory while open; we seal to the container **after each message**
  purely as crash insurance — cheap now that a save is "one appended chunk + tiny
  core." A burst (draining a full mailbox) is batched into ONE save. A timer would be
  strictly worse: it loses more on a crash AND writes when nothing changed.
- **Working copy while open.** HIDDEN account = **RAM only** (never restored to
  plaintext files on disk); on close, memory buffers are zeroized and its pages are
  `mlock`ed so the OS can't swap a plaintext copy out (we cannot reliably scrub swap
  after the fact — so prevent it, and advise the user to disable/encrypt swap and
  disable hibernation). VISIBLE accounts, being non-secret, may use a normal working
  copy.
- **P1 vs P3 = the allocation ceiling only.** P1: visible region confined to its A cap.
  P3: allowed the whole container → may spill into B (accepted-risk masking). Hidden
  always confined to its region.
- **A/B split** chosen at creation (§7); a soft reserve, not enforced against P3.

**Open design item (multiple accounts):** the slot/region model already supports
arbitrary regions, but the VISIBLE region now holds several accounts' metadata in one
blob-set → re-seal/compaction cost scales with total visible metadata (pruning keeps it
bounded). Whether to give each visible account its own sub-index for cheaper per-account
saves is a Phase-2 refinement, not settled here.

---

## 4. Media & the zero‑external‑artifact rule (hard constraint)

- **Main account:** small stuff (contacts/text/**small previews**) lives INSIDE the
  container; heavy bulk media (photos/files) stays OUTSIDE as separate encrypted
  blobs — fast, and bulk media existing is not itself incriminating.
- **Hidden account: ZERO external artifacts.** Any external blob from the hidden
  account is a countable, undeniable tell — the exact thing we eliminate. So the
  hidden account keeps *everything* inside the container. Concretely: a **per‑account
  "don't accept media" toggle** (locked with the user) so nothing from the hidden
  session is ever written outside the container; oversize incoming media is refused,
  not spilled to disk. Warn the user: heavy content in the hidden account is
  discouraged and, if forced, capped to the region — at their own risk.
- The hidden session must also write **nothing** account‑identifying to WebKit
  `localStorage` (today only device prefs `karst_lang/theme/cover` live there — keep
  it that way) and produce no logs/temp with account data.

---

## 5. Network deniability (the axis the note ignored)

E2E encryption hides *content*, not *that a second network identity exists*. A working
account, per the proxy model, publishes proxy bundles and polls mailboxes; the relay
**must** see the mailbox address to route. So an online hidden account leaks:

1. **Distinct mailbox addresses / bundles** the relay sees (a second identity).
2. **A directory bundle** if the hidden account is reachable.
3. **Timing correlation** — mailbox Z polled only when your device is online.

Graded by adversary: disk‑only image → fully deniable; passive link observer → weak
leak; **relay‑log holder / global passive → observable.** Mitigations we build:

- **Per‑account OFFLINE toggle (default ON for hidden).** Offline = emits nothing;
  deniability perfect. The leak becomes rare, user‑controlled sync windows, not a
  continuous signal.
- **Per‑account circuit isolation.** *(Shipped.)* Sync the hidden account over a
  **separate** Tor/I2P circuit/session from the main account (stream isolation), so the
  relay cannot co‑locate the two identities behind one client. Implemented by
  construction: every `Relay` mints a fresh random SOCKS‑auth token
  (`node::transport::isolation_token` → `Socks5Adapter::isolated`), which drives Tor's
  `IsolateSOCKSAuth` — connections presenting different credentials get different
  circuits. The desktop rebuilds the relay set per session (`enter → build_relays` on
  that session's own store), so the hidden account never inherits the main account's
  token; two accounts cannot share a circuit. "Tor is present" is not enough by
  itself — sharing one circuit re‑links them; the per‑`Relay` token is the piece that
  keeps them apart. (Offline‑default means the hidden account has *no* circuit at all
  until a deliberate sync.)
- **Timing controls (settings).** *(Shipped — client‑side, per‑session.)* **Message‑
  timing** mode (Realtime 2.5–6.5 s / Balanced 10–30 s / High‑latency 60–180 s) sets the
  jittered poll cadence; **cover‑traffic** intensity (Off / Light ~90 s / Balanced ~45 s /
  Heavy ~15 s mean, extends #101) sets the Poisson deposit rate. Prefs are scoped
  **per session**: a hidden session reads its own `localStorage` keys
  (`karst_latency_hidden` / `karst_cover_hidden`) and **defaults to High‑latency +
  cover‑on**, so it never inherits the main account's cadence at the exposed sync
  moment; the main account keeps `karst_latency` / `karst_cover`. The scope is latched
  from `container_hidden` in `loadApp` before the cover/poll loops read it, and reset on
  lock. Randomized flush (compose offline → upload at a random later time) is subsumed
  by the offline toggle + high‑latency mode; a dedicated deferred‑flush queue is future
  work.

**Honest residual:** client‑side latency/jitter/cover raise the observation cost but
do **not** defeat a true global passive adversary watching both ends — that requires
real mixnet transport (multiple independently‑delaying hops), not a single client.
State this; do not imply an absolute guarantee.

---

## 6. Dead‑man ⇄ opacity (unchanged fork → D1)

A launch‑time dead‑man needs a plaintext marker or a wipe‑capable agent — both are
tells inside a fully opaque container. Decision: **D1** — the dead‑man fires *at
unlock* (real key present → check `last_seen` in the real region → wipe if lapsed),
not while absent. Document the weakened‑absence limit. `wipe` password destroys the
**whole** container (both regions).

---

## 7. Sizing, migration, UI

- **User chooses N** at creation (up to `free − max(2 GiB, 10%)`), plus an **A/B
  slider** (main vs hidden reserve) with the honest warning that hidden is
  best‑effort under P3 and best kept light. Writing N random bytes is slow → progress
  off the UI thread.
- **Main‑region full policy (settled with user):** format (b) hard‑caps the main
  account at A, so its growing metadata (sessions/history/contacts) can fill it.
  Policy = **generous A default + an always‑on "container nearly full" warning** +
  an **OPTIONAL, off‑by‑default auto‑prune** of the oldest history to reclaim space.
  Nothing is ever deleted silently without the user opting in; with prune off, the
  main account surfaces a clear "full" state rather than losing data.
- **Migration: none.** Pre‑alpha, **0 users** — the container format simply becomes
  the storage for newly created accounts; the throwaway test vaults (k1/k2) are
  recreated. No risky in‑place migration path, no secure‑erase‑of‑old‑layout caveat.
- **UI honesty banner** = the §1 ceiling verbatim, plus the §5 network caveat and the
  "a large high‑entropy file is itself conspicuous — Tier 2 hides *what's inside*, not
  *that a container exists*" note.

---

## 8. Acceptance criterion (what a cold image + the app surface may STILL reveal)

"Done" only when the list contains **nothing that proves a hidden account exists**:

- The container exists (a file of N random bytes) — existence of the *container* is
  not deniable; *whether a hidden account lives inside* is. Behavioural deniability
  (reveal P3) answers "open it."
- Size N (user‑chosen; round defaults recommended), filesystem mtime (recent
  activity, not content), cloud/backup of the whole file (outside the crypto
  boundary — advise against), key in RAM/swap (OS‑level; mlock or document).
- **Network:** per §5 — online hidden account is observable to a relay‑log adversary.
  This is the honest ceiling, not a bug to be closed at the disk layer.

Test surface must be **system‑wide**, not just "the region looks random": header‑slot
indistinguishability, P1/P3 same‑account + policy, P3‑spill corrupts hidden while P1
never does, hidden account leaves **zero** files outside the container, offline
toggle emits zero packets, crash‑safety of the atomic swap, full‑image entropy.

---

## 9. Phased build (each phase its own reviewed PR, like the proxy model)

1. **Container core** — format (b) blob regions, 8 in‑container header slots, salt
   prefix, random fill, atomic swap, `Container` type presenting the API `store.rs`
   expects. Judge test: entropy + slot indistinguishability.
2. **Store on the container** — route the ~20 `self.dir.join(...).seal` sites through
   the container object API; main account runs entirely on it.
3. **Three passwords** — P1/P2/P3 roles + policy flag; hidden region; P3 spill vs P1
   protect; system‑wide deniability test.
4. **Zero‑external‑artifact + no‑media toggle** for the hidden session (§4).
5. **Network controls** — per‑account offline toggle, circuit isolation, latency/flush
   settings (§5).
6. **UI** — creation flow (N + A/B slider + progress), Security‑card controls, the §1
   honesty banner; supersede the shipped note UI.
7. **Advisor + security‑audit gate** before any public announcement; keep the
   redesign unannounced until the system‑wide property is proven (embargo instinct).

---

## 10. Open decisions

None blocking — all forks resolved with the user (hidden = account not note; three
passwords; blind‑write accepted; format (b); media inside=metadata/hidden=zero‑
external + no‑media toggle; offline‑default + circuit isolation + timing settings;
D1 dead‑man; wipe = whole container; no migration). Remaining are implementation
details settled in‑phase.
